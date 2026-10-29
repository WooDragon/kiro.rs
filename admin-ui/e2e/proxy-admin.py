#!/usr/bin/env python3
"""Real Rust Admin browser E2E; requires Docker able to run linux/arm64 containers
and installed Python Playwright.

Only dummy credentials are used. No credential submission, balance, refresh,
probe, or inference is performed. Background service maintenance still runs;
this test does not promise zero outbound traffic or proxy connectivity.
Artifacts contain dummy passwords verbatim to verify persistence semantics.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from playwright.sync_api import expect, sync_playwright

ADMIN_KEY = "dummy-proxy-admin-e2e"
LONG_NAME = "长代理名称用于检验换行" + "LongProxyName" * 160
LONG_URL = "http://" + "long-proxy-segment-" * 10 + ".invalid:3128"
MODES = ["使用全局代理配置", "明确直连", "使用指定代理", "高级：内联地址"]
OPTIONS = None


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def docker(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True,
                          timeout=60, check=check)


def credentials():
    return [{"id": number, "authMethod": "api_key",
             "kiroApiKey": f"ksk_dummy_never_submit_{number}",
             "email": f"dummy-{number}@example.invalid", "priority": number}
            for number in range(1, 5)]


def compact_document():
    items = [{"id": number, "authMethod": "api_key",
              "kiroApiKey": f"ksk_dummy_never_submit_{number}",
              "email": f"user{number:02d}@example.invalid", "priority": number,
              "disabled": number % 4 == 0,
              **({"disabledReason": "Manual"} if number % 4 == 0 else {})}
             for number in range(1, 26)]
    items[4]["proxyId"] = "office"
    return {"version": 1, "proxies": [{"id": "office", "name": "OfficeProxy",
            "url": "http://127.0.0.1:9"}], "credentials": items}


def fixture_document(global_proxy):
    items = credentials()
    if not global_proxy:
        return items
    items[2]["email"] = "long-identity-" * 18 + "@example.invalid"
    items[1]["proxyUrl"] = "direct"
    items[2]["proxyId"] = "long-proxy"
    items[3].update(proxyUrl=LONG_URL, proxyUsername="dummy-inline",
                    proxyPassword=" inline original ")
    return {"version": 1, "proxies": [
        {"id": "long-proxy", "name": LONG_NAME, "url": LONG_URL,
         "username": "dummy-user", "password": " original password "}],
        "credentials": items}


class Service:
    def __init__(self, directory, artifacts):
        self.directory = directory
        self.artifacts = artifacts
        self.container = None
        self.base = None
        self.http = []
        self.snapshot_index = 0

    def request(self, path, key=ADMIN_KEY):
        request = Request(self.base + path, headers={"x-api-key": key})
        try:
            with urlopen(request, timeout=2) as response:
                status, body = response.status, response.read().decode()
        except HTTPError as error:
            status, body = error.code, error.read().decode()
        self.http.append({"path": path, "status": status, "body": body})
        save_json(self.artifacts / "http.json", self.http)
        return status, json.loads(body)

    def snapshot(self, label):
        self.snapshot_index += 1
        text = (self.directory / "credentials.json").read_text()
        (self.artifacts / f"{self.snapshot_index:02d}-{label}.json").write_text(text)
        return json.loads(text)

    def start(self):
        result = docker("run", "--platform", "linux/arm64", "-d", "--read-only", "--tmpfs", "/tmp",
                        "-p", "127.0.0.1::8990", "-w", "/fixture",
                        "-v", f"{OPTIONS.binary}:/kiro-rs:ro",
                        "-v", f"{self.directory}:/fixture:rw",
                        "rust:1.92-alpine", "/kiro-rs", "--config",
                        "/fixture/config.json", "--credentials",
                        "/fixture/credentials.json")
        self.container = result.stdout.strip()
        (self.artifacts / "container-id.txt").write_text(self.container + "\n")
        mapping = docker("port", self.container, "8990/tcp").stdout.strip()
        if not mapping.startswith("127.0.0.1:") or "\n" in mapping:
            raise RuntimeError(f"Unexpected port binding: {mapping}")
        self.base = "http://" + mapping
        deadline = time.monotonic() + 30
        last_error = None
        while time.monotonic() < deadline:
            try:
                status, _ = self.request("/api/admin/credentials")
                if status == 200:
                    return
            except (URLError, TimeoutError, ConnectionError) as error:
                last_error = str(error)
            time.sleep(0.2)
        raise RuntimeError(f"Admin not ready within 30 seconds: {last_error}")

    def close(self):
        if not self.container:
            return
        logs = docker("logs", "--timestamps", self.container, check=False)
        (self.artifacts / "service.log").write_text(logs.stdout + logs.stderr)
        result = docker("rm", "-f", self.container, check=False)
        save_json(self.artifacts / "cleanup.json", {
            "container": self.container, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(f"Cannot remove owned container {self.container}: {result.stderr}")


@contextmanager
def private_fixture(label, global_proxy=False, compact=False):
    artifacts = OPTIONS.artifacts / label
    artifacts.mkdir()
    with tempfile.TemporaryDirectory(prefix="kiro-proxy-admin-") as temporary:
        directory = Path(temporary)
        config = {"host": "0.0.0.0", "port": 8990,
                  "apiKey": "dummy-public-e2e", "adminApiKey": ADMIN_KEY}
        if global_proxy:
            config["proxyUrl"] = "http://127.0.0.1:9"
        save_json(directory / "config.json", config)
        document = compact_document() if compact else fixture_document(global_proxy)
        save_json(directory / "credentials.json", document)
        service = Service(directory, artifacts)
        save_json(artifacts / "fixture.json", {"config": config,
                  "credentials": document, "directory": temporary})
        try:
            service.start()
            yield service
        finally:
            service.close()
    save_json(artifacts / "fixture-cleanup.json", {"removed": not directory.exists()})


class BrowserSession:
    def __init__(self, browser, service):
        self.service = service
        self.context = browser.new_context(viewport={"width": 1440, "height": 900})
        self.context.tracing.start(screenshots=True, snapshots=True, sources=True)
        self.page = self.context.new_page()
        self.page.set_default_timeout(8000)
        self.events = []
        self.expected = set()
        self.bad = []
        self.focus_failures = []
        self.context.on("page", self.observe_page)
        self.observe_page(self.page)

    def observe_page(self, page):
        page.on("pageerror", lambda error: self.record("pageerror", str(error), True))
        page.on("console", self.console)
        page.on("requestfailed", lambda request: self.record(
            "requestfailed", {"url": request.url, "failure": request.failure}, True))
        page.on("response", self.response)
        page.on("request", lambda request: self.record("request", {
            "url": request.url, "method": request.method, "postData": request.post_data}))

    def record(self, kind, detail, bad=False):
        event = {"kind": kind, "detail": detail, "unexpected": bad}
        self.events.append(event)
        if bad:
            self.bad.append(event)
        save_json(self.service.artifacts / "browser-events.json", self.events)

    def console(self, message):
        if message.type != "error":
            self.record("console." + message.type, message.text)
            return
        # Chromium reports expected HTTP failures separately from response events.
        # Correlate the exact resource URL AND numeric status, never blanket-ignore.
        url = message.location.get("url", "")
        text = message.text
        expected = any(url == self.service.base + path and
                       f"status of {status}" in text for path, status in self.expected)
        self.record("console.error", {"text": text, "location": message.location}, not expected)

    def response(self, response):
        request = response.request
        path = urlsplit(response.url).path
        expected = (path, response.status) in self.expected
        if response.status == 401:
            expected = expected and request.header_value("x-api-key") == "dummy-wrong-key"
        detail = {"url": response.url, "method": request.method,
                  "status": response.status, "expected": expected}
        if path.startswith("/api/admin"):
            detail["postData"] = request.post_data
        self.record("response", detail, response.status >= 400 and not expected)

    def close(self):
        try:
            self.context.tracing.stop(path=self.service.artifacts / "trace.zip")
        finally:
            self.context.close()

    def shot(self, name):
        self.page.screenshot(path=self.service.artifacts / f"{name}.png", full_page=False)

    def login(self, bad_key=False):
        # Axum's nested root is /admin; /admin/ is separately recorded, not hidden.
        try:
            with urlopen(self.service.base + "/admin/", timeout=2) as response:
                trailing_status = response.status
        except HTTPError as error:
            trailing_status = error.code
        save_json(self.service.artifacts / "admin-entrypoint.json", {
            "requested": "/admin/", "status": trailing_status,
            "browser_entry": "/admin", "note": "Existing Rust route uses no trailing slash"})
        response = self.page.goto(self.service.base + "/admin", wait_until="networkidle")
        assert response.status == 200, f"Admin document: {response.status}"
        html = response.text()
        expected_html = (Path(__file__).resolve().parents[1] / "dist/index.html").read_text()
        assert html == expected_html, "Served Admin does not match the current built dist"
        (self.service.artifacts / "served-admin.html").write_text(html)
        resources = []
        for name in ("index-hQAFE82u.js", "index-CgqMuxC8.css"):
            path = "/admin/assets/" + name
            assert path in html, f"Expected current dist resource missing: {path}"
            with urlopen(self.service.base + path, timeout=5) as asset:
                content = asset.read()
                assert asset.status == 200
            local = Path(__file__).resolve().parents[1] / "dist/assets" / name
            assert content == local.read_bytes(), f"Stale served resource: {name}"
            resources.append({"path": path, "bytes": len(content), "matchesDist": True,
                              "sha256": hashlib.sha256(content).hexdigest()})
        save_json(self.service.artifacts / "served-resources.json", resources)
        if bad_key:
            self.expected.add(("/api/admin/credentials", 401))
            self.expected.add(("/api/admin/proxies", 401))
            self.expected.add(("/api/admin/config/load-balancing", 401))
            self.page.get_by_placeholder("Admin API Key").fill("dummy-wrong-key")
            with self.page.expect_response(lambda response:
                    urlsplit(response.url).path == "/api/admin/credentials" and response.status == 401):
                self.page.get_by_role("button", name="登录", exact=True).click()
            self.page.get_by_role("button", name="重新登录").click()
        self.page.get_by_placeholder("Admin API Key").fill(ADMIN_KEY)
        self.page.get_by_role("button", name="登录", exact=True).click()
        expect(self.page.get_by_role("button", name="代理列表", exact=True)).to_be_visible()

    def dialog(self, title):
        dialog = self.page.get_by_role("dialog", name=title, exact=True)
        expect(dialog).to_be_visible()
        return dialog

    def pool(self):
        self.page.get_by_role("button", name="代理列表", exact=True).click()
        dialog = self.dialog("代理列表")
        expect(dialog.get_by_role("button", name="新增代理", exact=True)).to_be_enabled()
        return dialog

    def row(self, credential_id):
        return self.page.get_by_test_id(f"credential-row-{credential_id}")

    def expand(self, credential_id):
        row = self.row(credential_id)
        trigger = row.get_by_role("button", name=f"凭据 #{credential_id} 详情", exact=True)
        if trigger.get_attribute("aria-expanded") != "true":
            trigger.click()
        expect(trigger).to_have_attribute("aria-expanded", "true")
        return row

    def edit_binding(self, credential_id=1):
        self.expand(credential_id).get_by_role("button", name="修改代理", exact=True).click()
        return self.dialog("修改代理")

    def mutation(self, method, path, action, status=200):
        with self.page.expect_response(lambda response:
                response.request.method == method and urlsplit(response.url).path == path) as pending:
            action()
        response = pending.value
        if response.status != status:
            raise AssertionError(f"{method} {path}: {response.status}: {response.text()}")
        return response.request.post_data_json if response.request.post_data else None

    def layout(self, dialog, label, action_selector='button[type="submit"]'):
        dialog.evaluate("""root => [...root.querySelectorAll('*')].filter(node =>
          getComputedStyle(node).overflowY === 'auto').forEach(node => node.scrollTop = 0)""")
        self.shot(label + "-top")
        measurements = dialog.evaluate("""(root, actionSelector) => {
          const box = root.getBoundingClientRect();
          const submits = [...root.querySelectorAll(actionSelector)];
          const title = root.querySelector('h2');
          const headerBefore = title.getBoundingClientRect().y;
          const footerBefore = submits.map(node => node.getBoundingClientRect().y);
          const headings = [...root.querySelectorAll('h1,h2,h3')].map(node => {
            const style = getComputedStyle(node);
            return {text:node.textContent, font:parseFloat(style.fontSize),
              line:parseFloat(style.lineHeight)};
          });
          const scrollers = [...root.querySelectorAll('*')].filter(node =>
            getComputedStyle(node).overflowY === 'auto').map(node => {
              node.scrollTop = node.scrollHeight;
              return {height:node.clientHeight, scroll:node.scrollHeight, top:node.scrollTop,
                clientWidth:node.clientWidth, scrollWidth:node.scrollWidth};
            });
          return {box:{x:box.x,y:box.y,right:box.right,bottom:box.bottom},
            client:root.clientWidth, scroll:root.scrollWidth,
            footerBefore, footerAfter:submits.map(node => node.getBoundingClientRect().y),
            headerBefore, headerAfter:title.getBoundingClientRect().y,
            width:innerWidth,height:innerHeight,headings,scrollers};
        }""", action_selector)
        save_json(self.service.artifacts / f"{label}-layout.json", measurements)
        box = measurements["box"]
        assert box["x"] >= 8 and box["right"] <= measurements["width"] - 8, measurements
        assert box["y"] >= 8 and box["bottom"] <= measurements["height"] - 8, measurements
        assert measurements["scroll"] <= measurements["client"] + 1, measurements
        for heading in measurements["headings"]:
            assert heading["line"] >= heading["font"] - 1, heading
        for scroller in measurements["scrollers"]:
            assert scroller["scrollWidth"] <= scroller["clientWidth"] + 1, scroller
        for before, after in zip(measurements["footerBefore"], measurements["footerAfter"]):
            assert abs(before - after) <= 1, measurements
        assert abs(measurements["headerBefore"] - measurements["headerAfter"]) <= 1, measurements
        for button in dialog.locator(action_selector).all():
            bounds = button.bounding_box()
            assert bounds and bounds["y"] >= box["y"] and bounds["y"] + bounds["height"] <= box["bottom"], bounds
        self.shot(label)
        return measurements

    def restored_focus(self, target, label):
        # Accumulate, do not waive: final assertion stays red for every failure.
        try:
            expect(target).to_be_focused(timeout=750)
        except AssertionError as error:
            detail = {"checkpoint": label, "assertion": str(error),
                      "active": self.page.evaluate("document.activeElement.outerHTML.slice(0, 1200)")}
            self.focus_failures.append(detail)
            save_json(self.service.artifacts / "focus-failures.json", self.focus_failures)
            self.shot(label + "-focus-failure")

    def assert_clean(self):
        assert not self.bad, f"{len(self.bad)} unexpected browser errors; see browser-events.json"
        checkpoints = [failure["checkpoint"] for failure in self.focus_failures]
        assert not checkpoints, f"Focus restoration failed: {checkpoints}; see focus-failures.json"

    def focus_trap(self, dialog):
        for _ in range(16):
            self.page.keyboard.press("Tab")
            assert dialog.evaluate("root => root.contains(document.activeElement)"), "Tab escaped dialog"
        for _ in range(4):
            self.page.keyboard.press("Shift+Tab")
            assert dialog.evaluate("root => root.contains(document.activeElement)"), "Shift+Tab escaped dialog"


@contextmanager
def browser_session(browser, service):
    session = BrowserSession(browser, service)
    try:
        yield session
    except BaseException:
        session.shot("failure")
        (service.artifacts / "failure.txt").write_text(traceback.format_exc())
        raise
    finally:
        session.close()


class ProxyAdminE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch()
        except BaseException:
            cls.playwright.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
        finally:
            cls.playwright.stop()

    def test_01_real_http_persistence_and_keyboard(self):
        """Given legacy credentials, CRUD/bind through the actual browser and disk."""
        with private_fixture("A-legacy") as service:
            with browser_session(self.browser, service) as session:
                session.login(bad_key=True)
                self.legacy_flow(session, service)
                session.assert_clean()

    def legacy_flow(self, session, service):
        pool = session.pool()
        expect(pool.get_by_text("代理列表为空", exact=True)).to_be_visible()
        expect(pool.get_by_role("button", name="新增代理", exact=True)).to_have_count(1)
        pool.get_by_role("button", name="新增代理", exact=True).click()
        create = session.dialog("新增代理")
        expect(create.get_by_role("note")).to_have_count(1)
        session.focus_trap(create)
        session.page.keyboard.press("Escape")
        session.restored_focus(pool.get_by_role("button", name="新增代理", exact=True), "create-close")
        pool.get_by_role("button", name="新增代理", exact=True).click()
        create = session.dialog("新增代理")
        create.get_by_label("名称", exact=True).fill("E2E proxy")
        create.get_by_label("协议", exact=True).select_option("http")
        create.get_by_label("主机:端口", exact=True).fill("127.0.0.1:9")
        create.get_by_label("代理用户名", exact=True).fill("dummy-user")
        create.get_by_label("代理密码", exact=True).fill(" original password ")
        body = session.mutation("POST", "/api/admin/proxies", lambda:
                                create.get_by_role("button", name="添加", exact=True).click())
        self.assertEqual(body["password"], " original password ")
        expect(create).not_to_be_visible()
        document = service.snapshot("first-proxy")
        self.assertEqual(document["version"], 1)
        self.assertTrue(all(not item.get("proxyId") for item in document["credentials"]))
        proxy_id = document["proxies"][0]["id"]
        self.assertEqual(document["proxies"][0]["password"], " original password ")
        expect(pool.get_by_text("被 0 个凭据引用", exact=True)).to_be_visible()
        self.password_states(session, service, pool, proxy_id)
        pool.get_by_role("button", name="新增代理", exact=True).click()
        create = session.dialog("新增代理")
        expect(create.get_by_role("note")).to_have_count(0)
        create.get_by_role("button", name="取消", exact=True).click()
        session.page.keyboard.press("Escape")
        self.bind_modes(session, service, proxy_id)
        self.conflict_and_delete(session, service, proxy_id)
        self.cancel_add(session, service)

    def password_states(self, session, service, pool, proxy_id):
        for state in ("keep", "replace", "clear"):
            pool.get_by_role("button", name="编辑 E2E proxy", exact=True).click()
            dialog = session.dialog("编辑代理")
            dialog.get_by_label("名称", exact=True).fill("E2E proxy")
            dialog.get_by_label("密码操作").select_option(state)
            if state == "replace":
                dialog.get_by_label("新密码", exact=True).fill(" replaced password ")
            patch = session.mutation("PATCH", f"/api/admin/proxies/{proxy_id}", lambda:
                                     dialog.get_by_role("button", name="保存", exact=True).click())
            expect(dialog).not_to_be_visible()
            entry = service.snapshot(f"password-{state}")["proxies"][0]
            self.assertNotIn("url", patch, "Unchanged URL must not be sent")
            if state == "keep":
                self.assertEqual(patch, {"name": "E2E proxy"})
                self.assertEqual(entry["password"], " original password ")
            elif state == "replace":
                self.assertEqual(patch["password"], " replaced password ")
                self.assertEqual(entry["password"], " replaced password ")
            else:
                self.assertIsNone(patch["password"])
                self.assertIsNone(patch["username"])
                self.assertIsNone(entry.get("password"))
                self.assertIsNone(entry.get("username"))
        pool.get_by_role("button", name="编辑 E2E proxy", exact=True).click()
        dialog = session.dialog("编辑代理")
        dialog.get_by_label("名称", exact=True).fill("Renamed E2E proxy")
        patch = session.mutation("PATCH", f"/api/admin/proxies/{proxy_id}", lambda:
                                 dialog.get_by_role("button", name="保存", exact=True).click())
        self.assertEqual(patch, {"name": "Renamed E2E proxy"})
        expect(dialog).not_to_be_visible()
        service.snapshot("rename-only")

    def bind_modes(self, session, service, proxy_id):
        for mode in ("direct", "inline", "inherit", "pool"):
            dialog = session.edit_binding()
            expect(dialog.get_by_text("未配置，使用系统默认网络", exact=True)).to_be_visible()
            radios = dialog.get_by_role("radio")
            self.assertEqual(radios.count(), 4)
            self.assertEqual(radios.evaluate_all("nodes => nodes.map(n => n.value)"),
                             ["inherit", "direct", "pool", "inline"])
            radio = dialog.locator(f'input[value="{mode}"]')
            radio.focus()
            session.page.keyboard.press("Space")
            expect(radio).to_be_checked()
            if mode == "direct":
                session.page.keyboard.press("ArrowRight")
                expect(dialog.locator('input[value="pool"]')).to_be_checked()
                session.page.keyboard.press("ArrowLeft")
                expect(radio).to_be_checked()
            if mode == "pool":
                dialog.get_by_label("选择指定代理").select_option(proxy_id)
            if mode == "inline":
                dialog.get_by_label("内联代理地址", exact=True).fill("http://127.0.0.1:9")
                dialog.get_by_label("内联代理用户名", exact=True).fill("dummy-inline")
                dialog.get_by_label("内联代理密码", exact=True).fill(" inline password ")
            body = session.mutation("PUT", "/api/admin/credentials/1/proxy", lambda:
                                    dialog.get_by_role("button", name="保存", exact=True).click())
            self.assertEqual(body["mode"], mode)
            expect(dialog).not_to_be_visible()
            document = service.snapshot(f"binding-{mode}")
            items = document["credentials"] if isinstance(document, dict) else document
            credential = next(item for item in items if item["id"] == 1)
            # Credentials omit absent Option fields; direct uses the legacy URL sentinel.
            expected_fields = {
                "inherit": {},
                "direct": {"proxyUrl": "direct"},
                "pool": {"proxyId": proxy_id},
                "inline": {"proxyUrl": "http://127.0.0.1:9",
                           "proxyUsername": "dummy-inline",
                           "proxyPassword": " inline password "},
            }
            proxy_fields = {key: value for key, value in credential.items()
                            if key.startswith("proxy")}
            self.assertEqual(proxy_fields, expected_fields[mode])
            status, response = service.request("/api/admin/credentials")
            self.assertEqual(status, 200)
            saved = next(item for item in response["credentials"] if item["id"] == 1)
            self.assertEqual(saved["proxyMode"], mode)
            self.unchanged_binding(session, service, mode)

    def unchanged_binding(self, session, service, mode):
        dialog = session.edit_binding()
        before = (service.directory / "credentials.json").read_bytes()
        def reject_write(request):
            if (request.method == "PUT" and
                    request.url == service.base + "/api/admin/credentials/1/proxy"):
                session.record("unexpected-binding-write", {"url": request.url,
                               "method": request.method}, True)
                self.fail(f"Unchanged {mode} binding issued a PUT request")

        session.page.on("request", reject_write)
        try:
            dialog.get_by_role("button", name="保存", exact=True).click()
            expect(dialog).not_to_be_visible()
            self.assertEqual(before, (service.directory / "credentials.json").read_bytes())
            service.snapshot(f"unchanged-{mode}")
        finally:
            session.page.remove_listener("request", reject_write)

    def conflict_and_delete(self, session, service, proxy_id):
        pool = session.pool()
        expect(pool.get_by_text("被 1 个凭据引用", exact=True)).to_be_visible()
        delete_button = pool.get_by_role("button", name="删除 Renamed E2E proxy", exact=True)
        for close in ("Escape", "取消", "关闭"):
            delete_button.click()
            dialog = session.dialog("删除代理")
            # Visibility precedes Radix layer registration and mount autofocus.
            expect(dialog).to_have_css("pointer-events", "auto")
            expect(dialog.get_by_role("button", name="取消", exact=True)).to_be_focused()
            if close == "Escape":
                session.page.keyboard.press("Escape")
            else:
                dialog.get_by_role("button", name=close, exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(pool).to_be_visible()
            expect(delete_button).to_be_focused()
        delete_button.click()
        dialog = session.dialog("删除代理")
        session.expected.add((f"/api/admin/proxies/{proxy_id}", 409))
        session.mutation("DELETE", f"/api/admin/proxies/{proxy_id}", lambda:
                         dialog.get_by_role("button", name="确认删除").click(), status=409)
        expect(dialog.get_by_role("alert")).to_be_visible()
        expect(dialog.get_by_role("alert")).to_be_visible()
        session.shot("delete-conflict")
        service.snapshot("delete-conflict-unchanged")
        dialog.get_by_role("button", name="取消", exact=True).click()
        expect(dialog).not_to_be_visible()
        expect(pool).to_be_visible()
        expect(delete_button).to_be_focused()
        session.page.keyboard.press("Escape")
        dialog = session.edit_binding()
        dialog.get_by_role("radio", name="使用全局代理配置", exact=True).check()
        session.mutation("PUT", "/api/admin/credentials/1/proxy", lambda:
                         dialog.get_by_role("button", name="保存", exact=True).click())
        expect(dialog).not_to_be_visible()
        pool = session.pool()
        expect(pool.get_by_text("被 0 个凭据引用", exact=True)).to_be_visible()
        pool.get_by_role("button", name="删除 Renamed E2E proxy", exact=True).click()
        dialog = session.dialog("删除代理")
        session.mutation("DELETE", f"/api/admin/proxies/{proxy_id}", lambda:
                         dialog.get_by_role("button", name="确认删除").click())
        expect(dialog).not_to_be_visible()
        expect(pool.get_by_text("代理列表为空", exact=True)).to_be_visible()
        expect(pool.get_by_role("button", name="删除 Renamed E2E proxy", exact=True)).to_have_count(0)
        expect(pool.get_by_role("button", name="新增代理", exact=True)).to_be_focused()
        self.assertIsInstance(service.snapshot("deleted-back-to-array"), list)
        session.page.keyboard.press("Escape")

    def cancel_add(self, session, service):
        before = (service.directory / "credentials.json").read_bytes()
        session.page.get_by_role("button", name="添加凭据", exact=True).click()
        dialog = session.dialog("添加凭据")
        for name in MODES:
            dialog.get_by_role("radio", name=name, exact=True).check()
        dialog.get_by_role("button", name="取消", exact=True).click()
        expect(dialog).not_to_be_visible()
        self.assertEqual(before, (service.directory / "credentials.json").read_bytes())
        submits = [event for event in session.events if event["kind"] == "response" and
                   event["detail"].get("method") == "POST" and
                   urlsplit(event["detail"]["url"]).path == "/api/admin/credentials"]
        self.assertEqual(submits, [])

    def test_02_global_long_content_visual_matrix(self):
        """Given all four sources and long data, each viewport/theme stays usable."""
        with private_fixture("B-global-long", global_proxy=True) as service:
            with browser_session(self.browser, service) as session:
                session.login()
                status, response = service.request("/api/admin/credentials")
                self.assertEqual(status, 200)
                self.assertTrue(response["globalProxyConfigured"])
                self.assertEqual([item["proxyMode"] for item in response["credentials"]],
                                 ["inherit", "direct", "pool", "inline"])
                for width, height in ((1440, 900), (390, 844), (320, 568)):
                    for theme in ("light", "dark"):
                        with self.subTest(viewport=f"{width}x{height}", theme=theme):
                            session.page.reload(wait_until="networkidle")
                            try:
                                self.visual_matrix(session, width, height, theme)
                            except BaseException:
                                session.shot(f"{width}x{height}-{theme}-failure")
                                raise
                service.snapshot("visual-final")
                session.assert_clean()

    def visual_matrix(self, session, width, height, theme):
        page = session.page
        page.set_viewport_size({"width": width, "height": height})
        page.emulate_media(reduced_motion="reduce")
        if page.locator("html").evaluate("node => node.classList.contains('dark')") != (theme == "dark"):
            page.get_by_role("button", name="切换主题", exact=True).click()
        assert page.locator("html").evaluate("node => node.classList.contains('dark')") == (theme == "dark")
        label = f"{width}x{height}-{theme}"
        expect(page.locator('[data-testid^="credential-row-"]')).to_have_count(4)
        page.screenshot(path=session.service.artifacts / f"{label}-dashboard.png", full_page=True)
        widths = page.locator('[data-testid^="credential-row-"]').evaluate_all("""nodes =>
          nodes.map(node => ({client:node.clientWidth, scroll:node.scrollWidth}))""")
        save_json(session.service.artifacts / f"{label}-page-width.json", widths)
        assert all(item["scroll"] <= item["client"] + 1 for item in widths), widths
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), label
        row = session.expand(3)
        source = row.get_by_test_id("credential-proxy-source")
        expect(source).to_contain_text(LONG_NAME)
        expect(row.locator('[id="credential-detail-3"] > p').filter(has_text="long-identity-")).to_contain_text("long-identity-" * 18 + "@example.invalid")
        assert row.evaluate("n => n.scrollWidth <= n.clientWidth + 1"), label
        assert source.evaluate("n => n.scrollWidth <= n.clientWidth + 1"), label
        page.screenshot(path=session.service.artifacts / f"{label}-expanded.png", full_page=True)
        row.locator('[id="credential-detail-3"]').evaluate("""n => scrollTo(0,
          n.getBoundingClientRect().top + scrollY - document.querySelector('header').offsetHeight - 8)""")
        session.shot(label + "-expanded-viewport")
        pool = session.pool()
        expect(pool.get_by_text(LONG_NAME, exact=True)).to_be_visible()
        session.layout(pool, label + "-pool")
        self.visual_delete(session, pool, label)
        pool.get_by_role("button", name="新增代理", exact=True).click()
        create = session.dialog("新增代理")
        session.layout(create, label + "-create")
        session.focus_trap(create)
        page.keyboard.press("Escape")
        session.restored_focus(pool.get_by_role("button", name="新增代理", exact=True), label + "-create-close")
        pool.get_by_role("button", name="编辑 " + LONG_NAME, exact=True).click()
        edit = session.dialog("编辑代理")
        edit.get_by_label("密码操作").select_option("replace")
        session.layout(edit, label + "-edit")
        edit.get_by_role("button", name="取消", exact=True).click()
        session.restored_focus(pool.get_by_role("button", name="编辑 " + LONG_NAME, exact=True), label + "-edit-close")
        page.keyboard.press("Escape")
        session.restored_focus(page.get_by_role("button", name="代理列表", exact=True), label + "-pool-close")
        self.visual_binding(session, label)
        page.get_by_role("button", name="添加凭据", exact=True).click()
        add = session.dialog("添加凭据")
        add.get_by_role("radio", name="高级：内联地址", exact=True).check()
        add.get_by_label("内联代理地址", exact=True).fill(LONG_URL)
        session.layout(add, label + "-add-cancel")
        add.get_by_role("button", name="取消", exact=True).click()
        session.restored_focus(page.get_by_role("button", name="添加凭据", exact=True), label + "-add-close")

    def visual_delete(self, session, pool, label):
        before = (session.service.directory / "credentials.json").read_bytes()
        trigger = pool.get_by_role("button", name="删除 " + LONG_NAME, exact=True)
        trigger.click()
        dialog = session.dialog("删除代理")
        expect(dialog).to_have_css("pointer-events", "auto")
        cancel = dialog.get_by_role("button", name="取消", exact=True)
        expect(cancel).to_be_focused()
        measurements = session.layout(dialog, label + "-delete", "button")
        box = measurements["box"]
        self.assertGreaterEqual(box["x"], 16)
        self.assertLessEqual(box["right"], measurements["width"] - 16)
        self.assertGreaterEqual(box["y"], 16)
        self.assertLessEqual(box["bottom"], measurements["height"] - 16)
        self.assertTrue(any(scroller["top"] > 0 for scroller in measurements["scrollers"]),
                        "Long delete description must scroll inside a fixed header/footer")
        for name in ("取消", "确认删除"):
            button = dialog.get_by_role("button", name=name, exact=True)
            expect(button).to_be_in_viewport()
            expect(button).to_be_enabled()
            self.assertTrue(button.evaluate("""node => {
              const box = node.getBoundingClientRect();
              return node.contains(document.elementFromPoint(box.x + box.width / 2,
                box.y + box.height / 2));
            }"""), f"{name} is obscured")
        cancel.click()
        expect(dialog).not_to_be_visible()
        expect(trigger).to_be_focused()
        self.assertEqual(before, (session.service.directory / "credentials.json").read_bytes())

    def visual_binding(self, session, label):
        dialog = session.edit_binding(3)
        expect(dialog.get_by_text("已配置全局代理", exact=True)).to_be_visible()
        expect(dialog.get_by_role("radio", name="使用指定代理", exact=True)).to_be_checked()
        session.layout(dialog, label + "-binding-pool")
        dialog.get_by_role("radio", name="高级：内联地址", exact=True).check()
        dialog.get_by_label("内联代理地址", exact=True).fill(LONG_URL)
        session.layout(dialog, label + "-binding-inline")
        session.focus_trap(dialog)
        session.page.keyboard.press("Escape")
        session.restored_focus(session.row(3).get_by_role("button", name="修改代理", exact=True), label + "-binding-close")
        expect(session.row(3).get_by_role("button", name="凭据 #3 详情", exact=True)).to_have_attribute("aria-expanded", "true")


    def test_03_compact_list_real_http_and_visual(self):
        """Given 25 local keys, manage compact rows without upstream operations."""
        with private_fixture("C-compact-list", compact=True) as service:
            with browser_session(self.browser, service) as session:
                session.login()
                page = session.page
                self.assert_rows(page, range(1, 13))
                expect(page.get_by_text("第 1 / 3 页，命中 25 项", exact=True)).to_be_visible()
                self.assertEqual(page.locator('[aria-expanded="true"][aria-controls^="credential-"]').count(), 0)
                expect(page.get_by_test_id("credential-disabled-reason")).to_have_count(0)
                expect(session.row(4).get_by_test_id("credential-disabled-summary")).to_contain_text("人工禁用")
                expect(session.row(5).get_by_test_id("credential-proxy-summary")).to_contain_text("OfficeProxy")
                problems = self.mode_transitions(session, service)
                self.cross_page_selection(session)
                self.search_filters(session)
                self.local_mutations(session, service)
                self.cancel_global_clear(session, service)
                forbidden = [event for event in session.events if event["kind"] == "request" and
                             any(part in urlsplit(event["detail"]["url"]).path
                                 for part in ("/balance", "/refresh", "/verify", "/probe", "/messages"))]
                self.assertEqual(forbidden, [], "Unexpected upstream-oriented browser operation")
                service.snapshot("final")
                session.assert_clean()
                self.assertEqual(problems, [], "Strict visual acceptance failed; see visual-metrics.json")

    def assert_rows(self, page, ids):
        rows = page.locator('[data-testid^="credential-row-"]')
        expected = [f"credential-row-{number}" for number in ids]
        expect(rows).to_have_count(len(expected))
        self.assertEqual(rows.evaluate_all("nodes => nodes.map(n => n.dataset.testid)"), expected)

    def assert_mode(self, session, service, mode):
        page = session.page
        label = "优先级模式" if mode == "priority" else "均衡负载"
        expect(page.get_by_role("button", name=label, exact=True)).to_be_enabled()
        status, response = service.request("/api/admin/config/load-balancing")
        self.assertEqual((status, response), (200, {"mode": mode}))
        status, listing = service.request("/api/admin/credentials")
        self.assertEqual(status, 200)
        self.assertEqual(listing["currentId"], 1)
        self.assertTrue(next(item for item in listing["credentials"] if item["id"] == 1)["isCurrent"])
        self.assert_rows(page, range(1, 13))
        overview = page.locator('[aria-label="凭据概览"]')
        indicators = page.get_by_text("当前选定", exact=True)
        if mode == "priority":
            expect(overview).to_contain_text("当前选定 #1")
            expect(session.row(1).get_by_text("当前选定", exact=True)).to_be_visible()
            expect(indicators).to_have_count(1)
        else:
            expect(overview).not_to_contain_text("当前选定")
            expect(overview).not_to_contain_text("#1")
            expect(indicators).to_have_count(0)
        for number in range(1, 13):
            row = session.row(number)
            summary = row.locator(":scope > div").first
            expect(summary.get_by_text("启用", exact=True)).to_have_count(0)
            expect(summary.get_by_text("已禁用", exact=True)).to_have_count(0)
            expect(row.get_by_role("switch", name=f"启用凭据 #{number}", exact=True)).to_be_checked(checked=number % 4 != 0)
            if mode == "priority":
                expect(summary.get_by_text(f"优先级 {number}", exact=True)).to_be_visible()
            else:
                expect(summary.get_by_text(re.compile("优先级"))).to_have_count(0)
        expect(session.row(4).get_by_test_id("credential-disabled-summary")).to_contain_text("人工禁用")
        shadows = [session.row(number).evaluate("n => getComputedStyle(n).boxShadow") for number in (1, 2)]
        self.assertEqual(shadows[0] == shadows[1], mode == "balanced", shadows)
        save_json(service.artifacts / f"{mode}-indicators.json", {"currentId": listing["currentId"], "shadows": shadows})

    def switch_mode(self, session, service, mode):
        before = "优先级模式" if mode == "balanced" else "均衡负载"
        body = session.mutation("PUT", "/api/admin/config/load-balancing", lambda:
                                session.page.get_by_role("button", name=before, exact=True).click())
        self.assertEqual(body, {"mode": mode})
        self.assert_mode(session, service, mode)
        config = json.loads((service.directory / "config.json").read_text())
        self.assertEqual(config["loadBalancingMode"], mode)
        save_json(service.artifacts / f"{mode}-config.json", config)
        service.snapshot(f"{mode}-credentials")
        # A toast under the last click pauses its dismissal while hovered.
        session.page.mouse.move(0, 0)
        expect(session.page.locator('[data-sonner-toast]')).to_have_count(0)

    def mode_transitions(self, session, service):
        self.assert_mode(session, service, "priority")
        problems = self.compact_visuals(session, "priority")
        self.switch_mode(session, service, "balanced")
        problems.extend(self.compact_visuals(session, "balanced"))
        row = session.expand(1)
        expect(row.get_by_text("负载相同时优先，数字越小越优先", exact=True)).to_be_visible()
        expect(row.get_by_role("button", name="提高优先级", exact=True)).to_be_enabled()
        expect(row.get_by_role("button", name="降低优先级", exact=True)).to_be_enabled()
        for priority in (0, 1):
            row.get_by_role("button", name="编辑优先级", exact=True).click()
            editor = row.get_by_role("spinbutton", name="优先级", exact=True)
            expect(editor).to_have_value(str(1 if priority == 0 else 0))
            editor.fill(str(priority))
            body = session.mutation("POST", "/api/admin/credentials/1/priority", lambda:
                                    row.get_by_role("button", name="保存优先级", exact=True).click())
            self.assertEqual(body, {"priority": priority})
            expect(row.get_by_role("button", name="编辑优先级", exact=True)).to_have_text(f"{priority}（编辑）")
            saved = service.snapshot(f"balanced-priority-{priority}")["credentials"]
            entry = next(item for item in saved if item["id"] == 1)
            # Credentials serializes the default zero priority by omitting it.
            if priority == 0:
                self.assertNotIn("priority", entry)
            else:
                self.assertEqual(entry["priority"], priority)
            status, listing = service.request("/api/admin/credentials")
            self.assertEqual(status, 200)
            self.assertEqual([item["id"] for item in listing["credentials"]], list(range(1, 26)))
            self.assertEqual(listing["credentials"][0]["priority"], priority)
        session.page.mouse.move(0, 0)
        expect(session.page.locator('[data-sonner-toast]')).to_have_count(0)
        session.page.screenshot(path=service.artifacts / "balanced-expanded-detail.png", full_page=True)
        row.get_by_role("button", name="凭据 #1 详情", exact=True).click()
        self.assert_mode(session, service, "balanced")
        self.switch_mode(session, service, "priority")
        row = session.expand(1)
        expect(row.get_by_role("button", name="编辑优先级", exact=True)).to_have_text("1（编辑）")
        expect(row.get_by_text("负载相同时优先，数字越小越优先", exact=True)).to_have_count(0)
        session.page.screenshot(path=service.artifacts / "priority-restored-detail.png", full_page=True)
        row.get_by_role("button", name="凭据 #1 详情", exact=True).click()
        return problems

    def compact_visuals(self, session, mode):
        page, metrics, problems = session.page, [], []
        for width, height in ((1440, 900), (390, 844), (320, 568)):
            for theme in ("light", "dark"):
                page.set_viewport_size({"width": width, "height": height})
                page.emulate_media(reduced_motion="reduce")
                if page.locator("html").evaluate("n => n.classList.contains('dark')") != (theme == "dark"):
                    page.get_by_role("button", name="切换主题", exact=True).click()
                page.evaluate("scrollTo(0, 0)")
                self.assert_rows(page, range(1, 13))
                label = f"{mode}-{width}x{height}-{theme}"
                page.screenshot(path=session.service.artifacts / f"{label}-full.png",
                                full_page=True, animations="disabled")
                measure = self.measure_compact(page)
                measure.update(viewport=f"{width}x{height}", theme=theme, mode=mode)
                failures = self.visual_failures(measure, width)
                measure["failures"] = failures
                metrics.append(measure)
                problems.extend(f"{label}: {failure}" for failure in failures)
                save_json(session.service.artifacts / f"{mode}-visual-metrics.json", metrics)
        page.set_viewport_size({"width": 1440, "height": 900})
        return problems

    def measure_compact(self, page):
        return page.evaluate("""() => {
          const box = n => {const b=n.getBoundingClientRect(); return {
            x:b.x,y:b.y,right:b.right,bottom:b.bottom,width:b.width,height:b.height}};
          const content = n => {const b=box(n),s=getComputedStyle(n); return {
            left:b.x+parseFloat(s.paddingLeft),right:b.right-parseFloat(s.paddingRight)}};
          const main=document.querySelector('main'), header=document.querySelector('header > div');
          const rows=[...document.querySelectorAll('[data-testid^="credential-row-"]')];
          const controls=[...document.querySelectorAll('header button,main button,main input,main select')]
            .filter(n => n.getBoundingClientRect().height).map(n => {
              const target=n.closest('label') || n;
              return {name:n.getAttribute('aria-label')||n.textContent, ...box(target)};});
          const headerBox=box(document.querySelector('header'));
          return {header:content(header),main:content(main),
            navRight:box(document.querySelector('header > div > div:last-child')).right,
            documentWidth:document.documentElement.scrollWidth,viewport:innerWidth,
            rows:rows.map(box),listHeight:box(rows.at(-1)).bottom-box(rows[0]).y,
            completeRows:rows.filter(n => {const b=box(n); return b.y>=headerBox.bottom && b.bottom<=innerHeight}).length,
            bodyFonts:rows.map(n => parseFloat(getComputedStyle(n.firstElementChild).fontSize)),controls};
        }""")

    def visual_failures(self, measure, width):
        failures = []
        for edge in ("left", "right"):
            if abs(measure["header"][edge] - measure["main"][edge]) > 1:
                failures.append(f"{edge} content misaligned: {measure['header']} vs {measure['main']}")
        if width == 1440 and abs(measure["navRight"] - measure["main"]["right"]) > 1:
            failures.append("Desktop navigation right edge is not aligned")
        if measure["documentWidth"] > width:
            failures.append(f"Document overflow: {measure['documentWidth']} > {width}")
        if width == 1440 and measure["listHeight"] > 720:
            failures.append(f"12 ordinary rows height {measure['listHeight']} > 720")
        if width == 1440 and measure["completeRows"] < 8:
            failures.append(f"First viewport has {measure['completeRows']} complete rows < 8")
        if any(abs(size - 14) > 1 for size in measure["bodyFonts"]):
            failures.append(f"Body text is not approximately 14px: {measure['bodyFonts']}")
        minimum = 32 if width == 1440 else 44
        failures.extend(f"Click target {control['name']!r}: height {control['height']} < {minimum}"
                        for control in measure["controls"] if control["height"] < minimum)
        return failures

    def cross_page_selection(self, session):
        page = session.page
        page.get_by_role("checkbox", name="选择当前页", exact=True).click()
        expect(page.get_by_role("status").filter(has_text="已选 12 项")).to_be_visible()
        page.get_by_role("button", name="下一页", exact=True).click()
        self.assert_rows(page, range(13, 25))
        page.get_by_role("checkbox", name="选择凭据 #13", exact=True).click()
        expect(page.get_by_role("checkbox", name="选择当前页", exact=True)).to_have_attribute("data-state", "indeterminate")
        expect(page.get_by_role("status").filter(has_text="已选 13 项")).to_be_visible()
        page.screenshot(path=session.service.artifacts / "cross-page-selection.png", full_page=True)
        page.get_by_role("button", name="上一页", exact=True).click()
        page.get_by_role("checkbox", name="选择当前页", exact=True).click()
        expect(page.get_by_role("status").filter(has_text="已选 1 项")).to_be_visible()
        self.assertEqual(page.get_by_role("checkbox", checked=True).count(), 0)
        page.get_by_role("button", name="下一页", exact=True).click()
        expect(page.get_by_role("checkbox", name="选择凭据 #13", exact=True)).to_be_checked()
        page.get_by_role("checkbox", name="选择当前页", exact=True).click()
        expect(page.get_by_role("status").filter(has_text="已选 12 项")).to_be_visible()
        page.get_by_role("button", name="清空选择", exact=True).click()
        expect(page.get_by_role("status").filter(has_text="已选 0 项")).to_be_visible()

    def search_filters(self, session):
        page = session.page
        search = page.get_by_role("searchbox", name="搜索凭据", exact=True)
        for query, ids in (("  USER01@EXAMPLE.INVALID  ", [1]), ("25", [25]),
                           ("  oFfIcEpRoXy ", [5]), ("absent-match", []), ("   ", range(1, 13))):
            search.fill(query)
            self.assert_rows(page, ids)
            expect(page.get_by_role("status").filter(has_text="已选 0 项")).to_be_visible()
            if not ids:
                expect(page.get_by_text("没有匹配的凭据", exact=True)).to_be_visible()
                expect(page.get_by_role("checkbox", name="选择当前页", exact=True)).to_be_disabled()
                expect(page.get_by_text("第 1 / 1 页，命中 0 项", exact=True)).to_be_visible()
        search.fill("")
        for status, ids, total in (("disabled", [4, 8, 12, 16, 20, 24], 6),
                                   ("enabled", [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15], 19)):
            page.get_by_role("combobox", name="凭据状态", exact=True).select_option(status)
            self.assert_rows(page, ids)
            expect(page.get_by_text(f"第 1 / {(total + 11) // 12} 页，命中 {total} 项", exact=True)).to_be_visible()
        page.get_by_role("button", name="下一页", exact=True).click()
        page.get_by_role("checkbox", name="选择凭据 #25", exact=True).click()
        search.fill("user")
        expect(page.get_by_role("status").filter(has_text="已选 0 项")).to_be_visible()
        expect(page.get_by_text("第 1 / 2 页，命中 19 项", exact=True)).to_be_visible()
        page.get_by_role("checkbox", name="选择当前页", exact=True).click()
        page.get_by_role("combobox", name="凭据状态", exact=True).select_option("all")
        expect(page.get_by_role("status").filter(has_text="已选 0 项")).to_be_visible()
        search.fill("")
        self.assert_rows(page, range(1, 13))

    def local_mutations(self, session, service):
        page = session.page
        row = session.expand(1)
        expect(session.row(2).get_by_role("button", name="凭据 #2 详情", exact=True)).to_have_attribute("aria-expanded", "false")
        page.evaluate("scrollTo(0, 0)")
        page.screenshot(path=service.artifacts / "ordinary-expanded-detail.png", full_page=True)
        trigger = row.get_by_role("button", name="凭据 #1 详情", exact=True)
        trigger.click()
        expect(trigger).to_have_attribute("aria-expanded", "false")
        toggle = row.get_by_role("switch", name="启用凭据 #1", exact=True)
        for disabled in (True, False):
            body = session.mutation("POST", "/api/admin/credentials/1/disabled", toggle.click)
            self.assertEqual(body, {"disabled": disabled})
            expect(toggle).to_be_checked(checked=not disabled)
            document = service.snapshot(f"local-disabled-{disabled}")
            self.assertEqual(next(item for item in document["credentials"] if item["id"] == 1)["disabled"], disabled)
            expect(trigger).to_have_attribute("aria-expanded", "false")
        for number in (1, 4, 8):
            page.get_by_role("checkbox", name=f"选择凭据 #{number}", exact=True).click()
        before = (service.directory / "credentials.json").read_bytes()
        requests_before = len(self.write_requests(session))
        confirmations = []
        def cancel(dialog):
            confirmations.append(dialog.message)
            dialog.dismiss()
        page.once("dialog", cancel)
        page.get_by_role("button", name="批量删除", exact=True).click()
        self.assertEqual(confirmations, ["已选 3 项，实际删除 2 个已禁用凭据，跳过 1 个未禁用凭据。此操作无法撤销。"])
        self.assertEqual(len(self.write_requests(session)), requests_before)
        self.assertEqual(before, (service.directory / "credentials.json").read_bytes())
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_response(lambda r: r.request.method == "DELETE" and urlsplit(r.url).path == "/api/admin/credentials/8"):
            page.get_by_role("button", name="批量删除", exact=True).click()
        expect(page.get_by_role("status").filter(has_text="已选 0 项")).to_be_visible()
        deleted = self.write_requests(session)[requests_before:]
        self.assertEqual([(entry["method"], urlsplit(entry["url"]).path) for entry in deleted],
                         [("DELETE", "/api/admin/credentials/4"), ("DELETE", "/api/admin/credentials/8")])
        remaining = service.snapshot("batch-delete")["credentials"]
        self.assertEqual([item["id"] for item in remaining], [number for number in range(1, 26) if number not in (4, 8)])

    def write_requests(self, session):
        return [event["detail"] for event in session.events if event["kind"] == "request" and
                urlsplit(event["detail"]["url"]).path.startswith("/api/admin/") and event["detail"]["method"] != "GET"]

    def cancel_global_clear(self, session, service):
        page = session.page
        page.get_by_role("searchbox", name="搜索凭据", exact=True).fill("user01")
        self.assert_rows(page, [1])
        before = (service.directory / "credentials.json").read_bytes()
        requests_before = len(self.write_requests(session))
        messages = []
        def cancel(dialog):
            messages.append(dialog.message)
            dialog.dismiss()
        page.once("dialog", cancel)
        page.get_by_role("button", name="清除全库已禁用凭据（4）", exact=True).click()
        self.assertEqual(messages, ["确定清除全库 4 个已禁用凭据？不受搜索、分页或选择限制。此操作无法撤销。"])
        page.get_by_role("button", name="提示词注入", exact=True).click()
        dialog = session.dialog("提示词注入")
        dialog.get_by_role("button", name="取消", exact=True).click()
        expect(dialog).not_to_be_visible()
        session.restored_focus(page.get_by_role("button", name="提示词注入", exact=True), "prompt-cancel")
        self.assertEqual(len(self.write_requests(session)), requests_before)
        self.assertEqual(before, (service.directory / "credentials.json").read_bytes())


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, type=Path,
                        help="Linux ARM64 release kiro-rs compatible with Alpine/musl in rust:1.92-alpine, "
                             "with the current embedded Admin dist")
    parser.add_argument("--artifacts", required=True, type=Path,
                        help="New, nonexistent private output directory (never overwritten)")
    OPTIONS = parser.parse_args()
    OPTIONS.binary = OPTIONS.binary.expanduser().resolve(strict=True)
    OPTIONS.artifacts = OPTIONS.artifacts.expanduser().absolute()
    OPTIONS.artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    save_json(OPTIONS.artifacts / "run.json", {
        "command": sys.argv, "binary": str(OPTIONS.binary),
        "sha256": hashlib.sha256(OPTIONS.binary.read_bytes()).hexdigest(),
        "python": sys.version, "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "scope": "real Rust Admin HTTP + browser + private disk; no upstream connectivity assertion"})
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProxyAdminE2E)
    if suite.countTestCases() != 3:
        raise RuntimeError("Expected exactly three serial fixture scenarios")
    with (OPTIONS.artifacts / "unittest.log").open("w") as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    failed_ids = {getattr(test, 'test_case', test).id()
                  for test, _ in result.failures + result.errors}
    summary = {"testsRun": result.testsRun, "failedTests": len(failed_ids),
               "failedChecks": len(result.failures), "errors": len(result.errors),
               "skipped": len(result.skipped),
               "passed": max(0, result.testsRun - len(failed_ids) - len(result.skipped))}
    save_json(OPTIONS.artifacts / "summary.json", summary)
    print((OPTIONS.artifacts / "unittest.log").read_text())
    print(json.dumps(summary), flush=True)
    return 0 if result.wasSuccessful() and result.testsRun == 3 and not result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
