"""Synthetic Admin UI scenarios; never contact Rust, real credentials or upstream."""

import argparse
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

UI_ROOT = Path(__file__).resolve().parents[1]
FAKE_KEY = "synthetic-admin-key-not-a-real-secret"
REASON = "TemporarilySuspended"


def credential(auth_method="social"):
    return {
        "id": 1, "priority": 0, "disabled": True, "failureCount": 1,
        "isCurrent": False, "expiresAt": None, "authMethod": auth_method,
        "hasProfileArn": False, "successCount": 0, "lastUsedAt": None,
        "hasProxy": False, "proxyMode": "direct", "refreshFailureCount": 0,
        "endpoint": "ide", "disabledReason": REASON,
    }


class StaticHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/admin/'):
            self.send_error(404)
            return
        self.path = self.path.removeprefix('/admin')
        super().do_GET()

    def log_message(self, *_args):
        pass


@contextmanager
def static_server():
    dist = UI_ROOT / "dist"
    if not (dist / "index.html").is_file():
        raise RuntimeError("Missing admin-ui/dist/index.html; run npm run build first")
    handler = partial(StaticHandler, directory=str(dist))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", dist
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class SyntheticApi:
    def __init__(self, origin, dist, auth_method="social", reject=False):
        self.origin = origin
        self.static_paths = {"/admin/"} | {
            "/admin/" + path.relative_to(dist).as_posix()
            for path in dist.rglob("*") if path.is_file()
        }
        self.item = credential(auth_method)
        self.reject = reject
        self.breaches = []
        self.reads = 0
        self.writes = []

    def route(self, route):
        request = route.request
        parsed = urlsplit(request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin != self.origin:
            return self.block(route, "external request")
        if parsed.path.startswith("/api/"):
            return self.api(route, parsed.path)
        if request.method == "GET" and parsed.path in self.static_paths:
            return route.continue_()
        self.block(route, "unknown static request")

    def block(self, route, reason):
        self.breaches.append(f"{reason}: {route.request.method} {route.request.url}")
        route.abort("blockedbyclient")

    def api(self, route, path):
        request = route.request
        if request.headers.get("x-api-key") != FAKE_KEY:
            return self.block(route, "unexpected API authentication")
        if request.method == "GET" and path == "/api/admin/credentials":
            self.reads += 1
            return route.fulfill(json={
                "globalProxyConfigured": False, "total": 1,
                "available": int(not self.item["disabled"]), "currentId": 0,
                "credentials": [self.item],
            })
        if request.method == "GET" and path == "/api/admin/config/load-balancing":
            return route.fulfill(json={"mode": "priority"})
        if request.method == "GET" and path == "/api/admin/proxies":
            return route.fulfill(json={"proxies": []})
        if request.method == "POST" and path in {
            "/api/admin/credentials/1/disabled", "/api/admin/credentials/1/reset",
        }:
            return self.mutate(route, path)
        self.block(route, "unknown API request")

    def mutate(self, route, path):
        body = route.request.post_data
        expected_body = {"disabled": False} if path.endswith("/disabled") else None
        actual_body = json.loads(body) if body else None
        if actual_body != expected_body:
            return self.block(route, "unexpected mutation body")
        self.writes.append((path, actual_body))
        if self.reject:
            return route.fulfill(status=400, json={
                "error": {"type": "invalid_request_error", "message": "Synthetic rejection"},
            })
        self.item.update(disabled=False, disabledReason=None, failureCount=0,
                         refreshFailureCount=0)
        route.fulfill(json={"success": True, "message": "合成测试：已解除本地禁用"})


@contextmanager
def isolated_page(browser, origin, api, width):
    context = browser.new_context(viewport={"width": width, "height": 1000},
                                  service_workers="block")
    context.route("**/*", api.route)
    context.add_init_script(f"localStorage.setItem('adminApiKey', {json.dumps(FAKE_KEY)})")
    page = context.new_page()
    errors, failed_requests, console_errors = [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("requestfailed", lambda request: failed_requests.append(request.url))
    page.on("console", lambda message: console_errors.append({
        "text": message.text, "url": message.location.get("url", "")})
        if message.type == "error" else None)
    try:
        page.goto(origin + "/admin/", wait_until="networkidle")
        yield page
        expected_urls = {origin + "/api/admin/credentials/1/" + action for action in ("disabled", "reset")}
        unexpected_console = [event for event in console_errors if not (
            api.reject and event["url"] in expected_urls and "status of 400" in event["text"])]
        assert not api.breaches, api.breaches
        assert not errors, errors
        assert not failed_requests, failed_requests
        assert not unexpected_console, unexpected_console
    finally:
        print(f"Browser events: console.error={len(console_errors)} pageerror={len(errors)} requestfailed={len(failed_requests)}")
        context.close()


def assert_reason(page):
    row = page.get_by_test_id("credential-row-1")
    trigger = row.get_by_role("button", name="凭据 #1 详情", exact=True)
    if trigger.get_attribute("aria-expanded") != "true":
        expect(row.get_by_test_id("credential-disabled-summary")).to_contain_text("上游临时安全锁定")
        expect(row.get_by_test_id("credential-disabled-reason")).to_have_count(0)
        trigger.click()
    expect(trigger).to_have_attribute("aria-expanded", "true")
    reason = row.get_by_test_id("credential-disabled-reason")
    expect(reason).to_be_visible()
    for text in ["上游临时安全锁定", "TEMPORARILY_SUSPENDED",
                 "触发原因和恢复时间未知，可联系官方支持",
                 "人工启用/重置仅解除本地禁用，不代表上游解锁"]:
        expect(reason).to_contain_text(text)
    bounds = reason.bounding_box()
    assert bounds and bounds["x"] >= 0
    assert bounds["x"] + bounds["width"] <= page.viewport_size["width"], bounds
    assert reason.evaluate("el => el.scrollWidth <= el.clientWidth"), "reason overflow"
    for paragraph in reason.locator("p").all():
        expect(paragraph).to_be_visible()
        assert paragraph.evaluate("el => el.scrollWidth <= el.clientWidth")
    return reason


def visual_scenario(browser, origin, dist, output, width, auth_method):
    api = SyntheticApi(origin, dist, auth_method)
    with isolated_page(browser, origin, api, width) as page:
        reason = assert_reason(page)
        page.screenshot(path=str(output / f"page-{auth_method}-{width}.png"), full_page=True)
        reason.screenshot(path=str(output / f"reason-{auth_method}-{width}.png"))
        assert not api.writes
        overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
        print(f"PASS reason {auth_method} width={width}; unrelated page overflow={overflow}")


def recovery_scenario(browser, origin, dist, output, width, action, reject):
    api = SyntheticApi(origin, dist, reject=reject)
    with isolated_page(browser, origin, api, width) as page:
        assert_reason(page)
        reads_before = api.reads
        control = page.get_by_role("switch") if action == "enable" else page.get_by_role(
            "button", name="重置失败", exact=True)
        control.click()
        if reject:
            expect(page.get_by_text("操作失败: Request failed with status code 400", exact=True)).to_be_visible()
            assert_reason(page)
            assert api.item["disabled"] and api.item["disabledReason"] == REASON
            page.screenshot(path=str(output / f"rejected-{action}-{width}.png"), full_page=True)
        else:
            expect(page.get_by_test_id("credential-disabled-reason")).to_have_count(0)
            expect(page.get_by_role("switch")).to_be_checked()
            assert api.reads > reads_before, "mutation did not refetch list"
            assert not api.item["disabled"] and api.item["disabledReason"] is None
        expected_path = "/api/admin/credentials/1/" + ("disabled" if action == "enable" else "reset")
        assert api.writes == [(expected_path, {"disabled": False} if action == "enable" else None)]
        page.reload(wait_until="networkidle")
        assert api.reads > reads_before
        if reject:
            assert_reason(page)
            expect(page.get_by_role("switch")).not_to_be_checked()
        else:
            expect(page.get_by_role("switch")).to_be_checked()
            expect(page.get_by_test_id("credential-disabled-reason")).to_have_count(0)
        print(f"PASS {action} reject={reject} width={width}; refreshed synthetic state verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=UI_ROOT / "node_modules/.cache/suspension-e2e")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(UI_ROOT):
        parser.error("Screenshots must remain inside this worktree's admin-ui")
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    with static_server() as (origin, dist), sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            for width in (375, 768, 1440):
                for auth_method in ("social", "api_key"):
                    visual_scenario(browser, origin, dist, output, width, auth_method)
                    count += 1
                for action in ("enable", "reset"):
                    for reject in (False, True):
                        recovery_scenario(browser, origin, dist, output, width, action, reject)
                        count += 1
        finally:
            browser.close()
    assert count == 18, count
    print(f"PASS {count}/18 synthetic browser scenarios; screenshots: {output}")


if __name__ == "__main__":
    main()
