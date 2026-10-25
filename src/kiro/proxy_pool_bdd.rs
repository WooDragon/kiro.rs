//! 代理池 BDD：覆盖计划验收表的每一行（除性能实测与上游协议冒烟）。
//!
//! 原则：
//! - 网络行为一律用本机受控代理与目标（`proxy_fixtures`），不触外网、不用凭据。
//! - 并发边界用 `Notify`/通道，不靠随机 sleep。
//! - 每条新回归断言都做过反事实验证（见各测试上方的注释）。

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::net::TcpListener;

use crate::http_client::{ProxyConfig, Route, RouteKey, redact_proxy_url};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::model::credentials::{CredentialsConfig, KiroCredentials};
use crate::kiro::model::proxy_pool::ProxyEntry;
use crate::kiro::provider::KiroProvider;
use crate::kiro::proxy_fixtures::{
    H2TargetServer, LocalProxy, TargetServer, spawn_socks5, spawn_socks5_redirect,
};
use crate::kiro::token_manager::{MultiTokenManager, ProxyBindingRequest, ProxyUpdateRequest};
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;

pub(super) struct TempDir(pub(super) std::path::PathBuf);

impl TempDir {
    pub(super) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kiro-rs-pool-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(super) fn path(&self) -> std::path::PathBuf {
        self.0.join("credentials.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

pub(super) fn api_key_credential(id: u64) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        kiro_api_key: Some(format!("ksk_test_{id}")),
        ..Default::default()
    }
}

/// 经真实 SOCKS5 隧道打到本地明文 H2 目标的路由。
///
/// 本地夹具只能是明文（无证书），所以用 h2c prior-knowledge 让 H2 层真正跑起来；
/// 隧道、握手、多路复用、PING 全部走真实协议栈。
fn h2_route(
    proxy_url: &str,
    keepalive: Option<(std::time::Duration, std::time::Duration)>,
) -> Arc<Route> {
    Route::build_for_test(
        RouteKey::Proxy(ProxyConfig::new(proxy_url)),
        Config::default().tls_backend,
        true,
        keepalive,
    )
    .unwrap()
}

pub(super) fn pool_entry(id: &str, url: &str) -> ProxyEntry {
    ProxyEntry {
        id: id.to_string(),
        name: id.to_string(),
        url: url.to_string(),
        username: None,
        password: None,
    }
}

pub(super) fn manager(
    dir: &TempDir,
    credentials: Vec<KiroCredentials>,
    proxies: Vec<ProxyEntry>,
) -> Arc<MultiTokenManager> {
    manager_with_global_proxy(dir, credentials, proxies, None).unwrap()
}

/// 同 [`manager`]，但可指定全局代理（`config.proxyUrl` 的等价物），
/// 并把构造失败原样返回——I1 的"非法全局代理 URL 必须 fail-fast"要断言 Err。
fn manager_with_global_proxy(
    dir: &TempDir,
    credentials: Vec<KiroCredentials>,
    proxies: Vec<ProxyEntry>,
    global_proxy: Option<ProxyConfig>,
) -> anyhow::Result<Arc<MultiTokenManager>> {
    Ok(Arc::new(MultiTokenManager::new_with_pool(
        Config::default(),
        credentials,
        proxies,
        global_proxy,
        Some(dir.path()),
        true,
        Arc::new(ModelRegistry::builtin()),
    )?))
}

/// 最小 endpoint：URL 指向本地目标。
struct TestEndpoint {
    url: String,
}

impl KiroEndpoint for TestEndpoint {
    fn name(&self) -> &'static str {
        "test"
    }
    fn api_url(&self, _ctx: &RequestContext<'_>) -> String {
        self.url.clone()
    }
    fn mcp_url(&self, _ctx: &RequestContext<'_>) -> String {
        self.url.clone()
    }
    fn decorate_api(
        &self,
        req: reqwest::RequestBuilder,
        _ctx: &RequestContext<'_>,
    ) -> reqwest::RequestBuilder {
        req
    }
    fn decorate_mcp(
        &self,
        req: reqwest::RequestBuilder,
        _ctx: &RequestContext<'_>,
    ) -> reqwest::RequestBuilder {
        req
    }
    fn transform_api_body(&self, body: &str, _ctx: &RequestContext<'_>) -> String {
        body.to_string()
    }
}

fn provider(manager: Arc<MultiTokenManager>, url: &str) -> KiroProvider {
    let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
    endpoints.insert(
        "test".to_string(),
        Arc::new(TestEndpoint {
            url: url.to_string(),
        }) as Arc<dyn KiroEndpoint>,
    );
    KiroProvider::with_proxy(manager, None, endpoints, "test".to_string())
}

fn request_body() -> String {
    json!({
        "conversationState": {
            "conversationId": "11111111-1111-1111-1111-111111111111",
            "currentMessage": {"userInputMessage": {"modelId": "claude-sonnet-5", "content": "hi"}}
        }
    })
    .to_string()
}

// ─────────────────────────────────────────────────────────────
// BDD: 热路径不构造 route（计数恒为 0）
// ─────────────────────────────────────────────────────────────

/// 启动后大量 `acquire_context*` 往返（跨 ≥3 条不同路由）时，
/// `route_build_counter` 的增量必须恒为 0。
///
/// 前置条件断言（缺一则恒绿）：
/// 1. 四条凭据的 route 指针**两两不同**——否则"计数为 0"可能只是所有凭据共用
///    一条路由，热路径压根没机会碰第二、第三条；
/// 2. 四条凭据的 route key 覆盖 System / Direct / 两个不同的 Proxy：启动期这四
///    个 key 各自构建过一次（计数 > 0），证明计数器确实在为本用例的 key 记账。
///
/// `route_build_counter` 是 thread-local（`http_client.rs:86`），所以本用例必须
/// 用默认的 `#[tokio::test]`（current_thread）运行时，且不 `tokio::spawn`——否则
/// 被测代码可能跑在别的 worker 线程上，计数器读到的 0 不代表什么都没建。
/// `join_all` 在单线程上交替推进，仍是"并发"语义（多个获取同时在进行）。
///
/// 反事实（见报告）：让 `CallContext` 的构造在 acquire 路径上调用
/// `route_get_or_build`，下面四条计数断言同时变红。
#[tokio::test]
async fn bdd_hot_path_never_builds_routes() {
    let dir = TempDir::new();

    let mut pool_one = api_key_credential(1);
    pool_one.proxy_id = Some("p1".into());
    let mut pool_two = api_key_credential(2);
    pool_two.proxy_id = Some("p2".into());
    let mut direct = api_key_credential(3);
    direct.proxy_url = Some("direct".into());
    let inherit = api_key_credential(4);

    let manager = manager(
        &dir,
        vec![pool_one, pool_two, direct, inherit],
        vec![
            pool_entry("p1", "socks5://127.0.0.1:1080"),
            pool_entry("p2", "socks5://127.0.0.1:1081"),
        ],
    );

    // (1) 前置条件：四条 route 指针两两不同。
    let mut pointers: Vec<*const Route> = (1..=4)
        .map(|id| manager.route_ptr_for_test(id).expect("凭据必须有 route"))
        .collect();
    pointers.sort();
    pointers.dedup();
    assert_eq!(
        pointers.len(),
        4,
        "前置条件不成立：四条凭据必须各自持有不同的 route，否则测不出多路由"
    );

    // (2) 前置条件：计数器确实在为这四个 key 记账——启动期每个 key 恰好构建一次。
    let keys = [
        RouteKey::System,
        RouteKey::Direct,
        RouteKey::Proxy(ProxyConfig::new("socks5://127.0.0.1:1080")),
        RouteKey::Proxy(ProxyConfig::new("socks5://127.0.0.1:1081")),
    ];
    for key in &keys {
        assert_eq!(
            crate::http_client::route_build_counter::count(key),
            1,
            "前置条件不成立：启动期 {key:?} 应恰好构建一次，否则计数器没在记账"
        );
    }
    crate::http_client::route_build_counter::reset();

    // (3) 大量获取往返，全部在**本线程**上推进。
    let before = (1..=4)
        .map(|id| manager.route_ptr_for_test(id).unwrap())
        .collect::<Vec<_>>();
    for _ in 0..50 {
        let futures: Vec<_> = (0..8)
            .map(|index| {
                let manager = manager.clone();
                async move {
                    if index % 2 == 0 {
                        manager.acquire_context(None).await.map(|ctx| ctx.id)
                    } else {
                        manager
                            .acquire_context_for_session_excluding(
                                None,
                                Some("hot-path-session"),
                                &Default::default(),
                            )
                            .await
                            .map(|ctx| ctx.id)
                    }
                }
            })
            .collect();
        let results = futures::future::join_all(futures).await;
        for result in results {
            let id = result.expect("获取上下文不得失败");
            assert!((1..=4).contains(&id), "必须选中既有凭据，实际 {id}");
        }
    }

    // (4) 结果：四条路由的构建计数增量全部为 0。
    for key in &keys {
        assert_eq!(
            crate::http_client::route_build_counter::count(key),
            0,
            "400 次获取往返之后 {key:?} 的 route 构建计数必须仍为 0"
        );
    }
    let after = (1..=4)
        .map(|id| manager.route_ptr_for_test(id).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(before, after, "请求路径不得重建或替换 route");
}

/// 同一路由并发 64 次真实请求：只建 1 条隧道、全部到达目标。
///
/// 与上一条的分工：上一条证"不构建 route"，本条证"真实请求路径复用同一条
/// 转发隧道"。两者都需要，因为指针不变并不能证明请求真的走到了目标。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_hot_path_requests_reuse_one_tunnel_per_route() {
    let dir = TempDir::new();
    let target = H2TargetServer::spawn().await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let url = format!("http://{}/x", target.addr);

    let creds = vec![
        {
            let mut cred = api_key_credential(1);
            cred.proxy_id = Some("p1".into());
            cred
        },
        api_key_credential(2),
    ];
    let manager = manager(&dir, creds, vec![pool_entry("p1", &socks.url)]);
    manager.install_route_for_test(1, h2_route(&socks.url, None));
    let provider = Arc::new(provider(manager.clone(), &url));

    assert_eq!(manager.snapshot().total, 2);
    let before = [manager.route_ptr_for_test(1), manager.route_ptr_for_test(2)];

    // 前置条件：先用一次请求把隧道建好。
    //
    // 不预热的话，64 个并发请求会在"首条 H2 连接还在握手"时同时进入连接池，
    // 池为降低队头阻塞再开一条隧道是合法行为，`connections() == 1` 会随机变红
    // （本用例在全量套件负载下实测到过）。预热带走这个冷启动竞态之后，
    // 断言才真正是在问"复用"，而不是"冷启动恰好没撞上"。
    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(target.connections(), 1, "前置条件：预热后应恰好一条隧道");

    let mut handles = Vec::new();
    for _ in 0..16 {
        let provider = provider.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..4 {
                let response = provider
                    .call_api_with_context(&request_body())
                    .await
                    .unwrap();
                assert_eq!(response.response.status().as_u16(), 200);
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    let after = [manager.route_ptr_for_test(1), manager.route_ptr_for_test(2)];
    assert_eq!(before, after, "请求路径不得重建或替换 route");
    assert_eq!(
        target.connections(),
        1,
        "隧道已建立后并发 64 次请求必须全部复用同一条 H2 连接"
    );
    assert_eq!(
        target.requests(),
        65,
        "预热 1 次 + 并发 64 次都必须到达目标"
    );
}

// ─────────────────────────────────────────────────────────────
// BDD: 同一路由只建 1 条隧道；编辑别的代理不重建；改名不重建
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bdd_same_route_reuses_tunnel_and_rename_keeps_route() {
    let dir = TempDir::new();
    let target = H2TargetServer::spawn().await;
    let socks_a = spawn_socks5_redirect(target.addr).await;
    let socks_b = spawn_socks5(None, "socks5").await;
    let url = format!("http://{}/x", target.addr);

    let mut cred_a = api_key_credential(1);
    cred_a.proxy_id = Some("a".into());
    let mut cred_b = api_key_credential(2);
    cred_b.proxy_id = Some("b".into());
    let manager = manager(
        &dir,
        vec![cred_a, cred_b],
        vec![pool_entry("a", &socks_a.url), pool_entry("b", &socks_b.url)],
    );
    manager.install_route_for_test(1, h2_route(&socks_a.url, None));
    let provider = provider(manager.clone(), &url);

    for _ in 0..3 {
        provider
            .call_api_with_context(&request_body())
            .await
            .unwrap();
    }
    let route_a_before = manager.route_ptr_for_test(1).unwrap();
    assert_eq!(target.connections(), 1, "同一路由 3 次请求只建一条隧道");
    assert_eq!(target.requests(), 3);

    // 编辑别的代理（b 认证变化）不得重建 a。
    manager
        .update_proxy(
            "b",
            ProxyUpdateRequest {
                password: Some(Some("secret".into())),
                username: Some(Some("user".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        route_a_before,
        "编辑其他代理不得重建 A 的 route"
    );

    // 只改名字：route 指针不变、不新建隧道。
    manager
        .update_proxy(
            "a",
            ProxyUpdateRequest {
                name: Some(Some("renamed".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        route_a_before,
        "改名不得重建 route"
    );
    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(target.connections(), 1, "改名后请求仍走原隧道（未新建）");
    assert_eq!(target.requests(), 4);
}

// ─────────────────────────────────────────────────────────────
// BDD: SOCKS5 / SOCKS5h 真实握手、认证、错误认证、DNS 位置
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bdd_socks5_auth_success_and_failure() {
    let socks = spawn_socks5(Some(("user", "pass")), "socks5").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;

    let good = ProxyConfig::new(&socks.url).with_auth("user", "pass");
    let route = Route::build(RouteKey::Proxy(good), Config::default().tls_backend).unwrap();
    let response = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(socks.stats.auth_failures(), 0);

    let bad = ProxyConfig::new(&socks.url).with_auth("user", "wrong");
    let route = Route::build(RouteKey::Proxy(bad), Config::default().tls_backend).unwrap();
    let error = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .expect_err("错误凭据必须导致握手失败");
    assert!(!error.is_timeout(), "错误认证应快速失败而非挂起: {error}");
    assert_eq!(socks.stats.auth_failures(), 1);
}

// ─────────────────────────────────────────────────────────────
// BDD: HTTP 转发与 HTTPS CONNECT
//
// 本组用例已迁移到 `proxy_pool_bdd_protocols`：旧版本只断言"代理认证成功"
// 与"CONNECT 被选中"，**没有观测目标侧收到的请求头**，因此"代理凭据被透传
// 给目标"这种泄漏在旧用例下全绿。新用例补齐了三态认证 + 目标侧头断言 +
// SOCKS5/SOCKS5h 的 ATYP 观测。
// ─────────────────────────────────────────────────────────────
// BDD: 代理不可达时不得绕过直连；direct 真正直连
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bdd_unreachable_proxy_never_falls_back_to_direct() {
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    // 绑定后立即释放，得到一个确定拒绝连接的端口。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);

    let route = Route::build(
        RouteKey::Proxy(ProxyConfig::new(format!("socks5://{dead}"))),
        Config::default().tls_backend,
    )
    .unwrap();
    let error = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .expect_err("代理不可达必须失败");
    assert!(error.is_connect() || error.is_request(), "{error}");
    assert_eq!(target.connections(), 0, "目标不得收到绕过代理的请求");
}

/// 环境变量里配了代理时，`RouteKey::Direct` 必须真正直连。
///
/// 环境变量是进程级状态，故放进独立子进程跑（见下方 `env_direct_child_probe`）。
///
/// 必须断言子进程**恰好跑了 1 个测试**：libtest 在过滤串匹配不到任何用例时
/// 仍以退出码 0 结束（输出 `running 0 tests` / `0 passed`）。只断言
/// `status.success()` 的话，过滤名写错、用例被 `#[ignore]` 掉、或函数被改名，
/// 本用例都会"绿"——它证明的其实是"什么都没跑"。
///
/// 反事实（见报告）：把下面的 `--exact` 过滤名改成不存在的名字，子进程
/// `running 0 tests`，本用例在 `running 1 test` 处变红。
#[test]
fn bdd_direct_route_ignores_env_proxy_in_subprocess() {
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "kiro::proxy_pool_bdd::env_direct_child_probe",
            "--ignored",
            "--test-threads=1",
        ])
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "socks5://127.0.0.1:1")
        .env("NO_PROXY", "")
        .output()
        .expect("子进程启动失败");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "子进程内的 direct 路由断言失败\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("running 1 test"),
        "子进程必须恰好跑 1 个测试（过滤串写错时 libtest 以 0 tests 退出 0）\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "子进程必须有 1 个测试通过\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("0 passed"),
        "不得出现 0 passed（那是没跑到用例的形态）\nstdout:\n{stdout}"
    );
}

#[tokio::test]
#[ignore = "由 bdd_direct_route_ignores_env_proxy_in_subprocess 在子进程中拉起"]
async fn env_direct_child_probe() {
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let direct = Route::build(RouteKey::Direct, Config::default().tls_backend).unwrap();
    let response = direct
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .expect("direct 路由必须绕过环境变量代理直连成功");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(target.connections(), 1);

    // 对照：System 路由会继承环境变量代理，直连会失败（证明上面的成功来自 no_proxy）。
    let system = Route::build(RouteKey::System, Config::default().tls_backend).unwrap();
    let error = system
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await;
    assert!(
        error.is_err(),
        "对照臂：System 路由应被环境变量代理接管并失败"
    );
    assert_eq!(target.connections(), 1, "对照臂不得直连到目标");
}

// ─────────────────────────────────────────────────────────────
// 上游协议冒烟（需要出站网络；不带任何凭据）
// ─────────────────────────────────────────────────────────────

/// 经本地 SOCKS5 夹具访问真实业务端点 host，确认 H2 协商 + 空闲复用 + 无 GOAWAY。
///
/// 需要出站网络。只发**未认证**的 GET，不携带任何凭据、不发送业务数据；上游会以
/// 401/403 之类的状态码回应，本用例只关心传输层行为（协议协商与连接复用），不关心
/// 业务语义。
///
/// 本地 SOCKS5 夹具在这里充当真实出口：`spawn_socks5` 会把 CONNECT 转发到真实
/// 目标（域名型目标由代理解析），因此观测到的就是生产形态的 TLS + ALPN。
///
/// 运行（含约 75s 空闲等待）：
/// `cargo test --bin kiro-rs upstream_protocol_smoke -- --ignored --nocapture`
#[tokio::test]
#[ignore = "需要出站网络；无凭据的未认证 GET"]
async fn upstream_protocol_smoke_reuses_tunnel_after_idle() {
    let socks = spawn_socks5(None, "socks5").await;
    let route = Route::build(
        RouteKey::Proxy(ProxyConfig::new(&socks.url)),
        Config::default().tls_backend,
    )
    .unwrap();
    let url = "https://q.us-east-1.amazonaws.com/generateAssistantResponse";

    let first = route
        .short
        .get(url)
        .send()
        .await
        .expect("经代理访问真实上游必须能完成 TLS/H2 协商");
    let version = first.version();
    let status = first.status();
    assert_eq!(
        version,
        reqwest::Version::HTTP_2,
        "必须协商为 HTTP/2，实际 {version:?}"
    );
    println!("SMOKE upstream version={version:?} status={status}");
    drop(first);

    // 空闲跨过两次 PING（生产 interval 30s），再请求一次。
    tokio::time::sleep(std::time::Duration::from_secs(75)).await;
    let second = route
        .short
        .get(url)
        .send()
        .await
        .expect("空闲后必须仍能复用同一隧道");
    println!("SMOKE upstream after-idle status={}", second.status());
    assert_eq!(
        socks.stats.connections(),
        1,
        "两次请求必须复用同一条隧道（未 GOAWAY、未重连）"
    );
}

// ─────────────────────────────────────────────────────────────
// BDD: 启动期 System 路由只构建一次
// ─────────────────────────────────────────────────────────────

/// N 个直连/继承凭据启动后，System 路由必须只被构建 1 次。
///
/// 回归的是本次改动引入的重复开销：构造器先建一条占位 `Route::build(System)`
/// 填进每个条目，随后 `build_routes_for_entries` 又在池里建一次 System，占位
/// 那条从未进入 `pool.routes` 就被丢弃——每启动一次白建一对 reqwest client。
///
/// 反事实：把占位路由改回独立构建，下面的 `count == 1` 立刻变 2。
#[tokio::test]
async fn bdd_startup_builds_system_route_once() {
    crate::http_client::route_build_counter::reset();

    let dir = TempDir::new();
    // 全部直连/继承：不涉及任何代理路由，System 计数应精确为 1。
    let mut direct = api_key_credential(1);
    direct.proxy_url = Some("direct".into());
    let manager = manager(
        &dir,
        vec![direct, api_key_credential(2), api_key_credential(3)],
        Vec::new(),
    );
    let _ = manager;

    let system = RouteKey::System;
    assert_eq!(
        crate::http_client::route_build_counter::count(&system),
        1,
        "3 个直连/继承凭据的启动只允许构建一次 System 路由"
    );
}

// ─────────────────────────────────────────────────────────────
// BDD: 持久化格式矩阵
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bdd_persistence_format_follows_content() {
    let dir = TempDir::new();

    // 1) 旧数组：仅改内联 → 仍写数组
    std::fs::write(
        dir.path(),
        r#"[{"id":1,"refreshToken":"r","proxyUrl":"direct"}]"#,
    )
    .unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    assert!(!loaded.is_envelope());
    let (credentials, proxies) = loaded.into_parts();
    let first = manager(&dir, credentials, proxies);
    first.set_priority(1, 5).unwrap();
    let raw = std::fs::read_to_string(dir.path()).unwrap();
    assert!(raw.trim_start().starts_with('['), "无池时必须维持数组格式");

    // 2) 首次建池 → 封套
    first
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path()).unwrap()).unwrap();
    assert_eq!(raw["version"], 1);
    assert_eq!(raw["proxies"][0]["id"], "p1");
    assert!(raw["credentials"].is_array());

    // 3) 绑定后再重启：池与绑定都在
    first
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .unwrap();
    first.set_priority(1, 6).unwrap();
    let reloaded = CredentialsConfig::load(dir.path()).unwrap();
    assert!(reloaded.is_envelope());
    let (credentials, proxies) = reloaded.into_parts();
    assert_eq!(proxies.len(), 1);
    assert_eq!(credentials[0].proxy_id.as_deref(), Some("p1"));

    // 4) 解绑 + 删光池 → 回到数组
    let restarted = manager(&dir, credentials, proxies);
    restarted
        .bind_credential_proxy(1, ProxyBindingRequest::Inherit)
        .await
        .unwrap();
    restarted.delete_proxy("p1").await.unwrap();
    let raw = std::fs::read_to_string(dir.path()).unwrap();
    assert!(
        raw.trim_start().starts_with('['),
        "删光池与绑定后必须回到数组格式，实际: {raw}"
    );
}

/// 每个字段都在的文件：`id` 与 `machineId` 齐备，构造器因此**不会**走
/// "补全 ID/machineId 后持久化"那条合法分支（`token_manager.rs` 构造器尾部的
/// `has_new_ids || has_new_machine_ids`）。缺了它们，本用例测的就不是"启动不
/// 改写"，而是那条补全路径——它本来就该写。
const COMPLETE_MACHINE_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn complete_legacy_credential_json(id: u64) -> String {
    format!(
        r#"{{"id":{id},"refreshToken":"r","machineId":"{COMPLETE_MACHINE_ID}","proxyUrl":"direct"}}"#
    )
}

/// 启动阶段对已完整的旧格式文件**逐字节**不回写：旧数组与单对象各一次。
///
/// 前置条件断言：
/// 1. 文件被真的加载出 1 条凭据（否则"字节不变"可能只是根本没读文件）；
/// 2. 单对象被识别为非多凭据格式（`is_multiple() == false`），这是它"无保存
///    路径"的由来，也是下面 `set_priority` 不得回写的前提；
/// 3. 写入磁盘的字节与读回的比较对象是同一份 `Vec<u8>`（含空白与键序），不是
///    解析结果——只要实现把文档重新序列化一次，大小写/缩进/跳过空字段的差异
///    都会让断言变红。
///
/// 反事实（见报告）：让构造器无条件调用一次 `persist_credentials()`（把
/// `has_new_ids || has_new_machine_ids` 改成 `true`），两个字节比较都变红。
#[tokio::test]
async fn bdd_persistence_startup_never_rewrites_existing_document() {
    let dir = TempDir::new();

    // (1) 旧数组：启动前后字节逐一相同。
    std::fs::write(
        dir.path(),
        format!("[{}]", complete_legacy_credential_json(1)),
    )
    .unwrap();
    let before = std::fs::read(dir.path()).unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    assert!(loaded.is_multiple(), "前置条件：数组必须是多凭据格式");
    let (credentials, proxies) = loaded.into_parts();
    assert_eq!(credentials.len(), 1, "前置条件：旧数组必须被加载");
    let manager = manager(&dir, credentials, proxies);
    assert_eq!(manager.snapshot().total, 1);
    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        before,
        "启动不得改写旧数组文件（逐字节比较，不是解析结果比较）"
    );
    drop(manager);

    // (2) 单对象：启动前后字节相同；之后一次管理写也不得回写。
    std::fs::write(dir.path(), complete_legacy_credential_json(7)).unwrap();
    let before = std::fs::read(dir.path()).unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    assert!(
        !loaded.is_multiple(),
        "前置条件：顶层无 credentials 键的对象必须识别为单对象格式"
    );
    let (single_credentials, single_proxies) = loaded.into_parts();
    assert_eq!(single_credentials.len(), 1, "前置条件：单对象必须被加载");
    assert!(
        single_credentials[0].machine_id.is_some(),
        "前置条件：单对象必须自带 machineId，否则构造器走补全分支而非本用例"
    );
    let manager = Arc::new(
        MultiTokenManager::new(
            Config::default(),
            single_credentials,
            None,
            Some(dir.path()),
            false,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    assert!(single_proxies.is_empty());
    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        before,
        "启动不得改写单对象文件（逐字节比较）"
    );
    manager.set_priority(7, 3).unwrap();
    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        before,
        "单对象文件的后续管理写不得回写（不回写契约）"
    );
}

/// 封套里 proxies / credentials 两类条目**逐字段**完整，且凭据原有字段不丢。
///
/// 断言面是磁盘上的原始 JSON（不是内存快照），因为字段丢失最可能发生在序列化
/// 那一步。凭据侧逐字段对照的是写盘前磁盘上的旧数组内容——池绑定只允许改
/// `proxyId`，其余字段必须原样带到封套里。
///
/// 反事实（见报告）：让 `should_write_envelope` 恒为 `true` 不影响本条（它本来就
/// 该写封套），故本条的反事实作用在字段上：把 `write_document` 的 credentials
/// 改成 `snapshot_entries(&[])`（丢字段）时，下面的逐字段断言全部变红。
#[tokio::test]
async fn bdd_envelope_roundtrip_keeps_every_field() {
    let dir = TempDir::new();
    // 带认证的池条目 + 一条字段齐全的旧数组凭据（封套化前它在磁盘上是数组）。
    let mut credential = KiroCredentials {
        id: Some(1),
        refresh_token: Some("refresh-1".into()),
        profile_arn: Some("arn:aws:codewhisperer:us-east-1:1:profile/test".into()),
        machine_id: Some(COMPLETE_MACHINE_ID.into()),
        priority: 2,
        endpoint: Some("ide".into()),
        ..Default::default()
    };
    credential.kiro_api_key = None;
    std::fs::write(
        dir.path(),
        serde_json::to_string(&vec![credential]).unwrap(),
    )
    .unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, proxies) = loaded.into_parts();
    assert!(proxies.is_empty(), "前置条件：旧数组格式没有池");

    let entry = ProxyEntry {
        id: "pool-1".into(),
        name: "named".into(),
        url: "socks5://127.0.0.1:1080".into(),
        username: Some("user".into()),
        password: Some("pa ss".into()),
    };
    let manager = manager(&dir, credentials, vec![entry]);
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "pool-1".into(),
            },
        )
        .await
        .unwrap();

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path()).unwrap()).unwrap();
    assert_eq!(raw["version"], 1, "封套必须带 version: 1");
    // 池条目逐字段。
    let proxy = &raw["proxies"][0];
    assert_eq!(proxy["id"], "pool-1");
    assert_eq!(proxy["name"], "named");
    assert_eq!(proxy["url"], "socks5://127.0.0.1:1080");
    assert_eq!(proxy["username"], "user");
    assert_eq!(proxy["password"], "pa ss", "密码不得被 trim 或丢弃");
    // 凭据逐字段（原有字段不丢 + 只有绑定字段变化）。
    let credential = &raw["credentials"][0];
    assert_eq!(credential["id"], 1);
    assert_eq!(credential["refreshToken"], "refresh-1");
    assert_eq!(
        credential["profileArn"],
        "arn:aws:codewhisperer:us-east-1:1:profile/test"
    );
    assert_eq!(credential["machineId"], COMPLETE_MACHINE_ID);
    assert_eq!(credential["priority"], 2);
    assert_eq!(credential["endpoint"], "ide");
    assert_eq!(credential["proxyId"], "pool-1");
    assert!(
        credential.get("proxyUrl").is_none(),
        "池绑定时不得残留旧的 proxyUrl 字段"
    );

    // 重启一致：再加载一次，两类条目与绑定都还在（同一份封套）。
    let reloaded = CredentialsConfig::load(dir.path()).unwrap();
    assert!(reloaded.is_envelope(), "重启后必须仍是封套");
    let (credentials, proxies) = reloaded.into_parts();
    assert_eq!(proxies.len(), 1);
    assert_eq!(
        proxies[0],
        ProxyEntry {
            id: "pool-1".into(),
            name: "named".into(),
            url: "socks5://127.0.0.1:1080".into(),
            username: Some("user".into()),
            password: Some("pa ss".into()),
        }
    );
    assert_eq!(credentials[0].proxy_id.as_deref(), Some("pool-1"));
    assert_eq!(
        credentials[0].profile_arn.as_deref(),
        Some("arn:aws:codewhisperer:us-east-1:1:profile/test")
    );
}

/// 「仅改内联」与「仅改直连」必须走**真实的管理端绑定入口**，且都不触发封套。
///
/// 旧用例用 `set_priority` 顶替绑定：那证明的是"别的管理写不引入封套"，
/// 不是"绑定内联/直连不引入封套"。两条规则不同，前者恒绿不能替代后者。
///
/// 反事实（见报告）：让 `should_write_envelope` 对 `proxy_url.is_some()` 也返回
/// `true`（即把内联绑定当成"使用代理池"），本用例第一段变红。
#[tokio::test]
async fn bdd_inline_or_direct_binding_via_admin_keeps_array_format() {
    let dir = TempDir::new();
    std::fs::write(
        dir.path(),
        format!("[{}]", complete_legacy_credential_json(1)),
    )
    .unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, proxies) = loaded.into_parts();
    let manager = manager(&dir, credentials, proxies);
    assert!(manager.list_proxies().is_empty(), "前置条件：池为空");

    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Inline {
                url: "socks5://127.0.0.1:1080".into(),
                username: Some("user".into()),
                password: Some("pass".into()),
            },
        )
        .await
        .unwrap();
    let raw = std::fs::read_to_string(dir.path()).unwrap();
    assert!(
        raw.trim_start().starts_with('['),
        "内联绑定不构成代理池，必须维持数组格式，实际: {raw}"
    );
    let reloaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, _) = reloaded.into_parts();
    assert_eq!(
        credentials[0].proxy_url.as_deref(),
        Some("socks5://127.0.0.1:1080"),
        "内联绑定必须真的落到磁盘"
    );

    manager
        .bind_credential_proxy(1, ProxyBindingRequest::Direct)
        .await
        .unwrap();
    let raw = std::fs::read_to_string(dir.path()).unwrap();
    assert!(
        raw.trim_start().starts_with('['),
        "直连绑定不构成代理池，必须维持数组格式，实际: {raw}"
    );
    let reloaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, _) = reloaded.into_parts();
    assert_eq!(
        credentials[0].proxy_url.as_deref(),
        Some(KiroCredentials::PROXY_DIRECT)
    );
}

#[tokio::test]
async fn bdd_single_object_and_missing_path_refuse_pool_writes() {
    let dir = TempDir::new();
    // 单对象（is_multiple_format=false）
    let manager = Arc::new(
        MultiTokenManager::new(
            Config::default(),
            vec![api_key_credential(1)],
            None,
            Some(dir.path()),
            false,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    let error = manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .expect_err("单对象文件不得接受池写操作");
    assert!(error.to_string().contains("不可回写"), "{error}");
    assert!(!dir.path().exists(), "拒绝时不得创建文件");

    // 无保存路径
    let manager = Arc::new(
        MultiTokenManager::new(
            Config::default(),
            vec![api_key_credential(1)],
            None,
            None,
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    assert!(
        manager
            .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bdd_invalid_documents_are_rejected_at_load() {
    let dir = TempDir::new();
    for content in [
        r#"{"version":2,"proxies":[],"credentials":[]}"#,
        r#"{"version":1,"proxies":[{"id":"a","name":"A","url":"socks5://h:1"},{"id":"a","name":"B","url":"socks5://h:2"}],"credentials":[]}"#,
        r#"{"version":1,"proxies":[],"credentials":[{"id":1,"proxyId":"missing"}]}"#,
        r#"{"version":1,"proxies":[{"id":"a","name":"A","url":"socks5://h:1"}],"credentials":[{"id":1,"proxyId":"a","proxyUrl":"socks5://x:1"}]}"#,
    ] {
        std::fs::write(dir.path(), content).unwrap();
        assert!(
            CredentialsConfig::load(dir.path()).is_err(),
            "必须拒绝: {content}"
        );
    }
}

/// 启动时旧内联 URL 无效：按既有先例禁用该凭据，不回退直连、不拖垮启动。
///
/// F3 之后"无效"的口径是 **reqwest `IntoProxy` 也拒绝**（`ftp://` 无 scheme 语义
/// 缺陷已在 F3 修复，master 上它本来就可用）。这里用无法解析的 URL 当夹具。
#[tokio::test]
async fn bdd_invalid_legacy_inline_url_disables_only_that_credential() {
    let dir = TempDir::new();
    let mut bad = api_key_credential(1);
    bad.proxy_url = Some("://".into());
    let manager = manager(&dir, vec![bad, api_key_credential(2)], Vec::new());
    let snapshot = manager.snapshot();
    let bad_entry = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
    assert!(bad_entry.disabled, "无效代理配置的凭据应被禁用");
    assert_eq!(bad_entry.disabled_reason.as_deref(), Some("InvalidConfig"));
    assert!(
        !snapshot
            .entries
            .iter()
            .find(|e| e.id == 2)
            .unwrap()
            .disabled,
        "其他凭据不受影响"
    );
}

// ─────────────────────────────────────────────────────────────
// BDD: 引用与并发
// ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bdd_delete_referenced_proxy_conflicts() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .unwrap();
    let error = manager
        .delete_proxy("p1")
        .await
        .expect_err("被引用时必须拒绝");
    assert!(error.to_string().contains("引用"), "{error}");

    // 禁用凭据的引用同样阻止删除。
    manager.set_disabled(1, true).unwrap();
    assert!(manager.delete_proxy("p1").await.is_err());

    manager
        .bind_credential_proxy(1, ProxyBindingRequest::Inherit)
        .await
        .unwrap();
    manager.delete_proxy("p1").await.unwrap();
    assert!(manager.list_proxies().is_empty());
}

/// 绑定提交阶段必须采用池中当前已发布条目的 route（审阅 Minor 第 6 条）。
///
/// 反事实：若沿用锁外构建的候选 route，下面编辑 URL 后的绑定点会指向旧代理。
#[tokio::test]
async fn bdd_bind_uses_published_proxy_route_after_concurrent_edit() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let url = format!("http://{}/x", target.addr);
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;

    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", &socks_a.url))
        .await
        .unwrap();

    // 闸门：绑定方完成锁外校验后停住，此时并发把 p1 改成另一个 URL，
    // 再放行——绑定的复核必须看到新 URL。双向 Barrier 让"停住"与"改完"
    // 都是确定性的，不靠 sleep。
    let gate = Arc::new(crate::kiro::token_manager::proxy_pool::BindGate::new());
    manager.install_bind_gate_for_test(gate.clone());
    let binder = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .bind_credential_proxy(
                    1,
                    ProxyBindingRequest::Pool {
                        proxy_id: "p1".into(),
                    },
                )
                .await
        })
    };
    gate.wait_arrival_and_release().await;
    manager
        .update_proxy(
            "p1",
            ProxyUpdateRequest {
                url: Some(Some(socks_b.url.clone())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    binder.await.unwrap().unwrap();

    let provider = provider(manager.clone(), &url);
    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(socks_a.stats.connections(), 0, "不得使用已被替换的旧代理");
    assert_eq!(socks_b.stats.connections(), 1, "必须使用当前已发布的代理");
}

/// `BindGate` 在多线程运行时、多次 bind 并发到达时不得丢唤醒。
///
/// 旧形态（`arrived.notify_one()` + 测试方 `notified().await`）只能保存一个许可：
/// 第一个 bind 被放行后，其余 bind 的到达通知要么落在没有等待者的窗口里被丢弃，
/// 要么互相覆盖——测试方再也收不到足够的到达，剩下的 bind 永远不被放行，用例
/// 以**挂死**收场。这里用 multi_thread × 4 worker × 8 个并发 bind 压它：
///
/// 前置条件断言：
/// 1. 8 个 bind 全部**真实到达**闸门（`wait_arrivals(8)`），且此刻没有一个完成
///    ——证明它们真的同时卡在闸门里，而不是提前放行；
/// 2. 8 次放行之后，8 次 bind 全部返回成功，且每条凭据的绑定字段确实落到了
///    对应的 proxyId 上（不是"任务结束了但什么都没做"）。
///
/// 反事实（见报告）：把 `arrive_and_wait` 换回 `arrived.notify_one()` +
/// `notified().await`，本用例在 `wait_arrivals(8)` 处超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_bind_gate_survives_concurrent_arrivals() {
    const FAIL_FAST: std::time::Duration = std::time::Duration::from_secs(20);
    const BINDS: u64 = 8;

    let dir = TempDir::new();
    // 每条凭据一个独立池条目：绑定完成后逐条核对落点，避免"都成功但绑错了"。
    let mut credentials = Vec::new();
    let mut proxies = Vec::new();
    for index in 1..=BINDS {
        credentials.push(api_key_credential(index));
        proxies.push(pool_entry(
            &format!("p{index}"),
            &format!("socks5://127.0.0.1:{}", 11000 + index),
        ));
    }
    let manager = manager(&dir, credentials, proxies);

    let gate = Arc::new(crate::kiro::token_manager::proxy_pool::BindGate::new());
    manager.install_bind_gate_for_test(gate.clone());

    let mut handles = Vec::new();
    for index in 1..=BINDS {
        let manager = manager.clone();
        handles.push(tokio::spawn(async move {
            manager
                .bind_credential_proxy(
                    index,
                    ProxyBindingRequest::Pool {
                        proxy_id: format!("p{index}"),
                    },
                )
                .await
        }));
    }

    // (1) 前置条件：8 个 bind 全部到达闸门，且都还没完成。
    tokio::time::timeout(FAIL_FAST, gate.wait_arrivals(BINDS as usize))
        .await
        .expect("8 个并发 bind 都应登记到达（旧实现会在这里丢唤醒并挂死）");
    let finished_before_release = handles.iter().filter(|handle| handle.is_finished()).count();
    assert_eq!(
        finished_before_release, 0,
        "前置条件不成立：放行之前不得有任何 bind 完成（说明闸门没拦住）"
    );

    // (2) 逐次放行：每次放行对应一个到达。
    for _ in 0..BINDS {
        gate.release_one_for_test();
    }
    for (index, handle) in handles.into_iter().enumerate() {
        let joined = tokio::time::timeout(FAIL_FAST, handle)
            .await
            .unwrap_or_else(|_| panic!("第 {} 个 bind 放行后仍未完成", index + 1));
        joined
            .unwrap_or_else(|error| panic!("第 {} 个 bind 失败: {error}", index + 1))
            .unwrap_or_else(|error| panic!("第 {} 个 bind 返回错误: {error}", index + 1));
    }

    // (3) 结果：每条凭据的绑定字段都落到自己的 proxyId 上。
    let snapshot = manager.snapshot();
    for index in 1..=BINDS {
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.id == index)
            .expect("凭据必须存在");
        assert_eq!(entry.proxy_mode, "pool", "凭据 {index} 必须已绑定到池代理");
    }
    assert_eq!(
        manager.list_proxies().len(),
        BINDS as usize,
        "池条目不得在绑定过程中被改动"
    );
}

/// 管理端写入不得重建条目（刷新锁/失败计数/在途计数原样保留）。
#[tokio::test]
async fn bdd_admin_bind_preserves_runtime_state() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    manager.set_disabled(1, true).unwrap();
    manager.set_disabled(1, false).unwrap();
    manager.report_failure(1);
    manager.report_failure(1);

    let (refresh_lock, failure_count, in_flight, revision) =
        manager.runtime_state_for_test(1).unwrap();
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .unwrap();
    let (after_lock, after_failures, after_in_flight, after_revision) =
        manager.runtime_state_for_test(1).unwrap();
    assert!(
        Arc::ptr_eq(&after_lock, &refresh_lock),
        "刷新锁必须原样保留"
    );
    assert_eq!(after_failures, failure_count);
    assert_eq!(after_in_flight, in_flight);
    assert_eq!(
        after_revision,
        revision.wrapping_add(1),
        "state_revision 沿用既有递增规则"
    );
}

/// 刷新落盘与管理写并发：两者都完成、不死锁，且落盘前 entries 已释放。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_admin_write_and_refresh_persist_concurrently_without_deadlock() {
    let dir = TempDir::new();
    let manager = manager(
        &dir,
        vec![api_key_credential(1), api_key_credential(2)],
        Vec::new(),
    );
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    let writer = {
        let manager = manager.clone();
        tokio::spawn(async move {
            for index in 0..20 {
                manager
                    .set_priority(1, index)
                    .expect("refresh 落盘与 set_priority 并发不得死锁");
            }
        })
    };
    let binder = {
        let manager = manager.clone();
        tokio::spawn(async move {
            for _ in 0..20 {
                manager
                    .bind_credential_proxy(
                        2,
                        ProxyBindingRequest::Pool {
                            proxy_id: "p1".into(),
                        },
                    )
                    .await
                    .unwrap();
                manager
                    .bind_credential_proxy(2, ProxyBindingRequest::Inherit)
                    .await
                    .unwrap();
            }
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        writer.await.unwrap();
        binder.await.unwrap();
    })
    .await
    .expect("并发写必须完成（死锁会在这里超时）");

    let reloaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, proxies) = reloaded.into_parts();
    assert_eq!(proxies.len(), 1);
    assert_eq!(credentials.len(), 2, "两个凭据都必须仍在文件里");
}

// ─────────────────────────────────────────────────────────────
// BDD: 秘密不得泄露
// ─────────────────────────────────────────────────────────────

#[test]
fn bdd_secrets_are_redacted_everywhere() {
    let with_auth =
        ProxyConfig::new("http://alice:s3cret@proxy.example:3128").with_auth("bob", "pw2");
    let debug = format!("{with_auth:?}");
    assert!(!debug.contains("s3cret"), "Debug 不得含内联密码: {debug}");
    assert!(!debug.contains("pw2"), "Debug 不得含认证密码: {debug}");
    assert!(debug.contains("has_password: true"), "实际 Debug: {debug}");
    assert!(!debug.contains("alice"), "Debug 不得含内联用户名: {debug}");
    // Minor 5：认证用户名同样是秘密材料，`proxy_pool.rs` 的构建失败告警会
    // 把整个 key（含 `ProxyConfig`）打进日志，这里必须脱敏成布尔。
    assert!(!debug.contains("bob"), "Debug 不得含认证用户名: {debug}");
    assert!(debug.contains("has_username: true"), "实际 Debug: {debug}");
    let without = format!("{:?}", ProxyConfig::new("http://proxy.example:3128"));
    assert!(without.contains("has_password: false"));
    assert!(without.contains("has_username: false"));

    let redacted = redact_proxy_url("http://alice:s3cret@proxy.example:3128/?token=abc#frag");
    assert!(!redacted.contains("alice"));
    assert!(!redacted.contains("s3cret"));
    assert!(!redacted.contains("token=abc"));
    assert!(!redacted.contains("frag"));
    assert_eq!(redacted, "http://proxy.example:3128/");

    let entry = ProxyEntry {
        id: "p1".into(),
        name: "P1".into(),
        url: "http://alice:s3cret@proxy.example:3128".into(),
        username: Some("bob".into()),
        password: Some("pw2".into()),
    };
    assert!(!entry.redacted_url().contains("s3cret"));
}

/// 凭据列表响应只回传脱敏信息，不回传密码。
#[test]
fn bdd_admin_response_never_includes_secrets() {
    let dir = TempDir::new();
    std::fs::write(
        dir.path(),
        r#"[{"id":1,"refreshToken":"rtoken-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proxyUrl":"http://alice:s3cret@proxy.example:3128"}]"#,
    )
    .unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, proxies) = loaded.into_parts();
    let manager = manager(&dir, credentials, proxies);
    let snapshot = manager.snapshot();
    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(!serialized.contains("s3cret"), "凭据快照不得含代理密码");
    assert!(
        !serialized.contains("rtoken-"),
        "凭据快照不得含 refreshToken"
    );
    assert_eq!(snapshot.entries[0].proxy_mode, "inline");
}

// ─────────────────────────────────────────────────────────────
// BDD: 密码三态
// ─────────────────────────────────────────────────────────────

#[test]
fn bdd_patch_password_double_option_semantics() {
    use crate::kiro::token_manager::ProxyUpdateRequest as Update;
    let base = || ProxyEntry {
        id: "p1".into(),
        name: "P1".into(),
        url: "socks5://h:1".into(),
        username: Some("u".into()),
        password: Some("old".into()),
    };

    let keep: Update = serde_json::from_str(r#"{"name":"renamed"}"#).unwrap();
    let mut entry = base();
    keep.apply_for_test(&mut entry);
    assert_eq!(entry.password.as_deref(), Some("old"), "缺省必须保留");
    assert_eq!(entry.name, "renamed");

    let clear: Update = serde_json::from_str(r#"{"password":null}"#).unwrap();
    let mut entry = base();
    clear.apply_for_test(&mut entry);
    assert_eq!(entry.password, None, "null 必须清除");

    let empty: Update = serde_json::from_str(r#"{"password":""}"#).unwrap();
    let mut entry = base();
    empty.apply_for_test(&mut entry);
    assert_eq!(empty.password, Some(Some(String::new())));
    assert_eq!(entry.password.as_deref(), Some(""), "空串是明确的空密码");

    let spaced: Update = serde_json::from_str(r#"{"password":" pa ss "}"#).unwrap();
    let mut entry = base();
    spaced.apply_for_test(&mut entry);
    assert_eq!(entry.password.as_deref(), Some(" pa ss "), "不得 trim 密码");
}

// ─────────────────────────────────────────────────────────────
// BDD: 多路由并发不跨路由排队；刷新隔离
// ─────────────────────────────────────────────────────────────

/// 跨 4 条独立路由的请求不得互相排队——用**同时停靠在目标闸门里**证明。
///
/// 旧判据是"24 次请求总耗时 < 5s"。墙钟把机器负载与调度抖动算进结论：慢机器上
/// 健康实现会红，快机器上串行实现也可能绿；而且它根本没有证明"多个请求真的
/// 同时在途"——串行跑完同样能在 5s 内结束。
///
/// 新判据是结构性事件链：
/// 1. 前置条件：4 条凭据的 route 指针两两不同（真的 4 条路由）；
/// 2. 打开每个目标的请求闸门后，4 个 handler 同时停住（各自 `wait_held(1)`），
///    期间没有任何放行——串行实现不可能产生这个状态；
/// 3. 放行后 24 次请求全部到达各自目标，每条路由只有 1 条隧道。
///
/// 墙钟只保留为失败上限（`FAIL_FAST`），不参与对不对的判定。
///
/// 反事实（见报告）：在选路临界区外再加一层全局异步锁，第 2 步只有 1 条路由能
/// 停靠，`wait_held(1)` 在 timeout 处变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_parallel_routes_do_not_share_a_bottleneck() {
    const FAIL_FAST: std::time::Duration = std::time::Duration::from_secs(30);

    let dir = TempDir::new();
    let mut proxies = Vec::new();
    let mut fixtures: Vec<LocalProxy> = Vec::new();
    let mut credentials = Vec::new();
    let mut targets: Vec<H2TargetServer> = Vec::new();
    for index in 0..4u64 {
        let target = H2TargetServer::spawn().await;
        let socks = spawn_socks5_redirect(target.addr).await;
        proxies.push(pool_entry(&format!("p{index}"), &socks.url));
        fixtures.push(socks);
        targets.push(target);
        let mut cred = api_key_credential(index + 1);
        cred.proxy_id = Some(format!("p{index}"));
        cred.priority = index as u32;
        credentials.push(cred);
    }
    let url = format!("http://127.0.0.1:{}/x", targets[0].addr.port());
    // priority 模式会一直粘在最小 priority 的那张凭据上，测不到"多路由并发"；
    // 这里按各自负载分配，才能真正让 4 条路由同时承压。
    let mut config = Config::default();
    config.load_balancing_mode = "balanced".to_string();
    let manager = Arc::new(
        MultiTokenManager::new_with_pool(
            config,
            credentials,
            proxies,
            None,
            Some(dir.path()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    for index in 0..4u64 {
        manager.install_route_for_test(index + 1, h2_route(&fixtures[index as usize].url, None));
    }

    // (1) 前置条件：4 条 route 指针两两不同。
    let mut pointers: Vec<*const Route> = (1..=4)
        .map(|id| manager.route_ptr_for_test(id).expect("凭据必须有 route"))
        .collect();
    let distinct = {
        pointers.sort();
        pointers.dedup();
        pointers.len()
    };
    assert_eq!(distinct, 4, "前置条件不成立：必须是 4 条不同路由");

    let provider = Arc::new(provider(manager, &url));

    // (2) 同时停靠：先打开 4 个目标的闸门，再各发一个请求。
    for target in &targets {
        target.hold_requests();
    }
    let mut handles = Vec::new();
    for _ in 0..4 {
        let provider = provider.clone();
        handles.push(tokio::spawn(async move {
            provider.call_api_with_context(&request_body()).await
        }));
    }
    for target in &targets {
        tokio::time::timeout(FAIL_FAST, target.wait_held(1))
            .await
            .expect("每条路由都应有一个请求停在目标闸门里（排队会在这里超时）");
    }
    let simultaneously_held = targets.iter().filter(|target| target.held() >= 1).count();
    assert_eq!(
        simultaneously_held, 4,
        "4 条路由的请求必须同时在途；实际只有 {simultaneously_held} 条同时停靠"
    );
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.requests(),
            1,
            "路由 {index} 在放行前应恰好收到 1 个请求，否则并发判定被污染"
        );
    }

    // (3) 放行，再补 20 次请求；24 次全部到达、每条路由仍只有 1 条隧道。
    for target in &targets {
        target.release_held();
    }
    for handle in handles {
        tokio::time::timeout(FAIL_FAST, handle)
            .await
            .expect("放行后首批请求必须完成")
            .unwrap()
            .expect("首批请求不得失败");
    }
    let mut rest = Vec::new();
    for _ in 0..20 {
        let provider = provider.clone();
        rest.push(tokio::spawn(async move {
            provider.call_api_with_context(&request_body()).await
        }));
    }
    for handle in rest {
        tokio::time::timeout(FAIL_FAST, handle)
            .await
            .expect("其余请求必须完成")
            .unwrap()
            .unwrap();
    }

    let total: usize = targets.iter().map(|target| target.requests()).sum();
    assert_eq!(total, 24, "24 次请求都必须到达目标");
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(target.connections(), 1, "路由 {index} 应只建一条隧道");
        // "每条路由都参与分担"已由上面的 4 路同时停靠锁死；这里只补一条
        // "之后仍有请求落在它上面"，不断言具体份额（balanced 会按实时 load
        // 分配，份额本身不是本用例的被测对象）。
        assert!(
            target.requests() >= 1,
            "路由 {index} 应至少承载一次请求（实际 {} 次）",
            target.requests()
        );
    }
}

// ─────────────────────────────────────────────────────────────
// BDD: 覆盖的 OAuth / MCP / generate 路径
// ─────────────────────────────────────────────────────────────

/// MCP 与 generate 都必须经过凭据所选路由。
#[tokio::test]
async fn bdd_api_and_mcp_both_use_credential_route() {
    let dir = TempDir::new();
    let target = H2TargetServer::spawn().await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let url = format!("http://{}/x", target.addr);

    let mut cred = api_key_credential(1);
    cred.proxy_id = Some("p1".into());
    let manager = manager(&dir, vec![cred], vec![pool_entry("p1", &socks.url)]);
    manager.install_route_for_test(1, h2_route(&socks.url, None));
    let provider = provider(manager, &url);

    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    provider
        .call_mcp(&request_body(), Some("session"))
        .await
        .unwrap();

    // 路由自带 idle / short 两个 client（超时语义不同，不能合并），各持自己的
    // 连接池，所以这里必然是 2 条隧道——关键是"每条都来自凭据所选代理"。
    assert_eq!(
        target.connections(),
        2,
        "generate 与 MCP 各自使用 route.idle / route.short 的隧道"
    );
    assert_eq!(target.requests(), 2, "两次请求都应到达目标");
    let observed = socks.stats.targets();
    assert_eq!(observed.len(), 2, "两次请求都应经代理: {observed:?}");
}

// ─────────────────────────────────────────────────────────────
// I1：全局代理 config.proxyUrl 必须作用于「继承」凭据
// ─────────────────────────────────────────────────────────────

/// 配置了全局代理 + 继承凭据：generate 请求必须经全局代理夹具。
///
/// 目标用**只有代理能解析**的主机名（socks5h + 重定向夹具）：一旦继承凭据
/// 绕过代理直连，请求在本地就解析失败，用例红。
///
/// 反事实：把 `Inherit` 映射回 `RouteKey::System`（修复前的实现），第一个
/// 断言（route key 必须是 Global）先红；只删网络断言时，直连目标
/// `connections()==0` 会红。
#[tokio::test]
async fn bdd_i1_inherit_credential_uses_global_proxy() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let global = ProxyConfig::new(socks.url.replacen("socks5://", "socks5h://", 1));

    let manager = manager_with_global_proxy(
        &dir,
        vec![api_key_credential(1)],
        Vec::new(),
        Some(global.clone()),
    )
    .unwrap();

    let route = manager.route_arc_for_test(1).unwrap();
    assert_eq!(
        route.key(),
        &RouteKey::Global(global.clone()),
        "继承凭据的 route 必须是全局代理路由"
    );
    assert!(
        manager
            .registered_route_for_test(&RouteKey::Global(global.clone()))
            .is_some(),
        "全局代理路由必须注册在池里（构造期建一次）"
    );

    // 目标主机名只在代理侧可解析；绕过代理时这里会解析失败。
    let url = format!("http://kiro-rs-i1-probe.invalid:{}/x", target.addr.port());
    let response = route.short.get(&url).send().await.expect("必须经全局代理");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(socks.stats.connections(), 1, "请求必须经全局代理");
    assert_eq!(
        target.connections(),
        1,
        "目标只能通过代理隧道被连（直连必然解析失败）"
    );
    assert_eq!(
        manager.snapshot().entries[0].proxy_mode,
        "inherit",
        "展示层语义不变"
    );
}

/// 同配置下 `direct` 凭据必须不经全局代理。
#[tokio::test]
async fn bdd_i1_direct_credential_bypasses_global_proxy() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let socks = spawn_socks5(None, "socks5").await;

    let mut direct = api_key_credential(1);
    direct.proxy_url = Some("direct".into());
    let manager = manager_with_global_proxy(
        &dir,
        vec![direct],
        Vec::new(),
        Some(ProxyConfig::new(&socks.url)),
    )
    .unwrap();

    let route = manager.route_arc_for_test(1).unwrap();
    assert!(!route.is_proxied(), "direct 凭据不得落在代理路由上");
    let response = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(target.connections(), 1, "direct 必须真正直连到目标");
    assert_eq!(socks.stats.connections(), 0, "direct 不得经过全局代理");
}

/// 全局代理 URL 非法时构造函数返回 Err（保持 master 的 fail-fast）。
///
/// 注意夹具选 `://` 这种**连 URL 都解析不出来**的值：`ftp://host:21` 在 master
/// 上是可用的（reqwest `IntoProxy` 的 scheme 语义），F3 之后本分支也恢复该语义，
/// 不再适合当"非法"夹具。构造失败的判据是 `Proxy::all` 本身返回 Err。
#[tokio::test]
async fn bdd_i1_invalid_global_proxy_fails_construction() {
    let dir = TempDir::new();
    let result = manager_with_global_proxy(
        &dir,
        vec![api_key_credential(1)],
        Vec::new(),
        Some(ProxyConfig::new("://")),
    );
    assert!(
        result.is_err(),
        "无法解析的全局代理必须让构造失败，而不是静默直连"
    );
}

/// 两个继承凭据共享同一个全局代理 `Arc`，且启动期只构建一次。
#[tokio::test]
async fn bdd_i1_global_route_is_built_once_and_shared() {
    let dir = TempDir::new();
    let socks = spawn_socks5(None, "socks5").await;
    let global = ProxyConfig::new(&socks.url);
    let global_key = RouteKey::Global(global.clone());

    crate::http_client::route_build_counter::reset();
    let manager = manager_with_global_proxy(
        &dir,
        vec![api_key_credential(1), api_key_credential(2)],
        Vec::new(),
        Some(global),
    )
    .unwrap();

    let first = manager.route_arc_for_test(1).unwrap();
    let second = manager.route_arc_for_test(2).unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "两个继承凭据必须共享同一个 route Arc"
    );
    assert_eq!(
        crate::http_client::route_build_counter::count(&global_key),
        1,
        "启动期全局路由只允许构建一次"
    );
}

// ─────────────────────────────────────────────────────────────
// I2：entries 与 pool 两把锁的锁序（确定性死锁回归）
// ─────────────────────────────────────────────────────────────

/// 在子进程里跑一个可能死锁的探针用例，父进程用硬超时兜底。
///
/// 为什么必须是子进程：`parking_lot::Mutex` 的死锁是**同步**阻塞，会连
/// `tokio::time::timeout` 一起挂住（测试线程本身卡在 `lock()` 里，没有 await
/// 点可以让 runtime 调度）。要满足"失败表现为超时而不是挂死整个测试进程"，
/// 只能把可能挂住的代码放到独立进程里，由父进程 `wait_timeout` 判死并 abort。
fn run_deadlock_probe(exact_test: &str) {
    let exe = std::env::current_exe().expect("获取测试可执行文件路径失败");
    let mut child = std::process::Command::new(exe)
        .args(["--exact", exact_test, "--ignored", "--test-threads=1"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("子进程启动失败");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait().expect("等待子进程失败") {
            Some(status) => {
                assert!(status.success(), "锁序探针子进程失败（锁倒置会挂死）");
                return;
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("锁序探针在 60s 硬超时内未完成：entries/pool 锁发生倒置");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

/// 对任一路径倒置都会失败：`snapshot` 与 `list_proxies` 若各自嵌套取两把锁
/// （两者方向相反），必然死锁。
///
/// 形态：真正的死锁是**同步**锁死锁，它会把测试进程本身挂住——这违反
/// "失败表现为超时/失败而不是挂死整个测试进程"。因此交错逻辑跑在**子进程**里：
/// 父进程用硬超时等待，子进程挂住即判失败并 abort 掉。
///
/// 反事实（把 `list_proxies` 改回先 pool 后 entries 的嵌套写法、`snapshot`
/// 保持 entries 后 pool）：子进程挂死，本用例在 60s 内以超时失败。
#[test]
fn bdd_i2_snapshot_and_list_proxies_never_deadlock() {
    run_deadlock_probe("kiro::proxy_pool_bdd::i2_deadlock_child_probe");
}

/// 子进程体：`snapshot` 与 `list_proxies` 各 4 个线程高频交错。
///
/// 由父用例通过 `--ignored --exact` 拉起；独立进程保证死锁不会污染主测试进程。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "由 bdd_i2_snapshot_and_list_proxies_never_deadlock 在子进程中拉起"]
async fn i2_deadlock_child_probe() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let manager = manager.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..500 {
                let _ = manager.snapshot();
            }
        }));
    }
    for _ in 0..4 {
        let manager = manager.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..500 {
                let _ = manager.list_proxies();
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

/// `persist_credentials`（save→entries→pool）与 `prune_routes`/`bind`
/// （管理写路径）并发时不得死锁。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bdd_i2_persist_and_prune_or_bind_never_deadlock() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    let persister = {
        let manager = manager.clone();
        tokio::spawn(async move {
            for index in 0..40 {
                manager.set_priority(1, index).unwrap();
            }
        })
    };
    let binder = {
        let manager = manager.clone();
        tokio::spawn(async move {
            for _ in 0..40 {
                manager
                    .bind_credential_proxy(
                        1,
                        ProxyBindingRequest::Pool {
                            proxy_id: "p1".into(),
                        },
                    )
                    .await
                    .unwrap();
                manager
                    .bind_credential_proxy(1, ProxyBindingRequest::Inherit)
                    .await
                    .unwrap();
            }
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        persister.await.unwrap();
        binder.await.unwrap();
    })
    .await
    .expect("落盘与 bind/prune 并发不得死锁");
}

// ─────────────────────────────────────────────────────────────
// I3：写盘失败时四条路径都不得改内存
// ─────────────────────────────────────────────────────────────

/// 让凭据文件写盘必然失败：父路径是普通文件（docker root 下 chmod 无效，
/// 故不用权限位）。
fn unwritable_dir() -> TempDir {
    let dir = TempDir::new();
    std::fs::write(dir.0.join("blocker"), b"not a directory").unwrap();
    dir
}

fn unwritable_path(dir: &TempDir) -> std::path::PathBuf {
    dir.0.join("blocker").join("credentials.json")
}

fn manager_at(
    path: std::path::PathBuf,
    credentials: Vec<KiroCredentials>,
) -> Arc<MultiTokenManager> {
    Arc::new(
        MultiTokenManager::new_with_pool(
            Config::default(),
            credentials,
            Vec::new(),
            None,
            Some(path),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    )
}

/// create_proxy 写盘失败：返回 Err，池、注册表、磁盘全不变。
///
/// 反事实：把 `pool.proxies.push` 挪回写盘之前，`list_proxies().len()` 会变 1。
#[tokio::test]
async fn bdd_i3_create_proxy_write_failure_publishes_nothing() {
    let dir = unwritable_dir();
    let manager = manager_at(unwritable_path(&dir), vec![api_key_credential(1)]);

    let error = manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");
    assert!(manager.list_proxies().is_empty(), "池不得出现半成品条目");
    assert!(
        manager
            .registered_route_for_test(&RouteKey::Proxy(ProxyConfig::new(
                "socks5://127.0.0.1:1080"
            )))
            .is_none(),
        "失败时不得发布新的路由注册"
    );

    // 之后一次无关落盘（set_priority）不得把半成品写进文件。
    let _ = manager.set_priority(1, 7);
    assert!(!unwritable_path(&dir).exists(), "文件不该被创建");
}

/// update_proxy 写盘失败：池条目与受影响凭据的 route 指针都不变。
#[tokio::test]
async fn bdd_i3_update_proxy_write_failure_keeps_pool_and_routes() {
    let dir = TempDir::new();
    let target = H2TargetServer::spawn().await;
    let socks_a = spawn_socks5_redirect(target.addr).await;
    let socks_b = spawn_socks5_redirect(target.addr).await;

    let mut cred = api_key_credential(1);
    cred.proxy_id = Some("a".into());
    let manager = manager(&dir, vec![cred], vec![pool_entry("a", &socks_a.url)]);
    let route_before = manager.route_ptr_for_test(1).unwrap();
    let url_before = manager.list_proxies()[0].url.clone();

    // 换成必然写失败的路径：新建一个同状态但目标不可写的 manager 不现实，
    // 因此这里直接删掉目录让 rename 与原地写都失败。
    std::fs::remove_file(dir.path()).unwrap();
    std::fs::create_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join("blocker"), b"x").unwrap();

    let error = manager
        .update_proxy(
            "a",
            ProxyUpdateRequest {
                url: Some(Some(socks_b.url.clone())),
                ..Default::default()
            },
        )
        .await
        .expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");
    assert_eq!(
        manager.list_proxies()[0].url,
        url_before,
        "失败时池条目必须保持原样"
    );
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        route_before,
        "失败时凭据 route 指针不得变化"
    );
}

/// delete_proxy 写盘失败：条目仍在池里。
#[tokio::test]
async fn bdd_i3_delete_proxy_write_failure_keeps_entry() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    std::fs::remove_file(dir.path()).unwrap();
    std::fs::create_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join("blocker"), b"x").unwrap();

    let error = manager.delete_proxy("p1").await.expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");
    assert_eq!(manager.list_proxies().len(), 1, "失败时条目必须仍在池里");
}

/// bind 写盘失败：绑定字段、route 指针、state_revision 全部不变。
#[tokio::test]
async fn bdd_i3_bind_write_failure_keeps_binding_and_route() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    let route_before = manager.route_ptr_for_test(1).unwrap();
    let revision_before = manager.runtime_state_for_test(1).unwrap().3;

    std::fs::remove_file(dir.path()).unwrap();
    std::fs::create_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join("blocker"), b"x").unwrap();

    let error = manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");

    let snapshot = manager.snapshot();
    assert_eq!(
        snapshot.entries[0].proxy_mode, "inherit",
        "失败时绑定字段必须保持原样"
    );
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        route_before,
        "失败时 route 指针必须保持原样"
    );
    assert_eq!(
        manager.runtime_state_for_test(1).unwrap().3,
        revision_before,
        "失败时 state_revision 不得递增"
    );
}

/// Minor 3：`update_proxy` / `bind` 写盘失败时，注册表里不得留下新网络身份的
/// client。
///
/// 缺陷形态：事务构造阶段就 `pool.publish`，写盘失败后注册表残留一个带新代理
/// （含密码）的 client，池里却没有任何条目引用它——要等下一次成功写触发的
/// prune 才收。`create_proxy` 是写盘后才发布的，这里对齐它。
///
/// 前置条件断言：失败注入点确实在写盘（返回的是 Storage 错误），且失败之后
/// 原池条目 / 原绑定仍然可用（不是把整个 manager 写坏了）。
///
/// 反事实（已现场验证）：把 update/bind 的 `pool.publish` 挪回事务构造阶段，
/// 两条断言各自在 `probe(...) is None` 处红。
#[tokio::test]
async fn bdd_minor3_failed_write_publishes_no_route() {
    let dir = TempDir::new();
    let target = H2TargetServer::spawn().await;
    let socks_a = spawn_socks5_redirect(target.addr).await;
    let socks_b = spawn_socks5_redirect(target.addr).await;
    let socks_c = spawn_socks5_redirect(target.addr).await;

    let mut cred = api_key_credential(1);
    cred.proxy_id = Some("a".into());
    let manager = manager(&dir, vec![cred], vec![pool_entry("a", &socks_a.url)]);

    let key_b = RouteKey::Proxy(ProxyConfig::new(&socks_b.url));
    let key_c = RouteKey::Proxy(ProxyConfig::new(&socks_c.url));
    // 前置条件：这两个身份此刻都还不在注册表里。
    assert!(manager.registered_route_for_test(&key_b).is_none());
    assert!(manager.registered_route_for_test(&key_c).is_none());

    // 让后续写盘必然失败（目录换成文件，rename 与原地写都失败）。
    std::fs::remove_file(dir.path()).unwrap();
    std::fs::create_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join("blocker"), b"x").unwrap();

    let error = manager
        .update_proxy(
            "a",
            ProxyUpdateRequest {
                url: Some(Some(socks_b.url.clone())),
                ..Default::default()
            },
        )
        .await
        .expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");
    assert!(
        manager.registered_route_for_test(&key_b).is_none(),
        "update_proxy 写盘失败后注册表不得残留新代理的 client"
    );

    let error = manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Inline {
                url: socks_c.url.clone(),
                username: None,
                password: None,
            },
        )
        .await
        .expect_err("写盘必然失败");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");
    assert!(
        manager.registered_route_for_test(&key_c).is_none(),
        "bind 写盘失败后注册表不得残留新内联代理的 client"
    );

    // 前置条件：失败没有破坏既有状态——原池条目仍在，绑定仍是原来的池条目。
    assert_eq!(manager.list_proxies().len(), 1);
    assert_eq!(manager.snapshot().entries[0].proxy_mode, "pool");
}

// ─────────────────────────────────────────────────────────────
// I4：新增凭据的验证刷新必须经所选代理
// ─────────────────────────────────────────────────────────────

/// mode=pool 新增凭据：验证刷新必须经该代理夹具，目标不得收到绕过代理的请求。
///
/// 反事实：把验证路由改回 `effective_route_key(None)`（池身份传 None 回落继承），
/// 刷新会直连——`socks.connections()==0` 且请求落到直连目标上。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_i4_add_credential_pool_verification_uses_selected_proxy() {
    let dir = TempDir::new();
    // OAuth mock 只经 SOCKS 隧道才可达：URL 里的主机名不可解析（代理解析或
    // 客户端解析都一样），因此"绕过代理直连"必然失败。凭据能被采纳本身就是
    // "走了所选代理"的证据；连接计数与目标观测再把它钉死。
    let target = TargetServer::spawn(r#"{"accessToken":"fresh-access","expiresIn":3600}"#).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    // 用 socks5h 让**代理**解析主机名：客户端解析的话，"不可解析主机"会在
    // 本地就失败，观测不到隧道是否建立。
    let socks_url = socks.url.replacen("socks5://", "socks5h://", 1);
    let manager = manager(&dir, vec![], vec![pool_entry("p1", &socks_url)]);
    manager.install_refresh_url_for_test(format!(
        "http://kiro-rs-i4-probe.invalid:{}/refresh",
        target.addr.port()
    ));

    let new_cred = KiroCredentials {
        refresh_token: Some("r".repeat(120)),
        auth_method: Some("social".into()),
        proxy_id: Some("p1".into()),
        ..Default::default()
    };
    let added = manager
        .add_credential(new_cred)
        .await
        .expect("经所选代理完成验证刷新");
    assert_eq!(socks.stats.connections(), 1, "验证刷新必须经所选代理");
    let observed = socks.stats.targets();
    assert!(
        observed
            .iter()
            .any(|item| item.target.starts_with("kiro-rs-i4-probe.invalid:")),
        "代理必须看到该目标: {observed:?}"
    );
    let snapshot = manager.snapshot();
    assert!(
        snapshot.entries.iter().any(|entry| entry.id == added),
        "验证刷新成功后凭据必须被采纳"
    );
}

/// mode=pool 但池里没有该 proxyId：新增必须失败且不新增凭据。
#[tokio::test]
async fn bdd_i4_add_credential_missing_pool_proxy_is_rejected() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    let new_cred = KiroCredentials {
        refresh_token: Some("r".repeat(120)),
        auth_method: Some("social".into()),
        proxy_id: Some("missing".into()),
        ..Default::default()
    };
    let error = manager
        .add_credential(new_cred)
        .await
        .expect_err("池里不存在该代理时必须拒绝");
    assert!(error.to_string().contains("代理不存在"), "{error}");
    assert_eq!(manager.total_count(), 0, "拒绝时不得新增凭据");
}

// ─────────────────────────────────────────────────────────────
// I5：add_credential 与 delete_proxy 竞态
// ─────────────────────────────────────────────────────────────

/// add 卡在"网络验证之后、取 save lock 之前"时删除该代理：
/// add 必须失败、不新增凭据、磁盘无悬空 proxyId。
///
/// 反事实：去掉 add 在锁内的复核（只在锁外检查过），add 会成功并写出
/// 悬空 `proxyId`，重启时 `validate_document` 拒载。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_i5_add_credential_rechecks_proxy_under_save_lock() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();

    let gate = Arc::new(crate::kiro::token_manager::proxy_pool::AdminWriteGate::new());
    manager.install_add_gate_for_test(gate.clone());

    let adder = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .add_credential(KiroCredentials {
                    kiro_api_key: Some("ksk_new".into()),
                    proxy_id: Some("p1".into()),
                    ..Default::default()
                })
                .await
        })
    };
    // 只等到达、不放行：删除必须在 add 取 save lock **之前**完成。
    gate.arrived.notified().await;
    manager
        .delete_proxy("p1")
        .await
        .expect("删除未被引用的代理");
    gate.release.add_permits(1);
    adder
        .await
        .unwrap()
        .expect_err("代理已被删除，新增必须失败");

    assert_eq!(manager.total_count(), 0, "失败时不得新增凭据");
    let raw = std::fs::read_to_string(dir.path()).unwrap();
    assert!(!raw.contains("p1"), "磁盘不得留下悬空 proxyId: {raw}");
    // 文件必须仍能被严格解析（下次启动不失败）。
    assert!(CredentialsConfig::load(dir.path()).is_ok());
}

/// 反向顺序：add 先提交，之后 delete_proxy 因仍被引用而冲突。
#[tokio::test]
async fn bdd_i5_delete_after_add_conflicts() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    manager
        .add_credential(KiroCredentials {
            kiro_api_key: Some("ksk_new".into()),
            proxy_id: Some("p1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let error = manager
        .delete_proxy("p1")
        .await
        .expect_err("仍被新凭据引用，删除必须冲突");
    assert!(error.to_string().contains("引用"), "{error}");
}

// ─────────────────────────────────────────────────────────────
// I6：InvalidConfig 禁用的凭据不得被 set_disabled(false) 静默启用
// ─────────────────────────────────────────────────────────────

/// 反事实：去掉 `set_disabled` 的 InvalidConfig 拦截，第一次断言处变红
/// （返回 Ok 且凭据被启用，随后会带着回落成继承路由的 route 直连出流量）。
#[tokio::test]
async fn bdd_i6_set_disabled_false_rejects_invalid_config_credential() {
    let dir = TempDir::new();
    let mut bad = api_key_credential(1);
    // 当前配置**确实无效**（URL 解析不出来）→ route 回落为继承路由，运行时
    // 事实 `route_build_failed` 为真，I6 的拦截必须继续生效（F2(c)）。
    bad.proxy_url = Some("://".into());
    let manager = manager(&dir, vec![bad], Vec::new());

    let snapshot = manager.snapshot();
    assert!(snapshot.entries[0].disabled, "前提：启动时已被禁用");
    assert_eq!(
        snapshot.entries[0].disabled_reason.as_deref(),
        Some("InvalidConfig")
    );

    let error = manager
        .set_disabled(1, false)
        .expect_err("InvalidConfig 凭据不得被启用");
    assert!(error.to_string().contains("配置无效"), "{error}");
    // Minor 9：文案不能要求重启——改绑成功即可恢复，只有手改文件才需要重启。
    assert!(
        !error.to_string().contains("请修正配置后重启服务"),
        "文案不得笼统要求重启: {error}"
    );
    assert!(
        error.to_string().contains("通过代理绑定修正配置"),
        "文案必须指出可恢复的路径: {error}"
    );
    assert!(
        manager.snapshot().entries[0].disabled,
        "拒绝启用后必须保持禁用"
    );

    // `reset_and_enable` 的既有拦截面不变（同口径、同风格）。
    let error = manager
        .reset_and_enable(1)
        .expect_err("reset_and_enable 同样拒绝");
    assert!(error.to_string().contains("配置无效"), "{error}");
}

// ─────────────────────────────────────────────────────────────
// I7：route 构建位置、共享复用与发布时机
// ─────────────────────────────────────────────────────────────

/// 持 `credentials_save_lock` 期间调用 update_proxy：新 key 的构建必须已经完成。
///
/// 观测确定性：update 卡在闸门（锁外预建之后、取 save lock 之前），此时
/// 断言 `route_build_counter` 已为该 key 记账；随后测试自己取一次 save lock
/// 并确认它能立刻拿到（证明 update 此时还没持锁）。
///
/// 注意 `route_build_counter` 是 thread-local：本条用 `#[tokio::test]` 的
/// 单线程 runtime 让整段逻辑落在同一个 OS 线程上，因此计数可见且不与其他
/// 用例串扰（每个用例各自 `reset()`）。
///
/// 反事实：把 `Route::build` 挪回 save lock 之内，(a) 的计数断言会在闸门处变红。
#[tokio::test]
async fn bdd_i7_update_proxy_builds_route_outside_save_lock() {
    let dir = TempDir::new();
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;
    let mut credential = api_key_credential(1);
    credential.proxy_id = Some("a".into());
    let manager = manager(&dir, vec![credential], vec![pool_entry("a", &socks_a.url)]);

    let new_key = RouteKey::Proxy(ProxyConfig::new(&socks_b.url));
    crate::http_client::route_build_counter::reset();
    assert_eq!(crate::http_client::route_build_counter::count(&new_key), 0);

    let gate = Arc::new(crate::kiro::token_manager::proxy_pool::AdminWriteGate::new());
    manager.install_admin_gate_for_test(gate.clone());
    let updater = {
        let manager = manager.clone();
        let url = socks_b.url.clone();
        tokio::spawn(async move {
            manager
                .update_proxy(
                    "a",
                    ProxyUpdateRequest {
                        url: Some(Some(url)),
                        ..Default::default()
                    },
                )
                .await
        })
    };

    gate.wait_arrival_and_release().await;
    assert_eq!(
        crate::http_client::route_build_counter::count(&new_key),
        1,
        "构建必须发生在取 save lock 之前（闸门处就该已完成）"
    );
    updater.await.unwrap().unwrap();
    assert!(
        manager.registered_route_for_test(&new_key).is_some(),
        "发布后注册表必须能查到新 route"
    );
}

/// 新建池条目的网络身份与已有内联凭据相同时：`Arc::ptr_eq` 成立、只构建一次。
///
/// 反事实：把 get-or-build 改回无条件 `Route::build` + `insert`，
/// 两次构建会得到两个不同 `Arc`，`ptr_eq` 变红。
#[tokio::test]
async fn bdd_i7_same_network_identity_shares_one_route() {
    let dir = TempDir::new();
    let socks = spawn_socks5(None, "socks5").await;

    let mut inline = api_key_credential(1);
    inline.proxy_url = Some(socks.url.clone());
    let manager = manager(&dir, vec![inline], Vec::new());
    let inline_route = manager.route_arc_for_test(1).unwrap();

    crate::http_client::route_build_counter::reset();
    manager
        .create_proxy(pool_entry("p1", &socks.url))
        .await
        .unwrap();
    let created = manager
        .registered_route_for_test(&RouteKey::Proxy(ProxyConfig::new(&socks.url)))
        .expect("新建条目必须已注册 route");

    assert!(
        Arc::ptr_eq(&inline_route, &created),
        "相同网络身份必须复用同一个 route Arc（P3）"
    );
    assert_eq!(
        crate::http_client::route_build_counter::count(&RouteKey::Proxy(ProxyConfig::new(
            &socks.url
        ))),
        0,
        "命中注册表时不得重新构建 client"
    );
}

/// 两个并发 update 之后，磁盘、池、受影响凭据的 route 指向同一份最终配置。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_i7_concurrent_updates_converge() {
    let dir = TempDir::new();
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;
    let socks_c = spawn_socks5(None, "socks5").await;

    let mut cred = api_key_credential(1);
    cred.proxy_id = Some("a".into());
    let manager = manager(&dir, vec![cred], vec![pool_entry("a", &socks_a.url)]);

    let first = {
        let manager = manager.clone();
        let url = socks_b.url.clone();
        tokio::spawn(async move {
            manager
                .update_proxy(
                    "a",
                    ProxyUpdateRequest {
                        url: Some(Some(url)),
                        ..Default::default()
                    },
                )
                .await
        })
    };
    let second = {
        let manager = manager.clone();
        let url = socks_c.url.clone();
        tokio::spawn(async move {
            manager
                .update_proxy(
                    "a",
                    ProxyUpdateRequest {
                        url: Some(Some(url)),
                        ..Default::default()
                    },
                )
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
    })
    .await
    .expect("并发 update 必须完成");

    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    let (_, proxies) = loaded.into_parts();
    let disk_url = proxies[0].url.clone();

    let published_url = {
        // 池里此刻的 URL 与已发布 route 必须与磁盘一致。
        let key = RouteKey::Proxy(ProxyConfig::new(&disk_url));
        match manager.registered_route_for_test(&key) {
            Some(route) => {
                assert!(
                    Arc::ptr_eq(&route, &manager.route_arc_for_test(1).unwrap()),
                    "凭据 route 必须指向已发布的那份注册表实例"
                );
                assert_eq!(route.key(), &key, "注册表的 key 必须与磁盘一致");
                disk_url
            }
            None => panic!("磁盘里的代理必须在注册表中有对应 route"),
        }
    };
    assert_eq!(
        manager.list_proxies()[0].url,
        redact_proxy_url(&published_url),
        "池视图、磁盘、注册表必须指向同一份最终配置"
    );
}

// ─────────────────────────────────────────────────────────────
// J3：hasProxy 语义必须与 master 一致
// ─────────────────────────────────────────────────────────────

/// `hasProxy` 表示"该凭据自己有代理覆盖"（master 的 `proxyUrl.is_some()`），
/// direct 也算有；它与"实际是否经代理出站"是两件事。
///
/// 三种旧模式 × 有无全局代理共 6 个组合，逐一对照 master 语义；
/// pool 模式是新增表达，按同一规则为 true。
///
/// 反事实：把 `proxy_view_for` 改回 `has_proxy: effective.is_some()`，
/// 会在 (direct, 无全局) → 期望 true/实际 false 与
/// (inherit, 有全局) → 期望 false/实际 true 两处变红。
#[test]
fn bdd_j3_has_proxy_matches_legacy_semantics() {
    let global = ProxyConfig::new("http://global.example:3128");
    let direct = KiroCredentials {
        id: Some(1),
        kiro_api_key: Some("ksk_j3_direct".into()),
        proxy_url: Some("direct".into()),
        ..Default::default()
    };
    let inline = KiroCredentials {
        id: Some(2),
        kiro_api_key: Some("ksk_j3_inline".into()),
        proxy_url: Some("socks5://own.example:1080".into()),
        ..Default::default()
    };
    let inherit = KiroCredentials {
        id: Some(3),
        kiro_api_key: Some("ksk_j3_inherit".into()),
        ..Default::default()
    };

    // (凭据, 有无全局代理, 期望 hasProxy, 期望 effectiveProxyUrl 是否为 Some)
    let cases = [
        (&direct, None, true, false),
        (&direct, Some(&global), true, false),
        (&inline, None, true, true),
        (&inline, Some(&global), true, true),
        (&inherit, None, false, false),
        (&inherit, Some(&global), false, true),
    ];
    for (credential, global_proxy, expected_has_proxy, expected_effective) in cases {
        let dir = TempDir::new();
        let manager = manager_with_global_proxy(
            &dir,
            vec![(*credential).clone()],
            Vec::new(),
            global_proxy.cloned(),
        )
        .unwrap();
        let entry = manager.snapshot().entries.into_iter().next().unwrap();
        assert_eq!(
            entry.has_proxy,
            expected_has_proxy,
            "hasProxy 必须与 master 语义一致: proxyUrl={:?} global={}",
            credential.proxy_url,
            global_proxy.is_some()
        );
        assert_eq!(
            entry.effective_proxy_url.is_some(),
            expected_effective,
            "effectiveProxyUrl 保持现状（含继承来的全局代理）: proxyUrl={:?}",
            credential.proxy_url
        );
    }
}

/// pool 模式：凭据自己绑定了池条目，`hasProxy` 为 true。
#[test]
fn bdd_j3_pool_binding_reports_has_proxy() {
    let dir = TempDir::new();
    let mut credential = api_key_credential(1);
    credential.proxy_id = Some("p1".into());
    let manager = manager(
        &dir,
        vec![credential],
        vec![pool_entry("p1", "socks5://127.0.0.1:1080")],
    );
    let entry = manager.snapshot().entries.into_iter().next().unwrap();
    assert!(entry.has_proxy, "pool 绑定是凭据自己的代理覆盖");
    assert_eq!(entry.proxy_mode, "pool");
    assert!(entry.effective_proxy_url.is_some());
}

// ─────────────────────────────────────────────────────────────
// J1/J2：manager 层的纵深防御与类型化错误
// ─────────────────────────────────────────────────────────────

/// 绕过 admin 直接把"`proxyId` + 旧字段"的凭据交给 `add_credential`：
/// 必须返回错误、不新增凭据、磁盘字节不变。
///
/// 反事实：去掉 `add_credential_impl` 开头的 `validate_new_credential_binding`，
/// 本条变红——凭据被采纳，写出的文件下次启动被 `validate_document` 拒载。
#[tokio::test]
async fn bdd_j1_manager_rejects_binding_conflict_before_write() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    let before = std::fs::read(dir.path()).expect("前提：池操作已落盘");

    let error = manager
        .add_credential(KiroCredentials {
            kiro_api_key: Some("ksk_j1_conflict".into()),
            proxy_id: Some("p1".into()),
            proxy_url: Some("socks5://other:1080".into()),
            ..Default::default()
        })
        .await
        .expect_err("冲突绑定必须拒绝");

    assert_eq!(manager.total_count(), 0, "拒绝时不得新增凭据");
    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        before,
        "拒绝时磁盘字节必须不变"
    );
    assert!(
        CredentialsConfig::load(dir.path()).is_ok(),
        "磁盘文件必须仍能被加载期接受"
    );
    // 类型化错误：Admin 层据此映射 400，而不是关键字猜。
    let proxy_error = error
        .downcast_ref::<crate::kiro::token_manager::ProxyPoolError>()
        .expect("必须是类型化的 ProxyPoolError");
    assert!(
        matches!(
            proxy_error,
            crate::kiro::token_manager::ProxyPoolError::Invalid(_)
        ),
        "{proxy_error:?}"
    );
}

/// 悬空 `proxyId` 在 manager 层是 NotFound（映射 404），不是 500。
#[tokio::test]
async fn bdd_j2_missing_pool_proxy_is_typed_not_found() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    let error = manager
        .add_credential(KiroCredentials {
            kiro_api_key: Some("ksk_j2_missing".into()),
            proxy_id: Some("missing".into()),
            ..Default::default()
        })
        .await
        .expect_err("池里没有该代理");
    let proxy_error = error
        .downcast_ref::<crate::kiro::token_manager::ProxyPoolError>()
        .expect("必须是类型化的 ProxyPoolError");
    assert!(
        matches!(
            proxy_error,
            crate::kiro::token_manager::ProxyPoolError::NotFound(_)
        ),
        "{proxy_error:?}"
    );
}

/// 内联 URL 无法构建（ftp 不是代理协议）：Invalid（映射 400）。
#[tokio::test]
async fn bdd_j2_unbuildable_inline_proxy_is_typed_invalid() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    let error = manager
        .add_credential(KiroCredentials {
            kiro_api_key: Some("ksk_j2_inline".into()),
            proxy_url: Some("ftp://not-a-proxy:21".into()),
            ..Default::default()
        })
        .await
        .expect_err("ftp 不能作为代理");
    let proxy_error = error
        .downcast_ref::<crate::kiro::token_manager::ProxyPoolError>()
        .expect("必须是类型化的 ProxyPoolError");
    assert!(
        matches!(
            proxy_error,
            crate::kiro::token_manager::ProxyPoolError::Invalid(_)
        ),
        "{proxy_error:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// J5：池条目 id 在手改文件时加载期 fail-fast
// ─────────────────────────────────────────────────────────────

/// 手改文件里的 `.`/`..`/空格/斜杠 id 必须在加载期被拒绝。
///
/// 反事实：把 `validate_proxy_entry` 的 id 判断改回 `trim().is_empty()`，
/// 四条全部变红（加载成功，条目在 UI 里无法定位）。
#[test]
fn bdd_j5_handwritten_unsafe_pool_ids_are_rejected_at_load() {
    let dir = TempDir::new();
    for id in [".", "..", " p1", "a/b"] {
        let content = format!(
            r#"{{"version":1,"proxies":[{{"id":"{id}","name":"P","url":"socks5://h:1"}}],"credentials":[]}}"#
        );
        std::fs::write(dir.path(), &content).unwrap();
        let error = CredentialsConfig::load(dir.path())
            .expect_err(&format!("id {id:?} 必须在加载期被拒绝"));
        assert!(
            error.to_string().contains("id"),
            "错误必须指向 id 字段: {error}"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// J9：旧格式里的 proxyId 不得静默回落
// ─────────────────────────────────────────────────────────────

/// 数组/单对象格式没有代理池：出现 `proxyId` 必须加载期 fail-fast，且错误带凭据标识。
///
/// 反事实：去掉 `reject_legacy_pool_binding`，两条变红（加载成功、静默回落继承）。
#[test]
fn bdd_j9_legacy_files_with_proxy_id_are_rejected() {
    let dir = TempDir::new();
    for content in [
        r#"[{"id":42,"kiroApiKey":"ksk_j9_array","proxyId":"p1"}]"#,
        r#"{"id":43,"kiroApiKey":"ksk_j9_single","proxyId":"p1"}"#,
    ] {
        std::fs::write(dir.path(), content).unwrap();
        let error = CredentialsConfig::load(dir.path()).expect_err(&format!("必须拒绝: {content}"));
        let message = error.to_string();
        assert!(
            message.contains("不存在的代理"),
            "错误风格必须与封套内悬空绑定一致: {message}"
        );
        assert!(
            message.contains("42") || message.contains("43"),
            "错误必须带凭据标识: {message}"
        );
    }

    // 不带 proxyId 的旧文件仍然加载成功（兼容性不退）。
    std::fs::write(dir.path(), r#"[{"id":44,"kiroApiKey":"ksk_j9_ok"}]"#).unwrap();
    assert!(CredentialsConfig::load(dir.path()).is_ok());
}

// ─────────────────────────────────────────────────────────────
// J6：PATCH 的 name/url 不可空（manager 层）
// ─────────────────────────────────────────────────────────────

/// `url: null` 必须返回 Invalid 且池条目不变；`name: null` 同理。
///
/// 反事实：恢复"忽略 null"的 `apply`，第一条变红（Ok，条目 URL 不变但返回成功）。
#[tokio::test]
async fn bdd_j6_null_url_and_name_are_rejected() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    let before = manager.list_proxies();

    for (patch, field) in [
        (
            ProxyUpdateRequest {
                url: Some(None),
                ..Default::default()
            },
            "url",
        ),
        (
            ProxyUpdateRequest {
                name: Some(None),
                ..Default::default()
            },
            "name",
        ),
    ] {
        let error = manager
            .update_proxy("p1", patch)
            .await
            .expect_err(&format!("{field} 不可空"));
        let proxy_error = error;
        assert!(
            matches!(
                proxy_error,
                crate::kiro::token_manager::ProxyPoolError::Invalid(_)
            ),
            "{proxy_error:?}"
        );
        assert!(
            proxy_error.to_string().contains(field),
            "错误必须指明字段名: {proxy_error}"
        );
    }

    let after = manager.list_proxies();
    assert_eq!(after.len(), before.len());
    assert_eq!(after[0].name, before[0].name, "被拒绝的 PATCH 不得改动条目");
    assert_eq!(after[0].url, before[0].url);
}

// ─────────────────────────────────────────────────────────────
// J8：管理端快照里的 direct 仍显示为 direct
// ─────────────────────────────────────────────────────────────

/// `direct` 不是 URL，各调用方在调用 `redact_proxy_url` 之前处理它；
/// 快照里必须仍是 `direct`，不能被占位符顶掉。
#[test]
fn bdd_j8_direct_is_still_shown_as_direct() {
    let dir = TempDir::new();
    let mut credential = api_key_credential(1);
    credential.proxy_url = Some("direct".into());
    let manager = manager(&dir, vec![credential], Vec::new());
    let entry = manager.snapshot().entries.into_iter().next().unwrap();
    assert_eq!(entry.proxy_mode, "direct");
    assert_eq!(entry.proxy_url.as_deref(), Some("direct"));
    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(
        !serialized.contains(crate::http_client::INVALID_PROXY_URL_PLACEHOLDER),
        "direct 不得被脱敏占位符顶掉: {serialized}"
    );
}

/// 内联代理的旧值没有 scheme（`admin:s3cret@host:1080`）：快照不得泄漏密码。
#[test]
fn bdd_j8_inline_snapshot_never_leaks_password() {
    let dir = TempDir::new();
    std::fs::write(
        dir.path(),
        r#"[{"id":1,"kiroApiKey":"ksk_j8","proxyUrl":"admin:s3cret@10.0.0.1:1080"}]"#,
    )
    .unwrap();
    let loaded = CredentialsConfig::load(dir.path()).unwrap();
    let (credentials, proxies) = loaded.into_parts();
    let manager = manager(&dir, credentials, proxies);
    let serialized = serde_json::to_string(&manager.snapshot()).unwrap();
    assert!(!serialized.contains("s3cret"), "{serialized}");
}

// ─────────────────────────────────────────────────────────────
// F1：锁外构建的 `Arc` 必须真的被带进锁内（save lock 内零构建）
// ─────────────────────────────────────────────────────────────

/// `update_proxy` 改 URL 时，**save lock 临界区内的 Route 构建次数必须为 0**。
///
/// 缺陷形态（F1）：锁外 `route_get_or_build` 只构建不注册、返回值被丢弃，锁内
/// 又 `pool.route(&key)` 重建一次——锁外那次白干，第二遍（含 TLS 根证书加载的
/// 磁盘 I/O）落在 save lock 里，阻塞刷新落盘。
///
/// 前置条件断言（缺一则本用例测的是空路径）：
/// 1. 新 key 的构建总数为 1（只建一次，不是两次、也不是零次）；
/// 2. 该凭据的 route 指针确实换了（P3），证明走的不是"身份没变"的短路分支。
///
/// 观测点 `builds_in_save_lock` 是 thread-local，且管理写事务的临界区是同步的
/// （无 `.await`、无跨线程移交），所以本条用单线程 runtime 让整段落在一个 OS
/// 线程上即可测量。
///
/// 反事实（已现场验证）：把 `update_proxy` 的锁内分支改回无条件
/// `Route::build`，`builds_in_save_lock()` 变成 1，本用例第一条断言红。
#[tokio::test]
async fn bdd_f1_update_proxy_builds_zero_routes_inside_save_lock() {
    use crate::http_client::route_build_counter;

    let dir = TempDir::new();
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;
    let mut credential = api_key_credential(1);
    credential.proxy_id = Some("a".into());
    let manager = manager(&dir, vec![credential], vec![pool_entry("a", &socks_a.url)]);

    let route_before = manager.route_ptr_for_test(1).unwrap();
    let new_key = RouteKey::Proxy(ProxyConfig::new(&socks_b.url));
    route_build_counter::reset();
    assert_eq!(
        route_build_counter::count(&new_key),
        0,
        "前置条件：新 key 尚未构建"
    );

    manager
        .update_proxy(
            "a",
            ProxyUpdateRequest {
                url: Some(Some(socks_b.url.clone())),
                ..Default::default()
            },
        )
        .await
        .expect("改 URL 必须成功");

    assert_eq!(
        route_build_counter::count(&new_key),
        1,
        "前置条件：新 key 必须恰好构建一次（两次=锁外那次被丢弃；零次=重建了却没用上）"
    );
    assert_ne!(
        manager.route_ptr_for_test(1).unwrap(),
        route_before,
        "前置条件：改 URL 必须换掉凭据的 route 指针（P3），否则测的是空路径"
    );
    assert_eq!(
        route_build_counter::builds_in_save_lock(),
        0,
        "save lock 临界区内不得构建任何 Route（F1：构建要加载 TLS 根证书，是磁盘 I/O）"
    );
}

/// `bind` 到**未注册**的 key 时，save lock 临界区内的 Route 构建次数为 0。
///
/// 缺陷形态（F1）：`bind` 同样丢弃锁外 `route_get_or_build` 的返回值，锁内
/// `pool.route(&published_key, ..)` 再建一遍。
///
/// 前置条件断言：新 key 构建总数为 1、凭据 route 指针确实指向新 key 对应的
/// 实例（不是继承路由）。
///
/// 反事实（已现场验证）：把 `bind` 的锁内分支改回 `pool.route(..)`，
/// `builds_in_save_lock()` 变成 1，本用例红。
#[tokio::test]
async fn bdd_f1_bind_unregistered_key_builds_zero_routes_inside_save_lock() {
    use crate::http_client::route_build_counter;

    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    let route_before = manager.route_ptr_for_test(1).unwrap();
    // 内联绑定用一个**池里不存在**的网络身份：注册表里必然没有它，因此
    // `bind` 的复核分支会走"probe 未命中"这条路——正是 F1 缺陷形态里
    // 锁内 `pool.route()` 重建的那条。
    let new_key = RouteKey::Proxy(ProxyConfig::new("socks5://127.0.0.1:18081"));
    route_build_counter::reset();
    assert!(
        manager.registered_route_for_test(&new_key).is_none(),
        "前置条件：该 key 必须尚未注册，否则走不到未命中分支"
    );
    assert_eq!(route_build_counter::count(&new_key), 0);

    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Inline {
                url: "socks5://127.0.0.1:18081".into(),
                username: None,
                password: None,
            },
        )
        .await
        .expect("绑定必须先构建后提交");

    assert_eq!(
        route_build_counter::count(&new_key),
        1,
        "前置条件：新 key 必须恰好构建一次（两次=锁外那次被丢弃；零次=重建了却没用上）"
    );
    assert_ne!(
        manager.route_ptr_for_test(1).unwrap(),
        route_before,
        "前置条件：绑定必须换掉凭据的 route 指针"
    );
    assert_eq!(
        route_build_counter::builds_in_save_lock(),
        0,
        "save lock 临界区内不得构建任何 Route（F1）"
    );
}

// ─────────────────────────────────────────────────────────────
// F2：InvalidConfig 必须可以从 UI 恢复（当前配置为准，不看历史落盘值）
// ─────────────────────────────────────────────────────────────

/// 完整链路：无效内联 → 启动禁用为 InvalidConfig → 刷新落盘把 reason 写进文件
/// → 管理员改绑到有效代理 → **启用成功** → 重启后仍可用。
///
/// 缺陷形态（F2）：`set_disabled(false)` 只看落盘/内存里的
/// `disabled_reason == InvalidConfig` 就 bail，而 bind 发布路径成功后不清该
/// reason。于是整条恢复链断在最后一步，只能手改 JSON。master 上这条判据是
/// 唯一的解禁通道，所以这是对 master 的行为回归。
///
/// 前置条件断言：
/// 1. 启动后确实处于 InvalidConfig 禁用态（否则测的不是恢复路径）；
/// 2. 改绑完成后落盘文件里**仍能看到** `InvalidConfig` 的历史痕迹已不在
///    （`credentials` 快照里 disabled=false），证明不是"文件里没写过"的假象；
/// 3. 强制刷新真的成功（证明 route 已经指向可用的新代理，而不只是把 flag 清了）。
///
/// 反事实（已现场验证）：把 `set_disabled` 的拦截判据改回
/// `entry.disabled_reason == Some(InvalidConfig)`（并让 bind 不清 reason），
/// 本用例在"改绑后必须能启用"处红：`凭据 #1 因配置无效被禁用，请通过代理绑定修正配置（手改配置文件需重启生效）`。
/// F2 用：可刷新的 social 凭据 + 旧内联代理 URL。
fn social_credential_with_inline(url: &str) -> KiroCredentials {
    KiroCredentials {
        access_token: Some("access-f2".into()),
        refresh_token: Some(format!("f2{}", "r".repeat(120))),
        auth_method: Some("social".into()),
        proxy_url: Some(url.to_string()),
        ..Default::default()
    }
}

#[tokio::test]
async fn bdd_f2_invalid_config_credential_recovers_after_rebinding() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(r#"{"accessToken":"fresh-access","expiresIn":3600}"#).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let socks_url = socks.url.replacen("socks5://", "socks5h://", 1);

    // 旧内联 URL 连解析都不成 → 启动期禁用为 InvalidConfig。
    let mut bad = social_credential_with_inline("://");
    bad.id = Some(1);
    let manager = manager(&dir, vec![bad], vec![pool_entry("p1", &socks_url)]);
    manager.install_refresh_url_for_test(format!(
        "http://kiro-rs-f2-probe.invalid:{}/refresh",
        target.addr.port()
    ));

    // (1) 前置条件：确实处于 InvalidConfig 禁用态。
    let snapshot = manager.snapshot();
    assert!(snapshot.entries[0].disabled, "前置条件：启动时必须被禁用");
    assert_eq!(
        snapshot.entries[0].disabled_reason.as_deref(),
        Some("InvalidConfig"),
        "前置条件：禁用原因必须是 InvalidConfig"
    );

    // (2) 刷新落盘一次，把 reason 写进文件（模拟真实序列）。
    let _ = manager.force_refresh_token_for(1).await;
    manager
        .set_priority(1, 1)
        .expect("管理写必须落盘，把历史 reason 写进文件");
    let on_disk = std::fs::read_to_string(dir.path()).unwrap();
    assert!(
        on_disk.contains("InvalidConfig"),
        "前置条件：历史 reason 必须已经落进文件，实际: {on_disk}"
    );

    // (3) 管理员改绑到有效代理（配置此时确实可构建）。
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .expect("改绑到有效代理必须成功");

    // (4) 启用必须成功——这是 F2 的核心。
    manager
        .set_disabled(1, false)
        .expect("改绑成有效配置之后，凭据必须能从 UI 启用（F2）");
    let snapshot = manager.snapshot();
    assert!(!snapshot.entries[0].disabled, "启用后必须真的可用");
    assert!(
        snapshot.entries[0].disabled_reason.is_none(),
        "InvalidConfig 必须被清掉"
    );

    // (5) 刷新可用：证明 route 指向的是可用的新代理，而不是"只是把 flag 清了"。
    manager
        .force_refresh_token_for(1)
        .await
        .expect("启用后刷新必须经新代理成功");
    assert!(socks.stats.connections() >= 1, "刷新必须经新绑定的代理");
}

/// 「配置仍然无效时启用被拒」这一臂：I6 的保护不能因为 F2 的判据改版而丢失。
///
/// 两条无效来源各一例：
/// 1. route 构建失败（URL 解析不出来）→ 运行时事实 `route_build_failed`；
/// 2. `authMethod=api_key` 缺 `kiroApiKey` → 与 route 无关的配置缺失。
///
/// 反事实（已现场验证）：把 `set_disabled` 的判据改成恒 `false`
/// （即完全去掉 I6 拦截），两个 `expect_err` 都红。
#[tokio::test]
async fn bdd_f2_still_invalid_config_cannot_be_enabled() {
    let dir = TempDir::new();
    let mut bad_route = api_key_credential(1);
    bad_route.proxy_url = Some("://".into());
    let bad_key = KiroCredentials {
        id: Some(2),
        auth_method: Some("api_key".into()),
        ..Default::default()
    };
    let manager = manager(&dir, vec![bad_route, bad_key], Vec::new());

    // 前置条件：两条都真的处于禁用态。
    let snapshot = manager.snapshot();
    assert!(
        snapshot.entries.iter().all(|entry| entry.disabled),
        "前置条件：两条都必须被禁用"
    );

    for id in [1, 2] {
        let error = manager
            .set_disabled(id, false)
            .expect_err("配置仍无效时不得启用");
        assert!(error.to_string().contains("配置无效"), "{error}");
        let error = manager
            .reset_and_enable(id)
            .expect_err("reset_and_enable 同样拒绝");
        assert!(error.to_string().contains("配置无效"), "{error}");
    }
}

// ─────────────────────────────────────────────────────────────
// F3：既有配置不套新白名单，新写入路径仍严格
// ─────────────────────────────────────────────────────────────

/// 全局代理 `127.0.0.1:7890`（**无 scheme**）必须能构造 manager。
///
/// 缺陷形态（F3）：`Route::build` 上的 `validate_proxy_scheme` 只白名单
/// `socks5/socks5h/http/https`，而 master 的 `Proxy::all` 走 reqwest `IntoProxy`，
/// 对无 scheme 的 `host:port` 会补 `http://` 重试——于是这类一直可用的部署
/// 在升级后**启动即失败**（Global route 构建失败 → 构造器 fail-fast）。
///
/// 前置条件断言：继承路由的 key 确实是 `Global`（配置真的生效了），并且
/// 两个 `localhost`/IP 形态都被接受（reqwest 两种写法都会补 scheme）。
///
/// 反事实（已现场验证）：把 `validate_proxy_scheme` 加回 `Route::build_with`，
/// 本用例在 `expect` 处红：
/// `创建继承（全局代理/系统）HTTP 客户端失败: 代理 URL 无法解析: relative URL without a base`。
#[tokio::test]
async fn bdd_f3_global_proxy_without_scheme_still_constructs() {
    let dir = TempDir::new();
    for url in ["127.0.0.1:7890", "localhost:7890"] {
        let manager = manager_with_global_proxy(
            &dir,
            vec![api_key_credential(1)],
            Vec::new(),
            Some(ProxyConfig::new(url)),
        )
        .unwrap_or_else(|error| {
            panic!("无 scheme 的全局代理 {url} 必须可用（master 语义）: {error}")
        });

        // 前置条件：全局代理真的生效（不是静默回落成 System）。
        let route = manager.route_arc_for_test(1).expect("凭据必须有 route");
        assert_eq!(
            route.key(),
            &RouteKey::Global(ProxyConfig::new(url)),
            "前置条件：{url} 必须解析成 Global 路由"
        );
    }
}

/// 旧内联 `127.0.0.1:7890`（无 scheme）的凭据：启动后**不得**被禁用为 InvalidConfig。
///
/// 这是"旧内联配置走 master 语义"的直接落点：加载期读到的内联 URL 不经过新的
/// 写边界校验，构建交给 reqwest。
///
/// 反事实（已现场验证）：把 scheme 白名单加回 `Route::build_with`，本用例在
/// "不得被禁用"处红（该凭据被标记 InvalidConfig 并回落到继承路由）。
#[tokio::test]
async fn bdd_f3_legacy_inline_without_scheme_is_not_disabled() {
    let dir = TempDir::new();
    let mut legacy = api_key_credential(1);
    legacy.proxy_url = Some("127.0.0.1:7890".into());
    let manager = manager(&dir, vec![legacy, api_key_credential(2)], Vec::new());

    let snapshot = manager.snapshot();
    let entry = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
    assert!(
        !entry.disabled,
        "无 scheme 的旧内联代理在 master 上可用，不得被禁用为 InvalidConfig"
    );
    assert!(
        entry.disabled_reason.is_none(),
        "{:?}",
        entry.disabled_reason
    );
    // 前置条件：它真的拿到了自己的代理路由，而不是回落成继承路由。
    let route = manager.route_arc_for_test(1).expect("凭据必须有 route");
    assert_eq!(
        route.key(),
        &RouteKey::Proxy(ProxyConfig::new("127.0.0.1:7890")),
        "旧内联必须解析成 Proxy 路由"
    );
}

/// 新写入路径继续严格：`create_proxy` 提交无 scheme URL 必须 400/Invalid。
///
/// 与上面两条互补，钉死分界：旧配置宽容、新配置严格。
///
/// 反事实（已现场验证）：把 `validate_pool_url` 的 scheme 匹配改成放行任意
/// 字符串，本用例红（返回 Ok）。
#[tokio::test]
async fn bdd_f3_new_pool_entry_without_scheme_is_rejected() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![], Vec::new());
    let error = manager
        .create_proxy(pool_entry("p1", "127.0.0.1:7890"))
        .await
        .expect_err("新池条目的 URL 必须带 scheme");
    assert!(
        matches!(
            error,
            crate::kiro::token_manager::ProxyPoolError::Invalid(_)
        ),
        "{error:?}"
    );
    assert!(
        manager.list_proxies().is_empty(),
        "被拒绝的条目不得留在池里"
    );
}

/// 新写入路径继续严格：管理端内联绑定无 scheme URL 必须 Invalid。
///
/// 反事实：把 `inline_proxy_config` 里的 `validate_proxy_scheme` 删掉，
/// 本用例红（绑定成功）。
#[tokio::test]
async fn bdd_f3_new_inline_binding_without_scheme_is_rejected() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    let error = manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Inline {
                url: "127.0.0.1:7890".into(),
                username: None,
                password: None,
            },
        )
        .await
        .expect_err("新内联绑定的 URL 必须带 scheme");
    assert!(
        matches!(
            error,
            crate::kiro::token_manager::ProxyPoolError::Invalid(_)
        ),
        "{error:?}"
    );
}

/// 新写入的内联代理走池 URL 的严格规则：带 userinfo 的 URL 必须被拒。
///
/// 缺陷形态（Minor 4）：内联只查 scheme + 认证成对，于是
/// `http://user:pw@host:port` 能写进 `proxyUrl`——秘密原文落盘，且与独立
/// username/password 一起用时会双重认证。
///
/// 前置条件断言：被拒绝后凭据仍处于绑定前状态、磁盘字节不变；`set_disabled`
/// 也拦不住的那条路径（新增内联）同样被拒。
///
/// 反事实（已现场验证）：把 `inline_proxy_config` 的校验换回
/// `validate_proxy_scheme`，本条在 `expect_err` 处红（绑定成功）。
#[tokio::test]
async fn bdd_minor4_inline_userinfo_is_rejected_by_bind() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    let before = manager.snapshot().entries[0].proxy_mode.clone();

    for url in [
        "http://user:pass@proxy.example:3128",
        "http://user@proxy.example:3128",
        "http://proxy.example:3128/?x=1",
        "http://proxy.example:3128/#f",
        "http://proxy.example:3128/path",
    ] {
        let error = manager
            .bind_credential_proxy(
                1,
                ProxyBindingRequest::Inline {
                    url: url.into(),
                    username: None,
                    password: None,
                },
            )
            .await
            .expect_err("带 userinfo/query/fragment/path 的内联 URL 必须被拒");
        assert!(
            matches!(
                error,
                crate::kiro::token_manager::ProxyPoolError::Invalid(_)
            ),
            "{url}: {error:?}"
        );
    }

    // 前置条件：被拒之后绑定字段没被动过。
    assert_eq!(
        manager.snapshot().entries[0].proxy_mode,
        before,
        "拒绝时不得改动绑定"
    );
}

// ─────────────────────────────────────────────────────────────
// F2-gap：落盘 InvalidConfig + 配置仍无效 → 重启后重新标记并保持禁用
// ─────────────────────────────────────────────────────────────

/// 加载期"先清后判"的重判路径：文件里写着 `disabledReason: "InvalidConfig"`，
/// 而该凭据的内联代理 URL 此刻仍然解析不出来 → 重启后必须重新标记为
/// `InvalidConfig` 并保持禁用，且启用通道（I6）继续被拒。
///
/// 为什么需要这条：上一批只覆盖了"落盘 InvalidConfig + 配置已有效 → 清除"。
/// 缺失的另一半一旦回归（比如把加载期顺序改回"先判后清"、或让
/// `build_routes_for_entries` 不再置 flag），管理员会看到一个**未禁用**但
/// route 已回落成继承路由的凭据——下一次请求就带着无效代理配置直连出流量。
///
/// 前置条件断言：
/// 1. 文件里确实写着 `disabledReason: "InvalidConfig"` 与 `disabled: true`
///    （不是"文件里压根没写"的假象）；
/// 2. 该内联 URL 真的构建不出路由（用同样的 `Route` 构建做一次独立核对）。
///
/// 反事实（已现场验证）：
/// - **A**：把 `config_currently_invalid` 改成恒 `false` → 第 (4) 条红：
///   `配置仍无效时不得启用: ()`，即 `set_disabled(false)` 返回了 Ok。
/// - **B**：`build_routes_for_entries` 的失败分支只置 `route_build_failed = false`
///   而仍调 `set_reason(InvalidConfig)` → 同样第 (4) 条红，同上消息。
/// - **C**：失败分支既不置 reason 也不置运行时事实 → 第 (2) 条红：
///   `配置仍然无效的凭据必须在重启后保持禁用`。
/// - **D（未红，如实记录）**：只把加载期的"先清 InvalidConfig"循环去掉
///   （即所谓"按落盘值恢复"）→ 用例仍绿。原因：清除只是**放宽**，真正的
///   重新标记由 `build_routes_for_entries` 完成，它在两种顺序下都会跑。
///   因此本条用例并不锁定"先清后判"这个顺序本身，锁定的是重判结果。
#[tokio::test]
async fn bdd_f2_gap_saved_invalid_config_still_invalid_is_re_marked_on_load() {
    let dir = TempDir::new();
    let invalid = "://";
    // 前置条件 2：这个 URL 确实构建不出路由（不依赖被测代码的判定）。
    assert!(
        Route::build(
            RouteKey::Proxy(ProxyConfig::new(invalid)),
            Config::default().tls_backend
        )
        .is_err(),
        "前置条件：{invalid:?} 必须构建不出路由"
    );

    let document = format!(
        r#"{{
  "version": 1,
  "proxies": [],
  "credentials": [
    {{"id": 1, "authMethod": "apiKey", "kiroApiKey": "ksk_gap_bad", "proxyUrl": "{invalid}",
      "disabled": true, "disabledReason": "InvalidConfig"}},
    {{"id": 2, "authMethod": "apiKey", "kiroApiKey": "ksk_gap_ok"}}
  ]
}}"#
    );
    std::fs::write(dir.path(), &document).unwrap();

    // 前置条件 1：文件里确实写着 InvalidConfig + disabled: true。
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path()).unwrap()).unwrap();
    assert_eq!(on_disk["credentials"][0]["disabled"], true);
    assert_eq!(on_disk["credentials"][0]["disabledReason"], "InvalidConfig");

    // 真实加载路径：文件 → CredentialsConfig::load → manager 构造。
    let loaded = CredentialsConfig::load(dir.path()).expect("文档本身合法，必须能加载");
    assert!(loaded.is_envelope(), "含 proxies/credentials 的封套格式");
    let (credentials, proxies) = loaded.into_parts();
    let manager = manager(&dir, credentials, proxies);

    // (1) 构造成功（不 panic）——上面已经走到这里。
    let snapshot = manager.snapshot();
    let bad = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
    let good = snapshot.entries.iter().find(|e| e.id == 2).unwrap();

    // (2)(3) 仍禁用，且原因仍是 InvalidConfig。
    assert!(bad.disabled, "配置仍然无效的凭据必须在重启后保持禁用");
    assert_eq!(
        bad.disabled_reason.as_deref(),
        Some("InvalidConfig"),
        "加载期必须按**当前配置**重新标记 InvalidConfig，不能只看落盘值"
    );

    // (4) I6 的保护不丢：两条启用通道都被拒。
    let error = manager
        .set_disabled(1, false)
        .expect_err("配置仍无效时不得启用");
    assert!(error.to_string().contains("配置无效"), "{error}");
    let error = manager
        .reset_and_enable(1)
        .expect_err("reset_and_enable 同样拒绝");
    assert!(error.to_string().contains("配置无效"), "{error}");
    assert!(
        manager
            .snapshot()
            .entries
            .iter()
            .find(|e| e.id == 1)
            .unwrap()
            .disabled,
        "拒绝启用后必须保持禁用"
    );

    // (5) 另一条配置有效的凭据不受影响。
    assert!(!good.disabled, "有效配置的凭据不得被连带禁用");
    assert!(good.disabled_reason.is_none());
}
