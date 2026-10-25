//! 代理池 BDD 重做批：把「恒绿/空心/只证明一半」的用例改成能因被测缺陷变红的形态。
//!
//! 本文件承载 P5（跨凭据刷新隔离）、P7（空闲死隧道剔除）、P2（直连/继承参数不变）、
//! P3（改 URL/认证真正换 route）的有效证据。原则与 `proxy_pool_bdd` 相同：
//! 只连本机回环夹具、并发边界用 notify/barrier、不靠 sleep 判定正确性。
//!
//! 每条用例的「前置条件断言」都必须先证明被观测状态真的成立（例如"客户端此刻确实
//! 卡在黑洞里"），否则断言本身可以恒绿。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::http_client::{ProxyConfig, Route, RouteKey};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::proxy_pool::ProxyEntry;
use crate::kiro::provider::KiroProvider;
use crate::kiro::proxy_fixtures::{
    H2TargetServer, TargetServer, spawn_socks5, spawn_socks5_redirect,
};
use crate::kiro::token_manager::{MultiTokenManager, ProxyBindingRequest, ProxyUpdateRequest};
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;

// ─────────────────────────────────────────────────────────────
// 共用夹具
// ─────────────────────────────────────────────────────────────

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kiro-rs-pool-iso-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> std::path::PathBuf {
        self.0.join("credentials.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn pool_entry(id: &str, url: &str) -> ProxyEntry {
    ProxyEntry {
        id: id.to_string(),
        name: id.to_string(),
        url: url.to_string(),
        username: None,
        password: None,
    }
}

/// 可刷新的 OAuth（social）凭据：`kiro_api_key` 必须为空，否则
/// `is_api_key_credential()` 为真、刷新会在 token_manager.rs:238 直接 bail。
pub(super) fn oauth_credential(id: u64, expired: bool) -> KiroCredentials {
    let mut credential = KiroCredentials {
        id: Some(id),
        access_token: Some(format!("access-{id}")),
        refresh_token: Some(format!("{id}{}", "r".repeat(120))),
        profile_arn: Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/test".to_string()),
        auth_method: Some("social".to_string()),
        priority: id as u32 - 1,
        ..Default::default()
    };
    if expired {
        credential.expires_at =
            Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    } else {
        credential.expires_at =
            Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    }
    credential
}

fn manager_with(
    dir: &TempDir,
    credentials: Vec<KiroCredentials>,
    proxies: Vec<ProxyEntry>,
) -> Arc<MultiTokenManager> {
    Arc::new(
        MultiTokenManager::new_with_pool(
            Config::default(),
            credentials,
            proxies,
            None,
            Some(dir.path()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    )
}

/// 最小 endpoint：URL 指向本地目标（与 `proxy_pool_bdd` 的同名夹具等价）。
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

/// 能按路径回固定 JSON 的 loopback OAuth 刷新服务。
///
/// 与 `token_manager::tests::Server` 同构，但在这里独立一份：本文件的用例需要
/// 「客户端连上之后停在服务端手里」的确定性观测点（`entered` 通知 + `release`
/// 放行），而不是靠 sleep 猜。
struct RefreshServer {
    url: String,
    state: Arc<RefreshState>,
    task: tokio::task::JoinHandle<()>,
}

struct RefreshState {
    /// 收到的请求体（用于确认"刷新真的发生了"）
    requests: parking_lot::Mutex<Vec<serde_json::Value>>,
    /// 每次进入 handler 时唤醒
    entered: Notify,
    /// 当 `hold` 为真时阻塞 handler，直到 `release` 放行
    hold: std::sync::atomic::AtomicBool,
    release: tokio::sync::Semaphore,
}

impl Drop for RefreshServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RefreshServer {
    async fn spawn() -> Self {
        use axum::{Router, routing::any};
        let state = Arc::new(RefreshState {
            requests: parking_lot::Mutex::new(Vec::new()),
            entered: Notify::new(),
            hold: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Semaphore::new(0),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let state_for_route = state.clone();
        let app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let state = state_for_route.clone();
            async move {
                use axum::body::to_bytes;
                let body = to_bytes(request.into_body(), 16384).await.unwrap();
                let parsed: serde_json::Value = if body.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                };
                state.requests.lock().push(parsed);
                state.entered.notify_waiters();
                if state.hold.load(std::sync::atomic::Ordering::SeqCst) {
                    state.release.acquire().await.unwrap().forget();
                }
                axum::Json(json!({
                    "accessToken": "refreshed-access",
                    "refreshToken": format!("{}x", "r".repeat(120)),
                    "expiresIn": 3600,
                    "profileArn": "arn:aws:codewhisperer:us-east-1:111111111111:profile/test",
                }))
            }
        }));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }

    fn count(&self) -> usize {
        self.state.requests.lock().len()
    }

    /// 等到刷新服务至少收到 `count` 个请求。
    async fn wait_count(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notified = self.state.entered.notified();
                if self.count() >= count {
                    return;
                }
                notified.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "等待刷新请求超时：期望 {count} 个，实际 {} 个",
                self.count()
            )
        });
    }
}

/// 黑洞 SOCKS5 夹具：完成 SOCKS5 握手与 CONNECT 应答（让 reqwest 认为隧道
/// 已建立），随后**永不转发、永不应答**——请求字节被吞掉，TCP 保持打开。
struct BlackholeSocks {
    url: String,
    /// 客户端已连入并完成 CONNECT 的次数
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    accepted_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BlackholeSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl BlackholeSocks {
    async fn spawn() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("socks5://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_notify = Arc::new(Notify::new());
        let (accepted_for_task, notify_for_task) = (accepted.clone(), accepted_notify.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let accepted = accepted_for_task.clone();
                let notify = notify_for_task.clone();
                tokio::spawn(async move {
                    // 握手：不要求认证。
                    let mut header = [0u8; 2];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; header[1] as usize];
                    if stream.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    if stream.write_all(&[5, 0x00]).await.is_err() {
                        return;
                    }
                    // CONNECT 请求：读掉地址，回成功应答，然后永久静默。
                    let mut request = [0u8; 4];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    let mut scratch = [0u8; 260];
                    let address_len = match request[3] {
                        0x01 => 4,
                        0x03 => {
                            if stream.read_exact(&mut scratch[..1]).await.is_err() {
                                return;
                            }
                            scratch[0] as usize + 1
                        }
                        _ => 16,
                    };
                    if stream
                        .read_exact(&mut scratch[..address_len + 2])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if stream
                        .write_all(&[5, 0x00, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // 从此不再读、不再写：请求数据滞留在内核缓冲，上游永不应答。
                    accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    notify.notify_waiters();
                    std::future::pending::<()>().await;
                });
            }
        });
        Self {
            url,
            accepted,
            accepted_notify,
            task,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 等到"至少有一条客户端连接已完成 SOCKS5 CONNECT 应答"。
    async fn wait_accepted(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notified = self.accepted_notify.notified();
                if self.accepted() > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("前置条件不成立：没有客户端连入黑洞代理");
    }
}

// ─────────────────────────────────────────────────────────────
// T3 / P7：空闲死隧道剔除
// ─────────────────────────────────────────────────────────────

fn h2_route(proxy_url: &str, keepalive: Option<(Duration, Duration)>) -> Arc<Route> {
    Route::build_for_test(
        RouteKey::Proxy(ProxyConfig::new(proxy_url)),
        Config::default().tls_backend,
        true,
        keepalive,
    )
    .unwrap()
}

/// P7 的承诺：**空闲**隧道被静默掐断后，keep-alive 在 interval+timeout 内
/// 主动关掉它，下一个请求**第一次就成功**、并建立新隧道。
///
/// 与旧用例的差别（旧用例只证明了"在途请求会快速失败"）：
/// - 旧用例在 `blackhole()` 后立刻发请求，观测的是在途 PING/读超时；
/// - 本用例先让隧道**空闲**，再黑洞化，然后等夹具侧看到**客户端主动关闭**
///   这条隧道（`tunnels_closed` ≥ 1）——这才是"空闲剔除"的事件本身；
/// - 剔除后只发一次请求，不重试：命中死隧道就会失败。
///
/// 反事实见报告：删掉 `http2_keep_alive_while_idle(true)` 时第 3 步的
/// `timeout` 内观察不到客户端关闭（隧道不会被剔除）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_idle_blackholed_tunnel_is_evicted_then_next_request_succeeds_once() {
    let interval = Duration::from_millis(200);
    let ping_timeout = Duration::from_millis(100);
    let target = H2TargetServer::spawn().await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let route = h2_route(&socks.url, Some((interval, ping_timeout)));
    let url = format!("http://{}/probe", target.addr);

    // (1) 第一次请求成功建立隧道；第二次证明该隧道被复用（连接数不增）。
    //
    // body 必须读完：h2 的 keep-alive 只在**没有活跃 stream** 时才认为连接空闲
    // （hyper `Ponger::is_idle` 按 ping 通道的 Arc 计数判定），响应 body 没消费完
    // 的 stream 仍算活跃，`while_idle` 就永远不会 ping。
    for expected_requests in 1..=2 {
        let response = route.short.get(&url).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body = response.bytes().await.unwrap();
        assert_eq!(body.as_ref(), br#"{"ok":true}"#, "前置条件：body 必须读完");
        assert_eq!(
            target.requests(),
            expected_requests,
            "前置条件：请求必须真的到达目标"
        );
    }
    assert_eq!(
        target.connections(),
        1,
        "前置条件：两条请求必须复用同一条 H2 隧道"
    );
    assert_eq!(
        socks.stats.tunnels_closed(),
        0,
        "前置条件：隧道此刻仍然通着"
    );

    // (2) 隧道已空闲（没有在途请求），此刻把它黑洞化：TCP 保持打开，
    //     之后任何帧（含 PING）都不再被应答。
    let bytes_before_blackhole = socks.stats.bytes_from_client();
    target.blackhole();
    // 取证：空闲期客户端仍在往隧道写帧（PING 是 17 字节帧），说明 keep-alive
    // 确实在 while_idle 下工作，而不是"根本没发"。判定依据是夹具侧的字节观测
    // 事件（notify），`timeout` 只决定失败多快。
    tokio::time::timeout(
        Duration::from_secs(2),
        socks.stats.wait_bytes_over(bytes_before_blackhole),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "空闲期客户端没有向隧道写入任何帧：keep-alive 未在 while_idle 下触发（bytes {} -> {}）",
            bytes_before_blackhole,
            socks.stats.bytes_from_client()
        )
    });

    // (3) 等一个确定性事件：客户端因 keep-alive PING 超时主动关掉这条空闲隧道。
    //     `timeout` 只决定失败多快（8×interval + 40×timeout），判定依据是 notify。
    let eviction_deadline = interval * 8 + ping_timeout * 40;
    tokio::time::timeout(eviction_deadline, socks.stats.wait_tunnel_closed())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "空闲隧道未被 keep-alive 剔除：{:?} 内没有观察到客户端关闭（closed={}）",
                eviction_deadline,
                socks.stats.tunnels_closed()
            )
        });
    assert_eq!(
        target.connections(),
        1,
        "前置条件：剔除期间目标侧不得新建隧道（旧的还没被换掉）"
    );

    // (4) 剔除之后的下一个请求必须第一次就成功，且走一条新隧道。
    let response = route.short.get(&url).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body = response.bytes().await.unwrap();
    assert_eq!(body.as_ref(), br#"{"ok":true}"#);
    assert_eq!(
        target.connections(),
        2,
        "剔除旧隧道后必须恰好新建一条（实际 {}）",
        target.connections()
    );
    assert_eq!(target.requests(), 3, "第三次请求也必须真的到达目标");
}

// ─────────────────────────────────────────────────────────────
// T1 / P5：慢代理刷新不阻塞其他凭据
// ─────────────────────────────────────────────────────────────

/// 凭据 A（可刷新、绑黑洞代理）的刷新卡死时，凭据 B（可刷新、绑健康代理）
/// 仍能完成自己的刷新与上下文获取。
///
/// 与旧用例的差别：
/// - 旧用例 A/B 都是 API key 凭据：A 的刷新在 `refresh_token_with_client`
///   直接 bail（token_manager.rs:238），B 的 Business 刷新在
///   `refresh_auth`（maintenance.rs:177-183）短路返回——两条路径都不碰刷新锁；
/// - 本用例 A/B 都是 OAuth 凭据，都真的走 HTTP 刷新。
///
/// 前置条件断言（缺一即恒绿）：
/// - A 的刷新任务确实连上了黑洞代理（`BlackholeSocks::wait_accepted`）；
/// - A 的每凭据 `refresh_lock` 此刻确实被占用（`runtime_state_for_test`）；
/// - 健康刷新服务在 B 完成前确实收到了 B 的请求。
///
/// 反事实见报告：把每凭据锁换成共享锁，B 的 `timeout` 内拿不到上下文。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_blocked_refresh_on_one_credential_does_not_block_another() {
    let dir = TempDir::new();
    let blackhole = BlackholeSocks::spawn().await;
    let healthy = RefreshServer::spawn().await;

    let slow = oauth_credential(1, true);
    let fast = oauth_credential(2, true);
    let manager = manager_with(
        &dir,
        vec![slow, fast],
        vec![pool_entry("blackhole", &blackhole.url)],
    );
    // A 绑黑洞代理，B 直连（继承 System 路由，指针指向本机 loopback 刷新服务）。
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "blackhole".into(),
            },
        )
        .await
        .unwrap();
    manager.install_refresh_url_for_test(healthy.url.clone());

    // (1) 触发 A 的刷新，并等到黑洞代理确实接受了 A 的连接。
    let slow_refresh = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.force_refresh_token_for(1).await })
    };
    blackhole.wait_accepted().await;

    // 前置条件：A 的刷新锁此刻确实被占用（不是"可能在某处等着"）。
    let (lock_a, ..) = manager.runtime_state_for_test(1).unwrap();
    assert!(
        lock_a.try_lock().is_err(),
        "前置条件不成立：A 的刷新锁没有被占用，说明 A 的刷新没有进入锁内"
    );

    // (2) A 仍卡着，让 B 走完业务上下文获取（含真的刷新）。
    //
    // 必须显式排除 A：priority 模式的首次选路会挑到 A（priority 最小、未禁用），
    // 然后卡在 A 自己的刷新锁上——那不是"跨凭据隔离"的失败，而是选到 A 的
    // 正常结果。生产里 A 挂死也是这样演进的（超时后进入 excluded_ids 换下一张）。
    //
    // 判据是结构性的，不用 `elapsed < 5s` 这种墙钟比值：`timeout` 只决定失败
    // 多快，对不对由"B 拿到刷新后的 token"+"A 此刻仍未完成"+"A 的隧道在 B 完成
    // 之前就已建立"三件事共同决定。墙钟会把机器负载算进结论：慢机器上健康实现
    // 会红，快机器上串行实现也可能绿。
    let excluded = std::collections::HashSet::from([1u64]);
    let context = tokio::time::timeout(
        Duration::from_secs(5),
        manager.acquire_context_for_session_excluding(None, None, &excluded),
    )
    .await
    .expect("B 不得因 A 的刷新卡死而被阻塞（共用刷新锁会在这里超时）");
    let context = context.expect("B 的上下文获取必须成功");
    assert_eq!(context.id, 2, "选出 B 才能验证 B 的刷新路径");

    // 前置条件 + 结果：B 的刷新确实打到了健康服务（不是靠旧 token 蒙过去的）。
    healthy.wait_count(1).await;
    assert_eq!(
        context.token, "refreshed-access",
        "B 必须用刷新后的 token 构造上下文"
    );

    // 结构性对照臂：B 已成功返回时 A **仍然**卡在黑洞里。这两件事同时成立，
    // 才证明"一个慢代理没有拖累另一个凭据"——仅凭耗时短只能证明当时快。
    assert!(
        !slow_refresh.is_finished(),
        "A 的刷新不应在黑洞代理上完成（否则本用例测的不是隔离而是两路都结束）"
    );
    let (lock_a_after, ..) = manager.runtime_state_for_test(1).unwrap();
    assert!(
        lock_a_after.try_lock().is_err(),
        "B 完成时 A 的刷新锁必须仍被占用：证明两条刷新确实并行而非先后"
    );

    // (3) 收尾：取消 A 的刷新任务，不泄漏。
    slow_refresh.abort();
}

// ─────────────────────────────────────────────────────────────
// T8 / P5：持真实 refresh_lock 时，fresh 业务路径不被无关刷新挡住
// ─────────────────────────────────────────────────────────────

/// 持有凭据 A **真实的** `entry.refresh_lock` 时：
/// - 凭据 B 的 fresh 业务路径照常完成（跨凭据隔离）；
/// - 凭据 A 自己的刷新必须被阻塞（对照臂，证明这把锁确实有互斥效力）。
///
/// 旧用例（token_manager.rs:8445）锁的是一个新建的、与 manager 毫无关系的
/// `Arc<TokioMutex>`，断言不可能失败。
#[tokio::test]
async fn bdd_fresh_business_bypasses_another_credentials_real_refresh_lock() {
    let dir = TempDir::new();
    let healthy = RefreshServer::spawn().await;
    let manager = manager_with(
        &dir,
        vec![oauth_credential(1, true), oauth_credential(2, false)],
        Vec::new(),
    );
    manager.install_refresh_url_for_test(healthy.url.clone());
    let (lock_a, ..) = manager.runtime_state_for_test(1).unwrap();
    let (lock_b, ..) = manager.runtime_state_for_test(2).unwrap();

    // 结构不变量（P5 的承重墙）：每凭据一把锁，两个条目绝不能共享同一个 Arc。
    // 这条断言是 T8 唯一能区分"每凭据锁"与"全局锁"的观测点——因为 fresh 短路
    // 发生在取锁之前，行为臂本身对锁的粒度不敏感（反事实已实测证实）。
    assert!(
        !Arc::ptr_eq(&lock_a, &lock_b),
        "P5：刷新锁必须每凭据一把，A 与 B 不得共享同一个 Arc"
    );

    let guard = lock_a.lock().await;

    // 结果臂：B 的 fresh 业务路径不排队。
    //
    // 与 T1 同理必须排除 A——否则 priority 模式会先选到 A 并卡在它的锁上。
    let excluded = std::collections::HashSet::from([1u64]);
    let acquired = tokio::time::timeout(
        Duration::from_secs(1),
        manager.acquire_context_for_session_excluding(None, None, &excluded),
    )
    .await
    .expect("B 不得排在 A 的刷新锁后面");
    assert_eq!(
        acquired.expect("B 的上下文获取必须成功").id,
        2,
        "fresh 凭据必须可被选中"
    );

    // 对照臂（前置证据）：锁确实生效——同一把锁下 A 的刷新拿不到，因此
    // 健康刷新服务一次请求都收不到。
    let blocked = tokio::time::timeout(
        Duration::from_millis(300),
        manager.force_refresh_token_for(1),
    )
    .await;
    assert!(
        blocked.is_err(),
        "对照臂不成立：持有 A 的 refresh_lock 时 A 的刷新仍能完成，说明这把锁没有互斥效力"
    );
    assert_eq!(
        healthy.count(),
        0,
        "对照臂：A 的刷新必须真的被锁挡住（健康服务不该收到 A 的刷新请求）"
    );
    drop(guard);
}

// ─────────────────────────────────────────────────────────────
// T2 / P3：改 URL 或认证必须真正换 route 并真的换出口
// ─────────────────────────────────────────────────────────────

/// 三步全部走真实 `update_proxy` 与真实生产 `Route`（无 `install_route_for_test`）：
/// 1. 初始指向 socks_a 的池代理 → 请求经 socks_a；
/// 2. `update_proxy(url → socks_b)` → 请求必须经 socks_b，socks_a 不得新增连接，
///    且凭据的 `route` 指针必须变（`Arc::ptr_eq` 为 false）；
/// 3. `update_proxy` 改成**要求认证**的 socks_c：先给错误认证 → 请求必须失败、
///    认证失败计数 ≥1、目标不得收到绕过代理的请求；再改成正确认证 → 请求成功。
///
/// 旧用例（`bdd_url_or_auth_change_rebuilds_route`）用 `install_route_for_test`
/// 注入 route：`before` 与 `after` 都是注入产物，任何指针差异都能让 `assert_ne!`
/// 成立；`socks_b.stats.connections()==1` 证明的是"注入的 route 指向 b"，
/// 不是"`update_proxy` 的发布结果"。本用例不用该钩子。
///
/// 目标用 HTTP/1.1 `TargetServer`：生产 `Route`（无 h2c prior-knowledge）能直接
/// 经 SOCKS5 打到它，与 `bdd_bind_uses_published_proxy_route_after_concurrent_edit`
/// 的既有做法一致。
#[tokio::test]
async fn bdd_update_proxy_url_and_auth_change_switches_real_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let url = format!("http://{}/x", target.addr);
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;

    let manager = manager_with(&dir, vec![oauth_credential(1, false)], Vec::new());
    manager
        .create_proxy(pool_entry("p", &socks_a.url))
        .await
        .unwrap();
    manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p".into(),
            },
        )
        .await
        .unwrap();
    let provider = provider(manager.clone(), &url);

    // (1) 初始：经 socks_a。
    let route_before = manager.route_arc_for_test(1).expect("凭据必须有 route");
    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(
        socks_a.stats.connections(),
        1,
        "前置条件：第一个请求必须经 socks_a"
    );
    assert_eq!(target.connections(), 1, "前置条件：目标必须收到请求");

    // (2) 改 URL 到 socks_b：必须真的换出口、换 route。
    manager
        .update_proxy(
            "p",
            ProxyUpdateRequest {
                url: Some(Some(socks_b.url.clone())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let route_after_url = manager.route_arc_for_test(1).unwrap();
    assert!(
        !Arc::ptr_eq(&route_before, &route_after_url),
        "P3：改 URL 必须发布新 route（旧 {route_before:?} vs 新 {route_after_url:?}）"
    );

    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(
        socks_b.stats.connections(),
        1,
        "P3：改 URL 后的请求必须经 socks_b"
    );
    assert_eq!(
        socks_a.stats.connections(),
        1,
        "P3：不得再走改前的 socks_a（连接数应保持 1）"
    );
    assert_eq!(target.connections(), 2, "目标应收到第二个请求");

    // (3a) 改成要求认证的 socks_c，先给**错误**认证。
    let socks_c = spawn_socks5(Some(("user", "pass")), "socks5").await;
    manager
        .update_proxy(
            "p",
            ProxyUpdateRequest {
                url: Some(Some(socks_c.url.clone())),
                username: Some(Some("user".into())),
                password: Some(Some("wrong-pass".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let error = provider
        .call_api_with_context(&request_body())
        .await
        .err()
        .expect("错误代理认证必须导致请求失败");
    assert!(
        socks_c.stats.auth_failures() >= 1,
        "前置条件：socks_c 必须观测到认证失败（实际 {}，error={error}）",
        socks_c.stats.auth_failures()
    );
    assert_eq!(
        target.connections(),
        2,
        "代理认证失败时目标不得收到绕过代理的请求"
    );
    // provider 层会按凭据重试，所以错误认证会留下多次失败记录；这里记下基线，
    // 只要求**改成正确认证之后不再增长**。
    let auth_failures_after_wrong = socks_c.stats.auth_failures();

    // (3b) 改成**正确**认证：请求必须成功。
    manager
        .update_proxy(
            "p",
            ProxyUpdateRequest {
                password: Some(Some("pass".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let route_after_auth = manager.route_arc_for_test(1).unwrap();
    assert!(
        !Arc::ptr_eq(&route_after_url, &route_after_auth),
        "P3：改认证必须发布新 route（认证属于网络身份）"
    );
    provider
        .call_api_with_context(&request_body())
        .await
        .unwrap();
    assert_eq!(
        socks_c.stats.auth_failures(),
        auth_failures_after_wrong,
        "正确认证后不得再出现新的认证失败"
    );
    assert_eq!(target.connections(), 3, "正确认证后请求必须到达目标");
}

// ─────────────────────────────────────────────────────────────
// T4 / P2：直连 / 继承路由的 client 参数与改动前一致
// ─────────────────────────────────────────────────────────────

/// 四类路由在 idle 与 short 两个 client 上**实际应用**的选项，必须与改动前
/// `build_client` / `build_idle_client` 的分支逐项一致。
///
/// 观测手法：`http_client::route_option_log` 的记录点长在 `apply_proxy` /
/// `apply_no_proxy` / `apply_h2_keepalive` 内部——也就是真正调用 reqwest setter
/// 的同一处代码。这不是"另写一份声明"，因此记录与实际不可能分叉。旧用例
/// （`bdd_direct_and_system_routes_match_legacy_params`）只断言 200、旧
/// `bdd_proxy_route_marks_keepalive_scope` 断言的 `is_proxied()` 与 builder
/// 设了什么选项无关，两者都恒绿。
///
/// 对照依据（`git show master:src/http_client.rs`）：
/// - `build_client`/`build_idle_client` 的 `proxy = Some(..)` 分支只有 `builder.proxy(..)`；
/// - `proxy = None` 分支什么都不做；
/// - 改动前没有任何 `no_proxy()`、也没有任何 `http2_keep_alive_*`。
///
/// 反事实见报告：给 Direct 加 keep-alive → 红；给 Global 加 keep-alive → 红；
/// 去掉 Proxy 的 keep-alive → 红。
#[test]
fn bdd_route_options_match_legacy_builders() {
    use crate::http_client::ClientRole;
    use crate::http_client::route_option_log::{self, AppliedOptions};

    const PROXY_URL: &str = "socks5://127.0.0.1:1080";
    let proxy = ProxyConfig::new(PROXY_URL);
    let global = ProxyConfig::new("http://127.0.0.1:3128");

    route_option_log::reset();

    let system = Route::build(RouteKey::System, Config::default().tls_backend).unwrap();
    let direct = Route::build(RouteKey::Direct, Config::default().tls_backend).unwrap();
    let global_route = Route::build(
        RouteKey::Global(global.clone()),
        Config::default().tls_backend,
    )
    .unwrap();
    let proxied = Route::build(
        RouteKey::Proxy(proxy.clone()),
        Config::default().tls_backend,
    )
    .unwrap();

    // 前置条件：四条 route 都真的构建出来了（否则下面的 Option::expect 会红，
    // 但那不是"选项不对"，是"根本没走到构建"）。
    for route in [&system, &direct, &global_route, &proxied] {
        for client in [&route.idle, &route.short] {
            assert!(
                client.get("http://127.0.0.1:1").build().is_ok(),
                "前置条件：client 必须可用"
            );
        }
    }

    let expectations = [
        (
            "System",
            RouteKey::System,
            AppliedOptions {
                proxy: false,
                no_proxy: false,
                keepalive: false,
            },
        ),
        (
            "Direct",
            RouteKey::Direct,
            AppliedOptions {
                proxy: false,
                no_proxy: true,
                keepalive: false,
            },
        ),
        (
            "Global",
            RouteKey::Global(global),
            AppliedOptions {
                proxy: true,
                no_proxy: false,
                keepalive: false,
            },
        ),
        (
            "Proxy",
            RouteKey::Proxy(proxy),
            AppliedOptions {
                proxy: true,
                no_proxy: false,
                keepalive: true,
            },
        ),
    ];

    for (label, key, expected) in expectations {
        for role in [ClientRole::Idle, ClientRole::Short] {
            let actual = route_option_log::options(&key, role).unwrap_or_else(|| {
                panic!("{label}/{role:?}：没有记录到任何选项，说明构建路径没走到记录点")
            });
            assert_eq!(
                actual, expected,
                "{label}/{role:?} 的实际选项与改动前不一致（实际 {actual:?}，期望 {expected:?}）"
            );
        }
    }

    // 额外锁死一条最容易被"顺手优化"破坏的性质：直连/继承绝不能带 keep-alive。
    for role in [ClientRole::Idle, ClientRole::Short] {
        for key in [RouteKey::System, RouteKey::Direct] {
            assert!(
                !route_option_log::options(&key, role).unwrap().keepalive,
                "P2：{key:?}/{role:?} 不得启用代理专属 keep-alive"
            );
        }
    }
}
