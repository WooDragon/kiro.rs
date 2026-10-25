//! 本地性能基准（`#[ignore]`，不进 CI 阻塞门槛）。
//!
//! 这些用例只在本机跑，用于给计划的性能要求留可复现的量化依据：
//!
//! ```text
//! cargo test --release --bin kiro-rs bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! **测绝对值必须加 `--release`**：debug 构建（默认）里 reqwest/tokio 的代码路径
//! 未优化，数字只可用于"同一构建配置下的相对比较"，不能当生产基线引用。
//!
//! 测量项与计划编号（`## 性能不变量`）的对应：
//! - `bench_direct_ttfb`：直连凭据的请求时延 p50/p99 + 启动预建耗时（P1/P2/P4），
//!   带 master 等价 client 的**同进程对照臂**
//! - `bench_socks_connection_reuse`：经本地 SOCKS5 夹具的连接复用开销（P3）
//! - `bench_parallel_credentials_routes`：8 条路由 × 并发度 ∈ {1, 8, 64} 不跨路由排队（P3）
//! - `bench_startup_route_prebuild`：启动预建随路由数线性增长（P4）
//!
//! `bench_parallel_credentials_routes` 的编号是 **P3**（连接复用与隔离），不是
//! P6——P6 是"管理写不阻塞请求"，与本基准无关。
//!
//! 一律只打本机回环夹具，不触外网、不用真实凭据。

use crate::http_client::{ProxyConfig, Route, RouteKey};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::proxy_pool::ProxyEntry;
use crate::kiro::provider::KiroProvider;
use crate::kiro::proxy_fixtures::{H2TargetServer, TargetServer, spawn_socks5_redirect};
use crate::kiro::token_manager::MultiTokenManager;
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;
use std::collections::HashMap;
use std::sync::Arc;

fn percentiles(mut samples: Vec<f64>) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let p50 = samples[n / 2];
    let p99 = samples[(n * 99 / 100).min(n - 1)];
    let mean = samples.iter().sum::<f64>() / n as f64;
    (mean, p50, p99)
}

fn bench_credential(id: u64) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        kiro_api_key: Some(format!("ksk_bench_{id}")),
        ..Default::default()
    }
}

fn body() -> String {
    r#"{"conversationState":{"conversationId":"11111111-1111-1111-1111-111111111111","currentMessage":{"userInputMessage":{"modelId":"claude-sonnet-5","content":"hi"}}}}"#.to_string()
}

struct Endpoint {
    url: String,
}

impl KiroEndpoint for Endpoint {
    fn name(&self) -> &'static str {
        "bench"
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

fn bench_provider(manager: Arc<MultiTokenManager>, url: &str) -> KiroProvider {
    let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
    endpoints.insert(
        "bench".to_string(),
        Arc::new(Endpoint {
            url: url.to_string(),
        }) as Arc<dyn KiroEndpoint>,
    );
    KiroProvider::with_proxy(manager, None, endpoints, "bench".to_string())
}

/// master 等价 client（`git show master:src/http_client.rs` 的
/// `build_idle_client(None, UPSTREAM_IDLE_TIMEOUT_SECS, tls)`）：无代理、
/// `read_timeout=930s` + `connect_timeout=30s`、无全局总超时、无 keep-alive。
///
/// 手写在这里而**不改生产代码**：它是对照臂，不是被测物。任何参数漂移都会让
/// "本分支路径 vs 改动前路径"的比较失去意义，所以下面逐项注释了出处。
fn master_eq_direct_idle_client() -> reqwest::Client {
    use std::time::Duration;
    // master `base_builder(None, tls)`: 仅 TLS 选择，无代理、无 no_proxy。
    reqwest::Client::builder()
        .use_rustls_tls()
        // master `build_idle_client`: read_timeout(930) + connect_timeout(30)。
        .read_timeout(Duration::from_secs(930))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// 直连凭据的端到端请求时延 + **每请求 client 获取**的三臂对照。
///
/// 分两段，因为它们的可比性不同：
///
/// **第一段 `provider_e2e`**：完整 provider 路径（选凭据 → 取 token →
/// endpoint 变换 → 发送）对本地 stub 的时延。这是绝对数字，只用于和其它构建
/// 比，**不能**与下面两臂并排比较——它们连的是同一件事的不同层。
///
/// **第二段 `client_acquisition`**：本改动真正动过的地方（P1）。三臂对同一个
/// 本地 stub 用**同一条发送路径**，只替换"怎么拿到 client"：
/// - `route_arc`：本分支——`Arc::clone(entry.route)` 再取 `.idle`；
/// - `master_cache_hit`：master 的 `client_for` 命中形态——取全局
///   `Mutex<HashMap<Option<ProxyConfig>, Client>>` 的锁、克隆并哈希
///   `ProxyConfig`、再 `Client::clone()`。手写在这里，**不改生产代码**；
/// - `master_cache_miss`：master 的未命中形态——在**持锁**状态下现建 client。
///
/// `startup_us` 是"凭据 + 路由"装配完成的时间（一次性）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "本地性能基准，不进 CI 门槛"]
async fn bench_direct_ttfb() {
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let url = format!("http://{}/generateAssistantResponse", target.addr);

    // ── 第一段：端到端 ───────────────────────────────────────
    let startup_started = std::time::Instant::now();
    let manager = Arc::new(
        MultiTokenManager::new(
            Config::default(),
            vec![bench_credential(1)],
            None,
            None,
            false,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    let startup_us = startup_started.elapsed().as_micros();
    let provider = bench_provider(manager.clone(), &url);

    for _ in 0..20 {
        provider.call_api_with_context(&body()).await.unwrap();
    }
    let mut e2e_samples = Vec::new();
    for _ in 0..300 {
        let started = std::time::Instant::now();
        let response = provider.call_api_with_context(&body()).await.unwrap();
        e2e_samples.push(started.elapsed().as_secs_f64() * 1000.0);
        drop(response);
    }
    let (e2e_mean, e2e_p50, e2e_p99) = percentiles(e2e_samples);
    println!(
        "BENCH direct arm=provider_e2e  ttfb_ms mean={e2e_mean:.3} p50={e2e_p50:.3} p99={e2e_p99:.3} startup_us={startup_us}"
    );

    // ── 第二段：每请求 client 获取（同一发送路径）────────────
    let route = manager.route_arc_for_test(1).expect("凭据必须有 route");

    // master `client_cache`: `Mutex<HashMap<Option<ProxyConfig>, Client>>`，
    // 命中后 `Client::clone()`；键是 `ProxyConfig`（克隆 + 哈希）。
    let master_cache: parking_lot::Mutex<
        std::collections::HashMap<Option<ProxyConfig>, reqwest::Client>,
    > = parking_lot::Mutex::new(std::collections::HashMap::new());
    let direct_key: Option<ProxyConfig> = None;
    master_cache
        .lock()
        .insert(direct_key.clone(), master_eq_direct_idle_client());

    // 预热三条臂。
    for _ in 0..20 {
        let _ = route
            .idle
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let client = master_cache.lock().get(&direct_key).cloned().unwrap();
        let _ = client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let client = master_eq_direct_idle_client();
        let _ = client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
    }

    let mut arc_samples = Vec::new();
    let mut hit_samples = Vec::new();
    let mut miss_samples = Vec::new();
    for _ in 0..300 {
        let started = std::time::Instant::now();
        let idle = &route.idle;
        let _ = idle.get(&url).send().await.unwrap().bytes().await.unwrap();
        arc_samples.push(started.elapsed().as_secs_f64() * 1000.0);

        let started = std::time::Instant::now();
        // 命中形态：取锁 → 克隆 ProxyConfig 作键 → Client::clone()。
        let key = direct_key.clone();
        let client = master_cache.lock().get(&key).cloned().expect("预热已插入");
        let _ = client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        hit_samples.push(started.elapsed().as_secs_f64() * 1000.0);

        let started = std::time::Instant::now();
        // 未命中形态：在持锁状态下现建 client（master `client_for` 的慢路径）。
        let _guard = master_cache.lock();
        let client = master_eq_direct_idle_client();
        drop(_guard);
        let _ = client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        miss_samples.push(started.elapsed().as_secs_f64() * 1000.0);
    }

    let (arc_mean, arc_p50, arc_p99) = percentiles(arc_samples);
    let (hit_mean, hit_p50, hit_p99) = percentiles(hit_samples);
    let (miss_mean, miss_p50, miss_p99) = percentiles(miss_samples);
    println!(
        "BENCH client_acquisition arm=route_arc         ms mean={arc_mean:.3} p50={arc_p50:.3} p99={arc_p99:.3}"
    );
    println!(
        "BENCH client_acquisition arm=master_cache_hit  ms mean={hit_mean:.3} p50={hit_p50:.3} p99={hit_p99:.3}"
    );
    println!(
        "BENCH client_acquisition arm=master_cache_miss ms mean={miss_mean:.3} p50={miss_p50:.3} p99={miss_p99:.3}"
    );
}

/// 同一路由经 SOCKS5 隧道复用连接的每次请求开销。
///
/// 用 h2c 目标，保证测到的是"复用同一条隧道"，而不是每次重新握手。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "本地性能基准，不进 CI 门槛"]
async fn bench_socks_connection_reuse() {
    let target = H2TargetServer::spawn().await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let route = Route::build_for_test(
        RouteKey::Proxy(ProxyConfig::new(&socks.url)),
        Config::default().tls_backend,
        true,
        None,
    )
    .unwrap();
    let url = format!("http://{}/probe", target.addr);

    route.short.get(&url).send().await.unwrap();
    let tunnels_after_first = target.connections();

    let mut samples = Vec::new();
    for _ in 0..200 {
        let started = std::time::Instant::now();
        let response = route.short.get(&url).send().await.unwrap();
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        drop(response);
    }
    let (mean, p50, p99) = percentiles(samples);
    println!(
        "BENCH socks reuse_ms mean={mean:.3} p50={p50:.3} p99={p99:.3} tunnels={} requests={}",
        target.connections(),
        target.requests()
    );
    assert_eq!(
        target.connections(),
        tunnels_after_first,
        "200 次请求必须复用同一条 SOCKS5 隧道"
    );
}

/// N 条凭据各绑一个代理，**并发度** M ∈ {1, 8, 64} 压测不跨路由排队。
///
/// 评审指出旧基准"并发度只测了 N=8"：单一并发度无法回答"并发上去之后是否出现
/// 跨路由排队"——那正是本基准要回答的问题。这里把并发度做成被扫描的轴，
/// 凭据/路由数固定为 8（覆盖"多路由"这一前提），三个量级分别是串行基线、
/// 常见规模与压力点。
///
/// 同时保留每个并发度的总耗时与每次请求均摊，便于看增长趋势。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "本地性能基准，不进 CI 门槛"]
async fn bench_parallel_credentials_routes() {
    const ROUTES: usize = 8;
    for concurrency in [1usize, 8, 64] {
        run_parallel_bench(ROUTES, concurrency, 3).await;
    }
}

/// 单次并发压测：`routes` 条凭据各绑一个代理，`concurrency` 个任务各发
/// `per_task` 次请求。
async fn run_parallel_bench(routes: usize, concurrency: usize, per_task: usize) {
    let directory = std::env::temp_dir().join(format!("kiro-rs-bench-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("credentials.json");

    let mut credentials = Vec::new();
    let mut proxies = Vec::new();
    let mut fixtures = Vec::new();
    let mut targets = Vec::new();
    for index in 0..routes {
        let target = H2TargetServer::spawn().await;
        let socks = spawn_socks5_redirect(target.addr).await;
        proxies.push(ProxyEntry {
            id: format!("p{index}"),
            name: format!("p{index}"),
            url: socks.url.clone(),
            username: None,
            password: None,
        });
        let mut credential = bench_credential(index as u64 + 1);
        credential.proxy_id = Some(format!("p{index}"));
        credential.priority = index as u32;
        credentials.push(credential);
        fixtures.push(socks);
        targets.push(target);
    }

    let mut config = Config::default();
    config.load_balancing_mode = "balanced".to_string();
    let manager = Arc::new(
        MultiTokenManager::new_with_pool(
            config,
            credentials,
            proxies,
            None,
            Some(path.clone()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    // 本地目标是明文 H2，而 `new_with_pool` 发布的是生产路由（无 h2c
    // prior-knowledge）；这里按同一代理注入测试路由，替换的只是传输层实现，
    // 不改变"每个凭据走自己那条路由"这一被测事实。
    for (index, fixture) in fixtures.iter().enumerate() {
        manager.install_route_for_test(
            index as u64 + 1,
            Route::build_for_test(
                RouteKey::Proxy(ProxyConfig::new(&fixture.url)),
                Config::default().tls_backend,
                true,
                None,
            )
            .unwrap(),
        );
    }

    let url = format!("http://127.0.0.1:{}/x", targets[0].addr.port());
    let provider = Arc::new(bench_provider(manager.clone(), &url));

    let started = std::time::Instant::now();
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let provider = provider.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..per_task {
                provider.call_api_with_context(&body()).await.unwrap();
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let elapsed = started.elapsed();
    let requests: usize = targets.iter().map(|target| target.requests()).sum();
    let tunnels: usize = targets.iter().map(|target| target.connections()).sum();
    println!(
        "BENCH parallel routes={routes} concurrency={concurrency} requests={requests} tunnels={tunnels} elapsed_ms={:.3} per_request_us={:.1}",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1_000_000.0 / requests as f64
    );
    assert_eq!(requests, concurrency * per_task);
    // P3：每条路由只应建一条隧道（idle client 复用同一连接池）。
    assert!(
        tunnels <= routes,
        "{routes} 条路由只允许 {routes} 条隧道，实际 {tunnels}"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// 启动期路由预建成本：N 个凭据各自独立的代理路由全部建好所需时间。
#[tokio::test]
#[ignore = "本地性能基准，不进 CI 门槛"]
async fn bench_startup_route_prebuild() {
    const ROUTES: usize = 8;
    let mut entries = Vec::new();
    for index in 0..ROUTES {
        entries.push(ProxyEntry {
            id: format!("p{index}"),
            name: format!("p{index}"),
            url: format!("socks5://127.0.0.1:{}", 20000 + index),
            username: None,
            password: None,
        });
    }
    let started = std::time::Instant::now();
    let mut built = 0;
    for entry in &entries {
        Route::build(
            RouteKey::Proxy(entry.to_proxy_config()),
            Config::default().tls_backend,
        )
        .unwrap();
        built += 1;
    }
    let elapsed = started.elapsed();
    println!(
        "BENCH startup prebuild routes={built} total_ms={:.3} per_route_us={}",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_micros() / built as u128
    );
}
