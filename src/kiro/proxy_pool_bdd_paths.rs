//! 出站路径 BDD：每一条非业务出站路径都必须经**该凭据所选的路由**。
//!
//! 覆盖矩阵（计划验收行「generate 两种模式、MCP、OAuth 各模式、profile、usage、
//! 后台维护 → 都经过所选凭据的路由」）：
//!
//! | 路径 | 入口 | 观测点 |
//! |---|---|---|
//! | OAuth social 刷新 | `force_refresh_token_for` | SOCKS 连接数 + 服务收到请求 |
//! | OAuth IdC 刷新 | `force_refresh_token_for` | 同上 |
//! | profile discovery | `acquire_context` | 同上 |
//! | usage/balance | `get_usage_limits_for` | 同上 |
//! | 后台维护（认证 + 额度） | `maintain_once` | 同上 |
//!
//! 每条路径两个臂：**经所选代理**（夹具看到连接、目标收到请求）与
//! **黑洞代理**（目标必须收到 0 个请求——证明没有回退直连/回退继承）。
//!
//! 反事实（逐条见各用例注释）：把这些路径的 client 换回直连/继承路由，本文件
//! 的"代理臂"必红——因为目标 URL 用的是只有代理解析得了的主机名，直连必失败。

use std::sync::Arc;

use serde_json::json;

use crate::common::atomic_file;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::proxy_pool::ProxyEntry;
use crate::kiro::proxy_fixtures::{LocalProxy, TargetServer, spawn_socks5_redirect};
use crate::kiro::token_manager::{MultiTokenManager, ProxyBindingRequest, ProxyUpdateRequest};
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;

/// API Key 凭据（不做 OAuth 刷新，管理事务用例只需一个可绑定的凭据）。
fn api_key_credential(id: u64) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        kiro_api_key: Some(format!("ksk_test_{id}")),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────
// 共用夹具
// ─────────────────────────────────────────────────────────────

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kiro-rs-pool-paths-{}", uuid::Uuid::new_v4()));
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

/// 凭据绑定的代理 URL：`socks5h` 让**代理**解析主机名，因此"绕过代理直连"
/// 会在客户端就解析失败——这正是"这条路必须经代理"的可观测形态。
fn socks5h_url(proxy: &LocalProxy) -> String {
    proxy.url.replacen("socks5://", "socks5h://", 1)
}

/// 每个路径的目标主机名都不可在本地解析：只有经代理（代理解析 + 重定向到本地
/// 服务）才可达。
fn unroutable_host(tag: &str, port: u16) -> String {
    format!("http://kiro-rs-{tag}-probe.invalid:{port}")
}

/// social OAuth 凭据（可刷新）。
fn social_credential(id: u64, proxy_id: Option<&str>) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        access_token: Some(format!("access-{id}")),
        refresh_token: Some(format!("{id}{}", "r".repeat(120))),
        auth_method: Some("social".to_string()),
        proxy_id: proxy_id.map(str::to_string),
        ..Default::default()
    }
}

/// IdC OAuth 凭据（可刷新）。
fn idc_credential(id: u64, proxy_id: Option<&str>) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        access_token: Some(format!("access-{id}")),
        refresh_token: Some(format!("{id}{}", "r".repeat(120))),
        client_id: Some("synthetic-client".to_string()),
        client_secret: Some("synthetic-secret".to_string()),
        auth_method: Some("idc".to_string()),
        proxy_id: proxy_id.map(str::to_string),
        ..Default::default()
    }
}

/// 绑定代理后必须可用的凭据：给它一个有效 profile ARN，避免业务 acquire 触发
/// profile discovery（本文件里 profile 有独立用例）。
fn with_profile(mut credential: KiroCredentials) -> KiroCredentials {
    credential.profile_arn =
        Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/test".to_string());
    credential.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    credential
}

/// 绑定代理 URL 的独立 manager（黑洞臂用：不经过池，直接池条目）。
fn manager_bound_to(
    dir: &TempDir,
    credentials: Vec<KiroCredentials>,
    url: &str,
) -> Arc<MultiTokenManager> {
    manager_with(dir, credentials, vec![pool_entry("p1", url)])
}

/// 断言"目标收到 0 个请求"——黑洞臂的核心断言。
fn assert_target_silent(target: &TargetServer) {
    assert_eq!(
        target.connections(),
        0,
        "代理不可达时不得回退直连/回退继承路由：目标收到了请求"
    );
}

// ─────────────────────────────────────────────────────────────
// social 刷新
// ─────────────────────────────────────────────────────────────

const SOCIAL_REFRESH_BODY: &str =
    r#"{"accessToken":"fresh-access","refreshToken":"rrrr","expiresIn":3600}"#;

/// 经代理臂：SOCKS 夹具观察到该凭据的连接，刷新服务收到请求。
///
/// 反事实：把 `refresh_auth_locked` 取 client 的那行改成 `Route::build(Direct)`
/// 的 short client → 主机名不可解析，刷新失败；本用例在"服务必须收到请求"处红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_social_refresh_uses_credential_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(SOCIAL_REFRESH_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &socks5h_url(&socks),
    );
    manager.install_refresh_url_for_test(unroutable_host("social", target.addr.port()));

    manager
        .force_refresh_token_for(1)
        .await
        .expect("经所选代理的刷新必须成功");

    assert_eq!(
        socks.stats.connections(),
        1,
        "SOCKS 夹具必须看到该凭据的连接"
    );
    assert_eq!(target.connections(), 1, "刷新服务必须收到请求");
}

/// 黑洞臂：代理不可达时刷新失败，且刷新服务收到 0 个请求。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_social_refresh_never_falls_back_when_proxy_is_dead() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(SOCIAL_REFRESH_BODY).await;
    let dead = dead_proxy().await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &dead.url,
    );
    manager.install_refresh_url_for_test(unroutable_host("social", target.addr.port()));

    let error = manager
        .force_refresh_token_for(1)
        .await
        .expect_err("代理不可达必须失败");
    assert!(!error.to_string().is_empty(), "失败必须带原因: {error}");
    assert_target_silent(&target);
}

// ─────────────────────────────────────────────────────────────
// IdC 刷新
// ─────────────────────────────────────────────────────────────

const IDC_REFRESH_BODY: &str =
    r#"{"accessToken":"fresh-access","refreshToken":"rrrr","expiresIn":3600}"#;

/// 反事实：同 social——把 client 换成直连/继承路由，"服务收到请求"处红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_idc_refresh_uses_credential_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(IDC_REFRESH_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(idc_credential(1, Some("p1")))],
        &socks5h_url(&socks),
    );
    manager.install_refresh_url_for_test(unroutable_host("idc", target.addr.port()));

    manager
        .force_refresh_token_for(1)
        .await
        .expect("经所选代理的 IdC 刷新必须成功");

    assert_eq!(
        socks.stats.connections(),
        1,
        "SOCKS 夹具必须看到该凭据的连接"
    );
    assert_eq!(target.connections(), 1, "IdC 刷新服务必须收到请求");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_idc_refresh_never_falls_back_when_proxy_is_dead() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(IDC_REFRESH_BODY).await;
    let dead = dead_proxy().await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(idc_credential(1, Some("p1")))],
        &dead.url,
    );
    manager.install_refresh_url_for_test(unroutable_host("idc", target.addr.port()));

    manager
        .force_refresh_token_for(1)
        .await
        .expect_err("代理不可达必须失败");
    assert_target_silent(&target);
}

// ─────────────────────────────────────────────────────────────
// profile discovery（ListAvailableProfiles）
// ─────────────────────────────────────────────────────────────

const PROFILE_BODY: &str =
    r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/discovered"}]}"#;

/// 凭据没有 profile ARN 时，业务 acquire 会触发 discovery；它必须经该凭据路由。
///
/// 反事实：`discover_profile_arn` 里把 `list_available_profiles(.., &route.short)`
/// 换成直连 client → 主机名不可解析，profile 服务收到 0 个请求，本用例红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_profile_discovery_uses_credential_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(PROFILE_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let mut credential = social_credential(1, Some("p1"));
    credential.profile_arn = None;
    credential.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    let manager = manager_bound_to(&dir, vec![credential], &socks5h_url(&socks));
    manager.install_profile_lookup_url_for_test(unroutable_host("profile", target.addr.port()));

    let context = manager
        .acquire_context(None)
        .await
        .expect("profile discovery 失败不应阻止拿到上下文");

    assert_eq!(
        socks.stats.connections(),
        1,
        "SOCKS 夹具必须看到该凭据的连接"
    );
    assert_eq!(target.connections(), 1, "profile 服务必须收到请求");
    // 前置条件：确认这次 acquire 真的走了 discovery 分支（否则上面两条可能是别的请求）。
    assert_eq!(manager.profile_lookup_requests_for_test(), 1);
    assert_eq!(
        context.credentials.profile_arn.as_deref(),
        Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/discovered")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_profile_discovery_never_falls_back_when_proxy_is_dead() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(PROFILE_BODY).await;
    let mut credential = social_credential(1, Some("p1"));
    credential.profile_arn = None;
    credential.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    let manager = manager_bound_to(&dir, vec![credential], &dead_proxy().await.url);
    manager.install_profile_lookup_url_for_test(unroutable_host("profile", target.addr.port()));

    // discovery 是 best-effort：失败不阻止拿上下文，但绝不能不经过代理就去目标。
    let _ = manager.acquire_context(None).await;
    assert_target_silent(&target);
    assert_eq!(
        manager.profile_lookup_requests_for_test(),
        1,
        "discovery 确实被执行了"
    );
}

// ─────────────────────────────────────────────────────────────
// usage / balance（getUsageLimits）
// ─────────────────────────────────────────────────────────────

const USAGE_BODY: &str =
    r#"{"usageBreakdownList":[{"currentUsageWithPrecision":1,"usageLimitWithPrecision":10}]}"#;

/// 反事实：`get_usage_limits_inner` 里把 `route_for_id(id)?.short` 换成直连 client
/// → 主机名不可解析，usage 服务收到 0 个请求，本用例红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_usage_limits_use_credential_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(USAGE_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &socks5h_url(&socks),
    );
    manager.install_usage_limits_url_for_test(unroutable_host("usage", target.addr.port()));

    manager
        .get_usage_limits_for(1)
        .await
        .expect("经所选代理的 usage 查询必须成功");

    assert_eq!(
        socks.stats.connections(),
        1,
        "SOCKS 夹具必须看到该凭据的连接"
    );
    assert_eq!(target.connections(), 1, "usage 服务必须收到请求");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_usage_limits_never_fall_back_when_proxy_is_dead() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(USAGE_BODY).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &dead_proxy().await.url,
    );
    manager.install_usage_limits_url_for_test(unroutable_host("usage", target.addr.port()));

    manager
        .get_usage_limits_for(1)
        .await
        .expect_err("代理不可达必须失败");
    assert_target_silent(&target);
}

// ─────────────────────────────────────────────────────────────
// 后台维护：认证维护 + 额度恢复
// ─────────────────────────────────────────────────────────────

/// 后台维护的认证刷新必须经该凭据路由。
///
/// 形态：凭据 A 用短 TTL 让后台判定需要刷新；刷新服务与 usage 服务都是**同一个**
/// 本地目标（重定向夹具），因此"目标收到请求"只需 ≥1；SOCKS 连接数 ≥1 证明
/// 出站确实经过了所选代理。
///
/// 反事实：`maintain_entry → refresh_auth` 里换成直连 client → 主机名不可解析，
/// 目标收到 0 个请求，本用例红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_background_maintenance_uses_credential_route() {
    let dir = TempDir::new();
    // 刷新响应 + usage 响应各一份；同一夹具按路径无所谓 body 形状，
    // 这里用刷新体（后台只会因刷新失败/成功而分流）。
    let target = TargetServer::spawn(SOCIAL_REFRESH_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;

    let mut credential = with_profile(social_credential(1, Some("p1")));
    // 短 TTL：`auth_delay_ms` 让它立刻到期（减掉剩余时间的 1/5 但不超过 10 分钟）。
    credential.expires_at = Some((chrono::Utc::now() + chrono::Duration::seconds(5)).to_rfc3339());
    let manager = manager_bound_to(&dir, vec![credential], &socks5h_url(&socks));
    manager.install_refresh_url_for_test(unroutable_host("maint", target.addr.port()));

    manager.maintain_once_for_test().await;

    assert!(
        socks.stats.connections() >= 1,
        "后台维护必须经该凭据所选代理出站，实际连接数: {}",
        socks.stats.connections()
    );
    assert!(target.connections() >= 1, "后台维护的刷新请求必须到达服务");
}

/// 后台维护的**额度恢复**查询也必须经该凭据路由。
///
/// 形态：凭据被标记额度耗尽（`report_quota_exhausted`）、token 仍有效 → 后台只做
/// usage 查询、不做认证刷新，因此目标收到的请求必然是 usage 请求。
///
/// 反事实：`get_usage_limits_inner` 的 client 换成直连 → 目标 0 请求，本用例红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_background_quota_recovery_uses_credential_route() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(USAGE_BODY).await;
    let socks = spawn_socks5_redirect(target.addr).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &socks5h_url(&socks),
    );
    manager.install_usage_limits_url_for_test(unroutable_host("maint-usage", target.addr.port()));

    // 前置条件：凭据此刻确实处于「额度耗尽」状态，否则后台根本不会查 usage。
    manager.report_quota_exhausted(1);
    assert!(
        manager.snapshot().entries[0].disabled,
        "前置条件：额度耗尽必须真的禁用了该凭据"
    );

    manager.maintain_once_for_test().await;

    assert!(
        socks.stats.connections() >= 1,
        "后台额度查询必须经该凭据所选代理出站"
    );
    assert!(target.connections() >= 1, "后台额度查询必须到达 usage 服务");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdd_path_background_maintenance_never_falls_back_when_proxy_is_dead() {
    let dir = TempDir::new();
    let target = TargetServer::spawn(USAGE_BODY).await;
    let manager = manager_bound_to(
        &dir,
        vec![with_profile(social_credential(1, Some("p1")))],
        &dead_proxy().await.url,
    );
    manager.install_usage_limits_url_for_test(unroutable_host("maint-usage", target.addr.port()));
    manager.report_quota_exhausted(1);

    manager.maintain_once_for_test().await;
    assert_target_silent(&target);
}

// ─────────────────────────────────────────────────────────────
// 管理事务层：落盘失败不发布（rename 失败注入）
// ─────────────────────────────────────────────────────────────

/// update_proxy 的原子写走到 rename 失败（单文件挂载的真实形态）时：
/// **回退成功**，因此事务应当**成功发布**，且磁盘文件内容与新状态一致。
///
/// 这条与「写失败不发布」互补：它证明 rename 失败不等于写失败——把两者混为
/// 一谈会让单文件挂载部署每次改代理都报错。
///
/// 反事实：删掉 `Err(rename_error)` 分支的原地写回退 → 返回 Err，本用例红。
#[tokio::test]
async fn bdd_transaction_rename_failure_still_publishes_after_in_place_fallback() {
    let dir = TempDir::new();
    let manager = manager_with(&dir, vec![api_key_credential(1)], vec![]);
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    let before = std::fs::read(dir.path()).unwrap();

    atomic_file::inject_rename_failure_for_test(std::io::ErrorKind::PermissionDenied);
    manager
        .update_proxy(
            "p1",
            ProxyUpdateRequest {
                name: Some(Some("renamed".to_string())),
                ..Default::default()
            },
        )
        .await
        .expect("rename 失败应退回原地写而不是让整个事务失败");

    assert_eq!(
        manager.list_proxies()[0].name,
        "renamed",
        "回退写成功后内存必须发布新状态"
    );
    let after = std::fs::read(dir.path()).unwrap();
    assert_ne!(before, after, "磁盘文件必须被真正改写");
    let parsed: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert!(
        parsed.to_string().contains("renamed"),
        "磁盘内容必须反映新名称，实际: {}",
        parsed
    );
}

/// 绑定的写盘失败（写 tmp 之前的故障）必须让事务返回 Err，且内存 binding /
/// route 指针 / state_revision 一律不发布——这是「先写盘、后发布」的顺序证明。
///
/// 反事实：把 `commit_pool_write` 改成「先发布内存、后写盘」→ 本用例红。
#[tokio::test]
async fn bdd_transaction_write_failure_publishes_nothing() {
    let dir = TempDir::new();
    let manager = manager_with(&dir, vec![api_key_credential(1)], vec![]);
    manager
        .create_proxy(pool_entry("p1", "socks5://127.0.0.1:1080"))
        .await
        .unwrap();
    let route_before = manager.route_ptr_for_test(1).unwrap();
    let revision_before = manager.runtime_state_for_test(1).unwrap().3;
    let disk_before = std::fs::read(dir.path()).unwrap();

    // F4 之后 `PermissionDenied` 会走「tmp 失败 → 原地写」回退，因此这里改用
    // **非权限类**失败（写入过程本身出错）来注入"真的写不成"：那类错误不得
    // 回退（原地写会在磁盘满时留下半截文件），必须上抛。
    atomic_file::inject_write_failure_for_test(std::io::ErrorKind::StorageFull);
    let error = manager
        .bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        )
        .await
        .expect_err("写盘失败必须上抛");
    assert!(error.to_string().contains("回写凭据文件失败"), "{error}");

    assert_eq!(
        manager.snapshot().entries[0].proxy_mode,
        "inherit",
        "写盘失败不得发布绑定字段"
    );
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        route_before,
        "写盘失败不得替换 route 指针"
    );
    assert_eq!(
        manager.runtime_state_for_test(1).unwrap().3,
        revision_before,
        "写盘失败不得递增 state_revision"
    );
    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        disk_before,
        "写盘失败不得改动磁盘文件"
    );
}

// ─────────────────────────────────────────────────────────────
// 辅助
// ─────────────────────────────────────────────────────────────

/// 一个**确定不可用**的代理：端口由本用例持有，接受连接后立刻关闭。
///
/// 不能用「bind 后立即 drop」——那个端口在 drop 与真正 connect 之间可能被**别的
/// 测试**抢走，于是"代理不可达"这条前提在并行跑全量时并不成立（实测踩过一次：
/// 外部进程在该端口起了服务，用例拿到 400 而不是连接拒绝）。这里保持 listener
/// 存活并立即关闭每条被接受的连接，因此出站一定**快速失败**（而不是挂到超时），
/// 且不会与任何其它用例争夺端口。
struct DeadProxy {
    url: String,
    _task: tokio::task::JoinHandle<()>,
}

impl Drop for DeadProxy {
    fn drop(&mut self) {
        self._task.abort();
    }
}

async fn dead_proxy() -> DeadProxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            // 立刻 drop：对端读到 EOF，SOCKS/HTTP 握手立刻失败。
            drop(stream);
        }
    });
    DeadProxy {
        url: format!("socks5://{addr}"),
        _task: task,
    }
}

/// JSON 构造辅助：保持与其它 BDD 文件同一风格（避免手写转义错误）。
#[allow(dead_code)]
fn usage_json() -> String {
    json!({"usageBreakdownList":[{"currentUsageWithPrecision":1,"usageLimitWithPrecision":10}]})
        .to_string()
}
