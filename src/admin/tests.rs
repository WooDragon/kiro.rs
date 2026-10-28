//! Admin 层回归：新增凭据的代理表达校验、错误映射、池条目 id 与 PATCH 三态。
//!
//! 这些用例走 `AdminService` 的真实入口（反序列化 → 服务 → 状态码），
//! 断言的是 HTTP 契约（状态码 + 错误体 `type`），不是内部实现细节。

use std::sync::Arc;

use super::error::AdminServiceError;
use super::service::AdminService;
use super::types::{
    AddCredentialRequest, BindProxyRequest, CreateProxyRequest, UpdateProxyRequest,
};
use crate::kiro::model::proxy_pool::ProxyEntry;
use crate::kiro::proxy_fixtures::CountingRefreshServer;
use crate::kiro::token_manager::MultiTokenManager;
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kiro-rs-admin-{}", uuid::Uuid::new_v4()));
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

fn service(dir: &TempDir) -> AdminService {
    let manager = MultiTokenManager::new_with_pool(
        Config::default(),
        Vec::new(),
        Vec::new(),
        None,
        Some(dir.path()),
        true,
        Arc::new(ModelRegistry::builtin()),
    )
    .unwrap();
    AdminService::new(Arc::new(manager), Vec::new())
}

/// 断言错误映射成给定状态码与错误体 `type`。
fn assert_status(error: AdminServiceError, code: u16, error_type: &str) {
    assert_eq!(error.status_code().as_u16(), code, "状态码: {error}");
    let body = error.into_response();
    assert_eq!(body.error.error_type, error_type, "错误体 type");
}

fn add_request(json: serde_json::Value) -> AddCredentialRequest {
    serde_json::from_value(json).expect("请求必须能反序列化")
}

fn api_key(extra: serde_json::Value) -> serde_json::Value {
    let mut value = serde_json::json!({"kiroApiKey": "ksk_admin_test"});
    if let (Some(target), Some(source)) = (value.as_object_mut(), extra.as_object()) {
        for (key, item) in source {
            target.insert(key.clone(), item.clone());
        }
    }
    value
}

#[test]
fn bdd_suspension_admin_contract_uses_existing_reason_field() {
    use crate::kiro::model::credentials::KiroCredentials;
    let credential = KiroCredentials {
        id: Some(1),
        kiro_api_key: Some("ksk_synthetic_suspension".into()),
        disabled: true,
        disabled_reason: Some("TemporarilySuspended".into()),
        ..Default::default()
    };
    let manager = Arc::new(
        MultiTokenManager::new(
            Config::default(),
            vec![credential],
            None,
            None,
            false,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    let response = AdminService::new(manager, Vec::new()).get_all_credentials();
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["available"], 0);
    assert_eq!(value["credentials"][0]["disabled"], true);
    assert_eq!(
        value["credentials"][0]["disabledReason"],
        "TemporarilySuspended"
    );
    assert!(!value.to_string().contains("ksk_synthetic_suspension"));
    assert!(value["credentials"][0].get("upstreamBlockReason").is_none());
}

#[test]
fn bdd_global_proxy_configured_matrix() {
    let direct_credential = crate::kiro::model::credentials::KiroCredentials {
        id: Some(1),
        kiro_api_key: Some("ksk_bdd_direct".into()),
        proxy_url: Some("direct".into()),
        ..Default::default()
    };
    let inherited_credential = crate::kiro::model::credentials::KiroCredentials {
        id: Some(1),
        kiro_api_key: Some("ksk_bdd_inherit".into()),
        ..Default::default()
    };
    let local_proxy = crate::http_client::ProxyConfig {
        url: "http://127.0.0.1:8080".into(),
        username: None,
        password: None,
    };
    let cases = [
        ("no proxy, no credentials", None, Vec::new(), false),
        (
            "proxy, no credentials",
            Some(local_proxy.clone()),
            Vec::new(),
            true,
        ),
        (
            "no proxy, direct credential",
            None,
            vec![direct_credential.clone()],
            false,
        ),
        (
            "proxy, direct credential",
            Some(local_proxy.clone()),
            vec![direct_credential],
            true,
        ),
        (
            "no proxy, inherited credential",
            None,
            vec![inherited_credential.clone()],
            false,
        ),
        (
            "proxy, inherited credential",
            Some(local_proxy),
            vec![inherited_credential],
            true,
        ),
    ];

    for (case, proxy, credentials, expected) in cases {
        let dir = TempDir::new();
        let expected_total = credentials.len();
        let manager = Arc::new(
            MultiTokenManager::new_with_pool(
                Config::default(),
                credentials,
                Vec::new(),
                proxy,
                Some(dir.path()),
                true,
                Arc::new(ModelRegistry::builtin()),
            )
            .unwrap(),
        );
        let snapshot = manager.snapshot();
        assert_eq!(
            snapshot.global_proxy_configured, expected,
            "{case}: snapshot"
        );
        let response = AdminService::new(manager, Vec::new()).get_all_credentials();
        assert_eq!(
            response.global_proxy_configured, expected,
            "{case}: service response"
        );
        let serialized = serde_json::to_value(&response).expect("响应必须能序列化");

        assert_eq!(
            serialized.get("globalProxyConfigured"),
            Some(&serde_json::json!(expected)),
            "{case}: 全局代理状态必须序列化为 boolean"
        );
        assert_eq!(response.total, expected_total, "{case}: total");
        assert_eq!(response.available, expected_total, "{case}: available");
        assert_eq!(
            serialized.get("total"),
            Some(&serde_json::json!(expected_total)),
            "{case}: total 必须保留"
        );
        assert_eq!(
            serialized.get("available"),
            Some(&serde_json::json!(expected_total)),
            "{case}: available 必须保留"
        );
        assert_eq!(
            serialized.get("currentId"),
            Some(&serde_json::json!(response.current_id)),
            "{case}: currentId 必须保留"
        );
        assert_eq!(
            serialized
                .get("credentials")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(expected_total),
            "{case}: credentials 必须保留"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// J1：新表达与旧表达的所有同现组合都必须 400
// ─────────────────────────────────────────────────────────────

/// 反事实：去掉 `proxy_binding_id` 里对 `proxyId` + 旧字段的判断，后两条变红
/// （返回 200 并把冲突绑定写进文件，下次启动 fail-fast）。
#[tokio::test]
async fn add_credential_rejects_mixed_proxy_expressions() {
    let dir = TempDir::new();
    let service = service(&dir);

    // 四种同现组合：proxy×旧字段、proxy×proxyId、proxyId×proxyUrl、
    // proxyId×proxyUsername/proxyPassword。
    let cases = [
        api_key(serde_json::json!({
            "proxy": {"mode": "direct"},
            "proxyUrl": "http://h:1"
        })),
        api_key(serde_json::json!({
            "proxy": {"mode": "pool", "proxyId": "p1"},
            "proxyId": "p1"
        })),
        api_key(serde_json::json!({
            "proxyId": "p1",
            "proxyUrl": "http://h:1"
        })),
        api_key(serde_json::json!({
            "proxyId": "p1",
            "proxyPassword": "secret"
        })),
    ];
    for case in cases {
        let error = service
            .add_credential(add_request(case.clone()))
            .await
            .expect_err("同现必须拒绝");
        assert_status(error, 400, "invalid_request");
    }

    assert!(
        !dir.path().exists(),
        "被拒绝的请求不得落盘（否则下次启动 fail-fast）"
    );
}

// ─────────────────────────────────────────────────────────────
// J2：代理相关失败必须映射成 4xx，而不是 500
// ─────────────────────────────────────────────────────────────

/// 反事实：去掉 `classify_add_error` 里的 `downcast_ref::<ProxyPoolError>()`，
/// 本条落到 500 `internal_error`（关键字匹配认不出"代理不存在"）。
#[tokio::test]
async fn add_credential_maps_missing_pool_proxy_to_404() {
    let dir = TempDir::new();
    let service = service(&dir);
    let error = service
        .add_credential(add_request(api_key(
            serde_json::json!({"proxyId": "missing"}),
        )))
        .await
        .expect_err("池里没有该代理");
    assert_status(error, 404, "not_found");
}

/// 验证期间代理被并发删除（I5 竞态路径）：409，而不是 500。
#[tokio::test]
async fn add_credential_maps_proxy_deleted_during_verification_to_409() {
    let dir = TempDir::new();
    let manager = Arc::new(
        MultiTokenManager::new_with_pool(
            Config::default(),
            Vec::new(),
            Vec::new(),
            None,
            Some(dir.path()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    manager
        .create_proxy(ProxyEntry {
            id: "p1".into(),
            name: "P1".into(),
            url: "socks5://127.0.0.1:1080".into(),
            username: None,
            password: None,
        })
        .await
        .unwrap();

    let gate = Arc::new(crate::kiro::token_manager::proxy_pool::AdminWriteGate::new());
    manager.install_add_gate_for_test(gate.clone());
    let adder = {
        let manager = manager.clone();
        tokio::spawn(async move {
            let service = AdminService::new(manager, Vec::new());
            service
                .add_credential(add_request(api_key(serde_json::json!({"proxyId": "p1"}))))
                .await
        })
    };
    gate.arrived.notified().await;
    manager
        .delete_proxy("p1")
        .await
        .expect("删除未被引用的代理");
    gate.release.add_permits(1);

    let error = adder.await.unwrap().expect_err("代理已被删除");
    assert_status(error, 409, "conflict");
    assert!(
        !dir.path().exists() || !std::fs::read_to_string(dir.path()).unwrap().contains("p1"),
        "被拒绝的请求不得写出悬空 proxyId"
    );
}

/// 内联 URL 无法构建（ftp 不是代理协议）：400，而不是 500。
#[tokio::test]
async fn add_credential_maps_unbuildable_inline_proxy_to_400() {
    let dir = TempDir::new();
    let service = service(&dir);
    let error = service
        .add_credential(add_request(api_key(
            serde_json::json!({"proxyUrl": "ftp://not-a-proxy:21"}),
        )))
        .await
        .expect_err("ftp 不能作为代理");
    assert_status(error, 400, "invalid_request");
}

// ─────────────────────────────────────────────────────────────
// J4：POST 的 proxy.inline 与 PUT 共用同一套校验
// ─────────────────────────────────────────────────────────────

/// 反事实：让 `apply_binding_fields` 直接透传、不调用共享校验，
/// `direct` 与半套认证两条变红（200）。
#[tokio::test]
async fn add_credential_inline_mode_shares_put_validation() {
    let dir = TempDir::new();
    let service = service(&dir);

    for case in [
        api_key(serde_json::json!({"proxy": {"mode": "inline", "url": "direct"}})),
        api_key(serde_json::json!({
            "proxy": {"mode": "inline", "url": "socks5://h:1", "username": "u"}
        })),
        api_key(serde_json::json!({
            "proxy": {"mode": "inline", "url": "socks5://h:1", "password": "p"}
        })),
    ] {
        let error = service
            .add_credential(add_request(case.clone()))
            .await
            .expect_err("新表达的内联必须与 PUT 同规则");
        assert_status(error, 400, "invalid_request");
    }

    // 旧三字段 `proxyUrl:"direct"` 的既有行为不变（向后兼容）。
    let response = service
        .add_credential(add_request(api_key(
            serde_json::json!({"proxyUrl": "direct"}),
        )))
        .await
        .expect("旧表达 direct 必须仍然被接受");
    let snapshot = service.get_all_credentials();
    let entry = snapshot
        .credentials
        .iter()
        .find(|item| item.id == response.credential_id)
        .expect("新凭据必须出现在列表里");
    assert_eq!(entry.proxy_mode, "direct");
    assert!(entry.has_proxy, "direct 是凭据自己的代理覆盖（旧语义）");
}

// ─────────────────────────────────────────────────────────────
// J5：池条目 id 由服务端生成
// ─────────────────────────────────────────────────────────────

/// 客户端多传 `id` 被忽略；返回的 id 是服务端 UUID。
///
/// 反事实：把 `create_proxy` 改回 `req.id.unwrap_or_else(...)`，第一条断言变红。
#[tokio::test]
async fn create_proxy_ignores_client_supplied_id() {
    let dir = TempDir::new();
    let service = service(&dir);
    let request: CreateProxyRequest = serde_json::from_value(serde_json::json!({
        "id": "..",
        "name": "P1",
        "url": "socks5://127.0.0.1:1080"
    }))
    .expect("未知字段 id 应被忽略");

    let list = service.create_proxy(request).await.expect("创建成功");
    assert_eq!(list.proxies.len(), 1);
    let id = &list.proxies[0].id;
    assert_ne!(id, "..", "客户端 id 必须被忽略");
    assert!(
        uuid::Uuid::parse_str(id).is_ok(),
        "服务端 id 必须是合法 UUID: {id}"
    );
    // 生成出来的 id 必须能通过加载期规则（否则自己写出的文件自己读不回来）。
    assert!(
        crate::kiro::model::proxy_pool::validate_proxy_id(id).is_ok(),
        "生成的 id 必须满足加载期规则"
    );
}

// ─────────────────────────────────────────────────────────────
// J6：PATCH 的 name/url 不可空
// ─────────────────────────────────────────────────────────────

/// 反事实：恢复"`url: null` 静默忽略"，第一条变红（200 且条目未变）。
#[tokio::test]
async fn patch_proxy_rejects_null_name_and_url() {
    let dir = TempDir::new();
    let service = service(&dir);
    let list = service
        .create_proxy(
            serde_json::from_value(serde_json::json!({
                "name": "P1",
                "url": "socks5://127.0.0.1:1080"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let id = list.proxies[0].id.clone();

    for body in [
        serde_json::json!({"url": null}),
        serde_json::json!({"name": null}),
    ] {
        let patch: UpdateProxyRequest = serde_json::from_value(body.clone()).unwrap();
        let error = service
            .update_proxy(&id, patch)
            .await
            .expect_err("不可空字段传 null 必须拒绝");
        assert_status(error, 400, "invalid_request");
    }

    let after = service.list_proxies();
    assert_eq!(after.proxies[0].name, "P1", "被拒绝的 PATCH 不得改动条目");
    assert_eq!(
        after.proxies[0].url, "socks5://127.0.0.1:1080",
        "被拒绝的 PATCH 不得改动 URL"
    );
}

/// `username`/`password` 的 null 语义仍是"清除"，不能被上面的收紧带跑。
#[tokio::test]
async fn patch_proxy_keeps_nullable_auth_semantics() {
    let dir = TempDir::new();
    let service = service(&dir);
    let list = service
        .create_proxy(
            serde_json::from_value(serde_json::json!({
                "name": "P1",
                "url": "socks5://127.0.0.1:1080",
                "username": "u",
                "password": "p"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let id = list.proxies[0].id.clone();
    assert!(list.proxies[0].has_password);

    let patch: UpdateProxyRequest = serde_json::from_value(serde_json::json!({
        "username": null,
        "password": null
    }))
    .unwrap();
    let after = service.update_proxy(&id, patch).await.expect("清除认证");
    assert!(!after.proxies[0].has_password);
    assert!(after.proxies[0].username.is_none());
}

// ─────────────────────────────────────────────────────────────
// F6：空串 `proxyId` 必须与"未绑定"区分开，且在发出任何网络请求之前拒绝
// ─────────────────────────────────────────────────────────────

/// 新增凭据传 `proxyId: ""`：400，且上游刷新服务收到 0 个请求。
///
/// 缺陷形态（F6）：入口用 `.filter(|id| !id.is_empty())` 把空串当"未绑定"放行，
/// 于是 OAuth 凭据**先经继承路由真实刷新一次 token**，锁内复核处再因为
/// `proxy_config("")` 查不到而返回 409「代理已被删除: 」。上游若在刷新时轮换
/// refresh token，用户手上的 token 会因此作废——危害就在"拦在请求之后"。
///
/// 前置条件断言：
/// 1. 刷新服务已安装（否则 `count() == 0` 可能只是"没有可数的服务"）；
/// 2. 该请求携带的是真正可刷新的 OAuth 凭据（长度合法），否则它会在刷新之前
///    被 `validate_refresh_token` 拒掉，`count() == 0` 就是假象。
///
/// 反事实（已现场验证）：把 `validate_binding_fields` 的空串判定改回放行，
/// 本条在状态码处红——实际得到 409「代理已被删除: 」，并且此前
/// `refresh.count()` 已经是 1。
#[tokio::test]
async fn add_credential_rejects_empty_proxy_id_before_any_network_request() {
    let dir = TempDir::new();
    let refresh = CountingRefreshServer::spawn().await;
    let manager = Arc::new(
        MultiTokenManager::new_with_pool(
            Config::default(),
            Vec::new(),
            Vec::new(),
            None,
            Some(dir.path()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    manager.install_refresh_url_for_test(refresh.url.clone());

    let request = add_request(serde_json::json!({
        "refreshToken": "r".repeat(120),
        "authMethod": "social",
        "proxyId": "",
    }));
    // 前置条件：这确实是一条能走到刷新那一步的 OAuth 凭据。
    assert_eq!(request.auth_method, "social");
    assert_eq!(request.proxy_binding_id().unwrap().as_deref(), Some(""));

    let service = AdminService::new(manager.clone(), Vec::new());
    let error = service
        .add_credential(request)
        .await
        .expect_err("空串 proxyId 必须拒绝，不能当成未绑定");
    assert_status(error, 400, "invalid_request");

    assert_eq!(
        refresh.count(),
        0,
        "拦截必须发生在任何网络请求之前（先刷新后拒绝会让 refresh token 有被轮换作废的风险）"
    );
    assert_eq!(manager.snapshot().total, 0, "被拒绝的请求不得发布内存");
}

/// 绑定传 `proxyId: ""`：400，与新增路径同一结论（不是 404「代理不存在: 」）。
///
/// 缺陷形态（F6）：`bind_credential_proxy` 拿空串去 `proxy_config("")` 查池，
/// 查不到就直接 404，于是同一份输入在 add 上是 409、在 bind 上是 404。
///
/// 前置条件断言：绑定前该凭据确实是"未绑定"（否则"没有写坏"可能只是"本来就
/// 有绑定"），且磁盘上没有该文件（否则"未被改写"无从判断）。
///
/// 反事实（已现场验证）：把 `bind_credential_proxy` 入口的共享校验去掉，
/// 本条在状态码处红——实际得到 404。
#[tokio::test]
async fn bind_credential_proxy_rejects_empty_proxy_id() {
    let dir = TempDir::new();
    let manager = Arc::new(
        MultiTokenManager::new_with_pool(
            Config::default(),
            vec![crate::kiro::model::credentials::KiroCredentials {
                id: Some(1),
                kiro_api_key: Some("ksk_bind_empty".into()),
                ..Default::default()
            }],
            Vec::new(),
            None,
            Some(dir.path()),
            true,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap(),
    );
    // 前置条件：确实是未绑定状态，且记下此刻磁盘上的字节（构造期会补
    // machineId 并落盘，所以不能假设文件不存在）。
    assert!(
        manager.snapshot().entries[0].proxy_id.is_none(),
        "前置条件：初始必须未绑定"
    );
    let disk_before =
        std::fs::read(dir.path()).expect("构造期应已落盘，否则无法判断文件是否被改写");

    let service = AdminService::new(manager.clone(), Vec::new());
    let binding: BindProxyRequest =
        serde_json::from_value(serde_json::json!({"mode": "pool", "proxyId": ""}))
            .expect("请求必须能反序列化");
    let error = service
        .bind_credential_proxy(1, binding)
        .await
        .expect_err("空串 proxyId 必须拒绝");
    assert_status(error, 400, "invalid_request");

    assert_eq!(
        std::fs::read(dir.path()).unwrap(),
        disk_before,
        "被拒绝的绑定不得改写磁盘文件"
    );
    assert!(
        manager.snapshot().entries[0].proxy_id.is_none(),
        "被拒绝的绑定不得发布内存"
    );
}
