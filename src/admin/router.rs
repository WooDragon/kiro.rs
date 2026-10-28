//! Admin API 路由配置

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post, put},
};

use super::{
    handlers::{
        add_credential, bind_credential_proxy, create_proxy, delete_credential, delete_proxy,
        force_refresh_token, get_all_credentials, get_credential_balance, get_load_balancing_mode,
        get_prompt_injection, list_proxies, reset_failure_count, set_credential_disabled,
        set_credential_priority, set_load_balancing_mode, set_prompt_injection, update_proxy,
    },
    middleware::{AdminState, admin_auth_middleware},
};

/// 创建 Admin API 路由
///
/// # 端点
/// - `GET /credentials` - 获取所有凭据状态
/// - `POST /credentials` - 添加新凭据
/// - `DELETE /credentials/:id` - 删除凭据
/// - `POST /credentials/:id/disabled` - 设置凭据禁用状态
/// - `POST /credentials/:id/priority` - 设置凭据优先级
/// - `POST /credentials/:id/reset` - 重置失败计数
/// - `POST /credentials/:id/refresh` - 强制刷新 Token
/// - `GET /credentials/:id/balance` - 获取凭据余额
/// - `PUT /credentials/:id/proxy` - 绑定凭据代理来源
/// - `GET /proxies` - 列出代理池
/// - `POST /proxies` - 新增池代理
/// - `PATCH /proxies/:id` - 编辑池代理
/// - `DELETE /proxies/:id` - 删除池代理
/// - `GET /config/load-balancing` - 获取负载均衡模式
/// - `PUT /config/load-balancing` - 设置负载均衡模式
///
/// # 认证
/// 需要 Admin API Key 认证，支持：
/// - `x-api-key` header
/// - `Authorization: Bearer <token>` header
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/credentials",
            get(get_all_credentials).post(add_credential),
        )
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/disabled", post(set_credential_disabled))
        .route("/credentials/{id}/priority", post(set_credential_priority))
        .route("/credentials/{id}/reset", post(reset_failure_count))
        .route("/credentials/{id}/refresh", post(force_refresh_token))
        .route("/credentials/{id}/balance", get(get_credential_balance))
        .route("/credentials/{id}/proxy", put(bind_credential_proxy))
        .route("/proxies", get(list_proxies).post(create_proxy))
        .route("/proxies/{id}", patch(update_proxy).delete(delete_proxy))
        .route(
            "/config/load-balancing",
            get(get_load_balancing_mode).put(set_load_balancing_mode),
        )
        .route(
            "/config/prompt-injection",
            get(get_prompt_injection).put(set_prompt_injection),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}
