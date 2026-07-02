//! Anthropic API 中间件

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use tracing::Instrument;
use uuid::Uuid;

use crate::common::auth;
use crate::kiro::provider::KiroProvider;
use crate::model::config::{CcStreamingMode, PromptCacheMode};
use crate::model::registry::ModelRegistry;

use super::prompt_cache::PromptCacheTracker;
use super::types::ErrorResponse;

/// 应用共享状态
#[derive(Clone)]
pub struct AppState {
    /// API 密钥
    pub api_key: String,
    /// Kiro Provider（可选，用于实际 API 调用）
    /// 内部使用 MultiTokenManager，已支持线程安全的多凭据管理
    pub kiro_provider: Option<Arc<KiroProvider>>,
    /// 是否开启非流式响应的 thinking 块提取
    pub extract_thinking: bool,
    pub prompt_cache_mode: PromptCacheMode,
    pub cc_streaming_mode: CcStreamingMode,
    pub prompt_cache: Arc<PromptCacheTracker>,
    pub model_registry: Arc<ModelRegistry>,
}

impl AppState {
    /// 创建新的应用状态
    pub fn new(
        api_key: impl Into<String>,
        extract_thinking: bool,
        prompt_cache_mode: PromptCacheMode,
        cc_streaming_mode: CcStreamingMode,
        model_registry: Arc<ModelRegistry>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            kiro_provider: None,
            extract_thinking,
            prompt_cache_mode,
            cc_streaming_mode,
            prompt_cache: Arc::new(PromptCacheTracker::default()),
            model_registry,
        }
    }

    /// 设置 KiroProvider
    pub fn with_kiro_provider(mut self, provider: KiroProvider) -> Self {
        self.kiro_provider = Some(Arc::new(provider));
        self
    }
}

/// API Key 认证中间件
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match auth::extract_api_key(&request) {
        Some(key) if auth::constant_time_eq(&key, &state.api_key) => next.run(request).await,
        _ => {
            let error = ErrorResponse::authentication_error();
            (StatusCode::UNAUTHORIZED, Json(error)).into_response()
        }
    }
}

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("request-id");

pub fn create_anthropic_request_id() -> String {
    format!("req_{}", Uuid::new_v4())
}

pub fn insert_request_id_header(headers: &mut HeaderMap, request_id: &str) {
    match HeaderValue::from_str(request_id) {
        Ok(value) => {
            headers.insert(REQUEST_ID_HEADER.clone(), value);
        }
        Err(e) => {
            tracing::warn!(error = %e, "生成的 request-id 无法作为响应头写入");
        }
    }
}

pub async fn request_id_middleware(request: Request<Body>, next: Next) -> Response {
    let id = create_anthropic_request_id();
    // method/path 直接作为 span 字段记录：`%` 在 info_span! 展开期即时格式化，
    // 借用仅存活到宏结束，之后 request 仍可 move 进 next.run，省去热路径两次堆分配。
    let span = tracing::info_span!(
        "req",
        request_id = %id,
        method = %request.method(),
        path = %request.uri().path(),
        conversation_id = tracing::field::Empty,
    );
    let mut response = next.run(request).instrument(span).await;
    insert_request_id_header(response.headers_mut(), &id);
    response
}

/// CORS 中间件层
///
/// **安全说明**：当前配置允许所有来源（Any），这是为了支持公开 API 服务。
/// 如果需要更严格的安全控制，请根据实际需求配置具体的允许来源、方法和头信息。
///
/// # 配置说明
/// - `allow_origin(Any)`: 允许任何来源的请求
/// - `allow_methods(Any)`: 允许任何 HTTP 方法
/// - `allow_headers(Any)`: 允许任何请求头
pub fn cors_layer() -> tower_http::cors::CorsLayer {
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers([REQUEST_ID_HEADER])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_anthropic_request_id_format() {
        let request_id = create_anthropic_request_id();

        assert!(request_id.starts_with("req_"));
        let uuid_part = &request_id[4..];
        assert!(Uuid::parse_str(uuid_part).is_ok());
    }

    #[test]
    fn test_insert_request_id_header() {
        let mut headers = HeaderMap::new();

        insert_request_id_header(&mut headers, "req_12345678-1234-1234-1234-123456789abc");

        assert_eq!(
            headers
                .get(&REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("req_12345678-1234-1234-1234-123456789abc")
        );
    }
}
