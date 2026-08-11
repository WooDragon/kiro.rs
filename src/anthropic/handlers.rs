//! Anthropic API Handler 函数

use std::convert::Infallible;

use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::token;
use anyhow::Error;
use axum::{
    Json as JsonExtractor,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use serde_json::json;
use std::time::Duration;
use tokio::time::{Instant, interval_at};
use tracing::Instrument;
use uuid::Uuid;

use super::converter::{ConversionError, convert_request};
use super::middleware::AppState;
use super::prompt_cache::{
    PromptCacheProfile, PromptCacheTracker, PromptCacheUsage, build_usage_value,
    decide_prompt_cache, extract_usage_snapshot_from_metering,
};
use super::stream::PrefixBufferedStreamContext;
use super::stream::{BufferedStreamContext, SseEvent, StreamContext};
use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking,
};
use super::websearch;
use crate::kiro::model::requests::conversation::ConversationState;
use crate::kiro::model::requests::kiro::InferenceConfig;
use crate::model::config::{CcStreamingMode, PromptCacheMode};
use crate::model::registry::ModelRegistry;
use std::sync::Arc;

/// 日志 payload 截断上限：8 KB
///
/// `pub(crate)`：websearch.rs 的 MCP 调试日志复用同一截断逻辑与上限（#71），
/// 避免维护两份等价实现。
pub(crate) const LOG_PAYLOAD_LIMIT: usize = 8 * 1024;

/// 日志用：超过 `limit` 字节则在 UTF-8 安全边界截断并标注省略字节数。
pub(crate) fn truncate_for_log(s: &str, limit: usize) -> std::borrow::Cow<'_, str> {
    if s.len() <= limit {
        std::borrow::Cow::Borrowed(s)
    } else {
        let end = crate::anthropic::stream::find_char_boundary(s, limit);
        std::borrow::Cow::Owned(format!(
            "{}...<truncated {} bytes>",
            &s[..end],
            s.len() - end
        ))
    }
}

/// PR-0（可观测性，零行为变更）：在既有 `request outcome` 事件上补充 4 个结构化字段
/// （credential_id / sticky_hit / session_id_extracted / cache_bucket_kind），
/// 供 jq 交叉聚合"哪个凭据处理了多少请求、sticky 命中率、session_id 提取成功率、
/// 缓存分桶方式"。事件名与 `req_outcome` 语义逐字不变，只是集中成一个函数以免
/// 12 处调用点各自手写字段名时写歪。
///
/// PR-0 返工（redteam MUST FIX 1）：上一版这里写"凭据获取阶段本身失败时这 4 个
/// 字段无从谈起"，对 `handle_non_stream_request` 里 body 中途断连（#64 场景）那个
/// 调用点是错的——那里凭据早已成功获取（`api_response` 在作用域内），只是读
/// 响应体这一步失败。真正"字段无从谈起"的是 `map_provider_error` 另外 4 个
/// 调用点（凭据获取阶段本身失败的 `Err` 分支，压根没有 `api_response`）：
/// 这批失败绝对量小、且请求压根没到达上游，缓存分桶讨论意义有限，故维持裸
/// `tracing::info!` 不接入本函数。#71 的 `status × req_outcome` 四态交叉表本就
/// 设计为容忍字段稀疏，不要求每条 `request outcome` 都带满 4 个字段。
///
/// `credential_id`/`sticky_hit` 用 `Option` 而非裸值：前者是 redteam 采纳建议 2
/// （`0` 是凭据文件里合法可手写的 id，不能当"未回填"哨兵）；后者是 MUST FIX 2
/// 的三态语义（`None` = 会话粘性机制未启用 / priority 模式，不是"未命中"）。
fn log_request_outcome(
    req_outcome: &str,
    credential_id: Option<u64>,
    sticky_hit: Option<bool>,
    session_id_extracted: bool,
    cache_bucket_kind: &str,
) {
    tracing::info!(
        req_outcome = req_outcome,
        credential_id,
        sticky_hit = match sticky_hit {
            Some(true) => "hit",
            Some(false) => "miss",
            None => "n_a",
        },
        session_id_extracted,
        cache_bucket_kind,
        "request outcome"
    );
}

/// PR-0 返工（redteam 采纳建议 1）：`cache_bucket_kind` 从实际构造出的
/// `account_key` 字符串取前缀，而不是重新判断一次 `stable_conversation_id`
/// 分支——避免这个字段沦为分桶逻辑的复制品：`account_key` 的构造规则将来变了，
/// 这个字段自动跟着变，不会有旁路判断悄悄脱节。未识别前缀（如 websearch.rs
/// 固定桶 `"websearch"`，本次未接入 `request outcome` 日志）落 `"cred"` 兜底，
/// 维持字段现有的二值语义。
fn cache_bucket_kind_from_account_key(account_key: &str) -> &'static str {
    match account_key.split_once(':').map(|(prefix, _)| prefix) {
        Some("conv") => "conv",
        _ => "cred",
    }
}

/// 构建并序列化 KiroRequest。
///
/// # 参数
/// * `conversation_state` - 已经过 validate_tool_pairing / remove_orphaned_tool_uses 配对校验的对话状态
/// * `inference_config` - 推理配置（max_tokens / temperature / top_p）
/// * `additional_model_request_fields` - 模型专属请求参数（thinking / output_config）
fn finalize_request_body(
    conversation_state: ConversationState,
    inference_config: Option<InferenceConfig>,
    additional_model_request_fields: Option<serde_json::Value>,
) -> Result<String, serde_json::Error> {
    let kiro_request = KiroRequest {
        conversation_state,
        inference_config,
        profile_arn: None,
        additional_model_request_fields,
    };

    serde_json::to_string(&kiro_request)
}

/// 将 KiroProvider 错误映射为 HTTP 响应
fn map_provider_error(err: Error) -> Response {
    map_provider_error_with_outcome(err, None)
}

/// PR-0 返工（redteam MUST FIX 1）：`map_provider_error` 的可观测性增强版本。
///
/// `handle_non_stream_request` 里 body 中途断连（#64 场景）那个调用点，凭据早已
/// 成功获取，`api_response` 的 4 个可观测性字段都是现成的、不该在走这条错误
/// 路径时凭空丢失——但也不能给 `map_provider_error` 本身加参数，那会牵动全部
/// ~13 个既有测试调用点。拆成"核心逻辑 + 可选字段"两层：`outcome_fields` 为
/// `None` 时走原有裸 `tracing::info!(req_outcome = ..)`，逐字不变；为 `Some(..)`
/// 时改走 `log_request_outcome` 补齐 4 个字段。两个分支共用同一个 `tracing::info!`
/// 调用点（`match` 内部条件分叉，不是并列的两条语句），因此对任意一次调用，
/// 结局事件只会被发出恰好一次——不可能是 0 次（函数内没有能跳过发射的提前
/// return）,也不可能是 2 次（`Some`/`None` 分支互斥，同一次调用只落进其中一支）。
/// `map_provider_error(err)` 保留原公开签名，作为 `None` 转发的薄包装，公开行为
/// 与既有测试期望逐字不变。
fn map_provider_error_with_outcome(
    err: Error,
    outcome_fields: Option<(Option<u64>, Option<bool>, bool, &str)>,
) -> Response {
    use crate::kiro::provider::ProviderError;

    if let Some(pe) = err.downcast_ref::<ProviderError>() {
        let (status, error_type, message, retry_after) = match pe {
            ProviderError::AllCredentialsDisabled { available, total } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded_error",
                format!(
                    "All credentials disabled ({}/{}). Service temporarily unavailable.",
                    available, total
                ),
                Some(60u64),
            ),
            ProviderError::AllCredentialsQuotaExhausted { detail } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                format!("All credentials quota exhausted: {}", detail),
                Some(60u64),
            ),
            ProviderError::TokenAcquisitionFailed { available, total } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded_error",
                format!(
                    "Token acquisition failed ({}/{}). Service temporarily unavailable.",
                    available, total
                ),
                Some(60u64),
            ),
            ProviderError::UpstreamClientError { status, body } => {
                if *status == 400 {
                    let message = if body.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
                        "Context window is full. Reduce conversation history, system prompt, or tools.".to_string()
                    } else if body.contains("Input is too long") {
                        "Input is too long. Reduce the size of your messages.".to_string()
                    } else {
                        // body 截断：未知上游错误原样回填对外 message，完整 body 可达
                        // 数百 KB，会让错误响应体异常膨胀（内存/带宽），与 #71 大 body
                        // 截断约束一致（Copilot re-review）。
                        format!(
                            "Upstream error: {}",
                            truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                        )
                    };
                    (
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        message,
                        None,
                    )
                } else {
                    (
                        StatusCode::BAD_GATEWAY,
                        "api_error",
                        format!(
                            "Upstream error: {} {}",
                            status,
                            truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                        ),
                        None,
                    )
                }
            }
            ProviderError::UpstreamTransientExhausted { last_status, body } => {
                if *last_status == 429 {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limit_error",
                        format!(
                            "Upstream rate limited (retries exhausted): {}",
                            truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                        ),
                        Some(30u64),
                    )
                } else {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "overloaded_error",
                        format!(
                            "Upstream service error (retries exhausted): {} {}",
                            last_status,
                            truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                        ),
                        Some(30u64),
                    )
                }
            }
            ProviderError::ConnectionFailed { detail } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded_error",
                format!("Connection failed (retries exhausted): {}", detail),
                Some(15u64),
            ),
            ProviderError::InternalConfig { detail } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Internal configuration error: {}", detail),
                None,
            ),
        };

        match status {
            StatusCode::BAD_REQUEST => tracing::warn!(error = %err, "上游拒绝请求（不应重试）"),
            StatusCode::INTERNAL_SERVER_ERROR => tracing::error!(error = %err, "内部配置错误"),
            _ => tracing::error!(error = %err, "Kiro API 调用失败"),
        }
        // req_outcome 统一以字符串字段记录（不加 %）：`%` 走 Display→record_debug，
        // 与其余发射点的 record_str 提取路径不一致，会让捕获层/JSON 里同一字段
        // 时而带引号时而不带，污染 jq 聚合。error_type 是 &str 可直接传。
        match outcome_fields {
            Some((credential_id, sticky_hit, session_id_extracted, cache_bucket_kind)) => {
                log_request_outcome(
                    error_type,
                    credential_id,
                    sticky_hit,
                    session_id_extracted,
                    cache_bucket_kind,
                );
            }
            None => tracing::info!(req_outcome = error_type, "request outcome"),
        }

        let mut response = (status, Json(ErrorResponse::new(error_type, message))).into_response();

        if let Some(seconds) = retry_after
            && let Ok(val) = header::HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, val);
        }

        response
    } else {
        tracing::error!(error = %err, "Kiro API 调用失败（未分类错误）");
        match outcome_fields {
            Some((credential_id, sticky_hit, session_id_extracted, cache_bucket_kind)) => {
                log_request_outcome(
                    "api_error",
                    credential_id,
                    sticky_hit,
                    session_id_extracted,
                    cache_bucket_kind,
                );
            }
            None => tracing::info!(req_outcome = "api_error", "request outcome"),
        }
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(
                "api_error",
                format!("上游 API 调用失败: {}", err),
            )),
        )
            .into_response()
    }
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models(State(state): State<AppState>) -> impl IntoResponse {
    tracing::info!("Received GET /v1/models request");

    let models = state
        .model_registry
        .available_models()
        .into_iter()
        .map(|m| Model {
            id: m.id,
            object: "model".to_string(),
            created: m.created,
            owned_by: "anthropic".to_string(),
            display_name: m.display_name,
            model_type: "chat".to_string(),
            max_tokens: m.max_tokens,
        })
        .collect();

    Json(ModelsResponse {
        object: "list".to_string(),
        data: models,
    })
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages request"
    );
    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload, &state.model_registry);
    let stripped_headers = payload.strip_anthropic_billing_headers();
    if stripped_headers > 0 {
        tracing::debug!(
            count = stripped_headers,
            "已剥离 Claude Code x-anthropic-billing-header 系统块"
        );
    }

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        let cache_profile = build_prompt_cache_profile(&state, &payload, input_tokens);
        return websearch::handle_websearch_request(
            provider,
            &payload,
            input_tokens,
            state.prompt_cache_mode,
            state.prompt_cache.clone(),
            cache_profile,
            &state.model_registry,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request(&payload, &state.model_registry) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!(error = %e, "请求转换失败");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 先取出 tool_name_map 和 stable_conversation_id（后续透传给流式/非流式处理器），再构建并序列化请求体
    let tool_name_map = conversion_result.tool_name_map;
    let stable_conversation_id = conversion_result.stable_conversation_id;

    if let Some(ref cid) = stable_conversation_id {
        tracing::Span::current().record("conversation_id", tracing::field::display(cid));
    }

    // 构建 Kiro 请求体（profile_arn 由 provider 层注入）
    let request_body = match finalize_request_body(
        conversion_result.conversation_state,
        conversion_result.inference_config,
        conversion_result.additional_model_request_fields,
    ) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "序列化请求失败");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!(target: "kiro_rs::payload", body = %truncate_for_log(&request_body, LOG_PAYLOAD_LIMIT), "Kiro request body");

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;
    let cache_profile = build_prompt_cache_profile(&state, &payload, input_tokens);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    if payload.stream {
        // 流式响应
        handle_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            thinking_enabled,
            tool_name_map,
            state.prompt_cache_mode,
            state.prompt_cache.clone(),
            cache_profile,
            stable_conversation_id,
            &state.model_registry,
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            extract_thinking,
            tool_name_map,
            state.prompt_cache_mode,
            state.prompt_cache.clone(),
            cache_profile,
            stable_conversation_id,
            &state.model_registry,
        )
        .await
    }
}

fn build_prompt_cache_profile(
    state: &AppState,
    payload: &MessagesRequest,
    input_tokens: i32,
) -> Option<PromptCacheProfile> {
    if matches!(
        state.prompt_cache_mode,
        PromptCacheMode::Auto | PromptCacheMode::Emulated
    ) {
        state.prompt_cache.build_profile(payload, input_tokens)
    } else {
        None
    }
}

/// 处理流式请求
#[allow(clippy::too_many_arguments)]
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    prompt_cache_mode: PromptCacheMode,
    prompt_cache: Arc<PromptCacheTracker>,
    prompt_cache_profile: Option<PromptCacheProfile>,
    stable_conversation_id: Option<String>,
    model_registry: &Arc<ModelRegistry>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let api_response = match provider.call_api_stream_with_context(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };
    let response = api_response.response;
    // conv: / cred: 前缀隔离两类实体命名空间，防止客户端 session_id 恰好等于 credential_id 时串缓存。
    // Some(id) = 客户端传了稳定 session_id，按会话分桶，跨凭据 fallback 不丢缓存；
    // None = 无稳定 ID，退回 credential_id 分桶（不比现状差）。
    // PR-0：session_id_extracted 是 account_key 分支判断的副产物，
    // 提前读一次 is_some()（借用，不消费 stable_conversation_id），供下方 request outcome 日志用。
    let session_id_extracted = stable_conversation_id.is_some();
    let account_key = match stable_conversation_id {
        Some(ref id) => format!("conv:{}", id),
        None => format!("cred:{}", api_response.credential_id),
    };
    // PR-0 返工（redteam 采纳建议 1）：cache_bucket_kind 从上面已构造好的 account_key
    // 取前缀，而不是重新判断一次 session_id_extracted 分支，避免两处判断脱节。
    let cache_bucket_kind = cache_bucket_kind_from_account_key(&account_key);
    let min_cacheable_tokens = model_registry.min_cacheable_tokens(model);
    let fallback_cache_usage = prompt_cache.compute(
        &account_key,
        prompt_cache_profile.as_ref(),
        min_cacheable_tokens,
    );
    let context_window = model_registry.context_window(model);

    // 创建流处理上下文
    let mut ctx = StreamContext::new_with_thinking(
        model,
        context_window,
        input_tokens,
        thinking_enabled,
        tool_name_map,
        min_cacheable_tokens,
    )
    .with_prompt_cache(
        prompt_cache_mode,
        Some(prompt_cache),
        Some(account_key),
        prompt_cache_profile,
        fallback_cache_usage,
    )
    .with_observability(
        api_response.credential_id,
        api_response.sticky_hit,
        session_id_extracted,
        cache_bucket_kind,
    );

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 在 handler 仍处于 req span 上下文中时捕获当前 span，
    // 传入 stream 闭包以便 hyper poll body 时仍能关联 request_id。
    let span = tracing::Span::current();

    // 创建 SSE 流
    let stream = create_sse_stream(response, ctx, initial_events, span);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
const PING_INTERVAL_SECS: u64 = 25;

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

fn create_ping_interval() -> tokio::time::Interval {
    interval_at(
        Instant::now() + Duration::from_secs(PING_INTERVAL_SECS),
        Duration::from_secs(PING_INTERVAL_SECS),
    )
}

/// 把 `StreamFailure` 映射为 `failure_mode` 日志字段取值（#83）。
///
/// 沿用 #71 结构化日志口径：snake_case 字符串常量，供 jq 按成因聚合、
/// 长期验证 200s 首字截止线闸门是否稳定。`FirstTokenTimeout` 与
/// `ConnectionInterrupted` 分开打标；match 穷举完整覆盖四个 variant，但
/// Err 路径当前实际只会打 `first_token_timeout` / `connection_interrupted` /
/// `non_transient` 三种——`empty_response` 分支是为穷举完整性与将来对称
/// 调用预留（`None` 分支目前单独记日志，不经此函数）。
fn failure_mode_label(failure: &super::stream::StreamFailure) -> &'static str {
    match failure {
        super::stream::StreamFailure::FirstTokenTimeout { .. } => "first_token_timeout",
        super::stream::StreamFailure::ConnectionInterrupted => "connection_interrupted",
        super::stream::StreamFailure::EmptyResponse => "empty_response",
        super::stream::StreamFailure::Fatal => "non_transient",
    }
}

/// 创建 SSE 事件流
///
/// `span` 是 handler 执行期间捕获的 req span。stream::unfold 闭包返回的每个
/// async 块都单独挂 `.instrument(span.clone())`，使 hyper 在 handler future 完成
/// 后 poll body stream 时，内部 tracing 事件仍能关联到原始 request_id。
fn create_sse_stream(
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
    span: tracing::Span,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    // 先发送初始事件
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // #83：入口即上游响应头已收到的时刻，用于给 classify_stream_failure 提供
    // 「本轮已运行多久」的 elapsed。Instant 是 Copy，move 闭包按值捕获即可，
    // 不必塞进 unfold 状态元组。
    let stream_start = Instant::now();

    // 然后处理 Kiro 响应流，同时每25秒发送 ping 保活
    let body_stream = response.bytes_stream();

    let processing_stream = stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            create_ping_interval(),
        ),
        // move 捕获 span；每次 poll 对 async block 单独 instrument，
        // 使 tracing::Instrument 的 Future impl 生效（Stream 上无此 impl）。
        move |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval)| {
            async move {
                if finished {
                    return None;
                }

                // 使用 select! 同时等待数据和 ping 定时器
                tokio::select! {
                    // 处理数据流
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
                                // 解码事件
                                if let Err(e) = decoder.feed(&chunk) {
                                    tracing::warn!(error = %e, "缓冲区溢出");
                                }

                                let mut events = Vec::new();
                                for result in decoder.decode_iter() {
                                    match result {
                                        Ok(frame) => {
                                            if let Ok(event) = Event::from_frame(frame) {
                                                let sse_events = ctx.process_kiro_event(&event);
                                                events.extend(sse_events);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "解码事件失败");
                                        }
                                    }
                                }

                                // 转换为 SSE 字节流
                                let bytes: Vec<Result<Bytes, Infallible>> = events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();

                                Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                            }
                            Some(Err(e)) => {
                                // #64：上游中途断连——发 error 帧让客户端感知失败并重试，
                                // 绝不走正常收尾（不补 message_delta/message_stop），避免把失败伪装成正常完成。
                                // #83：把 transient/is_empty_response/elapsed 三个既有信号交给
                                // classify_stream_failure 分类，区分「上游首字截止线超时」与
                                // 「普通连接中断」——error_type/req_outcome 语义不变，只改归因与文案。
                                let transient = crate::http_client::is_transient(&e);
                                let elapsed = stream_start.elapsed();
                                let failure = super::stream::classify_stream_failure(
                                    transient,
                                    ctx.is_empty_response(),
                                    elapsed,
                                );
                                tracing::error!(
                                    error = %crate::http_client::describe_reqwest_error(&e),
                                    failure_mode = failure_mode_label(&failure),
                                    elapsed_secs = elapsed.as_secs(),
                                    "读取响应流失败"
                                );
                                log_request_outcome(
                                    if transient { "overloaded_error" } else { "api_error" },
                                    ctx.credential_id,
                                    ctx.sticky_hit,
                                    ctx.session_id_extracted,
                                    ctx.cache_bucket_kind,
                                );
                                let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(Bytes::from(
                                    super::stream::error_sse_event(failure).to_sse_string(),
                                ))];
                                Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                            }
                            None => {
                                // 流结束。#64：本轮零产出（上游 200 空响应）时发 error 帧诱导重试，
                                // 否则正常收尾（有内容分支逐字保留原调用）。
                                // #83：干净结束零产出压根没有断连，改用 EmptyResponse 变体，
                                // 与非流式路径（handlers.rs 空响应分支）措辞对齐。
                                let final_events = if ctx.is_empty_response() {
                                    tracing::error!("上游响应为空（无内容），返回 error 事件以触发客户端重试");
                                    log_request_outcome(
                                        "overloaded_error",
                                        ctx.credential_id,
                                        ctx.sticky_hit,
                                        ctx.session_id_extracted,
                                        ctx.cache_bucket_kind,
                                    );
                                    vec![super::stream::error_sse_event(super::stream::StreamFailure::EmptyResponse)]
                                } else {
                                    log_request_outcome(
                                        "success",
                                        ctx.credential_id,
                                        ctx.sticky_hit,
                                        ctx.session_id_extracted,
                                        ctx.cache_bucket_kind,
                                    );
                                    ctx.generate_final_events()
                                };
                                let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                            }
                        }
                    }
                    // 发送 ping 保活
                    _ = ping_interval.tick() => {
                        tracing::trace!("发送 ping 保活事件");
                        let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                        Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                    }
                }
            }
            .instrument(span.clone())
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}

/// 处理非流式请求
#[allow(clippy::too_many_arguments)]
async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    prompt_cache_mode: PromptCacheMode,
    prompt_cache: Arc<PromptCacheTracker>,
    prompt_cache_profile: Option<PromptCacheProfile>,
    stable_conversation_id: Option<String>,
    model_registry: &Arc<ModelRegistry>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let api_response = match provider.call_api_with_context(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };
    let response = api_response.response;
    // conv: / cred: 前缀隔离两类实体命名空间，防止客户端 session_id 恰好等于 credential_id 时串缓存。
    // Some(id) = 客户端传了稳定 session_id，按会话分桶，跨凭据 fallback 不丢缓存；
    // None = 无稳定 ID，退回 credential_id 分桶（不比现状差）。
    // PR-0：session_id_extracted 是 account_key 分支判断的副产物，
    // 提前读一次 is_some()（借用，不消费 stable_conversation_id），供下方 request outcome 日志用。
    let session_id_extracted = stable_conversation_id.is_some();
    let account_key = match stable_conversation_id {
        Some(ref id) => format!("conv:{}", id),
        None => format!("cred:{}", api_response.credential_id),
    };
    // PR-0 返工（redteam 采纳建议 1）：cache_bucket_kind 从上面已构造好的 account_key
    // 取前缀，而不是重新判断一次 session_id_extracted 分支，避免两处判断脱节。
    let cache_bucket_kind = cache_bucket_kind_from_account_key(&account_key);
    let min_cacheable_tokens = model_registry.min_cacheable_tokens(model);
    let fallback_cache_usage = prompt_cache.compute(
        &account_key,
        prompt_cache_profile.as_ref(),
        min_cacheable_tokens,
    );

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            // 服务端日志打结构化诊断串，便于区分 idle 超时 / 上游 reset / 真截断
            tracing::error!(
                error = %crate::http_client::describe_reqwest_error(&e),
                "读取响应体失败"
            );
            // #64：body 中途断连（is_transient=true，如 HTTP/2 RST / 超时 / 连接失败）复用
            // ProviderError 瞬态语义 → map_provider_error 映射 503 + Retry-After，让客户端重试；
            // 非瞬态（构造/配置类）保留原 502 语义。此处是 .bytes() 原始字节读取分支，
            // is_transient 使用合规（不涉及 .json() 反序列化）。
            if crate::http_client::is_transient(&e) {
                let provider_err: Error = crate::kiro::provider::ProviderError::ConnectionFailed {
                    detail: format!("上游响应体读取中断: {}", e),
                }
                .into();
                // PR-0 返工（redteam MUST FIX 1）：这里凭据早已成功获取
                // （`api_response` 在作用域内），走 map_provider_error 不该白白
                // 丢掉 4 个可观测性字段——尤其这正是 #64 记录的真实故障场景
                // （上游 HTTP/2 RST 中途冲断），是最该定位到具体凭据的一类失败，
                // 漏记还会拉低 sticky 命中率分母。改走
                // map_provider_error_with_outcome 带上字段，机制见该函数文档。
                return map_provider_error_with_outcome(
                    provider_err,
                    Some((
                        Some(api_response.credential_id),
                        api_response.sticky_hit,
                        session_id_extracted,
                        cache_bucket_kind,
                    )),
                );
            }
            // 非瞬态分支绕过 map_provider_error，结局事件在此单独补发。
            log_request_outcome(
                "api_error",
                Some(api_response.credential_id),
                api_response.sticky_hit,
                session_id_extracted,
                cache_bucket_kind,
            );
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    // 客户端响应只暴露 Display，不外泄 source chain
                    format!("读取响应失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    // 解析事件流
    let mut decoder = EventStreamDecoder::new();
    if let Err(e) = decoder.feed(&body_bytes) {
        tracing::warn!(error = %e, "缓冲区溢出");
    }

    let mut text_content = String::new();
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    // 从 contextUsageEvent 计算的实际输入 tokens
    let mut context_input_tokens: Option<i32> = None;
    let mut upstream_input_tokens: Option<i32> = None;
    let mut upstream_output_tokens: Option<i32> = None;
    let mut upstream_cache_usage: Option<PromptCacheUsage> = None;

    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(tool_use.tool_use_id.clone())
                                .or_default();
                            buffer.push_str(&tool_use.input);

                            // 如果是完整的工具调用，添加到列表
                            if tool_use.stop {
                                let input: serde_json::Value = if buffer.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::from_str(buffer).unwrap_or_else(|e| {
                                        tracing::warn!(
                                            error = %e,
                                            tool_use_id = %tool_use.tool_use_id,
                                            "工具输入 JSON 解析失败"
                                        );
                                        serde_json::json!({})
                                    })
                                };

                                let original_name = tool_name_map
                                    .get(&tool_use.name)
                                    .cloned()
                                    .unwrap_or_else(|| tool_use.name.clone());

                                tool_uses.push(json!({
                                    "type": "tool_use",
                                    "id": tool_use.tool_use_id,
                                    "name": original_name,
                                    "input": input
                                }));
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 从上下文使用百分比计算实际的 input_tokens
                            let window_size = model_registry.context_window(model);
                            let actual_input_tokens =
                                (context_usage.context_usage_percentage * (window_size as f64)
                                    / 100.0) as i32;
                            context_input_tokens = Some(actual_input_tokens);
                            // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                            if context_usage.context_usage_percentage >= 100.0 {
                                stop_reason = "model_context_window_exceeded".to_string();
                            }
                            tracing::debug!(
                                context_usage_pct = context_usage.context_usage_percentage,
                                input_tokens = actual_input_tokens,
                                "收到 contextUsageEvent"
                            );
                        }
                        Event::Metering(payload) => {
                            if let Some(snapshot) = extract_usage_snapshot_from_metering(&payload) {
                                if let Some(input_tokens) = snapshot.input_tokens {
                                    upstream_input_tokens = Some(input_tokens.max(1));
                                } else if let Some(total_tokens) = snapshot.total_tokens
                                    && let Some(output_tokens) = snapshot.output_tokens
                                {
                                    upstream_input_tokens =
                                        Some((total_tokens - output_tokens).max(1));
                                }
                                if let Some(output_tokens) = snapshot.output_tokens {
                                    upstream_output_tokens = Some(output_tokens.max(0));
                                }
                                if let Some(usage) = snapshot.prompt_cache_usage {
                                    upstream_cache_usage = Some(usage);
                                }
                            }
                        }
                        Event::Exception {
                            exception_type,
                            message,
                        } => {
                            if exception_type == "ContentLengthExceededException" {
                                stop_reason = "max_tokens".to_string();
                            }
                            tracing::warn!(event_type = %exception_type, error = %message, "收到异常事件");
                        }
                        Event::Error {
                            error_code,
                            error_message,
                        } => {
                            tracing::error!(event_type = %error_code, error = %error_message, "收到错误事件");
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "解码事件失败");
            }
        }
    }

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // #43 非流式路径同款检测：上游把工具调用 XML 当纯文本吐出且本轮无结构化 tool_use
    // → stop_reason 修正为 max_tokens（CC 自动续机制兜底），仅在 stop_reason 仍为默认值时介入。
    if !has_tool_use
        && let Some(marker) = super::tool_call_leak::detect_text_tool_call_leak(&text_content)
    {
        if stop_reason == "end_turn" {
            stop_reason = "max_tokens".to_string();
        }
        tracing::warn!(
            leak_marker = ?marker,
            model = model,
            text_len = text_content.len(),
            stop_reason = %stop_reason,
            "检测到工具调用明文泄漏(#43,非流式)"
        );
    }

    // 构建响应内容
    let mut content: Vec<serde_json::Value> = Vec::new();

    if thinking_enabled {
        // 从完整文本中提取 thinking 块
        let (thinking, remaining_text) =
            super::stream::extract_thinking_from_complete_text(&text_content);

        if let Some(thinking_text) = thinking {
            content.push(json!({
                "type": "thinking",
                "thinking": thinking_text
            }));
        }

        if !remaining_text.is_empty() {
            content.push(json!({
                "type": "text",
                "text": remaining_text
            }));
        }
    } else if !text_content.is_empty() {
        content.push(json!({
            "type": "text",
            "text": text_content
        }));
    }

    content.extend(tool_uses);

    // #64：上游 200 + 空 body（或解析后零内容）会走到这里且 content 为空——此前被组装成
    // content=[] 的假 200，客户端误判任务成功。改为返回可重试错误（与流式 None 分支对称：
    // 503 + overloaded_error），让客户端重试而非误判完成。content 仅由 thinking/text/tool_use
    // 填充，故 content.is_empty() 精确等价于「无 text/thinking 且 !has_tool_use」，与流式
    // is_empty_response（output_tokens==0 && !has_tool_use，thinking 计入 output_tokens）语义一致。
    // 短路在 token 估算/缓存更新之前，避免为失败响应产生副作用（同流式异常分支跳过收尾）。
    //
    // 但（#64 自身引入的死循环修正，与流式 is_empty_response 对称）：上游发
    // ContentLengthExceededException / contextUsage>=100% 后不吐内容就结束时，content 为空
    // 但 stop_reason 已被显式置为 max_tokens / model_context_window_exceeded——这是**终止信号**
    // 而非空响应。此时不返 503，走正常 200 透传该 stop_reason（content=[] 但 stop_reason 有意义，
    // 客户端据此处理，如 max_tokens 触发续写），避免客户端永久重试必然触发上限的请求形成死循环。
    // stop_reason 初值为 "end_turn"，仅在上述显式终止信号时被改写，故 `== "end_turn"` 精确表示
    // 「无显式终止原因」。
    //
    // C4（credits 记账）：本项目无本地 credit/usage 台账——上游 meteringEvent 仅被读取用于
    // ①填充响应体 usage 展示字段（503 无响应体，无意义）②驱动 prompt_cache 本地缓存模拟
    // （非计费）。真实 credits 由 Kiro 上游侧计量，本地 503 短路不涉及任何 credits 状态丢失。
    // 故此处 503 前无需补记账。（prompt_cache.update 亦无需在失败响应上执行：失败请求的前缀不应
    // 被记为"已缓存"。）
    if content.is_empty() && stop_reason == "end_turn" {
        tracing::error!(
            model = model,
            "上游响应为空（无内容且无显式终止信号），返回可重试错误以触发客户端重试"
        );
        log_request_outcome(
            "overloaded_error",
            Some(api_response.credential_id),
            api_response.sticky_hit,
            session_id_extracted,
            cache_bucket_kind,
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(
                "overloaded_error",
                "Upstream returned an empty response. Please retry.",
            )),
        )
            .into_response();
    }

    // 估算输出 tokens
    let output_tokens =
        upstream_output_tokens.unwrap_or_else(|| token::estimate_output_tokens(&content));

    // 优先使用上游 meteringEvent usage，其次 contextUsageEvent，最后回退估算值
    let final_input_tokens = upstream_input_tokens
        .or(context_input_tokens)
        .unwrap_or(input_tokens);
    let cache_decision = decide_prompt_cache(
        prompt_cache_mode,
        upstream_cache_usage,
        fallback_cache_usage,
        prompt_cache_profile.is_some(),
    );
    if matches!(
        prompt_cache_mode,
        PromptCacheMode::Auto | PromptCacheMode::Emulated
    ) {
        prompt_cache.update(
            &account_key,
            prompt_cache_profile.as_ref(),
            min_cacheable_tokens,
        );
    }

    log_request_outcome(
        "success",
        Some(api_response.credential_id),
        api_response.sticky_hit,
        session_id_extracted,
        cache_bucket_kind,
    );

    // 构建 Anthropic 响应
    let response_body = json!({
        "id": format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": build_usage_value(
            final_input_tokens,
            output_tokens,
            cache_decision.fallback_usage,
            cache_decision.include_cache_fields,
        )
    });

    (StatusCode::OK, Json(response_body)).into_response()
}

/// 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
///
/// - Opus 4.6/4.7/4.8：覆写为 adaptive 类型
/// - 其他模型：覆写为 enabled 类型
/// - budget_tokens 固定为 20000
fn override_thinking_from_model_name(
    payload: &mut MessagesRequest,
    registry: &crate::model::registry::ModelRegistry,
) {
    let model_lower = payload.model.to_lowercase();
    if !model_lower.contains("thinking") {
        return;
    }

    // 使用 registry 的 thinking_override 方法
    if let Some(thinking) = registry.thinking_override(&payload.model) {
        tracing::info!(
            model = %payload.model,
            thinking_type = %thinking.thinking_type,
            "模型名包含 thinking 后缀，覆写 thinking 配置"
        );

        payload.thinking = Some(Thinking {
            thinking_type: thinking.thinking_type,
            budget_tokens: thinking.budget_tokens,
        });

        // 客户端显式 output_config 优先于配置默认值，与 converter 的 effort 取值链
        // （客户端 ?? 配置 thinking_effort ?? "high"）语义一致。Claude Code 的 /effort、
        // --effort、CLAUDE_CODE_EFFORT_LEVEL 都落在这个字段上，覆盖它等于丢弃用户意图。
        if let (None, Some(effort_str)) = (&payload.output_config, thinking.effort) {
            payload.output_config = Some(OutputConfig { effort: effort_str });
        }
    }
}

/// POST /v1/messages/count_tokens
///
/// 计算消息的 token 数量
pub async fn count_tokens(
    JsonExtractor(mut payload): JsonExtractor<CountTokensRequest>,
) -> impl IntoResponse {
    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );
    let stripped_headers = payload.strip_anthropic_billing_headers();
    if stripped_headers > 0 {
        tracing::debug!(
            count = stripped_headers,
            "已剥离 Claude Code x-anthropic-billing-header 系统块"
        );
    }

    let total_tokens = token::count_all_tokens(
        payload.model,
        payload.system,
        payload.messages,
        payload.tools,
    ) as i32;

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1),
    })
}

/// POST /cc/v1/messages
///
/// Claude Code 兼容端点，与 /v1/messages 的区别在于：
/// - 流式响应会等待 kiro 端返回 contextUsageEvent 后再发送 message_start
/// - message_start 中的 input_tokens 是从 contextUsageEvent 计算的准确值
pub async fn post_messages_cc(
    State(state): State<AppState>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /cc/v1/messages request"
    );

    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload, &state.model_registry);
    let stripped_headers = payload.strip_anthropic_billing_headers();
    if stripped_headers > 0 {
        tracing::debug!(
            count = stripped_headers,
            "已剥离 Claude Code x-anthropic-billing-header 系统块"
        );
    }

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        let cache_profile = build_prompt_cache_profile(&state, &payload, input_tokens);
        return websearch::handle_websearch_request(
            provider,
            &payload,
            input_tokens,
            state.prompt_cache_mode,
            state.prompt_cache.clone(),
            cache_profile,
            &state.model_registry,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request(&payload, &state.model_registry) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!(error = %e, "请求转换失败");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 先取出 tool_name_map 和 stable_conversation_id（后续透传给流式/非流式处理器），再构建并序列化请求体
    let tool_name_map = conversion_result.tool_name_map;
    let stable_conversation_id = conversion_result.stable_conversation_id;

    if let Some(ref cid) = stable_conversation_id {
        tracing::Span::current().record("conversation_id", tracing::field::display(cid));
    }

    // 构建 Kiro 请求体（profile_arn 由 provider 层注入）
    let request_body = match finalize_request_body(
        conversion_result.conversation_state,
        conversion_result.inference_config,
        conversion_result.additional_model_request_fields,
    ) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "序列化请求失败");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!(target: "kiro_rs::payload", body = %truncate_for_log(&request_body, LOG_PAYLOAD_LIMIT), "Kiro request body");

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;
    let cache_profile = build_prompt_cache_profile(&state, &payload, input_tokens);

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    if payload.stream {
        match state.cc_streaming_mode {
            CcStreamingMode::Buffered => {
                handle_stream_request_buffered(
                    provider,
                    &request_body,
                    &payload.model,
                    input_tokens,
                    thinking_enabled,
                    tool_name_map,
                    state.prompt_cache_mode,
                    state.prompt_cache.clone(),
                    cache_profile,
                    stable_conversation_id,
                    &state.model_registry,
                )
                .await
            }
            CcStreamingMode::Prefix => {
                handle_stream_request_prefix_buffered(
                    provider,
                    &request_body,
                    &payload.model,
                    input_tokens,
                    thinking_enabled,
                    tool_name_map,
                    state.prompt_cache_mode,
                    state.prompt_cache.clone(),
                    cache_profile,
                    stable_conversation_id,
                    &state.model_registry,
                )
                .await
            }
            CcStreamingMode::Streaming => {
                handle_stream_request(
                    provider,
                    &request_body,
                    &payload.model,
                    input_tokens,
                    thinking_enabled,
                    tool_name_map,
                    state.prompt_cache_mode,
                    state.prompt_cache.clone(),
                    cache_profile,
                    stable_conversation_id,
                    &state.model_registry,
                )
                .await
            }
        }
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            extract_thinking,
            tool_name_map,
            state.prompt_cache_mode,
            state.prompt_cache.clone(),
            cache_profile,
            stable_conversation_id,
            &state.model_registry,
        )
        .await
    }
}

/// 处理流式请求（前缀缓冲版本）
#[allow(clippy::too_many_arguments)]
async fn handle_stream_request_prefix_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    estimated_input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    prompt_cache_mode: PromptCacheMode,
    prompt_cache: Arc<PromptCacheTracker>,
    prompt_cache_profile: Option<PromptCacheProfile>,
    stable_conversation_id: Option<String>,
    model_registry: &Arc<ModelRegistry>,
) -> Response {
    let api_response = match provider.call_api_stream_with_context(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };
    let response = api_response.response;
    // PR-0：session_id_extracted 是 account_key 分支判断的副产物，
    // 提前读一次 is_some()（借用，不消费 stable_conversation_id），供下方 request outcome 日志用。
    let session_id_extracted = stable_conversation_id.is_some();
    // conv: / cred: 前缀隔离两类实体命名空间，防止客户端 session_id 恰好等于 credential_id 时串缓存。
    // Some(id) = 客户端传了稳定 session_id，按会话分桶，跨凭据 fallback 不丢缓存；
    // None = 无稳定 ID，退回 credential_id 分桶（不比现状差）。
    let account_key = match stable_conversation_id {
        Some(ref id) => format!("conv:{}", id),
        None => format!("cred:{}", api_response.credential_id),
    };
    // PR-0 返工（redteam 采纳建议 1）：cache_bucket_kind 从上面已构造好的 account_key
    // 取前缀，而不是重新判断一次 session_id_extracted 分支，避免两处判断脱节。
    let cache_bucket_kind = cache_bucket_kind_from_account_key(&account_key);
    let min_cacheable_tokens = model_registry.min_cacheable_tokens(model);
    let context_window = model_registry.context_window(model);
    let fallback_cache_usage = prompt_cache.compute(
        &account_key,
        prompt_cache_profile.as_ref(),
        min_cacheable_tokens,
    );

    let ctx = PrefixBufferedStreamContext::new(
        model,
        context_window,
        estimated_input_tokens,
        thinking_enabled,
        tool_name_map,
        min_cacheable_tokens,
    )
    .with_prompt_cache(
        prompt_cache_mode,
        Some(prompt_cache),
        Some(account_key),
        prompt_cache_profile,
        fallback_cache_usage,
    )
    .with_observability(
        api_response.credential_id,
        api_response.sticky_hit,
        session_id_extracted,
        cache_bucket_kind,
    );

    // 在 handler 仍处于 req span 上下文中时捕获当前 span。
    let span = tracing::Span::current();

    let stream = create_prefix_buffered_sse_stream(response, ctx, span);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

const PREFIX_BUFFER_TIMEOUT_SECS: u64 = 2;

fn create_prefix_buffered_sse_stream(
    response: reqwest::Response,
    ctx: PrefixBufferedStreamContext,
    span: tracing::Span,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();
    // #83：同 create_sse_stream，入口即上游响应头已收到的时刻。
    let stream_start = Instant::now();

    stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            create_ping_interval(),
            Box::pin(tokio::time::sleep(Duration::from_secs(PREFIX_BUFFER_TIMEOUT_SECS))),
        ),
        move |(
            mut body_stream,
            mut ctx,
            mut decoder,
            finished,
            mut ping_interval,
            mut prefix_timeout,
        )| {
            async move {
                if finished {
                    return None;
                }

                tokio::select! {
                    _ = &mut prefix_timeout, if !ctx.is_released() => {
                        let events = ctx.release_due_to_timeout();
                        let bytes: Vec<Result<Bytes, Infallible>> = events
                            .into_iter()
                            .map(|e| Ok(Bytes::from(e.to_sse_string())))
                            .collect();
                        Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, prefix_timeout)))
                    }
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
                                if let Err(e) = decoder.feed(&chunk) {
                                    tracing::warn!(error = %e, "缓冲区溢出");
                                }

                                let mut events = Vec::new();
                                for result in decoder.decode_iter() {
                                    match result {
                                        Ok(frame) => {
                                            if let Ok(event) = Event::from_frame(frame) {
                                                events.extend(ctx.process_event(&event));
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "解码事件失败");
                                        }
                                    }
                                }

                                let bytes: Vec<Result<Bytes, Infallible>> = events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();

                                Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, prefix_timeout)))
                            }
                            Some(Err(e)) => {
                                // #64：上游中途断连——发 error 帧让客户端感知失败并重试，
                                // 绝不走正常收尾（不调 ctx.finish()），避免把失败伪装成正常完成。
                                // #83：同 create_sse_stream，用 classify_stream_failure 区分成因。
                                let transient = crate::http_client::is_transient(&e);
                                let elapsed = stream_start.elapsed();
                                let failure = super::stream::classify_stream_failure(
                                    transient,
                                    ctx.is_empty_response(),
                                    elapsed,
                                );
                                tracing::error!(
                                    error = %crate::http_client::describe_reqwest_error(&e),
                                    failure_mode = failure_mode_label(&failure),
                                    elapsed_secs = elapsed.as_secs(),
                                    "读取响应流失败"
                                );
                                {
                                    let (credential_id, sticky_hit, session_id_extracted, cache_bucket_kind) =
                                        ctx.observability();
                                    log_request_outcome(
                                        if transient { "overloaded_error" } else { "api_error" },
                                        credential_id,
                                        sticky_hit,
                                        session_id_extracted,
                                        cache_bucket_kind,
                                    );
                                }
                                let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(Bytes::from(
                                    super::stream::error_sse_event(failure).to_sse_string(),
                                ))];
                                Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, prefix_timeout)))
                            }
                            None => {
                                // #64：本轮零产出（上游 200 空响应）时发 error 帧诱导重试，
                                // 否则正常收尾（有内容分支逐字保留 ctx.finish()）。
                                // C3 修正（前缀缓冲 None 分支丢 buffer）：is_empty_response 已在
                                // #64 修正中排除「有显式 stop_reason」——上游发 max_tokens /
                                // model_context_window_exceeded 后无内容结束时不再误判空，走
                                // ctx.finish() 正常 flush（释放缓冲的 message_start + 收尾帧透传该
                                // stop_reason）。真空响应（无内容无 stop_reason）才走 error 帧：此时
                                // 缓冲区未 released，除占位 message_start 外无内容，直接发 error 帧不会
                                // 遗漏已产出内容（未 flush 的 message_start 随 ctx drop 丢弃，无残留）。
                                // #83：干净结束零产出改用 EmptyResponse 变体，与非流式路径对齐措辞。
                                let final_events = if ctx.is_empty_response() {
                                    tracing::error!("上游响应为空（无内容），返回 error 事件以触发客户端重试");
                                    let (credential_id, sticky_hit, session_id_extracted, cache_bucket_kind) =
                                        ctx.observability();
                                    log_request_outcome(
                                        "overloaded_error",
                                        credential_id,
                                        sticky_hit,
                                        session_id_extracted,
                                        cache_bucket_kind,
                                    );
                                    vec![super::stream::error_sse_event(super::stream::StreamFailure::EmptyResponse)]
                                } else {
                                    let (credential_id, sticky_hit, session_id_extracted, cache_bucket_kind) =
                                        ctx.observability();
                                    log_request_outcome(
                                        "success",
                                        credential_id,
                                        sticky_hit,
                                        session_id_extracted,
                                        cache_bucket_kind,
                                    );
                                    ctx.finish()
                                };
                                let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, prefix_timeout)))
                            }
                        }
                    }
                    _ = ping_interval.tick() => {
                        tracing::trace!("发送 ping 保活事件（前缀缓冲模式）");
                        let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                        Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, prefix_timeout)))
                    }
                }
            }
            .instrument(span.clone())
        },
    )
    .flatten()
}

/// 处理流式请求（缓冲版本）
///
/// 与 `handle_stream_request` 不同，此函数会缓冲所有事件直到流结束，
/// 然后用从 contextUsageEvent 计算的正确 input_tokens 生成 message_start 事件。
#[allow(clippy::too_many_arguments)]
async fn handle_stream_request_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    estimated_input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    prompt_cache_mode: PromptCacheMode,
    prompt_cache: Arc<PromptCacheTracker>,
    prompt_cache_profile: Option<PromptCacheProfile>,
    stable_conversation_id: Option<String>,
    model_registry: &Arc<ModelRegistry>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let api_response = match provider.call_api_stream_with_context(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };
    let response = api_response.response;
    // PR-0：session_id_extracted 是 account_key 分支判断的副产物，
    // 提前读一次 is_some()（借用，不消费 stable_conversation_id），供下方 request outcome 日志用。
    let session_id_extracted = stable_conversation_id.is_some();
    // conv: / cred: 前缀隔离两类实体命名空间，防止客户端 session_id 恰好等于 credential_id 时串缓存。
    // Some(id) = 客户端传了稳定 session_id，按会话分桶，跨凭据 fallback 不丢缓存；
    // None = 无稳定 ID，退回 credential_id 分桶（不比现状差）。
    let account_key = match stable_conversation_id {
        Some(ref id) => format!("conv:{}", id),
        None => format!("cred:{}", api_response.credential_id),
    };
    // PR-0 返工（redteam 采纳建议 1）：cache_bucket_kind 从上面已构造好的 account_key
    // 取前缀，而不是重新判断一次 session_id_extracted 分支，避免两处判断脱节。
    let cache_bucket_kind = cache_bucket_kind_from_account_key(&account_key);
    let min_cacheable_tokens = model_registry.min_cacheable_tokens(model);
    let context_window = model_registry.context_window(model);
    let fallback_cache_usage = prompt_cache.compute(
        &account_key,
        prompt_cache_profile.as_ref(),
        min_cacheable_tokens,
    );

    // 创建缓冲流处理上下文
    let ctx = BufferedStreamContext::new(
        model,
        context_window,
        estimated_input_tokens,
        thinking_enabled,
        tool_name_map,
        min_cacheable_tokens,
    )
    .with_prompt_cache(
        prompt_cache_mode,
        Some(prompt_cache),
        Some(account_key),
        prompt_cache_profile,
        fallback_cache_usage,
    )
    .with_observability(
        api_response.credential_id,
        api_response.sticky_hit,
        session_id_extracted,
        cache_bucket_kind,
    );

    // 在 handler 仍处于 req span 上下文中时捕获当前 span。
    let span = tracing::Span::current();

    // 创建缓冲 SSE 流
    let stream = create_buffered_sse_stream(response, ctx, span);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 创建缓冲 SSE 事件流
///
/// 工作流程：
/// 1. 等待上游流完成，期间不发送数据，避免 message_start 前出现事件
/// 2. 使用 StreamContext 的事件处理逻辑处理所有 Kiro 事件，结果缓存
/// 3. 流结束后，用正确的 input_tokens 更正 message_start 事件
/// 4. 一次性发送所有事件
fn create_buffered_sse_stream(
    response: reqwest::Response,
    ctx: BufferedStreamContext,
    span: tracing::Span,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();
    // #83：同 create_sse_stream，入口即上游响应头已收到的时刻。
    let stream_start = Instant::now();

    stream::unfold(
        (body_stream, ctx, EventStreamDecoder::new(), false),
        move |(mut body_stream, mut ctx, mut decoder, finished)| {
            async move {
                if finished {
                    return None;
                }

                loop {
                    match body_stream.next().await {
                        Some(Ok(chunk)) => {
                            // 解码事件
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!(error = %e, "缓冲区溢出");
                            }

                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            // 缓冲事件（复用 StreamContext 的处理逻辑）
                                            ctx.process_and_buffer(&event);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "解码事件失败");
                                    }
                                }
                            }
                            // 继续读取下一个 chunk，不发送任何数据
                        }
                        Some(Err(e)) => {
                            // #64：上游中途断连——发 error 帧让客户端感知失败并重试，
                            // 绝不走正常收尾（不调 finish_and_get_all_events），避免把失败伪装成正常完成。
                            // 缓冲模式本就未 flush 过任何事件（Some(Ok) 只往 buffer 追加不 emit），
                            // 故断连时只发干净 error 帧、丢弃未 flush 的缓冲——是「要么全成功要么全失败」
                            // 的自洽语义；若改成「先 flush 收尾（含 message_stop）再追加 error」，会发出
                            // message_stop 后又 error 的自相矛盾序列（先告知成功再告知失败），反而更糟。
                            // #83：同 create_sse_stream，用 classify_stream_failure 区分成因。
                            let transient = crate::http_client::is_transient(&e);
                            let elapsed = stream_start.elapsed();
                            let failure = super::stream::classify_stream_failure(
                                transient,
                                ctx.is_empty_response(),
                                elapsed,
                            );
                            tracing::error!(
                                error = %crate::http_client::describe_reqwest_error(&e),
                                failure_mode = failure_mode_label(&failure),
                                elapsed_secs = elapsed.as_secs(),
                                "读取响应流失败"
                            );
                            {
                                let (
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                ) = ctx.observability();
                                log_request_outcome(
                                    if transient {
                                        "overloaded_error"
                                    } else {
                                        "api_error"
                                    },
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                );
                            }
                            let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(Bytes::from(
                                super::stream::error_sse_event(failure).to_sse_string(),
                            ))];
                            return Some((stream::iter(bytes), (body_stream, ctx, decoder, true)));
                        }
                        None => {
                            // 流结束。#64：本轮零产出（上游 200 空响应）时发 error 帧诱导重试，
                            // 否则正常收尾（有内容分支逐字保留 finish_and_get_all_events）。
                            // #83：干净结束零产出改用 EmptyResponse 变体，与非流式路径对齐措辞。
                            let all_events = if ctx.is_empty_response() {
                                tracing::error!(
                                    "上游响应为空（无内容），返回 error 事件以触发客户端重试"
                                );
                                let (
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                ) = ctx.observability();
                                log_request_outcome(
                                    "overloaded_error",
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                );
                                vec![super::stream::error_sse_event(
                                    super::stream::StreamFailure::EmptyResponse,
                                )]
                            } else {
                                let (
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                ) = ctx.observability();
                                log_request_outcome(
                                    "success",
                                    credential_id,
                                    sticky_hit,
                                    session_id_extracted,
                                    cache_bucket_kind,
                                );
                                ctx.finish_and_get_all_events()
                            };
                            let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            return Some((stream::iter(bytes), (body_stream, ctx, decoder, true)));
                        }
                    }
                }
            }
            .instrument(span.clone())
        },
    )
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_for_model(model: &str) -> MessagesRequest {
        MessagesRequest {
            model: model.to_string(),
            max_tokens: 1024,
            messages: vec![super::super::types::Message {
                role: "user".to_string(),
                content: serde_json::json!("hello"),
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        }
    }

    #[test]
    fn test_available_models_includes_opus_4_7() {
        let registry = crate::model::registry::ModelRegistry::default();
        let models = registry.available_models();
        assert!(models.iter().any(|m| m.id == "claude-opus-4-7"));
        assert!(models.iter().any(|m| m.id == "claude-opus-4-7-thinking"));
    }

    #[test]
    fn test_available_models_includes_opus_4_8() {
        let registry = crate::model::registry::ModelRegistry::default();
        let models = registry.available_models();
        assert!(models.iter().any(|m| m.id == "claude-opus-4-8"));
        assert!(models.iter().any(|m| m.id == "claude-opus-4-8-thinking"));
    }

    #[test]
    fn test_override_thinking_opus_4_8_uses_adaptive() {
        let mut payload = request_for_model("claude-opus-4-8-thinking");

        override_thinking_from_model_name(
            &mut payload,
            &crate::model::registry::ModelRegistry::default(),
        );

        let thinking = payload.thinking.unwrap();
        assert_eq!(thinking.thinking_type, "adaptive");
        assert_eq!(thinking.budget_tokens, 20000);
        assert_eq!(
            payload.output_config.as_ref().map(|c| c.effort.as_str()),
            Some("high")
        );
    }

    #[test]
    fn test_override_thinking_opus_4_7_uses_adaptive() {
        let mut payload = request_for_model("claude-opus-4-7-thinking");

        override_thinking_from_model_name(
            &mut payload,
            &crate::model::registry::ModelRegistry::default(),
        );

        let thinking = payload.thinking.unwrap();
        assert_eq!(thinking.thinking_type, "adaptive");
        assert_eq!(thinking.budget_tokens, 20000);
        assert_eq!(
            payload.output_config.as_ref().map(|c| c.effort.as_str()),
            Some("high")
        );
    }

    // === effort 透传 · 客户端优先回归测试 ===
    //
    // 回归防护：override_thinking_from_model_name 曾无条件用配置 thinking_effort
    // 覆盖 payload.output_config，丢弃客户端已显式传入的 effort 意图。现为
    // 「仅当 payload.output_config.is_none() 时才用配置值填充」。

    #[test]
    fn test_effort_client_output_config_wins_over_thinking_suffix_config() {
        // 客户端已显式传 output_config.effort=max，即便命中 "-thinking" 后缀
        // 覆写路径，最终 effort 也应保留客户端的 "max"，而不是被配置的
        // thinking_effort（"high"）覆盖。
        let mut payload = request_for_model("claude-sonnet-5-thinking");
        payload.output_config = Some(OutputConfig {
            effort: "max".to_string(),
        });

        override_thinking_from_model_name(
            &mut payload,
            &crate::model::registry::ModelRegistry::default(),
        );

        assert_eq!(
            payload.output_config.as_ref().map(|c| c.effort.as_str()),
            Some("max"),
            "客户端显式 effort 应优先于配置 thinking_effort"
        );
    }

    #[test]
    fn test_effort_thinking_suffix_falls_back_to_config_when_client_absent() {
        // 守住不回归：客户端没有传 output_config 时，仍应用配置的
        // thinking_effort 填充（这是改动 A 修复后必须保留的老行为）。
        let mut payload = request_for_model("claude-sonnet-5-thinking");
        assert!(payload.output_config.is_none());

        override_thinking_from_model_name(
            &mut payload,
            &crate::model::registry::ModelRegistry::default(),
        );

        assert_eq!(
            payload.output_config.as_ref().map(|c| c.effort.as_str()),
            Some("high"),
            "客户端未传 output_config 时应回退到配置的 thinking_effort"
        );
    }

    #[test]
    fn test_effort_client_priority_survives_full_convert_path() {
        // 端到端钉：override_thinking_from_model_name → convert_request →
        // build_additional_model_request_fields 全路径上客户端 effort 都不被吞。
        // 单测 override 函数只覆盖了第一段，这里补上真正发往上游的那个字段。
        let registry = crate::model::registry::ModelRegistry::default();
        let mut payload = request_for_model("claude-sonnet-5-thinking");
        payload.output_config = Some(OutputConfig {
            effort: "max".to_string(),
        });

        override_thinking_from_model_name(&mut payload, &registry);
        let result = convert_request(&payload, &registry).expect("convert_request 应成功");

        let structured = result
            .additional_model_request_fields
            .expect("adaptive 模型应产出结构化字段");
        assert_eq!(
            structured["output_config"]["effort"], "max",
            "客户端 effort=max 应一路透传到 additionalModelRequestFields"
        );
    }

    // --- map_provider_error tests ---

    fn response_status(r: Response) -> StatusCode {
        r.status()
    }

    fn response_has_retry_after(r: &Response) -> bool {
        r.headers().contains_key("retry-after")
    }

    fn response_retry_after_value(r: &Response) -> Option<u64> {
        r.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    async fn response_error_type(r: Response) -> String {
        use axum::body::to_bytes;
        let bytes = to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["error"]["type"].as_str().unwrap_or("").to_string()
    }

    #[tokio::test]
    async fn test_map_all_credentials_disabled_gives_503() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::AllCredentialsDisabled {
            available: 0,
            total: 2,
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_retry_after_value(&r), Some(60));
        assert_eq!(response_error_type(r).await, "overloaded_error");
    }

    #[tokio::test]
    async fn test_map_quota_exhausted_gives_429() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::AllCredentialsQuotaExhausted {
            detail: "monthly limit".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response_retry_after_value(&r), Some(60));
        assert_eq!(response_error_type(r).await, "rate_limit_error");
    }

    #[tokio::test]
    async fn test_map_token_acquisition_failed_gives_503() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::TokenAcquisitionFailed {
            available: 0,
            total: 1,
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_retry_after_value(&r), Some(60));
        assert_eq!(response_error_type(r).await, "overloaded_error");
    }

    #[tokio::test]
    async fn test_map_upstream_client_error_generic_gives_502() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamClientError {
            status: 401,
            body: "Unauthorized".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "api_error");
    }

    #[tokio::test]
    async fn test_map_upstream_client_error_content_length_gives_400() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamClientError {
            status: 400,
            body: "CONTENT_LENGTH_EXCEEDS_THRESHOLD".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "invalid_request_error");
    }

    #[tokio::test]
    async fn test_map_upstream_client_error_input_too_long_gives_400() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamClientError {
            status: 400,
            body: "Input is too long for this model".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "invalid_request_error");
    }

    #[tokio::test]
    async fn test_map_upstream_client_error_400_unknown_body_gives_400() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamClientError {
            status: 400,
            body: r#"{"message":"Mantle request failed with status 400","reason":"TOOL_SCHEMA_INVALID"}"#.to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "invalid_request_error");
    }

    #[tokio::test]
    async fn test_map_transient_exhausted_429_gives_429() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamTransientExhausted {
            last_status: 429,
            body: "rate limited".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response_retry_after_value(&r), Some(30));
        assert_eq!(response_error_type(r).await, "rate_limit_error");
    }

    #[tokio::test]
    async fn test_map_transient_exhausted_503_gives_503() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::UpstreamTransientExhausted {
            last_status: 503,
            body: "service unavailable".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_retry_after_value(&r), Some(30));
        assert_eq!(response_error_type(r).await, "overloaded_error");
    }

    #[tokio::test]
    async fn test_map_connection_failed_gives_503() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::ConnectionFailed {
            detail: "connection refused".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_retry_after_value(&r), Some(15));
        assert_eq!(response_error_type(r).await, "overloaded_error");
    }

    #[tokio::test]
    async fn test_map_internal_config_gives_500() {
        use crate::kiro::provider::ProviderError;
        let err: anyhow::Error = ProviderError::InternalConfig {
            detail: "unknown endpoint: foo".to_string(),
        }
        .into();
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "internal_error");
    }

    #[tokio::test]
    async fn test_map_plain_anyhow_fallback_gives_502() {
        let err: anyhow::Error = anyhow::anyhow!("some generic error without ProviderError");
        let r = map_provider_error(err);
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        assert!(!response_has_retry_after(&r));
        assert_eq!(response_error_type(r).await, "api_error");
    }

    // -----------------------------------------------------------------------
    // #71 Change 6 / Group B — map_provider_error 结局事件（非流式路径代表）
    //
    // 上面十二个 test_map_* 只断言 HTTP 响应体（status/retry-after/error type
    // 字段），从不检查 Change 2 新增的 `tracing::info!(req_outcome, "request
    // outcome")` 是否真的发出——这正是 Change 6 要补的缺口：响应体正确不代表
    // 日志事件被发出，两者是独立的副作用。用 span_capture::OutcomeCapturingLayer
    // （复用既有 request_id 提取逻辑，另加 req_outcome/message 字段提取）在
    // set_default 作用域内调用 map_provider_error，直接断言捕获到的事件。
    //
    // handle_non_stream_request 的三个终结点（Change 3a/3b/3c）不在此处覆盖：
    // 该函数要求 Arc<KiroProvider>，与文件下方 S3/S4 rationale 段落记录的
    // 脚手架成本论证完全相同——3a（success）、3b（空响应→503）、3c（非瞬态
    // →502）都是无分支的直线胶水代码，其判定输入（is_transient/字符串比较）
    // 已被 http_client.rs 与本文件既有测试覆盖。三条路径里 3c 之外的瞬态分支
    // 复用 map_provider_error（已被本组覆盖）；3a/3b 未被自动化测试覆盖，
    // 如实标注在回报里而非略过。
    // -----------------------------------------------------------------------

    /// 在 OutcomeCapturingLayer 下调用 map_provider_error，返回捕获到的
    /// 「带 req_outcome 字段」那一条 event（同一次调用还会发 warn!/error! 等
    /// 不带 req_outcome 的日志，用 find 定位而非假设只有一条捕获记录）。
    fn capture_outcome_event(
        f: impl FnOnce() -> Response,
    ) -> (Response, Option<span_capture::CapturedOutcome>) {
        use span_capture::{CapturedOutcomes, OutcomeCapturingLayer};
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedOutcomes::default();
        let layer = OutcomeCapturingLayer(captured.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = f();

        let outcome_event = captured
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.req_outcome.is_some())
            .cloned();
        (response, outcome_event)
    }

    /// BDD：ProviderError::ConnectionFailed 走 map_provider_error 时，
    /// req_outcome 必须与响应体的 error type（"overloaded_error"）一致——
    /// 证明 Change 2 在这条分支真的发出了结局事件，而非只是改对了响应体。
    #[test]
    fn test_map_provider_error_outcome_matches_error_type_for_connection_failed() {
        use crate::kiro::provider::ProviderError;

        let (response, outcome) = capture_outcome_event(|| {
            let err: anyhow::Error = ProviderError::ConnectionFailed {
                detail: "connection refused".to_string(),
            }
            .into();
            map_provider_error(err)
        });

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let outcome = outcome.expect(
            "map_provider_error 必须发出带 req_outcome 字段的 tracing::info! 事件（Change 2）",
        );
        assert_eq!(
            outcome.req_outcome.as_deref(),
            Some("overloaded_error"),
            "req_outcome 必须与 error_type 一致，实际：{:?}",
            outcome.req_outcome
        );
        assert_eq!(outcome.message.as_deref(), Some("request outcome"));
    }

    /// BDD：未分类的 plain anyhow 错误走 fallback 分支时，
    /// req_outcome 必须硬编码为 "api_error"（Change 2 else 分支）。
    #[test]
    fn test_map_provider_error_fallback_outcome_is_api_error() {
        let (response, outcome) = capture_outcome_event(|| {
            let err: anyhow::Error = anyhow::anyhow!("some generic error without ProviderError");
            map_provider_error(err)
        });

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let outcome = outcome.expect(
            "map_provider_error fallback 分支必须发出带 req_outcome 字段的事件（Change 2）",
        );
        assert_eq!(outcome.req_outcome.as_deref(), Some("api_error"));
    }

    /// BDD：map_provider_error 本身不建 span，结局事件的 request_id 完全依赖
    /// 调用处的 ambient span（生产环境里就是 request_id_middleware 建立、
    /// .instrument(span.clone()) 覆盖整个 next.run() 的那个 req span）。
    /// 用 span.enter() 模拟"调用处已在 req span 内"，证明 request_id 能
    /// 正确向上找到——若调用处不在任何 span 内（如误从 spawn 出去的裸 task
    /// 调用），request_id 会是 None，这不是 bug 而是 tracing scope 的固有语义，
    /// 此测试确认的是「在 span 内调用时能拿到」这一正向路径。
    #[test]
    fn test_map_provider_error_outcome_inherits_ambient_request_id() {
        use crate::kiro::provider::ProviderError;

        // span 必须在 capture_outcome_event 的 subscriber 上下文内创建：若在外层
        // （测试无全局 subscriber = noop）建 span，该 span 无真实 span data，进到
        // capture 的 registry 里 enter 时 event_scope 找不到 request_id → None。
        // 生产环境无此问题（middleware 建 span 时全局 subscriber 已就位），这纯是
        // 测试脚手架的 subscriber 时序要求。
        let (_response, outcome) = capture_outcome_event(|| {
            let span = tracing::info_span!("req", request_id = "test_req_map_err");
            let _guard = span.enter();
            let err: anyhow::Error = ProviderError::InternalConfig {
                detail: "unknown endpoint: foo".to_string(),
            }
            .into();
            map_provider_error(err)
        });

        let outcome = outcome.expect("必须捕获到带 req_outcome 的事件");
        assert_eq!(
            outcome.request_id.as_deref(),
            Some("test_req_map_err"),
            "req_outcome 事件必须继承调用处 ambient span 的 request_id，实际：{:?}",
            outcome.request_id
        );
    }

    // --- truncate_for_log tests ---

    #[test]
    fn test_truncate_ascii_short_returns_borrowed() {
        let s = "hello world";
        let result = truncate_for_log(s, 100);
        // Short string: must return Borrowed (no allocation)
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), s);
    }

    #[test]
    fn test_truncate_ascii_exact_limit_returns_borrowed() {
        let s = "hello";
        let result = truncate_for_log(s, 5);
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), s);
    }

    #[test]
    fn test_truncate_ascii_exceeds_limit() {
        let s = "hello world!";
        let result = truncate_for_log(s, 5);
        let r = result.as_ref();
        assert!(r.starts_with("hello"));
        assert!(r.contains("<truncated"));
        // Result must be valid UTF-8 (conversion to String must not panic)
        let _ = r.to_string();
        // Truncated portion must have correct byte count annotated
        assert!(r.contains(&format!("{} bytes>", s.len() - 5)));
    }

    #[test]
    fn test_truncate_multibyte_no_panic_chinese() {
        // "你好世界" = 4 Chinese chars × 3 bytes each = 12 bytes total
        // limit=4 falls in the middle of the second char (bytes 3..6)
        let s = "你好世界";
        assert_eq!(s.len(), 12);
        let result = truncate_for_log(s, 4);
        // Must not panic, result must be valid UTF-8
        let r = result.as_ref();
        let _ = r.to_string();
        // The kept prefix must be valid UTF-8 — boundary was rounded back to char boundary ≤4
        // "你" = bytes 0..3, so boundary should snap back to 3
        assert!(r.starts_with("你"));
        assert!(r.contains("<truncated"));
    }

    #[test]
    fn test_truncate_multibyte_no_panic_emoji() {
        // "😀" = 4 bytes; limit=2 falls inside the emoji
        let s = "😀 hi";
        let result = truncate_for_log(s, 2);
        let r = result.as_ref();
        // Must not panic; result is valid UTF-8
        let _ = r.to_string();
        assert!(r.contains("<truncated"));
    }

    #[test]
    fn test_truncate_limit_zero() {
        let s = "hello";
        let result = truncate_for_log(s, 0);
        let r = result.as_ref();
        let _ = r.to_string();
        // Nothing kept before truncation marker
        assert!(r.contains("<truncated"));
    }

    #[test]
    fn test_truncate_limit_equals_len() {
        let s = "hello";
        let result = truncate_for_log(s, s.len());
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), s);
    }

    #[test]
    fn test_truncate_limit_len_minus_one() {
        let s = "hello";
        let result = truncate_for_log(s, s.len() - 1);
        let r = result.as_ref();
        let _ = r.to_string();
        assert!(r.contains("<truncated"));
        assert!(r.contains("1 bytes>"));
    }

    // -----------------------------------------------------------------------
    // Task 3 — BDD: stream 内 event 能关联到 req span 的 request_id 字段
    //
    // FALLBACK 说明：首选端到端形态需要构造 reqwest::Response，但 reqwest 0.12
    // 的 Response 类型无公开构造器（不暴露 From<http::Response<...>>），
    // 无法在测试中伪造上游 HTTP 响应而不引入新依赖。
    // 因此退为 fallback：用 stream::unfold + .instrument(span.clone()) 直接
    // 验证"对 unfold 闭包返回的 async block 挂 instrument 后，跨 poll 仍保留
    // span 字段"这一被依赖前提——此模式与 handlers.rs Task 1 fix 完全一致。
    // 端到端接线由 Task 1 代码 + 编译类型保证。
    // -----------------------------------------------------------------------

    /// 自定义 Layer：将每个新 span 的 request_id 存入 extensions，
    /// 每条 event 发出时向上遍历 scope 取出 request_id 记录到共享 Vec。
    mod span_capture {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::Context;
        use tracing_subscriber::registry::LookupSpan;

        /// 类型化包装，存入 span extensions TypeMap
        pub struct RequestIdExt(pub String);

        /// Visitor：从 span Attributes 里提取 request_id 字段值
        pub struct RequestIdVisitor(pub Option<String>);

        impl tracing::field::Visit for RequestIdVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "request_id" {
                    self.0 = Some(value.to_string());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "request_id" {
                    self.0 = Some(format!("{:?}", value));
                }
            }
        }

        /// 共享捕获容器（None 代表该 event 没有携带 request_id）
        #[derive(Default, Clone)]
        pub struct CapturedIds(pub Arc<Mutex<Vec<Option<String>>>>);

        /// 自定义 Layer 实现
        pub struct CapturingLayer(pub CapturedIds);

        impl<S> Layer<S> for CapturingLayer
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            /// 新 span 创建时，把 request_id 字段值写进 extensions
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                id: &tracing::span::Id,
                ctx: Context<'_, S>,
            ) {
                if let Some(span) = ctx.span(id) {
                    let mut visitor = RequestIdVisitor(None);
                    attrs.record(&mut visitor);
                    if let Some(rid) = visitor.0 {
                        span.extensions_mut().insert(RequestIdExt(rid));
                    }
                }
            }

            /// event 发出时，沿 scope 向上找最近含 RequestIdExt 的 span
            fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
                let request_id = ctx.event_scope(event).and_then(|mut scope| {
                    scope.find_map(|span_ref| {
                        span_ref
                            .extensions()
                            .get::<RequestIdExt>()
                            .map(|r| r.0.clone())
                    })
                });
                self.0.0.lock().unwrap().push(request_id);
            }
        }

        /// Visitor：从 event 字段中提取 req_outcome 与 message（Task Change 6
        /// 结局事件断言用——CapturingLayer/RequestIdVisitor 只认 request_id，
        /// 结局事件断言还需要读 req_outcome 本身的值，故加一个专用 visitor
        /// 而非改写既有 CapturedIds 类型影响 test_stream_events_carry_req_span_request_id）。
        pub struct OutcomeVisitor {
            pub req_outcome: Option<String>,
            pub message: Option<String>,
        }

        impl tracing::field::Visit for OutcomeVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "req_outcome" => self.req_outcome = Some(value.to_string()),
                    "message" => self.message = Some(value.to_string()),
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                match field.name() {
                    "req_outcome" => self.req_outcome = Some(format!("{:?}", value)),
                    "message" => self.message = Some(format!("{:?}", value)),
                    _ => {}
                }
            }
        }

        /// 一条捕获到的 event：request_id 走既有 scope-walk 逻辑，
        /// req_outcome/message 直接从 event 自身字段提取。
        #[derive(Debug, Clone)]
        pub struct CapturedOutcome {
            pub request_id: Option<String>,
            pub req_outcome: Option<String>,
            pub message: Option<String>,
        }

        #[derive(Default, Clone)]
        pub struct CapturedOutcomes(pub Arc<Mutex<Vec<CapturedOutcome>>>);

        /// 结局事件专用 Layer：request_id 提取逻辑与 CapturingLayer 完全一致
        /// （小段重复而非放宽 CapturingLayer 的字段可见性去共享——两个 Layer
        /// 各自职责单一，改成通用容器反而让两处既有测试都要跟着改类型）。
        pub struct OutcomeCapturingLayer(pub CapturedOutcomes);

        impl<S> Layer<S> for OutcomeCapturingLayer
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                id: &tracing::span::Id,
                ctx: Context<'_, S>,
            ) {
                if let Some(span) = ctx.span(id) {
                    let mut visitor = RequestIdVisitor(None);
                    attrs.record(&mut visitor);
                    if let Some(rid) = visitor.0 {
                        span.extensions_mut().insert(RequestIdExt(rid));
                    }
                }
            }

            fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
                let request_id = ctx.event_scope(event).and_then(|mut scope| {
                    scope.find_map(|span_ref| {
                        span_ref
                            .extensions()
                            .get::<RequestIdExt>()
                            .map(|r| r.0.clone())
                    })
                });
                let mut visitor = OutcomeVisitor {
                    req_outcome: None,
                    message: None,
                };
                event.record(&mut visitor);
                self.0.0.lock().unwrap().push(CapturedOutcome {
                    request_id,
                    req_outcome: visitor.req_outcome,
                    message: visitor.message,
                });
            }
        }
    }

    /// BDD: 对 stream::unfold 闭包返回的 async block 挂 .instrument(span) 后，
    /// 即使 stream 在 span 上下文之外被 poll，内部 tracing event 仍携带 request_id。
    ///
    /// 验证修复前语义：若不挂 .instrument()，ids 全为 None，断言失败。
    /// 修复后：ids 全为 Some("test_req_abc")，断言通过。
    #[test]
    fn test_stream_events_carry_req_span_request_id() {
        use self::span_capture::{CapturedIds, CapturingLayer};
        use tracing::Instrument;
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedIds::default();
        let layer = CapturingLayer(captured.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // 模拟 handler 内部：建立 req span 并 enter，在 span 上下文里用
            // Span::current() 捕获——与 create_*_sse_stream 调用点完全同构。
            let span = tracing::info_span!("req", request_id = "test_req_abc");
            let captured_span = {
                let _guard = span.enter();
                // 在 enter 的 span 内取 current()，复刻生产代码 let span = Span::current();
                tracing::Span::current()
            };
            // 此处 _guard 已 drop，span 不再 active——模拟 handler 返回后 req span 退出。

            // 构造 stream::unfold，每个 async block 单独 instrument——
            // 与 Task 1 修复后 create_*_sse_stream 内的模式完全相同。
            let test_stream = futures::stream::unfold(0u32, move |count| {
                let s = captured_span.clone();
                async move {
                    if count >= 3 {
                        return None;
                    }
                    // 这条 event 必须携带 request_id，断言依赖此行为
                    tracing::debug!(iteration = count, "stream poll event");
                    Some((count, count + 1))
                }
                .instrument(s)
            });

            // 在 span 之外 poll stream，模拟 hyper poll body 时 req span 已 drop 的场景。
            // futures::executor::block_on 在当前线程同步执行，保持 with_default subscriber。
            futures::executor::block_on(async move {
                use futures::StreamExt;
                let mut s = Box::pin(test_stream);
                while s.next().await.is_some() {}
            });
        });

        let ids = captured.0.lock().unwrap();
        assert!(
            !ids.is_empty(),
            "stream 未发出任何 tracing event，检查 unfold 闭包是否执行"
        );
        // 核心断言：每条 event 都必须携带正确的 request_id
        // 若 .instrument() 未挂（修复前），ids 全为 None，此断言失败
        assert!(
            ids.iter().all(|id| id.as_deref() == Some("test_req_abc")),
            "部分 stream event 未携带 request_id — .instrument(span) 未生效: {:?}",
            &*ids
        );
    }

    /// BDD（#71）：请求结局事件必须携带正确的 `req_outcome` 字段值，且靠 span
    /// 继承带上 request_id。这是痛点 1+4 的核心断言——运维按 conversation_id
    /// grep `request outcome` 事件聚合成功/失败分布，字段值错则整个视图失真。
    ///
    /// 覆盖流内部发射场景：event 在 span 之外被 poll 的 unfold 闭包里发出，
    /// 仍须继承 request_id（与 test_stream_events_carry_req_span_request_id 同构，
    /// 但额外断言 req_outcome 的具体取值，用 OutcomeCapturingLayer）。
    #[test]
    fn test_outcome_event_carries_req_outcome_and_request_id() {
        use self::span_capture::{CapturedOutcomes, OutcomeCapturingLayer};
        use tracing::Instrument;
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedOutcomes::default();
        let layer = OutcomeCapturingLayer(captured.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("req", request_id = "test_req_xyz");
            let captured_span = {
                let _guard = span.enter();
                tracing::Span::current()
            };
            // span 已退出——模拟流式 handler 返回后 req span 已 drop 的场景
            let outcomes = ["success", "overloaded_error", "rate_limit_error"];
            let test_stream = futures::stream::unfold(0usize, move |i| {
                let s = captured_span.clone();
                async move {
                    if i >= outcomes.len() {
                        return None;
                    }
                    // 复刻生产发射点，统一以字符串字段记录（不加 %，与所有生产
                    // 发射点一致——% 走 Display→record_debug 会造成字段格式不一致）
                    tracing::info!(req_outcome = outcomes[i], "request outcome");
                    Some((i, i + 1))
                }
                .instrument(s)
            });
            futures::executor::block_on(async move {
                use futures::StreamExt;
                let mut s = Box::pin(test_stream);
                while s.next().await.is_some() {}
            });
        });

        let events = captured.0.lock().unwrap();
        // 只看结局事件（message == "request outcome"）
        let outcome_events: Vec<_> = events
            .iter()
            .filter(|e| e.message.as_deref() == Some("request outcome"))
            .collect();
        assert_eq!(
            outcome_events.len(),
            3,
            "应捕获 3 条结局事件，实得 {:?}",
            &*events
        );
        // 断言 1：req_outcome 取值逐条正确（视图聚合的正确性根基）
        let got: Vec<_> = outcome_events
            .iter()
            .map(|e| e.req_outcome.as_deref())
            .collect();
        assert_eq!(
            got,
            vec![
                Some("success"),
                Some("overloaded_error"),
                Some("rate_limit_error")
            ],
            "req_outcome 字段值不符"
        );
        // 断言 2：request_id 靠 span 继承带上（去掉 .instrument 则全 None 必红）
        assert!(
            outcome_events
                .iter()
                .all(|e| e.request_id.as_deref() == Some("test_req_xyz")),
            "结局事件未继承 request_id — span 传递失效: {:?}",
            &*events
        );
    }

    /// BDD（PR-0 返工，redteam 采纳建议 2）：`credential_id: Option<u64>` 为
    /// `None` 时字段必须从事件里彻底缺席，而不是以 `null` 或任何其他形式出现——
    /// 这是"用 `Option` 让未回填字段在日志里缺席，而不是伪造 `0` 当哨兵值"这一
    /// 设计选择的可运行背书，不满足黑盒实测背书就凭推断落笔的仓库纪律。
    ///
    /// 验证手段：`tracing_core::Value for Option<T>` 的行为发生在
    /// `Value::record` 这一层——`None` 时该实现直接不调用 visitor 的任何
    /// `record_*` 方法，这比"序列化成 JSON 后拿 jq 校验字段缺席"更贴近断言对象
    /// 本身（JSON 输出只是这一行为的下游表现，不是它的定义处）。用一个只认
    /// `credential_id` 字段名的 Visitor，比较"字段名是否曾被访问过"而非其值。
    #[test]
    fn test_none_credential_id_omitted_from_event_fields() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::{Context, SubscriberExt};
        use tracing_subscriber::registry::LookupSpan;

        /// 只关心 "credential_id" 这一个字段名是否被 visitor 访问过——
        /// 不关心值本身，因为本测试要证的是"访问与否"而非"访问到什么"。
        struct FieldPresenceVisitor {
            seen: Vec<&'static str>,
        }

        impl tracing::field::Visit for FieldPresenceVisitor {
            fn record_u64(&mut self, field: &tracing::field::Field, _value: u64) {
                if field.name() == "credential_id" {
                    self.seen.push("credential_id");
                }
            }
            fn record_debug(
                &mut self,
                field: &tracing::field::Field,
                _value: &dyn std::fmt::Debug,
            ) {
                if field.name() == "credential_id" {
                    self.seen.push("credential_id");
                }
            }
        }

        #[derive(Default, Clone)]
        struct PresenceFlags(Arc<Mutex<Vec<bool>>>);

        struct PresenceLayer(PresenceFlags);

        impl<S> Layer<S> for PresenceLayer
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let mut visitor = FieldPresenceVisitor { seen: Vec::new() };
                event.record(&mut visitor);
                self.0.0.lock().unwrap().push(!visitor.seen.is_empty());
            }
        }

        let flags = PresenceFlags::default();
        let layer = PresenceLayer(flags.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // 第一条：credential_id = Some(7) —— 字段必须被访问到。
            log_request_outcome("success", Some(7), Some(true), true, "conv");
            // 第二条：credential_id = None —— 字段必须彻底缺席，不调用任何
            // record_* 方法（不是"调用了但值是空"，是压根没调用）。
            log_request_outcome("api_error", None, None, false, "cred");
        });

        let flags = flags.0.lock().unwrap();
        assert_eq!(flags.len(), 2, "应捕获 2 条 request outcome 事件");
        assert!(
            flags[0],
            "credential_id = Some(7) 时字段应被 visitor 访问到，实际未访问"
        );
        assert!(
            !flags[1],
            "credential_id = None 时字段应从事件中彻底缺席，实际仍被 visitor 访问到"
        );
    }

    // -----------------------------------------------------------------------
    // #64 BDD S1/S1b/S2 — create_sse_stream 端到端收尾语义
    //
    // 直接调用私有 fn create_sse_stream(response, ctx, initial_events, span)，
    // response 用 http_client.rs 已有的裸 TCP mock 上游 + 一个不设超时的普通
    // reqwest::Client 构造（无需 KiroProvider，create_sse_stream 只消费
    // reqwest::Response 本身）。收集整条 stream 产出的字节，拼成完整 SSE 文本
    // 后做字符串级断言——比逐事件解析更贴近"客户端最终看到什么"。
    // -----------------------------------------------------------------------

    /// 启动一个「响应头已发、body 中途异常终止连接」的 mock 上游。
    ///
    /// 与 http_client.rs 里同名 helper 的行为完全一致（该文件的 `mod tests`
    /// 是私有模块，无法从这里 `crate::http_client::tests::` 访问，故复制一份
    /// 而非放宽其可见性——避免为测试互访放大生产模块的公开面）。
    ///
    /// 行为：accept 连接 → 丢弃请求头 → 发 200 响应头（chunked）→ 发一个
    /// **不完整**的 chunked 帧（chunk-size 声明 100 字节，实际只发 10 字节）
    /// → `force_rst=true` 时 `SO_LINGER(0)` 后 drop（近似 TCP RST），
    /// `force_rst=false` 时直接 drop（正常 FIN）。
    async fn spawn_mid_body_reset_upstream(force_rst: bool) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            let headers =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");

            stream
                .write_all(b"64\r\n")
                .await
                .expect("写 chunk header 失败");
            stream
                .write_all(b"partial...")
                .await
                .expect("写不完整 payload 失败");

            if force_rst {
                let _ = stream.set_linger(Some(std::time::Duration::ZERO));
            }
            drop(stream);
        });

        addr
    }

    /// 启动一个「200 但立即空 body」的 mock 上游（S2 用）。
    ///
    /// 同上，复制自 http_client.rs 的同名私有 helper。
    ///
    /// 行为：accept 连接 → 丢弃请求头 → 发 200 响应头（chunked）
    /// → 立即发终止帧 `0\r\n\r\n`（不发任何 payload chunk）→ 正常结束连接。
    async fn spawn_empty_body_200_upstream() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            let headers =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");
            stream.write_all(b"0\r\n\r\n").await.expect("写终止帧失败");
        });

        addr
    }

    /// 启动一个「只发响应头、零 body 字节、随即 TCP RST」的 mock 上游（#83）。
    ///
    /// 与 `spawn_mid_body_reset_upstream` 的区别：后者无论 `force_rst` 取值都会先写
    /// 一个不完整 chunk（chunk-size 声明 100 字节、实际写 10 字节 `"partial..."`），
    /// 不是零 body 字节场景。这里只发响应头就立即 `SO_LINGER(0)` 后 drop，拿到「零内容 +
    /// 真实 TCP RST」这个更纯净的前提，对应 classify_stream_failure 的 empty==true 输入。
    async fn spawn_header_only_rst_upstream() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            let headers =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");

            // 零 body 字节，直接 RST：SO_LINGER(0) 后 drop 近似 TCP RST。
            let _ = stream.set_linger(Some(std::time::Duration::ZERO));
            drop(stream);
        });

        addr
    }

    /// 构造一个 fresh StreamContext + 对应 initial_events，供 S1/S1b/S2 复用。
    fn fresh_ctx_with_initial_events() -> (StreamContext, Vec<SseEvent>) {
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            std::collections::HashMap::new(),
            1024,
        );
        let initial_events = ctx.generate_initial_events();
        (ctx, initial_events)
    }

    /// 收集 create_sse_stream 产出的全部字节，拼成完整 SSE 文本。
    async fn collect_sse_text(stream: impl Stream<Item = Result<Bytes, Infallible>>) -> String {
        let chunks: Vec<Bytes> = stream
            .map(|r| r.expect("Infallible 不会出错"))
            .collect()
            .await;
        chunks
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join("")
    }

    /// S1 — 流式请求中途上游断连（无先前内容）。
    ///
    /// 复用 http_client.rs 的 spawn_mid_body_reset_upstream(false)：响应头已发，
    /// body 中途以 FIN 断连（无完整 chunk 边界）。断连字节喂给 EventStreamDecoder
    /// 必然产生 decode 错误（非合法帧），但核心断言只关心 create_sse_stream 的
    /// Some(Err(e)) 分支——发 error 帧、finished=true，绝不补 message_stop/
    /// message_delta 伪装成正常完成。
    #[tokio::test]
    async fn test_s1_stream_upstream_interruption_no_prior_content_emits_error_not_stop() {
        let addr = spawn_mid_body_reset_upstream(false).await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败，而非 send 阶段）");

        let (ctx, initial_events) = fresh_ctx_with_initial_events();
        let span = tracing::Span::none();
        let stream = create_sse_stream(response, ctx, initial_events, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("event: error"),
            "S1：上游中途断连必须发 error 帧，实际 SSE 文本：{text}"
        );
        assert!(
            text.contains("overloaded_error"),
            "S1：断连是瞬态失败，error 帧应为 overloaded_error，实际：{text}"
        );
        assert!(
            !text.contains("message_stop"),
            "S1：断连后绝不能补 message_stop 伪装成正常完成，实际 SSE 文本：{text}"
        );
        assert!(
            !text.contains("message_delta"),
            "S1：断连后绝不能补 message_delta 伪装成正常完成，实际 SSE 文本：{text}"
        );
    }

    /// S1b — 流式请求中途上游断连，且断连前已有内容产出。
    ///
    /// 断连前的"已有内容"通过直接对 ctx 调用 process_kiro_event 预置
    /// （而非手工构造合法 AWS event-stream 二进制帧）：create_sse_stream 的
    /// Some(Err(e)) 分支只依赖 ctx 在中断发生时的状态（此处并不读取
    /// ctx.is_empty_response()，只是无条件发 error 帧），不依赖内容如何写入 ——
    /// 手搓字节级帧编码器对这条断言无额外背书价值，属于不必要的复杂度。
    /// mock 上游侧仍是真实 TCP 中断，断连本身是端到端的。
    #[tokio::test]
    async fn test_s1b_stream_upstream_interruption_with_prior_content_emits_error_not_stop() {
        let addr = spawn_mid_body_reset_upstream(true).await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败，而非 send 阶段）");

        let (mut ctx, mut initial_events) = fresh_ctx_with_initial_events();
        // 预置"断连前已产出内容"：直接喂一条非空 AssistantResponse 事件，
        // 复刻 stream.rs 里 assistant_response_event() 的构造方式
        // （extra 字段私有，跨模块 ..Default::default() 编译不过，故走
        // Default::default() 再赋值公开字段）。
        let mut prior = crate::kiro::model::events::AssistantResponseEvent::default();
        prior.content = "some prior text before interruption".to_string();
        let prior_events =
            ctx.process_kiro_event(&crate::kiro::model::events::Event::AssistantResponse(prior));
        assert!(
            !prior_events.is_empty(),
            "前提：预置内容应产生非空 SSE 事件（text_delta），否则下面的断言无意义"
        );
        initial_events.extend(prior_events);
        assert!(
            !ctx.is_empty_response(),
            "前提：预置内容后 ctx 不应再是空响应状态"
        );

        let span = tracing::Span::none();
        let stream = create_sse_stream(response, ctx, initial_events, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("some prior text before interruption"),
            "S1b：断连前已产出的内容必须出现在 SSE 文本中，实际：{text}"
        );
        assert!(
            text.contains("event: error"),
            "S1b：即便已有内容，中途断连仍必须发 error 帧，实际 SSE 文本：{text}"
        );
        assert!(
            text.contains("overloaded_error"),
            "S1b：断连是瞬态失败，error 帧应为 overloaded_error，实际：{text}"
        );
        assert!(
            !text.contains("message_stop"),
            "S1b：已有内容也不能豁免——断连后绝不能补 message_stop 伪装成正常完成，实际 SSE 文本：{text}"
        );
        assert!(
            !text.contains("message_delta"),
            "S1b：已有内容也不能豁免——断连后绝不能补 message_delta 伪装成正常完成，实际 SSE 文本：{text}"
        );
    }

    /// S2 — 流式请求上游 200 但空 body（正常 EOF，零产出）。
    ///
    /// 复用 http_client.rs 的 spawn_empty_body_200_upstream：连接正常结束
    /// （非 Err），body_stream.next() 最终产出 None。create_sse_stream 的
    /// None 分支里 ctx.is_empty_response()==true（从未收到任何内容），
    /// 应发 error_sse_event(StreamFailure::EmptyResponse) 而非
    /// ctx.generate_final_events() 的正常收尾（不应出现 end_turn stop_reason）。
    #[tokio::test]
    async fn test_s2_stream_empty_response_emits_error_not_end_turn() {
        let addr = spawn_empty_body_200_upstream().await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");

        let (ctx, initial_events) = fresh_ctx_with_initial_events();
        let span = tracing::Span::none();
        let stream = create_sse_stream(response, ctx, initial_events, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("event: error"),
            "S2：上游 200 空 body 必须发 error 帧诱导重试，实际 SSE 文本：{text}"
        );
        assert!(
            text.contains("overloaded_error"),
            "S2：空响应应为 overloaded_error（可重试），实际：{text}"
        );
        assert!(
            !text.contains("end_turn"),
            "S2：零产出不能被伪装成正常 end_turn 完成，实际 SSE 文本：{text}"
        );
        assert!(
            !text.contains("message_stop"),
            "S2：零产出不能补 message_stop 伪装成正常完成，实际 SSE 文本：{text}"
        );
        // 钉死 EmptyResponse 文案（PR #84 评审 Minor 2）：本 PR 把客户端可见
        // 文案从旧 "Upstream connection interrupted. Please retry." 改为新
        // "Upstream returned an empty response. Please retry."，没有本断言
        // 的话被人改回旧文案照样绿，这是本 PR 最值钱的一条防回归。
        assert!(
            text.contains("Upstream returned an empty response"),
            "S2：空响应文案必须是 EmptyResponse 专属措辞，实际 SSE 文本：{text}"
        );
        assert!(
            !text.contains("connection interrupted"),
            "S2：干净结束零内容压根没断连，绝不能报连接中断，实际 SSE 文本：{text}"
        );
    }

    /// C2 — 全缓冲流断连即便已缓冲内容也只发干净 error 帧（不 flush、不补收尾）。
    ///
    /// 缓冲模式把事件攒在 event_buffer 直到 finish 才 flush，断连前从未 emit 过任何字节。
    /// Some(Err) 时只发 error 帧、丢弃未 flush 的缓冲——「要么全成功要么全失败」的自洽语义。
    /// 反例（曾评审误判为需修的 bug）：若「先 flush 收尾(含 message_stop)再追加 error」，会发出
    /// message_stop 后又 error 的自相矛盾序列（先告知成功再告知失败），违背 #64「失败不能看起来
    /// 像成功」，反而更糟。故此处即便预置了已缓冲内容，断连也只发 error 帧、不出现 message_stop。
    ///
    /// 构造：先对 BufferedStreamContext 处理一条非空 AssistantResponse 预置"已缓冲内容"，再用
    /// spawn_mid_body_reset_upstream 提供真实 TCP 中断的 response 喂给 create_buffered_sse_stream。
    #[tokio::test]
    async fn test_c2_buffered_stream_interruption_emits_only_error_no_fake_stop() {
        let addr = spawn_mid_body_reset_upstream(true).await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败）");

        let mut ctx = BufferedStreamContext::new(
            "test-model",
            200_000,
            10,
            false,
            std::collections::HashMap::new(),
            1024,
        );
        // 预置"断连前已缓冲内容"：一条非空 AssistantResponse。
        let mut prior = crate::kiro::model::events::AssistantResponseEvent::default();
        prior.content = "buffered content before reset".to_string();
        ctx.process_and_buffer(&crate::kiro::model::events::Event::AssistantResponse(prior));
        assert!(
            !ctx.is_empty_response(),
            "前提：预置内容后缓冲上下文不应为空响应"
        );

        let span = tracing::Span::none();
        let stream = create_buffered_sse_stream(response, ctx, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("event: error"),
            "C2：断连必须发 error 帧告知流被中断，实际 SSE 文本：{text}"
        );
        assert!(
            text.contains("overloaded_error"),
            "C2：RST 断连是瞬态失败，error 帧应为 overloaded_error，实际：{text}"
        );
        // 核心：缓冲模式断连绝不发 message_stop/message_delta 伪装成正常完成——即便已缓冲内容。
        assert!(
            !text.contains("message_stop"),
            "C2：断连绝不能补 message_stop 伪装成正常完成（message_stop 后又 error 是自相矛盾序列），实际：{text}"
        );
        assert!(
            !text.contains("message_delta"),
            "C2：断连绝不能补 message_delta，实际：{text}"
        );
    }

    /// C2b — 全缓冲流零产出时断连只发 error 帧（不无中生有补 message_start/收尾帧）。
    #[tokio::test]
    async fn test_c2_buffered_stream_interruption_no_content_emits_only_error() {
        let addr = spawn_mid_body_reset_upstream(true).await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");

        // 全新缓冲上下文，未预置任何内容 → is_empty_response()==true。
        let ctx = BufferedStreamContext::new(
            "test-model",
            200_000,
            10,
            false,
            std::collections::HashMap::new(),
            1024,
        );
        assert!(ctx.is_empty_response(), "前提：未处理任何事件应为空响应");

        let span = tracing::Span::none();
        let stream = create_buffered_sse_stream(response, ctx, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("event: error"),
            "C2b：零产出断连必须发 error 帧，实际：{text}"
        );
        assert!(
            !text.contains("message_stop"),
            "C2b：零产出不应补 message_stop 伪装完成，实际：{text}"
        );
        assert!(
            !text.contains("message_delta"),
            "C2b：零产出不应补 message_delta，实际：{text}"
        );
    }

    /// S1c（#83）— 零内容 + 真实 TCP RST 走进 empty 链路，error.type 仍是
    /// overloaded_error。
    ///
    /// 诚实标注该用例的能力边界：E2E 不可能真等 200s 让 elapsed 越过
    /// FIRST_TOKEN_DEADLINE_HINT_SECS 闸门，故本用例只验证「零内容 + 真实
    /// TCP RST 落进 is_empty_response()==true 分支、classify_stream_failure
    /// 判定为瞬态可重试」这条链路本身是通的；`elapsed >= 200s` 那一半判定
    /// 已由 stream.rs 的 test_classify_stream_failure_matrix 单元矩阵覆盖。
    /// 本用例不引入 sleep、不调小生产常量、不注入测试专用阈值来迁就
    /// FirstTokenTimeout 分支——那会把这条护栏本身变成假背书。
    #[tokio::test]
    async fn test_s1c_stream_header_only_rst_no_content_emits_error_overloaded() {
        let addr = spawn_header_only_rst_upstream().await;
        let client = crate::http_client::build_idle_client(
            None,
            30,
            crate::model::config::TlsBackend::Rustls,
        )
        .expect("构建测试 client 失败");
        let response = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败）");

        let (ctx, initial_events) = fresh_ctx_with_initial_events();
        let span = tracing::Span::none();
        let stream = create_sse_stream(response, ctx, initial_events, span);
        let text = collect_sse_text(stream).await;

        assert!(
            text.contains("event: error"),
            "S1c：零内容 + 真实 TCP RST 必须发 error 帧，实际 SSE 文本：{text}"
        );
        assert!(
            text.contains("overloaded_error"),
            "S1c：零内容 + TCP RST 是瞬态失败，error.type 应为 overloaded_error，实际：{text}"
        );
        assert!(
            !text.contains("message_stop"),
            "S1c：零内容断连不应补 message_stop 伪装成正常完成，实际：{text}"
        );
    }

    // -----------------------------------------------------------------------
    // #64 BDD S3/S4 — handle_non_stream_request 收尾语义为何未做独立 E2E
    //
    // S3（非流式中途断连 is_transient 分支）与 S4（非流式空 content→503）
    // 的生产代码都挂在 handle_non_stream_request 上，该函数签名要求
    // Arc<KiroProvider>：完整构造需要 MultiTokenManager + 凭据 + 自定义
    // KiroEndpoint 实现（生产 IdeEndpoint 硬编码 AWS 域名，测试必须能把
    // 请求指到本地 mock 端口）。provider.rs 当前零测试先例，为这两条分支
    // 单独搭这套脚手架成本与收益不成比例——与本文件上方 Task 3
    // "FALLBACK 说明"同样的取舍（reqwest::Response 无公开构造器时退化到
    // 覆盖被依赖的前提，而非硬堆脚手架）。
    //
    // 实际覆盖拆成两层：
    // 1. http_client.rs 的 test_is_transient_true_for_mid_body_reset_fin/rst
    //    + test_is_transient_true_for_read_timeout/test_is_transient_false_for_builder_error
    //    ——用真实 mock 上游坐实 is_transient 对各类断连的分类结果（S3 的
    //    判定输入）。
    // 2. 本文件 test_map_connection_failed_gives_503——坐实
    //    ProviderError::ConnectionFailed 到 503 + Retry-After(15) +
    //    overloaded_error 的映射（S3 的判定输出）。handle_non_stream_request
    //    body-read-Err 分支里 `if is_transient(&e) { ... return
    //    map_provider_error(ProviderError::ConnectionFailed{..}) }` 只是把
    //    这两段已验证的逻辑串起来，胶水代码本身不含独立分支逻辑。
    // S4（content.is_empty() → 503 overloaded_error）同理是纯胶水：
    // 空 content 判断是一次直接的 String::is_empty() 调用，503 响应体走的
    // 也是与 test_map_all_credentials_disabled_gives_503 等测试相同的
    // ErrorResponse::new 构造路径，无需再搭一套 provider 才能验证格式正确性。
    // -----------------------------------------------------------------------
}
