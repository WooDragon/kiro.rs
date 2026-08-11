//! WebSearch 工具处理模块
//!
//! 实现 Anthropic WebSearch 请求到 Kiro MCP 的转换和响应生成

use std::convert::Infallible;

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::prompt_cache::{
    PromptCacheProfile, PromptCacheTracker, PromptCacheUsage, ScaledCacheUsage, build_usage_value,
};
use super::stream::SseEvent;
use super::types::{ErrorResponse, MessagesRequest};
use crate::model::config::PromptCacheMode;
use crate::model::registry::ModelRegistry;
use std::sync::Arc;

/// MCP 请求
#[derive(Debug, Serialize)]
pub struct McpRequest {
    pub id: String,
    pub jsonrpc: String,
    pub method: String,
    pub params: McpParams,
}

/// MCP 请求参数
#[derive(Debug, Serialize)]
pub struct McpParams {
    pub name: String,
    pub arguments: McpArguments,
}

/// MCP 参数
#[derive(Debug, Serialize)]
pub struct McpArguments {
    pub query: String,
}

/// MCP 响应
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResponse {
    pub error: Option<McpError>,
    pub id: String,
    pub jsonrpc: String,
    pub result: Option<McpResult>,
}

/// MCP 错误
#[derive(Debug, Deserialize)]
pub struct McpError {
    pub code: Option<i32>,
    pub message: Option<String>,
}

/// MCP 结果
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

/// MCP 内容
#[derive(Debug, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// WebSearch 搜索结果
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct WebSearchResults {
    pub results: Vec<WebSearchResult>,
    #[serde(rename = "totalResults")]
    pub total_results: Option<i32>,
    pub query: Option<String>,
    pub error: Option<String>,
}

/// 单个搜索结果
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct WebSearchResult {
    pub title: String,
    pub url: String,
    pub snippet: Option<String>,
    #[serde(rename = "publishedDate")]
    pub published_date: Option<i64>,
    pub id: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "maxVerbatimWordLimit")]
    pub max_verbatim_word_limit: Option<i32>,
    #[serde(rename = "publicDomain")]
    pub public_domain: Option<bool>,
}

/// 检查请求是否为纯 WebSearch 请求
///
/// 条件：tools 有且只有一个，且 name 为 web_search
pub fn has_web_search_tool(req: &MessagesRequest) -> bool {
    req.tools.as_ref().is_some_and(|tools| {
        tools.len() == 1 && tools.first().is_some_and(|t| t.name == "web_search")
    })
}

/// 从消息中提取搜索查询
///
/// 读取 messages 的第一条消息的第一个内容块
/// 并去除 "Perform a web search for the query: " 前缀
pub fn extract_search_query(req: &MessagesRequest) -> Option<String> {
    // 获取第一条消息
    let first_msg = req.messages.first()?;

    // 提取文本内容
    let text = match &first_msg.content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            // 获取第一个内容块
            let first_block = arr.first()?;
            if first_block.get("type")?.as_str()? == "text" {
                first_block.get("text")?.as_str()?.to_string()
            } else {
                return None;
            }
        }
        _ => return None,
    };

    // 去除前缀 "Perform a web search for the query: "
    const PREFIX: &str = "Perform a web search for the query: ";
    let query = if let Some(stripped) = text.strip_prefix(PREFIX) {
        stripped.to_string()
    } else {
        text
    };

    if query.is_empty() { None } else { Some(query) }
}

/// 生成22位大小写字母和数字的随机字符串
fn generate_random_id_22() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..22)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 生成8位小写字母和数字的随机字符串
fn generate_random_id_8() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..8)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 创建 MCP 请求
///
/// ID 格式: web_search_tooluse_{22位随机}_{毫秒时间戳}_{8位随机}
pub fn create_mcp_request(query: &str) -> (String, McpRequest) {
    let random_22 = generate_random_id_22();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let random_8 = generate_random_id_8();

    let request_id = format!(
        "web_search_tooluse_{}_{}_{}",
        random_22, timestamp, random_8
    );

    // tool_use_id 使用相同格式
    let tool_use_id = format!(
        "srvtoolu_{}",
        &Uuid::new_v4().to_string().replace('-', "")[..32]
    );

    let request = McpRequest {
        id: request_id,
        jsonrpc: "2.0".to_string(),
        method: "tools/call".to_string(),
        params: McpParams {
            name: "web_search".to_string(),
            arguments: McpArguments {
                query: query.to_string(),
            },
        },
    };

    (tool_use_id, request)
}

/// 解析 MCP 响应中的搜索结果
pub fn parse_search_results(mcp_response: &McpResponse) -> Option<WebSearchResults> {
    let result = mcp_response.result.as_ref()?;
    let content = result.content.first()?;

    if content.content_type != "text" {
        return None;
    }

    serde_json::from_str(&content.text).ok()
}

/// 生成 WebSearch SSE 响应流
pub fn create_websearch_sse_stream(
    model: String,
    query: String,
    tool_use_id: String,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
    prompt_cache_usage: ScaledCacheUsage,
    include_prompt_cache_fields: bool,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let events = generate_websearch_events(
        &model,
        &query,
        &tool_use_id,
        search_results,
        input_tokens,
        prompt_cache_usage,
        include_prompt_cache_fields,
    );

    stream::iter(
        events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    )
}

/// 生成 WebSearch SSE 事件序列
fn generate_websearch_events(
    model: &str,
    query: &str,
    tool_use_id: &str,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
    prompt_cache_usage: ScaledCacheUsage,
    include_prompt_cache_fields: bool,
) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let message_id = format!("msg_{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);

    // 1. message_start
    events.push(SseEvent::new(
        "message_start",
        json!({
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
                "usage": build_usage_value(
                    input_tokens,
                    0,
                    prompt_cache_usage,
                    include_prompt_cache_fields,
                )
            }
        }),
    ));

    // 2. content_block_start (text - 搜索决策说明, index 0)
    let decision_text = format!("I'll search for \"{}\".", query);
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "text",
                "text": ""
            }
        }),
    ));

    events.push(SseEvent::new(
        "content_block_delta",
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": decision_text
            }
        }),
    ));

    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 0
        }),
    ));

    // 3. content_block_start (server_tool_use, index 1)
    // server_tool_use 是服务端工具，input 在 content_block_start 中一次性完整发送，
    // 不像客户端 tool_use 需要通过 input_json_delta 增量传输。
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "id": tool_use_id,
                "type": "server_tool_use",
                "name": "web_search",
                "input": {"query": query}
            }
        }),
    ));

    // 4. content_block_stop (server_tool_use)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 1
        }),
    ));

    // 5. content_block_start (web_search_tool_result, index 2)
    // 官方 API 的 web_search_tool_result 没有 tool_use_id 字段
    let search_content = if let Some(ref results) = search_results {
        results
            .results
            .iter()
            .map(|r| {
                let page_age = r.published_date.and_then(|ms| {
                    chrono::DateTime::from_timestamp_millis(ms)
                        .map(|dt| dt.format("%B %-d, %Y").to_string())
                });
                json!({
                    "type": "web_search_result",
                    "title": r.title,
                    "url": r.url,
                    "encrypted_content": r.snippet.clone().unwrap_or_default(),
                    "page_age": page_age
                })
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 2,
            "content_block": {
                "type": "web_search_tool_result",
                "content": search_content
            }
        }),
    ));

    // 6. content_block_stop (web_search_tool_result)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 2
        }),
    ));

    // 7. content_block_start (text, index 3)
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 3,
            "content_block": {
                "type": "text",
                "text": ""
            }
        }),
    ));

    // 8. content_block_delta (text_delta) - 生成搜索结果摘要
    let summary = generate_search_summary(query, &search_results);

    // 分块发送文本
    let chunk_size = 100;
    for chunk in summary.chars().collect::<Vec<_>>().chunks(chunk_size) {
        let text: String = chunk.iter().collect();
        events.push(SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 3,
                "delta": {
                    "type": "text_delta",
                    "text": text
                }
            }),
        ));
    }

    // 9. content_block_stop (text)
    events.push(SseEvent::new(
        "content_block_stop",
        json!({
            "type": "content_block_stop",
            "index": 3
        }),
    ));

    // 10. message_delta
    // 官方 API 的 message_delta.delta 中没有 stop_sequence 字段
    // 统一走 tiktoken 尺子（#85）——曾用 `(summary.len()+3)/4` 按 UTF-8 字节数估算，
    // CJK 摘要文本会明显低报（约 2 倍，字节数/4 而非按字符/BPE token 计）。
    let output_tokens = crate::token::count_text(&summary);
    events.push(SseEvent::new(
        "message_delta",
        json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": "end_turn"
            },
            "usage": {
                "output_tokens": output_tokens,
                "server_tool_use": {
                    "web_search_requests": 1
                }
            }
        }),
    ));

    // 11. message_stop
    events.push(SseEvent::new(
        "message_stop",
        json!({
            "type": "message_stop"
        }),
    ));

    events
}

/// 生成搜索结果摘要
fn generate_search_summary(query: &str, results: &Option<WebSearchResults>) -> String {
    let mut summary = format!("Here are the search results for \"{}\":\n\n", query);

    if let Some(results) = results {
        for (i, result) in results.results.iter().enumerate() {
            summary.push_str(&format!("{}. **{}**\n", i + 1, result.title));
            if let Some(ref snippet) = result.snippet {
                // 截断过长的摘要（安全处理 UTF-8 多字节字符）
                let truncated = match snippet.char_indices().nth(200) {
                    Some((idx, _)) => format!("{}...", &snippet[..idx]),
                    None => snippet.clone(),
                };
                summary.push_str(&format!("   {}\n", truncated));
            }
            summary.push_str(&format!("   Source: {}\n\n", result.url));
        }
    } else {
        summary.push_str("No results found.\n");
    }

    summary.push_str("\nPlease note that these are web search results and may not be fully accurate or up-to-date.");

    summary
}

/// 处理 WebSearch 请求
pub async fn handle_websearch_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    payload: &MessagesRequest,
    input_tokens: i32,
    prompt_cache_mode: PromptCacheMode,
    prompt_cache: Arc<PromptCacheTracker>,
    prompt_cache_profile: Option<PromptCacheProfile>,
    model_registry: &Arc<ModelRegistry>,
) -> Response {
    // 1. 提取搜索查询
    let query = match extract_search_query(payload) {
        Some(q) => q,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    "无法从消息中提取搜索查询",
                )),
            )
                .into_response();
        }
    };

    tracing::info!(query = %query, "处理 WebSearch 请求");

    // 2. 创建 MCP 请求
    let (tool_use_id, mcp_request) = create_mcp_request(&query);

    // 2.5 提取 session id，复用 converter.rs 的解析逻辑，使 WebSearch 请求
    // 也能命中同一会话的粘性凭据绑定（#86），避免与主对话链路各绑各的。
    let session_id = payload
        .metadata
        .as_ref()
        .and_then(|m| m.user_id.as_ref())
        .and_then(|user_id| super::converter::extract_session_id(user_id));

    // 3. 调用 Kiro MCP API
    let search_results = match call_mcp_api(&provider, &mcp_request, session_id.as_deref()).await {
        Ok(response) => parse_search_results(&response),
        Err(e) => {
            tracing::warn!(error = %e, "MCP API 调用失败");
            None
        }
    };

    // 4. 生成 SSE 响应
    let model = payload.model.clone();
    let account_key = "websearch";
    let min_cacheable_tokens = model_registry.min_cacheable_tokens(&model);
    let prompt_cache_usage = if matches!(
        prompt_cache_mode,
        PromptCacheMode::Auto | PromptCacheMode::Emulated
    ) {
        prompt_cache.compute(
            account_key,
            prompt_cache_profile.as_ref(),
            min_cacheable_tokens,
        )
    } else {
        PromptCacheUsage::default()
    };
    // WebSearch 路径完全绕开上游 metering（合成的客户端 SSE），没有 decide_prompt_cache
    // 可用；这里的 input_tokens 本身也只是另一把本地估算尺（非上游真实值），
    // into_real 在该场景下退化为"近似恒等缩放"（#85 设计注记）。
    let prompt_cache_usage = match prompt_cache_profile
        .as_ref()
        .map(|p| p.local_total_tokens())
    {
        Some(local_total) => ScaledCacheUsage::Local {
            usage: prompt_cache_usage,
            local_total,
        },
        None => ScaledCacheUsage::Real(prompt_cache_usage),
    };
    let include_prompt_cache_fields = prompt_cache_profile.is_some()
        && matches!(
            prompt_cache_mode,
            PromptCacheMode::Auto | PromptCacheMode::Emulated
        );
    if matches!(
        prompt_cache_mode,
        PromptCacheMode::Auto | PromptCacheMode::Emulated
    ) {
        prompt_cache.update(
            account_key,
            prompt_cache_profile.as_ref(),
            min_cacheable_tokens,
        );
    }
    let stream = create_websearch_sse_stream(
        model,
        query,
        tool_use_id,
        search_results,
        input_tokens,
        prompt_cache_usage,
        include_prompt_cache_fields,
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 调用 Kiro MCP API
async fn call_mcp_api(
    provider: &crate::kiro::provider::KiroProvider,
    request: &McpRequest,
    session_id: Option<&str>,
) -> anyhow::Result<McpResponse> {
    let request_body = serde_json::to_string(request)?;

    // 复用 handlers.rs 的截断逻辑与上限，避免维护两份等价实现（#71）。
    tracing::debug!(
        target: "kiro_rs::payload",
        body = %super::handlers::truncate_for_log(&request_body, super::handlers::LOG_PAYLOAD_LIMIT),
        "MCP request"
    );

    let response = provider.call_mcp(&request_body, session_id).await?;

    let body = response.text().await?;
    tracing::debug!(
        target: "kiro_rs::payload",
        body = %super::handlers::truncate_for_log(&body, super::handlers::LOG_PAYLOAD_LIMIT),
        "MCP response"
    );

    let mcp_response: McpResponse = serde_json::from_str(&body)?;

    if let Some(ref error) = mcp_response.error {
        anyhow::bail!(
            "MCP error: {} - {}",
            error.code.unwrap_or(-1),
            error.message.as_deref().unwrap_or("Unknown error")
        );
    }

    Ok(mcp_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_web_search_tool_only_one() {
        use crate::anthropic::types::{Message, Tool};

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            stream: true,
            system: None,
            tools: Some(vec![Tool {
                tool_type: Some("web_search_20250305".to_string()),
                name: "web_search".to_string(),
                description: String::new(),
                input_schema: Default::default(),
                max_uses: Some(8),
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        assert!(has_web_search_tool(&req));
    }

    #[test]
    fn test_has_web_search_tool_multiple_tools() {
        use crate::anthropic::types::{Message, Tool};

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            stream: true,
            system: None,
            tools: Some(vec![
                Tool {
                    tool_type: Some("web_search_20250305".to_string()),
                    name: "web_search".to_string(),
                    description: String::new(),
                    input_schema: Default::default(),
                    max_uses: Some(8),
                    cache_control: None,
                },
                Tool {
                    tool_type: None,
                    name: "other_tool".to_string(),
                    description: "Other tool".to_string(),
                    input_schema: Default::default(),
                    max_uses: None,
                    cache_control: None,
                },
            ]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        // 多个工具时不应该被识别为纯 websearch 请求
        assert!(!has_web_search_tool(&req));
    }

    #[test]
    fn test_extract_search_query_with_prefix() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!([{
                    "type": "text",
                    "text": "Perform a web search for the query: rust latest version 2026"
                }]),
            }],
            stream: true,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let query = extract_search_query(&req);
        // 前缀应该被去除
        assert_eq!(query, Some("rust latest version 2026".to_string()));
    }

    #[test]
    fn test_extract_search_query_plain_text() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("What is the weather today?"),
            }],
            stream: true,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let query = extract_search_query(&req);
        assert_eq!(query, Some("What is the weather today?".to_string()));
    }

    #[test]
    fn test_create_mcp_request() {
        let (tool_use_id, request) = create_mcp_request("test query");

        assert!(tool_use_id.starts_with("srvtoolu_"));
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "tools/call");
        assert_eq!(request.params.name, "web_search");
        assert_eq!(request.params.arguments.query, "test query");

        // 验证 ID 格式: web_search_tooluse_{22位}_{时间戳}_{8位}
        assert!(request.id.starts_with("web_search_tooluse_"));
    }

    #[test]
    fn test_mcp_request_id_format() {
        let (_, request) = create_mcp_request("test");

        // 格式: web_search_tooluse_{22位}_{毫秒时间戳}_{8位}
        let id = &request.id;
        assert!(id.starts_with("web_search_tooluse_"));

        let suffix = &id["web_search_tooluse_".len()..];
        let parts: Vec<&str> = suffix.split('_').collect();
        assert_eq!(parts.len(), 3, "应该有3个部分: 22位随机_时间戳_8位随机");

        // 第一部分: 22位大小写字母和数字
        assert_eq!(parts[0].len(), 22);
        assert!(parts[0].chars().all(|c| c.is_ascii_alphanumeric()));

        // 第二部分: 毫秒时间戳
        assert!(parts[1].parse::<i64>().is_ok());

        // 第三部分: 8位小写字母和数字
        assert_eq!(parts[2].len(), 8);
        assert!(
            parts[2]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_parse_search_results() {
        let response = McpResponse {
            error: None,
            id: "test_id".to_string(),
            jsonrpc: "2.0".to_string(),
            result: Some(McpResult {
                content: vec![McpContent {
                    content_type: "text".to_string(),
                    text: r#"{"results":[{"title":"Test","url":"https://example.com","snippet":"Test snippet"}],"totalResults":1}"#.to_string(),
                }],
                is_error: false,
            }),
        };

        let results = parse_search_results(&response);
        assert!(results.is_some());
        let results = results.unwrap();
        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].title, "Test");
    }

    #[test]
    fn test_generate_search_summary() {
        let results = WebSearchResults {
            results: vec![WebSearchResult {
                title: "Test Result".to_string(),
                url: "https://example.com".to_string(),
                snippet: Some("This is a test snippet".to_string()),
                published_date: None,
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("test".to_string()),
            error: None,
        };

        let summary = generate_search_summary("test", &Some(results));

        assert!(summary.contains("Test Result"));
        assert!(summary.contains("https://example.com"));
        assert!(summary.contains("This is a test snippet"));
    }

    /// #85 调用点 #6（`generate_websearch_events` 的 `build_usage_value` 调用，
    /// 团队约定"最容易漏改"的一处）：message_start 里的 usage 字段必须满足
    /// `input_tokens + cc + cr == real_total`，且传入 `ScaledCacheUsage::Local`
    /// 时必须真的按比例换算（而不是被当成 `PromptCacheUsage` 直接塞进去导致编译期
    /// 类型不匹配——本测试同时充当"这个调用点确实吃了新类型"的编译期证据）。
    ///
    /// 夹具刻意选 `cc(4000)+cr(1500)=5500 != real_total(5000)`——若两者恰好相等，
    /// 调用点丢失 `Local` 缩放语义（被 `.raw()` 打平成 `Real` 再传入）也会巧合凑出
    /// 同一个 5000，测不出问题（反事实验证曾在同构场景撞过一次假阴性）。
    #[test]
    fn generate_websearch_events_message_start_usage_conserves_against_real_total() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 4000,
                cache_read_input_tokens: 1500,
                cache_creation_5m_input_tokens: 4000,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 10_000,
        };
        let real_total = 5000;

        let events = generate_websearch_events(
            "claude-sonnet-4-5",
            "test query",
            "tool_1",
            None,
            real_total,
            scaled,
            true,
        );

        let message_start = events
            .iter()
            .find(|e| e.event == "message_start")
            .expect("should emit message_start");
        let usage = &message_start.data["message"]["usage"];
        let reported_input = usage["input_tokens"].as_i64().unwrap() as i32;
        let cc = usage["cache_creation_input_tokens"].as_i64().unwrap() as i32;
        let cr = usage["cache_read_input_tokens"].as_i64().unwrap() as i32;

        assert_eq!(
            reported_input + cc + cr,
            real_total,
            "守恒律：message_start usage 的 input_tokens+cc+cr 必须恒等于 real_total"
        );
    }

    /// #85 第六把尺子回归：`generate_websearch_events` 的
    /// `message_delta.usage.output_tokens` 曾用 `(summary.len()+3)/4` 按 UTF-8
    /// *字节数* 估算——与 `stream.rs:1348` 修过的那处是同一类 bug 的逐字复制品，
    /// 只是方向相反（这里对 CJK 摘要是**低报**约 2 倍：字节数/4 用"4 字节/token"
    /// 假设，中文实际约 1.5~2 token/字，远小于字节数/4 得出的量级）。
    ///
    /// 用喂含中文 title/snippet 的 `WebSearchResults` 构造出 CJK 占比高的
    /// summary，断言 `output_tokens` 不再撞回旧字节公式、且与 `count_text`
    /// 直接计算的值一致（同一份 summary 文本，函数内部与测试各自独立调用
    /// `count_text`/`generate_search_summary`，两者必须吻合）。
    #[test]
    fn generate_websearch_events_message_delta_output_tokens_uses_tiktoken_not_utf8_bytes() {
        let results = WebSearchResults {
            results: vec![WebSearchResult {
                title: "所有权系统是 Rust 语言在编译期保证内存安全的核心机制".to_string(),
                url: "https://example.com".to_string(),
                snippet: Some(
                    "它通过借用检查器在没有垃圾回收器的情况下追踪每一个值的生命周期与作用域边界，这是一段专门用来验证 token 计数不再退化为字节计数的中文摘要文本".to_string(),
                ),
                published_date: None,
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("所有权".to_string()),
            error: None,
        };

        let summary = generate_search_summary("所有权", &Some(results.clone()));
        let byte_len_estimate = (summary.len() as i32 + 3) / 4;

        let events = generate_websearch_events(
            "claude-sonnet-4-5",
            "所有权",
            "toolu_test",
            Some(results),
            5000,
            ScaledCacheUsage::Real(PromptCacheUsage::default()),
            false,
        );

        let message_delta = events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should emit message_delta");
        let output_tokens = message_delta.data["usage"]["output_tokens"]
            .as_i64()
            .unwrap() as i32;

        assert_ne!(
            output_tokens, byte_len_estimate,
            "output_tokens 撞回旧字节估算公式 (summary.len()+3)/4，怀疑第六把尺子未修"
        );
        assert_eq!(
            output_tokens,
            crate::token::count_text(&summary),
            "output_tokens 应与 tiktoken 尺子直接计算的值一致"
        );
    }
}
