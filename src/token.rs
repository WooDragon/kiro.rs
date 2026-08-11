//! Token 计算模块
//!
//! 提供文本 token 数量计算功能。
//!
//! # 计算规则（#85 token 守恒律 + tiktoken）
//! 统一使用 `tiktoken-rs` 的 `cl100k_base` 编码器作为唯一尺子（[`count_text`]），
//! 取代此前 char-heuristic（"非西文 4 字符单位 / 西文 1 字符单位"）与 stream.rs
//! 内联估算等多把互不兼容的尺子。词表通过 crate 内嵌（编译期 `include_str!`），
//! 零运行时网络/文件 IO。

use crate::anthropic::types::{
    CountTokensRequest, CountTokensResponse, Message, SystemMessage, Tool,
};
use crate::http_client::{ProxyConfig, build_client};
use crate::model::config::TlsBackend;
use serde_json::Value;
use std::sync::OnceLock;
use tiktoken_rs::CoreBPE;

/// Count Tokens API 配置
#[derive(Clone, Default)]
pub struct CountTokensConfig {
    /// 外部 count_tokens API 地址
    pub api_url: Option<String>,
    /// count_tokens API 密钥
    pub api_key: Option<String>,
    /// count_tokens API 认证类型（"x-api-key" 或 "bearer"）
    pub auth_type: String,
    /// 代理配置
    pub proxy: Option<ProxyConfig>,

    pub tls_backend: TlsBackend,
}

/// 全局配置存储
static COUNT_TOKENS_CONFIG: OnceLock<CountTokensConfig> = OnceLock::new();

/// 初始化 count_tokens 配置
///
/// 应在应用启动时调用一次
pub fn init_config(config: CountTokensConfig) {
    let _ = COUNT_TOKENS_CONFIG.set(config);
}

/// 获取配置
fn get_config() -> Option<&'static CountTokensConfig> {
    COUNT_TOKENS_CONFIG.get()
}

/// 全局 tiktoken cl100k_base 编码器单例。
///
/// 不直接用 tiktoken-rs 自带的 `cl100k_base_singleton()`：其内部 `unwrap()`
/// panic 时不带任何上下文，排障困难。这里显式 `get_or_init` + 带上下文的
/// `expect`，panic message 能直接指向"词表加载失败"这一具体原因。
static CL100K_TOKENIZER: OnceLock<CoreBPE> = OnceLock::new();

fn tokenizer() -> &'static CoreBPE {
    CL100K_TOKENIZER.get_or_init(|| {
        tiktoken_rs::cl100k_base()
            .expect("cl100k_base 词表加载失败：词表通过编译期 include_str! 内嵌进二进制，属构建期不变量，不应在运行时失败")
    })
}

/// 计算文本的 token 数量（统一尺子：tiktoken cl100k_base）
pub fn count_text(text: &str) -> i32 {
    if text.is_empty() {
        return 0;
    }
    tokenizer().encode_ordinary(text).len() as i32
}

/// 估算请求的输入 tokens
///
/// 优先调用远程 API，失败时回退到本地计算
pub(crate) fn count_all_tokens(
    model: String,
    system: Option<Vec<SystemMessage>>,
    messages: Vec<Message>,
    tools: Option<Vec<Tool>>,
) -> u64 {
    // 检查是否配置了远程 API
    if let Some(config) = get_config()
        && let Some(api_url) = &config.api_url
    {
        // 尝试调用远程 API
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(call_remote_count_tokens(
                api_url, config, model, &system, &messages, &tools,
            ))
        });

        match result {
            Ok(tokens) => {
                tracing::debug!("远程 count_tokens API 返回: {}", tokens);
                return tokens;
            }
            Err(e) => {
                tracing::warn!("远程 count_tokens API 调用失败，回退到本地计算: {}", e);
            }
        }
    }

    // 本地计算
    count_all_tokens_local(system, messages, tools)
}

/// 调用远程 count_tokens API
async fn call_remote_count_tokens(
    api_url: &str,
    config: &CountTokensConfig,
    model: String,
    system: &Option<Vec<SystemMessage>>,
    messages: &[Message],
    tools: &Option<Vec<Tool>>,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = build_client(config.proxy.as_ref(), 300, config.tls_backend)?;

    // 构建请求体
    let request = CountTokensRequest {
        model, // 模型名称用于 token 计算
        messages: messages.to_owned(),
        system: system.clone(),
        tools: tools.clone(),
    };

    // 构建请求
    let mut req_builder = client.post(api_url);

    // 设置认证头
    if let Some(api_key) = &config.api_key {
        if config.auth_type == "bearer" {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", api_key));
        } else {
            req_builder = req_builder.header("x-api-key", api_key);
        }
    }

    // 发送请求
    let response = req_builder
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("API 返回错误状态: {}", response.status()).into());
    }

    let result: CountTokensResponse = response.json().await?;
    Ok(result.input_tokens as u64)
}

/// image 内容块的 token 占位估算常量。
///
/// 上游未提供任何视觉 token 计价公式（黑盒未观测到相关字段），这里只是一个
/// 粗略估计常量，不是精确计费口径——只求「不再静默计 0」，不承诺准确。
const IMAGE_BLOCK_TOKEN_ESTIMATE: u64 = 1500;

/// document 内容块（`source.type == "base64"`，如 PDF）的 token 占位估算常量。
///
/// 与 image 同一顾虑但方向相反：不是"静默计 0"而是"数出天文数字"——base64
/// payload 若落进 [`count_value_recursive`] 兜底会被当纯文本数，1MB PDF ≈133 万
/// 字符 ≈40 万 token，直接暴露给 `/v1/messages/count_tokens` 调用方（#85 B3）。
/// 同 `IMAGE_BLOCK_TOKEN_ESTIMATE` 一样只求「不再离谱」，不承诺精确计费口径
/// （官方/上游均未提供 PDF 逐页 token 计价公式）。仅对 `source.type == "base64"`
/// 生效；`text`/`url` 等非 base64 来源不携带大体积无意义载荷，仍走正常递归计数。
///
/// 注意：与 image 不同，这里的 1500 在量级上是**有意的低报取舍**，不是同等意义上
/// 的"合理中位数"——image 单图成本有天然上界（约 1~1.6K token），1500 落在合理
/// 区间；但 document 页数无界，100 页 PDF 真实 token 量级约 15 万，估成 1500 是
/// 约 100 倍低报。之所以接受这个低报，是因为唯一的替代方案（把 base64 payload
/// 当正文数）会造出约 40 万倍的高报（见上），两害相权取其轻。按 payload 长度
/// 分档估算会引入新的魔法系数、且同样缺乏官方计价公式背书，本轮不做——1500
/// 这个具体数值本身未经论证，只是"两个方向都离谱时选择离谱更小的那个"。
const DOCUMENT_BLOCK_TOKEN_ESTIMATE: u64 = 1500;

/// 递归统计任意 JSON 值里的文本 token（兜底路径）：
/// 字符串直接计数，数组/对象递归遍历所有元素/字段值，其余类型（数字/bool/null）计 0。
///
/// 用于覆盖 `count_content_block` 未识别的块类型——不认识的块结构也不该静默计 0，
/// 而是尽力扫描它携带的所有字段值。
fn count_value_recursive(value: &Value) -> u64 {
    match value {
        Value::String(s) => count_text(s) as u64,
        Value::Array(items) => items.iter().map(count_value_recursive).sum(),
        Value::Object(map) => map.values().map(count_value_recursive).sum(),
        _ => 0,
    }
}

/// 返回媒体块的固定 token 估算。
///
/// image 不区分 source 类型；document 仅在 base64 source 时屏蔽其二进制载荷。
/// 这个判断同时服务真实计数和 prompt cache 的 ruler，避免两个路径再度漂移。
fn fixed_media_token_estimate(item: &Value) -> Option<u64> {
    match item.get("type").and_then(Value::as_str) {
        Some("image") => Some(IMAGE_BLOCK_TOKEN_ESTIMATE),
        Some("document")
            if item
                .get("source")
                .and_then(|source| source.get("type"))
                .and_then(Value::as_str)
                == Some("base64") =>
        {
            Some(DOCUMENT_BLOCK_TOKEN_ESTIMATE)
        }
        _ => None,
    }
}

/// 构造 content block 的 prompt-cache ruler 视图及媒体固定估算。
///
/// 只识别直接 image、base64 document，以及 tool_result.content 数组中的同类块；
/// tool input/schema 与普通 object 不递归，防止把用户数据误当媒体协议块。
/// 返回 None 表示原值必须逐字保留给普通 `count_text` 路径。
pub(crate) fn content_block_token_view(item: &Value) -> Option<(Value, u64)> {
    if let Some(estimate) = fixed_media_token_estimate(item) {
        return Some((Value::Null, estimate));
    }

    if item.get("type").and_then(Value::as_str) != Some("tool_result") {
        return None;
    }
    let Value::Array(content) = item.get("content")? else {
        return None;
    };

    let mut total_estimate = 0_u64;
    let mut has_replacement = false;
    let mut view = item.clone();
    let view_content = view.get_mut("content").and_then(Value::as_array_mut)?;
    for (index, block) in content.iter().enumerate() {
        if let Some((replacement, estimate)) = content_block_token_view(block) {
            view_content[index] = replacement;
            total_estimate = total_estimate.saturating_add(estimate);
            has_replacement = true;
        }
    }
    has_replacement.then_some((view, total_estimate))
}

/// 统计单个 content block（`{"type": ..., ...}`）的 token。
///
/// 覆盖 text / tool_use（name + input JSON）/ tool_result（content 可以是
/// string 或 array，array 分支递归复用本函数）/ media（固定占位常量）；
/// 未识别的块类型兜底走 [`count_value_recursive`] 扫描全部字段值。
fn count_content_block(item: &Value) -> u64 {
    if let Some(estimate) = fixed_media_token_estimate(item) {
        return estimate;
    }

    match item.get("type").and_then(|v| v.as_str()) {
        Some("text") => item
            .get("text")
            .and_then(|v| v.as_str())
            .map(|t| count_text(t) as u64)
            .unwrap_or(0),
        Some("tool_use") => {
            let mut total = 0u64;
            if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                total += count_text(name) as u64;
            }
            if let Some(input) = item.get("input") {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                total += count_text(&input_str) as u64;
            }
            total
        }
        Some("tool_result") => match item.get("content") {
            Some(Value::String(s)) => count_text(s) as u64,
            Some(Value::Array(arr)) => arr.iter().map(count_content_block).sum(),
            _ => 0,
        },
        _ => count_value_recursive(item),
    }
}

/// 统计 message.content（string 或 array）里的 token。
fn count_message_content(content: &Value) -> u64 {
    match content {
        Value::String(s) => count_text(s) as u64,
        Value::Array(items) => items.iter().map(count_content_block).sum(),
        other => count_value_recursive(other),
    }
}

/// 本地计算请求的输入 tokens
fn count_all_tokens_local(
    system: Option<Vec<SystemMessage>>,
    messages: Vec<Message>,
    tools: Option<Vec<Tool>>,
) -> u64 {
    let mut total: u64 = 0;

    // 系统消息
    if let Some(ref system) = system {
        for msg in system {
            total += count_text(&msg.text) as u64;
        }
    }

    // 用户消息：递归覆盖 text / tool_use / tool_result / image / 未识别块类型
    for msg in &messages {
        total += count_message_content(&msg.content);
    }

    // 工具定义
    if let Some(ref tools) = tools {
        for tool in tools {
            total += count_text(&tool.name) as u64;
            total += count_text(&tool.description) as u64;
            let input_schema_json = serde_json::to_string(&tool.input_schema).unwrap_or_default();
            total += count_text(&input_schema_json) as u64;
        }
    }

    total.max(1)
}

/// 估算输出 tokens
pub(crate) fn estimate_output_tokens(content: &[serde_json::Value]) -> i32 {
    let mut total = 0;

    for block in content {
        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
            total += count_text(text);
        }
        if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
            // 工具调用开销
            if let Some(input) = block.get("input") {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                total += count_text(&input_str);
            }
        }
    }

    total.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn count_text_counts_non_empty_ascii() {
        let n = count_text("hello world, this is a test sentence.");
        assert!(n > 0, "expected positive token count, got {n}");
    }

    #[test]
    fn count_text_empty_is_zero() {
        assert_eq!(count_text(""), 0);
    }

    #[test]
    fn count_text_is_char_based_not_byte_based() {
        // 中文字符 3 字节/字符（UTF-8），若实现退化为字节计数会明显偏大；
        // tiktoken 是真实 BPE 分词，这里只断言不等于粗暴的字节长度，
        // 防止将来又滑回 `.len()` 字节计数的旧坑（#85 同源教训）。
        let text = "你好世界，这是一个测试句子。";
        let byte_len = text.len() as i32;
        let n = count_text(text);
        assert!(
            n < byte_len,
            "count_text 不应等于/超过字节长度（怀疑退化为字节计数）：n={n}, byte_len={byte_len}"
        );
    }

    /// #85 回归测试：`count_all_tokens_local` 此前只统计数组 content 里
    /// `item.get("text")` 命中的块，tool_use / tool_result / image 块全部静默计 0。
    ///
    /// 反证验证：临时把 fix 还原（`count_message_content` 改回旧的
    /// "只认 text 字段" 实现）重跑此测试，得到：
    ///   thread 'token::tests::counts_tool_use_tool_result_and_image_blocks' panicked:
    ///   expected recursive coverage of tool_use/tool_result/image, got total=1
    /// （total.max(1) 兜底命中，说明旧实现三种块全计 0）——证明本测试在修复前确实为红。
    #[test]
    fn counts_tool_use_tool_result_and_image_blocks() {
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "search_documents",
                    "input": {"query": "rust programming language ownership guide"}
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": "here are the search results describing rust ownership rules"
                },
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}
                }
            ]),
        }];

        let total = count_all_tokens_local(None, messages, None);
        assert!(
            total > 10,
            "expected recursive coverage of tool_use/tool_result/image, got total={total}"
        );
    }

    /// tool_result.content 为**数组**（而非字符串）时须递归复用同一套块统计逻辑，
    /// 而不是把整个数组当不认识的类型直接兜底扫描字段值（虽然兜底也能扫到文本，
    /// 但这里专门验证数组分支显式复用 `count_content_block` 这条路径本身生效）。
    #[test]
    fn counts_tool_result_with_array_content() {
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_2",
                    "content": [
                        {"type": "text", "text": "first part of a fairly long tool result payload"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "abc"}}
                    ]
                }
            ]),
        }];

        let total = count_all_tokens_local(None, messages, None);
        // image 占位常量 1500 + text 若干 token，应远超旧实现的 total.max(1)=1。
        assert!(
            total >= IMAGE_BLOCK_TOKEN_ESTIMATE,
            "expected array tool_result content to be recursively counted, got total={total}"
        );
    }

    /// #85 B3 回归测试：`document` 块 `source.type == "base64"`（如 PDF）时，
    /// `data` 字段是 base64 payload 不是正文——若落进 `count_value_recursive`
    /// 兜底会被当纯文本数，制造出天文数字的 token 计数（1MB PDF ≈133 万字符
    /// ≈40 万 token，直接暴露给 `/v1/messages/count_tokens` 调用方）。
    ///
    /// 反事实验证：临时把 `count_content_block` 的 document 特判分支还原成裸
    /// `_ => count_value_recursive(item)`，重跑得到：
    ///   thread 'token::tests::document_base64_block_uses_fixed_estimate_not_payload_text'
    ///   panicked at src/token.rs:410:9:
    ///   expected fixed placeholder estimate for base64 document payload,
    ///   got total=10941（远超占位常量 1500 的 2 倍上限，证明 100KB base64
    ///   payload 确实被当正文数了）
    /// ——证明本测试在修复前确实为红，已复原修复代码并确认无残留污染。
    #[test]
    fn document_base64_block_uses_fixed_estimate_not_payload_text() {
        // 模拟 100KB 的 base64 PDF payload：用完整 base64 字符集循环填充，
        // 避免单字符重复被 BPE 高效合并、掩盖"payload 被当正文数"的问题。
        const BASE64_CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let fake_pdf_base64: String = (0..100_000)
            .map(|i| BASE64_CHARSET[i % BASE64_CHARSET.len()] as char)
            .collect();

        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": fake_pdf_base64
                    }
                }
            ]),
        }];

        let total = count_all_tokens_local(None, messages, None);
        assert!(
            total <= DOCUMENT_BLOCK_TOKEN_ESTIMATE * 2,
            "expected fixed placeholder estimate for base64 document payload, got total={total}\
             （怀疑 base64 payload 被 count_value_recursive 当正文数）"
        );
    }

    /// document 块 `source.type == "text"`（非 base64）时，`data` 字段是真实正文，
    /// 仍应走正常递归计数，不能因为新增的 base64 特判而误伤非 base64 来源。
    ///
    /// 用 `assert!(total > 1)` 无法区分「走了 count_value_recursive 正文计数」与
    /// 「被 base64 特判误吞成 DOCUMENT_BLOCK_TOKEN_ESTIMATE(1500) 占位常量」——
    /// 两者都满足 `> 1`。这里改用 assert_eq! 精确对齐递归路径的计算方式（`type`/
    /// `source.type`/`source.media_type`/`source.data` 四个字符串字段各自
    /// count_text 求和），并额外用 assert_ne! 直接排除占位常量。
    #[test]
    fn document_text_source_still_counts_content_normally() {
        let body = "this is a genuine plain text document body that should be counted normally";
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {
                    "type": "document",
                    "source": {
                        "type": "text",
                        "media_type": "text/plain",
                        "data": body
                    }
                }
            ]),
        }];

        let total = count_all_tokens_local(None, messages, None);
        let expected = count_text("document") as u64
            + count_text("text") as u64
            + count_text("text/plain") as u64
            + count_text(body) as u64;
        assert_eq!(
            total, expected,
            "非 base64 document 来源应精确等于递归路径对各字符串字段的 count_text 求和，\
             got total={total} expected={expected}"
        );
        assert_ne!(
            total, DOCUMENT_BLOCK_TOKEN_ESTIMATE,
            "不应落入 base64 占位常量分支，got total={total}"
        );
    }

    /// 未识别的块类型（既非 text/tool_use/tool_result/image）兜底递归扫描全部字段值，
    /// 不静默计 0。
    #[test]
    fn counts_unrecognized_block_type_via_fallback_recursion() {
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!([
                {
                    "type": "some_future_block_type_not_yet_supported",
                    "payload": "this text lives inside an unrecognized block type field"
                }
            ]),
        }];

        let total = count_all_tokens_local(None, messages, None);
        assert!(
            total > 1,
            "expected fallback recursion to count unrecognized block's field values, got total={total}"
        );
    }

    /// 纯文本消息回归：确保重构没有破坏最基本的 string content 路径。
    #[test]
    fn content_block_token_view_normalizes_direct_image_sources() {
        for source in [
            json!({"type": "base64", "media_type": "image/png", "data": "AQID"}),
            json!({"type": "url", "url": "https://example.test/very/long/image.png"}),
        ] {
            assert_eq!(
                content_block_token_view(&json!({"type": "image", "source": source})),
                Some((Value::Null, IMAGE_BLOCK_TOKEN_ESTIMATE))
            );
        }
    }

    #[test]
    fn content_block_token_view_normalizes_only_base64_documents() {
        let base64 = json!({"type": "document", "source": {"type": "base64", "data": "AQID"}});
        assert_eq!(
            content_block_token_view(&base64),
            Some((Value::Null, DOCUMENT_BLOCK_TOKEN_ESTIMATE))
        );
        for source_type in ["text", "url"] {
            let document = json!({"type": "document", "source": {"type": source_type, "data": "ordinary content"}});
            assert_eq!(content_block_token_view(&document), None);
        }
    }

    #[test]
    fn content_block_token_view_recurses_only_through_tool_result_content() {
        let tool_result = json!({
            "type": "tool_result",
            "content": [
                {"type": "text", "text": "keep this text"},
                {"type": "image", "source": {"type": "base64", "data": "AQID"}}
            ]
        });
        let (view, estimate) = content_block_token_view(&tool_result).unwrap();
        assert_eq!(estimate, IMAGE_BLOCK_TOKEN_ESTIMATE);
        assert_eq!(
            view["content"][0],
            json!({"type": "text", "text": "keep this text"})
        );
        assert_eq!(view["content"][1], Value::Null);

        let tool_use = json!({
            "type": "tool_use",
            "input": {"type": "image", "source": {"type": "base64", "data": "AQID"}}
        });
        assert_eq!(content_block_token_view(&tool_use), None);
    }

    #[test]
    fn counts_plain_string_message_content() {
        let messages = vec![Message {
            role: "user".to_string(),
            content: json!("a reasonably long plain text message for token counting"),
        }];
        let total = count_all_tokens_local(None, messages, None);
        assert!(total > 1);
    }
}
