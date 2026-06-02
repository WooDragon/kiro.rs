//! Anthropic API 类型定义

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

// === 错误响应 ===

/// API 错误响应
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// 错误详情
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl ErrorResponse {
    /// 创建新的错误响应
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                error_type: error_type.into(),
                message: message.into(),
            },
        }
    }

    /// 创建认证错误响应
    pub fn authentication_error() -> Self {
        Self::new("authentication_error", "Invalid API key")
    }
}

// === Models 端点类型 ===

/// 模型信息
#[derive(Debug, Serialize)]
pub struct Model {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub owned_by: String,
    pub display_name: String,
    #[serde(rename = "type")]
    pub model_type: String,
    pub max_tokens: i32,
}

/// 模型列表响应
#[derive(Debug, Serialize)]
pub struct ModelsResponse {
    pub object: String,
    pub data: Vec<Model>,
}

// === Messages 端点类型 ===

/// 最大思考预算 tokens
const MAX_BUDGET_TOKENS: i32 = 24576;

/// Thinking 配置
#[derive(Debug, Deserialize, Clone)]
pub struct Thinking {
    #[serde(rename = "type")]
    pub thinking_type: String,
    #[serde(
        default = "default_budget_tokens",
        deserialize_with = "deserialize_budget_tokens"
    )]
    pub budget_tokens: i32,
}

impl Thinking {
    /// 是否启用了 thinking（enabled 或 adaptive）
    pub fn is_enabled(&self) -> bool {
        self.thinking_type == "enabled" || self.thinking_type == "adaptive"
    }
}

fn default_budget_tokens() -> i32 {
    20000
}
fn deserialize_budget_tokens<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    Ok(value.min(MAX_BUDGET_TOKENS))
}

/// OutputConfig 配置
#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    #[serde(default = "default_effort")]
    pub effort: String,
}

fn default_effort() -> String {
    "high".to_string()
}

/// Claude Code 请求中的 metadata
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    /// 用户 ID，格式如: user_xxx_account__session_0b4445e1-f5be-49e1-87ce-62bbc28ad705
    pub user_id: Option<String>,
}

/// Messages 请求体
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MessagesRequest {
    pub model: String,
    pub max_tokens: i32,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, deserialize_with = "deserialize_system")]
    pub system: Option<Vec<SystemMessage>>,
    pub tools: Option<Vec<Tool>>,
    pub tool_choice: Option<serde_json::Value>,
    pub thinking: Option<Thinking>,
    pub output_config: Option<OutputConfig>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    /// Claude Code 请求中的 metadata，包含 session 信息
    pub metadata: Option<Metadata>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheControl {
    #[serde(rename = "type")]
    pub cache_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<serde_json::Value>,
}

/// 反序列化 system 字段，支持字符串或数组格式
fn deserialize_system<'de, D>(deserializer: D) -> Result<Option<Vec<SystemMessage>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // 创建一个 visitor 来处理 string 或 array
    struct SystemVisitor;

    impl<'de> serde::de::Visitor<'de> for SystemVisitor {
        type Value = Option<Vec<SystemMessage>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or an array of system messages")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(vec![SystemMessage {
                text: value.to_string(),
                cache_control: None,
            }]))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut messages = Vec::new();
            while let Some(msg) = seq.next_element()? {
                messages.push(msg);
            }
            Ok(if messages.is_empty() {
                None
            } else {
                Some(messages)
            })
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            serde::de::Deserialize::deserialize(deserializer)
        }
    }

    deserializer.deserialize_any(SystemVisitor)
}

/// 消息
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    /// 可以是 string 或 ContentBlock 数组
    pub content: serde_json::Value,
}

/// 系统消息
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemMessage {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

const CLAUDE_CODE_PROMPT_FILTER_PREFIXES: &[&str] = &["x-anthropic-billing-header:"];

pub(crate) fn is_claude_code_filtered_prompt_text(text: &str) -> bool {
    let normalized = text.trim_start().to_ascii_lowercase();
    CLAUDE_CODE_PROMPT_FILTER_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
}

fn is_claude_code_filtered_prompt_line(line: &str) -> bool {
    is_claude_code_filtered_prompt_text(line)
}

pub(crate) fn strip_anthropic_billing_header_text(text: &str) -> Option<Cow<'_, str>> {
    let mut changed = false;
    let kept_lines: Vec<&str> = text
        .lines()
        .filter(|line| {
            let should_filter = is_claude_code_filtered_prompt_line(line);
            if should_filter {
                changed = true;
            }
            !should_filter
        })
        .collect();

    if !changed {
        return Some(Cow::Borrowed(text));
    }

    let stripped = kept_lines.join("\n");
    if stripped.trim().is_empty() {
        None
    } else {
        Some(Cow::Owned(stripped))
    }
}

impl SystemMessage {
    pub(crate) fn without_anthropic_billing_headers(&self) -> Option<Self> {
        strip_anthropic_billing_header_text(&self.text).map(|text| Self {
            text: text.into_owned(),
            cache_control: self.cache_control.clone(),
        })
    }
}

fn strip_anthropic_billing_headers_from_system(system: &mut Option<Vec<SystemMessage>>) -> usize {
    let Some(messages) = system.take() else {
        return 0;
    };

    let mut changed = 0;
    let mut stripped = Vec::with_capacity(messages.len());

    for msg in messages {
        match strip_anthropic_billing_header_text(&msg.text) {
            Some(Cow::Borrowed(_)) => stripped.push(msg),
            Some(Cow::Owned(text)) => {
                changed += 1;
                stripped.push(SystemMessage {
                    text,
                    cache_control: msg.cache_control,
                });
            }
            None => changed += 1,
        }
    }

    *system = if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    };

    changed
}

impl MessagesRequest {
    pub(crate) fn strip_anthropic_billing_headers(&mut self) -> usize {
        strip_anthropic_billing_headers_from_system(&mut self.system)
    }
}

/// 工具定义
///
/// 支持两种格式：
/// 1. 普通工具：{ name, description, input_schema }
/// 2. WebSearch 工具：{ type: "web_search_20250305", name: "web_search", max_uses: 8 }
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tool {
    /// 工具类型，如 "web_search_20250305"（可选，仅 WebSearch 工具）
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tool_type: Option<String>,
    /// 工具名称
    #[serde(default)]
    pub name: String,
    /// 工具描述（普通工具必需，WebSearch 工具可选）
    #[serde(default)]
    pub description: String,
    /// 输入参数 schema（普通工具必需，WebSearch 工具无此字段）
    #[serde(default)]
    pub input_schema: HashMap<String, serde_json::Value>,
    /// 最大使用次数（仅 WebSearch 工具）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<i32>,
    /// Anthropic prompt cache 控制字段
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

/// 内容块
#[derive(Debug, Deserialize, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ImageSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

/// 图片数据源
#[derive(Debug, Deserialize, Serialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub media_type: String,
    pub data: String,
}

// === Count Tokens 端点类型 ===

/// Token 计数请求
#[derive(Debug, Serialize, Deserialize)]
pub struct CountTokensRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_system"
    )]
    pub system: Option<Vec<SystemMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

impl CountTokensRequest {
    pub(crate) fn strip_anthropic_billing_headers(&mut self) -> usize {
        strip_anthropic_billing_headers_from_system(&mut self.system)
    }
}

/// Token 计数响应
#[derive(Debug, Serialize, Deserialize)]
pub struct CountTokensResponse {
    pub input_tokens: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_standalone_anthropic_billing_header_system_block() {
        let mut req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("hello"),
            }],
            stream: false,
            system: Some(vec![
                SystemMessage {
                    text: "x-anthropic-billing-header: cc_version=2.1.87.1; cch=aaaa;".to_string(),
                    cache_control: None,
                },
                SystemMessage {
                    text: "stable system prompt".to_string(),
                    cache_control: None,
                },
            ]),
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        assert_eq!(req.strip_anthropic_billing_headers(), 1);
        let system = req.system.expect("stable system prompt should remain");
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].text, "stable system prompt");
    }

    #[test]
    fn strips_billing_header_line_without_dropping_other_text() {
        let stripped = strip_anthropic_billing_header_text(
            "  X-Anthropic-Billing-Header: cc_version=2.1.87.42; cch=bbbb;\nreal prompt",
        );

        assert_eq!(stripped.as_deref(), Some("real prompt"));
    }

    #[test]
    fn preserves_cache_control_when_stripping_billing_header_line() {
        let mut system = Some(vec![SystemMessage {
            text: "x-anthropic-billing-header: cc_version=2.1.87.42; cch=bbbb;\nreal prompt"
                .to_string(),
            cache_control: Some(CacheControl {
                cache_type: "ephemeral".to_string(),
                ttl: None,
            }),
        }]);

        assert_eq!(strip_anthropic_billing_headers_from_system(&mut system), 1);
        let system = system.expect("system prompt should remain");
        assert_eq!(system[0].text, "real prompt");
        assert_eq!(
            system[0]
                .cache_control
                .as_ref()
                .map(|cache_control| cache_control.cache_type.as_str()),
            Some("ephemeral")
        );
    }

    #[test]
    fn preserves_non_billing_system_text() {
        let text = "please mention x-anthropic-billing-header: literally";

        assert_eq!(
            strip_anthropic_billing_header_text(text).as_deref(),
            Some(text)
        );
    }

    #[test]
    fn claude_code_prompt_filter_only_matches_safe_prefixes() {
        assert!(is_claude_code_filtered_prompt_text(
            "  x-anthropic-billing-header: cc_version=2.1.87.42"
        ));
        assert!(!is_claude_code_filtered_prompt_text(
            "please keep x-anthropic-billing-header: as literal text"
        ));
    }
}
