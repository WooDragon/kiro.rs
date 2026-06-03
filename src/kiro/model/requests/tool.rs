//! 工具类型定义
//!
//! 定义 Kiro API 中工具相关的类型

use serde::{Deserialize, Serialize};

/// 空成功结果的占位符。
/// 规避 Kiro 上游对空 `{"text":""}` tool_result 的 validation 400；
/// 为系统兜底注解，非工具真实输出。
const EMPTY_RESULT_PLACEHOLDER: &str = "(empty result)";

/// 空错误消息的占位符。
/// 规避 Kiro 上游对空 `{"text":""}` tool_result 的 validation 400；
/// 与 EMPTY_RESULT_PLACEHOLDER 使用不同文案，便于模型区分成功与错误语义。
const EMPTY_ERROR_PLACEHOLDER: &str = "(tool returned no error message)";

/// 工具定义
///
/// 用于在请求中定义可用的工具
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// 工具规范
    pub tool_specification: ToolSpecification,
}

/// 工具规范
///
/// 定义工具的名称、描述和输入模式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpecification {
    /// 工具名称
    pub name: String,
    /// 工具描述
    pub description: String,
    /// 输入模式（JSON Schema）
    pub input_schema: InputSchema,
}

/// 输入模式
///
/// 包装 JSON Schema 定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSchema {
    /// JSON Schema 定义
    pub json: serde_json::Value,
}

impl Default for InputSchema {
    fn default() -> Self {
        Self {
            json: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        }
    }
}

impl InputSchema {
    /// 从 JSON 值创建
    pub fn from_json(json: serde_json::Value) -> Self {
        Self { json }
    }
}

/// 工具执行结果
///
/// 用于返回工具执行的结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    /// 工具使用 ID（与请求中的 tool_use_id 对应）
    pub tool_use_id: String,
    /// 结果内容（数组格式）
    pub content: Vec<serde_json::Map<String, serde_json::Value>>,
    /// 执行状态（"success" 或 "error"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// 是否为错误
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_error: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ToolResult {
    /// 创建成功的工具结果。
    ///
    /// # 参数
    /// * `tool_use_id` - 与请求中 tool_use_id 对应的 ID
    /// * `content` - 工具执行的输出内容；若为空或纯空白，自动替换为
    ///   `EMPTY_RESULT_PLACEHOLDER`，规避 Kiro 上游对空 text 的 400 校验。
    ///   **非空内容绝不改写**，防止过度替换。
    pub fn success(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        let raw: String = content.into();
        // 覆盖空串 + 纯空白两种情况，非空则原样保留
        let text = if raw.trim().is_empty() {
            EMPTY_RESULT_PLACEHOLDER.to_string()
        } else {
            raw
        };

        let mut map = serde_json::Map::new();
        map.insert("text".to_string(), serde_json::Value::String(text));

        Self {
            tool_use_id: tool_use_id.into(),
            content: vec![map],
            status: Some("success".to_string()),
            is_error: false,
        }
    }

    /// 创建错误的工具结果。
    ///
    /// # 参数
    /// * `tool_use_id` - 与请求中 tool_use_id 对应的 ID
    /// * `error_message` - 工具返回的错误信息；若为空或纯空白，自动替换为
    ///   `EMPTY_ERROR_PLACEHOLDER`，规避 Kiro 上游对空 text 的 400 校验。
    ///   **非空内容绝不改写**，防止过度替换。
    pub fn error(tool_use_id: impl Into<String>, error_message: impl Into<String>) -> Self {
        let raw: String = error_message.into();
        // 覆盖空串 + 纯空白两种情况，非空则原样保留
        let text = if raw.trim().is_empty() {
            EMPTY_ERROR_PLACEHOLDER.to_string()
        } else {
            raw
        };

        let mut map = serde_json::Map::new();
        map.insert("text".to_string(), serde_json::Value::String(text));

        Self {
            tool_use_id: tool_use_id.into(),
            content: vec![map],
            status: Some("error".to_string()),
            is_error: true,
        }
    }
}

/// 工具使用条目
///
/// 用于历史消息中记录工具调用
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolUseEntry {
    /// 工具使用 ID
    pub tool_use_id: String,
    /// 工具名称
    pub name: String,
    /// 工具输入参数
    pub input: serde_json::Value,
}

impl ToolUseEntry {
    /// 创建新的工具使用条目
    pub fn new(tool_use_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            tool_use_id: tool_use_id.into(),
            name: name.into(),
            input: serde_json::json!({}),
        }
    }

    /// 设置输入参数
    pub fn with_input(mut self, input: serde_json::Value) -> Self {
        self.input = input;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success("tool-123", "Operation completed");

        assert!(!result.is_error);
        assert_eq!(result.status, Some("success".to_string()));
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error("tool-456", "File not found");

        assert!(result.is_error);
        assert_eq!(result.status, Some("error".to_string()));
    }

    #[test]
    fn test_tool_result_serialize() {
        let result = ToolResult::success("tool-789", "Done");
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"toolUseId\":\"tool-789\""));
        assert!(json.contains("\"status\":\"success\""));
        // is_error = false 应该被跳过
        assert!(!json.contains("isError"));
    }

    // ── P0-2：空 tool_result fallback 测试 ──────────────────────────────────

    /// T-P02-01：success() 空串 → 占位符
    #[test]
    fn test_success_empty_string_uses_placeholder() {
        let result = ToolResult::success("id-1", "");
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, EMPTY_RESULT_PLACEHOLDER);
    }

    /// T-P02-02：success() 纯空白 → 占位符
    #[test]
    fn test_success_whitespace_only_uses_placeholder() {
        let result = ToolResult::success("id-2", "   \t\n  ");
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, EMPTY_RESULT_PLACEHOLDER);
    }

    /// T-P02-03：error() 空串 → 不同占位符
    #[test]
    fn test_error_empty_string_uses_placeholder() {
        let result = ToolResult::error("id-3", "");
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, EMPTY_ERROR_PLACEHOLDER);
    }

    /// T-P02-04：error() 纯空白 → 不同占位符
    #[test]
    fn test_error_whitespace_only_uses_placeholder() {
        let result = ToolResult::error("id-4", "  \n  ");
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, EMPTY_ERROR_PLACEHOLDER);
    }

    /// T-P02-05：success() 和 error() 占位符文案必须不同（便于模型区分语义）
    #[test]
    fn test_success_and_error_placeholders_are_different() {
        assert_ne!(
            EMPTY_RESULT_PLACEHOLDER, EMPTY_ERROR_PLACEHOLDER,
            "成功与错误占位符必须使用不同文案"
        );
    }

    /// T-P02-06：success() 非空内容不被改写（防过度替换）
    #[test]
    fn test_success_nonempty_content_not_overwritten() {
        let original = "some tool output";
        let result = ToolResult::success("id-5", original);
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, original, "非空内容不应被占位符覆盖");
    }

    /// T-P02-07：error() 非空内容不被改写（防过度替换）
    #[test]
    fn test_error_nonempty_content_not_overwritten() {
        let original = "file not found";
        let result = ToolResult::error("id-6", original);
        let text = result.content[0]["text"].as_str().unwrap();
        assert_eq!(text, original, "非空错误信息不应被占位符覆盖");
    }

    /// T-P02-08：空 success 序列化后不含 `"text":""`（Kiro 400 的根因）
    #[test]
    fn test_empty_success_serialized_has_no_empty_text() {
        let result = ToolResult::success("id-7", "");
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"text\":\"\""), "序列化结果不应含空 text");
        assert!(json.contains(EMPTY_RESULT_PLACEHOLDER));
    }

    /// T-P02-09：空 error 序列化后不含 `"text":""`（Kiro 400 的根因）
    #[test]
    fn test_empty_error_serialized_has_no_empty_text() {
        let result = ToolResult::error("id-8", "");
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"text\":\"\""), "序列化结果不应含空 text");
        assert!(json.contains(EMPTY_ERROR_PLACEHOLDER));
    }

    #[test]
    fn test_tool_use_entry() {
        let entry = ToolUseEntry::new("use-123", "read_file")
            .with_input(serde_json::json!({"path": "/test.txt"}));

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"toolUseId\":\"use-123\""));
        assert!(json.contains("\"name\":\"read_file\""));
        assert!(json.contains("\"path\":\"/test.txt\""));
    }

    #[test]
    fn test_input_schema_default() {
        let schema = InputSchema::default();
        assert_eq!(schema.json["type"], "object");
    }
}
