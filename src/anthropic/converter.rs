//! Anthropic → Kiro 协议转换器
//!
//! 负责将 Anthropic API 请求格式转换为 Kiro API 请求格式

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::kiro::model::requests::conversation::{
    AssistantMessage, ConversationState, CurrentMessage, HistoryAssistantMessage,
    HistoryUserMessage, KiroImage, Message, UserInputMessage, UserInputMessageContext, UserMessage,
};
use crate::kiro::model::requests::tool::{
    InputSchema, Tool, ToolResult, ToolSpecification, ToolUseEntry,
};
use crate::model::registry::ModelRegistry;

use super::types::{ContentBlock, MessagesRequest};

/// JSON Schema composition/reference keys that are valid without object-only fields.
///
/// "$ref" 留在此数组是历史沿留（最小化改动）：自 `should_default_to_object_type`
/// 新增显式 $ref 短路判据（`obj.contains_key("$ref")` 优先命中）后，$ref 是否
/// 出现在本数组已不影响该函数的返回结果——有 $ref 时显式判据必先短路。保留只是
/// 因为移除有风险，不代表 $ref 仍在走 composition（anyOf/oneOf/allOf）判断路径。
const COMPOSITION_SCHEMA_KEYS: &[&str] = &["anyOf", "oneOf", "allOf", "$ref"];

/// 规范化 JSON Schema，修复 MCP 工具定义中常见的类型问题
///
/// Claude Code / MCP 工具定义偶尔会出现 `required: null`、`properties: null` 等，
/// 导致上游返回 400 "Improperly formed request"。
fn normalize_json_schema(schema: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut obj) = schema else {
        return serde_json::json!({
            "type": "object",
            "properties": {}
        });
    };

    // type：只在缺失或无效时补 object，避免改变有效 schema 语义。
    // anyOf/oneOf/allOf 组合 schema 保持原样不补；但顶层裸 $ref（如 {"$ref":...,"$defs":{...}}）
    // 上游硬约束 inputSchema.json 顶层必须有 type:object，$ref 本身不提供 type，故仍需补上（issue92）。
    let has_composition = COMPOSITION_SCHEMA_KEYS
        .iter()
        .any(|key| obj.contains_key(*key));
    let schema_type = obj.get("type").and_then(|v| v.as_str());
    let type_is_valid = schema_type.is_some_and(|s| !s.is_empty());
    let mut is_object_schema = schema_type == Some("object");
    if !type_is_valid && should_default_to_object_type(&obj, has_composition) {
        obj.insert(
            "type".to_string(),
            serde_json::Value::String("object".to_string()),
        );
        is_object_schema = true;
    }

    // properties：存在但不是 object 时修复；缺失时仅为 object schema 补空对象。
    match (is_object_schema, obj.get("properties")) {
        (_, Some(serde_json::Value::Object(_))) => {}
        (_, Some(_)) | (true, None) => {
            obj.insert(
                "properties".to_string(),
                serde_json::Value::Object(serde_json::Map::new()),
            );
        }
        _ => {}
    }

    // required：Kiro 只接受非空 string 数组；空数组/非法值会导致 Improperly formed request。
    if let Some(serde_json::Value::Array(arr)) = obj.remove("required") {
        let required: Vec<_> = arr
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| serde_json::Value::String(s.to_string())))
            .collect();
        if !required.is_empty() {
            obj.insert("required".to_string(), serde_json::Value::Array(required));
        }
    }

    // additionalProperties：Kiro-Go 对应实现会递归移除该字段，避免 Kiro 400。
    obj.remove("additionalProperties");
    clean_nested_schema_fields(&mut obj);

    serde_json::Value::Object(obj)
}

fn should_default_to_object_type(
    obj: &serde_json::Map<String, serde_json::Value>,
    has_composition: bool,
) -> bool {
    // 顶层裸 $ref（如 {"$ref":"#/$defs/Root","$defs":{...}}）自身不提供 type，
    // 但上游硬约束 inputSchema.json 顶层必须有 type:object，故即使没有
    // properties/required 也要补（issue92）。anyOf/oneOf/allOf 组合 schema
    // 保持原有行为不变——那些形态本就合法地没有顶层 type。
    //
    // 若顶层同时含 $ref 与 anyOf/oneOf/allOf（极罕见的组合形态），$ref 判据
    // 优先命中、仍补 type:object，这是有意为之而非 bug：上游硬约束顶层必须
    // type:object，顶层缺 type 本就 400，此组合无论如何都要补，不存在
    // "该保持组合 schema 原样不补" 的合法诉求。
    obj.contains_key("$ref")
        || !has_composition
        || obj.contains_key("properties")
        || obj.contains_key("required")
}

fn clean_nested_schema_fields(obj: &mut serde_json::Map<String, serde_json::Value>) {
    for value in obj.values_mut() {
        match value {
            serde_json::Value::Object(child) => {
                clean_schema_fields(child);
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    if let serde_json::Value::Object(child) = item {
                        clean_schema_fields(child);
                    }
                }
            }
            _ => {}
        }
    }
}

fn clean_schema_fields(obj: &mut serde_json::Map<String, serde_json::Value>) {
    obj.remove("additionalProperties");

    if let Some(required) = obj.remove("required")
        && let serde_json::Value::Array(arr) = required
    {
        let required: Vec<_> = arr
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| serde_json::Value::String(s.to_string())))
            .collect();
        if !required.is_empty() {
            obj.insert("required".to_string(), serde_json::Value::Array(required));
        }
    }

    clean_nested_schema_fields(obj);
}

/// 追加到 Write 工具 description 末尾的内容
const WRITE_TOOL_DESCRIPTION_SUFFIX: &str = "- IMPORTANT: If the content to write exceeds 150 lines, you MUST only write the first 50 lines using this tool, then use `Edit` tool to append the remaining content in chunks of no more than 50 lines each. If needed, leave a unique placeholder to help append content. Do NOT attempt to write all content at once.";

/// 追加到 Edit 工具 description 末尾的内容
const EDIT_TOOL_DESCRIPTION_SUFFIX: &str = "- IMPORTANT: If the `new_string` content exceeds 50 lines, you MUST split it into multiple Edit calls, each replacing no more than 50 lines at a time. If used to append content, leave a unique placeholder to help append content. On the final chunk, do NOT include the placeholder.";

/// 追加到系统提示词的分块写入策略
const SYSTEM_CHUNKED_POLICY: &str = "\
When the Write or Edit tool has content size limits, always comply silently. \
Never suggest bypassing these limits via alternative tools. \
Never ask the user whether to switch approaches. \
Complete all chunked operations without commentary.";

/// tool_result 仅含图片、无文本时的占位文案。
/// 图片已 hoist 到 userInputMessage.images；此处给模型一句说明，
/// 避免 ToolResult::success 把空文本兜底成 "(empty result)"
/// 而误导模型以为工具返回空。
const TOOL_RESULT_IMAGE_PLACEHOLDER: &str =
    "[Tool returned an image; the image is attached to this message.]";

/// 转换结果
#[derive(Debug)]
pub struct ConversionResult {
    /// 转换后的 Kiro 请求
    pub conversation_state: ConversationState,
    /// 工具名称映射（短名称 → 原始名称），仅当存在超长工具名时非空
    pub tool_name_map: HashMap<String, String>,
    /// 推理配置
    pub inference_config: Option<crate::kiro::model::requests::kiro::InferenceConfig>,
    /// 稳定会话 ID：客户端显式传入的 session UUID（从 metadata.user_id 提取）。
    /// Some = 客户端确实给了稳定 session_id（可作为跨凭据缓存分桶键）；
    /// None = 无稳定 ID（随机兜底路径），此时缓存应退回 credential_id 分桶。
    /// ⚠️ 绝不能把随机 Uuid::new_v4() 当作此字段的值——每次请求新 UUID 等于每次新桶，永远 miss。
    pub stable_conversation_id: Option<String>,
    /// 模型专属请求参数（thinking、output_config）
    pub additional_model_request_fields: Option<serde_json::Value>,
}

/// 转换错误
#[derive(Debug)]
pub enum ConversionError {
    UnsupportedModel(String),
    EmptyMessages,
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConversionError::UnsupportedModel(model) => write!(f, "模型不支持: {}", model),
            ConversionError::EmptyMessages => write!(f, "消息列表为空"),
        }
    }
}

impl std::error::Error for ConversionError {}

/// 从 metadata.user_id 中提取 session UUID
///
/// 支持两种格式:
/// 1. 字符串格式: user_xxx_account__session_0b4445e1-f5be-49e1-87ce-62bbc28ad705
/// 2. JSON 格式: {"device_id":"...","account_uuid":"...","session_id":"UUID"}
///
/// 提取 session UUID 作为 conversationId
pub(crate) fn extract_session_id(user_id: &str) -> Option<String> {
    // 先尝试 JSON 解析
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(user_id)
        && let Some(session_id) = json.get("session_id").and_then(|v| v.as_str())
        && is_valid_uuid(session_id)
    {
        return Some(session_id.to_string());
    }

    // 回退到字符串格式：从右向左匹配 "_session_"（带前导下划线）。
    // 真实格式恒为 user_<hash>_account__session_<uuid>，而 <hash> 段来自外部输入
    // （例如用户名恰好含 "_session_" 字面串），从左向右 find 会在伪匹配处提前截断，
    // 拿到无效串后整体退化为随机 UUID、彻底丧失粘性（#86）。UUID 恒在字符串末尾，
    // 用 rsplit_once 从右向左匹配才与真实格式契合。
    if let Some((_, session_part)) = user_id.rsplit_once("_session_") {
        // #86 返工 MUST FIX 2：user_id 完全由客户端提供，session_part.len() 是
        // 字节数而非字符数，非 ASCII 输入（例如分隔符后紧跟 emoji）按字节 [..36]
        // 切片可能落在非字符边界，直接 panic（"byte index N is not a char
        // boundary"）。改用 get(..36) 返回 Option<&str>：非法边界时得到 None，
        // 落到下面的 None 兜底（既有的随机 UUID 兜底逻辑在调用方），从"客户端
        // 输入即可让服务端 panic"退化为"提取失败"。UUID 恒为 36 个 ASCII 字符，
        // 合法输入下 get 与切片等价，行为不变。
        if let Some(uuid_str) = session_part.get(..36)
            && is_valid_uuid(uuid_str)
        {
            return Some(uuid_str.to_string());
        }
    }
    None
}

/// 简单验证 UUID 格式（36 字符，包含 4 个连字符）
fn is_valid_uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok()
}

/// 收集历史消息中使用的所有工具名称
fn collect_history_tool_names(history: &[Message]) -> Vec<String> {
    let mut tool_names = Vec::new();

    for msg in history {
        if let Message::Assistant(assistant_msg) = msg
            && let Some(ref tool_uses) = assistant_msg.assistant_response_message.tool_uses
        {
            for tool_use in tool_uses {
                if !tool_names.contains(&tool_use.name) {
                    tool_names.push(tool_use.name.clone());
                }
            }
        }
    }

    tool_names
}

/// 为历史中使用但不在 tools 列表中的工具创建占位符定义
/// Kiro API 要求：历史消息中引用的工具必须在 currentMessage.tools 中有定义
fn create_placeholder_tool(name: &str) -> Tool {
    Tool {
        tool_specification: ToolSpecification {
            name: name.to_string(),
            description: "Tool used in conversation history".to_string(),
            input_schema: InputSchema::from_json(serde_json::json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": true
            })),
        },
    }
}

/// 将 Anthropic 请求转换为 Kiro 请求
pub fn convert_request(
    req: &MessagesRequest,
    registry: &ModelRegistry,
) -> Result<ConversionResult, ConversionError> {
    // 1. 映射模型
    let model_id = registry
        .map_model(&req.model)
        .ok_or_else(|| ConversionError::UnsupportedModel(req.model.clone()))?;

    // 2. 检查消息列表
    if req.messages.is_empty() {
        return Err(ConversionError::EmptyMessages);
    }

    // 2.5. 预处理 prefill：如果末尾是 assistant，静默丢弃并截断到最后一条 user
    // Claude 4.x 已弃用 assistant prefill，Kiro API 也不支持
    let messages: &[_] = if req.messages.last().is_some_and(|m| m.role != "user") {
        tracing::info!("检测到末尾 assistant 消息（prefill），静默丢弃");
        let last_user_idx = req
            .messages
            .iter()
            .rposition(|m| m.role == "user")
            .ok_or(ConversionError::EmptyMessages)?;
        &req.messages[..=last_user_idx]
    } else {
        &req.messages
    };

    // 3. 生成会话 ID 和代理 ID
    // 优先从 metadata.user_id 中提取 session UUID 作为 conversationId。
    // stable_conversation_id 只在客户端确实传了 session_id 时为 Some；
    // 随机兜底 UUID 仅用于 Kiro 上游请求，不透出给缓存分桶——每请求新 UUID 等于每次新桶，永远 miss。
    let stable_conversation_id: Option<String> = req
        .metadata
        .as_ref()
        .and_then(|m| m.user_id.as_ref())
        .and_then(|user_id| extract_session_id(user_id));
    let conversation_id = stable_conversation_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let agent_continuation_id = Uuid::new_v4().to_string();

    // 4. 确定触发类型
    let chat_trigger_type = determine_chat_trigger_type(req);

    // 5. 处理最后一条消息作为 current_message（经过 prefill 预处理，末尾必为 user）
    let last_message = messages.last().unwrap();
    let (text_content, images, tool_results) = process_message_content(&last_message.content)?;

    // 6. 转换工具定义（超长名称自动缩短并记录映射）
    let mut tool_name_map = HashMap::new();
    let mut tools = convert_tools(&req.tools, &mut tool_name_map);

    // 7. 构建历史消息（需要先构建，以便收集历史中使用的工具）
    let mut history = build_history(req, messages, &model_id, &mut tool_name_map)?;

    // 8. 验证并过滤 tool_use/tool_result 配对
    // 移除孤立的 tool_result（没有对应的 tool_use）
    // 同时返回孤立的 tool_use_id 集合，用于后续清理
    let (validated_tool_results, orphaned_tool_use_ids) =
        validate_tool_pairing(&history, &tool_results);

    // 9. 从历史中移除孤立的 tool_use（Kiro API 要求 tool_use 必须有对应的 tool_result）
    remove_orphaned_tool_uses(&mut history, &orphaned_tool_use_ids);

    // 10. 收集历史中使用的工具名称，为缺失的工具生成占位符定义
    // Kiro API 要求：历史消息中引用的工具必须在 tools 列表中有定义
    // 注意：Kiro 匹配工具名称时忽略大小写，所以这里也需要忽略大小写比较
    let history_tool_names = collect_history_tool_names(&history);
    let existing_tool_names: std::collections::HashSet<_> = tools
        .iter()
        .map(|t| t.tool_specification.name.to_lowercase())
        .collect();

    for tool_name in history_tool_names {
        if !existing_tool_names.contains(&tool_name.to_lowercase()) {
            tools.push(create_placeholder_tool(&tool_name));
        }
    }

    // 11. 构建 UserInputMessageContext
    let mut context = UserInputMessageContext::new();
    if !tools.is_empty() {
        context = context.with_tools(tools);
    }
    if !validated_tool_results.is_empty() {
        context = context.with_tool_results(validated_tool_results);
    }

    // 12. 构建当前消息
    // 保留文本内容，即使有工具结果也不丢弃用户文本
    let content = text_content;

    let mut user_input = UserInputMessage::new(content, &model_id)
        .with_context(context)
        .with_origin("AI_EDITOR");

    if !images.is_empty() {
        user_input = user_input.with_images(images);
    }

    let current_message = CurrentMessage::new(user_input);

    // 13. 构建 ConversationState
    let conversation_state = ConversationState::new(conversation_id)
        .with_agent_continuation_id(agent_continuation_id)
        .with_agent_task_type("vibe")
        .with_chat_trigger_type(chat_trigger_type)
        .with_current_message(current_message)
        .with_history(history);

    if !tool_name_map.is_empty() {
        tracing::info!("工具名称映射: {} 个超长名称已缩短", tool_name_map.len());
    }

    // 14. 构建 InferenceConfig
    let inference_config = if req.max_tokens > 0 || req.temperature.is_some() || req.top_p.is_some()
    {
        Some(crate::kiro::model::requests::kiro::InferenceConfig {
            max_tokens: if req.max_tokens > 0 {
                Some(req.max_tokens as u32)
            } else {
                None
            },
            temperature: req.temperature,
            top_p: req.top_p,
        })
    } else {
        None
    };

    Ok(ConversionResult {
        conversation_state,
        tool_name_map,
        inference_config,
        stable_conversation_id,
        additional_model_request_fields: build_additional_model_request_fields(req, registry),
    })
}

/// 确定聊天触发类型
/// "AUTO" 模式可能会导致 400 Bad Request 错误
fn determine_chat_trigger_type(_req: &MessagesRequest) -> String {
    "MANUAL".to_string()
}

/// 处理消息内容，提取文本、图片和工具结果
fn process_message_content(
    content: &serde_json::Value,
) -> Result<(String, Vec<KiroImage>, Vec<ToolResult>), ConversionError> {
    let mut text_parts = Vec::new();
    let mut images = Vec::new();
    let mut tool_results = Vec::new();

    match content {
        serde_json::Value::String(s) => {
            text_parts.push(s.clone());
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Ok(block) = serde_json::from_value::<ContentBlock>(item.clone()) {
                    match block.block_type.as_str() {
                        "text" => {
                            if let Some(text) = block.text {
                                text_parts.push(text);
                            }
                        }
                        "image" => {
                            if let Some(source) = block.source
                                && let Some(format) = get_image_format(&source.media_type)
                            {
                                images.push(KiroImage::from_base64(format, source.data));
                            }
                        }
                        "tool_result" => {
                            if let Some(tool_use_id) = block.tool_use_id {
                                let (mut result_content, result_images) =
                                    extract_tool_result_content(&block.content);
                                let is_error = block.is_error.unwrap_or(false);

                                // 图片 hoist 到当轮 userInputMessage.images（复用 user 贴图路径）；
                                // 仅 success 场景在空文本时写图片占位，避免 ToolResult::success 兜底成
                                // "(empty result)" 误导模型以为工具返回空；error 场景保持空文本，
                                // 让 ToolResult::error 用其专用占位符，不丢 error 语义
                                // （两种场景都 hoist 图片）
                                if !result_images.is_empty() {
                                    if !is_error && result_content.trim().is_empty() {
                                        result_content = TOOL_RESULT_IMAGE_PLACEHOLDER.to_string();
                                    }
                                    images.extend(result_images);
                                }

                                let mut result = if is_error {
                                    ToolResult::error(&tool_use_id, result_content)
                                } else {
                                    ToolResult::success(&tool_use_id, result_content)
                                };
                                result.status =
                                    Some(if is_error { "error" } else { "success" }.to_string());

                                tool_results.push(result);
                            }
                        }
                        "tool_use" => {
                            // tool_use 在 assistant 消息中处理，这里忽略
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    Ok((text_parts.join("\n"), images, tool_results))
}

/// 从 media_type 获取图片格式
fn get_image_format(media_type: &str) -> Option<String> {
    match media_type {
        "image/jpeg" => Some("jpeg".to_string()),
        "image/png" => Some("png".to_string()),
        "image/gif" => Some("gif".to_string()),
        "image/webp" => Some("webp".to_string()),
        _ => None,
    }
}

/// 提取工具结果内容，同时将 image block 提取为 KiroImage 列表
///
/// # 参数
/// * `content` - tool_result 的 content 字段（可为字符串、数组或 None）
///
/// # 返回
/// `(文本内容, 图片列表)`：文本供写入 ToolResult，图片 hoist 到 userInputMessage.images
fn extract_tool_result_content(content: &Option<serde_json::Value>) -> (String, Vec<KiroImage>) {
    let mut images = Vec::new();
    let text = match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            let mut parts = Vec::new();
            for item in arr {
                if let Some(t) = item.get("text").and_then(|v| v.as_str()) {
                    // 文本 block：拼入文本
                    parts.push(t.to_string());
                } else if item.get("type").and_then(|v| v.as_str()) == Some("image")
                    && let Some(img) = extract_image_from_json(item)
                {
                    // image block：提取图片（复用 user 贴图路径 get_image_format）
                    images.push(img);
                }
                // 其他未知 block 类型：静默跳过，与 user 贴图路径一致
            }
            parts.join("\n")
        }
        Some(v) => v.to_string(),
        None => String::new(),
    };
    (text, images)
}

/// 从 tool_result content 的 image block（动态 JSON）提取 KiroImage
///
/// # 参数
/// * `item` - 形如 `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"..."}}` 的 JSON
///
/// # 返回
/// `Some(KiroImage)` 若字段完整且 media_type 受支持，否则 `None`（静默跳过）
fn extract_image_from_json(item: &serde_json::Value) -> Option<KiroImage> {
    let source = item.get("source")?;
    let media_type = source.get("media_type").and_then(|v| v.as_str())?;
    let format = get_image_format(media_type)?; // media_type 不支持时返回 None，静默跳过
    let data = source.get("data").and_then(|v| v.as_str())?;
    Some(KiroImage::from_base64(format, data))
}

/// 验证并过滤 tool_use/tool_result 配对
///
/// 收集所有 tool_use_id，验证 tool_result 是否匹配
/// 静默跳过孤立的 tool_use 和 tool_result，输出警告日志
///
/// # Arguments
/// * `history` - 历史消息引用
/// * `tool_results` - 当前消息中的 tool_result 列表
///
/// # Returns
/// 元组：(经过验证和过滤后的 tool_result 列表, 孤立的 tool_use_id 集合)
fn validate_tool_pairing(
    history: &[Message],
    tool_results: &[ToolResult],
) -> (Vec<ToolResult>, std::collections::HashSet<String>) {
    use std::collections::HashSet;

    // 1. 收集所有历史中的 tool_use_id
    let mut all_tool_use_ids: HashSet<String> = HashSet::new();
    // 2. 收集历史中已经有 tool_result 的 tool_use_id
    let mut history_tool_result_ids: HashSet<String> = HashSet::new();

    for msg in history {
        match msg {
            Message::Assistant(assistant_msg) => {
                if let Some(ref tool_uses) = assistant_msg.assistant_response_message.tool_uses {
                    for tool_use in tool_uses {
                        all_tool_use_ids.insert(tool_use.tool_use_id.clone());
                    }
                }
            }
            Message::User(user_msg) => {
                // 收集历史 user 消息中的 tool_results
                for result in &user_msg
                    .user_input_message
                    .user_input_message_context
                    .tool_results
                {
                    history_tool_result_ids.insert(result.tool_use_id.clone());
                }
            }
        }
    }

    // 3. 计算真正未配对的 tool_use_ids（排除历史中已配对的）
    let mut unpaired_tool_use_ids: HashSet<String> = all_tool_use_ids
        .difference(&history_tool_result_ids)
        .cloned()
        .collect();

    // 4. 过滤并验证当前消息的 tool_results
    let mut filtered_results = Vec::new();

    for result in tool_results {
        if unpaired_tool_use_ids.contains(&result.tool_use_id) {
            // 配对成功
            filtered_results.push(result.clone());
            unpaired_tool_use_ids.remove(&result.tool_use_id);
        } else if all_tool_use_ids.contains(&result.tool_use_id) {
            // tool_use 存在但已经在历史中配对过了，这是重复的 tool_result
            tracing::warn!(
                "跳过重复的 tool_result：该 tool_use 已在历史中配对，tool_use_id={}",
                result.tool_use_id
            );
        } else {
            // 孤立 tool_result - 找不到对应的 tool_use
            tracing::warn!(
                "跳过孤立的 tool_result：找不到对应的 tool_use，tool_use_id={}",
                result.tool_use_id
            );
        }
    }

    // 5. 检测真正孤立的 tool_use（有 tool_use 但在历史和当前消息中都没有 tool_result）
    for orphaned_id in &unpaired_tool_use_ids {
        tracing::warn!(
            "检测到孤立的 tool_use：找不到对应的 tool_result，将从历史中移除，tool_use_id={}",
            orphaned_id
        );
    }

    (filtered_results, unpaired_tool_use_ids)
}

/// 从历史消息中移除孤立的 tool_use
///
/// Kiro API 要求每个 tool_use 必须有对应的 tool_result，否则返回 400 Bad Request。
/// 此函数遍历历史中的 assistant 消息，移除没有对应 tool_result 的 tool_use。
///
/// # Arguments
/// * `history` - 可变的历史消息列表
/// * `orphaned_ids` - 需要移除的孤立 tool_use_id 集合
fn remove_orphaned_tool_uses(
    history: &mut [Message],
    orphaned_ids: &std::collections::HashSet<String>,
) {
    if orphaned_ids.is_empty() {
        return;
    }

    for msg in history.iter_mut() {
        if let Message::Assistant(assistant_msg) = msg
            && let Some(ref mut tool_uses) = assistant_msg.assistant_response_message.tool_uses
        {
            let original_len = tool_uses.len();
            tool_uses.retain(|tu| !orphaned_ids.contains(&tu.tool_use_id));

            // 如果移除后为空，设置为 None
            if tool_uses.is_empty() {
                assistant_msg.assistant_response_message.tool_uses = None;
            } else if tool_uses.len() != original_len {
                tracing::debug!(
                    "从 assistant 消息中移除了 {} 个孤立的 tool_use",
                    original_len - tool_uses.len()
                );
            }
        }
    }
}

/// Kiro API 工具名称最大长度限制
const TOOL_NAME_MAX_LEN: usize = 63;

/// 生成确定性短名称：截断前缀 + "_" + 8 位 SHA256 hex
fn shorten_tool_name(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let hash_hex = format!("{:x}", hasher.finalize());
    let hash_suffix = &hash_hex[..8];
    // 54 prefix + 1 underscore + 8 hash = 63
    let prefix_max = TOOL_NAME_MAX_LEN - 1 - 8;
    let prefix = match name.char_indices().nth(prefix_max) {
        Some((idx, _)) => &name[..idx],
        None => name,
    };
    format!("{}_{}", prefix, hash_suffix)
}

/// 如果名称超长则缩短，并记录映射（short → original）
fn map_tool_name(name: &str, tool_name_map: &mut HashMap<String, String>) -> String {
    if name.len() <= TOOL_NAME_MAX_LEN {
        return name.to_string();
    }
    let short = shorten_tool_name(name);
    tool_name_map.insert(short.clone(), name.to_string());
    short
}

/// 转换工具定义
fn convert_tools(
    tools: &Option<Vec<super::types::Tool>>,
    tool_name_map: &mut HashMap<String, String>,
) -> Vec<Tool> {
    let Some(tools) = tools else {
        return Vec::new();
    };

    tools
        .iter()
        .map(|t| {
            let mut description = t.description.clone();

            // 对 Write/Edit 工具追加自定义描述后缀
            let suffix = match t.name.as_str() {
                "Write" => WRITE_TOOL_DESCRIPTION_SUFFIX,
                "Edit" => EDIT_TOOL_DESCRIPTION_SUFFIX,
                _ => "",
            };
            if !suffix.is_empty() {
                description.push('\n');
                description.push_str(suffix);
            }

            // 限制描述长度为 10000 字符（安全截断 UTF-8）。
            // fast-path：字节数 <= 10000 时字符数必 <= 10000（UTF-8 每字符 >= 1 字节），
            // 直接跳过 O(N) 字符边界迭代——正常工具描述远短于此，热点通路省迭代。
            let mut description = if description.len() > 10000 {
                match description.char_indices().nth(10000) {
                    Some((idx, _)) => description[..idx].to_string(),
                    None => description,
                }
            } else {
                description
            };

            // 空 description 兜底：上游 Kiro/Bedrock 的 toolSpecification.description
            // 是硬约束（length >= 1），空字符串会让整个请求被 400 拒绝（#46）。
            // 填充 `Tool: {name}` 占位（非纯空格/标点，避免诱导退化，参 #26），
            // 不删字段（删字段同样过不了非空校验）、不删工具（会让历史中已有的
            // tool_use 落单，撞 validate_tool_pairing 反而 400）。
            let mapped_name = map_tool_name(&t.name, tool_name_map);
            if description.trim().is_empty() {
                description = format!("Tool: {}", mapped_name);
            }

            Tool {
                tool_specification: ToolSpecification {
                    name: mapped_name,
                    description,
                    input_schema: InputSchema::from_json(normalize_json_schema(serde_json::json!(
                        t.input_schema
                    ))),
                },
            }
        })
        .collect()
}

/// 构建结构化 `additionalModelRequestFields`（thinking + effort 透传）
///
/// 判据同样改为模型配置 thinking_type。上游对 adaptive + budget_tokens 宽容无视
/// （黑盒探针 C 实测四臂全 200），故构造 payload 时不引用 budget_tokens；
/// 若客户端原始请求带了 thinking 字段（非 disabled），打 WARN 提示 budget_tokens
/// 被忽略，不静默吞（分支 a）。
fn build_additional_model_request_fields(
    req: &MessagesRequest,
    registry: &ModelRegistry,
) -> Option<serde_json::Value> {
    // disabled 优先级最高：客户端主动关闭 thinking，任何配置下都不产结构化字段。
    if req
        .thinking
        .as_ref()
        .is_some_and(|t| t.thinking_type == "disabled")
    {
        return None;
    }

    let config = registry.thinking_config(&req.model);
    if config.thinking_type != "adaptive" {
        return None;
    }

    // budget_tokens 在 adaptive 下被上游忽略（成本由 effort 控制）是设计预期的正常行为，
    // 非异常——CC 每个标准 enabled 请求都带 budget_tokens，故此处必须 debug 而非 warn，
    // 否则每个真实请求刷一条 warn（与 #56/#58 治日志刷屏取向冲突）。排障时可开 debug 观测。
    if let Some(t) = &req.thinking {
        tracing::debug!(
            model = %req.model,
            budget_tokens = t.budget_tokens,
            "adaptive 模式下 budget_tokens 被忽略，成本由 effort 控制"
        );
    }

    let effort = req
        .output_config
        .as_ref()
        .map(|c| c.effort.clone())
        .or_else(|| config.effort.clone())
        .unwrap_or_else(|| "high".to_string());

    Some(serde_json::json!({
        "thinking": { "type": "adaptive" },
        "output_config": { "effort": effort }
    }))
}

/// 构建历史消息
///
/// # Arguments
/// * `req` - 原始请求，用于读取 `system` 字段
/// * `messages` - 经过 prefill 预处理的消息切片，末尾必定是 user 消息。
///   注意：该切片与 `req.messages` 可能不同（prefill 时会截断末尾的 assistant 消息），
///   调用方应始终使用此参数而非 `req.messages`。
/// * `model_id` - 已映射的 Kiro 模型 ID
///
/// # Returns
/// 构建好的历史消息列表。
fn build_history(
    req: &MessagesRequest,
    messages: &[super::types::Message],
    model_id: &str,
    tool_name_map: &mut HashMap<String, String>,
) -> Result<Vec<Message>, ConversionError> {
    let mut history = Vec::new();

    // 1. 处理系统消息
    if let Some(ref system) = req.system {
        let system_content: String = system
            .iter()
            .filter_map(|s| s.without_anthropic_billing_headers())
            .map(|s| s.text)
            .collect::<Vec<_>>()
            .join("\n");

        if !system_content.is_empty() {
            // 追加分块写入策略到系统消息
            let system_content = format!("{}\n{}", system_content, SYSTEM_CHUNKED_POLICY);

            // 系统消息作为 user + assistant 配对注入 history 首部
            let user_msg = HistoryUserMessage::new(system_content, model_id);
            history.push(Message::User(user_msg));

            let assistant_msg = HistoryAssistantMessage::new("I will follow these instructions.");
            history.push(Message::Assistant(assistant_msg));
        }
    }

    // 2. 处理常规消息历史
    // 最后一条消息作为 currentMessage，不加入历史
    // 经过 prefill 预处理后，messages 末尾必定是 user，故直接截掉最后一条即可
    let history_end_index = messages.len().saturating_sub(1);

    // 收集并配对消息
    let mut user_buffer: Vec<&super::types::Message> = Vec::new();
    let mut assistant_buffer: Vec<&super::types::Message> = Vec::new();

    for msg in messages.iter().take(history_end_index) {
        if msg.role == "user" {
            // 先处理累积的 assistant 消息
            if !assistant_buffer.is_empty() {
                let merged = merge_assistant_messages(&assistant_buffer, tool_name_map)?;
                history.push(Message::Assistant(merged));
                assistant_buffer.clear();
            }
            user_buffer.push(msg);
        } else if msg.role == "assistant" {
            // 先处理累积的 user 消息
            if !user_buffer.is_empty() {
                let merged_user = merge_user_messages(&user_buffer, model_id)?;
                history.push(Message::User(merged_user));
                user_buffer.clear();
            }
            // 累积 assistant 消息（支持连续多条）
            assistant_buffer.push(msg);
        }
    }

    // 处理末尾累积的 assistant 消息
    if !assistant_buffer.is_empty() {
        let merged = merge_assistant_messages(&assistant_buffer, tool_name_map)?;
        history.push(Message::Assistant(merged));
    }

    // 处理结尾的孤立 user 消息
    if !user_buffer.is_empty() {
        let merged_user = merge_user_messages(&user_buffer, model_id)?;
        history.push(Message::User(merged_user));

        // 自动配对一个 "OK" 的 assistant 响应
        let auto_assistant = HistoryAssistantMessage::new("OK");
        history.push(Message::Assistant(auto_assistant));
    }

    Ok(history)
}

/// 合并多个 user 消息
fn merge_user_messages(
    messages: &[&super::types::Message],
    model_id: &str,
) -> Result<HistoryUserMessage, ConversionError> {
    let mut content_parts = Vec::new();
    let mut all_images = Vec::new();
    let mut all_tool_results = Vec::new();

    for msg in messages {
        let (text, images, tool_results) = process_message_content(&msg.content)?;
        if !text.is_empty() {
            content_parts.push(text);
        }
        all_images.extend(images);
        all_tool_results.extend(tool_results);
    }

    let content = content_parts.join("\n");
    // 保留文本内容，即使有工具结果也不丢弃用户文本
    let mut user_msg = UserMessage::new(&content, model_id);

    if !all_images.is_empty() {
        user_msg = user_msg.with_images(all_images);
    }

    if !all_tool_results.is_empty() {
        let mut ctx = UserInputMessageContext::new();
        ctx = ctx.with_tool_results(all_tool_results);
        user_msg = user_msg.with_context(ctx);
    }

    Ok(HistoryUserMessage {
        user_input_message: user_msg,
    })
}

/// 转换 assistant 消息
fn convert_assistant_message(
    msg: &super::types::Message,
    tool_name_map: &mut HashMap<String, String>,
) -> Result<HistoryAssistantMessage, ConversionError> {
    let mut thinking_content = String::new();
    let mut text_content = String::new();
    let mut tool_uses = Vec::new();

    match &msg.content {
        serde_json::Value::String(s) => {
            text_content = s.clone();
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Ok(block) = serde_json::from_value::<ContentBlock>(item.clone()) {
                    match block.block_type.as_str() {
                        "thinking" => {
                            if let Some(thinking) = block.thinking {
                                thinking_content.push_str(&thinking);
                            }
                        }
                        "text" => {
                            if let Some(text) = block.text {
                                text_content.push_str(&text);
                            }
                        }
                        "tool_use" => {
                            if let (Some(id), Some(name)) = (block.id, block.name) {
                                let input = block.input.unwrap_or(serde_json::json!({}));
                                let mapped_name = map_tool_name(&name, tool_name_map);
                                tool_uses
                                    .push(ToolUseEntry::new(id, mapped_name).with_input(input));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }

    super::tool_call_leak::strip_leaked_tool_call_xml(&mut text_content);

    // 组合 thinking 和 text 内容
    // 格式: <thinking>思考内容</thinking>\n\ntext内容
    // 纯 tool_use 轮 content 留空串：对齐 kiro2api（content 无 omitempty → "content":""）
    // 不再注入空格占位符——空壳轮会诱导模型只回空格/句号（见 #26）
    let final_content = if !thinking_content.is_empty() {
        if !text_content.is_empty() {
            format!(
                "<thinking>{}</thinking>\n\n{}",
                thinking_content, text_content
            )
        } else {
            format!("<thinking>{}</thinking>", thinking_content)
        }
    } else {
        text_content
    };

    let mut assistant = AssistantMessage::new(final_content);
    if !tool_uses.is_empty() {
        assistant = assistant.with_tool_uses(tool_uses);
    }

    Ok(HistoryAssistantMessage {
        assistant_response_message: assistant,
    })
}

/// 合并多个连续的 assistant 消息为一条
/// 用于处理网络不稳定时产生的连续 assistant 消息（Issue #79）
fn merge_assistant_messages(
    messages: &[&super::types::Message],
    tool_name_map: &mut HashMap<String, String>,
) -> Result<HistoryAssistantMessage, ConversionError> {
    assert!(!messages.is_empty());
    if messages.len() == 1 {
        return convert_assistant_message(messages[0], tool_name_map);
    }

    let mut all_tool_uses: Vec<ToolUseEntry> = Vec::new();
    let mut content_parts: Vec<String> = Vec::new();

    for msg in messages {
        let converted = convert_assistant_message(msg, tool_name_map)?;
        let am = converted.assistant_response_message;
        if !am.content.trim().is_empty() {
            content_parts.push(am.content);
        }
        if let Some(tus) = am.tool_uses {
            all_tool_uses.extend(tus);
        }
    }

    // 空壳不注入占位符（#26）；上方已过滤空白子消息，join 不会产生多余换行
    let content = content_parts.join("\n\n");

    let mut assistant = AssistantMessage::new(content);
    if !all_tool_uses.is_empty() {
        assistant = assistant.with_tool_uses(all_tool_uses);
    }
    Ok(HistoryAssistantMessage {
        assistant_response_message: assistant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::registry::ModelRegistry;

    fn test_registry() -> ModelRegistry {
        ModelRegistry::from_toml(include_str!("../../models.toml")).unwrap()
    }

    #[test]
    fn test_map_model_sonnet() {
        let registry = test_registry();
        assert!(
            registry
                .map_model("claude-sonnet-4-20250514")
                .unwrap()
                .contains("sonnet")
        );
        assert!(
            registry
                .map_model("claude-3-5-sonnet-20241022")
                .unwrap()
                .contains("sonnet")
        );
    }

    #[test]
    fn test_map_model_opus() {
        let registry = test_registry();
        assert!(
            registry
                .map_model("claude-opus-4-20250514")
                .unwrap()
                .contains("opus")
        );
    }

    #[test]
    fn test_map_model_haiku() {
        let registry = test_registry();
        assert!(
            registry
                .map_model("claude-haiku-4-20250514")
                .unwrap()
                .contains("haiku")
        );
    }

    #[test]
    fn test_map_model_unsupported() {
        let registry = test_registry();
        assert!(registry.map_model("gpt-4").is_none());
    }

    #[test]
    fn test_map_model_thinking_suffix_sonnet() {
        let registry = test_registry();
        // thinking 后缀不应影响 sonnet 模型映射
        let result = registry.map_model("claude-sonnet-4-5-20250929-thinking");
        assert_eq!(result, Some("claude-sonnet-4.5".to_string()));
    }

    #[test]
    fn test_map_model_thinking_suffix_opus_4_5() {
        let registry = test_registry();
        // thinking 后缀不应影响 opus 4.5 模型映射
        let result = registry.map_model("claude-opus-4-5-20251101-thinking");
        assert_eq!(result, Some("claude-opus-4.5".to_string()));
    }

    #[test]
    fn test_map_model_thinking_suffix_opus_4_6() {
        let registry = test_registry();
        // thinking 后缀不应影响 opus 4.6 模型映射
        let result = registry.map_model("claude-opus-4-6-thinking");
        assert_eq!(result, Some("claude-opus-4.6".to_string()));
    }

    #[test]
    fn test_map_model_opus_4_7() {
        let registry = test_registry();
        let result = registry.map_model("claude-opus-4-7-thinking");
        assert_eq!(result, Some("claude-opus-4.7".to_string()));

        let dotted = registry.map_model("claude-opus-4.7");
        assert_eq!(dotted, Some("claude-opus-4.7".to_string()));
    }

    #[test]
    fn test_map_model_opus_4_8() {
        let registry = test_registry();
        let result = registry.map_model("claude-opus-4-8-thinking");
        assert_eq!(result, Some("claude-opus-4.8".to_string()));

        let dotted = registry.map_model("claude-opus-4.8");
        assert_eq!(dotted, Some("claude-opus-4.8".to_string()));
    }

    #[test]
    fn test_map_model_other_opus_defaults_to_4_6() {
        let registry = test_registry();
        let result = registry.map_model("claude-opus-4-20250514");
        assert_eq!(result, Some("claude-opus-4.6".to_string()));
    }

    #[test]
    fn test_context_window_opus_4_7() {
        let registry = test_registry();
        assert_eq!(registry.context_window("claude-opus-4-7"), 1_000_000);
    }

    #[test]
    fn test_context_window_opus_4_8() {
        let registry = test_registry();
        assert_eq!(registry.context_window("claude-opus-4-8"), 1_000_000);
    }

    #[test]
    fn test_map_model_thinking_suffix_haiku() {
        let registry = test_registry();
        // thinking 后缀不应影响 haiku 模型映射
        let result = registry.map_model("claude-haiku-4-5-20251001-thinking");
        assert_eq!(result, Some("claude-haiku-4.5".to_string()));
    }

    #[test]
    fn test_determine_chat_trigger_type() {
        // 无工具时返回 MANUAL
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };
        assert_eq!(determine_chat_trigger_type(&req), "MANUAL");
    }

    #[test]
    fn test_convert_request_strips_anthropic_billing_header_system_block() {
        use super::super::types::{Message as AnthropicMessage, SystemMessage};

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
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

        let result = convert_request(&req, &test_registry()).expect("request should convert");
        let system_history = match &result.conversation_state.history[0] {
            Message::User(msg) => &msg.user_input_message.content,
            _ => panic!("expected system prompt to be converted as user history"),
        };

        assert!(!system_history.contains("x-anthropic-billing-header"));
        assert!(!system_history.contains("cch=aaaa"));
        assert!(system_history.contains("stable system prompt"));
    }

    #[test]
    fn test_convert_request_strips_leaked_xml_from_history() {
        use super::super::types::{Message as AnthropicMessage, SystemMessage};

        let req = MessagesRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 4096,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("hello"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!(
                        "分析完成\n<invoke name=\"Bash\">\n<parameter name=\"command\">ls</parameter>\n</invoke>"
                    ),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("继续"),
                },
            ],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).expect("request should convert");

        let assistant_content = result
            .conversation_state
            .history
            .iter()
            .find_map(|msg| match msg {
                Message::Assistant(am) => Some(&am.assistant_response_message.content),
                _ => None,
            })
            .expect("history should contain an assistant turn");

        assert!(
            !assistant_content.contains("<invoke"),
            "leaked tool call XML should be stripped from history, got: {}",
            assistant_content
        );
        assert!(
            assistant_content.contains("分析完成"),
            "legitimate text should be preserved, got: {}",
            assistant_content
        );
    }

    #[test]
    fn test_collect_history_tool_names() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 创建包含工具使用的历史消息
        let mut assistant_msg = AssistantMessage::new("I'll read the file.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read")
                .with_input(serde_json::json!({"path": "/test.txt"})),
            ToolUseEntry::new("tool-2", "write")
                .with_input(serde_json::json!({"path": "/out.txt"})),
        ]);

        let history = vec![
            Message::User(HistoryUserMessage::new(
                "Read the file",
                "claude-sonnet-4.5",
            )),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        let tool_names = collect_history_tool_names(&history);
        assert_eq!(tool_names.len(), 2);
        assert!(tool_names.contains(&"read".to_string()));
        assert!(tool_names.contains(&"write".to_string()));
    }

    #[test]
    fn test_create_placeholder_tool() {
        let tool = create_placeholder_tool("my_custom_tool");

        assert_eq!(tool.tool_specification.name, "my_custom_tool");
        assert!(!tool.tool_specification.description.is_empty());

        // 验证 JSON 序列化正确
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"name\":\"my_custom_tool\""));
    }

    #[test]
    fn test_shorten_tool_name_deterministic() {
        let long_name =
            "mcp__some_very_long_server_name__some_very_long_tool_name_that_exceeds_limit";
        assert!(long_name.len() > TOOL_NAME_MAX_LEN);

        let short1 = shorten_tool_name(long_name);
        let short2 = shorten_tool_name(long_name);
        assert_eq!(short1, short2, "相同输入应产生相同的短名称");
        assert!(
            short1.len() <= TOOL_NAME_MAX_LEN,
            "短名称长度应 <= 63，实际 {}",
            short1.len()
        );
    }

    #[test]
    fn test_shorten_tool_name_uniqueness() {
        let name_a = "mcp__server_alpha__tool_name_that_is_very_long_and_exceeds_the_limit_a";
        let name_b = "mcp__server_alpha__tool_name_that_is_very_long_and_exceeds_the_limit_b";
        let short_a = shorten_tool_name(name_a);
        let short_b = shorten_tool_name(name_b);
        assert_ne!(short_a, short_b, "不同输入应产生不同的短名称");
    }

    #[test]
    fn test_map_tool_name_short_passthrough() {
        let mut map = HashMap::new();
        let result = map_tool_name("short_name", &mut map);
        assert_eq!(result, "short_name");
        assert!(map.is_empty(), "短名称不应产生映射");
    }

    #[test]
    fn test_map_tool_name_long_creates_mapping() {
        let mut map = HashMap::new();
        let long_name = "mcp__plugin_very_long_server_name__extremely_long_tool_name_exceeds_63";
        let result = map_tool_name(long_name, &mut map);
        assert!(result.len() <= TOOL_NAME_MAX_LEN);
        assert_eq!(map.get(&result), Some(&long_name.to_string()));
    }

    #[test]
    fn test_tool_name_mapping_in_convert_request() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let long_tool_name =
            "mcp__plugin_very_long_server_name__extremely_long_tool_name_exceeds_63";
        assert!(long_tool_name.len() > TOOL_NAME_MAX_LEN);

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            system: None,
            stream: false,
            tools: Some(vec![AnthropicTool {
                name: long_tool_name.to_string(),
                description: "A test tool".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            thinking: None,
            tool_choice: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).unwrap();

        // 应该有映射
        assert_eq!(result.tool_name_map.len(), 1);

        // 映射中的值应该是原始名称
        let (short, original) = result.tool_name_map.iter().next().unwrap();
        assert_eq!(original, long_tool_name);
        assert!(short.len() <= TOOL_NAME_MAX_LEN);

        // Kiro 请求中的工具名应该是短名称
        let tools = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tools;
        assert_eq!(tools[0].tool_specification.name, *short);
    }

    /// #46 回归：空 description 工具不应原样透传，必须兜底为非空占位，
    /// 否则上游 Kiro/Bedrock 以 length>=1 校验拒整个请求（400）。
    #[test]
    fn test_convert_tools_empty_description_filled_with_placeholder() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        let cases = [
            ("memory", String::new()),        // 真·空串（#46 现场形态）
            ("Bash", "   \n\t ".to_string()), // 纯空白同样视为空
        ];

        for (name, desc) in cases {
            let req = MessagesRequest {
                model: "claude-sonnet-4".to_string(),
                max_tokens: 1024,
                messages: vec![AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("test"),
                }],
                system: None,
                stream: true,
                tools: Some(vec![AnthropicTool {
                    name: name.to_string(),
                    description: desc,
                    input_schema: schema.clone(),
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                }]),
                thinking: None,
                tool_choice: None,
                output_config: None,
                temperature: None,
                top_p: None,
                metadata: None,
            };

            let result = convert_request(&req, &test_registry()).unwrap();
            let tools = &result
                .conversation_state
                .current_message
                .user_input_message
                .user_input_message_context
                .tools;

            let desc = &tools[0].tool_specification.description;
            assert!(
                !desc.trim().is_empty(),
                "tool `{}` description 不应为空，实际: {:?}",
                name,
                desc
            );
            assert_eq!(desc, &format!("Tool: {}", name));
        }
    }

    /// #46 边界：超长工具名 + 空 description 组合——占位须用缩短后的 mapped_name，
    /// 与 tool_specification.name 严格一致，不能用原始长名。
    #[test]
    fn test_convert_tools_empty_description_long_name_uses_mapped_name() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let long_name = "mcp__plugin_very_long_server_name__extremely_long_tool_name_exceeds_63";
        assert!(long_name.len() > TOOL_NAME_MAX_LEN);

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            system: None,
            stream: true,
            tools: Some(vec![AnthropicTool {
                name: long_name.to_string(),
                description: String::new(), // 空 description
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            thinking: None,
            tool_choice: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).unwrap();
        let tools = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tools;

        let spec = &tools[0].tool_specification;
        // 占位文本中的名字必须与落地的 name 字段一致（均为缩短后的短名）
        assert_eq!(spec.description, format!("Tool: {}", spec.name));
        assert!(spec.name.len() <= TOOL_NAME_MAX_LEN);
        assert!(!spec.description.trim().is_empty());
    }

    /// #46 反向：非空 description 不应被改写（占位逻辑不得误伤正常工具）。
    #[test]
    fn test_convert_tools_nonempty_description_unchanged() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            system: None,
            stream: true,
            tools: Some(vec![AnthropicTool {
                name: "Read".to_string(),
                description: "Read a file".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            thinking: None,
            tool_choice: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).unwrap();
        let tools = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tools;
        assert_eq!(tools[0].tool_specification.description, "Read a file");
    }

    #[test]
    fn test_normalize_json_schema_removes_kiro_rejected_fields_recursively() {
        let schema = serde_json::json!({
            "type": "object",
            "description": "Run a shell command",
            "properties": {
                "command": {
                    "type": "string",
                    "additionalProperties": false,
                    "required": null
                },
                "options": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [],
                    "properties": {
                        "timeout": {"type": "integer", "minimum": 1}
                    }
                }
            },
            "required": ["command"],
            "additionalProperties": false,
            "anyOf": [
                {
                    "type": "object",
                    "required": [],
                    "additionalProperties": false
                }
            ]
        });

        let normalized = normalize_json_schema(schema);
        assert!(!schema_contains_key(&normalized, "additionalProperties"));
        assert_eq!(normalized["required"], serde_json::json!(["command"]));
        assert_eq!(
            normalized["properties"]["command"].get("required"),
            None,
            "nested null required should be removed"
        );
        assert_eq!(
            normalized["properties"]["options"].get("required"),
            None,
            "nested empty required should be removed"
        );
        assert_eq!(
            normalized["anyOf"][0].get("required"),
            None,
            "composition empty required should be removed"
        );
    }

    #[test]
    fn test_normalize_json_schema_preserves_composition_required_values() {
        let schema = serde_json::json!({
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                },
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]
                }
            ]
        });

        let normalized = normalize_json_schema(schema.clone());
        assert_eq!(normalized, schema);
    }

    /// issue92：Kiro 上游实测普遍认 $ref/$defs（原样透传全 200），$ref 展开反而是
    /// 真实回归根因（见下一测试）。normalize 不再展开引用，$ref/$defs 原样保留。
    #[test]
    fn test_normalize_preserves_ref_and_defs_untouched() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "filter": {"$ref": "#/$defs/Filter"}
            },
            "required": ["filter"],
            "$defs": {
                "Filter": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "limit": {"type": "integer"}
                    },
                    "required": ["name"]
                }
            }
        });

        let normalized = normalize_json_schema(schema);
        assert_eq!(
            normalized["properties"]["filter"]["$ref"], "#/$defs/Filter",
            "$ref 应原样保留，不被展开"
        );
        assert!(
            normalized.get("$defs").is_some(),
            "$defs 应原样保留，供上游自解析"
        );
        assert_eq!(
            normalized["$defs"]["Filter"]["properties"]["name"]["type"],
            "string"
        );
    }

    /// issue92 补充回归：移除顶层 `remove($defs)` 后（$defs 不再被摘出来单独
    /// 处理），$defs 内部字段仍必须被 `clean_nested_schema_fields` 递归清理到——
    /// 这条路径容易在未来被误改成"跳过 $defs"，一旦跳过，$defs 内部残留的
    /// additionalProperties/非法 required 元素会让上游 400。
    #[test]
    fn test_normalize_cleans_additionalproperties_inside_defs() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "filter": {"$ref": "#/$defs/Filter"}
            },
            "required": ["filter"],
            "$defs": {
                "Filter": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "required": ["name", 42],
                    "additionalProperties": false
                }
            }
        });

        let normalized = normalize_json_schema(schema);

        // $ref/$defs 结构本身仍保留（不展开、不丢失）。
        assert_eq!(
            normalized["properties"]["filter"]["$ref"], "#/$defs/Filter",
            "$ref 应原样保留"
        );
        assert!(normalized.get("$defs").is_some(), "$defs 应原样保留");

        // $defs 内部字段被递归清理：additionalProperties 剥掉，
        // required 中的非法元素（数字 42）被过滤，只剩合法 string 项。
        let filter_def = &normalized["$defs"]["Filter"];
        assert_eq!(
            filter_def.get("additionalProperties"),
            None,
            "$defs 内部的 additionalProperties 应被清理，不能因为顶层不再 remove($defs) 而漏网"
        );
        assert_eq!(
            filter_def["required"],
            serde_json::json!(["name"]),
            "$defs 内部 required 的非法元素应被过滤"
        );
    }

    /// issue92 核心回归测试：递归自引用 schema（Tree 含 children 数组，item 是
    /// 指回自身的 $ref）经 normalize 后，$ref/$defs 保留，且绝不产生畸形的
    /// `type: {...}` 嵌套对象——旧展开逻辑会把递归引用展开成套娃，导致 type
    /// 字段值变成 object 而非合法的 string，上游报 400 TOOL_SCHEMA_INVALID。
    #[test]
    fn test_normalize_recursive_ref_no_type_corruption() {
        let schema = serde_json::json!({
            "$ref": "#/$defs/Tree",
            "$defs": {
                "Tree": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/Tree"}
                        }
                    }
                }
            }
        });

        let normalized = normalize_json_schema(schema);

        assert_eq!(normalized["$ref"], "#/$defs/Tree", "顶层 $ref 应原样保留");
        assert!(normalized.get("$defs").is_some(), "$defs 应原样保留");

        // 关键断言：schema 里任何 "type" 字段的值都必须是 string 或 array，
        // 绝不能是 object（那是旧展开逻辑套娃出的畸形结构）。
        assert_no_object_typed_type_field(&normalized);
    }

    /// 递归检查：schema 树中任何键为 "type" 的字段，其值只能是字符串或数组，
    /// 不能是 object（后者是 $ref 展开套娃产生的畸形结构，issue92 回归信号）。
    fn assert_no_object_typed_type_field(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(type_value) = map.get("type") {
                    assert!(
                        !type_value.is_object(),
                        "发现畸形 type 字段：值是 object 而非 string/array: {:?}",
                        type_value
                    );
                }
                for child in map.values() {
                    assert_no_object_typed_type_field(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_object_typed_type_field(item);
                }
            }
            _ => {}
        }
    }

    /// issue92：OpenAPI 风格外部引用（`#/components/schemas/...`）实测上游对保留的
    /// 外部 $ref 返回 200，不再退化为 object——展开/退化都不是上游要求的行为。
    #[test]
    fn test_normalize_openapi_external_ref_preserved() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a": {"$ref": "#/components/schemas/Foo"},
                "b": {"$ref": "#/$defs/Missing"}
            }
        });

        let normalized = normalize_json_schema(schema);
        assert_eq!(
            normalized["properties"]["a"]["$ref"], "#/components/schemas/Foo",
            "外部 $ref 应原样保留，不退化为 object"
        );
        assert_eq!(
            normalized["properties"]["b"]["$ref"], "#/$defs/Missing",
            "未命中的 $defs 引用同样应原样保留，不退化为 object"
        );
    }

    /// issue92：顶层裸 $ref（无 anyOf/oneOf/allOf，只有 $ref + $defs）本身不带 type，
    /// 但上游硬约束 inputSchema.json 顶层必须有 type:object，故 normalize 需补上——
    /// 实测 cand2（type:object + $ref + $defs 共存）上游 200。
    #[test]
    fn test_normalize_toplevel_bare_ref_gets_type_object() {
        let schema = serde_json::json!({
            "$ref": "#/$defs/Root",
            "$defs": {
                "Root": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }
            }
        });

        let normalized = normalize_json_schema(schema);
        assert_eq!(
            normalized["type"], "object",
            "顶层裸 $ref 缺 type 时应补 type:object"
        );
        assert_eq!(normalized["$ref"], "#/$defs/Root", "$ref 应保留");
        assert!(normalized.get("$defs").is_some(), "$defs 应保留");
    }

    /// issue92：property 内嵌 $ref（非顶层）应原样透传，不受顶层补 type 逻辑影响。
    #[test]
    fn test_normalize_nested_ref_in_property_preserved() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "config": {"$ref": "#/$defs/Config"}
            },
            "$defs": {
                "Config": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"}
                    }
                }
            }
        });

        let normalized = normalize_json_schema(schema);
        assert_eq!(normalized["type"], "object", "顶层 type 保留");
        assert_eq!(
            normalized["properties"]["config"]["$ref"], "#/$defs/Config",
            "property 内的 $ref 应原样透传"
        );
        assert!(normalized.get("$defs").is_some(), "$defs 应保留");
    }

    #[test]
    fn test_normalize_json_schema_repairs_invalid_tool_schema_fields() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": null,
            "required": ["path", 42, null],
            "additionalProperties": "sometimes"
        });

        let normalized = normalize_json_schema(schema);
        assert_eq!(normalized["type"], "object");
        assert_eq!(normalized["properties"], serde_json::json!({}));
        assert_eq!(normalized["required"], serde_json::json!(["path"]));
        assert_eq!(normalized.get("additionalProperties"), None);
    }

    #[test]
    fn test_opus_4_8_sanitizes_multiple_tool_schemas() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut bash_schema = std::collections::HashMap::new();
        bash_schema.insert("type".to_string(), serde_json::json!("object"));
        bash_schema.insert(
            "properties".to_string(),
            serde_json::json!({
                "command": {"type": "string"},
                "description": {"type": "string"}
            }),
        );
        bash_schema.insert("required".to_string(), serde_json::json!(["command"]));
        bash_schema.insert("additionalProperties".to_string(), serde_json::json!(false));

        let mut edit_schema = std::collections::HashMap::new();
        edit_schema.insert("type".to_string(), serde_json::json!("object"));
        edit_schema.insert(
            "properties".to_string(),
            serde_json::json!({
                "file_path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"}
            }),
        );
        edit_schema.insert(
            "required".to_string(),
            serde_json::json!(["file_path", "old_string", "new_string"]),
        );

        let req = MessagesRequest {
            model: "claude-opus-4-8-thinking".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("use tools"),
            }],
            system: None,
            stream: true,
            tools: Some(vec![
                AnthropicTool {
                    name: "Bash".to_string(),
                    description: "Run a shell command".to_string(),
                    input_schema: bash_schema,
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                },
                AnthropicTool {
                    name: "Edit".to_string(),
                    description: "Edit a file".to_string(),
                    input_schema: edit_schema,
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                },
            ]),
            thinking: None,
            tool_choice: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result =
            convert_request(&req, &test_registry()).expect("opus 4.8 request should convert");
        let user_input = &result.conversation_state.current_message.user_input_message;
        assert_eq!(user_input.model_id, "claude-opus-4.8");

        let tools = &user_input.user_input_message_context.tools;
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].tool_specification.name, "Bash");
        assert_eq!(
            tools[0]
                .tool_specification
                .input_schema
                .json
                .get("additionalProperties"),
            None
        );
        assert_eq!(
            tools[0].tool_specification.input_schema.json["required"],
            serde_json::json!(["command"])
        );
        assert_eq!(tools[1].tool_specification.name, "Edit");
        assert_eq!(
            tools[1].tool_specification.input_schema.json["required"],
            serde_json::json!(["file_path", "old_string", "new_string"])
        );
    }

    fn schema_contains_key(value: &serde_json::Value, key: &str) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                map.contains_key(key) || map.values().any(|child| schema_contains_key(child, key))
            }
            serde_json::Value::Array(items) => {
                items.iter().any(|child| schema_contains_key(child, key))
            }
            _ => false,
        }
    }

    #[test]
    fn test_tool_name_mapping_in_history() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let long_tool_name =
            "mcp__plugin_very_long_server_name__extremely_long_tool_name_exceeds_63";

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("use the tool"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "text", "text": "calling tool"},
                        {"type": "tool_use", "id": "toolu_01", "name": long_tool_name, "input": {}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "toolu_01", "content": "done"}
                    ]),
                },
            ],
            system: None,
            stream: false,
            tools: Some(vec![AnthropicTool {
                name: long_tool_name.to_string(),
                description: "A test tool".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            thinking: None,
            tool_choice: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).unwrap();
        let short_name = result.tool_name_map.iter().next().unwrap().0.clone();

        // 历史中 assistant 消息的 tool_use name 也应该被映射
        let history = &result.conversation_state.history;
        let mut found = false;
        for msg in history {
            if let Message::Assistant(a) = msg
                && let Some(ref tool_uses) = a.assistant_response_message.tool_uses
            {
                for tu in tool_uses {
                    if tu.tool_use_id == "toolu_01" {
                        assert_eq!(tu.name, short_name, "历史中的 tool_use name 应该是短名称");
                        found = true;
                    }
                }
            }
        }
        assert!(found, "应该在历史中找到 tool_use");
    }

    #[test]
    fn test_history_tools_added_to_tools_list() {
        use super::super::types::Message as AnthropicMessage;

        // 创建一个请求，历史中有工具使用，但 tools 列表为空
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("Read the file"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "text", "text": "I'll read the file."},
                        {"type": "tool_use", "id": "tool-1", "name": "read", "input": {"path": "/test.txt"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tool-1", "content": "file content"}
                    ]),
                },
            ],
            stream: false,
            system: None,
            tools: None, // 没有提供工具定义
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).unwrap();

        // 验证 tools 列表中包含了历史中使用的工具的占位符定义
        let tools = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tools;

        assert!(!tools.is_empty(), "tools 列表不应为空");
        assert!(
            tools.iter().any(|t| t.tool_specification.name == "read"),
            "tools 列表应包含 'read' 工具的占位符定义"
        );
    }

    /// Regression #26: 删除 sanitize_history_tools 降级后，多轮 agent loop 历史
    /// 必须保留结构化 toolUses/toolResults，且绝不出现单空格 " " 空壳 assistant 轮。
    /// 空壳轮密度过高会诱导模型只回空格/句号，导致 CC 长会话死循环（与上下文长度无关）。
    /// See https://github.com/WooDragon/kiro.rs/issues/26
    #[test]
    fn test_regression_26_structured_tool_turns_preserved_no_empty_shells() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        // 3 轮 agent loop：每轮 (assistant 纯 tool_use 无 text) + (user tool_result)，
        // current 为纯文本，使历史内所有 tool_use 都已配对（不被 remove_orphaned 清理）。
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("start the task"),
                },
                // 第 1 轮：纯 tool_use（无 text）
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"cmd": "ls"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_1", "content": "file1\nfile2"}
                    ]),
                },
                // 第 2 轮：纯 tool_use（无 text）
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_2", "name": "Read", "input": {"path": "/file1"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_2", "content": "contents of file1"}
                    ]),
                },
                // 第 3 轮：纯 tool_use（无 text）
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_3", "name": "Bash", "input": {"cmd": "cat /file1"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_3", "content": "done"}
                    ]),
                },
                // 当前消息：纯文本，无 tool_result
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("now summarize what you found"),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![
                AnthropicTool {
                    name: "Bash".to_string(),
                    description: "Run a command".to_string(),
                    input_schema: schema.clone(),
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                },
                AnthropicTool {
                    name: "Read".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: schema,
                    tool_type: None,
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

        let result =
            convert_request(&req, &test_registry()).expect("multi-turn agent loop should convert");
        let history = &result.conversation_state.history;

        // 不变量 1（无空壳轮）：history 里绝不出现单空格 " " 空壳 assistant 轮（#26 死循环根因），
        // 纯 tool_use 轮 content 应为空串 "" 而非任何空白占位。
        let mut assistant_tool_turns = 0;
        for msg in history {
            if let Message::Assistant(a) = msg {
                let content = &a.assistant_response_message.content;
                assert_ne!(
                    content, " ",
                    "assistant content 不得为单空格占位符（空壳轮诱导模型死循环，#26）"
                );
                if a.assistant_response_message.tool_uses.is_some() {
                    assistant_tool_turns += 1;
                    if content.trim().is_empty() {
                        assert_eq!(content, "", "纯 tool_use 轮 content 应为空串而非空白占位");
                    }
                }
            }
        }

        // 不变量 2（保留结构化）：3 轮纯 tool_use 的 toolUses 都应保留（非活跃历史轮也不剥离）。
        assert!(
            assistant_tool_turns >= 3,
            "3 轮纯 tool_use 的 toolUses 都应结构化保留，实际 {} 轮",
            assistant_tool_turns
        );

        // 不变量 2（续）：历史 user 轮的结构化 toolResults 必须保留（不被叙述清空）。
        let total_tool_results: usize = history
            .iter()
            .filter_map(|m| match m {
                Message::User(u) => Some(
                    u.user_input_message
                        .user_input_message_context
                        .tool_results
                        .len(),
                ),
                _ => None,
            })
            .sum();
        assert!(
            total_tool_results >= 3,
            "3 个 tool_result 都应结构化保留，实际 {}",
            total_tool_results
        );

        // 不变量 3（不叙述成文本）：user content 不得含叙述化的 tool result 文本。
        for msg in history {
            if let Message::User(u) = msg {
                let content = &u.user_input_message.content;
                for pat in ["[Bash]", "[Read]", "[Tool Call", "] ERROR:"] {
                    assert!(
                        !content.contains(pat),
                        "user content 不得叙述化 tool result（应保留结构化），发现 '{}': {:?}",
                        pat,
                        content
                    );
                }
            }
        }
    }

    /// Regression #26: 连续 assistant 轮合并时，纯 tool_use（空 content）子消息
    /// 与有文本的子消息混合，content 应为非空文本本身，不产生单空格占位或多余换行。
    #[test]
    fn test_regression_26_merge_assistant_no_empty_shell() {
        use super::super::types::Message as AnthropicMessage;

        let msgs = [
            // 第一个：纯 tool_use（content 空）
            AnthropicMessage {
                role: "assistant".to_string(),
                content: serde_json::json!([
                    {"type": "tool_use", "id": "tu_a", "name": "Bash", "input": {"cmd": "ls"}}
                ]),
            },
            // 第二个：有 text
            AnthropicMessage {
                role: "assistant".to_string(),
                content: serde_json::json!("Here is the result."),
            },
        ];
        let refs: Vec<&AnthropicMessage> = msgs.iter().collect();

        let merged =
            merge_assistant_messages(&refs, &mut HashMap::new()).expect("merge should succeed");
        let content = &merged.assistant_response_message.content;

        assert_eq!(
            content, "Here is the result.",
            "合并后 content 应是非空子消息本身，不含空壳占位或多余换行"
        );
        assert_ne!(content, " ", "不得出现单空格占位符（#26）");

        let tool_uses = merged
            .assistant_response_message
            .tool_uses
            .expect("应保留 tool_uses");
        assert_eq!(tool_uses.len(), 1, "应保留第一轮的 tool_use");
        assert_eq!(tool_uses[0].tool_use_id, "tu_a");
    }

    /// Regression #26: 连续两个纯 tool_use assistant 轮合并，content 应为空串而非空格占位。
    #[test]
    fn test_regression_26_merge_two_tool_only_turns_empty_content() {
        use super::super::types::Message as AnthropicMessage;

        let msgs = [
            AnthropicMessage {
                role: "assistant".to_string(),
                content: serde_json::json!([
                    {"type": "tool_use", "id": "tu_x", "name": "Bash", "input": {"cmd": "a"}}
                ]),
            },
            AnthropicMessage {
                role: "assistant".to_string(),
                content: serde_json::json!([
                    {"type": "tool_use", "id": "tu_y", "name": "Bash", "input": {"cmd": "b"}}
                ]),
            },
        ];
        let refs: Vec<&AnthropicMessage> = msgs.iter().collect();

        let merged =
            merge_assistant_messages(&refs, &mut HashMap::new()).expect("merge should succeed");

        assert_eq!(
            merged.assistant_response_message.content, "",
            "两个纯 tool_use 轮合并后 content 应为空串（不注入空格占位）"
        );
        assert_eq!(
            merged
                .assistant_response_message
                .tool_uses
                .expect("应有 tool_uses")
                .len(),
            2,
            "两轮 tool_use 都应合并保留"
        );
    }

    /// Regression: narrated tool-call text in assistant content causes model mimicry.
    /// See https://github.com/WooDragon/kiro.rs/issues/22
    #[test]
    fn test_regression_no_tool_call_patterns_in_assistant_content() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert(
            "properties".to_string(),
            serde_json::json!({"path": {"type": "string"}}),
        );

        // 3 轮 tool 交互 + 1 条纯用户消息，覆盖多轮历史降级
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                // 第 1 轮
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("read /foo"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "text", "text": "Reading the file."},
                        {"type": "tool_use", "id": "tu_1", "name": "Read", "input": {"path": "/foo"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_1", "content": "foo content"}
                    ]),
                },
                // 第 2 轮：assistant 只有 tool_use 没有文本
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_2", "name": "Bash", "input": {"cmd": "ls"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_2", "content": "file1\nfile2"}
                    ]),
                },
                // 第 3 轮：assistant 正常回复
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!("Done, here are the results."),
                },
                // 新用户消息（无 tool_result）
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("now summarize"),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![
                AnthropicTool {
                    name: "Read".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: schema.clone(),
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                },
                AnthropicTool {
                    name: "Bash".to_string(),
                    description: "Run a command".to_string(),
                    input_schema: schema,
                    tool_type: None,
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

        let result = convert_request(&req, &test_registry())
            .expect("multi-turn tool request should convert");

        // 会引起模型模仿的危险模式
        let dangerous_patterns = [
            "[Tool Call:",
            "[Tool Call]",
            "[Called tool",
            "Arguments: {",
            "tool_use_id",
            "\"type\":\"tool_use\"",
            "\"type\": \"tool_use\"",
        ];

        let mut structured_tool_use_turns = 0;
        for msg in &result.conversation_state.history {
            if let Message::Assistant(a) = msg {
                let content = &a.assistant_response_message.content;
                for pattern in &dangerous_patterns {
                    assert!(
                        !content.contains(pattern),
                        "assistant content must not contain '{}' (causes model mimicry), found in: {:?}",
                        pattern,
                        content
                    );
                }
                // #26 强化：不得出现单空格空壳轮
                assert_ne!(
                    content, " ",
                    "assistant content 不得为单空格占位符（#26 空壳轮诱导死循环）"
                );
                if a.assistant_response_message.tool_uses.is_some() {
                    structured_tool_use_turns += 1;
                }
            }
        }

        // #26 强化：历史中 tool_use 轮的结构化 toolUses 必须保留（修复前会被剥离降级）
        assert!(
            structured_tool_use_turns >= 2,
            "多轮历史的结构化 toolUses 应保留（非活跃轮也不剥离），实际 {} 轮",
            structured_tool_use_turns
        );
    }

    #[test]
    fn test_extract_session_id_valid() {
        // 测试有效的 user_id 格式
        let user_id = "user_0dede55c6dcc4a11a30bbb5e7f22e6fdf86cdeba3820019cc27612af4e1243cd_account__session_8bb5523b-ec7c-4540-a9ca-beb6d79f1552";
        let session_id = extract_session_id(user_id);
        assert_eq!(
            session_id,
            Some("8bb5523b-ec7c-4540-a9ca-beb6d79f1552".to_string())
        );
    }

    #[test]
    fn test_extract_session_id_json_format() {
        // 测试 JSON 格式的 user_id
        let user_id = r#"{"device_id":"0dede55c6dcc4a11a30bbb5e7f22e6fdf86cdeba3820019cc27612af4e1243cd","account_uuid":"","session_id":"8bb5523b-ec7c-4540-a9ca-beb6d79f1552"}"#;
        let session_id = extract_session_id(user_id);
        assert_eq!(
            session_id,
            Some("8bb5523b-ec7c-4540-a9ca-beb6d79f1552".to_string())
        );
    }

    #[test]
    fn test_extract_session_id_json_invalid_session() {
        // 测试 JSON 格式但 session_id 不是有效 UUID
        let user_id = r#"{"device_id":"abc","session_id":"not-a-uuid"}"#;
        let session_id = extract_session_id(user_id);
        assert_eq!(session_id, None);
    }

    #[test]
    fn test_extract_session_id_no_session() {
        // 测试没有 session 的 user_id
        let user_id = "user_0dede55c6dcc4a11a30bbb5e7f22e6fdf86cdeba3820019cc27612af4e1243cd";
        let session_id = extract_session_id(user_id);
        assert_eq!(session_id, None);
    }

    #[test]
    fn test_extract_session_id_invalid_uuid() {
        // 测试无效的 UUID 格式
        let user_id = "user_xxx_session_invalid-uuid";
        let session_id = extract_session_id(user_id);
        assert_eq!(session_id, None);
    }

    #[test]
    fn test_extract_session_id_rejects_uuid_shaped_non_uuid() {
        // 36 字符且连字符位置类似 UUID，但包含非法十六进制字符，不能作为会话 ID
        let user_id = "user_xxx_session_zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
        let session_id = extract_session_id(user_id);
        assert_eq!(session_id, None);
    }

    #[test]
    fn test_extract_session_id_json_key_name_does_not_leak_into_substring_fallback() {
        // Scenario: user_id 里的 hash 段来自外部输入（如用户名恰好含 "_session_" 字面串），
        // Given 一个内嵌了伪 "_session_" 干扰串（my_session_bot）的 user_id，
        // When 提取 session id，
        // Then 必须命中末尾真实的 "_session_<UUID>"，而不是被中段的伪匹配提前截断。
        let user_id = "user_my_session_bot_account__session_8bb5523b-ec7c-4540-a9ca-beb6d79f1552";
        let session_id = extract_session_id(user_id);
        assert_eq!(
            session_id,
            Some("8bb5523b-ec7c-4540-a9ca-beb6d79f1552".to_string()),
            "用户名内含 _session_ 干扰串时，仍应提取末尾真实 session UUID"
        );
    }

    /// Scenario: 分隔符后紧跟非 ASCII 字符（emoji）时不 panic（#86 返工 MUST FIX 2）
    ///
    /// Given user_id 完全由客户端提供，"_session_" 分隔符后是 1 个 ASCII 字符
    ///       紧跟 10 个 4 字节 emoji（混合宽度，共 41 字节 >= 36）
    /// When  提取 session id
    /// Then  不应 panic（原按字节 [..36] 切片会 "byte index 36 is not a char
    ///       boundary"），应安全返回 None（提取失败，落到调用方既有的随机 UUID 兜底）
    ///
    /// 输入构造说明（#86 返工返工二轮：原 10 个纯 emoji 输入是恒绿测试）：纯
    /// emoji（等宽 4 字节）串的字符边界必然是 4 的倍数，而 36 恰好能被 4 整除，
    /// 于是 `[..36]`/`get(..36)` 在原输入上永远落在合法边界（切出前 9 个 emoji），
    /// 两个实现在修复前后都返回 None，断言恒真、对被修的 panic 缺陷零覆盖。要让
    /// 字节 36 落在非边界，必须用**混合宽度**：前缀 1 个 1 字节 ASCII 字符
    /// 把所有后续 emoji 边界整体错开奇偶，字符边界序列变为
    /// [0,1,5,9,...,33,37,41]，36 恰好落在第 9 个 emoji（[33,37) 区间）内部。
    #[test]
    fn test_extract_session_id_non_char_boundary_does_not_panic() {
        let user_id = "a_session_x😀😀😀😀😀😀😀😀😀😀";
        let session_id = extract_session_id(user_id);
        assert_eq!(
            session_id, None,
            "非字符边界的伪 UUID 段应安全返回 None，而不是 panic"
        );
    }

    #[test]
    fn test_convert_request_with_session_metadata() {
        use super::super::types::{Message as AnthropicMessage, Metadata};

        // 测试带有 metadata 的请求，应该使用 session UUID 作为 conversationId
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("Hello"),
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: Some(Metadata {
                user_id: Some(
                    "user_0dede55c6dcc4a11a30bbb5e7f22e6fdf86cdeba3820019cc27612af4e1243cd_account__session_a0662283-7fd3-4399-a7eb-52b9a717ae88".to_string(),
                ),
            }),
        };

        let result = convert_request(&req, &test_registry()).unwrap();
        assert_eq!(
            result.conversation_state.conversation_id,
            "a0662283-7fd3-4399-a7eb-52b9a717ae88"
        );
        // PR-0：session_id_extracted 的取值来源即 stable_conversation_id.is_some()。
        assert!(
            result.stable_conversation_id.is_some(),
            "session_id_extracted 应为 true：客户端传入了有效 session_id"
        );
    }

    #[test]
    fn test_convert_request_without_metadata() {
        use super::super::types::Message as AnthropicMessage;

        // 测试没有 metadata 的请求，应该生成新的 UUID
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("Hello"),
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
        };

        let result = convert_request(&req, &test_registry()).unwrap();
        // 验证生成的是有效的 UUID 格式
        assert_eq!(result.conversation_state.conversation_id.len(), 36);
        assert_eq!(
            result
                .conversation_state
                .conversation_id
                .chars()
                .filter(|c| *c == '-')
                .count(),
            4
        );
        // PR-0：无 metadata 时退回随机 UUID 兜底，session_id_extracted 应为 false。
        assert!(
            result.stable_conversation_id.is_none(),
            "session_id_extracted 应为 false：无 metadata 时退回随机 UUID 兜底"
        );
    }

    #[test]
    fn test_validate_tool_pairing_orphaned_result() {
        // 测试孤立的 tool_result 被过滤
        // 历史中没有 tool_use，但 tool_results 中有 tool_result
        let history = vec![
            Message::User(HistoryUserMessage::new("Hello", "claude-sonnet-4.5")),
            Message::Assistant(HistoryAssistantMessage::new("Hi there!")),
        ];

        let tool_results = vec![ToolResult::success("orphan-123", "some result")];

        let (filtered, _) = validate_tool_pairing(&history, &tool_results);

        // 孤立的 tool_result 应该被过滤掉
        assert!(filtered.is_empty(), "孤立的 tool_result 应该被过滤");
    }

    #[test]
    fn test_validate_tool_pairing_orphaned_use() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试孤立的 tool_use（有 tool_use 但没有对应的 tool_result）
        let mut assistant_msg = AssistantMessage::new("I'll read the file.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-orphan", "read")
                .with_input(serde_json::json!({"path": "/test.txt"})),
        ]);

        let history = vec![
            Message::User(HistoryUserMessage::new(
                "Read the file",
                "claude-sonnet-4.5",
            )),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        // 没有 tool_result
        let tool_results: Vec<ToolResult> = vec![];

        let (filtered, orphaned) = validate_tool_pairing(&history, &tool_results);

        // 结果应该为空（因为没有 tool_result）
        // 同时应该返回孤立的 tool_use_id
        assert!(filtered.is_empty());
        assert!(orphaned.contains("tool-orphan"));
    }

    #[test]
    fn test_validate_tool_pairing_valid() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试正常配对的情况
        let mut assistant_msg = AssistantMessage::new("I'll read the file.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read")
                .with_input(serde_json::json!({"path": "/test.txt"})),
        ]);

        let history = vec![
            Message::User(HistoryUserMessage::new(
                "Read the file",
                "claude-sonnet-4.5",
            )),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        let tool_results = vec![ToolResult::success("tool-1", "file content")];

        let (filtered, orphaned) = validate_tool_pairing(&history, &tool_results);

        // 配对成功，应该保留，无孤立
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tool_use_id, "tool-1");
        assert!(orphaned.is_empty());
    }

    #[test]
    fn test_validate_tool_pairing_mixed() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试混合情况：部分配对成功，部分孤立
        let mut assistant_msg = AssistantMessage::new("I'll use two tools.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read").with_input(serde_json::json!({})),
            ToolUseEntry::new("tool-2", "write").with_input(serde_json::json!({})),
        ]);

        let history = vec![
            Message::User(HistoryUserMessage::new("Do something", "claude-sonnet-4.5")),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        // tool_results: tool-1 配对，tool-3 孤立
        let tool_results = vec![
            ToolResult::success("tool-1", "result 1"),
            ToolResult::success("tool-3", "orphan result"), // 孤立
        ];

        let (filtered, orphaned) = validate_tool_pairing(&history, &tool_results);

        // 只有 tool-1 应该保留
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tool_use_id, "tool-1");
        // tool-2 是孤立的 tool_use（无 result），tool-3 是孤立的 tool_result
        assert!(orphaned.contains("tool-2"));
    }

    #[test]
    fn test_validate_tool_pairing_history_already_paired() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试历史中已配对的 tool_use 不应该被报告为孤立
        // 场景：多轮对话中，之前的 tool_use 已经在历史中有对应的 tool_result
        let mut assistant_msg1 = AssistantMessage::new("I'll read the file.");
        assistant_msg1 = assistant_msg1.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read")
                .with_input(serde_json::json!({"path": "/test.txt"})),
        ]);

        // 构建历史中的 user 消息，包含 tool_result
        let mut user_msg_with_result = UserMessage::new("", "claude-sonnet-4.5");
        let mut ctx = UserInputMessageContext::new();
        ctx = ctx.with_tool_results(vec![ToolResult::success("tool-1", "file content")]);
        user_msg_with_result = user_msg_with_result.with_context(ctx);

        let history = vec![
            // 第一轮：用户请求
            Message::User(HistoryUserMessage::new(
                "Read the file",
                "claude-sonnet-4.5",
            )),
            // 第一轮：assistant 使用工具
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg1,
            }),
            // 第二轮：用户返回工具结果（历史中已配对）
            Message::User(HistoryUserMessage {
                user_input_message: user_msg_with_result,
            }),
            // 第二轮：assistant 响应
            Message::Assistant(HistoryAssistantMessage::new("The file contains...")),
        ];

        // 当前消息没有 tool_results（用户只是继续对话）
        let tool_results: Vec<ToolResult> = vec![];

        let (filtered, orphaned) = validate_tool_pairing(&history, &tool_results);

        // 结果应该为空，且不应该有孤立 tool_use
        // 因为 tool-1 已经在历史中配对了
        assert!(filtered.is_empty());
        assert!(orphaned.is_empty());
    }

    #[test]
    fn test_validate_tool_pairing_duplicate_result() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试重复的 tool_result（历史中已配对，当前消息又发送了相同的 tool_result）
        let mut assistant_msg = AssistantMessage::new("I'll read the file.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read")
                .with_input(serde_json::json!({"path": "/test.txt"})),
        ]);

        // 历史中已有 tool_result
        let mut user_msg_with_result = UserMessage::new("", "claude-sonnet-4.5");
        let mut ctx = UserInputMessageContext::new();
        ctx = ctx.with_tool_results(vec![ToolResult::success("tool-1", "file content")]);
        user_msg_with_result = user_msg_with_result.with_context(ctx);

        let history = vec![
            Message::User(HistoryUserMessage::new(
                "Read the file",
                "claude-sonnet-4.5",
            )),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
            Message::User(HistoryUserMessage {
                user_input_message: user_msg_with_result,
            }),
            Message::Assistant(HistoryAssistantMessage::new("Done")),
        ];

        // 当前消息又发送了相同的 tool_result（重复）
        let tool_results = vec![ToolResult::success("tool-1", "file content again")];

        let (filtered, _) = validate_tool_pairing(&history, &tool_results);

        // 重复的 tool_result 应该被过滤掉
        assert!(filtered.is_empty(), "重复的 tool_result 应该被过滤");
    }

    #[test]
    fn test_convert_assistant_message_tool_use_only() {
        use super::super::types::Message as AnthropicMessage;

        // 测试仅包含 tool_use 的 assistant 消息（无 text 块）
        // 修复 #26 后：纯 tool_use 轮 content 为空串 ""，不再注入空格占位符
        let msg = AnthropicMessage {
            role: "assistant".to_string(),
            content: serde_json::json!([
                {"type": "tool_use", "id": "toolu_01ABC", "name": "read_file", "input": {"path": "/test.txt"}}
            ]),
        };

        let result = convert_assistant_message(&msg, &mut HashMap::new()).expect("应该成功转换");

        // 验证 content 为空串（对齐 kiro2api "content":""，不再使用占位符）
        assert_eq!(
            result.assistant_response_message.content, "",
            "仅 tool_use 时 content 应为空串"
        );
        assert_ne!(
            result.assistant_response_message.content, " ",
            "不得注入单空格占位符（#26 死循环根因）"
        );

        // 验证 tool_uses 被正确保留
        let tool_uses = result
            .assistant_response_message
            .tool_uses
            .expect("应该有 tool_uses");
        assert_eq!(tool_uses.len(), 1);
        assert_eq!(tool_uses[0].tool_use_id, "toolu_01ABC");
        assert_eq!(tool_uses[0].name, "read_file");
    }

    #[test]
    fn test_convert_assistant_message_with_text_and_tool_use() {
        use super::super::types::Message as AnthropicMessage;

        // 测试同时包含 text 和 tool_use 的 assistant 消息
        let msg = AnthropicMessage {
            role: "assistant".to_string(),
            content: serde_json::json!([
                {"type": "text", "text": "Let me read that file for you."},
                {"type": "tool_use", "id": "toolu_02XYZ", "name": "read_file", "input": {"path": "/data.json"}}
            ]),
        };

        let result = convert_assistant_message(&msg, &mut HashMap::new()).expect("应该成功转换");

        // 验证 content 使用原始文本（不是占位符）
        assert_eq!(
            result.assistant_response_message.content,
            "Let me read that file for you."
        );

        // 验证 tool_uses 被正确保留
        let tool_uses = result
            .assistant_response_message
            .tool_uses
            .expect("应该有 tool_uses");
        assert_eq!(tool_uses.len(), 1);
        assert_eq!(tool_uses[0].tool_use_id, "toolu_02XYZ");
    }

    #[test]
    fn test_remove_orphaned_tool_uses() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试从历史中移除孤立的 tool_use
        let mut assistant_msg = AssistantMessage::new("I'll use multiple tools.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read").with_input(serde_json::json!({})),
            ToolUseEntry::new("tool-2", "write").with_input(serde_json::json!({})),
            ToolUseEntry::new("tool-3", "delete").with_input(serde_json::json!({})),
        ]);

        let mut history = vec![
            Message::User(HistoryUserMessage::new("Do something", "claude-sonnet-4.5")),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        // 移除 tool-1 和 tool-3
        let mut orphaned = std::collections::HashSet::new();
        orphaned.insert("tool-1".to_string());
        orphaned.insert("tool-3".to_string());

        remove_orphaned_tool_uses(&mut history, &orphaned);

        // 验证只剩下 tool-2
        if let Message::Assistant(ref assistant_msg) = history[1] {
            let tool_uses = assistant_msg
                .assistant_response_message
                .tool_uses
                .as_ref()
                .expect("应该还有 tool_uses");
            assert_eq!(tool_uses.len(), 1);
            assert_eq!(tool_uses[0].tool_use_id, "tool-2");
        } else {
            panic!("应该是 Assistant 消息");
        }
    }

    #[test]
    fn test_remove_orphaned_tool_uses_all_removed() {
        use crate::kiro::model::requests::tool::ToolUseEntry;

        // 测试移除所有 tool_use 后，tool_uses 变为 None
        let mut assistant_msg = AssistantMessage::new("I'll use a tool.");
        assistant_msg = assistant_msg.with_tool_uses(vec![
            ToolUseEntry::new("tool-1", "read").with_input(serde_json::json!({})),
        ]);

        let mut history = vec![
            Message::User(HistoryUserMessage::new("Do something", "claude-sonnet-4.5")),
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: assistant_msg,
            }),
        ];

        let mut orphaned = std::collections::HashSet::new();
        orphaned.insert("tool-1".to_string());

        remove_orphaned_tool_uses(&mut history, &orphaned);

        // 验证 tool_uses 变为 None
        if let Message::Assistant(ref assistant_msg) = history[1] {
            assert!(
                assistant_msg.assistant_response_message.tool_uses.is_none(),
                "移除所有 tool_use 后应为 None"
            );
        } else {
            panic!("应该是 Assistant 消息");
        }
    }

    #[test]
    fn test_merge_consecutive_assistant_messages() {
        // 测试连续 assistant 消息被正确合并（Issue #79）
        use super::super::types::Message as AnthropicMessage;

        let msg1 = AnthropicMessage {
            role: "assistant".to_string(),
            content: serde_json::json!([
                {"type": "thinking", "thinking": "Let me think about this..."},
                {"type": "text", "text": " "}
            ]),
        };

        let msg2 = AnthropicMessage {
            role: "assistant".to_string(),
            content: serde_json::json!([
                {"type": "thinking", "thinking": "I should read the file."},
                {"type": "text", "text": "Let me read that file."},
                {"type": "tool_use", "id": "toolu_01ABC", "name": "read_file", "input": {"path": "/test.txt"}}
            ]),
        };

        let messages: Vec<&AnthropicMessage> = vec![&msg1, &msg2];
        let result = merge_assistant_messages(&messages, &mut HashMap::new()).expect("合并应成功");

        let content = &result.assistant_response_message.content;
        assert!(content.contains("<thinking>"), "应包含 thinking 标签");
        assert!(
            content.contains("Let me read that file"),
            "应包含第二条消息的 text 内容"
        );

        let tool_uses = result
            .assistant_response_message
            .tool_uses
            .expect("应有 tool_uses");
        assert_eq!(tool_uses.len(), 1);
        assert_eq!(tool_uses[0].tool_use_id, "toolu_01ABC");
    }

    #[test]
    fn test_consecutive_assistant_with_tool_use_result_pairing() {
        // 测试 Issue #79 的完整场景
        use super::super::types::Message as AnthropicMessage;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("Read the config file"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "thinking", "thinking": "I need to read the file..."},
                        {"type": "text", "text": " "}
                    ]),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "thinking", "thinking": "Let me read the config."},
                        {"type": "text", "text": "I'll read the config file for you."},
                        {"type": "tool_use", "id": "toolu_01XYZ", "name": "read_file", "input": {"path": "/config.json"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "toolu_01XYZ", "content": "{\"key\": \"value\"}"}
                    ]),
                },
            ],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry());
        assert!(
            result.is_ok(),
            "连续 assistant 消息场景不应报错: {:?}",
            result.err()
        );

        let state = result.unwrap().conversation_state;
        let mut found_tool_use = false;
        for msg in &state.history {
            if let Message::Assistant(assistant_msg) = msg
                && let Some(ref tool_uses) = assistant_msg.assistant_response_message.tool_uses
                && tool_uses.iter().any(|t| t.tool_use_id == "toolu_01XYZ")
            {
                found_tool_use = true;
                break;
            }
        }
        assert!(found_tool_use, "合并后的 assistant 消息应包含 tool_use");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P0-2 E2E 测试（通过 convert_request 验证占位符落到活跃 turn 的 tool_results）
    // ═══════════════════════════════════════════════════════════════════════

    /// T-P02-E2E-01：空 tool_result 经 convert_request 后占位符落到活跃 turn 的
    /// tool_results[0].content[0]["text"]；序列化结果不含 `"text":""`
    #[test]
    fn test_empty_tool_result_placeholder_in_active_turn() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("do something"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_empty", "name": "Bash", "input": {}}
                    ]),
                },
                // 空 tool_result：content 为空字符串
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_empty", "content": ""}
                    ]),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![AnthropicTool {
                name: "Bash".to_string(),
                description: "Run command".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).expect("should convert");
        let tool_results = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tool_results;

        assert_eq!(tool_results.len(), 1, "应有 1 个 tool_result");
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(text, "(empty result)", "空 tool_result 应替换为占位符");

        // 序列化后不含空 text
        let json = serde_json::to_string(&result.conversation_state).unwrap();
        assert!(!json.contains("\"text\":\"\""), "序列化结果不应含空 text");
        assert!(json.contains("(empty result)"));
    }

    /// T-P02-E2E-02：非空 tool_result 经 convert_request 后内容不被改写
    #[test]
    fn test_nonempty_tool_result_not_overwritten_in_e2e() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("do something"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_real", "name": "Bash", "input": {}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_real", "content": "real output"}
                    ]),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![AnthropicTool {
                name: "Bash".to_string(),
                description: "Run command".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).expect("should convert");
        let tool_results = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tool_results;

        assert_eq!(tool_results.len(), 1);
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(text, "real output", "非空内容不应被改写");
    }

    /// 回归护栏变体：空 tool_result 经叙述/历史处理后，assistant content 不含危险模式
    #[test]
    fn test_regression_empty_tool_result_narrated_has_no_dangerous_patterns() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));

        // 构造：第1轮 tool 调用返回空 result（修复 #26 后结构化保留、不再叙述），第2轮正常
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("do the thing"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_empty_hist", "name": "Bash", "input": {}}
                    ]),
                },
                // 空 tool_result（会进入历史被叙述）
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_result", "tool_use_id": "tu_empty_hist", "content": ""}
                    ]),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!("Done."),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("follow up"),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![AnthropicTool {
                name: "Bash".to_string(),
                description: "Run command".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).expect("should convert");

        // 危险模式不应出现在 assistant content 里
        let dangerous_patterns = [
            "[Tool Call:",
            "[Tool Call]",
            "[Called tool",
            "Arguments: {",
            "tool_use_id",
            "\"type\":\"tool_use\"",
        ];

        for msg in &result.conversation_state.history {
            if let Message::Assistant(a) = msg {
                let content = &a.assistant_response_message.content;
                for pattern in &dangerous_patterns {
                    assert!(
                        !content.contains(pattern),
                        "assistant content 不应含危险模式 '{}': {:?}",
                        pattern,
                        content
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Issue #35：tool_result 图片 hoist 到 userInputMessage.images
    // ═══════════════════════════════════════════════════════════════════════

    /// 构造完整 MessagesRequest，末尾 user 消息含 tool_result（带图片 content）
    ///
    /// # 参数
    /// * `tool_result_content` - tool_result 的 content 数组（JSON Value）
    ///
    /// # 返回
    /// 可直接传给 convert_request 的 MessagesRequest
    fn make_req_with_tool_result_image(tool_result_content: serde_json::Value) -> MessagesRequest {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};
        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));
        MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("read a file"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_read_img", "name": "Read", "input": {"file_path": "/tmp/a.png"}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([{
                        "type": "tool_result",
                        "tool_use_id": "tu_read_img",
                        "content": tool_result_content
                    }]),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![AnthropicTool {
                name: "Read".to_string(),
                description: "Read file".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        }
    }

    /// 构造标准 PNG base64 数据（1×1 红点）供测试用
    fn test_png_base64() -> &'static str {
        // 最小合法 base64，测试只关心字段传递不关心像素
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwADhQGAWjR9awAAAABJRU5ErkJggg=="
    }

    /// TC-35-01：tool_result content 含单个 image block → images 非空、format 正确、bytes 是原 data
    #[test]
    fn test_issue35_single_image_block_hoisted() {
        let content = serde_json::json!([{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": test_png_base64()
            }
        }]);
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("应成功转换");

        let user_input = &result.conversation_state.current_message.user_input_message;

        // 图片应 hoist 到 images
        assert_eq!(user_input.images.len(), 1, "应有 1 张图片 hoist 到 images");
        assert_eq!(user_input.images[0].format, "png", "格式应为 png");
        assert_eq!(
            user_input.images[0].source.bytes,
            test_png_base64(),
            "bytes 应是原 base64 data"
        );
    }

    /// TC-35-02：仅图无文的 tool_result → ToolResult content 是 TOOL_RESULT_IMAGE_PLACEHOLDER，非 "(empty result)"
    #[test]
    fn test_issue35_image_only_uses_image_placeholder() {
        let content = serde_json::json!([{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": test_png_base64()
            }
        }]);
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("应成功转换");

        let tool_results = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tool_results;

        assert_eq!(tool_results.len(), 1, "应有 1 个 tool_result");
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(
            text, TOOL_RESULT_IMAGE_PLACEHOLDER,
            "仅图无文时应用图片占位符，不应是 (empty result)"
        );
        assert_ne!(
            text, "(empty result)",
            "不应用空结果占位符——那会误导模型以为工具没返回内容"
        );
    }

    /// TC-35-03：文本 + 图片混合 → 文本进 tool_result content，图片进 images，两者都不丢
    #[test]
    fn test_issue35_text_and_image_mixed() {
        let content = serde_json::json!([
            {"type": "text", "text": "file contents above image"},
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": test_png_base64()
                }
            }
        ]);
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("应成功转换");

        let user_input = &result.conversation_state.current_message.user_input_message;

        // 图片进 images
        assert_eq!(user_input.images.len(), 1, "图片应 hoist 到 images");

        // 文本进 tool_result content
        let tool_results = &user_input.user_input_message_context.tool_results;
        assert_eq!(tool_results.len(), 1);
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(
            text, "file contents above image",
            "文本不应丢失，应完整写入 tool_result content"
        );
    }

    /// TC-35-04：多个 image block → 全部 hoist 进 images
    #[test]
    fn test_issue35_multiple_images_all_hoisted() {
        let content = serde_json::json!([
            {
                "type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": test_png_base64()}
            },
            {
                "type": "image",
                "source": {"type": "base64", "media_type": "image/jpeg", "data": "/9j/fake_jpeg=="}
            }
        ]);
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("应成功转换");

        let images = &result
            .conversation_state
            .current_message
            .user_input_message
            .images;

        assert_eq!(images.len(), 2, "两张图片都应 hoist");
        assert_eq!(images[0].format, "png");
        assert_eq!(images[1].format, "jpeg");
    }

    /// TC-35-05：不支持的 media_type（image/svg+xml）→ 静默跳过，images 空，不 panic
    #[test]
    fn test_issue35_unsupported_media_type_silently_skipped() {
        let content = serde_json::json!([{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/svg+xml",
                "data": "PHN2ZyB4bWxucz0i"
            }
        }]);
        let req = make_req_with_tool_result_image(content);
        // 不应 panic
        let result =
            convert_request(&req, &test_registry()).expect("应成功转换，不支持的格式静默跳过");

        let images = &result
            .conversation_state
            .current_message
            .user_input_message
            .images;
        assert!(images.is_empty(), "不支持的格式应静默跳过，images 应为空");
    }

    /// TC-35-06：回归——无图的空 tool_result 仍兜底 "(empty result)"（向后兼容）
    #[test]
    fn test_issue35_regression_empty_tool_result_still_uses_empty_placeholder() {
        let content = serde_json::json!("");
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("应成功转换");

        let tool_results = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tool_results;

        assert_eq!(tool_results.len(), 1);
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(
            text, "(empty result)",
            "无图空 tool_result 应仍用 (empty result) 占位"
        );
    }

    /// TC-35-07：端到端——完整请求转换后 images 非空 + tool_result 文本为图片占位符
    #[test]
    fn test_issue35_e2e_image_hoist_and_placeholder() {
        let content = serde_json::json!([{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": test_png_base64()
            }
        }]);
        let req = make_req_with_tool_result_image(content);
        let result = convert_request(&req, &test_registry()).expect("端到端转换应成功");

        let user_input = &result.conversation_state.current_message.user_input_message;

        // 1. images 非空
        assert!(
            !user_input.images.is_empty(),
            "userInputMessage.images 应非空（图片已 hoist）"
        );

        // 2. tool_result 文本为图片占位符
        let tool_results = &user_input.user_input_message_context.tool_results;
        assert_eq!(tool_results.len(), 1, "应有 1 个 tool_result");
        let text = tool_results[0].content[0]["text"].as_str().unwrap();
        assert_eq!(
            text, TOOL_RESULT_IMAGE_PLACEHOLDER,
            "仅图时 tool_result 文本应为图片占位符"
        );

        // 3. 序列化后不含空 text
        let json = serde_json::to_string(&result.conversation_state).unwrap();
        assert!(!json.contains("\"text\":\"\""), "序列化结果不应含空 text");
    }

    /// TC-35-08：is_error=true 且 content 仅含 image（无文本）→
    ///   图片仍 hoist 到 images，但 tool_result 文本走 error 专用占位
    ///   "(tool returned no error message)"，而非 TOOL_RESULT_IMAGE_PLACEHOLDER
    #[test]
    fn test_issue35_error_tool_result_image_only_keeps_error_placeholder() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        // 内联构造带 is_error=true 的 tool_result 请求
        let mut schema = std::collections::HashMap::new();
        schema.insert("type".to_string(), serde_json::json!("object"));
        schema.insert("properties".to_string(), serde_json::json!({}));
        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("run a tool"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!([
                        {"type": "tool_use", "id": "tu_err_img", "name": "Read", "input": {}}
                    ]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([{
                        "type": "tool_result",
                        "tool_use_id": "tu_err_img",
                        "is_error": true,
                        "content": [{
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": test_png_base64()
                            }
                        }]
                    }]),
                },
            ],
            stream: false,
            system: None,
            tools: Some(vec![AnthropicTool {
                name: "Read".to_string(),
                description: "Read file".to_string(),
                input_schema: schema,
                tool_type: None,
                max_uses: None,
                cache_control: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result = convert_request(&req, &test_registry()).expect("应成功转换");
        let user_input = &result.conversation_state.current_message.user_input_message;

        // (a) 图片仍 hoist 到 images
        assert_eq!(
            user_input.images.len(),
            1,
            "error 场景图片也应 hoist 到 images"
        );

        let tool_results = &user_input.user_input_message_context.tool_results;
        assert_eq!(tool_results.len(), 1, "应有 1 个 tool_result");

        let text = tool_results[0].content[0]["text"].as_str().unwrap();

        // (b) 文本应为 error 专用占位，而非图片占位
        assert_eq!(
            text, "(tool returned no error message)",
            "error+仅图时应走 error 专用占位，不应用 TOOL_RESULT_IMAGE_PLACEHOLDER"
        );
        assert_ne!(
            text, TOOL_RESULT_IMAGE_PLACEHOLDER,
            "不应用图片占位符——那会丢失 error 语义"
        );

        // (c) tool_result 的 is_error 为 true
        assert!(tool_results[0].is_error, "tool_result.is_error 应为 true");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // plan mode 信号回归测试（issue #40）
    // ═══════════════════════════════════════════════════════════════════════

    /// plan-mode-T1：system block 中的 plan reminder 文本经 convert_request 后完整保留，
    /// billing header 行正常剥离（双断言——证伪 without_anthropic_billing_headers 回归用）
    #[test]
    fn test_plan_mode_reminder_in_system_preserved() {
        use super::super::types::{Message as AnthropicMessage, SystemMessage};

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("hello"),
            }],
            stream: false,
            system: Some(vec![
                SystemMessage {
                    // 真实 billing header 行——应被 without_anthropic_billing_headers 剥离
                    text: "x-anthropic-billing-header: cc_version=2.1.87.1; cch=test;".to_string(),
                    cache_control: None,
                },
                SystemMessage {
                    // plan reminder 元素——应完整保留
                    text: "You are an assistant.\n<system-reminder>Plan Mode is enabled. Never write files.</system-reminder>".to_string(),
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

        let result = convert_request(&req, &test_registry()).expect("request should convert");
        let system_content = match &result.conversation_state.history[0] {
            Message::User(msg) => &msg.user_input_message.content,
            _ => panic!("history[0] should be User (system pair)"),
        };

        // billing header 已剥离（非平凡断言——fixture 含 billing 行，若 strip 回归此处 fail）
        assert!(
            !system_content.contains("x-anthropic-billing-header"),
            "billing header line should be stripped"
        );
        assert!(
            !system_content.contains("cch=test"),
            "billing header content should be stripped"
        );
        // plan reminder 文本完整保留
        assert!(
            system_content.contains("Plan Mode is enabled"),
            "plan reminder text should survive convert_request"
        );
        assert!(
            system_content.contains("Never write files"),
            "plan reminder tail should survive convert_request"
        );
    }

    /// plan-mode-T2：user content 文本块中的 plan reminder 经 convert_request 后完整保留
    ///
    /// 2a：current_message 路径（process_message_content）
    /// 2b：历史轮路径（merge_user_messages — if !text.is_empty() skip 路径）
    #[test]
    fn test_plan_mode_reminder_in_user_content_preserved() {
        use super::super::types::Message as AnthropicMessage;

        // ── 2a：current_message 路径 ──────────────────────────────────────
        let req_2a = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!([{
                    "type": "text",
                    "text": "<system-reminder>Plan Mode enabled. In plan mode, never write files.</system-reminder>"
                }]),
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
        };

        let result_2a =
            convert_request(&req_2a, &test_registry()).expect("2a: request should convert");
        let current_content = &result_2a
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(
            current_content.contains("Plan Mode enabled"),
            "2a: plan reminder in current_message user content should be preserved"
        );

        // ── 2b：历史轮路径（merge_user_messages） ───────────────────────────
        // msg[0] user + msg[1] assistant → history pair
        // msg[2] user with plan reminder → history (via merge_user_messages)
        // msg[3] user "final" → current_message
        let req_2b = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("start"),
                },
                AnthropicMessage {
                    role: "assistant".to_string(),
                    content: serde_json::json!("OK"),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!([{
                        "type": "text",
                        "text": "<system-reminder>Plan Mode is enabled.</system-reminder>\nWhat should I do next?"
                    }]),
                },
                AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("final message"),
                },
            ],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            temperature: None,
            top_p: None,
            metadata: None,
        };

        let result_2b =
            convert_request(&req_2b, &test_registry()).expect("2b: request should convert");
        // msg[2] 经 build_history 的 trailing user_buffer 走 merge_user_messages 处理。
        // history 可能 merge 成 [user(start+reminder), assistant(OK)]，
        // 也可能是 [user(start), assistant(OK), user(reminder)]。
        // 无论哪种，history 中总有某条 User 消息包含 reminder 文本。
        let reminder_in_history = result_2b.conversation_state.history.iter().any(|msg| {
            if let Message::User(u) = msg {
                u.user_input_message
                    .content
                    .contains("Plan Mode is enabled")
            } else {
                false
            }
        });
        assert!(
            reminder_in_history,
            "2b: plan reminder in historical user turn should be preserved through merge_user_messages"
        );
    }

    /// plan-mode-T3：ExitPlanMode / EnterPlanMode 工具名经 convert_request 后完整保留，
    /// 且无名称缩短（tool_name_map 为空）
    #[test]
    fn test_plan_mode_tools_exit_enter_preserved() {
        use super::super::types::{Message as AnthropicMessage, Tool as AnthropicTool};

        let schema = {
            let mut m = std::collections::HashMap::new();
            m.insert("type".to_string(), serde_json::json!("object"));
            m.insert("properties".to_string(), serde_json::json!({}));
            m
        };

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: serde_json::json!("should I exit plan mode?"),
            }],
            stream: false,
            system: None,
            tools: Some(vec![
                AnthropicTool {
                    name: "ExitPlanMode".to_string(),
                    description: "Exit plan mode".to_string(),
                    input_schema: schema.clone(),
                    tool_type: None,
                    max_uses: None,
                    cache_control: None,
                },
                AnthropicTool {
                    name: "EnterPlanMode".to_string(),
                    description: "Enter plan mode".to_string(),
                    input_schema: schema,
                    tool_type: None,
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

        let result = convert_request(&req, &test_registry()).expect("request should convert");

        // 名称在 63 字符以内，不触发缩短
        assert!(
            result.tool_name_map.is_empty(),
            "ExitPlanMode/EnterPlanMode are under TOOL_NAME_MAX_LEN; tool_name_map should be empty"
        );

        // convert_tools 的输出落地的精确字段路径
        let tools = &result
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .tools;

        assert_eq!(tools.len(), 2, "both plan mode tools should be present");
        assert_eq!(
            tools[0].tool_specification.name, "ExitPlanMode",
            "first tool name should be ExitPlanMode unchanged"
        );
        assert_eq!(
            tools[1].tool_specification.name, "EnterPlanMode",
            "second tool name should be EnterPlanMode unchanged"
        );
    }

    // === thinking/effort 透传：配置驱动判据矩阵测试 ===
    //
    // 判据从「请求 thinking.type」改为「模型配置 thinking_type」（registry.thinking_config）。
    // claude-sonnet-5 在 models.toml 中配置 thinking_type = adaptive；
    // claude-opus-4-5-20251101 配置 thinking_type = enabled——用这两个真实模型名
    // 覆盖矩阵中「配置 adaptive」与「配置 enabled」两条分支及其非对称的空 thinking 处理。

    fn thinking_req(
        model: &str,
        thinking: Option<super::super::types::Thinking>,
        output_config: Option<super::super::types::OutputConfig>,
    ) -> MessagesRequest {
        MessagesRequest {
            model: model.to_string(),
            max_tokens: 1024,
            messages: vec![],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking,
            output_config,
            temperature: None,
            top_p: None,
            metadata: None,
        }
    }
    #[test]
    fn test_thinking_matrix_enabled_request_adaptive_config_produces_structured() {
        // 1. 请求 enabled × claude-sonnet-5（配置 adaptive）→ 结构化 adaptive+effort，无文本前缀
        let req = thinking_req(
            "claude-sonnet-5",
            Some(super::super::types::Thinking {
                thinking_type: "enabled".to_string(),
                budget_tokens: 20000,
            }),
            None,
        );
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        assert_eq!(structured["thinking"]["type"], "adaptive");
        assert_eq!(structured["output_config"]["effort"], "high");
    }

    #[test]
    fn test_thinking_matrix_adaptive_request_adaptive_config_produces_structured() {
        // 2. 请求 adaptive × claude-sonnet-5（配置 adaptive）→ 结构化 adaptive+effort
        let req = thinking_req(
            "claude-sonnet-5",
            Some(super::super::types::Thinking {
                thinking_type: "adaptive".to_string(),
                budget_tokens: 20000,
            }),
            None,
        );
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        assert_eq!(structured["thinking"]["type"], "adaptive");
        assert_eq!(structured["output_config"]["effort"], "high");
    }

    #[test]
    fn test_thinking_matrix_no_thinking_adaptive_config_still_produces_structured() {
        // 3. 无 thinking × claude-sonnet-5（配置 adaptive）→ 结构化 adaptive+effort
        // Sonnet-5 官方客户端常省略 thinking 字段，adaptive 配置下仍应开启结构化透传。
        let req = thinking_req("claude-sonnet-5", None, None);
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        assert_eq!(structured["thinking"]["type"], "adaptive");
        assert_eq!(structured["output_config"]["effort"], "high");
    }

    #[test]
    fn test_thinking_matrix_no_thinking_enabled_config_stays_pure() {
        // 4. 无 thinking × claude-opus-4-5-20251101（配置 enabled）→ 无结构化、无文本前缀
        // 防污染断言：老模型的常规请求不应因为判据改动而被意外注入任何 thinking 相关内容。
        let req = thinking_req("claude-opus-4-5-20251101", None, None);
        let registry = test_registry();

        assert!(build_additional_model_request_fields(&req, &registry).is_none());
    }

    #[test]
    fn test_enabled_config_model_produces_no_structured_fields() {
        // 5+6 合并（原两条 prefix 用例随 generate_thinking_prefix 一并删除）：
        // 配置 enabled 的模型无论客户端请求 enabled 还是 adaptive，都不产结构化字段。
        // 上游实测背书：opus-4.5 收到 additionalModelRequestFields 直接 400
        // "additionalModelRequestFields is not supported for this model"，
        // 故「不产出」是唯一正确行为，不是能力缺失。
        let registry = test_registry();

        for req_type in ["enabled", "adaptive"] {
            let req = thinking_req(
                "claude-opus-4-5-20251101",
                Some(super::super::types::Thinking {
                    thinking_type: req_type.to_string(),
                    budget_tokens: 12345,
                }),
                None,
            );
            assert!(
                build_additional_model_request_fields(&req, &registry).is_none(),
                "请求 thinking.type={req_type} 时 enabled 配置模型不应产出结构化字段"
            );
        }
    }

    #[test]
    fn test_thinking_matrix_client_effort_overrides_config_default() {
        // 7. 客户端 output_config.effort=medium × claude-sonnet-5 → 结构化 effort=medium
        //    （覆盖配置默认 high）
        let req = thinking_req(
            "claude-sonnet-5",
            None,
            Some(super::super::types::OutputConfig {
                effort: "medium".to_string(),
            }),
        );
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        assert_eq!(structured["thinking"]["type"], "adaptive");
        assert_eq!(structured["output_config"]["effort"], "medium");
    }

    #[test]
    fn test_thinking_matrix_disabled_wins_over_any_config() {
        // 8. 请求 disabled × 任意配置 → 两者都不产（客户端主动关闭优先级最高）
        let registry = test_registry();

        for model in ["claude-sonnet-5", "claude-opus-4-5-20251101"] {
            let req = thinking_req(
                model,
                Some(super::super::types::Thinking {
                    thinking_type: "disabled".to_string(),
                    budget_tokens: 0,
                }),
                None,
            );
            assert!(
                build_additional_model_request_fields(&req, &registry).is_none(),
                "model {model} 应无结构化字段"
            );
        }
    }

    #[test]
    fn test_thinking_matrix_budget_tokens_not_referenced_in_adaptive_payload() {
        // 分支 (a) 背书：adaptive 配置下客户端仍带 budget_tokens 时，
        // 结构化 payload 本身不引用 budget_tokens（上游宽容无视）。
        // 注：忽略事件走 debug 日志（非 warn，避免每请求刷屏），此处只断言 payload 形态。
        let req = thinking_req(
            "claude-sonnet-5",
            Some(super::super::types::Thinking {
                thinking_type: "enabled".to_string(),
                budget_tokens: 9999,
            }),
            None,
        );
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        // 结构化 payload 不应包含 budget_tokens 字段。
        assert!(structured.get("budget_tokens").is_none());
        assert!(structured["thinking"].get("budget_tokens").is_none());
    }

    // === effort 透传修正：三项改动（A/B/C）的 BDD 回归测试 ===
    //
    // 背景：全 13 模型黑盒实测（2026-08-05）确定了上游对
    // additionalModelRequestFields 的能力边界——
    // opus-5/4.8/4.7/4.6/sonnet-5/sonnet-4-6 接受（200）；
    // opus-4.5/sonnet-4.5/haiku-4.5 拒绝（400 "additionalModelRequestFields is
    // not supported for this model"）；gpt-5.6 三变体拒绝（400 "property
    // 'output_config' is not defined in the schema"）。这组测试守住三条边界：
    // 谁该产出结构化字段、谁绝不能产出、以及旧文本前缀机制被彻底清除。

    #[test]
    fn test_sonnet_4_6_adaptive_config_produces_structured_effort() {
        // 改动 C 验证：claude-sonnet-4-6 的 thinking_type 由 "enabled" 改为
        // "adaptive"（models.toml），客户端 effort=max 应透传为结构化字段。
        let req = thinking_req(
            "claude-sonnet-4-6",
            None,
            Some(super::super::types::OutputConfig {
                effort: "max".to_string(),
            }),
        );
        let registry = test_registry();

        let structured = build_additional_model_request_fields(&req, &registry).unwrap();
        assert_eq!(structured["thinking"]["type"], "adaptive");
        assert_eq!(structured["output_config"]["effort"], "max");
    }

    #[test]
    fn test_non_adaptive_models_never_produce_additional_fields() {
        // 护栏（最重要）：这些模型上游对 additionalModelRequestFields 直接 400——
        // opus-4.5/sonnet-4.5/haiku-4.5 → "additionalModelRequestFields is not
        // supported for this model"；gpt-5.6 三变体 → "property 'output_config'
        // is not defined in the schema"。无论客户端是否传 thinking/output_config，
        // 都绝不能产出该字段，否则整个请求被上游拒绝。
        let registry = test_registry();
        let non_adaptive_models = [
            "claude-opus-4-5-20251101",
            "claude-sonnet-4-5-20250929",
            "claude-haiku-4-5-20251001",
            "gpt-5-6-sol",
            "gpt-5-6-terra",
            "gpt-5-6-luna",
        ];

        for model in non_adaptive_models {
            // 分支 1：客户端什么都没传
            let req = thinking_req(model, None, None);
            assert!(
                build_additional_model_request_fields(&req, &registry).is_none(),
                "model {model} 无 thinking/output_config 时仍不应产出结构化字段"
            );

            // 分支 2：客户端传了 enabled thinking
            let req = thinking_req(
                model,
                Some(super::super::types::Thinking {
                    thinking_type: "enabled".to_string(),
                    budget_tokens: 20000,
                }),
                None,
            );
            assert!(
                build_additional_model_request_fields(&req, &registry).is_none(),
                "model {model} 传 enabled thinking 时仍不应产出结构化字段"
            );

            // 分支 3：客户端传了 output_config.effort
            let req = thinking_req(
                model,
                None,
                Some(super::super::types::OutputConfig {
                    effort: "max".to_string(),
                }),
            );
            assert!(
                build_additional_model_request_fields(&req, &registry).is_none(),
                "model {model} 传 output_config.effort 时仍不应产出结构化字段"
            );

            // 分支 4/5：客户端传 adaptive 或 disabled，同样不得产出——
            // adaptive 是最危险的一支（模型配置不是 adaptive，但客户端可能主动发），
            // 若判据误读请求 type 就会给这些模型发出 400 payload。
            for req_type in ["adaptive", "disabled"] {
                let req = thinking_req(
                    model,
                    Some(super::super::types::Thinking {
                        thinking_type: req_type.to_string(),
                        budget_tokens: 20000,
                    }),
                    Some(super::super::types::OutputConfig {
                        effort: "max".to_string(),
                    }),
                );
                assert!(
                    build_additional_model_request_fields(&req, &registry).is_none(),
                    "model {model} 传 thinking.type={req_type} 时仍不应产出结构化字段"
                );
            }
        }
    }

    #[test]
    fn test_adaptive_models_all_produce_structured_effort() {
        // 正面覆盖：全部配置为 adaptive 的模型都应产出结构化 effort 字段。
        let registry = test_registry();
        let adaptive_models = [
            "claude-opus-5",
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
        ];

        for model in adaptive_models {
            let req = thinking_req(model, None, None);
            let structured = build_additional_model_request_fields(&req, &registry)
                .unwrap_or_else(|| panic!("model {model} 应产出结构化字段"));
            assert_eq!(
                structured["thinking"]["type"], "adaptive",
                "model {model} thinking.type 应为 adaptive"
            );
            // 钉死确值而非仅 is_string()：这些模型在 models.toml 里都配了
            // thinking_effort = "high"，配置写空串或错值时必须失败而非放过。
            assert_eq!(
                structured["output_config"]["effort"], "high",
                "model {model} 应取配置的 thinking_effort=high"
            );
        }
    }

    #[test]
    fn test_thinking_prefix_gone_for_all_models() {
        // 改动 B 验证：generate_thinking_prefix 删除后，convert_request 产出的
        // 请求体（序列化后的 conversation_state JSON）不应再包含 <thinking_mode>
        // 文本前缀字面，覆盖全部 13 个模型 id（含旧 "enabled" 配置模型）。
        // 注意：该函数被删除后不存在，因此从 convert_request 的输出层面断言，
        // 而不是直接调用即将被删除的函数。
        use super::super::types::Message as AnthropicMessage;

        let registry = test_registry();
        let all_model_ids = [
            "claude-opus-5",
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-opus-4-5-20251101",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-sonnet-4-5-20250929",
            "claude-haiku-4-5-20251001",
            "gpt-5-6-sol",
            "gpt-5-6-terra",
            "gpt-5-6-luna",
        ];

        for model in all_model_ids {
            let req = MessagesRequest {
                model: model.to_string(),
                max_tokens: 1024,
                messages: vec![AnthropicMessage {
                    role: "user".to_string(),
                    content: serde_json::json!("hello"),
                }],
                stream: false,
                system: Some(vec![super::super::types::SystemMessage {
                    text: "You are an assistant.".to_string(),
                    cache_control: None,
                }]),
                tools: None,
                tool_choice: None,
                thinking: Some(super::super::types::Thinking {
                    thinking_type: "enabled".to_string(),
                    budget_tokens: 20000,
                }),
                output_config: None,
                temperature: None,
                top_p: None,
                metadata: None,
            };

            let result = convert_request(&req, &registry)
                .unwrap_or_else(|e| panic!("model {model} 应能成功转换: {e:?}"));
            let json = serde_json::to_string(&result.conversation_state).unwrap();
            assert!(
                !json.contains("<thinking_mode>"),
                "model {model} 转换结果不应含 <thinking_mode> 文本前缀"
            );
            assert!(
                !json.contains("<max_thinking_length>"),
                "model {model} 转换结果不应含 <max_thinking_length> 文本前缀"
            );
        }
    }

    #[test]
    fn test_effort_disabled_produces_nothing_on_adaptive_model() {
        // 守住不回归：客户端主动 disabled，即便模型配置为 adaptive，
        // 也绝不产出结构化字段（disabled 优先级最高）。
        let req = thinking_req(
            "claude-sonnet-5",
            Some(super::super::types::Thinking {
                thinking_type: "disabled".to_string(),
                budget_tokens: 0,
            }),
            None,
        );
        let registry = test_registry();

        assert!(build_additional_model_request_fields(&req, &registry).is_none());
    }
}
