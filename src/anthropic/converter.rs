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

use super::types::{ContentBlock, MessagesRequest};

/// JSON Schema composition/reference keys that are valid without object-only fields.
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

    // type：只在缺失或无效且不是组合/$ref schema 时补 object，避免改变有效 schema 语义。
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
    !has_composition || obj.contains_key("properties") || obj.contains_key("required")
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

/// 模型映射：将 Anthropic 模型名映射到 Kiro 模型 ID
///
/// 按照用户要求：
/// - sonnet 4.6/4-6 → claude-sonnet-4.6
/// - 其他 sonnet → claude-sonnet-4.5
/// - opus 4.5/4-5 → claude-opus-4.5
/// - opus 4.7/4-7 → claude-opus-4.7
/// - opus 4.8/4-8 → claude-opus-4.8
/// - 其他 opus → claude-opus-4.6
/// - 所有 haiku → claude-haiku-4.5
pub fn map_model(model: &str) -> Option<String> {
    let model_lower = model.to_lowercase();

    if model_lower.contains("sonnet") {
        if model_lower.contains("4-6") || model_lower.contains("4.6") {
            Some("claude-sonnet-4.6".to_string())
        } else {
            Some("claude-sonnet-4.5".to_string())
        }
    } else if model_lower.contains("opus") {
        if model_lower.contains("4-8") || model_lower.contains("4.8") {
            Some("claude-opus-4.8".to_string())
        } else if model_lower.contains("4-7") || model_lower.contains("4.7") {
            Some("claude-opus-4.7".to_string())
        } else if model_lower.contains("4-5") || model_lower.contains("4.5") {
            Some("claude-opus-4.5".to_string())
        } else {
            Some("claude-opus-4.6".to_string())
        }
    } else if model_lower.contains("haiku") {
        Some("claude-haiku-4.5".to_string())
    } else {
        None
    }
}

/// 根据模型名称返回对应的上下文窗口大小
///
/// 复用 `map_model` 的映射逻辑，确保窗口大小判断与模型映射一致。
/// Kiro 于 2026-03-24 将 Opus 4.6 和 Sonnet 4.6 升级至 1M 上下文。
pub fn get_context_window_size(model: &str) -> i32 {
    match map_model(model) {
        Some(mapped)
            if mapped == "claude-sonnet-4.6"
                || mapped == "claude-opus-4.6"
                || mapped == "claude-opus-4.7"
                || mapped == "claude-opus-4.8" =>
        {
            1_000_000
        }
        _ => 200_000,
    }
}

/// 转换结果
#[derive(Debug)]
pub struct ConversionResult {
    /// 转换后的 Kiro 请求
    pub conversation_state: ConversationState,
    /// 工具名称映射（短名称 → 原始名称），仅当存在超长工具名时非空
    pub tool_name_map: HashMap<String, String>,
    /// 推理配置
    pub inference_config: Option<crate::kiro::model::requests::kiro::InferenceConfig>,
    /// history 首部是否注入了 system 对（User+Assistant 伪装）。
    /// system 对在数据结构上与普通消息无法区分，必须在注入点记录并向下游传递，
    /// 供 `trim_history_to_byte_limit` 保护首部不可裁对数。
    pub has_system_pair: bool,
}

/// payload 大小裁剪统计，用于 warn 日志记录
pub struct TrimStats {
    /// 裁掉的 (User, Assistant) 对数
    pub pairs_removed: usize,
    /// 裁剪前 body 字节数（`KiroRequest` 完整序列化大小）
    pub bytes_before: usize,
    /// 裁剪后 body 字节数的保守上界：因 cut_bytes 是真实删除量的安全低估，
    /// `bytes_before - cut_bytes` 是裁后真实大小的高估上界（真实值 ≤ 此值 ≤ max_bytes）。
    pub bytes_after_est: usize,
}

/// 每次请求读取 env `KIRO_MAX_PAYLOAD_BYTES`，若未设置或解析失败则使用默认值。
///
/// 默认 900 KiB（921600 字节），保守阈值优先避免误删历史。
/// 每次请求现读而非 LazyLock 缓存，使运维可热调阈值无需重启进程。
pub(crate) fn max_payload_bytes() -> usize {
    const DEFAULT: usize = 900 * 1024; // 900 KiB
    std::env::var("KIRO_MAX_PAYLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT)
}

/// 最近保留的 (User, Assistant) 对数，确保活跃 tool turn 永在保留区内。
const KEEP_RECENT_PAIRS: usize = 2;

/// 对 `conversation_state.history` 做 proactive 大小裁剪。
///
/// 只裁 history 字段；不触碰 `payload.messages`（prompt cache 指纹的数据源）；
/// 不触碰 current_message（独立字段）。
///
/// # 参数
/// * `state` - 可变的对话状态；`history` 已经过 `validate_tool_pairing` / `remove_orphaned_tool_uses` 配对校验
/// * `has_system_pair` - build_history 注入 system 对时置 true；首 2 条永不裁
/// * `max_bytes` - 最大允许 body 大小（字节），由调用方传入 `max_payload_bytes()`
/// * `bytes_before` - 调用方已测量的完整 `KiroRequest` 序列化大小，复用避免重复序列化
///
/// # 返回
/// `Some(TrimStats)` 表示执行了裁剪；`None` 表示无需裁剪、无可裁对或结构异常（fail-open）。
///
/// # 安全保证
/// - system 对（前 `pinned_front` 条）永不裁
/// - 尾部 `KEEP_RECENT_PAIRS` 对（4 条）永不裁，保护活跃 tool turn
/// - 遇结构异常（role 不成对、首条非 User）→ fail-open：跳过裁剪、warn 记录、返回 None
/// - 裁剪算法安全低估（漏掉相邻逗号），数学保证一轮达标，不需补删循环
pub(crate) fn trim_history_to_byte_limit(
    state: &mut ConversationState,
    has_system_pair: bool,
    max_bytes: usize,
    bytes_before: usize,
) -> Option<TrimStats> {
    if bytes_before <= max_bytes {
        // 未超限，热路径零额外成本
        return None;
    }

    let history = &mut state.history;
    let len = history.len();

    // ── 鲁棒性检查（运行时检查，非 debug_assert，release 下同样生效）──
    // history 必须严格 User/Assistant 交替（build_history 保证），否则 fail-open
    if !len.is_multiple_of(2) {
        tracing::warn!(
            len,
            "history 长度为奇数，结构异常，跳过 payload 裁剪（fail-open）"
        );
        return None;
    }
    if len > 0 && !matches!(history[0], Message::User(_)) {
        tracing::warn!("history 首条非 User，结构异常，跳过 payload 裁剪（fail-open）");
        return None;
    }

    // ── 计算可裁窗口 ──────────────────────────────────────────────────────
    // 前 pinned_front 条（system 对）永不裁；尾部保留 KEEP_RECENT_PAIRS 对（4 条）
    let pinned_front = if has_system_pair { 2 } else { 0 };
    let pinned_tail = KEEP_RECENT_PAIRS * 2;

    // 可裁区间：[pinned_front, len - pinned_tail)
    if len <= pinned_front + pinned_tail {
        tracing::warn!(
            bytes_before,
            max_bytes,
            "无可裁对（全被 system/活跃对锁住），原样发送（map_provider_error 兜底）"
        );
        return None;
    }

    let cuttable_end = len - pinned_tail; // exclusive

    // ── 正向裁剪（旧 → 新），低估计算，一轮达标 ──────────────────────────
    let excess = bytes_before - max_bytes;
    let mut cut_bytes: usize = 0;
    let mut pairs_to_remove: usize = 0;
    let mut reached = false; // 是否累积到足够字节（cut_bytes >= excess）

    let mut i = pinned_front;
    while i + 1 < cuttable_end {
        let user_msg = &history[i];
        let assistant_msg = &history[i + 1];

        // 鲁棒性：窗口内 role 不成对属结构异常 → 真正 fail-open（不修改 history）
        if !matches!(user_msg, Message::User(_)) || !matches!(assistant_msg, Message::Assistant(_))
        {
            tracing::warn!(
                i,
                "裁剪窗口内 role 不成对，结构异常，跳过裁剪（fail-open，不修改 history）"
            );
            return None;
        }

        // 对整个 Message 序列化（含 tool_uses 等全部字段），安全低估
        // 漏掉的仅是相邻元素间的结构性逗号，故 est ≤ 该对在 body 中的真实字节
        let est = serde_json::to_string(user_msg)
            .map(|s| s.len())
            .unwrap_or(0)
            + serde_json::to_string(assistant_msg)
                .map(|s| s.len())
                .unwrap_or(0);

        cut_bytes += est;
        pairs_to_remove += 1;

        if cut_bytes >= excess {
            // 已累积足够字节，一轮达标，停止
            reached = true;
            break;
        }

        i += 2;
    }

    // 删光整个可裁窗口仍不足以覆盖 excess（超限主要来自 system/tools/current 等不可裁部分），
    // 或窗口内本就无可删对 → 真正 fail-open：不裁剪、保留历史，交 map_provider_error 兜底。
    // 仅在 reached 时返回 Some，锁住不变量「返回 Some ⟺ 裁后 body ≤ max_bytes」。
    if !reached {
        tracing::warn!(
            bytes_before,
            max_bytes,
            cut_bytes,
            "可裁窗口不足以将 payload 裁剪到限内，跳过裁剪（fail-open），交 map_provider_error 兜底"
        );
        return None;
    }

    // ── 调整裁剪边界到对话回合边界（删 sanitize_history_tools 后必须，#26）────────
    // trim 机械按 (User, Assistant) 对裁，但 tool_use（Assistant 轮）对应的 tool_result
    // 落在下一对的 User 轮——跨对依赖。历史保留结构化 tool 数据后，若 drain 边界切在
    // 「回合中段」（tool_result 轮），被裁 tool_use 的 tool_result 会孤立 → Kiro 400。
    // 故把 drain_end 向后吸附到下一个「真实用户输入轮」（tool_results 为空的 User）作为
    // 回合边界：裁掉若干完整回合，剩余 history 从干净用户输入开始，无跨界孤立配对。
    // drain_end 恒偶数（pinned_front 偶 + 偶），history 首条 User ⟹ 偶数索引恒为 User。
    let mut drain_end = pinned_front + pairs_to_remove * 2;
    loop {
        let at_turn_boundary = match &history[drain_end] {
            Message::User(u) => u
                .user_input_message
                .user_input_message_context
                .tool_results
                .is_empty(),
            Message::Assistant(_) => false,
        };
        if at_turn_boundary {
            break; // drain_end 处是真实用户输入轮，可安全裁到此
        }
        drain_end += 2;
        if drain_end > cuttable_end {
            // 吸附越过保留区起点仍无干净边界 → 末尾是横跨保留区的超长 tool 回合，
            // 无法在不孤立 tool_result 的前提下裁剪 → fail-open，原样发送交 map_provider_error。
            tracing::warn!(
                bytes_before,
                max_bytes,
                "可裁区无安全回合边界（tool 回合横跨保留区），跳过裁剪（fail-open）"
            );
            return None;
        }
    }

    // ── 执行裁剪：一次性 drain ────────────────────────────────────────────
    let pairs_removed = (drain_end - pinned_front) / 2;
    state.history.drain(pinned_front..drain_end);

    // bytes_after_est = bytes_before - cut_bytes。cut_bytes 是「裁到 pairs_to_remove」的安全
    // 低估；吸附后实际裁的对 ≥ pairs_to_remove，真实删除量 ≥ cut_bytes ≥ excess，故此值仍是
    // 裁后真实 body 的保守上界（真实值 ≤ 此值），reached 保证它 ≤ max_bytes。
    let bytes_after_est = bytes_before.saturating_sub(cut_bytes);
    Some(TrimStats {
        pairs_removed,
        bytes_before,
        bytes_after_est,
    })
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
fn extract_session_id(user_id: &str) -> Option<String> {
    // 先尝试 JSON 解析
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(user_id)
        && let Some(session_id) = json.get("session_id").and_then(|v| v.as_str())
        && is_valid_uuid(session_id)
    {
        return Some(session_id.to_string());
    }

    // 回退到字符串格式: 查找 "session_" 后面的内容
    if let Some(pos) = user_id.find("session_") {
        let session_part = &user_id[pos + 8..]; // "session_" 长度为 8
        if session_part.len() >= 36 {
            let uuid_str = &session_part[..36];
            if is_valid_uuid(uuid_str) {
                return Some(uuid_str.to_string());
            }
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
pub fn convert_request(req: &MessagesRequest) -> Result<ConversionResult, ConversionError> {
    // 1. 映射模型
    let model_id = map_model(&req.model)
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
    // 优先从 metadata.user_id 中提取 session UUID 作为 conversationId
    let conversation_id = req
        .metadata
        .as_ref()
        .and_then(|m| m.user_id.as_ref())
        .and_then(|user_id| extract_session_id(user_id))
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
    // build_history 同时返回 has_system_pair flag：system 对伪装成普通 User+Assistant，
    // 无法从数据反推，必须在注入点记录并向下游传递（供裁剪保护首部不可裁对数）
    let (mut history, has_system_pair) =
        build_history(req, messages, &model_id, &mut tool_name_map)?;

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
        has_system_pair,
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
                                let result_content = extract_tool_result_content(&block.content);
                                let is_error = block.is_error.unwrap_or(false);

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

/// 提取工具结果内容
fn extract_tool_result_content(content: &Option<serde_json::Value>) -> String {
    match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            let mut parts = Vec::new();
            for item in arr {
                if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                    parts.push(text.to_string());
                }
            }
            parts.join("\n")
        }
        Some(v) => v.to_string(),
        None => String::new(),
    }
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

            // 限制描述长度为 10000 字符（安全截断 UTF-8，单次遍历）
            let description = match description.char_indices().nth(10000) {
                Some((idx, _)) => description[..idx].to_string(),
                None => description,
            };

            Tool {
                tool_specification: ToolSpecification {
                    name: map_tool_name(&t.name, tool_name_map),
                    description,
                    input_schema: InputSchema::from_json(normalize_json_schema(serde_json::json!(
                        t.input_schema
                    ))),
                },
            }
        })
        .collect()
}

/// 生成thinking标签前缀
fn generate_thinking_prefix(req: &MessagesRequest) -> Option<String> {
    if let Some(t) = &req.thinking {
        if t.thinking_type == "enabled" {
            return Some(format!(
                "<thinking_mode>enabled</thinking_mode><max_thinking_length>{}</max_thinking_length>",
                t.budget_tokens
            ));
        } else if t.thinking_type == "adaptive" {
            let effort = req
                .output_config
                .as_ref()
                .map(|c| c.effort.as_str())
                .unwrap_or("high");
            return Some(format!(
                "<thinking_mode>adaptive</thinking_mode><thinking_effort>{}</thinking_effort>",
                effort
            ));
        }
    }
    None
}

/// 检查内容是否已包含thinking标签
fn has_thinking_tags(content: &str) -> bool {
    content.contains("<thinking_mode>") || content.contains("<max_thinking_length>")
}

/// 构建历史消息
///
/// # Arguments
/// * `req` - 原始请求，用于读取 `system`、`thinking` 等配置字段
/// * `messages` - 经过 prefill 预处理的消息切片，末尾必定是 user 消息。
///   注意：该切片与 `req.messages` 可能不同（prefill 时会截断末尾的 assistant 消息），
///   调用方应始终使用此参数而非 `req.messages`。
/// * `model_id` - 已映射的 Kiro 模型 ID
///
/// # Returns
/// `(history, has_system_pair)`：
/// - `history` - 构建好的历史消息列表
/// - `has_system_pair` - 是否在 history 首部注入了 system 对（User+Assistant 伪装）。
///   system 对无法从数据结构反推，必须在注入点记录，供 `trim_history_to_byte_limit` 保护。
fn build_history(
    req: &MessagesRequest,
    messages: &[super::types::Message],
    model_id: &str,
    tool_name_map: &mut HashMap<String, String>,
) -> Result<(Vec<Message>, bool), ConversionError> {
    let mut history = Vec::new();
    // 记录是否向 history 首部注入了 system 对；在两个注入分支处置 true，作为单一真相源
    let mut has_system_pair = false;

    // 生成thinking前缀（如果需要）
    let thinking_prefix = generate_thinking_prefix(req);

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

            // 注入thinking标签到系统消息最前面（如果需要且不存在）
            let final_content = if let Some(ref prefix) = thinking_prefix {
                if !has_thinking_tags(&system_content) {
                    format!("{}\n{}", prefix, system_content)
                } else {
                    system_content
                }
            } else {
                system_content
            };

            // 系统消息作为 user + assistant 配对注入 history 首部
            let user_msg = HistoryUserMessage::new(final_content, model_id);
            history.push(Message::User(user_msg));

            let assistant_msg = HistoryAssistantMessage::new("I will follow these instructions.");
            history.push(Message::Assistant(assistant_msg));

            // ← 系统注入分支 1：标记 has_system_pair
            has_system_pair = true;
        }
    } else if let Some(ref prefix) = thinking_prefix {
        // 没有系统消息但有thinking配置，插入新的系统消息（作为 system 对处理）
        let user_msg = HistoryUserMessage::new(prefix.clone(), model_id);
        history.push(Message::User(user_msg));

        let assistant_msg = HistoryAssistantMessage::new("I will follow these instructions.");
        history.push(Message::Assistant(assistant_msg));

        // ← 系统注入分支 2：标记 has_system_pair
        has_system_pair = true;
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

    Ok((history, has_system_pair))
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

    #[test]
    fn test_map_model_sonnet() {
        assert!(
            map_model("claude-sonnet-4-20250514")
                .unwrap()
                .contains("sonnet")
        );
        assert!(
            map_model("claude-3-5-sonnet-20241022")
                .unwrap()
                .contains("sonnet")
        );
    }

    #[test]
    fn test_map_model_opus() {
        assert!(
            map_model("claude-opus-4-20250514")
                .unwrap()
                .contains("opus")
        );
    }

    #[test]
    fn test_map_model_haiku() {
        assert!(
            map_model("claude-haiku-4-20250514")
                .unwrap()
                .contains("haiku")
        );
    }

    #[test]
    fn test_map_model_unsupported() {
        assert!(map_model("gpt-4").is_none());
    }

    #[test]
    fn test_map_model_thinking_suffix_sonnet() {
        // thinking 后缀不应影响 sonnet 模型映射
        let result = map_model("claude-sonnet-4-5-20250929-thinking");
        assert_eq!(result, Some("claude-sonnet-4.5".to_string()));
    }

    #[test]
    fn test_map_model_thinking_suffix_opus_4_5() {
        // thinking 后缀不应影响 opus 4.5 模型映射
        let result = map_model("claude-opus-4-5-20251101-thinking");
        assert_eq!(result, Some("claude-opus-4.5".to_string()));
    }

    #[test]
    fn test_map_model_thinking_suffix_opus_4_6() {
        // thinking 后缀不应影响 opus 4.6 模型映射
        let result = map_model("claude-opus-4-6-thinking");
        assert_eq!(result, Some("claude-opus-4.6".to_string()));
    }

    #[test]
    fn test_map_model_opus_4_7() {
        let result = map_model("claude-opus-4-7-thinking");
        assert_eq!(result, Some("claude-opus-4.7".to_string()));

        let dotted = map_model("claude-opus-4.7");
        assert_eq!(dotted, Some("claude-opus-4.7".to_string()));
    }

    #[test]
    fn test_map_model_opus_4_8() {
        let result = map_model("claude-opus-4-8-thinking");
        assert_eq!(result, Some("claude-opus-4.8".to_string()));

        let dotted = map_model("claude-opus-4.8");
        assert_eq!(dotted, Some("claude-opus-4.8".to_string()));
    }

    #[test]
    fn test_map_model_other_opus_defaults_to_4_6() {
        let result = map_model("claude-opus-4-20250514");
        assert_eq!(result, Some("claude-opus-4.6".to_string()));
    }

    #[test]
    fn test_context_window_opus_4_7() {
        assert_eq!(get_context_window_size("claude-opus-4-7"), 1_000_000);
    }

    #[test]
    fn test_context_window_opus_4_8() {
        assert_eq!(get_context_window_size("claude-opus-4-8"), 1_000_000);
    }

    #[test]
    fn test_map_model_thinking_suffix_haiku() {
        // thinking 后缀不应影响 haiku 模型映射
        let result = map_model("claude-haiku-4-5-20251001-thinking");
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

        let result = convert_request(&req).expect("request should convert");
        let system_history = match &result.conversation_state.history[0] {
            Message::User(msg) => &msg.user_input_message.content,
            _ => panic!("expected system prompt to be converted as user history"),
        };

        assert!(!system_history.contains("x-anthropic-billing-header"));
        assert!(!system_history.contains("cch=aaaa"));
        assert!(system_history.contains("stable system prompt"));
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

        let result = convert_request(&req).unwrap();

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

        let result = convert_request(&req).expect("opus 4.8 request should convert");
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

        let result = convert_request(&req).unwrap();
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

        let result = convert_request(&req).unwrap();

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

        let result = convert_request(&req).expect("multi-turn agent loop should convert");
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

        let result = convert_request(&req).expect("multi-turn tool request should convert");

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

        let result = convert_request(&req).unwrap();
        assert_eq!(
            result.conversation_state.conversation_id,
            "a0662283-7fd3-4399-a7eb-52b9a717ae88"
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

        let result = convert_request(&req).unwrap();
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

        let result = convert_request(&req);
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

        let result = convert_request(&req).expect("should convert");
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

        let result = convert_request(&req).expect("should convert");
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

    // ═══════════════════════════════════════════════════════════════════════
    // P0-1 裁剪函数单元测试
    // ═══════════════════════════════════════════════════════════════════════

    /// 辅助函数：构造一个 N 轮对话的 ConversationState（无 system 对，无 tool）
    fn make_conversation_state(rounds: usize, content_per_msg: &str) -> ConversationState {
        let model_id = "claude-sonnet-4.5";
        let mut history = Vec::new();
        for i in 0..rounds {
            let user = Message::User(HistoryUserMessage::new(
                format!("{content_per_msg} user {i}"),
                model_id,
            ));
            let assistant = Message::Assistant(HistoryAssistantMessage::new(format!(
                "{content_per_msg} assistant {i}"
            )));
            history.push(user);
            history.push(assistant);
        }
        ConversationState::new("test-conv").with_history(history)
    }

    /// 计算一个真实可达成的 limit，使裁剪恰好需移除从 pinned_front 起的前 `pairs` 对才达标。
    /// 返回 `(limit, bytes_before)`：`limit = bytes_before - (前 pairs 对的 est 之和)`，
    /// 故 `excess` 等于这些对的 est 之和，移除它们后 `cut_bytes >= excess`（reached）→ 返回 Some。
    /// 取代旧测试里的 `limit=1` 暴力值——后者在新语义下属"窗口不足"会 fail-open(None)。
    fn limit_for_trimming_pairs(
        state: &ConversationState,
        has_system_pair: bool,
        pairs: usize,
    ) -> (usize, usize) {
        let bytes_before = serde_json::to_string(state).unwrap().len();
        let pinned_front = if has_system_pair { 2 } else { 0 };
        let mut est_sum = 0usize;
        for k in 0..pairs {
            let u = pinned_front + k * 2;
            est_sum += serde_json::to_string(&state.history[u]).unwrap().len()
                + serde_json::to_string(&state.history[u + 1]).unwrap().len();
        }
        (bytes_before - est_sum, bytes_before)
    }

    /// T01：未超限时 trim_history_to_byte_limit 返回 None，history 不变
    #[test]
    fn test_trim_no_change_when_under_limit() {
        let mut state = make_conversation_state(2, "hello");
        let serialized = serde_json::to_string(&state).unwrap();
        let bytes = serialized.len();
        // 设置 limit > bytes，不应裁剪
        let result = trim_history_to_byte_limit(&mut state, false, bytes + 1000, bytes);
        assert!(result.is_none(), "未超限时不应裁剪");
        assert_eq!(state.history.len(), 4, "history 不应改变");
    }

    /// T02：超限时裁剪最旧优先（裁掉第一对）
    #[test]
    fn test_trim_removes_oldest_pair_first() {
        let mut state = make_conversation_state(4, "some content here");
        let orig_len = state.history.len(); // 8
        // 记录最旧那对的 user 内容，裁剪后应不再是 history[0]
        let oldest_user = if let Message::User(u) = &state.history[0] {
            u.user_input_message.content.clone()
        } else {
            panic!("history[0] 应为 User")
        };

        // 真实 limit：移除最旧 1 对即达标
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 1);
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);
        assert!(result.is_some(), "超限且可裁时应裁剪");
        let stats = result.unwrap();
        assert_eq!(stats.pairs_removed, 1, "移除最旧 1 对即达标");
        assert!(state.history.len() < orig_len, "history 应变短");
        if let Message::User(u) = &state.history[0] {
            assert_ne!(
                u.user_input_message.content, oldest_user,
                "最旧那对应被优先裁掉"
            );
        }
    }

    /// T03：裁剪后 history 严格保持 User/Assistant 交替
    #[test]
    fn test_trim_preserves_alternating_roles() {
        let mut state = make_conversation_state(6, "content");
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 2);
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);
        assert!(result.is_some(), "应发生裁剪");

        // 验证剩余 history 严格交替
        for (i, msg) in state.history.iter().enumerate() {
            if i % 2 == 0 {
                assert!(
                    matches!(msg, Message::User(_)),
                    "偶数位置应为 User，实际不是 i={}",
                    i
                );
            } else {
                assert!(
                    matches!(msg, Message::Assistant(_)),
                    "奇数位置应为 Assistant，实际不是 i={}",
                    i
                );
            }
        }
    }

    /// T04：has_system_pair=true 时，history 首 2 条（system 对）永不被裁
    #[test]
    fn test_trim_preserves_system_pair() {
        use crate::kiro::model::requests::conversation::HistoryAssistantMessage;

        let model_id = "claude-sonnet-4.5";

        // 构造：system 对 + 3 轮普通对话（共 8 条）
        let sys_user = Message::User(HistoryUserMessage::new(
            "You are a helpful assistant.",
            model_id,
        ));
        let sys_assistant = Message::Assistant(HistoryAssistantMessage::new(
            "I will follow these instructions.",
        ));

        let mut history = vec![sys_user, sys_assistant];
        for i in 0..3 {
            history.push(Message::User(HistoryUserMessage::new(
                format!("user message {i}"),
                model_id,
            )));
            history.push(Message::Assistant(HistoryAssistantMessage::new(format!(
                "assistant reply {i}"
            ))));
        }

        let system_content_snapshot = if let Message::User(u) = &history[0] {
            u.user_input_message.content.clone()
        } else {
            panic!("history[0] 应为 User")
        };

        let mut state = ConversationState::new("test-conv").with_history(history);
        // 真实 limit：has_system_pair=true，移除 system 对之后最旧 1 对即达标
        let (limit, bytes) = limit_for_trimming_pairs(&state, true, 1);

        // 触发裁剪；has_system_pair=true 保护首 2 条
        let result = trim_history_to_byte_limit(&mut state, true, limit, bytes);
        assert!(result.is_some(), "应裁剪 1 对");

        // system 对应保留
        if let Message::User(u) = &state.history[0] {
            assert_eq!(
                u.user_input_message.content, system_content_snapshot,
                "system 对首条不应被裁"
            );
        } else {
            panic!("裁剪后 history[0] 应仍为 User（system）");
        }
        assert!(state.history.len() >= 2, "system 对的 2 条必须保留");
    }

    /// T05：活跃 tool turn（尾部保留区）不被裁
    #[test]
    fn test_trim_preserves_active_tool_turn() {
        use crate::kiro::model::requests::conversation::AssistantMessage;
        use crate::kiro::model::requests::conversation::HistoryAssistantMessage;
        use crate::kiro::model::requests::tool::ToolUseEntry;

        let model_id = "claude-sonnet-4.5";

        // 构造：3 轮历史 + 活跃 tool turn（最后 1 对）
        let mut history = Vec::new();
        for i in 0..3 {
            history.push(Message::User(HistoryUserMessage::new(
                format!("old user {i}"),
                model_id,
            )));
            history.push(Message::Assistant(HistoryAssistantMessage::new(format!(
                "old assistant {i}"
            ))));
        }

        // 活跃 tool turn：assistant 带 tool_use
        let user_before_tool = Message::User(HistoryUserMessage::new("invoke tool", model_id));
        let mut active_assistant = AssistantMessage::new("");
        active_assistant = active_assistant.with_tool_uses(vec![
            ToolUseEntry::new("tu_active", "Bash").with_input(serde_json::json!({"cmd": "ls"})),
        ]);
        history.push(user_before_tool);
        history.push(Message::Assistant(HistoryAssistantMessage {
            assistant_response_message: active_assistant,
        }));

        let mut state = ConversationState::new("test-conv").with_history(history);
        let orig_len = state.history.len(); // 8
        // 真实 limit：裁掉可裁窗口的 2 对（活跃 tool turn 在尾部保留区，不受影响）
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 2);

        // 触发裁剪
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);
        assert!(result.is_some(), "应发生裁剪");

        // 活跃 tool turn（最后 2 条）必须保留
        let new_len = state.history.len();
        assert!(new_len <= orig_len, "history 应变短或相同");

        // 最后一条必须是带 tool_uses 的 assistant（活跃 tool turn）
        let last = state.history.last().unwrap();
        if let Message::Assistant(a) = last {
            assert!(
                a.assistant_response_message.tool_uses.is_some(),
                "活跃 tool turn（最后 assistant）不应被裁"
            );
        } else {
            panic!("裁剪后最后一条应仍为 assistant");
        }
    }

    /// T05b（#26）：删 sanitize_history_tools 后历史保留结构化 tool 数据，trim 裁剪
    /// 边界不得切在「回合中段」（tool_result 轮）——否则被裁 tool_use 的 tool_result 孤立
    /// → Kiro 400。drain_end 应吸附到回合边界，裁掉完整回合，无跨界孤立配对。
    #[test]
    fn test_trim_does_not_orphan_tool_result_at_turn_boundary() {
        use crate::kiro::model::requests::conversation::{
            AssistantMessage, HistoryAssistantMessage, UserMessage,
        };
        use crate::kiro::model::requests::tool::{ToolResult, ToolUseEntry};

        let model_id = "claude-sonnet-4.5";
        let tool_use_turn = |id: &str| {
            Message::Assistant(HistoryAssistantMessage {
                assistant_response_message: AssistantMessage::new("").with_tool_uses(vec![
                    ToolUseEntry::new(id, "Bash").with_input(serde_json::json!({"cmd": "ls -la"})),
                ]),
            })
        };
        let tool_result_turn = |id: &str| {
            let mut m = UserMessage::new("", model_id);
            m.user_input_message_context.tool_results = vec![ToolResult::success(
                id,
                "tool output here, padded for byte size",
            )];
            Message::User(HistoryUserMessage {
                user_input_message: m,
            })
        };

        // 2 个完整 tool 回合，每回合 = User问题 + Assistant(tool_use) + User(tool_result) + Assistant(答案)
        let history = vec![
            Message::User(HistoryUserMessage::new(
                "question one, padded for byte size",
                model_id,
            )),
            tool_use_turn("tu_1"),
            tool_result_turn("tu_1"),
            Message::Assistant(HistoryAssistantMessage::new(
                "answer one, padded for byte size",
            )),
            Message::User(HistoryUserMessage::new(
                "question two, padded for byte size",
                model_id,
            )),
            tool_use_turn("tu_2"),
            tool_result_turn("tu_2"),
            Message::Assistant(HistoryAssistantMessage::new(
                "answer two, padded for byte size",
            )),
        ];

        let mut state = ConversationState::new("test-conv").with_history(history);
        // limit 使「机械裁 1 对」即达标——drain_end=2 会切在 history[2]（tool_result tu_1 轮）中段
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 1);
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);

        // 修复后：吸附到回合边界（history[4]）裁掉整个回合 1，应发生裁剪
        assert!(result.is_some(), "应吸附到回合边界并裁剪");

        // 核心断言：裁后 history 无孤立 tool_result（每个 tool_result 的 tool_use_id
        // 都能在剩余 history 的某个 tool_use 找到）。修复前裁 1 对会留孤立 tu_1 → 此断言失败。
        let all_tool_use_ids: std::collections::HashSet<String> = state
            .history
            .iter()
            .filter_map(|m| match m {
                Message::Assistant(a) => a.assistant_response_message.tool_uses.as_ref(),
                _ => None,
            })
            .flatten()
            .map(|tu| tu.tool_use_id.clone())
            .collect();

        for msg in &state.history {
            if let Message::User(u) = msg {
                for tr in &u.user_input_message.user_input_message_context.tool_results {
                    assert!(
                        all_tool_use_ids.contains(&tr.tool_use_id),
                        "裁后出现孤立 tool_result（对应 tool_use 被裁），tool_use_id={} —— #26 trim 配对 regression",
                        tr.tool_use_id
                    );
                }
            }
        }
    }

    /// T06：current_message 独立于 history，裁剪前后不变
    #[test]
    fn test_trim_does_not_touch_current_message() {
        use crate::kiro::model::requests::conversation::{CurrentMessage, UserInputMessage};

        let mut state = make_conversation_state(4, "content");

        // 设置 current_message 内容
        let user_input = UserInputMessage::new("this is the current message", "claude-sonnet-4.5");
        state.current_message = CurrentMessage::new(user_input);

        // 真实 limit：移除最旧 1 对即达标（current_message 独立于 history，不受影响）
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 1);
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);
        assert!(result.is_some(), "应发生裁剪");

        assert_eq!(
            state.current_message.user_input_message.content, "this is the current message",
            "current_message 不应被裁剪"
        );
    }

    /// T07：无可裁对（全被 pinned）时原样透传，不报错，返回 None
    #[test]
    fn test_trim_no_panic_when_nothing_cuttable() {
        use crate::kiro::model::requests::conversation::HistoryAssistantMessage;

        let model_id = "claude-sonnet-4.5";

        // 只有 system 对（2 条）+ KEEP_RECENT_PAIRS*2 条（4 条）= 6 条，全被 pinned
        let sys_user = Message::User(HistoryUserMessage::new("system", model_id));
        let sys_assistant = Message::Assistant(HistoryAssistantMessage::new(
            "I will follow these instructions.",
        ));

        let mut history = vec![sys_user, sys_assistant];
        for i in 0..2 {
            history.push(Message::User(HistoryUserMessage::new(
                format!("recent user {i}"),
                model_id,
            )));
            history.push(Message::Assistant(HistoryAssistantMessage::new(format!(
                "recent assistant {i}"
            ))));
        }

        let orig_len = history.len();
        let mut state = ConversationState::new("test-conv").with_history(history);
        let serialized = serde_json::to_string(&state).unwrap();
        let bytes = serialized.len();

        // 即使超限，也无可裁对
        let result = trim_history_to_byte_limit(&mut state, true, 1, bytes);
        assert!(result.is_none(), "无可裁对时应返回 None（不报错）");
        assert_eq!(state.history.len(), orig_len, "history 不应改变");
    }

    /// T08a：恰好等于 limit，不裁剪
    #[test]
    fn test_trim_exact_limit_no_trim() {
        let mut state = make_conversation_state(2, "msg");
        let serialized = serde_json::to_string(&state).unwrap();
        let bytes = serialized.len();

        let result = trim_history_to_byte_limit(&mut state, false, bytes, bytes);
        assert!(result.is_none(), "恰好等于 limit 时不应裁剪");
    }

    /// T08b：limit+1 触发裁剪（bytes_before = limit+1 > limit）
    #[test]
    fn test_trim_limit_plus_one_triggers_trim() {
        let mut state = make_conversation_state(4, "some long content here");
        let bytes = serde_json::to_string(&state).unwrap().len();

        // limit = bytes-1 → excess=1，最旧 1 对的 est 远大于 1，移除 1 对即达标
        let result = trim_history_to_byte_limit(&mut state, false, bytes - 1, bytes);
        assert!(result.is_some(), "超限 1 字节且可裁时应裁剪");
        assert_eq!(
            result.unwrap().pairs_removed,
            1,
            "excess=1 时移除最旧 1 对即达标"
        );
    }

    /// T09：has_system_pair=false 路径正常工作（无 system 对时 pinned_front=0）
    #[test]
    fn test_trim_no_system_pair_path() {
        let mut state = make_conversation_state(4, "content");
        // has_system_pair=false，pinned_front=0；真实 limit 移除最旧 1 对
        let (limit, bytes) = limit_for_trimming_pairs(&state, false, 1);
        let result = trim_history_to_byte_limit(&mut state, false, limit, bytes);
        assert!(result.is_some(), "has_system_pair=false 且可裁时应正常裁剪");
        assert!(
            state.history.len().is_multiple_of(2),
            "裁剪后 history 长度应为偶数"
        );
    }

    /// T10：fail-open 路径——奇数长度 history 不 panic，返回 None
    #[test]
    fn test_trim_odd_history_fails_open() {
        use crate::kiro::model::requests::conversation::HistoryAssistantMessage;

        // 构造奇数长度 history（结构异常）
        let model_id = "claude-sonnet-4.5";
        let history = vec![
            Message::User(HistoryUserMessage::new("user1", model_id)),
            Message::Assistant(HistoryAssistantMessage::new("assistant1")),
            Message::User(HistoryUserMessage::new("user2", model_id)), // 奇数
        ];

        let mut state = ConversationState::new("test-conv").with_history(history);
        let serialized = serde_json::to_string(&state).unwrap();
        let bytes = serialized.len();

        // 不应 panic，应 fail-open 返回 None
        let result = trim_history_to_byte_limit(&mut state, false, 1, bytes);
        assert!(result.is_none(), "奇数长度 history 应 fail-open 返回 None");
        assert_eq!(state.history.len(), 3, "fail-open 时 history 不应改变");
    }

    /// 评论2：裁剪窗口内 role 不成对 → 真正 fail-open（返回 None，不修改 history）
    #[test]
    fn test_trim_mid_window_role_mismatch_fails_open() {
        use crate::kiro::model::requests::conversation::HistoryAssistantMessage;
        let model_id = "claude-sonnet-4.5";
        // 偶数长度、首条 User、通过早期检查；但可裁窗口内第 2 对 role 不成对（U,U）
        let history = vec![
            Message::User(HistoryUserMessage::new("u0", model_id)),
            Message::Assistant(HistoryAssistantMessage::new("a0")),
            Message::User(HistoryUserMessage::new("u1", model_id)),
            Message::User(HistoryUserMessage::new("u1-broken", model_id)), // 异常：应为 Assistant
            Message::Assistant(HistoryAssistantMessage::new("a2")),
            Message::Assistant(HistoryAssistantMessage::new("a2b")),
            Message::User(HistoryUserMessage::new("u3", model_id)),
            Message::Assistant(HistoryAssistantMessage::new("a3")),
        ];
        let orig_len = history.len();
        let mut state = ConversationState::new("test-conv").with_history(history);
        let bytes = serde_json::to_string(&state).unwrap().len();

        // limit=1 → excess 极大，迫使循环走到第 2 对（索引 2,3）触发 role 异常
        let result = trim_history_to_byte_limit(&mut state, false, 1, bytes);
        assert!(result.is_none(), "窗口内 role 不成对应 fail-open 返回 None");
        assert_eq!(
            state.history.len(),
            orig_len,
            "fail-open 时 history 不应被修改"
        );
    }

    /// 评论3：删光整个可裁窗口仍不足覆盖 excess → 真正 fail-open（None，保留历史）
    #[test]
    fn test_trim_insufficient_window_fails_open() {
        let mut state = make_conversation_state(4, "x"); // 小内容，4 对，可裁窗口 2 对
        let orig_len = state.history.len();
        let bytes = serde_json::to_string(&state).unwrap().len();

        // limit=1 → excess 远超整个可裁窗口能释放的字节，无法一轮达标
        let result = trim_history_to_byte_limit(&mut state, false, 1, bytes);
        assert!(
            result.is_none(),
            "可裁窗口不足以达标时应 fail-open 返回 None"
        );
        assert_eq!(
            state.history.len(),
            orig_len,
            "fail-open 时 history 不应被修改"
        );
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

        let result = convert_request(&req).expect("should convert");

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
}
