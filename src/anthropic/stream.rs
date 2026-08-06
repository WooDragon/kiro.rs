//! 流式响应处理模块
//!
//! 实现 Kiro → Anthropic 流式响应转换和 SSE 状态管理

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::kiro::model::events::Event;
use crate::model::config::PromptCacheMode;

use super::prompt_cache::{
    PromptCacheProfile, PromptCacheTracker, PromptCacheUsage, build_usage_value,
    decide_prompt_cache, extract_usage_snapshot_from_metering,
};
use super::tool_call_leak::{TOOL_CALL_LEAK_TAIL_CHARS, detect_text_tool_call_leak};

/// 找到小于等于目标位置的最近有效UTF-8字符边界
///
/// UTF-8字符可能占用1-4个字节，直接按字节位置切片可能会切在多字节字符中间导致panic。
/// 这个函数从目标位置向前搜索，找到最近的有效字符边界。
pub(crate) fn find_char_boundary(s: &str, target: usize) -> usize {
    if target >= s.len() {
        return s.len();
    }
    if target == 0 {
        return 0;
    }
    // 从目标位置向前搜索有效的字符边界
    let mut pos = target;
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

/// 需要跳过的包裹字符
///
/// 当 thinking 标签被这些字符包裹时，认为是在引用标签而非真正的标签：
/// - 反引号 (`)：行内代码
/// - 双引号 (")：字符串
/// - 单引号 (')：字符串
const QUOTE_CHARS: &[u8] = b"`\"'\\#!@$%^&*()-_=+[]{};:<>,.?/";

/// 检查指定位置的字符是否是引用字符
fn is_quote_char(buffer: &str, pos: usize) -> bool {
    buffer
        .as_bytes()
        .get(pos)
        .map(|c| QUOTE_CHARS.contains(c))
        .unwrap_or(false)
}

/// 查找真正的 thinking 结束标签（不被引用字符包裹，且后面有双换行符）
///
/// 当模型在思考过程中提到 `</thinking>` 时，通常会用反引号、引号等包裹，
/// 或者在同一行有其他内容（如"关于 </thinking> 标签"）。
/// 这个函数会跳过这些情况，只返回真正的结束标签位置。
///
/// 跳过的情况：
/// - 被引用字符包裹（反引号、引号等）
/// - 后面没有双换行符（真正的结束标签后面会有 `\n\n`）
/// - 标签在缓冲区末尾（流式处理时需要等待更多内容）
///
/// # 参数
/// - `buffer`: 要搜索的字符串
///
/// # 返回值
/// - `Some(pos)`: 真正的结束标签的起始位置
/// - `None`: 没有找到真正的结束标签
fn find_real_thinking_end_tag(buffer: &str) -> Option<usize> {
    const TAG: &str = "</thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        // 如果被引用字符包裹，跳过
        if has_quote_before || has_quote_after {
            search_start = absolute_pos + 1;
            continue;
        }

        // 检查后面的内容
        let after_content = &buffer[after_pos..];

        // 如果标签后面内容不足以判断是否有双换行符，等待更多内容
        if after_content.len() < 2 {
            return None;
        }

        // 真正的 thinking 结束标签后面会有双换行符 `\n\n`
        if after_content.starts_with("\n\n") {
            return Some(absolute_pos);
        }

        // 不是双换行符，跳过继续搜索
        search_start = absolute_pos + 1;
    }

    None
}

/// 查找缓冲区末尾的 thinking 结束标签（允许末尾只有空白字符）
///
/// 用于“边界事件”场景：例如 thinking 结束后立刻进入 tool_use，或流结束，
/// 此时 `</thinking>` 后面可能没有 `\n\n`，但结束标签依然应被识别并过滤。
///
/// 约束：只有当 `</thinking>` 之后全部都是空白字符时才认为是结束标签，
/// 以避免在 thinking 内容中提到 `</thinking>`（非结束标签）时误判。
fn find_real_thinking_end_tag_at_buffer_end(buffer: &str) -> Option<usize> {
    const TAG: &str = "</thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        if has_quote_before || has_quote_after {
            search_start = absolute_pos + 1;
            continue;
        }

        // 只有当标签后面全部是空白字符时才认定为结束标签
        if buffer[after_pos..].trim().is_empty() {
            return Some(absolute_pos);
        }

        search_start = absolute_pos + 1;
    }

    None
}

/// 查找真正的 thinking 开始标签（不被引用字符包裹）
///
/// 与 `find_real_thinking_end_tag` 类似，跳过被引用字符包裹的开始标签。
fn find_real_thinking_start_tag(buffer: &str) -> Option<usize> {
    const TAG: &str = "<thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        // 如果不被引用字符包裹，则是真正的开始标签
        if !has_quote_before && !has_quote_after {
            return Some(absolute_pos);
        }

        // 继续搜索下一个匹配
        search_start = absolute_pos + 1;
    }

    None
}

/// 从完整文本中提取 thinking 块（用于非流式响应）
///
/// 使用与流式处理相同的标签检测逻辑（引用字符过滤），确保一致性。
/// 非流式场景下文本已完整，无需处理跨 chunk 分割问题。
///
/// # 返回值
/// - `(Some(thinking_content), remaining_text)` — 检测到有效 thinking 块
/// - `(None, original_text)` — 未检测到，原样返回
pub(crate) fn extract_thinking_from_complete_text(text: &str) -> (Option<String>, String) {
    let start_pos = match find_real_thinking_start_tag(text) {
        Some(pos) => pos,
        None => return (None, text.to_string()),
    };

    let before = &text[..start_pos];
    let after_open = &text[start_pos + "<thinking>".len()..];

    // 查找结束标签：优先匹配带 \n\n 后缀的，退而使用末尾匹配
    let (thinking_raw, text_after) = if let Some(end_pos) = find_real_thinking_end_tag(after_open) {
        (
            &after_open[..end_pos],
            &after_open[end_pos + "</thinking>\n\n".len()..],
        )
    } else if let Some(end_pos) = find_real_thinking_end_tag_at_buffer_end(after_open) {
        let after_tag = end_pos + "</thinking>".len();
        (&after_open[..end_pos], after_open[after_tag..].trim_start())
    } else {
        // 找不到有效的结束标签，不做提取
        return (None, text.to_string());
    };

    // 剥离开头的换行符（与流式处理一致：模型输出 <thinking>\n）
    let thinking_content = thinking_raw.strip_prefix('\n').unwrap_or(thinking_raw);

    // 组装剩余文本：跳过纯空白的 before 部分
    let mut remaining = String::new();
    if !before.trim().is_empty() {
        remaining.push_str(before);
    }
    remaining.push_str(text_after);

    if thinking_content.is_empty() {
        (None, remaining)
    } else {
        (Some(thinking_content.to_string()), remaining)
    }
}

/// SSE 事件
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: String,
    pub data: serde_json::Value,
}

impl SseEvent {
    pub fn new(event: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            event: event.into(),
            data,
        }
    }

    /// 格式化为 SSE 字符串
    pub fn to_sse_string(&self) -> String {
        format!(
            "event: {}\ndata: {}\n\n",
            self.event,
            serde_json::to_string(&self.data).unwrap_or_default()
        )
    }
}

/// 流式失败成因（#83）。
///
/// 用枚举替掉原先的 `transient: bool`——`bool` 只能表达「可重试/不可重试」两态，
/// 承载不了「零内容+瞬态错误」这类还需要区分「是否已跑够久到能归因为上游首字
/// 截止线」的第三态。继续在 bool 上叠参数是往烂设计上叠补丁，枚举让四种成因
/// 各自独立成变体，`error_sse_event` 的映射逻辑随之变成穷举匹配而非条件分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailure {
    /// 零内容 + 瞬态传输错误 + 已运行够久（`elapsed >= FIRST_TOKEN_DEADLINE_HINT_SECS`）。
    /// 归因为上游首字截止线超时，`elapsed_secs` 是运行时实测值（非硬编码 240）。
    FirstTokenTimeout { elapsed_secs: u64 },
    /// 已有内容中断，或零内容但发生在早期（未达闸门）——不做首字超时归因，
    /// 沿用原「连接中断」文案，逐字保留现状。
    ConnectionInterrupted,
    /// 上游 200 干净结束但零产出（无 Err，`body_stream.next()` 直接返回 `None`）。
    /// 与 `ConnectionInterrupted` 区分开是因为这里压根没有断连，用「连接中断」
    /// 文案会误导排查方向；与非流式路径（`handlers.rs` 空响应分支）对齐措辞。
    EmptyResponse,
    /// 非瞬态失败，不可重试。
    Fatal,
}

/// 首字超时归因的最小 elapsed 闸门（秒）。
///
/// 只影响对外 message 措辞与日志分类，**绝不影响** `error_type` / `req_outcome` /
/// 请求生命周期——三者均由 `transient` 一票决定，闸门只在 `transient==true` 内部
/// 再切分「归因为首字超时」还是「归因为连接中断」。
///
/// 阈值取 200s：#83 生产样本 29 例 min=240s、无一例低于此值，240s 是观测到的死线
/// 地板；`elapsed` 从 `create_sse_stream` 入口（即上游响应头已收到）起算，比请求
/// 总时长略短，200 的余量足以吸收这段差值，同时把 2 秒级早期网络抖动排除在
/// 「首字超时」归因之外（避免把抖动误报成 ~240s 的确定性上限）。
pub const FIRST_TOKEN_DEADLINE_HINT_SECS: u64 = 200;

/// 把「瞬态与否 + 本轮是否零产出 + 已运行时长」三个既有信号分类为流失败成因（#83）。
///
/// 纯函数：无副作用、无 I/O，三条流式路径共用同一份判定逻辑，可表驱动单测覆盖
/// 全部输入组合，避免三处调用点各自实现一份判定逻辑漂移出不一致的行为。
///
/// - `transient`：来自 `http_client::is_transient`，决定可重试与否，一票通盘。
/// - `empty`：来自 `ctx.is_empty_response()`，本轮是否零产出。
/// - `elapsed`：从流构造入口（上游响应头已收到）到本次失败判定的耗时。
pub fn classify_stream_failure(
    transient: bool,
    empty: bool,
    elapsed: std::time::Duration,
) -> StreamFailure {
    if !transient {
        return StreamFailure::Fatal;
    }
    let elapsed_secs = elapsed.as_secs();
    if empty && elapsed_secs >= FIRST_TOKEN_DEADLINE_HINT_SECS {
        StreamFailure::FirstTokenTimeout { elapsed_secs }
    } else {
        StreamFailure::ConnectionInterrupted
    }
}

/// 构造 Anthropic SSE `error` 事件帧（#64，#83 扩展为四态成因）。
///
/// **全仓唯一 error 帧构造点**——三条流式路径的异常分支与「本轮零产出」分支统一经此
/// 构造，禁止在各路径就地拼 error JSON。
///
/// 四个成因变体到 `(error_type, message)` 的映射：
/// - `FirstTokenTimeout{elapsed_secs}` → `overloaded_error` + 携实测 `elapsed_secs`
///   的专属文案，把「上游首字截止线超时」讲清楚，不再被误报成「连接中断」而
///   误导排查方向（#83 的核心诉求）。
/// - `ConnectionInterrupted` → `overloaded_error` + 原文案逐字保留（#64 现状）。
/// - `EmptyResponse` → `overloaded_error` + 与非流式路径（`handlers.rs` 空响应
///   分支）对齐的文案——上游 200 干净结束但零产出压根没有断连，不该用「连接
///   中断」表述。
/// - `Fatal` → `api_error`，不可重试文案，原文案逐字保留（#64 现状）。
///
/// 语义要点：异常分支发此帧后即置 `finished=true`，绝不再走正常收尾
/// （`message_delta`/`message_stop`），使失败对客户端可感知、不被伪装成正常完成。
///
/// C5（半开状态）：此 error 帧可能在 `message_start`（乃至已打开的 content_block）之后发出而不
/// 补 `content_block_stop`/`message_stop`。这依赖 **Anthropic SSE 契约：`error` 事件作为流终止
/// 信号，客户端（Claude Code）识别后即中止本轮**，故半开的 content_block 不会导致客户端挂起——
/// 属可接受状态，无需强行补齐收尾帧。
pub fn error_sse_event(failure: StreamFailure) -> SseEvent {
    let (error_type, message) = match failure {
        StreamFailure::FirstTokenTimeout { elapsed_secs } => (
            "overloaded_error",
            format!(
                "Upstream produced no content in {elapsed_secs}s before resetting the stream \
                 (upstream first-token deadline). Retrying an identical long-reasoning request \
                 may hit the same limit; consider lowering reasoning effort for this request."
            ),
        ),
        StreamFailure::ConnectionInterrupted => (
            "overloaded_error",
            "Upstream connection interrupted. Please retry.".to_string(),
        ),
        StreamFailure::EmptyResponse => (
            "overloaded_error",
            "Upstream returned an empty response. Please retry.".to_string(),
        ),
        StreamFailure::Fatal => ("api_error", "Upstream response failed.".to_string()),
    };
    SseEvent::new(
        "error",
        json!({
            "type": "error",
            "error": {
                "type": error_type,
                "message": message,
            }
        }),
    )
}

/// 内容块状态
#[derive(Debug, Clone)]
struct BlockState {
    block_type: String,
    started: bool,
    stopped: bool,
}

impl BlockState {
    fn new(block_type: impl Into<String>) -> Self {
        Self {
            block_type: block_type.into(),
            started: false,
            stopped: false,
        }
    }
}

/// SSE 状态管理器
///
/// 确保 SSE 事件序列符合 Claude API 规范：
/// 1. message_start 只能出现一次
/// 2. content_block 必须先 start 再 delta 再 stop
/// 3. message_delta 只能出现一次，且在所有 content_block_stop 之后
/// 4. message_stop 在最后
#[derive(Debug)]
pub struct SseStateManager {
    /// message_start 是否已发送
    message_started: bool,
    /// message_delta 是否已发送
    message_delta_sent: bool,
    /// 活跃的内容块状态
    active_blocks: HashMap<i32, BlockState>,
    /// 消息是否已结束
    message_ended: bool,
    /// 下一个块索引
    next_block_index: i32,
    /// 当前 stop_reason
    stop_reason: Option<String>,
    /// 是否有工具调用
    has_tool_use: bool,
}

impl Default for SseStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SseStateManager {
    pub fn new() -> Self {
        Self {
            message_started: false,
            message_delta_sent: false,
            active_blocks: HashMap::new(),
            message_ended: false,
            next_block_index: 0,
            stop_reason: None,
            has_tool_use: false,
        }
    }

    /// 判断指定块是否处于可接收 delta 的打开状态
    fn is_block_open_of_type(&self, index: i32, expected_type: &str) -> bool {
        self.active_blocks
            .get(&index)
            .is_some_and(|b| b.started && !b.stopped && b.block_type == expected_type)
    }

    /// 获取下一个块索引
    pub fn next_block_index(&mut self) -> i32 {
        let index = self.next_block_index;
        self.next_block_index += 1;
        index
    }

    /// 记录工具调用
    pub fn set_has_tool_use(&mut self, has: bool) {
        self.has_tool_use = has;
    }

    /// 本轮是否产生过结构化 tool_use（用于 #43 文本化工具调用泄漏检测的误报收敛）
    pub fn has_tool_use(&self) -> bool {
        self.has_tool_use
    }

    /// 设置 stop_reason
    pub fn set_stop_reason(&mut self, reason: impl Into<String>) {
        self.stop_reason = Some(reason.into());
    }

    /// 检查是否存在非 thinking 类型的内容块（如 text 或 tool_use）
    fn has_non_thinking_blocks(&self) -> bool {
        self.active_blocks
            .values()
            .any(|b| b.block_type != "thinking")
    }

    /// 获取最终的 stop_reason
    pub fn get_stop_reason(&self) -> String {
        if let Some(ref reason) = self.stop_reason {
            reason.clone()
        } else if self.has_tool_use {
            "tool_use".to_string()
        } else {
            "end_turn".to_string()
        }
    }

    /// 是否已被显式设置为终止性 stop_reason（#64）。
    ///
    /// `stop_reason` 字段默认 `None`（见 `SseStateManager::new`），仅在收到明确终止信号时
    /// 经 `set_stop_reason` 置为 `Some(...)`：
    /// - `max_tokens`（ContentLengthExceededException / thinking-only 耗尽预算）
    /// - `model_context_window_exceeded`（contextUsage >= 100%）
    ///
    /// 这些是上游给出的**显式终止原因**——客户端据此终止本轮（如 max_tokens 触发续写），
    /// 而非把它当作失败重试。因此「零产出 + 已有显式终止 stop_reason」不能判为空响应
    /// （否则会误发 error 帧诱导无谓重试，形成死循环）。
    ///
    /// `Some("end_turn")` 理论上不会出现（`set_stop_reason` 从不传 end_turn），仍显式排除，
    /// 确保「默认收尾」不被误判为显式终止。
    pub fn has_explicit_stop_reason(&self) -> bool {
        self.stop_reason.as_deref().is_some_and(|r| r != "end_turn")
    }

    /// 处理 message_start 事件
    pub fn handle_message_start(&mut self, event: serde_json::Value) -> Option<SseEvent> {
        if self.message_started {
            tracing::trace!("跳过重复的 message_start 事件");
            return None;
        }
        self.message_started = true;
        Some(SseEvent::new("message_start", event))
    }

    /// 处理 content_block_start 事件
    pub fn handle_content_block_start(
        &mut self,
        index: i32,
        block_type: &str,
        data: serde_json::Value,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 如果是 tool_use 块，先关闭之前的文本块
        if block_type == "tool_use" {
            self.has_tool_use = true;
            for (block_index, block) in self.active_blocks.iter_mut() {
                if block.block_type == "text" && block.started && !block.stopped {
                    // 自动发送 content_block_stop 关闭文本块
                    events.push(SseEvent::new(
                        "content_block_stop",
                        json!({
                            "type": "content_block_stop",
                            "index": block_index
                        }),
                    ));
                    block.stopped = true;
                }
            }
        }

        // 检查块是否已存在
        if let Some(block) = self.active_blocks.get_mut(&index) {
            if block.started {
                tracing::trace!(
                    block_index = index,
                    "块已启动，跳过重复的 content_block_start"
                );
                return events;
            }
            block.started = true;
        } else {
            let mut block = BlockState::new(block_type);
            block.started = true;
            self.active_blocks.insert(index, block);
        }

        events.push(SseEvent::new("content_block_start", data));
        events
    }

    /// 处理 content_block_delta 事件
    pub fn handle_content_block_delta(
        &mut self,
        index: i32,
        data: serde_json::Value,
    ) -> Option<SseEvent> {
        // 确保块已启动
        if let Some(block) = self.active_blocks.get(&index) {
            if !block.started || block.stopped {
                tracing::warn!(
                    block_index = index,
                    started = block.started,
                    stopped = block.stopped,
                    "块状态异常"
                );
                return None;
            }
        } else {
            // 块不存在，可能需要先创建
            tracing::warn!(block_index = index, "收到未知块的 delta 事件");
            return None;
        }

        Some(SseEvent::new("content_block_delta", data))
    }

    /// 处理 content_block_stop 事件
    pub fn handle_content_block_stop(&mut self, index: i32) -> Option<SseEvent> {
        if let Some(block) = self.active_blocks.get_mut(&index) {
            if block.stopped {
                tracing::trace!(
                    block_index = index,
                    "块已停止，跳过重复的 content_block_stop"
                );
                return None;
            }
            block.stopped = true;
            return Some(SseEvent::new(
                "content_block_stop",
                json!({
                    "type": "content_block_stop",
                    "index": index
                }),
            ));
        }
        None
    }

    /// 生成最终事件序列
    pub fn generate_final_events(
        &mut self,
        input_tokens: i32,
        output_tokens: i32,
        prompt_cache_usage: PromptCacheUsage,
        include_prompt_cache_fields: bool,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 关闭所有未关闭的块
        for (index, block) in self.active_blocks.iter_mut() {
            if block.started && !block.stopped {
                events.push(SseEvent::new(
                    "content_block_stop",
                    json!({
                        "type": "content_block_stop",
                        "index": index
                    }),
                ));
                block.stopped = true;
            }
        }

        // 发送 message_delta
        if !self.message_delta_sent {
            self.message_delta_sent = true;
            events.push(SseEvent::new(
                "message_delta",
                json!({
                    "type": "message_delta",
                    "delta": {
                        "stop_reason": self.get_stop_reason(),
                        "stop_sequence": null
                    },
                    "usage": build_usage_value(
                        input_tokens,
                        output_tokens,
                        prompt_cache_usage,
                        include_prompt_cache_fields,
                    )
                }),
            ));
        }

        // 发送 message_stop
        if !self.message_ended {
            self.message_ended = true;
            events.push(SseEvent::new(
                "message_stop",
                json!({ "type": "message_stop" }),
            ));
        }

        events
    }
}

/// 流处理上下文
pub struct StreamContext {
    /// SSE 状态管理器
    pub state_manager: SseStateManager,
    /// 请求的模型名称
    pub model: String,
    /// 上下文窗口大小（预解析）
    pub context_window: i32,
    /// 消息 ID
    pub message_id: String,
    /// 输入 tokens（估算值）
    pub input_tokens: i32,
    /// 从 contextUsageEvent 计算的实际输入 tokens
    pub context_input_tokens: Option<i32>,
    /// 输出 tokens 累计
    pub output_tokens: i32,
    pub prompt_cache_mode: PromptCacheMode,
    pub prompt_cache: Option<Arc<PromptCacheTracker>>,
    pub prompt_cache_account: Option<String>,
    pub prompt_cache_profile: Option<PromptCacheProfile>,
    pub min_cacheable_tokens: i32,
    pub prompt_cache_usage: PromptCacheUsage,
    pub include_prompt_cache_fields: bool,
    pub upstream_prompt_cache_usage: Option<PromptCacheUsage>,
    pub upstream_input_tokens: Option<i32>,
    pub upstream_output_tokens: Option<i32>,
    pub prompt_cache_updated: bool,
    /// 工具块索引映射 (tool_id -> block_index)
    pub tool_block_indices: HashMap<String, i32>,
    /// 工具名称反向映射（短名称 → 原始名称），用于响应时还原
    pub tool_name_map: HashMap<String, String>,
    /// thinking 是否启用
    pub thinking_enabled: bool,
    /// thinking 内容缓冲区
    pub thinking_buffer: String,
    /// 是否在 thinking 块内
    pub in_thinking_block: bool,
    /// thinking 块是否已提取完成
    pub thinking_extracted: bool,
    /// thinking 块索引
    pub thinking_block_index: Option<i32>,
    /// 文本块索引（thinking 启用时动态分配）
    pub text_block_index: Option<i32>,
    /// 是否需要剥离 thinking 内容开头的换行符
    /// 模型输出 `<thinking>\n` 时，`\n` 可能与标签在同一 chunk 或下一 chunk
    strip_thinking_leading_newline: bool,
    /// #43 文本化工具调用泄漏检测：O(1) 滑动窗口，仅保留最近 TOOL_CALL_LEAK_TAIL_CHARS 个字符，
    /// 用于覆盖标记跨 chunk 截断的情况。不做全量缓冲（本服务是流式代理，禁止驻留整段响应）。
    tool_call_leak_tail: String,
    /// 命中的工具调用明文标记字面（命中后置位，后续 chunk 短路跳过检测）。
    tool_call_leak_marker: Option<&'static str>,
}

impl StreamContext {
    /// 创建启用thinking的StreamContext
    pub fn new_with_thinking(
        model: impl Into<String>,
        context_window: i32,
        input_tokens: i32,
        thinking_enabled: bool,
        tool_name_map: HashMap<String, String>,
        min_cacheable_tokens: i32,
    ) -> Self {
        Self {
            state_manager: SseStateManager::new(),
            model: model.into(),
            context_window,
            message_id: format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
            input_tokens,
            context_input_tokens: None,
            output_tokens: 0,
            prompt_cache_mode: PromptCacheMode::Off,
            prompt_cache: None,
            prompt_cache_account: None,
            prompt_cache_profile: None,
            min_cacheable_tokens,
            prompt_cache_usage: PromptCacheUsage::default(),
            include_prompt_cache_fields: false,
            upstream_prompt_cache_usage: None,
            upstream_input_tokens: None,
            upstream_output_tokens: None,
            prompt_cache_updated: false,
            tool_block_indices: HashMap::new(),
            tool_name_map,
            thinking_enabled,
            thinking_buffer: String::new(),
            in_thinking_block: false,
            thinking_extracted: false,
            thinking_block_index: None,
            text_block_index: None,
            strip_thinking_leading_newline: false,
            tool_call_leak_tail: String::new(),
            tool_call_leak_marker: None,
        }
    }

    pub fn with_prompt_cache(
        mut self,
        mode: PromptCacheMode,
        tracker: Option<Arc<PromptCacheTracker>>,
        account: Option<String>,
        profile: Option<PromptCacheProfile>,
        fallback_usage: PromptCacheUsage,
    ) -> Self {
        self.prompt_cache_mode = mode;
        self.prompt_cache = tracker;
        self.prompt_cache_account = account;
        self.include_prompt_cache_fields = profile.is_some()
            && !matches!(mode, PromptCacheMode::Off | PromptCacheMode::Passthrough);
        self.prompt_cache_profile = profile;
        self.prompt_cache_usage = fallback_usage;
        self
    }

    /// 生成 message_start 事件
    pub fn create_message_start_event(&self) -> serde_json::Value {
        json!({
            "type": "message_start",
            "message": {
                "id": self.message_id,
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": self.model,
                "stop_reason": null,
                "stop_sequence": null,
                "usage": build_usage_value(
                    self.input_tokens,
                    1,
                    self.prompt_cache_usage,
                    self.include_prompt_cache_fields,
                )
            }
        })
    }

    /// 生成初始事件序列 (message_start + 文本块 start)
    ///
    /// 当 thinking 启用时，不在初始化时创建文本块，而是等到实际收到内容时再创建。
    /// 这样可以确保 thinking 块（索引 0）在文本块（索引 1）之前。
    pub fn generate_initial_events(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // message_start
        let msg_start = self.create_message_start_event();
        if let Some(event) = self.state_manager.handle_message_start(msg_start) {
            events.push(event);
        }

        // 如果启用了 thinking，不在这里创建文本块
        // thinking 块和文本块会在 process_content_with_thinking 中按正确顺序创建
        if self.thinking_enabled {
            return events;
        }

        // 创建初始文本块（仅在未启用 thinking 时）
        let text_block_index = self.state_manager.next_block_index();
        self.text_block_index = Some(text_block_index);
        let text_block_events = self.state_manager.handle_content_block_start(
            text_block_index,
            "text",
            json!({
                "type": "content_block_start",
                "index": text_block_index,
                "content_block": {
                    "type": "text",
                    "text": ""
                }
            }),
        );
        events.extend(text_block_events);

        events
    }

    /// 处理 Kiro 事件并转换为 Anthropic SSE 事件
    pub fn process_kiro_event(&mut self, event: &Event) -> Vec<SseEvent> {
        match event {
            Event::AssistantResponse(resp) => self.process_assistant_response(&resp.content),
            Event::ToolUse(tool_use) => self.process_tool_use(tool_use),
            Event::ContextUsage(context_usage) => {
                // 从上下文使用百分比计算实际的 input_tokens
                let window_size = self.context_window;
                let actual_input_tokens =
                    (context_usage.context_usage_percentage * (window_size as f64) / 100.0) as i32;
                self.context_input_tokens = Some(actual_input_tokens);
                // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                if context_usage.context_usage_percentage >= 100.0 {
                    self.state_manager
                        .set_stop_reason("model_context_window_exceeded");
                }
                tracing::debug!(
                    context_usage_pct = context_usage.context_usage_percentage,
                    input_tokens = actual_input_tokens,
                    "收到 contextUsageEvent，已计算 input_tokens"
                );
                Vec::new()
            }
            Event::Metering(payload) => {
                if let Some(snapshot) = extract_usage_snapshot_from_metering(payload) {
                    if let Some(input_tokens) = snapshot.input_tokens {
                        self.upstream_input_tokens = Some(input_tokens.max(1));
                    } else if let Some(total_tokens) = snapshot.total_tokens
                        && let Some(output_tokens) = snapshot.output_tokens
                    {
                        self.upstream_input_tokens = Some((total_tokens - output_tokens).max(1));
                    }
                    if let Some(output_tokens) = snapshot.output_tokens {
                        self.upstream_output_tokens = Some(output_tokens.max(0));
                    }
                    if let Some(usage) = snapshot.prompt_cache_usage {
                        self.upstream_prompt_cache_usage = Some(usage);
                    }
                    let decision = decide_prompt_cache(
                        self.prompt_cache_mode,
                        self.upstream_prompt_cache_usage,
                        self.prompt_cache_usage,
                        self.prompt_cache_profile.is_some(),
                    );
                    self.prompt_cache_usage = decision.fallback_usage;
                    self.include_prompt_cache_fields = decision.include_cache_fields;
                }
                Vec::new()
            }
            Event::Error {
                error_code,
                error_message,
            } => {
                tracing::error!(
                    event_type = %error_code,
                    error = %error_message,
                    "收到错误事件"
                );
                Vec::new()
            }
            Event::Exception {
                exception_type,
                message,
            } => {
                // 处理 ContentLengthExceededException
                if exception_type == "ContentLengthExceededException" {
                    self.state_manager.set_stop_reason("max_tokens");
                }
                tracing::warn!(
                    event_type = %exception_type,
                    error = %message,
                    "收到异常事件"
                );
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// 处理助手响应事件
    fn process_assistant_response(&mut self, content: &str) -> Vec<SseEvent> {
        if content.is_empty() {
            return Vec::new();
        }

        // #43 文本化工具调用泄漏检测（O(1) 滑动窗口，纯可观测，不改透传）
        self.scan_tool_call_leak(content);

        // 估算 tokens
        self.output_tokens += estimate_tokens(content);

        // 如果启用了thinking，需要处理thinking块
        if self.thinking_enabled {
            return self.process_content_with_thinking(content);
        }

        // 非 thinking 模式同样复用统一的 text_delta 发送逻辑，
        // 以便在 tool_use 自动关闭文本块后能够自愈重建新的文本块，避免“吞字”。
        self.create_text_delta_events(content)
    }

    /// #43 滑动窗口扫描工具调用明文泄漏。命中后短路（marker 已置位则不再做任何拼接/检测/截断，
    /// 避免在流剩余几千 token 上做无用功）。窗口仅保留最近 TOOL_CALL_LEAK_TAIL_CHARS 个字符，
    /// 按 UTF-8 字符边界安全截断，内存 O(1)。
    fn scan_tool_call_leak(&mut self, content: &str) {
        if self.tool_call_leak_marker.is_some() {
            return;
        }
        self.tool_call_leak_tail.push_str(content);
        if let Some(m) = detect_text_tool_call_leak(&self.tool_call_leak_tail) {
            self.tool_call_leak_marker = Some(m);
            self.tool_call_leak_tail.clear();
            return;
        }
        // 仅保留最后 TOOL_CALL_LEAK_TAIL_CHARS 个字符，覆盖跨 chunk 截断的标记
        let char_count = self.tool_call_leak_tail.chars().count();
        if char_count > TOOL_CALL_LEAK_TAIL_CHARS {
            let skip = char_count - TOOL_CALL_LEAK_TAIL_CHARS;
            let byte_start = self
                .tool_call_leak_tail
                .char_indices()
                .nth(skip)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.tool_call_leak_tail.drain(..byte_start);
        }
    }

    /// 处理包含thinking块的内容
    fn process_content_with_thinking(&mut self, content: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 将内容添加到缓冲区进行处理
        self.thinking_buffer.push_str(content);

        loop {
            if !self.in_thinking_block && !self.thinking_extracted {
                // 查找 <thinking> 开始标签（跳过被反引号包裹的）
                if let Some(start_pos) = find_real_thinking_start_tag(&self.thinking_buffer) {
                    // 发送 <thinking> 之前的内容作为 text_delta
                    // 注意：如果前面只是空白字符（如 adaptive 模式返回的 \n\n），则跳过，
                    // 避免在 thinking 块之前产生无意义的 text 块导致客户端解析失败
                    let before_thinking = self.thinking_buffer[..start_pos].to_string();
                    if !before_thinking.is_empty() && !before_thinking.trim().is_empty() {
                        events.extend(self.create_text_delta_events(&before_thinking));
                    }

                    // 进入 thinking 块
                    self.in_thinking_block = true;
                    self.strip_thinking_leading_newline = true;
                    self.thinking_buffer =
                        self.thinking_buffer[start_pos + "<thinking>".len()..].to_string();

                    // 创建 thinking 块的 content_block_start 事件
                    let thinking_index = self.state_manager.next_block_index();
                    self.thinking_block_index = Some(thinking_index);
                    let start_events = self.state_manager.handle_content_block_start(
                        thinking_index,
                        "thinking",
                        json!({
                            "type": "content_block_start",
                            "index": thinking_index,
                            "content_block": {
                                "type": "thinking",
                                "thinking": ""
                            }
                        }),
                    );
                    events.extend(start_events);
                } else {
                    // 没有找到 <thinking>，检查是否可能是部分标签
                    // 保留可能是部分标签的内容
                    let target_len = self
                        .thinking_buffer
                        .len()
                        .saturating_sub("<thinking>".len());
                    let safe_len = find_char_boundary(&self.thinking_buffer, target_len);
                    if safe_len > 0 {
                        let safe_content = self.thinking_buffer[..safe_len].to_string();
                        // 如果 thinking 尚未提取，且安全内容只是空白字符，
                        // 则不发送为 text_delta，继续保留在缓冲区等待更多内容。
                        // 这避免了 4.6 模型中 <thinking> 标签跨事件分割时，
                        // 前导空白（如 "\n\n"）被错误地创建为 text 块，
                        // 导致 text 块先于 thinking 块出现的问题。
                        if !safe_content.is_empty() && !safe_content.trim().is_empty() {
                            events.extend(self.create_text_delta_events(&safe_content));
                            self.thinking_buffer = self.thinking_buffer[safe_len..].to_string();
                        }
                    }
                    break;
                }
            } else if self.in_thinking_block {
                // 剥离 <thinking> 标签后紧跟的换行符（可能跨 chunk）
                if self.strip_thinking_leading_newline {
                    if self.thinking_buffer.starts_with('\n') {
                        self.thinking_buffer = self.thinking_buffer[1..].to_string();
                        self.strip_thinking_leading_newline = false;
                    } else if !self.thinking_buffer.is_empty() {
                        // buffer 非空但不以 \n 开头，不再需要剥离
                        self.strip_thinking_leading_newline = false;
                    }
                    // buffer 为空时保留标志，等待下一个 chunk
                }

                // 在 thinking 块内，查找 </thinking> 结束标签（跳过被反引号包裹的）
                if let Some(end_pos) = find_real_thinking_end_tag(&self.thinking_buffer) {
                    // 提取 thinking 内容
                    let thinking_content = self.thinking_buffer[..end_pos].to_string();
                    if !thinking_content.is_empty()
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        events.push(
                            self.create_thinking_delta_event(thinking_index, &thinking_content),
                        );
                    }

                    // 结束 thinking 块
                    self.in_thinking_block = false;
                    self.thinking_extracted = true;

                    // 发送空的 thinking_delta 事件，然后发送 content_block_stop 事件
                    if let Some(thinking_index) = self.thinking_block_index {
                        // 先发送空的 thinking_delta
                        events.push(self.create_thinking_delta_event(thinking_index, ""));
                        // 再发送 content_block_stop
                        if let Some(stop_event) =
                            self.state_manager.handle_content_block_stop(thinking_index)
                        {
                            events.push(stop_event);
                        }
                    }

                    // 剥离 `</thinking>\n\n`（find_real_thinking_end_tag 已确认 \n\n 存在）
                    self.thinking_buffer =
                        self.thinking_buffer[end_pos + "</thinking>\n\n".len()..].to_string();
                } else {
                    // 没有找到结束标签，发送当前缓冲区内容作为 thinking_delta。
                    // 保留末尾可能是部分 `</thinking>\n\n` 的内容：
                    // find_real_thinking_end_tag 要求标签后有 `\n\n` 才返回 Some，
                    // 因此保留区必须覆盖 `</thinking>\n\n` 的完整长度（13 字节），
                    // 否则当 `</thinking>` 已在 buffer 但 `\n\n` 尚未到达时，
                    // 标签的前几个字符会被错误地作为 thinking_delta 发出。
                    let target_len = self
                        .thinking_buffer
                        .len()
                        .saturating_sub("</thinking>\n\n".len());
                    let safe_len = find_char_boundary(&self.thinking_buffer, target_len);
                    if safe_len > 0 {
                        let safe_content = self.thinking_buffer[..safe_len].to_string();
                        if !safe_content.is_empty()
                            && let Some(thinking_index) = self.thinking_block_index
                        {
                            events.push(
                                self.create_thinking_delta_event(thinking_index, &safe_content),
                            );
                        }
                        self.thinking_buffer = self.thinking_buffer[safe_len..].to_string();
                    }
                    break;
                }
            } else {
                // thinking 已提取完成，剩余内容作为 text_delta
                if !self.thinking_buffer.is_empty() {
                    let remaining = self.thinking_buffer.clone();
                    self.thinking_buffer.clear();
                    events.extend(self.create_text_delta_events(&remaining));
                }
                break;
            }
        }

        events
    }

    /// 创建 text_delta 事件
    ///
    /// 如果文本块尚未创建，会先创建文本块。
    /// 当发生 tool_use 时，状态机会自动关闭当前文本块；后续文本会自动创建新的文本块继续输出。
    ///
    /// 返回值包含可能的 content_block_start 事件和 content_block_delta 事件。
    fn create_text_delta_events(&mut self, text: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 如果当前 text_block_index 指向的块已经被关闭（例如 tool_use 开始时自动 stop），
        // 则丢弃该索引并创建新的文本块继续输出，避免 delta 被状态机拒绝导致“吞字”。
        if let Some(idx) = self.text_block_index
            && !self.state_manager.is_block_open_of_type(idx, "text")
        {
            self.text_block_index = None;
        }

        // 获取或创建文本块索引
        let text_index = if let Some(idx) = self.text_block_index {
            idx
        } else {
            // 文本块尚未创建，需要先创建
            let idx = self.state_manager.next_block_index();
            self.text_block_index = Some(idx);

            // 发送 content_block_start 事件
            let start_events = self.state_manager.handle_content_block_start(
                idx,
                "text",
                json!({
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {
                        "type": "text",
                        "text": ""
                    }
                }),
            );
            events.extend(start_events);
            idx
        };

        // 发送 content_block_delta 事件
        if let Some(delta_event) = self.state_manager.handle_content_block_delta(
            text_index,
            json!({
                "type": "content_block_delta",
                "index": text_index,
                "delta": {
                    "type": "text_delta",
                    "text": text
                }
            }),
        ) {
            events.push(delta_event);
        }

        events
    }

    /// 创建 thinking_delta 事件
    fn create_thinking_delta_event(&self, index: i32, thinking: &str) -> SseEvent {
        SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "thinking_delta",
                    "thinking": thinking
                }
            }),
        )
    }

    /// 处理工具使用事件
    fn process_tool_use(
        &mut self,
        tool_use: &crate::kiro::model::events::ToolUseEvent,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        self.state_manager.set_has_tool_use(true);

        // tool_use 必须发生在 thinking 结束之后。
        // 但当 `</thinking>` 后面没有 `\n\n`（例如紧跟 tool_use 或流结束）时，
        // thinking 结束标签会滞留在 thinking_buffer，导致后续 flush 时把 `</thinking>` 当作内容输出。
        // 这里在开始 tool_use block 前做一次“边界场景”的结束标签识别与过滤。
        if self.thinking_enabled
            && self.in_thinking_block
            && let Some(end_pos) = find_real_thinking_end_tag_at_buffer_end(&self.thinking_buffer)
        {
            let thinking_content = self.thinking_buffer[..end_pos].to_string();
            if !thinking_content.is_empty()
                && let Some(thinking_index) = self.thinking_block_index
            {
                events.push(self.create_thinking_delta_event(thinking_index, &thinking_content));
            }

            // 结束 thinking 块
            self.in_thinking_block = false;
            self.thinking_extracted = true;

            if let Some(thinking_index) = self.thinking_block_index {
                // 先发送空的 thinking_delta
                events.push(self.create_thinking_delta_event(thinking_index, ""));
                // 再发送 content_block_stop
                if let Some(stop_event) =
                    self.state_manager.handle_content_block_stop(thinking_index)
                {
                    events.push(stop_event);
                }
            }

            // 把结束标签后的内容当作普通文本（通常为空或空白）
            let after_pos = end_pos + "</thinking>".len();
            let remaining = self.thinking_buffer[after_pos..].trim_start().to_string();
            self.thinking_buffer.clear();
            if !remaining.is_empty() {
                events.extend(self.create_text_delta_events(&remaining));
            }
        }

        // thinking 模式下，process_content_with_thinking 可能会为了探测 `<thinking>` 而暂存一小段尾部文本。
        // 如果此时直接开始 tool_use，状态机会自动关闭 text block，导致这段"待输出文本"看起来被 tool_use 吞掉。
        // 约束：只在尚未进入 thinking block、且 thinking 尚未被提取时，将缓冲区当作普通文本 flush。
        if self.thinking_enabled
            && !self.in_thinking_block
            && !self.thinking_extracted
            && !self.thinking_buffer.is_empty()
        {
            let buffered = std::mem::take(&mut self.thinking_buffer);
            events.extend(self.create_text_delta_events(&buffered));
        }

        // 获取或分配块索引
        let block_index = if let Some(&idx) = self.tool_block_indices.get(&tool_use.tool_use_id) {
            idx
        } else {
            let idx = self.state_manager.next_block_index();
            self.tool_block_indices
                .insert(tool_use.tool_use_id.clone(), idx);
            idx
        };

        // 还原工具名称（如果有映射）
        let original_name = self
            .tool_name_map
            .get(&tool_use.name)
            .cloned()
            .unwrap_or_else(|| tool_use.name.clone());

        // 发送 content_block_start
        let start_events = self.state_manager.handle_content_block_start(
            block_index,
            "tool_use",
            json!({
                "type": "content_block_start",
                "index": block_index,
                "content_block": {
                    "type": "tool_use",
                    "id": tool_use.tool_use_id,
                    "name": original_name,
                    "input": {}
                }
            }),
        );
        events.extend(start_events);

        // 发送参数增量 (ToolUseEvent.input 是 String 类型)
        if !tool_use.input.is_empty() {
            self.output_tokens += (tool_use.input.len() as i32 + 3) / 4; // 估算 token

            if let Some(delta_event) = self.state_manager.handle_content_block_delta(
                block_index,
                json!({
                    "type": "content_block_delta",
                    "index": block_index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": tool_use.input
                    }
                }),
            ) {
                events.push(delta_event);
            }
        }

        // 如果是完整的工具调用（stop=true），发送 content_block_stop
        if tool_use.stop
            && let Some(stop_event) = self.state_manager.handle_content_block_stop(block_index)
        {
            events.push(stop_event);
        }

        events
    }

    /// 生成最终事件序列
    pub fn generate_final_events(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // Flush thinking_buffer 中的剩余内容
        if self.thinking_enabled && !self.thinking_buffer.is_empty() {
            if self.in_thinking_block {
                // 末尾可能残留 `</thinking>`（例如紧跟 tool_use 或流结束），需要在 flush 时过滤掉结束标签。
                if let Some(end_pos) =
                    find_real_thinking_end_tag_at_buffer_end(&self.thinking_buffer)
                {
                    let thinking_content = self.thinking_buffer[..end_pos].to_string();
                    if !thinking_content.is_empty()
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        events.push(
                            self.create_thinking_delta_event(thinking_index, &thinking_content),
                        );
                    }

                    // 关闭 thinking 块：先发送空的 thinking_delta，再发送 content_block_stop
                    if let Some(thinking_index) = self.thinking_block_index {
                        events.push(self.create_thinking_delta_event(thinking_index, ""));
                        if let Some(stop_event) =
                            self.state_manager.handle_content_block_stop(thinking_index)
                        {
                            events.push(stop_event);
                        }
                    }

                    // 把结束标签后的内容当作普通文本（通常为空或空白）
                    let after_pos = end_pos + "</thinking>".len();
                    let remaining = self.thinking_buffer[after_pos..].trim_start().to_string();
                    self.thinking_buffer.clear();
                    self.in_thinking_block = false;
                    self.thinking_extracted = true;
                    if !remaining.is_empty() {
                        events.extend(self.create_text_delta_events(&remaining));
                    }
                } else {
                    // 如果还在 thinking 块内，发送剩余内容作为 thinking_delta
                    if let Some(thinking_index) = self.thinking_block_index {
                        events.push(
                            self.create_thinking_delta_event(thinking_index, &self.thinking_buffer),
                        );
                    }
                    // 关闭 thinking 块：先发送空的 thinking_delta，再发送 content_block_stop
                    if let Some(thinking_index) = self.thinking_block_index {
                        // 先发送空的 thinking_delta
                        events.push(self.create_thinking_delta_event(thinking_index, ""));
                        // 再发送 content_block_stop
                        if let Some(stop_event) =
                            self.state_manager.handle_content_block_stop(thinking_index)
                        {
                            events.push(stop_event);
                        }
                    }
                }
            } else {
                // 否则发送剩余内容作为 text_delta
                let buffer_content = self.thinking_buffer.clone();
                events.extend(self.create_text_delta_events(&buffer_content));
            }
            self.thinking_buffer.clear();
        }

        // 如果整个流中只产生了 thinking 块，没有 text 也没有 tool_use，
        // 则设置 stop_reason 为 max_tokens（表示模型耗尽了 token 预算在思考上），
        // 并补发一套完整的 text 事件（内容为一个空格），确保 content 数组中有 text 块
        if self.thinking_enabled
            && self.thinking_block_index.is_some()
            && !self.state_manager.has_non_thinking_blocks()
        {
            self.state_manager.set_stop_reason("max_tokens");
            events.extend(self.create_text_delta_events(" "));
        }

        let final_input_tokens = self.final_input_tokens();
        let final_output_tokens = self.final_output_tokens();

        // #43 上游 opus-4-8 偶发把工具调用 XML 当纯文本吐出：命中明文标记且本轮无结构化 tool_use
        // → stop_reason 修正为 max_tokens（CC 自动续机制兜底），仅在无其他显式 override 时介入。
        if let Some(marker) = self.tool_call_leak_marker
            && !self.state_manager.has_tool_use()
        {
            if self.state_manager.get_stop_reason() == "end_turn" {
                self.state_manager.set_stop_reason("max_tokens");
            }
            tracing::warn!(
                leak_marker = ?marker,
                model = %self.model,
                message_id = %self.message_id,
                output_tokens = final_output_tokens,
                stop_reason = %self.state_manager.get_stop_reason(),
                "检测到工具调用明文泄漏(#43)"
            );
        }

        self.update_prompt_cache();

        // 生成最终事件
        events.extend(self.state_manager.generate_final_events(
            final_input_tokens,
            final_output_tokens,
            self.prompt_cache_usage,
            self.include_prompt_cache_fields,
        ));
        events
    }

    pub fn final_input_tokens(&self) -> i32 {
        self.upstream_input_tokens
            .or(self.context_input_tokens)
            .unwrap_or(self.input_tokens)
            .max(1)
    }

    pub fn final_output_tokens(&self) -> i32 {
        self.upstream_output_tokens
            .unwrap_or(self.output_tokens)
            .max(0)
    }

    pub fn has_reliable_input_tokens(&self) -> bool {
        self.upstream_input_tokens.is_some() || self.context_input_tokens.is_some()
    }

    /// 本轮是否零产出**且无显式终止信号**（#64）。
    ///
    /// 语义 = 无任何 text/thinking 输出（`output_tokens==0`）、无结构化 tool_use，
    /// **且未收到显式终止 stop_reason**（max_tokens / model_context_window_exceeded）。
    ///
    /// `output_tokens` 在 `process_assistant_response` 出口对所有 assistantResponse
    /// 内容（含 thinking，见 stream.rs 递增点）累加，故 `==0` 精确表示上游未吐任何内容。
    ///
    /// 关键修正（#64 自身引入的死循环）：上游发 `Exception(ContentLengthExceededException)`
    /// 或 `contextUsage>=100%` 后**不吐 assistantResponse 就结束**，此时 `output_tokens==0`
    /// 但 stop_reason 已被显式置为 max_tokens / model_context_window_exceeded——这是**终止
    /// 信号而非空响应**。若仍判空并发 error 帧（overloaded_error），客户端会永久重试同一必然
    /// 触发上限的请求，形成死循环。故此处排除「已有显式终止 stop_reason」的情况，让其走正常
    /// 收尾透传该 stop_reason（客户端据此终止/续写，不重试）。
    pub fn is_empty_response(&self) -> bool {
        self.output_tokens == 0
            && !self.state_manager.has_tool_use()
            && !self.state_manager.has_explicit_stop_reason()
    }

    fn update_prompt_cache(&mut self) {
        if self.prompt_cache_updated {
            return;
        }
        self.prompt_cache_updated = true;
        if !matches!(
            self.prompt_cache_mode,
            PromptCacheMode::Auto | PromptCacheMode::Emulated
        ) {
            return;
        }
        let (Some(tracker), Some(account), Some(profile)) = (
            self.prompt_cache.as_ref(),
            self.prompt_cache_account.as_ref(),
            self.prompt_cache_profile.as_ref(),
        ) else {
            return;
        };
        tracker.update(account, Some(profile), self.min_cacheable_tokens);
    }
}

/// 缓冲流处理上下文 - 用于 /cc/v1/messages 流式请求
///
/// 与 `StreamContext` 不同，此上下文会缓冲所有事件直到流结束，
/// 然后用从 `contextUsageEvent` 计算的正确 `input_tokens` 更正 `message_start` 事件。
///
/// 工作流程：
/// 1. 使用 `StreamContext` 正常处理所有 Kiro 事件
/// 2. 把生成的 SSE 事件缓存起来（而不是立即发送）
/// 3. 流结束时，找到 `message_start` 事件并更新其 `input_tokens`
/// 4. 一次性返回所有事件
pub struct BufferedStreamContext {
    /// 内部流处理上下文（复用现有的事件处理逻辑）
    inner: StreamContext,
    /// 缓冲的所有事件（包括 message_start、content_block_start 等）
    event_buffer: Vec<SseEvent>,
    /// 是否已经生成了初始事件
    initial_events_generated: bool,
}

impl BufferedStreamContext {
    /// 创建缓冲流上下文
    pub fn new(
        model: impl Into<String>,
        context_window: i32,
        estimated_input_tokens: i32,
        thinking_enabled: bool,
        tool_name_map: HashMap<String, String>,
        min_cacheable_tokens: i32,
    ) -> Self {
        let inner = StreamContext::new_with_thinking(
            model,
            context_window,
            estimated_input_tokens,
            thinking_enabled,
            tool_name_map,
            min_cacheable_tokens,
        );
        Self {
            inner,
            event_buffer: Vec::new(),
            initial_events_generated: false,
        }
    }

    pub fn with_prompt_cache(
        mut self,
        mode: PromptCacheMode,
        tracker: Option<Arc<PromptCacheTracker>>,
        account: Option<String>,
        profile: Option<PromptCacheProfile>,
        fallback_usage: PromptCacheUsage,
    ) -> Self {
        self.inner = self
            .inner
            .with_prompt_cache(mode, tracker, account, profile, fallback_usage);
        self
    }

    /// 处理 Kiro 事件并缓冲结果
    ///
    /// 复用 StreamContext 的事件处理逻辑，但把结果缓存而不是立即发送。
    pub fn process_and_buffer(&mut self, event: &crate::kiro::model::events::Event) {
        // 首次处理事件时，先生成初始事件（message_start 等）
        if !self.initial_events_generated {
            let initial_events = self.inner.generate_initial_events();
            self.event_buffer.extend(initial_events);
            self.initial_events_generated = true;
        }

        // 处理事件并缓冲结果
        let events = self.inner.process_kiro_event(event);
        self.event_buffer.extend(events);
    }

    /// 本轮是否零产出（#64）。委托内部 `StreamContext`，语义与其一致
    /// （无 text/thinking 且无 tool_use）。
    pub fn is_empty_response(&self) -> bool {
        self.inner.is_empty_response()
    }

    /// 完成流处理并返回所有事件
    ///
    /// 此方法会：
    /// 1. 生成最终事件（message_delta, message_stop）
    /// 2. 用正确的 input_tokens 更正 message_start 事件
    /// 3. 返回所有缓冲的事件
    pub fn finish_and_get_all_events(&mut self) -> Vec<SseEvent> {
        // 如果从未处理过事件，也要生成初始事件
        if !self.initial_events_generated {
            let initial_events = self.inner.generate_initial_events();
            self.event_buffer.extend(initial_events);
            self.initial_events_generated = true;
        }

        // 生成最终事件
        let final_events = self.inner.generate_final_events();
        self.event_buffer.extend(final_events);

        // 获取正确的 input_tokens
        let final_input_tokens = self.inner.final_input_tokens();

        // 更正 message_start 事件中的 input_tokens
        for event in &mut self.event_buffer {
            if event.event == "message_start"
                && let Some(message) = event.data.get_mut("message")
                && let Some(usage) = message.get_mut("usage")
            {
                *usage = build_usage_value(
                    final_input_tokens,
                    1,
                    self.inner.prompt_cache_usage,
                    self.inner.include_prompt_cache_fields,
                );
            }
        }

        std::mem::take(&mut self.event_buffer)
    }
}

const PREFIX_BUFFER_MAX_EVENTS: usize = 128;

/// 前缀缓冲流处理上下文 - 用于 /cc/v1/messages 默认流式策略
///
/// 只在 `message_start` 前短暂缓冲；拿到可靠 input_tokens、超过缓冲上限或超时后，
/// 释放修正后的前缀事件，随后退化为普通实时流式输出。
pub struct PrefixBufferedStreamContext {
    inner: StreamContext,
    event_buffer: Vec<SseEvent>,
    initial_events_generated: bool,
    released: bool,
}

impl PrefixBufferedStreamContext {
    pub fn new(
        model: impl Into<String>,
        context_window: i32,
        estimated_input_tokens: i32,
        thinking_enabled: bool,
        tool_name_map: HashMap<String, String>,
        min_cacheable_tokens: i32,
    ) -> Self {
        Self {
            inner: StreamContext::new_with_thinking(
                model,
                context_window,
                estimated_input_tokens,
                thinking_enabled,
                tool_name_map,
                min_cacheable_tokens,
            ),
            event_buffer: Vec::new(),
            initial_events_generated: false,
            released: false,
        }
    }

    pub fn with_prompt_cache(
        mut self,
        mode: PromptCacheMode,
        tracker: Option<Arc<PromptCacheTracker>>,
        account: Option<String>,
        profile: Option<PromptCacheProfile>,
        fallback_usage: PromptCacheUsage,
    ) -> Self {
        self.inner = self
            .inner
            .with_prompt_cache(mode, tracker, account, profile, fallback_usage);
        self
    }

    pub fn is_released(&self) -> bool {
        self.released
    }

    /// 本轮是否零产出（#64）。委托内部 `StreamContext`，语义与其一致
    /// （无 text/thinking 且无 tool_use）。
    pub fn is_empty_response(&self) -> bool {
        self.inner.is_empty_response()
    }

    pub fn process_event(&mut self, event: &Event) -> Vec<SseEvent> {
        if !self.initial_events_generated {
            let initial_events = self.inner.generate_initial_events();
            if self.released {
                self.initial_events_generated = true;
                let mut events = initial_events;
                events.extend(self.inner.process_kiro_event(event));
                return events;
            }
            self.event_buffer.extend(initial_events);
            self.initial_events_generated = true;
        }

        let events = self.inner.process_kiro_event(event);
        if self.released {
            events
        } else {
            self.event_buffer.extend(events);
            if self.inner.has_reliable_input_tokens()
                || self.event_buffer.len() >= PREFIX_BUFFER_MAX_EVENTS
            {
                self.release()
            } else {
                Vec::new()
            }
        }
    }

    pub fn release_due_to_timeout(&mut self) -> Vec<SseEvent> {
        if self.released {
            Vec::new()
        } else {
            tracing::debug!("Claude Code prefix buffer timed out; releasing with best usage");
            self.release()
        }
    }

    pub fn finish(&mut self) -> Vec<SseEvent> {
        if self.released {
            self.inner.generate_final_events()
        } else {
            if !self.initial_events_generated {
                self.event_buffer
                    .extend(self.inner.generate_initial_events());
                self.initial_events_generated = true;
            }
            let final_events = self.inner.generate_final_events();
            self.event_buffer.extend(final_events);
            self.release()
        }
    }

    fn release(&mut self) -> Vec<SseEvent> {
        if !self.initial_events_generated {
            self.event_buffer
                .extend(self.inner.generate_initial_events());
            self.initial_events_generated = true;
        }
        self.released = true;
        let final_input_tokens = self.inner.final_input_tokens();
        for event in &mut self.event_buffer {
            if event.event == "message_start"
                && let Some(message) = event.data.get_mut("message")
                && let Some(usage) = message.get_mut("usage")
            {
                *usage = build_usage_value(
                    final_input_tokens,
                    1,
                    self.inner.prompt_cache_usage,
                    self.inner.include_prompt_cache_fields,
                );
            }
        }
        std::mem::take(&mut self.event_buffer)
    }
}

/// 简单的 token 估算
fn estimate_tokens(text: &str) -> i32 {
    let chars: Vec<char> = text.chars().collect();
    let mut chinese_count = 0;
    let mut other_count = 0;

    for c in &chars {
        if *c >= '\u{4E00}' && *c <= '\u{9FFF}' {
            chinese_count += 1;
        } else {
            other_count += 1;
        }
    }

    // 中文约 1.5 字符/token，英文约 4 字符/token
    let chinese_tokens = (chinese_count * 2 + 2) / 3;
    let other_tokens = (other_count + 3) / 4;

    (chinese_tokens + other_tokens).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_format() {
        let event = SseEvent::new("message_start", json!({"type": "message_start"}));
        let sse_str = event.to_sse_string();

        assert!(sse_str.starts_with("event: message_start\n"));
        assert!(sse_str.contains("data: "));
        assert!(sse_str.ends_with("\n\n"));
    }

    #[test]
    fn test_sse_state_manager_message_start() {
        let mut manager = SseStateManager::new();

        // 第一次应该成功
        let event = manager.handle_message_start(json!({"type": "message_start"}));
        assert!(event.is_some());

        // 第二次应该被跳过
        let event = manager.handle_message_start(json!({"type": "message_start"}));
        assert!(event.is_none());
    }

    #[test]
    fn test_sse_state_manager_block_lifecycle() {
        let mut manager = SseStateManager::new();

        // 创建块
        let events = manager.handle_content_block_start(0, "text", json!({}));
        assert_eq!(events.len(), 1);

        // delta
        let event = manager.handle_content_block_delta(0, json!({}));
        assert!(event.is_some());

        // stop
        let event = manager.handle_content_block_stop(0);
        assert!(event.is_some());

        // 重复 stop 应该被跳过
        let event = manager.handle_content_block_stop(0);
        assert!(event.is_none());
    }

    #[test]
    fn test_tool_name_reverse_mapping_in_stream() {
        use crate::kiro::model::events::ToolUseEvent;

        let mut map = HashMap::new();
        map.insert(
            "short_abc12345".to_string(),
            "mcp__very_long_original_tool_name".to_string(),
        );

        let mut ctx = StreamContext::new_with_thinking("test-model", 200000, 100, false, map, 1024);
        let _ = ctx.generate_initial_events();

        // 模拟 Kiro 返回短名称的 tool_use
        let tool_event = Event::ToolUse(ToolUseEvent {
            name: "short_abc12345".to_string(),
            tool_use_id: "toolu_01".to_string(),
            input: r#"{"key":"value"}"#.to_string(),
            stop: true,
        });

        let events = ctx.process_kiro_event(&tool_event);

        // content_block_start 中的 name 应该是原始长名称
        let start_event = events
            .iter()
            .find(|e| e.event == "content_block_start")
            .unwrap();
        assert_eq!(
            start_event.data["content_block"]["name"], "mcp__very_long_original_tool_name",
            "应还原为原始工具名称"
        );
    }

    #[test]
    fn stream_final_usage_prefers_upstream_metering_tokens() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let events = ctx.process_kiro_event(&Event::Metering(json!({
            "usage": {
                "inputTokens": 321,
                "outputTokens": 17
            }
        })));
        assert!(events.is_empty());

        let final_events = ctx.generate_final_events();
        let delta = final_events
            .iter()
            .find(|event| event.event == "message_delta")
            .unwrap();
        assert_eq!(delta.data["usage"]["input_tokens"], 321);
        assert_eq!(delta.data["usage"]["output_tokens"], 17);
    }

    #[test]
    fn stream_final_usage_derives_input_from_total_and_output_tokens() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let _ = ctx.process_kiro_event(&Event::Metering(json!({
            "usage": {
                "totalTokens": 100,
                "outputTokens": 7
            }
        })));

        let final_events = ctx.generate_final_events();
        let delta = final_events
            .iter()
            .find(|event| event.event == "message_delta")
            .unwrap();
        assert_eq!(delta.data["usage"]["input_tokens"], 93);
        assert_eq!(delta.data["usage"]["output_tokens"], 7);
    }

    #[test]
    fn prefix_buffer_releases_message_start_when_usage_arrives() {
        let mut ctx = PrefixBufferedStreamContext::new(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );

        let events = ctx.process_event(&Event::Metering(json!({
            "usage": {
                "inputTokens": 321,
                "outputTokens": 17
            }
        })));

        assert!(ctx.is_released());
        let message_start = events
            .iter()
            .find(|event| event.event == "message_start")
            .unwrap();
        assert_eq!(message_start.data["message"]["usage"]["input_tokens"], 321);
    }

    #[test]
    fn prefix_buffer_timeout_releases_with_estimated_usage() {
        let mut ctx = PrefixBufferedStreamContext::new(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );

        let buffered = ctx.process_event(&Event::AssistantResponse(
            serde_json::from_value(json!({"content": "hello"})).unwrap(),
        ));
        assert!(buffered.is_empty());
        assert!(!ctx.is_released());

        let events = ctx.release_due_to_timeout();
        assert!(ctx.is_released());
        let message_start = events
            .iter()
            .find(|event| event.event == "message_start")
            .unwrap();
        assert_eq!(message_start.data["message"]["usage"]["input_tokens"], 10);
        assert!(
            events
                .iter()
                .any(|event| event.event == "content_block_delta")
        );
    }

    #[test]
    fn prefix_buffer_timeout_before_first_upstream_event_emits_message_start() {
        let mut ctx = PrefixBufferedStreamContext::new(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );

        let events = ctx.release_due_to_timeout();

        assert!(ctx.is_released());
        assert_eq!(
            events.first().map(|event| event.event.as_str()),
            Some("message_start")
        );
        assert!(
            events
                .iter()
                .any(|event| event.event == "content_block_start")
        );

        let final_events = ctx.finish();
        assert!(
            final_events
                .iter()
                .any(|event| event.event == "message_delta")
        );
        assert!(
            !final_events
                .iter()
                .any(|event| event.event == "message_start")
        );
    }

    #[test]
    fn buffered_stream_rewrites_message_start_with_upstream_metering_tokens() {
        let mut ctx = BufferedStreamContext::new(
            "claude-sonnet-4-5-20250929",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );

        ctx.process_and_buffer(&Event::Metering(json!({
            "usage": {
                "inputTokens": 321,
                "outputTokens": 17
            }
        })));

        let events = ctx.finish_and_get_all_events();
        let message_start = events
            .iter()
            .find(|event| event.event == "message_start")
            .unwrap();
        let message_delta = events
            .iter()
            .find(|event| event.event == "message_delta")
            .unwrap();

        assert_eq!(message_start.data["message"]["usage"]["input_tokens"], 321);
        assert_eq!(message_delta.data["usage"]["input_tokens"], 321);
        assert_eq!(message_delta.data["usage"]["output_tokens"], 17);
    }

    #[test]
    fn test_text_delta_after_tool_use_restarts_text_block() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);

        let initial_events = ctx.generate_initial_events();
        assert!(
            initial_events
                .iter()
                .any(|e| e.event == "content_block_start"
                    && e.data["content_block"]["type"] == "text")
        );

        let initial_text_index = ctx
            .text_block_index
            .expect("initial text block index should exist");

        // tool_use 开始会自动关闭现有 text block
        let tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "test_tool".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });
        assert!(
            tool_events.iter().any(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(initial_text_index as i64)
            }),
            "tool_use should stop the previous text block"
        );

        // 之后再来文本增量，应自动创建新的 text block 而不是往已 stop 的块里写 delta
        let text_events = ctx.process_assistant_response("hello");
        let new_text_start_index = text_events.iter().find_map(|e| {
            if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                e.data["index"].as_i64()
            } else {
                None
            }
        });
        assert!(
            new_text_start_index.is_some(),
            "should start a new text block"
        );
        assert_ne!(
            new_text_start_index.unwrap(),
            initial_text_index as i64,
            "new text block index should differ from the stopped one"
        );
        assert!(
            text_events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == "hello"
            }),
            "should emit text_delta after restarting text block"
        );
    }

    #[test]
    fn test_tool_use_flushes_pending_thinking_buffer_text_before_tool_block() {
        // thinking 模式下，短文本可能被暂存在 thinking_buffer 以等待 `<thinking>` 的跨 chunk 匹配。
        // 当紧接着出现 tool_use 时，应先 flush 这段文本，再开始 tool_use block。
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        // 两段短文本（各 2 个中文字符），总长度仍可能不足以满足 safe_len>0 的输出条件，
        // 因而会留在 thinking_buffer 中等待后续 chunk。
        let ev1 = ctx.process_assistant_response("有修");
        assert!(
            ev1.iter().all(|e| e.event != "content_block_delta"),
            "short prefix should be buffered under thinking mode"
        );
        let ev2 = ctx.process_assistant_response("改：");
        assert!(
            ev2.iter().all(|e| e.event != "content_block_delta"),
            "short prefix should still be buffered under thinking mode"
        );

        let events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "Write".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });

        let text_start_index = events.iter().find_map(|e| {
            if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                e.data["index"].as_i64()
            } else {
                None
            }
        });
        let pos_text_delta = events.iter().position(|e| {
            e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta"
        });
        let pos_text_stop = text_start_index.and_then(|idx| {
            events.iter().position(|e| {
                e.event == "content_block_stop" && e.data["index"].as_i64() == Some(idx)
            })
        });
        let pos_tool_start = events.iter().position(|e| {
            e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
        });

        assert!(
            text_start_index.is_some(),
            "should start a text block to flush buffered text"
        );
        assert!(
            pos_text_delta.is_some(),
            "should flush buffered text as text_delta"
        );
        assert!(
            pos_text_stop.is_some(),
            "should stop text block before tool_use block starts"
        );
        assert!(pos_tool_start.is_some(), "should start tool_use block");

        let pos_text_delta = pos_text_delta.unwrap();
        let pos_text_stop = pos_text_stop.unwrap();
        let pos_tool_start = pos_tool_start.unwrap();

        assert!(
            pos_text_delta < pos_text_stop && pos_text_stop < pos_tool_start,
            "ordering should be: text_delta -> text_stop -> tool_use_start"
        );

        assert!(
            events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == "有修改："
            }),
            "flushed text should equal the buffered prefix"
        );
    }

    #[test]
    fn test_estimate_tokens() {
        assert!(estimate_tokens("Hello") > 0);
        assert!(estimate_tokens("你好") > 0);
        assert!(estimate_tokens("Hello 你好") > 0);
    }

    #[test]
    fn test_find_real_thinking_start_tag_basic() {
        // 基本情况：正常的开始标签
        assert_eq!(find_real_thinking_start_tag("<thinking>"), Some(0));
        assert_eq!(find_real_thinking_start_tag("prefix<thinking>"), Some(6));
    }

    #[test]
    fn test_find_real_thinking_start_tag_with_backticks() {
        // 被反引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("`<thinking>`"), None);
        assert_eq!(find_real_thinking_start_tag("use `<thinking>` tag"), None);

        // 先有被包裹的，后有真正的开始标签
        assert_eq!(
            find_real_thinking_start_tag("about `<thinking>` tag<thinking>content"),
            Some(22)
        );
    }

    #[test]
    fn test_find_real_thinking_start_tag_with_quotes() {
        // 被双引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("\"<thinking>\""), None);
        assert_eq!(find_real_thinking_start_tag("the \"<thinking>\" tag"), None);

        // 被单引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("'<thinking>'"), None);

        // 混合情况
        assert_eq!(
            find_real_thinking_start_tag("about \"<thinking>\" and '<thinking>' then<thinking>"),
            Some(40)
        );
    }

    #[test]
    fn test_find_real_thinking_end_tag_basic() {
        // 基本情况：正常的结束标签后面有双换行符
        assert_eq!(find_real_thinking_end_tag("</thinking>\n\n"), Some(0));
        assert_eq!(
            find_real_thinking_end_tag("content</thinking>\n\n"),
            Some(7)
        );
        assert_eq!(
            find_real_thinking_end_tag("some text</thinking>\n\nmore text"),
            Some(9)
        );

        // 没有双换行符的情况
        assert_eq!(find_real_thinking_end_tag("</thinking>"), None);
        assert_eq!(find_real_thinking_end_tag("</thinking>\n"), None);
        assert_eq!(find_real_thinking_end_tag("</thinking> more"), None);
    }

    #[test]
    fn test_find_real_thinking_end_tag_with_backticks() {
        // 被反引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("`</thinking>`\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("mention `</thinking>` in code\n\n"),
            None
        );

        // 只有前面有反引号
        assert_eq!(find_real_thinking_end_tag("`</thinking>\n\n"), None);

        // 只有后面有反引号
        assert_eq!(find_real_thinking_end_tag("</thinking>`\n\n"), None);
    }

    #[test]
    fn test_find_real_thinking_end_tag_with_quotes() {
        // 被双引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("\"</thinking>\"\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("the string \"</thinking>\" is a tag\n\n"),
            None
        );

        // 被单引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("'</thinking>'\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("use '</thinking>' as marker\n\n"),
            None
        );

        // 混合情况：双引号包裹后有真正的标签
        assert_eq!(
            find_real_thinking_end_tag("about \"</thinking>\" tag</thinking>\n\n"),
            Some(23)
        );

        // 混合情况：单引号包裹后有真正的标签
        assert_eq!(
            find_real_thinking_end_tag("about '</thinking>' tag</thinking>\n\n"),
            Some(23)
        );
    }

    #[test]
    fn test_find_real_thinking_end_tag_mixed() {
        // 先有被包裹的，后有真正的结束标签
        assert_eq!(
            find_real_thinking_end_tag("discussing `</thinking>` tag</thinking>\n\n"),
            Some(28)
        );

        // 多个被包裹的，最后一个是真正的
        assert_eq!(
            find_real_thinking_end_tag("`</thinking>` and `</thinking>` done</thinking>\n\n"),
            Some(36)
        );

        // 多种引用字符混合
        assert_eq!(
            find_real_thinking_end_tag(
                "`</thinking>` and \"</thinking>\" and '</thinking>' done</thinking>\n\n"
            ),
            Some(54)
        );
    }

    #[test]
    fn test_tool_use_immediately_after_thinking_filters_end_tag_and_closes_thinking_block() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();

        // thinking 内容以 `</thinking>` 结尾，但后面没有 `\n\n`（模拟紧跟 tool_use 的场景）
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>"));

        let tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "Write".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });
        all_events.extend(tool_events);

        all_events.extend(ctx.generate_final_events());

        // 不应把 `</thinking>` 当作 thinking 内容输出
        assert!(
            all_events.iter().all(|e| {
                !(e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "thinking_delta"
                    && e.data["delta"]["thinking"] == "</thinking>")
            }),
            "`</thinking>` should be filtered from output"
        );

        // thinking block 必须在 tool_use block 之前关闭
        let thinking_index = ctx
            .thinking_block_index
            .expect("thinking block index should exist");
        let pos_thinking_stop = all_events.iter().position(|e| {
            e.event == "content_block_stop"
                && e.data["index"].as_i64() == Some(thinking_index as i64)
        });
        let pos_tool_start = all_events.iter().position(|e| {
            e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
        });
        assert!(
            pos_thinking_stop.is_some(),
            "thinking block should be stopped"
        );
        assert!(pos_tool_start.is_some(), "tool_use block should be started");
        assert!(
            pos_thinking_stop.unwrap() < pos_tool_start.unwrap(),
            "thinking block should stop before tool_use block starts"
        );
    }

    #[test]
    fn test_final_flush_filters_standalone_thinking_end_tag() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>"));
        all_events.extend(ctx.generate_final_events());

        assert!(
            all_events.iter().all(|e| {
                !(e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "thinking_delta"
                    && e.data["delta"]["thinking"] == "</thinking>")
            }),
            "`</thinking>` should be filtered during final flush"
        );
    }

    #[test]
    fn test_thinking_strips_leading_newline_same_chunk() {
        // <thinking>\n 在同一个 chunk 中，\n 应被剥离
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>\nHello world");

        // 找到所有 thinking_delta 事件
        let thinking_deltas: Vec<_> = events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        // 拼接所有 thinking 内容
        let full_thinking: String = thinking_deltas
            .iter()
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_thinking.starts_with('\n'),
            "thinking content should not start with \\n, got: {:?}",
            full_thinking
        );
    }

    #[test]
    fn test_thinking_strips_leading_newline_cross_chunk() {
        // <thinking> 在第一个 chunk 末尾，\n 在第二个 chunk 开头
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let events1 = ctx.process_assistant_response("<thinking>");
        let events2 = ctx.process_assistant_response("\nHello world");

        let mut all_events = Vec::new();
        all_events.extend(events1);
        all_events.extend(events2);

        let thinking_deltas: Vec<_> = all_events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        let full_thinking: String = thinking_deltas
            .iter()
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_thinking.starts_with('\n'),
            "thinking content should not start with \\n across chunks, got: {:?}",
            full_thinking
        );
    }

    #[test]
    fn test_thinking_no_strip_when_no_leading_newline() {
        // <thinking> 后直接跟内容（无 \n），内容应完整保留
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>abc</thinking>\n\ntext");

        let thinking_deltas: Vec<_> = events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        let full_thinking: String = thinking_deltas
            .iter()
            .filter(|e| {
                !e.data["delta"]["thinking"]
                    .as_str()
                    .unwrap_or("")
                    .is_empty()
            })
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert_eq!(full_thinking, "abc", "thinking content should be 'abc'");
    }

    #[test]
    fn test_text_after_thinking_strips_leading_newlines() {
        // `</thinking>\n\n` 后的文本不应以 \n\n 开头
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>\nabc</thinking>\n\n你好");

        let text_deltas: Vec<_> = events
            .iter()
            .filter(|e| e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta")
            .collect();

        let full_text: String = text_deltas
            .iter()
            .map(|e| e.data["delta"]["text"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_text.starts_with('\n'),
            "text after thinking should not start with \\n, got: {:?}",
            full_text
        );
        assert_eq!(full_text, "你好");
    }

    /// 辅助函数：从事件列表中提取所有 thinking_delta 的拼接内容
    fn collect_thinking_content(events: &[SseEvent]) -> String {
        events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 辅助函数：从事件列表中提取所有 text_delta 的拼接内容
    fn collect_text_content(events: &[SseEvent]) -> String {
        events
            .iter()
            .filter(|e| e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta")
            .map(|e| e.data["delta"]["text"].as_str().unwrap_or(""))
            .collect()
    }

    #[test]
    fn test_end_tag_newlines_split_across_events() {
        // `</thinking>\n` 在 chunk 1，`\n` 在 chunk 2，`text` 在 chunk 3
        // 确保 `</thinking>` 不会被部分当作 thinking 内容发出
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("你好"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "你好", "text should be '你好', got: {:?}", text);
    }

    #[test]
    fn test_end_tag_alone_in_chunk_then_newlines_in_next() {
        // `</thinking>` 单独在一个 chunk，`\n\ntext` 在下一个 chunk
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all.extend(ctx.process_assistant_response("\n\n你好"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "你好", "text should be '你好', got: {:?}", text);
    }

    #[test]
    fn test_start_tag_newline_split_across_events() {
        // `\n\n` 在 chunk 1，`<thinking>` 在 chunk 2，`\n` 在 chunk 3
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("\n\n"));
        all.extend(ctx.process_assistant_response("<thinking>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("abc</thinking>\n\ntext"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "text", "text should be 'text', got: {:?}", text);
    }

    #[test]
    fn test_full_flow_maximally_split() {
        // 极端拆分：每个关键边界都在不同 chunk
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        // \n\n<thinking>\n 拆成多段
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("<thin"));
        all.extend(ctx.process_assistant_response("king>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("hello"));
        // </thinking>\n\n 拆成多段
        all.extend(ctx.process_assistant_response("</thi"));
        all.extend(ctx.process_assistant_response("nking>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("world"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "hello",
            "thinking should be 'hello', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "world", "text should be 'world', got: {:?}", text);
    }

    #[test]
    fn test_thinking_only_sets_max_tokens_stop_reason() {
        // 整个流只有 thinking 块，没有 text 也没有 tool_use，stop_reason 应为 max_tokens
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "max_tokens",
            "stop_reason should be max_tokens when only thinking is produced"
        );

        // 应补发一套完整的 text 事件（content_block_start + delta 空格 + content_block_stop）
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_start" && e.data["content_block"]["type"] == "text"
            }),
            "should emit text content_block_start"
        );
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == " "
            }),
            "should emit text_delta with a single space"
        );
        // text block 应被 generate_final_events 自动关闭
        let text_block_index = all_events
            .iter()
            .find_map(|e| {
                if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                    e.data["index"].as_i64()
                } else {
                    None
                }
            })
            .expect("text block should exist");
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(text_block_index)
            }),
            "text block should be stopped"
        );
    }

    #[test]
    fn test_thinking_with_text_keeps_end_turn_stop_reason() {
        // thinking + text 的情况，stop_reason 应为 end_turn
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>\n\nHello"));
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "end_turn",
            "stop_reason should be end_turn when text is also produced"
        );
    }

    #[test]
    fn test_thinking_with_tool_use_keeps_tool_use_stop_reason() {
        // thinking + tool_use 的情况，stop_reason 应为 tool_use
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, true, HashMap::new(), 1024);
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all_events.extend(
            ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
                name: "test_tool".to_string(),
                tool_use_id: "tool_1".to_string(),
                input: "{}".to_string(),
                stop: true,
            }),
        );
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "tool_use",
            "stop_reason should be tool_use when tool_use is present"
        );
    }

    // ===== #43 工具调用明文泄漏检测 =====

    #[test]
    fn test_detect_tool_call_leak_positive() {
        // 正例：含 <invoke name=" 命中
        assert_eq!(
            detect_text_tool_call_leak("进第12轮验证。\n\ncall\n<invoke name=\"Bash\">\n"),
            Some("<invoke name=\"")
        );
        // 正例：含 <function_calls> 命中
        assert_eq!(
            detect_text_tool_call_leak("foo<function_calls>bar"),
            Some("<function_calls>")
        );
    }

    #[test]
    fn test_detect_tool_call_leak_negative() {
        // 反例：正常文本含 call/function/parameter 单词不命中
        assert_eq!(detect_text_tool_call_leak("call the function please"), None);
        assert_eq!(
            detect_text_tool_call_leak("参数 parameter 的说明如下"),
            None
        );
        assert_eq!(detect_text_tool_call_leak("我们来 invoke 这个工具"), None);
        assert_eq!(detect_text_tool_call_leak(""), None);
    }

    #[test]
    fn test_leak_sliding_window_cross_chunk() {
        // 标记 `<invoke name="` 跨 chunk 边界切断，滑动窗口拼接后仍应命中
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        ctx.process_assistant_response("一些前置正常文本，长到足以触发窗口截断的内容……<inv");
        assert!(ctx.tool_call_leak_marker.is_none(), "半截标记不应误命中");
        ctx.process_assistant_response("oke name=\"Bash\">");
        assert_eq!(
            ctx.tool_call_leak_marker,
            Some("<invoke name=\""),
            "跨 chunk 拼接后应命中"
        );
    }

    #[test]
    fn test_leak_window_is_bounded() {
        // 滑动窗口内存 O(1)：喂入大量无标记文本后，tail 长度不超过窗口上限
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        for _ in 0..1000 {
            ctx.process_assistant_response("这是一段没有任何工具调用标记的普通长文本内容。");
        }
        assert!(ctx.tool_call_leak_marker.is_none());
        assert!(
            ctx.tool_call_leak_tail.chars().count() <= TOOL_CALL_LEAK_TAIL_CHARS,
            "窗口字符数应被限制在 {} 以内，实际 {}",
            TOOL_CALL_LEAK_TAIL_CHARS,
            ctx.tool_call_leak_tail.chars().count()
        );
    }

    #[test]
    fn test_leak_short_circuit_after_hit() {
        // 命中后短路：marker 已置位则后续 chunk 不再拼接（tail 保持清空）
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        ctx.process_assistant_response("<invoke name=\"Bash\">");
        assert_eq!(ctx.tool_call_leak_marker, Some("<invoke name=\""));
        assert!(ctx.tool_call_leak_tail.is_empty());
        ctx.process_assistant_response("后续还有很多文本但不应再被拼接进窗口");
        assert!(
            ctx.tool_call_leak_tail.is_empty(),
            "命中后窗口应保持清空（短路）"
        );
    }

    #[test]
    fn test_leak_overrides_stop_reason_to_max_tokens() {
        // 集成：文本含 invoke 标签 + 无结构化 tool_use → 命中告警条件
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        ctx.process_assistant_response("分析完成。\n\ncall\n<invoke name=\"Bash\">\ncmd</invoke>");
        ctx.generate_final_events();
        assert!(
            ctx.tool_call_leak_marker.is_some() && !ctx.state_manager.has_tool_use(),
            "应满足告警条件：marker 命中且无 tool_use"
        );
        assert_eq!(
            ctx.state_manager.get_stop_reason(),
            "max_tokens",
            "泄漏检测应将 stop_reason 修正为 max_tokens"
        );
    }

    #[test]
    fn test_leak_no_warn_when_real_tool_use() {
        // 回归：真结构化 tool_use 在场时，即便文本恰含 invoke 标签也不告警（不误报）
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        ctx.process_assistant_response("文本里讨论了 <invoke name=\"X\"> 的语法");
        ctx.state_manager.set_has_tool_use(true);
        ctx.generate_final_events();
        assert!(
            !(ctx.tool_call_leak_marker.is_some() && !ctx.state_manager.has_tool_use()),
            "has_tool_use=true 时不应满足告警条件"
        );
        assert_eq!(
            ctx.state_manager.get_stop_reason(),
            "tool_use",
            "has_tool_use=true 时 stop_reason 应为 tool_use 而非被泄漏检测覆盖"
        );
    }

    #[test]
    fn test_leak_does_not_override_explicit_stop_reason() {
        // 当已有显式 stop_reason（如 context exceeded）时，泄漏检测不覆盖
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 200_000, 1, false, HashMap::new(), 1024);
        ctx.state_manager
            .set_stop_reason("model_context_window_exceeded");
        ctx.process_assistant_response("触发泄漏\n<invoke name=\"Bash\">\n参数</invoke>");
        ctx.generate_final_events();
        assert!(ctx.tool_call_leak_marker.is_some(), "marker 应命中");
        assert_eq!(
            ctx.state_manager.get_stop_reason(),
            "model_context_window_exceeded",
            "已有显式 stop_reason 时不应被泄漏检测覆盖"
        );
    }

    #[test]
    fn test_leak_stop_reason_non_stream_logic() {
        // 非流式路径决策逻辑验证：detect + stop_reason == "end_turn" → override
        let text_leak = "分析完成\n<invoke name=\"Bash\">\ncmd</invoke>";
        let text_clean = "正常文本，没有工具调用标记";

        // Case 1: 命中 + end_turn → 应 override
        assert!(detect_text_tool_call_leak(text_leak).is_some());
        let mut stop_reason = "end_turn".to_string();
        if detect_text_tool_call_leak(text_leak).is_some() && stop_reason == "end_turn" {
            stop_reason = "max_tokens".to_string();
        }
        assert_eq!(stop_reason, "max_tokens");

        // Case 2: 命中 + 非 end_turn → 不 override
        let mut stop_reason2 = "model_context_window_exceeded".to_string();
        if detect_text_tool_call_leak(text_leak).is_some() && stop_reason2 == "end_turn" {
            stop_reason2 = "max_tokens".to_string();
        }
        assert_eq!(stop_reason2, "model_context_window_exceeded");

        // Case 3: 未命中 + end_turn → 不 override
        assert!(detect_text_tool_call_leak(text_clean).is_none());
        let mut stop_reason3 = "end_turn".to_string();
        if detect_text_tool_call_leak(text_clean).is_some() && stop_reason3 == "end_turn" {
            stop_reason3 = "max_tokens".to_string();
        }
        assert_eq!(stop_reason3, "end_turn");
    }

    // ─────────────────────────────────────────────────────────────────
    // #64 — error_sse_event 与 is_empty_response 单元测试
    //
    // 覆盖 BDD S1/S1b/S2/S2b 的判定逻辑层：具体的流式收尾时序（含真实
    // 上游中断/空 body）在 handlers.rs 用 mock 上游做端到端验证，此处
    // 聚焦 error_sse_event 的 JSON 结构与 is_empty_response 在各输入
    // 状态下的真值，为端到端测试的判定依据提供独立单元背书。
    // ─────────────────────────────────────────────────────────────────

    /// 构造一个只关心 `content` 的 AssistantResponseEvent。
    ///
    /// `extra` 字段是私有的（跨模块 `..Default::default()` 编译不过），
    /// 用 `Default::default()` 再赋值公开字段绕开可见性限制。
    fn assistant_response_event(
        content: &str,
    ) -> crate::kiro::model::events::AssistantResponseEvent {
        let mut event = crate::kiro::model::events::AssistantResponseEvent::default();
        event.content = content.to_string();
        event
    }

    #[test]
    fn test_error_sse_event_connection_interrupted_is_overloaded_error() {
        let event = error_sse_event(StreamFailure::ConnectionInterrupted);
        assert_eq!(event.event, "error");
        assert_eq!(event.data["type"], "error");
        assert_eq!(event.data["error"]["type"], "overloaded_error");
        assert_eq!(
            event.data["error"]["message"],
            "Upstream connection interrupted. Please retry."
        );
    }

    #[test]
    fn test_error_sse_event_fatal_is_api_error() {
        let event = error_sse_event(StreamFailure::Fatal);
        assert_eq!(event.event, "error");
        assert_eq!(event.data["type"], "error");
        assert_eq!(event.data["error"]["type"], "api_error");
        assert_eq!(event.data["error"]["message"], "Upstream response failed.");
    }

    // ─────────────────────────────────────────────────────────────────
    // #83 — StreamFailure 四变体 + classify_stream_failure 判定矩阵
    //
    // 分两层：classify_stream_failure 是纯函数，可表驱动穷举所有输入组合；
    // error_sse_event 的四变体映射另起用例分别核对 (error_type, message)。
    // 两层合起来才完整覆盖「输入信号 → 成因分类 → 对外文案」这条链路。
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_stream_failure_matrix() {
        use std::time::Duration;

        // (transient, empty, elapsed_secs, 期望成因)
        let cases: Vec<(bool, bool, u64, StreamFailure)> = vec![
            // 瞬态 + 零产出 + 已运行够久 → 首字超时归因，携带实测 elapsed。
            (
                true,
                true,
                300,
                StreamFailure::FirstTokenTimeout { elapsed_secs: 300 },
            ),
            (
                true,
                true,
                240,
                StreamFailure::FirstTokenTimeout { elapsed_secs: 240 },
            ),
            // 闸门下界：199s 未达 200s 阈值，不归因为首字超时（早期抖动）。
            (true, true, 199, StreamFailure::ConnectionInterrupted),
            // 回应 plan-review Round 1 [Major]：2 秒抖动绝不能被绝对化归因为
            // ~240s 首字超时，否则会把早期网络问题误报成确定性上限。
            (true, true, 2, StreamFailure::ConnectionInterrupted),
            // 有内容不算首字超时，即便运行时长已过闸门。
            (true, false, 300, StreamFailure::ConnectionInterrupted),
            // 非瞬态一票归 Fatal，empty/elapsed 取值不再参与判定。
            (false, true, 300, StreamFailure::Fatal),
        ];

        for (transient, empty, elapsed_secs, expected) in cases {
            let actual =
                classify_stream_failure(transient, empty, Duration::from_secs(elapsed_secs));
            assert_eq!(
                actual, expected,
                "classify_stream_failure(transient={transient}, empty={empty}, elapsed={elapsed_secs}s) \
                 期望 {expected:?}，实际 {actual:?}"
            );
        }
    }

    #[test]
    fn test_error_sse_event_first_token_timeout_message_contains_measured_elapsed() {
        // 钉死「报实测不报硬编码 240s」：message 必须逐字含运行时实测秒数，
        // 300 与 240 都要能在文案里各自精确出现，防止实现里悄悄写死 240。
        let event_300 = error_sse_event(StreamFailure::FirstTokenTimeout { elapsed_secs: 300 });
        let message_300 = event_300.data["error"]["message"].as_str().unwrap();
        assert!(
            message_300.contains("300s"),
            "FirstTokenTimeout{{300}} 的文案应含实测秒数 300s，实际：{message_300}"
        );
        assert!(
            !message_300.contains("240s"),
            "300s 的实测值不应被硬编码的 240s 顶替，实际：{message_300}"
        );

        let event_240 = error_sse_event(StreamFailure::FirstTokenTimeout { elapsed_secs: 240 });
        let message_240 = event_240.data["error"]["message"].as_str().unwrap();
        assert!(
            message_240.contains("240s"),
            "FirstTokenTimeout{{240}} 的文案应含实测秒数 240s，实际：{message_240}"
        );

        assert_eq!(event_300.data["error"]["type"], "overloaded_error");
        assert_eq!(event_240.data["error"]["type"], "overloaded_error");
    }

    #[test]
    fn test_error_sse_event_empty_response_is_overloaded_error_aligned_with_non_stream() {
        let event = error_sse_event(StreamFailure::EmptyResponse);
        assert_eq!(event.event, "error");
        assert_eq!(event.data["error"]["type"], "overloaded_error");
        // 与非流式路径（handlers.rs 空响应分支）对齐措辞，不再复用「连接中断」。
        assert_eq!(
            event.data["error"]["message"],
            "Upstream returned an empty response. Please retry."
        );
    }

    #[test]
    fn test_all_three_transient_failures_are_overloaded_error() {
        // 重试语义防回归护栏（硬约束1）：三种可重试成因的 error.type 必须
        // 全部保持 overloaded_error，本次改动只改文案分类，不改重试语义。
        let transient_failures = [
            StreamFailure::FirstTokenTimeout { elapsed_secs: 300 },
            StreamFailure::ConnectionInterrupted,
            StreamFailure::EmptyResponse,
        ];
        for failure in transient_failures {
            let event = error_sse_event(failure);
            assert_eq!(
                event.data["error"]["type"], "overloaded_error",
                "{failure:?} 的 error.type 必须是 overloaded_error，实际：{:?}",
                event.data["error"]["type"]
            );
        }
    }

    #[test]
    fn test_error_sse_event_to_sse_string_has_error_event_line() {
        // S1/S2 端到端断言都靠 to_sse_string() 里的 "event: error\n" 文本判定，
        // 这里独立锚定该格式不被后续改动破坏。
        let sse = error_sse_event(StreamFailure::ConnectionInterrupted).to_sse_string();
        assert!(sse.starts_with("event: error\n"));
        assert!(sse.contains("overloaded_error"));
    }

    #[test]
    fn test_is_empty_response_true_for_fresh_context() {
        // S2 前提：全新 ctx（未处理任何事件）应判定为空响应。
        let ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        assert!(ctx.is_empty_response());
    }

    #[test]
    fn test_is_empty_response_false_after_nonempty_assistant_response() {
        // S2b 前提：收到非空文本内容后，output_tokens > 0，不应判定为空响应。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let event = Event::AssistantResponse(assistant_response_event("hello world"));
        ctx.process_kiro_event(&event);

        assert!(!ctx.is_empty_response());
    }

    #[test]
    fn test_is_empty_response_true_after_empty_content_assistant_response() {
        // process_assistant_response 对空 content 短路返回，不累加 output_tokens——
        // 即便收到过 assistantResponseEvent 帧，只要 content 都是空串，仍应判定为空响应。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let event = Event::AssistantResponse(assistant_response_event(""));
        ctx.process_kiro_event(&event);

        assert!(
            ctx.is_empty_response(),
            "空 content 的 assistantResponseEvent 不应使 is_empty_response 翻转为 false"
        );
    }

    #[test]
    fn test_has_explicit_stop_reason_default_is_false() {
        // 默认 stop_reason 为 None（未设置），不算显式终止。
        let mgr = SseStateManager::new();
        assert!(!mgr.has_explicit_stop_reason());
    }

    #[test]
    fn test_has_explicit_stop_reason_true_for_max_tokens() {
        let mut mgr = SseStateManager::new();
        mgr.set_stop_reason("max_tokens");
        assert!(mgr.has_explicit_stop_reason());
    }

    #[test]
    fn test_has_explicit_stop_reason_true_for_context_window_exceeded() {
        let mut mgr = SseStateManager::new();
        mgr.set_stop_reason("model_context_window_exceeded");
        assert!(mgr.has_explicit_stop_reason());
    }

    #[test]
    fn test_has_explicit_stop_reason_false_for_end_turn() {
        // end_turn 是默认收尾语义，即便被显式塞入也不算终止信号。
        let mut mgr = SseStateManager::new();
        mgr.set_stop_reason("end_turn");
        assert!(!mgr.has_explicit_stop_reason());
    }

    #[test]
    fn test_is_empty_response_false_when_context_window_exceeded_without_content() {
        // C1 死循环修正核心：contextUsage>=100% 设置 model_context_window_exceeded 后
        // 上游不吐任何 assistantResponse 就结束 —— output_tokens==0 且无 tool_use，但
        // 有显式终止 stop_reason，不应判空（否则发 error 帧诱导客户端永久重试必然触发上限的请求）。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        // contextUsage 100% → 设置 model_context_window_exceeded，且返回空事件（不产出内容）
        let events = ctx.process_kiro_event(&Event::ContextUsage(
            serde_json::from_value(json!({"contextUsagePercentage": 100.0})).unwrap(),
        ));
        assert!(events.is_empty(), "contextUsage 事件本身不产出 SSE 内容");

        assert!(
            !ctx.is_empty_response(),
            "有 model_context_window_exceeded 终止信号时零产出不应判空"
        );
    }

    #[test]
    fn test_is_empty_response_false_when_content_length_exceeded_without_content() {
        // C1：ContentLengthExceededException 设置 max_tokens 后上游不吐内容就结束——
        // 同样不应判空，走正常收尾透传 max_tokens（客户端据此续写而非重试）。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let events = ctx.process_kiro_event(&Event::Exception {
            exception_type: "ContentLengthExceededException".to_string(),
            message: "content length exceeds threshold".to_string(),
        });
        assert!(events.is_empty(), "Exception 事件本身不产出 SSE 内容");

        assert!(
            !ctx.is_empty_response(),
            "有 max_tokens 终止信号时零产出不应判空"
        );
    }

    #[test]
    fn test_empty_with_explicit_stop_reason_finish_emits_stop_reason_not_error() {
        // C1 流式收尾正路：零产出 + 显式 stop_reason 走 generate_final_events（正常收尾），
        // message_delta 携带 max_tokens，绝不发 error 帧。这是死循环修复后的期望收尾语义。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        ctx.process_kiro_event(&Event::Exception {
            exception_type: "ContentLengthExceededException".to_string(),
            message: "content length exceeds threshold".to_string(),
        });
        assert!(!ctx.is_empty_response());

        let final_events = ctx.generate_final_events();
        let delta = final_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("零产出+显式 stop_reason 应走正常收尾，含 message_delta");
        assert_eq!(
            delta.data["delta"]["stop_reason"], "max_tokens",
            "应透传上游显式终止的 max_tokens"
        );
        assert!(
            final_events.iter().any(|e| e.event == "message_stop"),
            "正常收尾必须含 message_stop"
        );
    }

    #[test]
    fn test_is_empty_response_false_after_tool_use() {
        // S2b 前提的另一分支：即便没有文本输出（output_tokens==0），只要有结构化
        // tool_use，也不应被判定为空响应（has_tool_use 短路 is_empty_response）。
        use crate::kiro::model::events::ToolUseEvent;

        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let event = Event::ToolUse(ToolUseEvent {
            name: "Bash".to_string(),
            tool_use_id: "toolu_01".to_string(),
            input: r#"{"command":"ls"}"#.to_string(),
            stop: true,
        });
        ctx.process_kiro_event(&event);

        assert!(!ctx.is_empty_response());
    }

    #[test]
    fn test_buffered_stream_context_is_empty_response_delegates_to_inner() {
        let mut ctx =
            BufferedStreamContext::new("test-model", 200_000, 10, false, HashMap::new(), 1024);
        assert!(ctx.is_empty_response(), "未处理任何事件时应为空响应");

        let event = Event::AssistantResponse(assistant_response_event("non-empty"));
        ctx.process_and_buffer(&event);

        assert!(
            !ctx.is_empty_response(),
            "BufferedStreamContext::is_empty_response 应与内部 StreamContext 状态一致"
        );
    }

    #[test]
    fn test_prefix_buffered_stream_context_is_empty_response_delegates_to_inner() {
        let mut ctx = PrefixBufferedStreamContext::new(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        assert!(ctx.is_empty_response(), "未处理任何事件时应为空响应");

        let event = Event::AssistantResponse(assistant_response_event("non-empty"));
        ctx.process_event(&event);

        assert!(
            !ctx.is_empty_response(),
            "PrefixBufferedStreamContext::is_empty_response 应与内部 StreamContext 状态一致"
        );
    }

    #[test]
    fn test_s2b_regression_normal_completion_with_content_emits_delta_and_stop() {
        // S2b 回归锚点：有内容的正常收尾（EOF 前已有输出）行为不受 #64 影响——
        // is_empty_response()==false，generate_final_events 仍产出 message_delta
        // + message_stop，stop_reason 为正常值（非 error 分支的 overloaded_error）。
        let mut ctx = StreamContext::new_with_thinking(
            "test-model",
            200_000,
            10,
            false,
            HashMap::new(),
            1024,
        );
        let _ = ctx.generate_initial_events();

        let event = Event::AssistantResponse(assistant_response_event("some real output"));
        ctx.process_kiro_event(&event);
        assert!(!ctx.is_empty_response());

        let final_events = ctx.generate_final_events();
        assert!(
            final_events.iter().any(|e| e.event == "message_delta"),
            "有内容收尾必须包含 message_delta"
        );
        assert!(
            final_events.iter().any(|e| e.event == "message_stop"),
            "有内容收尾必须包含 message_stop"
        );
        let delta = final_events
            .iter()
            .find(|e| e.event == "message_delta")
            .unwrap();
        assert_eq!(delta.data["delta"]["stop_reason"], "end_turn");
    }
}
