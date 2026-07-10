//! Kiro API 客户端模块

pub mod endpoint;
pub mod machine_id;
pub mod model;
pub mod parser;
pub mod provider;
pub mod token_manager;

/// 日志 payload 截断上限：8 KB。
///
/// 与 `anthropic::handlers` 里的同名私有常量口径一致，各自持有一份是刻意的——
/// 避免跨 `anthropic`/`kiro` 模块边界建立耦合（#71 Step3 施工期间与并行改动
/// handlers.rs 的 agent 隔离，不共享该模块的私有项）。
pub(crate) const LOG_PAYLOAD_LIMIT: usize = 8 * 1024;

/// 找到小于等于目标位置的最近有效 UTF-8 字符边界。
///
/// 与 `anthropic::stream::find_char_boundary` 逻辑等价的本地副本——那边的
/// `stream` 模块整体是私有的（`mod stream;` 未 `pub`），跨 `kiro`/`anthropic`
/// 边界不可达，且改 `anthropic/mod.rs` 的可见性会踩并行 agent 的地盘，故就近
/// 复刻一份，不建跨模块依赖。
fn find_char_boundary(s: &str, target: usize) -> usize {
    if target >= s.len() {
        return s.len();
    }
    if target == 0 {
        return 0;
    }
    let mut pos = target;
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

/// 日志用：超过 `limit` 字节则在 UTF-8 安全边界截断并标注省略字节数。
pub(crate) fn truncate_for_log(s: &str, limit: usize) -> std::borrow::Cow<'_, str> {
    if s.len() <= limit {
        std::borrow::Cow::Borrowed(s)
    } else {
        let end = find_char_boundary(s, limit);
        std::borrow::Cow::Owned(format!(
            "{}...<truncated {} bytes>",
            &s[..end],
            s.len() - end
        ))
    }
}
