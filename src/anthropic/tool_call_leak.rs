//! 工具调用 XML 明文泄漏检测与历史消毒
//!
//! #43 上游 opus-4-8 偶发把 Claude 内部工具调用协议明文（`<invoke name="...">` /
//! `<function_calls>`）当普通文本吐进 assistantResponseEvent，而非走结构化 tool_use 通道，
//! 导致 CC 屏幕"突然停止 + call 字样"、用户被迫「继续」。
//!
//! 检测函数仅做**可观测检测**（命中返回标记字面），不改任何透传行为、不改 stop_reason。
//! 误报收敛由调用方组合 `!has_tool_use`（真退化时模型没走结构化通道）完成。
//!
//! 本文件另提供**历史消毒**：在把 assistant 历史消息回传给上游前，截断尾部已闭合的
//! 泄漏 XML 块，阻止模型下一轮把泄漏明文当"已执行调用"产生幻觉（历史污染 → 幻觉链）。
//! 与 #43 的 stop_reason 缓解（改成 max_tokens 促使 CC 续接）正交互补：
//! stream.rs 侧治当轮流式输出，本文件治历史回传。

/// 最长标记 `<function_calls>` = 16 字节，流式滑动窗口保留 15 字符即可覆盖跨 chunk 截断。
pub(crate) const TOOL_CALL_LEAK_MARKERS: [&str; 2] = ["<invoke name=\"", "<function_calls>"];

/// 滑动窗口需保留的字符数：max(markers.len()) - 1，覆盖跨 chunk 截断的最坏情况。
pub(crate) const TOOL_CALL_LEAK_TAIL_CHARS: usize = 15;

/// 检测文本中是否含工具调用 XML 明文标记，命中返回该标记字面，否则 None。
pub(crate) fn detect_text_tool_call_leak(text: &str) -> Option<&'static str> {
    TOOL_CALL_LEAK_MARKERS
        .iter()
        .find(|m| text.contains(**m))
        .copied()
}

/// 从历史 assistant text content 中剥离尾部的工具调用 XML 泄漏块。
/// 循环执行直到尾部不再有泄漏闭合标签。
pub(crate) fn strip_leaked_tool_call_xml(text: &mut String) {
    while let Some(pos) = find_tail_leak_start(text.trim_end()) {
        text.truncate(text[..pos].trim_end().len());
    }
}

fn find_tail_leak_start(text: &str) -> Option<usize> {
    if text.is_empty() {
        return None;
    }

    let tail_tag = if text.ends_with("</function_calls>") {
        "</function_calls>"
    } else if text.ends_with("</invoke>") {
        "</invoke>"
    } else if text.ends_with("</parameter>") {
        "</parameter>"
    } else {
        return None;
    };

    match tail_tag {
        "</function_calls>" => {
            let pos = text.rfind("<function_calls>")?;
            let open_len = "<function_calls>".len();
            let close_len = tail_tag.len();
            let middle = &text[pos + open_len..text.len() - close_len];
            if middle.contains("</function_calls>") {
                return None;
            }
            Some(pos)
        }
        "</invoke>" | "</parameter>" => {
            let pos = text.rfind("<invoke")?;
            let close_tag = if tail_tag == "</invoke>" {
                "</invoke>"
            } else {
                "</parameter>"
            };
            let after_open = pos + text[pos..].find('>')? + 1;
            let before_tail = text.len() - close_tag.len();
            if after_open < before_tail && text[after_open..before_tail].contains("</invoke>") {
                return None;
            }
            let before = text[..pos].trim_end();
            if let Some(fc_pos) = before.rfind("<function_calls>") {
                if !text[fc_pos..pos].contains("</function_calls>") {
                    return Some(fc_pos);
                }
            }
            Some(pos)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_marker_hit() {
        assert_eq!(
            detect_text_tool_call_leak("进第12轮验证。\n\ncall\n<invoke name=\"Bash\">\n"),
            Some("<invoke name=\"")
        );
        assert_eq!(
            detect_text_tool_call_leak("foo<function_calls>bar"),
            Some("<function_calls>")
        );
        assert_eq!(detect_text_tool_call_leak("call the function please"), None);
        assert_eq!(detect_text_tool_call_leak(""), None);
    }

    #[test]
    fn test_strips_complete_invoke() {
        let mut text = "正常文本\n<invoke name=\"Bash\">\n<parameter name=\"command\">ls</parameter>\n</invoke>".to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "正常文本");
    }

    #[test]
    fn test_strips_complete_function_calls() {
        let mut text = "正常文本\n<function_calls>\n<invoke name=\"Bash\">\n<parameter name=\"command\">ls</parameter>\n</invoke>\n</function_calls>".to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "正常文本");
    }

    #[test]
    fn test_strips_consecutive_bare_invokes() {
        let mut text =
            "text\n<invoke name=\"A\"></invoke>\n<invoke name=\"B\"></invoke>".to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "text");
    }

    #[test]
    fn test_strips_nested_unclosed_function_calls() {
        let mut text =
            "text\n<function_calls>\n<invoke name=\"A\"></invoke>\n<invoke name=\"B\"></invoke>"
                .to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "text");
    }

    #[test]
    fn test_preserves_code_block() {
        let mut text = "text\n```\n<invoke name=\"X\"></invoke>\n```".to_string();
        let expected = text.clone();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, expected);
    }

    #[test]
    fn test_preserves_inline_prose() {
        let mut text = "use <invoke name=\"X\"> to call tools".to_string();
        let expected = text.clone();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, expected);
    }

    #[test]
    fn test_preserves_unclosed() {
        let mut text = "text\n<invoke name=\"X\">\n<parameter".to_string();
        let expected = text.clone();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, expected);
    }

    #[test]
    fn test_preserves_with_previous_closed_block() {
        // rfind("<invoke") 定位到的 open tag 与尾部闭合标签之间已经出现过一次
        // "</invoke>"（说明这段本来就已经闭合、尾部这个 "</invoke>" 是多余/游离的），
        // 防跨块保护应触发 None，不做截断。
        let mut text = "text\n<invoke name=\"A\">stuff</invoke>extra</invoke>".to_string();
        let expected = text.clone();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, expected);
    }

    #[test]
    fn test_full_leak_empty() {
        let mut text = "<invoke name=\"A\"></invoke>".to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "");
    }

    #[test]
    fn test_no_start_marker() {
        let mut text = "text </invoke>".to_string();
        let expected = text.clone();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, expected);
    }

    #[test]
    fn test_trims_whitespace() {
        let mut text = "正常文本   \n\n<invoke name=\"Bash\"></invoke>   \n".to_string();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "正常文本");
    }

    #[test]
    fn test_empty_noop() {
        let mut text = String::new();
        strip_leaked_tool_call_xml(&mut text);
        assert_eq!(text, "");
    }
}
