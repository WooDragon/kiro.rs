use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::model::config::PromptCacheMode;

use super::types::{CacheControl, MessagesRequest};

const DEFAULT_PROMPT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MIN_CACHEABLE_TOKENS: i32 = 1024;
const OPUS_MIN_CACHEABLE_TOKENS: i32 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromptCacheUsage {
    pub cache_creation_input_tokens: i32,
    pub cache_read_input_tokens: i32,
    pub cache_creation_5m_input_tokens: i32,
    pub cache_creation_1h_input_tokens: i32,
}

impl PromptCacheUsage {
    pub fn has_tokens(self) -> bool {
        self.cache_creation_input_tokens > 0
            || self.cache_read_input_tokens > 0
            || self.cache_creation_5m_input_tokens > 0
            || self.cache_creation_1h_input_tokens > 0
    }
}

#[derive(Debug, Clone)]
struct PromptCacheBreakpoint {
    fingerprint: [u8; 32],
    cumulative_tokens: i32,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct PromptCacheProfile {
    breakpoints: Vec<PromptCacheBreakpoint>,
    total_input_tokens: i32,
    model: String,
}

#[derive(Debug, Clone, Copy)]
struct PromptCacheEntry {
    expires_at: Instant,
    ttl: Duration,
}

#[derive(Debug, Default)]
pub struct PromptCacheTracker {
    entries_by_account: Mutex<HashMap<String, HashMap<[u8; 32], PromptCacheEntry>>>,
}

#[derive(Debug, Clone, Copy)]
pub struct PromptCacheDecision {
    pub fallback_usage: PromptCacheUsage,
    pub include_cache_fields: bool,
}

impl PromptCacheTracker {
    pub fn build_profile(
        &self,
        req: &MessagesRequest,
        total_input_tokens: i32,
    ) -> Option<PromptCacheProfile> {
        let blocks = flatten_cache_blocks(req);
        if blocks.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        let mut breakpoints = Vec::new();
        let mut cumulative_tokens = 0;
        let mut active_ttl = None;

        for block in blocks {
            write_hash_chunk(&mut hasher, block.canonical.as_bytes());
            cumulative_tokens += block.tokens;

            let breakpoint_ttl = if let Some(ttl) = block.ttl {
                active_ttl = Some(ttl);
                Some(ttl)
            } else if block.is_message_end {
                active_ttl
            } else {
                None
            };

            if let Some(ttl) = breakpoint_ttl {
                breakpoints.push(PromptCacheBreakpoint {
                    fingerprint: hasher.clone().finalize().into(),
                    cumulative_tokens,
                    ttl,
                });
            }
        }

        if breakpoints.is_empty() {
            return None;
        }

        Some(PromptCacheProfile {
            breakpoints,
            total_input_tokens: total_input_tokens.max(cumulative_tokens).max(1),
            model: req.model.clone(),
        })
    }

    pub fn compute(
        &self,
        account_key: &str,
        profile: Option<&PromptCacheProfile>,
    ) -> PromptCacheUsage {
        let Some(profile) = profile else {
            return PromptCacheUsage::default();
        };
        if account_key.is_empty() || profile.breakpoints.is_empty() {
            return PromptCacheUsage::default();
        }

        let min_tokens = min_cacheable_tokens_for_model(&profile.model);
        let mut last_tokens = profile
            .breakpoints
            .last()
            .map(|b| b.cumulative_tokens.min(profile.total_input_tokens))
            .unwrap_or_default();
        let now = Instant::now();

        let mut entries_by_account = self
            .entries_by_account
            .lock()
            .expect("prompt cache lock poisoned");
        prune_expired(&mut entries_by_account, now);

        let Some(entries) = entries_by_account.get_mut(account_key) else {
            let effective_creation = if last_tokens >= min_tokens {
                last_tokens
            } else {
                0
            };
            let (cache_5m, cache_1h) = compute_ttl_breakdown(profile, 0);
            return PromptCacheUsage {
                cache_creation_input_tokens: effective_creation,
                cache_read_input_tokens: 0,
                cache_creation_5m_input_tokens: cache_5m,
                cache_creation_1h_input_tokens: cache_1h,
            };
        };

        let max_cacheable = ((profile.total_input_tokens as f64) * 0.85) as i32;
        if last_tokens > max_cacheable {
            last_tokens = max_cacheable;
        }

        let mut matched_tokens = 0;
        for breakpoint in profile.breakpoints.iter().rev() {
            if breakpoint.cumulative_tokens < min_tokens {
                continue;
            }
            let Some(entry) = entries.get_mut(&breakpoint.fingerprint) else {
                continue;
            };
            if entry.expires_at <= now {
                continue;
            }
            entry.expires_at = now + entry.ttl;
            matched_tokens = breakpoint
                .cumulative_tokens
                .min(profile.total_input_tokens)
                .min(last_tokens);
            break;
        }

        let creation = (last_tokens - matched_tokens).max(0);
        let (cache_5m, cache_1h) = compute_ttl_breakdown(profile, matched_tokens);
        PromptCacheUsage {
            cache_creation_input_tokens: creation,
            cache_read_input_tokens: matched_tokens,
            cache_creation_5m_input_tokens: cache_5m,
            cache_creation_1h_input_tokens: cache_1h,
        }
    }

    pub fn update(&self, account_key: &str, profile: Option<&PromptCacheProfile>) {
        let Some(profile) = profile else {
            return;
        };
        if account_key.is_empty() || profile.breakpoints.is_empty() {
            return;
        }

        let min_tokens = min_cacheable_tokens_for_model(&profile.model);
        let now = Instant::now();
        let mut entries_by_account = self
            .entries_by_account
            .lock()
            .expect("prompt cache lock poisoned");
        prune_expired(&mut entries_by_account, now);

        let entries = entries_by_account
            .entry(account_key.to_string())
            .or_default();
        for breakpoint in &profile.breakpoints {
            if breakpoint.cumulative_tokens < min_tokens {
                continue;
            }
            entries.insert(
                breakpoint.fingerprint,
                PromptCacheEntry {
                    expires_at: now + breakpoint.ttl,
                    ttl: breakpoint.ttl,
                },
            );
        }
    }
}

pub fn decide_prompt_cache(
    mode: PromptCacheMode,
    upstream_usage: Option<PromptCacheUsage>,
    fallback_usage: PromptCacheUsage,
    has_profile: bool,
) -> PromptCacheDecision {
    match mode {
        PromptCacheMode::Off => PromptCacheDecision {
            fallback_usage: PromptCacheUsage::default(),
            include_cache_fields: false,
        },
        PromptCacheMode::Passthrough => PromptCacheDecision {
            fallback_usage: upstream_usage.unwrap_or_default(),
            include_cache_fields: upstream_usage.is_some(),
        },
        PromptCacheMode::Emulated => PromptCacheDecision {
            fallback_usage,
            include_cache_fields: has_profile,
        },
        PromptCacheMode::Auto => {
            if let Some(usage) = upstream_usage {
                PromptCacheDecision {
                    fallback_usage: usage,
                    include_cache_fields: true,
                }
            } else {
                PromptCacheDecision {
                    fallback_usage,
                    include_cache_fields: has_profile,
                }
            }
        }
    }
}

pub fn uncached_input_tokens(input_tokens: i32, usage: PromptCacheUsage) -> i32 {
    (input_tokens - usage.cache_creation_input_tokens - usage.cache_read_input_tokens).max(0)
}

pub fn build_usage_value(
    input_tokens: i32,
    output_tokens: i32,
    usage: PromptCacheUsage,
    include_cache_fields: bool,
) -> Value {
    let mut result = Map::new();
    result.insert(
        "input_tokens".to_string(),
        json!(uncached_input_tokens(input_tokens, usage)),
    );
    result.insert("output_tokens".to_string(), json!(output_tokens));

    if include_cache_fields {
        result.insert(
            "cache_creation_input_tokens".to_string(),
            json!(usage.cache_creation_input_tokens),
        );
        result.insert(
            "cache_read_input_tokens".to_string(),
            json!(usage.cache_read_input_tokens),
        );
        result.insert(
            "cache_creation".to_string(),
            json!({
                "ephemeral_5m_input_tokens": usage.cache_creation_5m_input_tokens,
                "ephemeral_1h_input_tokens": usage.cache_creation_1h_input_tokens,
            }),
        );
    }

    Value::Object(result)
}

pub fn extract_usage_from_metering(value: &Value) -> Option<PromptCacheUsage> {
    let mut maps = Vec::new();
    collect_usage_maps(value, &mut maps);

    for map in maps {
        let cache_read =
            read_i32(map, &["cacheReadInputTokens", "cache_read_input_tokens"]).unwrap_or(0);
        let cache_creation = read_i32(
            map,
            &[
                "cacheCreationInputTokens",
                "cache_creation_input_tokens",
                "cacheWriteInputTokens",
                "cache_write_input_tokens",
            ],
        )
        .unwrap_or(0);
        let cache_5m = read_i32(
            map,
            &[
                "cacheCreation5mInputTokens",
                "cache_creation_5m_input_tokens",
                "ephemeral_5m_input_tokens",
            ],
        )
        .unwrap_or(0);
        let cache_1h = read_i32(
            map,
            &[
                "cacheCreation1hInputTokens",
                "cache_creation_1h_input_tokens",
                "ephemeral_1h_input_tokens",
            ],
        )
        .unwrap_or(0);

        let usage = PromptCacheUsage {
            cache_creation_input_tokens: cache_creation,
            cache_read_input_tokens: cache_read,
            cache_creation_5m_input_tokens: cache_5m,
            cache_creation_1h_input_tokens: cache_1h,
        };
        if usage.has_tokens()
            || map.contains_key("uncachedInputTokens")
            || map.contains_key("uncached_input_tokens")
        {
            return Some(usage);
        }
    }

    None
}

#[derive(Debug)]
struct CacheBlock {
    canonical: String,
    tokens: i32,
    ttl: Option<Duration>,
    is_message_end: bool,
}

fn flatten_cache_blocks(req: &MessagesRequest) -> Vec<CacheBlock> {
    let mut blocks = Vec::new();
    let prelude = json!({
        "kind": "request_prelude",
        "model": req.model,
        "tool_choice": req.tool_choice,
    });
    append_cache_block(&mut blocks, prelude, None, false);

    if let Some(tools) = &req.tools {
        for (idx, tool) in tools.iter().enumerate() {
            let value = json!({
                "kind": "tool",
                "tool_index": idx,
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "type": tool.tool_type,
                "max_uses": tool.max_uses,
            });
            append_cache_block(
                &mut blocks,
                value,
                ttl_from_cache_control(tool.cache_control.as_ref()),
                false,
            );
        }
    }

    if let Some(system) = &req.system {
        for (idx, msg) in system.iter().enumerate() {
            let value = json!({
                "kind": "system",
                "system_index": idx,
                "block": {
                    "type": "text",
                    "text": msg.text,
                    "cache_control": msg.cache_control,
                }
            });
            append_cache_block(
                &mut blocks,
                value,
                ttl_from_cache_control(msg.cache_control.as_ref()),
                false,
            );
        }
    }

    for (message_idx, message) in req.messages.iter().enumerate() {
        match &message.content {
            Value::String(text) => {
                let value = json!({
                    "kind": "message",
                    "message_index": message_idx,
                    "role": message.role,
                    "block_index": 0,
                    "block": {
                        "type": "text",
                        "text": text,
                    }
                });
                append_cache_block(&mut blocks, value, None, true);
            }
            Value::Array(items) => {
                let last = items.len().saturating_sub(1);
                for (block_idx, block) in items.iter().enumerate() {
                    let value = json!({
                        "kind": "message",
                        "message_index": message_idx,
                        "role": message.role,
                        "block_index": block_idx,
                        "block": block,
                    });
                    append_cache_block(
                        &mut blocks,
                        value,
                        ttl_from_value(block),
                        block_idx == last,
                    );
                }
            }
            other => {
                if !other.is_null() {
                    let value = json!({
                        "kind": "message",
                        "message_index": message_idx,
                        "role": message.role,
                        "block_index": 0,
                        "block": other,
                    });
                    append_cache_block(&mut blocks, value, ttl_from_value(other), true);
                }
            }
        }
    }

    blocks
}

fn append_cache_block(
    blocks: &mut Vec<CacheBlock>,
    value: Value,
    ttl: Option<Duration>,
    is_message_end: bool,
) {
    if is_anthropic_billing_header_block(value.get("block").unwrap_or(&value)) {
        return;
    }
    let canonical = canonical_json(&strip_position_keys(value));
    blocks.push(CacheBlock {
        tokens: estimate_tokens(&canonical),
        canonical,
        ttl,
        is_message_end,
    });
}

fn ttl_from_cache_control(cache_control: Option<&CacheControl>) -> Option<Duration> {
    let cache_control = cache_control?;
    if !cache_control.cache_type.eq_ignore_ascii_case("ephemeral") {
        return None;
    }
    parse_ttl(cache_control.ttl.as_ref()).or(Some(DEFAULT_PROMPT_CACHE_TTL))
}

fn ttl_from_value(value: &Value) -> Option<Duration> {
    let cache_control = value.get("cache_control")?;
    let cache_type = cache_control.get("type")?.as_str()?;
    if !cache_type.eq_ignore_ascii_case("ephemeral") {
        return None;
    }
    parse_ttl(cache_control.get("ttl")).or(Some(DEFAULT_PROMPT_CACHE_TTL))
}

fn parse_ttl(value: Option<&Value>) -> Option<Duration> {
    let ttl = match value {
        Some(Value::String(s)) => {
            let s = s.trim().to_ascii_lowercase();
            if let Some(stripped) = s.strip_suffix('m') {
                stripped
                    .parse::<u64>()
                    .ok()
                    .map(|m| Duration::from_secs(m * 60))
            } else if let Some(stripped) = s.strip_suffix('h') {
                stripped
                    .parse::<u64>()
                    .ok()
                    .map(|h| Duration::from_secs(h * 60 * 60))
            } else if let Some(stripped) = s.strip_suffix('s') {
                stripped.parse::<u64>().ok().map(Duration::from_secs)
            } else {
                s.parse::<u64>().ok().map(Duration::from_secs)
            }
        }
        Some(Value::Number(n)) => n.as_u64().map(Duration::from_secs),
        _ => None,
    }?;

    Some(normalize_ttl(ttl))
}

fn normalize_ttl(ttl: Duration) -> Duration {
    if ttl > Duration::from_secs(60 * 60) {
        Duration::from_secs(60 * 60)
    } else if ttl > DEFAULT_PROMPT_CACHE_TTL {
        Duration::from_secs(60 * 60)
    } else {
        DEFAULT_PROMPT_CACHE_TTL
    }
}

fn compute_ttl_breakdown(profile: &PromptCacheProfile, matched_tokens: i32) -> (i32, i32) {
    let mut cache_5m = 0;
    let mut cache_1h = 0;
    let mut previous = matched_tokens;
    for breakpoint in &profile.breakpoints {
        let current = breakpoint.cumulative_tokens.min(profile.total_input_tokens);
        if current <= previous {
            continue;
        }
        let delta = current - previous;
        if breakpoint.ttl >= Duration::from_secs(60 * 60) {
            cache_1h += delta;
        } else {
            cache_5m += delta;
        }
        previous = current;
    }
    (cache_5m, cache_1h)
}

fn prune_expired(
    entries_by_account: &mut HashMap<String, HashMap<[u8; 32], PromptCacheEntry>>,
    now: Instant,
) {
    entries_by_account.retain(|_, entries| {
        entries.retain(|_, entry| entry.expires_at > now);
        !entries.is_empty()
    });
}

fn min_cacheable_tokens_for_model(model: &str) -> i32 {
    if model.to_ascii_lowercase().contains("opus") {
        OPUS_MIN_CACHEABLE_TOKENS
    } else {
        DEFAULT_MIN_CACHEABLE_TOKENS
    }
}

fn estimate_tokens(text: &str) -> i32 {
    ((text.chars().count() as i32 + 3) / 4).max(1)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => serde_json::to_string(v).unwrap_or_default(),
        Value::Array(items) => {
            let inner = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", inner)
        }
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (key, item) in map {
                if key == "cache_control" {
                    continue;
                }
                sorted.insert(key, item);
            }
            let inner = sorted
                .into_iter()
                .map(|(key, item)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(item)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", inner)
        }
    }
}

fn strip_position_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let filtered = map
                .into_iter()
                .filter_map(|(key, value)| {
                    if matches!(
                        key.as_str(),
                        "tool_index" | "system_index" | "message_index" | "block_index"
                    ) {
                        None
                    } else {
                        Some((key, strip_position_keys(value)))
                    }
                })
                .collect();
            Value::Object(filtered)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(strip_position_keys).collect()),
        other => other,
    }
}

fn is_anthropic_billing_header_block(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    if let Some(Value::String(block_type)) = map.get("type") {
        if !block_type.is_empty() && block_type != "text" {
            return false;
        }
    }
    let Some(text) = map.get("text").and_then(Value::as_str) else {
        return false;
    };
    text.trim_start()
        .to_ascii_lowercase()
        .starts_with("x-anthropic-billing-header:")
}

fn write_hash_chunk(hasher: &mut Sha256, chunk: &[u8]) {
    hasher.update(chunk.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(chunk);
    hasher.update([0]);
}

fn collect_usage_maps<'a>(value: &'a Value, out: &mut Vec<&'a Map<String, Value>>) {
    match value {
        Value::Object(map) => {
            out.push(map);
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if lower == "usage" || lower == "tokenusage" || lower == "token_usage" {
                    if let Some(child_map) = child.as_object() {
                        out.push(child_map);
                    }
                }
                collect_usage_maps(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_usage_maps(item, out);
            }
        }
        _ => {}
    }
}

fn read_i32(map: &Map<String, Value>, keys: &[&str]) -> Option<i32> {
    for key in keys {
        let Some(value) = map.get(*key) else {
            continue;
        };
        if let Some(n) = value.as_i64() {
            return Some(n as i32);
        }
        if let Some(n) = value.as_u64() {
            return Some(n as i32);
        }
        if let Some(n) = value.as_f64() {
            return Some(n as i32);
        }
        if let Some(s) = value.as_str() {
            if let Ok(n) = s.parse::<i32>() {
                return Some(n);
            }
            if let Ok(n) = s.parse::<f64>() {
                return Some(n as i32);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::types::{Message, SystemMessage};

    fn long_text() -> String {
        "abcd ".repeat(1200)
    }

    #[test]
    fn parses_upstream_cache_usage() {
        let value = json!({
            "usage": {
                "cacheReadInputTokens": 123,
                "cacheCreationInputTokens": 456
            }
        });
        let usage = extract_usage_from_metering(&value).unwrap();
        assert_eq!(usage.cache_read_input_tokens, 123);
        assert_eq!(usage.cache_creation_input_tokens, 456);
    }

    #[test]
    fn computes_cache_creation_then_read() {
        let tracker = PromptCacheTracker::default();
        let req = MessagesRequest {
            model: "claude-sonnet-4-5".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: Value::String(long_text()),
            }],
            stream: false,
            system: Some(vec![SystemMessage {
                text: long_text(),
                cache_control: Some(CacheControl {
                    cache_type: "ephemeral".to_string(),
                    ttl: None,
                }),
            }]),
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        };
        let profile = tracker.build_profile(&req, 3000).unwrap();
        let first = tracker.compute("account", Some(&profile));
        assert!(first.cache_creation_input_tokens > 0);
        assert_eq!(first.cache_read_input_tokens, 0);
        tracker.update("account", Some(&profile));
        let second = tracker.compute("account", Some(&profile));
        assert!(second.cache_read_input_tokens > 0);
    }
}
