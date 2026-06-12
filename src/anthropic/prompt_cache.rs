use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 缓存桶容量上限，对齐 sticky session 的 MAX_STICKY_SESSIONS。
/// 桶维度从凭据数（几个）换为会话数（可能上万）后必须加上限防内存膨胀。
const MAX_CACHE_ACCOUNTS: usize = 10_000;

/// 批量驱逐目标水位：超限时砍到 80%，一次摊销 ~20% 的桶。
/// 批量驱逐让 N 次插入才触发一次 O(N) 排序，摊销回 O(1) 插入代价。
const CACHE_PRUNE_TARGET: usize = MAX_CACHE_ACCOUNTS * 4 / 5; // 8_000，整数算术避免浮点

/// 全量 TTL 扫描的节流间隔，对齐 STICKY_SESSION_PRUNE_INTERVAL。
const CACHE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::model::config::PromptCacheMode;

use super::types::{CacheControl, MessagesRequest, is_claude_code_filtered_prompt_text};

const DEFAULT_PROMPT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MIN_CACHEABLE_TOKENS: i32 = 1024;
const HAIKU_3_MIN_CACHEABLE_TOKENS: i32 = 2048;
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
}

/// 单个账号/会话的缓存桶。
///
/// `last_touched` 仅在 `update`（写入）时刷新，`compute`（纯读）不刷新。
/// 这是 **LRW（Least Recently Written）** 策略而非真正的 LRU：
/// - 写即保活：正常每请求必然 update，活跃会话会持续刷新 last_touched。
/// - 读不改状态：避免只读路径持有写锁时发生争用。
/// - 已知折中：纯读命中的长会话（只读不写）在桶数超限时可能因 last_touched
///   较旧被过早驱逐；实际场景中 update 与 compute 总是配对，此折中可接受。
#[derive(Debug)]
struct AccountBucket {
    entries: HashMap<[u8; 32], PromptCacheEntry>,
    last_touched: Instant,
}

impl AccountBucket {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            last_touched: now,
        }
    }
}

#[derive(Debug, Default)]
pub struct PromptCacheTracker {
    entries_by_account: Mutex<HashMap<String, AccountBucket>>,
    /// 上次执行全量 TTL 扫描的时刻，用于节流 prune_expired。
    ///
    /// 锁顺序约定：`last_prune_at` 只能在已持有 `entries_by_account` 锁期间访问
    /// （目前仅 `maybe_prune_expired` 一处，且总在持 entries 锁时调用）。
    /// 新增访问点必须遵守此顺序，禁止先锁 last_prune_at 再锁 entries_by_account，
    /// 否则会与 compute/update 形成 ABBA 死锁。
    last_prune_at: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Copy)]
pub struct PromptCacheDecision {
    pub fallback_usage: PromptCacheUsage,
    pub include_cache_fields: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageSnapshot {
    pub input_tokens: Option<i32>,
    pub output_tokens: Option<i32>,
    pub total_tokens: Option<i32>,
    pub prompt_cache_usage: Option<PromptCacheUsage>,
}

impl UsageSnapshot {
    pub fn has_tokens(self) -> bool {
        self.input_tokens.is_some()
            || self.output_tokens.is_some()
            || self.total_tokens.is_some()
            || self.prompt_cache_usage.is_some()
    }
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
        maybe_prune_expired(&mut entries_by_account, &self.last_prune_at, now);

        let Some(bucket) = entries_by_account.get_mut(account_key) else {
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
            let Some(entry) = bucket.entries.get_mut(&breakpoint.fingerprint) else {
                continue;
            };
            if entry.expires_at <= now {
                continue;
            }
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
        maybe_prune_expired(&mut entries_by_account, &self.last_prune_at, now);

        // 写入时刷新 last_touched（LRW 策略：写即保活）。
        let bucket = entries_by_account
            .entry(account_key.to_string())
            .or_insert_with(|| AccountBucket::new(now));
        bucket.last_touched = now;
        for breakpoint in &profile.breakpoints {
            if breakpoint.cumulative_tokens < min_tokens {
                continue;
            }
            bucket.entries.insert(
                breakpoint.fingerprint,
                PromptCacheEntry {
                    expires_at: now + breakpoint.ttl,
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

#[allow(dead_code)]
pub fn extract_usage_from_metering(value: &Value) -> Option<PromptCacheUsage> {
    extract_usage_snapshot_from_metering(value).and_then(|snapshot| snapshot.prompt_cache_usage)
}

pub fn extract_usage_snapshot_from_metering(value: &Value) -> Option<UsageSnapshot> {
    let mut maps = Vec::new();
    collect_usage_maps(value, &mut maps);

    let mut snapshot = UsageSnapshot::default();
    let mut cache_usage = PromptCacheUsage::default();
    let mut saw_cache_fields = false;

    for map in maps {
        snapshot.input_tokens = snapshot.input_tokens.or_else(|| {
            read_i32(
                map,
                &[
                    "inputTokens",
                    "input_tokens",
                    "contextInputTokens",
                    "context_input_tokens",
                    "promptTokens",
                    "prompt_tokens",
                    "uncachedInputTokens",
                    "uncached_input_tokens",
                ],
            )
        });
        snapshot.output_tokens = snapshot.output_tokens.or_else(|| {
            read_i32(
                map,
                &[
                    "outputTokens",
                    "output_tokens",
                    "completionTokens",
                    "completion_tokens",
                    "generatedTokens",
                    "generated_tokens",
                ],
            )
        });
        snapshot.total_tokens = snapshot
            .total_tokens
            .or_else(|| read_i32(map, &["totalTokens", "total_tokens"]));
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
        let has_cache_fields = usage.has_tokens()
            || map.contains_key("cacheReadInputTokens")
            || map.contains_key("cache_read_input_tokens")
            || map.contains_key("cacheCreationInputTokens")
            || map.contains_key("cache_creation_input_tokens")
            || map.contains_key("cacheWriteInputTokens")
            || map.contains_key("cache_write_input_tokens");
        if has_cache_fields {
            saw_cache_fields = true;
            cache_usage.cache_read_input_tokens =
                cache_usage.cache_read_input_tokens.max(cache_read);
            cache_usage.cache_creation_input_tokens =
                cache_usage.cache_creation_input_tokens.max(cache_creation);
            cache_usage.cache_creation_5m_input_tokens =
                cache_usage.cache_creation_5m_input_tokens.max(cache_5m);
            cache_usage.cache_creation_1h_input_tokens =
                cache_usage.cache_creation_1h_input_tokens.max(cache_1h);
        }
    }

    if saw_cache_fields {
        snapshot.prompt_cache_usage = Some(cache_usage);
    }

    snapshot.has_tokens().then_some(snapshot)
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
    // 超过默认 5m TTL 的一律归一化到 1h 档，其余保持 5m 默认。
    // ttl > 1h 必然蕴含 ttl > DEFAULT_PROMPT_CACHE_TTL（5m），故无需单独判 1h 上限。
    if ttl > DEFAULT_PROMPT_CACHE_TTL {
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

/// 节流的缓存清理入口，每次 compute/update 调用。
///
/// 节流逻辑（对齐 token_manager.rs 的 maybe_prune_sticky_sessions）：
/// - 距上次全量扫描 < CACHE_PRUNE_INTERVAL：仅做超限批量驱逐，跳过 TTL 全扫。
/// - 距上次全量扫描 >= CACHE_PRUNE_INTERVAL 或首次调用：执行完整 prune（TTL + 驱逐）。
fn maybe_prune_expired(
    entries_by_account: &mut HashMap<String, AccountBucket>,
    last_prune_at: &Mutex<Option<Instant>>,
    now: Instant,
) {
    let should_ttl_scan = {
        let last = last_prune_at.lock().expect("last_prune_at lock poisoned");
        last.map(|t| now.duration_since(t) >= CACHE_PRUNE_INTERVAL)
            .unwrap_or(true)
    };

    if should_ttl_scan {
        // 全量 TTL 清理：清空过期指纹，删除空桶。
        entries_by_account.retain(|_, bucket| {
            bucket.entries.retain(|_, entry| entry.expires_at > now);
            !bucket.entries.is_empty()
        });
        *last_prune_at.lock().expect("last_prune_at lock poisoned") = Some(now);
    }

    // 批量 LRW 驱逐：仅当桶数超限才触发，一次砍到目标水位。
    //
    // 策略说明：这是 LRW（Least Recently Written）而非真 LRU——
    // 按 last_touched（最后写入时刻）升序排列，踢掉最久未写入的桶。
    // compute（纯读）不更新 last_touched，因此纯读命中的长会话在桶超限时
    // 可能被过早驱逐——这是已知折中，实际场景中 update 与 compute 配对出现，影响可接受。
    //
    // 批量摊销：N 次插入才触发一次 O(N) 排序，单次插入摊销代价为 O(1)。
    // 绝不能"每次超限只踢最老一个"——那会让每次插入都是 O(N) 扫描（写放大）。
    if entries_by_account.len() > MAX_CACHE_ACCOUNTS {
        let mut keys: Vec<_> = entries_by_account
            .iter()
            .map(|(k, bucket)| (k.clone(), bucket.last_touched))
            .collect();
        // 按 last_touched 升序：最旧的排前面，优先驱逐。
        keys.sort_by_key(|(_, touched)| *touched);

        let remove_count = entries_by_account.len().saturating_sub(CACHE_PRUNE_TARGET);
        for (key, _) in keys.into_iter().take(remove_count) {
            entries_by_account.remove(&key);
        }
    }
}

fn min_cacheable_tokens_for_model(model: &str) -> i32 {
    let model = model.to_ascii_lowercase().replace(['_', ' '], "-");
    if model.contains("opus") {
        OPUS_MIN_CACHEABLE_TOKENS
    } else if model.contains("haiku-3") {
        HAIKU_3_MIN_CACHEABLE_TOKENS
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
    if let Some(Value::String(block_type)) = map.get("type")
        && !block_type.is_empty()
        && block_type != "text"
    {
        return false;
    }
    let Some(text) = map.get("text").and_then(Value::as_str) else {
        return false;
    };
    is_claude_code_filtered_prompt_text(text)
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
                if (lower == "usage" || lower == "tokenusage" || lower == "token_usage")
                    && let Some(child_map) = child.as_object()
                {
                    out.push(child_map);
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
    fn parses_upstream_usage_snapshot_tokens_and_cache_fields() {
        let value = json!({
            "metering": {
                "tokenUsage": {
                    "inputTokens": "321",
                    "outputTokens": 17,
                    "totalTokens": 338,
                    "cacheWriteInputTokens": 55,
                    "cacheReadInputTokens": 89
                }
            }
        });

        let snapshot = extract_usage_snapshot_from_metering(&value).unwrap();
        assert_eq!(snapshot.input_tokens, Some(321));
        assert_eq!(snapshot.output_tokens, Some(17));
        assert_eq!(snapshot.total_tokens, Some(338));
        let cache = snapshot.prompt_cache_usage.unwrap();
        assert_eq!(cache.cache_creation_input_tokens, 55);
        assert_eq!(cache.cache_read_input_tokens, 89);
    }

    #[test]
    fn parses_upstream_usage_snapshot_from_total_minus_output() {
        let value = json!({
            "usage": {
                "total_tokens": 1000,
                "output_tokens": 25
            }
        });

        let snapshot = extract_usage_snapshot_from_metering(&value).unwrap();
        assert_eq!(snapshot.input_tokens, None);
        assert_eq!(snapshot.output_tokens, Some(25));
        assert_eq!(snapshot.total_tokens, Some(1000));
    }

    #[test]
    fn merges_usage_snapshot_tokens_and_cache_from_separate_maps() {
        let value = json!({
            "cacheReadInputTokens": 44,
            "usage": {
                "inputTokens": 900,
                "outputTokens": 33
            }
        });

        let snapshot = extract_usage_snapshot_from_metering(&value).unwrap();
        assert_eq!(snapshot.input_tokens, Some(900));
        assert_eq!(snapshot.output_tokens, Some(33));
        assert_eq!(
            snapshot.prompt_cache_usage.unwrap().cache_read_input_tokens,
            44
        );
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
            temperature: None,
            top_p: None,
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

    #[test]
    fn cache_hit_does_not_extend_expiry() {
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
            temperature: None,
            top_p: None,
            metadata: None,
        };
        let profile = tracker.build_profile(&req, 3000).unwrap();
        let fingerprint = profile.breakpoints.last().unwrap().fingerprint;

        tracker.update("account", Some(&profile));
        let before = {
            let entries_by_account = tracker.entries_by_account.lock().unwrap();
            entries_by_account
                .get("account")
                .and_then(|bucket| bucket.entries.get(&fingerprint))
                .map(|entry| entry.expires_at)
                .unwrap()
        };

        let usage = tracker.compute("account", Some(&profile));
        assert!(usage.cache_read_input_tokens > 0);

        let after = {
            let entries_by_account = tracker.entries_by_account.lock().unwrap();
            entries_by_account
                .get("account")
                .and_then(|bucket| bucket.entries.get(&fingerprint))
                .map(|entry| entry.expires_at)
                .unwrap()
        };
        assert_eq!(after, before);
    }

    #[test]
    fn min_cacheable_tokens_follow_anthropic_model_thresholds() {
        assert_eq!(
            min_cacheable_tokens_for_model("claude-opus-4-7"),
            OPUS_MIN_CACHEABLE_TOKENS
        );
        assert_eq!(
            min_cacheable_tokens_for_model("claude-haiku-3-5-20241022"),
            HAIKU_3_MIN_CACHEABLE_TOKENS
        );
        assert_eq!(
            min_cacheable_tokens_for_model("claude-haiku-4-5-20251001"),
            DEFAULT_MIN_CACHEABLE_TOKENS
        );
        assert_eq!(
            min_cacheable_tokens_for_model("claude-sonnet-4-5"),
            DEFAULT_MIN_CACHEABLE_TOKENS
        );
    }

    /// 构造含 cache_control 标记的最小请求，确保 build_profile 能拿到 breakpoints。
    fn make_cacheable_req(model: &str) -> MessagesRequest {
        MessagesRequest {
            model: model.to_string(),
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
            temperature: None,
            top_p: None,
            metadata: None,
        }
    }

    /// 同一 account_key（模拟 "conv:S"）下，用 update 写入后再 compute 仍命中。
    ///
    /// 验证核心语义：只要 account_key 不变，凭据信息根本不进 key，
    /// 换凭据（凭据 A → 凭据 B）不会丢失缓存命中。
    /// 对比：用不同 key（"cred:A" vs "cred:B"）写入后读取必然 miss，
    /// 证明旧的凭据分桶行为才会导致跨凭据 miss。
    #[test]
    fn test_fallback_credential_preserves_cache_hit() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // 模拟凭据 A 写入缓存，account_key 是会话维度的 "conv:S"。
        tracker.update("conv:S", Some(&profile));

        // 模拟 fallback 到凭据 B，但 account_key 仍是同一会话 "conv:S" ——应命中。
        let hit = tracker.compute("conv:S", Some(&profile));
        assert!(
            hit.cache_read_input_tokens > 0,
            "同会话 key 换凭据后应仍命中，cache_read={}",
            hit.cache_read_input_tokens
        );

        // 对比：若 key 按凭据分桶（旧行为），凭据 A 写的缓存，凭据 B 读时 key 不同 → miss。
        let miss = tracker.compute("cred:B", Some(&profile));
        assert_eq!(
            miss.cache_read_input_tokens, 0,
            "不同 key 不应命中（旧凭据桶与新凭据桶独立）"
        );
    }

    /// 两个不同 account_key（"conv:S1" / "conv:S2"）即使使用相同 profile，也不互相命中。
    ///
    /// 防止跨会话缓存串扰：S1 的缓存不能被 S2 读到。
    #[test]
    fn test_distinct_conversations_do_not_cross_hit() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // S1 写入缓存。
        tracker.update("conv:S1", Some(&profile));

        // S1 自读应命中。
        let s1_hit = tracker.compute("conv:S1", Some(&profile));
        assert!(s1_hit.cache_read_input_tokens > 0, "S1 自读应命中");

        // S2 读 S1 写入的缓存：不同 key，应 miss。
        let s2_miss = tracker.compute("conv:S2", Some(&profile));
        assert_eq!(
            s2_miss.cache_read_input_tokens, 0,
            "S2 不应读到 S1 的缓存，防串扰"
        );
    }

    /// 无稳定会话 ID 时退回 credential_id 分桶（"cred:N"），行为同现状。
    ///
    /// 验证兜底路径：handler 在 stable_conversation_id 为 None 时用 "cred:N" 作 key，
    /// 该 key 作为普通桶正常写读命中，不 panic、不比现状差。
    /// 同时验证：换凭据（cred:1 → cred:2）在兜底路径下仍会 miss（这是已知折中，
    /// 因为无会话 ID 无法做跨凭据共享，等同旧行为，不退化）。
    #[test]
    fn test_no_session_id_falls_back_to_credential_bucket() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // 凭据 1 兜底桶写入后自读应命中。
        tracker.update("cred:1", Some(&profile));
        let hit = tracker.compute("cred:1", Some(&profile));
        assert!(
            hit.cache_read_input_tokens > 0,
            "兜底 cred 桶自读应命中，cache_read={}",
            hit.cache_read_input_tokens
        );

        // 换到凭据 2 兜底桶：无会话 ID 时无法跨凭据共享，miss 属已知折中（等同旧行为）。
        let miss = tracker.compute("cred:2", Some(&profile));
        assert_eq!(
            miss.cache_read_input_tokens, 0,
            "无会话 ID 兜底路径换凭据 miss，等同旧行为不退化"
        );
    }

    /// 模拟 balanced 模式凭据反复切换：session_id 不变，credential 在 A/B 间来回轮转，
    /// 缓存命中在整个序列中保持稳定。
    ///
    /// 这是 #48 修复的核心场景——旧实现按 cred:N 分桶，balanced 切凭据即 miss；
    /// 新实现按 conv:UUID 分桶，凭据切换对缓存不可见。
    ///
    /// 测试流程模拟 handler 的完整 request-response 循环：
    /// 1. 请求到达 → handler 用 stable_conversation_id 构造 account_key = "conv:S"
    /// 2. compute() 查缓存（不关心实际路由到了哪个凭据）
    /// 3. 上游响应成功 → update() 写入/续期
    /// 4. 下一个请求到达，凭据可能已轮转到另一个 → 但 account_key 仍是 "conv:S"
    #[test]
    fn test_balanced_credential_rotation_does_not_break_cache() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // 模拟凭据 A/B 列表（实际 handler 只用 session_id 做 key，credential_id 不参与）
        let credentials = ["cred-A", "cred-B"];
        let session_id = "conv:stable-session-uuid";

        // 第 1 次请求：凭据 A，首次建缓存
        // handler: account_key = format!("conv:{}", session_id) — credential_id 不参与
        let usage = tracker.compute(session_id, Some(&profile));
        assert_eq!(
            usage.cache_read_input_tokens, 0,
            "首次请求应 miss（尚无缓存）"
        );
        assert!(
            usage.cache_creation_input_tokens > 0,
            "首次请求应报 creation"
        );
        // 上游成功后 update
        tracker.update(session_id, Some(&profile));

        // 第 2~10 次请求：凭据在 A/B 间交替轮转，模拟 balanced round-robin
        for i in 2..=10 {
            let _credential = credentials[i % 2]; // 凭据轮转，但 handler 不用它构造 key

            let usage = tracker.compute(session_id, Some(&profile));
            assert!(
                usage.cache_read_input_tokens > 0,
                "第 {} 次请求（凭据={}）应命中缓存，实际 cache_read={}",
                i,
                credentials[i % 2],
                usage.cache_read_input_tokens
            );
            assert_eq!(
                usage.cache_creation_input_tokens, 0,
                "第 {} 次请求不应有新 creation（全量命中）",
                i
            );
            // 每次成功后 update 续期
            tracker.update(session_id, Some(&profile));
        }
    }

    /// 对比验证：旧的凭据分桶行为下，balanced 轮转必然导致交替 miss。
    ///
    /// 证明 #48 之前的行为确实有问题：按 cred:N 分桶时，凭据切换 = key 切换 = miss。
    /// 此测试作为"问题复现"存在，确认修复前的行为是坏的。
    #[test]
    fn test_old_credential_bucketing_causes_alternating_miss() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // 模拟旧行为：account_key = format!("cred:{}", credential_id)
        // 凭据 A 写入
        tracker.update("cred:A", Some(&profile));

        // 凭据 A 自读：命中
        let hit = tracker.compute("cred:A", Some(&profile));
        assert!(hit.cache_read_input_tokens > 0, "凭据 A 自读应命中");

        // balanced 切到凭据 B：miss（旧行为的 bug）
        let miss = tracker.compute("cred:B", Some(&profile));
        assert_eq!(
            miss.cache_read_input_tokens, 0,
            "旧行为：凭据 B 读凭据 A 的缓存必然 miss"
        );

        // 凭据 B 写入自己的桶
        tracker.update("cred:B", Some(&profile));

        // 再切回凭据 A：又 miss（凭据 A 的缓存虽在但凭据 B 的 update 不影响凭据 A 桶的 TTL）
        // 实际上凭据 A 桶仍有缓存（还没过期），所以这里会命中——
        // 但关键是凭据 B 的那次请求是 miss 的，整体命中率 = 50%（交替 miss/hit）
        let hit_again = tracker.compute("cred:A", Some(&profile));
        assert!(
            hit_again.cache_read_input_tokens > 0,
            "凭据 A 桶缓存未过期仍在"
        );

        // 核心论证：10 次轮转中，旧行为前两次 (A→B) 必 miss 一次，
        // 之后如果两个桶都建立了则都能命中——但首次切换时的 miss 是 #48 要修的。
        // 新行为：conv: 桶从第 2 次起永远命中，零 miss。
    }

    /// 桶数超过 MAX_CACHE_ACCOUNTS 时触发批量 LRW 驱逐，桶数砍到 CACHE_PRUNE_TARGET 水位。
    ///
    /// 验证：
    /// 1. 驱逐后桶数 <= CACHE_PRUNE_TARGET。
    /// 2. 最近写入（last_touched 最新）的桶保留。
    /// 3. 最早写入（last_touched 最旧）的桶被驱逐。
    ///
    /// 实现方式：直接向 entries_by_account 注入带有不同 last_touched 的桶，
    /// 然后调用 maybe_prune_expired 触发驱逐逻辑，不依赖实际 TTL 过期。
    #[test]
    fn test_cache_bucket_lru_eviction() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req, 3000).unwrap();

        // 构造超过上限的桶数：注入 MAX_CACHE_ACCOUNTS + 10 个桶。
        // 前 10 个桶 last_touched 最旧（应被驱逐），后续桶 last_touched 更新（应保留）。
        let overflow_count = MAX_CACHE_ACCOUNTS + 10;
        {
            let mut map = tracker.entries_by_account.lock().unwrap();
            let base = Instant::now();
            for i in 0..overflow_count {
                // 越早的 key（i 越小）last_touched 越旧，越应被驱逐。
                let last_touched = base + Duration::from_secs(i as u64);
                let mut bucket = AccountBucket::new(last_touched);
                // 插入一条未过期指纹，让桶不会因 TTL 清理而被删除。
                for bp in &profile.breakpoints {
                    bucket.entries.insert(
                        bp.fingerprint,
                        PromptCacheEntry {
                            expires_at: last_touched + Duration::from_secs(3600),
                        },
                    );
                }
                map.insert(format!("conv:evict-test-{}", i), bucket);
            }
        }

        // 触发 prune：由于节流间隔，这里手动调用底层函数。
        {
            let mut map = tracker.entries_by_account.lock().unwrap();
            let now = Instant::now();
            // 直接调用 maybe_prune_expired（跳过节流，因为 last_prune_at 为 None）。
            maybe_prune_expired(&mut map, &tracker.last_prune_at, now);
        }

        let map = tracker.entries_by_account.lock().unwrap();
        let final_count = map.len();

        // 驱逐后桶数应 <= CACHE_PRUNE_TARGET（8_000）。
        assert!(
            final_count <= CACHE_PRUNE_TARGET,
            "驱逐后桶数应 <= CACHE_PRUNE_TARGET({})，实际={}",
            CACHE_PRUNE_TARGET,
            final_count
        );

        // 最旧的桶（conv:evict-test-0 ~ conv:evict-test-9）应被驱逐。
        for i in 0..10 {
            let key = format!("conv:evict-test-{}", i);
            assert!(!map.contains_key(&key), "最旧桶 {} 应被驱逐", key);
        }

        // 最新写入的桶（conv:evict-test-(overflow_count-1)）应保留。
        let newest_key = format!("conv:evict-test-{}", overflow_count - 1);
        assert!(
            map.contains_key(&newest_key),
            "最新桶 {} 应保留",
            newest_key
        );
    }
}
