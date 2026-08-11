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

/// token 守恒律的核心载体（#85）。
///
/// 根因：`cc`/`cr`（cache_creation/cache_read）与 `input_tokens` 曾用不同的尺子
/// 度量——`cc`/`cr` 出自本地 `PromptCacheTracker::compute()`（章程见
/// `flatten_cache_blocks` + `count_text` 的本地估算），`input_tokens` 出自上游
/// 真实值或另一把估算尺（`contextUsagePercentage × context_window`）。两者相减
/// （`uncached_input_tokens`）没有守恒保证，因为被减数和减数根本不在同一刻度上。
///
/// 本类型把"这份 usage 是哪把尺子量出来的"显式带在类型里，强制调用方在真正拼
/// 响应 JSON 之前，把本地尺度换算成与 `input_tokens` 同源的真实尺度
/// （[`into_real`](Self::into_real)）。这条构造保证只覆盖 `Local` 变体——
/// `Real` 变体是"信任上游原值"的显式取舍（原样透传、不重新缩放，见
/// [`into_real`](Self::into_real) 文档），上游值与 `input_tokens` 可以互不相容，
/// 此时 `cc + cr <= real_total` 不由构造保证，`uncached_input_tokens` 里的
/// `.max(0)` 兜底仍承重。
#[derive(Debug, Clone, Copy)]
pub enum ScaledCacheUsage {
    /// 上游/真实值，直接使用，不做任何重新缩放。
    Real(PromptCacheUsage),
    /// 本地尺子估算值，`local_total` 是产生它的那把尺子量出的分母；
    /// 待真实总量已知后，通过 [`into_real`](Self::into_real) 按比例换算。
    Local {
        usage: PromptCacheUsage,
        local_total: i32,
    },
}

impl ScaledCacheUsage {
    /// 取出内部原始 `PromptCacheUsage` 数值，不携带缩放语义。
    ///
    /// 用于"这份 usage 接下来要被当作新一轮 `decide_prompt_cache` 的 fallback
    /// 候选"这类只关心数值、不关心当前处于哪种尺度的场景——数值本身在两个分支里
    /// 都是有意义的候选值，只是缩放语义不同。
    pub fn raw(self) -> PromptCacheUsage {
        match self {
            ScaledCacheUsage::Real(usage) => usage,
            ScaledCacheUsage::Local { usage, .. } => usage,
        }
    }

    /// 换算成与 `real_total`（如 `context_input_tokens`/上游真实值）同源尺度的
    /// `PromptCacheUsage`，保证 `cache_creation + cache_read <= real_total`。
    ///
    /// `Real` 分支直接透传，不重新缩放（上游给的就是真值，缩放反而画蛇添足）。
    /// `Local` 分支按比例换算：
    /// ```text
    /// ratio_cached  = clamp(last_tokens    / local_total, 0.0, 1.0)
    /// ratio_matched = clamp(matched_tokens / local_total, 0.0, ratio_cached)
    /// cr = clamp(round(real_total * ratio_matched), 0, real_total)
    /// cc = clamp(round(real_total * ratio_cached),  cr, real_total) - cr
    /// ```
    /// 除法在转 `f64` 之后才进行（唯一的实现级硬约束——i32 整除在
    /// `last_tokens < local_total` 时恒为 0，会把 cc/cr 全部清零，直接废掉整个重构）。
    ///
    /// `local_total <= 0` 时直接返回 `default()`，不进入换算（防止除零）；
    /// `real_total <= 0` 无需特殊 guard，公式本身退化为 cr=0/cc=0。
    pub fn into_real(self, real_total: i32) -> PromptCacheUsage {
        let (usage, local_total) = match self {
            ScaledCacheUsage::Real(usage) => return usage,
            ScaledCacheUsage::Local { usage, local_total } => (usage, local_total),
        };
        if local_total <= 0 {
            return PromptCacheUsage::default();
        }
        let real_total = real_total.max(0);

        let last_tokens = usage.cache_creation_input_tokens + usage.cache_read_input_tokens;
        let matched_tokens = usage.cache_read_input_tokens;

        let ratio_cached = (last_tokens as f64 / local_total as f64).clamp(0.0, 1.0);
        let ratio_matched = (matched_tokens as f64 / local_total as f64).clamp(0.0, ratio_cached);

        let cr = ((real_total as f64 * ratio_matched).round() as i32).clamp(0, real_total);
        let cc = ((real_total as f64 * ratio_cached).round() as i32).clamp(cr, real_total) - cr;

        let (cache_5m, cache_1h) = split_5m_1h_by_local_ratio(
            usage.cache_creation_5m_input_tokens,
            usage.cache_creation_1h_input_tokens,
            cc,
        );

        PromptCacheUsage {
            cache_creation_input_tokens: cc,
            cache_read_input_tokens: cr,
            cache_creation_5m_input_tokens: cache_5m,
            cache_creation_1h_input_tokens: cache_1h,
        }
    }
}

/// 按本地尺度下 5m/1h 的原始比例，把真实尺度的 `real_cc` 拆成 5m/1h 两档。
///
/// `cc` 先整体算出（见 `into_real`），5m/1h 只是在其内部按本地原始占比二次分配，
/// 不独立取整——否则两个方向不同的四舍五入会导致 `cc` 变负或 5m+1h != cc。
/// 余数吸收进 1h（`real_1h = real_cc - real_5m`），保证两者之和恒等于 `real_cc`。
fn split_5m_1h_by_local_ratio(local_5m: i32, local_1h: i32, real_cc: i32) -> (i32, i32) {
    if real_cc <= 0 {
        return (0, 0);
    }
    let local_total = local_5m + local_1h;
    if local_total <= 0 {
        // 本地没有可参考的 5m/1h 占比（理论上不该发生：cc 由 compute_ttl_breakdown
        // 产生的 5m/1h 之和推得），保守把全部余量记进 1h。
        return (0, real_cc);
    }
    let ratio_5m = local_5m as f64 / local_total as f64;
    let real_5m = ((real_cc as f64) * ratio_5m).round() as i32;
    let real_5m = real_5m.clamp(0, real_cc);
    let real_1h = real_cc - real_5m;
    (real_5m, real_1h)
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
    /// 本地尺子（`flatten_cache_blocks` + `count_text`）估算的输入 token 总量。
    ///
    /// 命名刻意避开 `total_input_tokens`——防后人把它误当上游真实值使用。它只是
    /// [`ScaledCacheUsage::Local`] 做比例换算时的分母，本身不是任何"真值"（#85）。
    local_total_tokens: i32,
    /// 仅用于排障时的 Debug 输出，无读取方；保留字段以免丢失诊断信息。
    #[allow(dead_code)]
    model: String,
}

impl PromptCacheProfile {
    /// 本地尺子估算的输入 token 总量，供 [`ScaledCacheUsage`] 换算时取用。
    pub fn local_total_tokens(&self) -> i32 {
        self.local_total_tokens
    }
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
    pub fallback_usage: ScaledCacheUsage,
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
    pub fn build_profile(&self, req: &MessagesRequest) -> Option<PromptCacheProfile> {
        Self::build_profile_from_blocks(req.model.clone(), flatten_cache_blocks(req))
    }

    /// 从已扁平化的 cache block 构造 profile。
    ///
    /// 保持独立入口使 token 累加不变量可直接被最小内部夹具验证，无需构造巨大 payload。
    fn build_profile_from_blocks(
        model: String,
        blocks: Vec<CacheBlock>,
    ) -> Option<PromptCacheProfile> {
        if blocks.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        let mut breakpoints = Vec::new();
        let mut cumulative_tokens: i32 = 0;
        let mut active_ttl = None;

        for block in blocks {
            write_hash_chunk(&mut hasher, block.canonical.as_bytes());
            cumulative_tokens = cumulative_tokens.saturating_add(block.tokens);

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
            // 分母必须是本循环累加器的终值——不是 `breakpoints.last().cumulative_tokens`
            // （那个等式只在"最后一个 block 恰好被判为断点"时成立，是前提不是通则，#85）。
            local_total_tokens: cumulative_tokens.max(1),
            model,
        })
    }

    pub fn compute(
        &self,
        account_key: &str,
        profile: Option<&PromptCacheProfile>,
        min_cacheable_tokens: i32,
    ) -> PromptCacheUsage {
        let Some(profile) = profile else {
            return PromptCacheUsage::default();
        };
        if account_key.is_empty() || profile.breakpoints.is_empty() {
            return PromptCacheUsage::default();
        }

        let min_tokens = min_cacheable_tokens;
        let last_tokens = profile
            .breakpoints
            .last()
            .map(|b| b.cumulative_tokens.min(profile.local_total_tokens))
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
                .min(profile.local_total_tokens)
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

    pub fn update(
        &self,
        account_key: &str,
        profile: Option<&PromptCacheProfile>,
        min_cacheable_tokens: i32,
    ) {
        let Some(profile) = profile else {
            return;
        };
        if account_key.is_empty() || profile.breakpoints.is_empty() {
            return;
        }

        let min_tokens = min_cacheable_tokens;
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

/// `local_total_tokens`：产生 `fallback_usage` 那把本地尺子的分母（通常取自
/// `PromptCacheProfile::local_total_tokens()`），随 `has_profile` 同源——两者都
/// 派生自同一个 `profile: Option<&PromptCacheProfile>`，调用方需保持二者一致。
/// `upstream_usage` 恒被判定为真实尺度（`ScaledCacheUsage::Real`），不做任何
/// 重新缩放——它本就来自上游 meteringEvent，缩放反而会引入误差。
pub fn decide_prompt_cache(
    mode: PromptCacheMode,
    upstream_usage: Option<PromptCacheUsage>,
    fallback_usage: PromptCacheUsage,
    has_profile: bool,
    local_total_tokens: Option<i32>,
) -> PromptCacheDecision {
    let scaled_fallback = |usage: PromptCacheUsage| -> ScaledCacheUsage {
        match local_total_tokens {
            Some(local_total) => ScaledCacheUsage::Local { usage, local_total },
            // 无 profile 时 fallback_usage 恒为 default()（全零），Real/Local 数值等价，
            // 直接透传即可，不需要一个不存在的分母。
            None => ScaledCacheUsage::Real(usage),
        }
    };
    match mode {
        PromptCacheMode::Off => PromptCacheDecision {
            fallback_usage: ScaledCacheUsage::Real(PromptCacheUsage::default()),
            include_cache_fields: false,
        },
        PromptCacheMode::Passthrough => PromptCacheDecision {
            fallback_usage: ScaledCacheUsage::Real(upstream_usage.unwrap_or_default()),
            include_cache_fields: upstream_usage.is_some(),
        },
        PromptCacheMode::Emulated => PromptCacheDecision {
            fallback_usage: scaled_fallback(fallback_usage),
            include_cache_fields: has_profile,
        },
        PromptCacheMode::Auto => {
            if let Some(usage) = upstream_usage {
                PromptCacheDecision {
                    fallback_usage: ScaledCacheUsage::Real(usage),
                    include_cache_fields: true,
                }
            } else {
                PromptCacheDecision {
                    fallback_usage: scaled_fallback(fallback_usage),
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
    usage: ScaledCacheUsage,
    include_cache_fields: bool,
) -> Value {
    // 拼 JSON 前的最后一道换算：把任意尺度的 usage 换算成与 input_tokens 同源的
    // 真实尺度，`cc + cr <= input_tokens` 从此由构造保证（#85 守恒律核心落点）。
    let usage = usage.into_real(input_tokens);
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
    // Identity and ruler deliberately diverge only for recognized media blocks:
    // canonical remains the complete request payload for hashing, while the ruler view
    // replaces media bytes with null and restores their fixed estimate separately.
    let canonical_value = strip_position_keys(value);
    let canonical = canonical_json(&canonical_value);
    let tokens = canonical_value
        .get("block")
        .and_then(crate::token::content_block_token_view)
        .map(|(ruler_block, fixed_estimate)| {
            let mut ruler_value = canonical_value.clone();
            *ruler_value
                .get_mut("block")
                .expect("cache wrapper block exists after billing-header filter") = ruler_block;
            let fixed_estimate = fixed_estimate.min(i32::MAX as u64) as i32;
            crate::token::count_text(&canonical_json(&ruler_value)).saturating_add(fixed_estimate)
        })
        .unwrap_or_else(|| crate::token::count_text(&canonical));
    blocks.push(CacheBlock {
        tokens,
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
        let current = breakpoint.cumulative_tokens.min(profile.local_total_tokens);
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

    const TEST_MIN_CACHEABLE: i32 = 1024;

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
        let profile = tracker.build_profile(&req).unwrap();
        let first = tracker.compute("account", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(first.cache_creation_input_tokens > 0);
        assert_eq!(first.cache_read_input_tokens, 0);
        tracker.update("account", Some(&profile), TEST_MIN_CACHEABLE);
        let second = tracker.compute("account", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();
        let fingerprint = profile.breakpoints.last().unwrap().fingerprint;

        tracker.update("account", Some(&profile), TEST_MIN_CACHEABLE);
        let before = {
            let entries_by_account = tracker.entries_by_account.lock().unwrap();
            entries_by_account
                .get("account")
                .and_then(|bucket| bucket.entries.get(&fingerprint))
                .map(|entry| entry.expires_at)
                .unwrap()
        };

        let usage = tracker.compute("account", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

        // 模拟凭据 A 写入缓存，account_key 是会话维度的 "conv:S"。
        tracker.update("conv:S", Some(&profile), TEST_MIN_CACHEABLE);

        // 模拟 fallback 到凭据 B，但 account_key 仍是同一会话 "conv:S" ——应命中。
        let hit = tracker.compute("conv:S", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(
            hit.cache_read_input_tokens > 0,
            "同会话 key 换凭据后应仍命中，cache_read={}",
            hit.cache_read_input_tokens
        );

        // 对比：若 key 按凭据分桶（旧行为），凭据 A 写的缓存，凭据 B 读时 key 不同 → miss。
        let miss = tracker.compute("cred:B", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

        // S1 写入缓存。
        tracker.update("conv:S1", Some(&profile), TEST_MIN_CACHEABLE);

        // S1 自读应命中。
        let s1_hit = tracker.compute("conv:S1", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(s1_hit.cache_read_input_tokens > 0, "S1 自读应命中");

        // S2 读 S1 写入的缓存：不同 key，应 miss。
        let s2_miss = tracker.compute("conv:S2", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

        // 凭据 1 兜底桶写入后自读应命中。
        tracker.update("cred:1", Some(&profile), TEST_MIN_CACHEABLE);
        let hit = tracker.compute("cred:1", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(
            hit.cache_read_input_tokens > 0,
            "兜底 cred 桶自读应命中，cache_read={}",
            hit.cache_read_input_tokens
        );

        // 换到凭据 2 兜底桶：无会话 ID 时无法跨凭据共享，miss 属已知折中（等同旧行为）。
        let miss = tracker.compute("cred:2", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

        // 模拟凭据 A/B 列表（实际 handler 只用 session_id 做 key，credential_id 不参与）
        let credentials = ["cred-A", "cred-B"];
        let session_id = "conv:stable-session-uuid";

        // 第 1 次请求：凭据 A，首次建缓存
        // handler: account_key = format!("conv:{}", session_id) — credential_id 不参与
        let usage = tracker.compute(session_id, Some(&profile), TEST_MIN_CACHEABLE);
        assert_eq!(
            usage.cache_read_input_tokens, 0,
            "首次请求应 miss（尚无缓存）"
        );
        assert!(
            usage.cache_creation_input_tokens > 0,
            "首次请求应报 creation"
        );
        // 上游成功后 update
        tracker.update(session_id, Some(&profile), TEST_MIN_CACHEABLE);

        // 第 2~10 次请求：凭据在 A/B 间交替轮转，模拟 balanced round-robin
        for i in 2..=10 {
            let _credential = credentials[i % 2]; // 凭据轮转，但 handler 不用它构造 key

            let usage = tracker.compute(session_id, Some(&profile), TEST_MIN_CACHEABLE);
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
            tracker.update(session_id, Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

        // 模拟旧行为：account_key = format!("cred:{}", credential_id)
        // 凭据 A 写入
        tracker.update("cred:A", Some(&profile), TEST_MIN_CACHEABLE);

        // 凭据 A 自读：命中
        let hit = tracker.compute("cred:A", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(hit.cache_read_input_tokens > 0, "凭据 A 自读应命中");

        // balanced 切到凭据 B：miss（旧行为的 bug）
        let miss = tracker.compute("cred:B", Some(&profile), TEST_MIN_CACHEABLE);
        assert_eq!(
            miss.cache_read_input_tokens, 0,
            "旧行为：凭据 B 读凭据 A 的缓存必然 miss"
        );

        // 凭据 B 写入自己的桶
        tracker.update("cred:B", Some(&profile), TEST_MIN_CACHEABLE);

        // 再切回凭据 A：又 miss（凭据 A 的缓存虽在但凭据 B 的 update 不影响凭据 A 桶的 TTL）
        // 实际上凭据 A 桶仍有缓存（还没过期），所以这里会命中——
        // 但关键是凭据 B 的那次请求是 miss 的，整体命中率 = 50%（交替 miss/hit）
        let hit_again = tracker.compute("cred:A", Some(&profile), TEST_MIN_CACHEABLE);
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
        let profile = tracker.build_profile(&req).unwrap();

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

    // ---- #85 token 守恒律：ScaledCacheUsage::into_real 系列测试 ----

    /// 守恒律核心断言：任意 `Local` 输入，换算后 `uncached + cc + cr == real_total`
    /// 恒成立（不只是 `<=`）。
    ///
    /// `<=` 在 `uncached_input_tokens` 的 `.max(0)` 兜底触发时同样成立——对"守恒律
    /// 是构造性成立还是被兜底掩盖"零覆盖，故补三条更强断言（#85 B2）：
    /// 1. 守恒等式 `uncached + cc + cr == real_total`；
    /// 2. `uncached` 精确等于裸减法 `real_total - cc - cr`，不是被 `.max(0)` 钳出的值；
    /// 3. ratio 被 clamp 到 1.0 的饱和场景精确打满 `real_total`（不能只满足 `<=`）。
    ///
    /// 用固定种子的一组边界/常规值代替 proptest（仓库无此依赖，不新增），
    /// 覆盖：cc/cr 均为 0、cc 独大、cr 独大、cc=cr、local_total 远大于 real_total、
    /// local_total 远小于 real_total（即 last_tokens > local_total 的越界输入，
    /// 恰好是 ratio 饱和场景）。
    ///
    /// 反事实验证（两条断言各自独立验证，均已复原正确实现）：
    /// - 断言 1/2：临时打断 `uncached_input_tokens`（去掉 `cache_read_input_tokens`
    ///   的减项），重跑得到 `left: 5000 right: 0`（case cc=0 cr=3000 local_total=3000
    ///   real_total=5000）——证明"精确等于裸减法"确实在测东西，不是摆设。
    ///   注：起初按"打断 `into_real` 内部独立取整公式"的思路试过，但经严格证明
    ///   （取整单调性 + `ratio_matched<=ratio_cached` 的结构不变量）在非负输入下
    ///   该改法数学上不可能产生负 `cc` 或破坏 `<=`，实测也确实是 `ok` 不是
    ///   `FAILED`；换成打断 `uncached_input_tokens` 本身才是真正命中新增断言
    ///   覆盖面的改法（新断言验证的正是 `into_real` 输出与 `uncached_input_tokens`
    ///   的集成关系，旧测试只单独查 `PromptCacheUsage` 字段、从未调用过
    ///   `uncached_input_tokens`）。
    /// - 断言 3：临时在饱和场景注入丢 1 个 token 的"差一"回归（`cr -= 1`，仅当
    ///   `ratio_cached>=1.0 && cc+cr==real_total`），重跑得到 `left: 4999
    ///   right: 5000`——证明饱和场景的 `==` 确实比旧测试的 `<=` 更能抓问题
    ///   （`<=` 对 4999<=5000 会照样放行）。
    #[test]
    fn into_real_conserves_cc_plus_cr_uncached_identity() {
        // 本数组仅接受 real_total >= 0：下方 `uncached == raw_subtraction`（裸减法）
        // 断言隐含前提是 `uncached_input_tokens` 不对 real_total 做 `.max(0)` 预处理，
        // 而 `into_real` 内部对 real_total<=0 会退化清零（见
        // into_real_real_total_non_positive_degrades_to_zero_without_panic）。若把
        // 负 real_total 顺手搬进这个数组，断言会以一个与「.max(0) 钳位」这个前提
        // 完全无关、信息量为零的报错炸掉；负 real_total 场景已由上述另一测试专门覆盖。
        let cases = [
            // (cache_creation, cache_read, local_total, real_total)
            (0, 0, 3000, 5000),
            (3000, 0, 3000, 5000),
            (0, 3000, 3000, 5000),
            (1500, 1500, 3000, 5000),
            (100, 50, 200_000, 5000),
            (100_000, 50_000, 10_000, 5000), // 越界输入：last_tokens > local_total，ratio 饱和 clamp 到 1.0
            (1, 1, 3000, 1),                 // real_total 极小
            (3000, 0, 3000, 0),              // real_total 为 0
        ];
        for (cc, cr, local_total, real_total) in cases {
            let scaled = ScaledCacheUsage::Local {
                usage: PromptCacheUsage {
                    cache_creation_input_tokens: cc,
                    cache_read_input_tokens: cr,
                    cache_creation_5m_input_tokens: cc,
                    cache_creation_1h_input_tokens: 0,
                },
                local_total,
            };
            let real = scaled.into_real(real_total);
            assert!(
                real.cache_creation_input_tokens + real.cache_read_input_tokens <= real_total,
                "守恒律违反：cc={} cr={} real_total={}（输入 cc={} cr={} local_total={}）",
                real.cache_creation_input_tokens,
                real.cache_read_input_tokens,
                real_total,
                cc,
                cr,
                local_total
            );
            assert!(real.cache_creation_input_tokens >= 0);
            assert!(real.cache_read_input_tokens >= 0);
            assert_eq!(
                real.cache_creation_5m_input_tokens + real.cache_creation_1h_input_tokens,
                real.cache_creation_input_tokens,
                "5m/1h 拆分之和必须恒等于 cc（输入 cc={} cr={} local_total={}）",
                cc,
                cr,
                local_total
            );

            // #85 B2 断言 1+2：守恒等式必须是构造性恒等，而非被 `.max(0)` 钳出的假象。
            let uncached = uncached_input_tokens(real_total, real);
            let raw_subtraction =
                real_total - real.cache_creation_input_tokens - real.cache_read_input_tokens;
            assert_eq!(
                uncached, raw_subtraction,
                "uncached_input_tokens 的返回值应精确等于裸减法 real_total-cc-cr，\
                 不应被 `.max(0)` 钳到 0（输入 cc={} cr={} local_total={} real_total={}）",
                cc, cr, local_total, real_total
            );
            assert_eq!(
                uncached + real.cache_creation_input_tokens + real.cache_read_input_tokens,
                real_total,
                "守恒等式 uncached+cc+cr 必须恒等于 real_total（输入 cc={} cr={} local_total={} real_total={}）",
                cc,
                cr,
                local_total,
                real_total
            );

            // #85 B2 断言 3：ratio 饱和(clamp 到 1.0)场景须精确打满 real_total。
            // 判据用结构条件而非硬编码某一条 case 的字面值：cc+cr >= local_total
            // 就是 ratio_cached 被 clamp 到 1.0 的定义本身（输入 last_tokens 达到
            // 或超过 local_total 时，比例饱和封顶），此时和恰好 == real_total。
            // 用字面元组单点特判会导致任何人调整 cases 数组里的具体数值都让 `if`
            // 静默不再匹配、断言退化成死代码；结构条件不受具体数值变动影响。
            if cc + cr >= local_total {
                assert_eq!(
                    real.cache_creation_input_tokens + real.cache_read_input_tokens,
                    real_total,
                    "ratio 饱和场景应精确打满 real_total，不能只满足 <="
                );
            }
        }
    }

    /// 回归守卫：除法必须先转 f64 再做，否则 last_tokens < local_total 时
    /// i32 整除截断为 0，会把 cc/cr 错误地清零（PR-2 四条实现级铁律之一）。
    ///
    /// 构造 ratio=0.4（4000/10000）但整数除法会截断为 0 的输入，
    /// 换算到 real_total=100 后期望 cc+cr ≈ 40，若退化为整数除法则会得到 0。
    #[test]
    fn into_real_uses_float_division_not_truncating_integer_division() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 4000,
                cache_read_input_tokens: 0,
                cache_creation_5m_input_tokens: 4000,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 10_000,
        };
        let real = scaled.into_real(100);
        assert!(
            real.cache_creation_input_tokens > 0,
            "若误用 i32 整除，4000/10000 会截断为 0 导致 cc=0；实际 cc={}",
            real.cache_creation_input_tokens
        );
        assert_eq!(real.cache_creation_input_tokens, 40);
    }

    /// `local_total <= 0` 必须短路返回 `default()`，不能进入除法（防除零 panic）。
    #[test]
    fn into_real_local_total_non_positive_short_circuits_to_default() {
        for local_total in [0, -1, -100] {
            let scaled = ScaledCacheUsage::Local {
                usage: PromptCacheUsage {
                    cache_creation_input_tokens: 500,
                    cache_read_input_tokens: 200,
                    cache_creation_5m_input_tokens: 500,
                    cache_creation_1h_input_tokens: 0,
                },
                local_total,
            };
            let real = scaled.into_real(5000);
            assert_eq!(
                real,
                PromptCacheUsage::default(),
                "local_total={} 应短路返回 default()",
                local_total
            );
        }
    }

    /// `real_total <= 0` 无需特殊 guard，公式自然退化为 cc=0/cr=0，不 panic。
    #[test]
    fn into_real_real_total_non_positive_degrades_to_zero_without_panic() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 500,
                cache_read_input_tokens: 200,
                cache_creation_5m_input_tokens: 500,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 3000,
        };
        for real_total in [0, -1, -100] {
            let real = scaled.into_real(real_total);
            assert_eq!(real.cache_creation_input_tokens, 0);
            assert_eq!(real.cache_read_input_tokens, 0);
        }
    }

    /// `Real` 分支直接透传，不做任何重新缩放——上游给的就是真值。
    #[test]
    fn into_real_real_variant_passes_through_unchanged() {
        let usage = PromptCacheUsage {
            cache_creation_input_tokens: 111,
            cache_read_input_tokens: 222,
            cache_creation_5m_input_tokens: 111,
            cache_creation_1h_input_tokens: 0,
        };
        let scaled = ScaledCacheUsage::Real(usage);
        assert_eq!(scaled.into_real(999_999), usage);
        assert_eq!(scaled.into_real(0), usage);
    }

    /// 当 `real_total == local_total`（message_start/websearch 场景：real_total 本身
    /// 也只是另一把本地估算尺，恰好与 profile 的 local_total 相等）时，换算应退化为
    /// 恒等缩放——换算后的 cc/cr 应与原始本地值完全一致。
    ///
    /// 这条测试是"同一套公式可无差别套用到全部 7 个调用点"这一设计假设的代数证明。
    #[test]
    fn into_real_degenerates_to_identity_when_real_equals_local_total() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 700,
                cache_read_input_tokens: 300,
                cache_creation_5m_input_tokens: 700,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 3000,
        };
        let real = scaled.into_real(3000);
        assert_eq!(real.cache_creation_input_tokens, 700);
        assert_eq!(real.cache_read_input_tokens, 300);
    }

    /// `raw()` 无视缩放语义，原样取出内部数值——供"转手当下一轮 fallback 候选"场景使用。
    #[test]
    fn raw_extracts_underlying_usage_regardless_of_variant() {
        let usage = PromptCacheUsage {
            cache_creation_input_tokens: 5,
            cache_read_input_tokens: 6,
            cache_creation_5m_input_tokens: 5,
            cache_creation_1h_input_tokens: 0,
        };
        assert_eq!(ScaledCacheUsage::Real(usage).raw(), usage);
        assert_eq!(
            ScaledCacheUsage::Local {
                usage,
                local_total: 100
            }
            .raw(),
            usage
        );
    }

    /// `build_usage_value` 端到端：input_tokens 字段必须满足
    /// `input_tokens_reported + cc + cr == real_total`（守恒律在最终 JSON 输出层的体现），
    /// 而不是像修复前那样在不同尺度间相减产生漂移。
    ///
    /// 夹具刻意选 `cc(4000)+cr(1500)=5500 != real_total(5000)`——若选成两者恰好
    /// 相等（如曾经的 4000+1000=5000），跳过 `into_real` 直接用 `raw()` 相减也会
    /// 巧合地凑出同一个 5000，测试就测不出"到底走没走 into_real"（反事实验证
    /// 时曾在此撞过一次假阴性）。
    #[test]
    fn build_usage_value_reports_conserve_against_real_total() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 4000,
                cache_read_input_tokens: 1500,
                cache_creation_5m_input_tokens: 4000,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 10_000,
        };
        let real_total = 5000;
        let value = build_usage_value(real_total, 20, scaled, true);
        let reported_input = value["input_tokens"].as_i64().unwrap() as i32;
        let cc = value["cache_creation_input_tokens"].as_i64().unwrap() as i32;
        let cr = value["cache_read_input_tokens"].as_i64().unwrap() as i32;
        assert_eq!(
            reported_input + cc + cr,
            real_total,
            "守恒律：input_tokens + cc + cr 必须恒等于 real_total"
        );
    }

    /// §3.5 端到端场景：`build_profile` 产出的本地估算 usage，经 `into_real` 换算到
    /// 一个与本地尺子不同的真实值（real_input_tokens=5000）后，仍必须满足守恒律。
    ///
    /// 记录的是"换算后的绝对值确实发生了变化"这一事实，不是断言旧值必须保持不变
    /// ——旧实现里 cc/cr 直接是本地估算值，新实现里它们被重新缩放到 real_total，
    /// 两者数值上不相等本就是本次修复的预期结果。
    #[test]
    fn computes_cache_creation_then_read_conserves_against_real_input_tokens() {
        let tracker = PromptCacheTracker::default();
        let req = make_cacheable_req("claude-sonnet-4-5");
        let profile = tracker.build_profile(&req).unwrap();
        let local_total = profile.local_total_tokens();

        tracker.update("account-conserve", Some(&profile), TEST_MIN_CACHEABLE);
        let local_usage = tracker.compute("account-conserve", Some(&profile), TEST_MIN_CACHEABLE);
        assert!(
            local_usage.cache_read_input_tokens > 0,
            "第二次读应命中缓存"
        );

        let real_input_tokens = 5000;
        let scaled = ScaledCacheUsage::Local {
            usage: local_usage,
            local_total,
        };
        let real_usage = scaled.into_real(real_input_tokens);

        assert!(
            real_usage.cache_creation_input_tokens + real_usage.cache_read_input_tokens
                <= real_input_tokens,
            "守恒律：换算后 cc+cr 必须 <= real_input_tokens={}，实际 cc={} cr={}",
            real_input_tokens,
            real_usage.cache_creation_input_tokens,
            real_usage.cache_read_input_tokens
        );
        // 记录"确实发生了缩放"这一事实：local_total 与 real_input_tokens 不同源，
        // 换算后的绝对值不应恰好与本地值相等（除非巧合正好等比）。
        assert_ne!(
            (
                real_usage.cache_creation_input_tokens,
                real_usage.cache_read_input_tokens
            ),
            (
                local_usage.cache_creation_input_tokens,
                local_usage.cache_read_input_tokens
            ),
            "local_total={} 与 real_input_tokens={} 不同源，换算前后数值应有变化",
            local_total,
            real_input_tokens
        );
    }

    /// `decide_prompt_cache` 的 `Emulated`/`Auto` 无上游分支必须产出 `Local` 变体
    /// （携带 local_total），`Off`/`Passthrough`/`Auto` 有上游分支必须产出 `Real`
    /// 变体（不重新缩放）——这是 7 个调用点能统一套用 `into_real` 的前提。
    #[test]
    fn decide_prompt_cache_tags_scale_variant_correctly_per_branch() {
        let fallback = PromptCacheUsage {
            cache_creation_input_tokens: 10,
            cache_read_input_tokens: 5,
            cache_creation_5m_input_tokens: 10,
            cache_creation_1h_input_tokens: 0,
        };
        let upstream = PromptCacheUsage {
            cache_creation_input_tokens: 20,
            cache_read_input_tokens: 15,
            cache_creation_5m_input_tokens: 20,
            cache_creation_1h_input_tokens: 0,
        };

        let off = decide_prompt_cache(PromptCacheMode::Off, None, fallback, true, Some(3000));
        assert!(matches!(off.fallback_usage, ScaledCacheUsage::Real(_)));

        let passthrough = decide_prompt_cache(
            PromptCacheMode::Passthrough,
            Some(upstream),
            fallback,
            true,
            Some(3000),
        );
        assert!(matches!(
            passthrough.fallback_usage,
            ScaledCacheUsage::Real(u) if u == upstream
        ));

        let emulated =
            decide_prompt_cache(PromptCacheMode::Emulated, None, fallback, true, Some(3000));
        assert!(matches!(
            emulated.fallback_usage,
            ScaledCacheUsage::Local { usage, local_total: 3000 } if usage == fallback
        ));

        let emulated_no_profile = decide_prompt_cache(
            PromptCacheMode::Emulated,
            None,
            PromptCacheUsage::default(),
            false,
            None,
        );
        assert!(matches!(
            emulated_no_profile.fallback_usage,
            ScaledCacheUsage::Real(u) if u == PromptCacheUsage::default()
        ));

        let auto_with_upstream = decide_prompt_cache(
            PromptCacheMode::Auto,
            Some(upstream),
            fallback,
            true,
            Some(3000),
        );
        assert!(matches!(
            auto_with_upstream.fallback_usage,
            ScaledCacheUsage::Real(u) if u == upstream
        ));

        let auto_without_upstream =
            decide_prompt_cache(PromptCacheMode::Auto, None, fallback, true, Some(3000));
        assert!(matches!(
            auto_without_upstream.fallback_usage,
            ScaledCacheUsage::Local { usage, local_total: 3000 } if usage == fallback
        ));
    }

    // ── #85 §3.5「1.5 段」旧尺基线快照 ────────────────────────────────────
    //
    // 下列 OLD_RULER_* 常量是旧字符启发式尺子（`prompt_cache.rs::estimate_tokens`
    // = `((chars+3)/4).max(1)`，已在本 PR 删除）在删除前对同一批样本文本的最后
    // 一次实测输出，仅作历史对照，**不是任何期望值**——新尺子(tiktoken)不必给出
    // 相同数字，方向也不统一（代码样本上新尺反而更省，中英混合/纯中文样本上新
    // 尺更贵）。目的只是让"换尺子改变了多少"留下可核对的证据，不是静默无痕迹地
    // 漂移（§3.5 要求断言"变化被记录"，不是"必须不变"）。
    const OLD_RULER_INPUT_MIXED: i32 = 70;
    const OLD_RULER_INPUT_CODE: i32 = 138;
    /// cn_sample_text(20)：旧尺下明确低于默认档 1024。
    const OLD_RULER_INPUT_CN_1024_TIER: i32 = 340;
    /// cn_sample_text(100)：旧尺下已过默认档 1024、仍明确低于 Opus 档 4096——
    /// 专门孤立出"新尺让 Opus 档也越过"这一新增行为分野，不与默认档穿越混同。
    const OLD_RULER_INPUT_CN_4096_TIER: i32 = 1700;

    fn mixed_sample_text() -> String {
        "Rust ownership 是 Rust 语言最独特的特性之一。The borrow checker enforces memory safety at compile time without a garbage collector. 每个值都有一个所有者（owner），当所有者离开作用域时，值会被自动释放。This design eliminates entire classes of bugs such as use-after-free and double-free errors that plague C and C++ programs.".to_string()
    }

    fn code_sample_text() -> String {
        r#"
pub fn build_profile(&self, req: &MessagesRequest) -> Option<PromptCacheProfile> {
    let blocks = flatten_cache_blocks(req);
    if blocks.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut breakpoints = Vec::new();
    let mut cumulative_tokens = 0;
    for block in blocks {
        write_hash_chunk(&mut hasher, block.canonical.as_bytes());
        cumulative_tokens += block.tokens;
    }
    Some(PromptCacheProfile { breakpoints, local_total_tokens: cumulative_tokens.max(1), model: req.model.clone() })
}
"#
        .to_string()
    }

    fn cn_sample_text(reps: usize) -> String {
        "所有权系统是 Rust 语言在编译期保证内存安全的核心机制，它通过借用检查器在没有垃圾回收器的情况下追踪每一个值的生命周期与作用域边界。".repeat(reps)
    }

    /// [`make_cacheable_req`] 的泛化版：system 文本可自定义，供旧尺基线测试
    /// 注入不同样本文本，复用同一条 build_profile 生产路径。
    fn req_with_system_text(model: &str, text: String) -> MessagesRequest {
        MessagesRequest {
            model: model.to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: Value::String(long_text()),
            }],
            stream: false,
            system: Some(vec![SystemMessage {
                text,
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

    /// 换尺子后，`count_text`（新尺）对同一批样本文本的输出应与旧尺历史实测值
    /// 不同——记录变化，不断言"必须不变"（§3.5 要求）。反事实验证：把
    /// `count_text` 换回旧公式跑同一份样本文本，三个 assert_ne! 会全部撞上
    /// 相同的历史常量而 panic（本测试与常量取自同一份原始文本，非经
    /// canonical_json 包装，比较是精确同源的）。
    #[test]
    fn baseline_ruler_shift_recorded_for_sample_texts() {
        assert_ne!(
            crate::token::count_text(&mixed_sample_text()),
            OLD_RULER_INPUT_MIXED,
            "中英混合样本换尺后数值未变化，ruler shift 未被记录"
        );
        assert_ne!(
            crate::token::count_text(&code_sample_text()),
            OLD_RULER_INPUT_CODE,
            "纯代码样本换尺后数值未变化，ruler shift 未被记录"
        );
        assert_ne!(
            crate::token::count_text(&cn_sample_text(20)),
            OLD_RULER_INPUT_CN_1024_TIER,
            "纯中文样本换尺后数值未变化，ruler shift 未被记录"
        );
    }

    /// input 面 `min_cacheable_tokens` 门槛穿越：同一份纯中文样本，旧尺
    /// (char/4) 下不足默认档 1024 / Opus 族 4096 门槛，新尺(tiktoken)下越过——
    /// 这不是数字游戏，`compute()` 会因此把 `cache_creation_input_tokens` 从 0
    /// 变成正数（是否开始缓存这个内容块的实际行为分野）。两档都验证，Opus
    /// 4096 档不能漏（生产主力模型是 opus-5）。
    #[test]
    fn baseline_input_min_cacheable_threshold_crossing_recorded() {
        let tracker = PromptCacheTracker::default();

        // 默认档 1024。
        assert!(
            OLD_RULER_INPUT_CN_1024_TIER < 1024,
            "基线常量本身必须低于默认门槛，否则测不到穿越"
        );
        let req_1024 = req_with_system_text("claude-sonnet-4-5", cn_sample_text(20));
        let profile_1024 = tracker.build_profile(&req_1024).unwrap();
        assert!(
            profile_1024.local_total_tokens() >= 1024,
            "新尺下应越过默认门槛 1024，实际={}",
            profile_1024.local_total_tokens()
        );
        let usage_1024 = tracker.compute("threshold-1024", Some(&profile_1024), 1024);
        assert!(
            usage_1024.cache_creation_input_tokens > 0,
            "越过默认门槛后 compute() 应报正的 cache_creation，实际={}",
            usage_1024.cache_creation_input_tokens
        );

        // Opus 族 4096 档：常量须落在「已过默认档、仍未过 Opus 档」区间，
        // 才能孤立出 Opus 档专属的穿越（而非跟默认档穿越混为一谈）。
        assert!(
            (1024..4096).contains(&OLD_RULER_INPUT_CN_4096_TIER),
            "基线常量必须落在[默认档,Opus档)区间，否则测不到 Opus 档专属穿越"
        );
        let req_4096 = req_with_system_text("claude-opus-5", cn_sample_text(100));
        let profile_4096 = tracker.build_profile(&req_4096).unwrap();
        assert!(
            profile_4096.local_total_tokens() >= 4096,
            "新尺下应越过 Opus 门槛 4096，实际={}",
            profile_4096.local_total_tokens()
        );
        let usage_4096 = tracker.compute("threshold-4096", Some(&profile_4096), 4096);
        assert!(
            usage_4096.cache_creation_input_tokens > 0,
            "越过 Opus 门槛后 compute() 应报正的 cache_creation，实际={}",
            usage_4096.cache_creation_input_tokens
        );
    }

    /// 守恒律必须是"构造性恒等"，不能靠 `uncached_input_tokens` 的 `.max(0)`
    /// 兜底钳出假象——即便在 `into_real` 最激进的边界(local 侧用量远超
    /// local_total，ratio 顶到 1.0 上限)下，`real_total - cc - cr` 本身就已经
    /// 非负，`.max(0)` 全程不生效。用最激进输入直接验证：先独立算裸减法（不
    /// 经过 `.max(0)`），断言它本身非负；再断言 `uncached_input_tokens` 的输出
    /// 与裸减法完全相等——若二者不等，说明守恒律依赖了钳位而非构造性恒等。
    fn req_with_cached_system_and_content(content: Value) -> MessagesRequest {
        MessagesRequest {
            model: "claude-opus-5".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content,
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

    /// #92：单个 block 已被钳到 i32::MAX 后，后续 block 不得令累计值回绕或在 debug
    /// 构建 panic。夹具直达内部 block 路径，避免为测试制造数十 MiB 的媒体 payload。
    #[test]
    fn build_profile_saturates_cumulative_tokens_at_i32_max() {
        let profile = PromptCacheTracker::build_profile_from_blocks(
            "claude-opus-5".to_string(),
            vec![
                CacheBlock {
                    canonical: "first".to_string(),
                    tokens: i32::MAX,
                    ttl: Some(DEFAULT_PROMPT_CACHE_TTL),
                    is_message_end: false,
                },
                CacheBlock {
                    canonical: "second".to_string(),
                    tokens: 1,
                    ttl: None,
                    is_message_end: true,
                },
            ],
        )
        .expect("fixture contains cache breakpoints");

        assert_eq!(profile.local_total_tokens(), i32::MAX);
        assert_eq!(profile.breakpoints.len(), 2);
        assert!(
            profile
                .breakpoints
                .iter()
                .all(|breakpoint| breakpoint.cumulative_tokens == i32::MAX),
            "all post-saturation breakpoints must remain clamped"
        );
    }

    /// #92：plain text 与非 base64 document 不进入媒体 ruler，必须严格沿用
    /// 旧的 canonical `count_text` 结果，避免正常文本被意外替换。
    #[test]
    fn plain_and_non_base64_document_blocks_keep_canonical_text_ruler() {
        for block in [
            json!({"type": "text", "text": "ordinary text must retain its BPE count"}),
            json!({"type": "document", "source": {"type": "text", "data": "ordinary document text"}}),
            json!({"type": "document", "source": {"type": "url", "url": "https://example.test/document.txt"}}),
        ] {
            let value = json!({"kind": "message", "block": block});
            let canonical = canonical_json(&strip_position_keys(value.clone()));
            let mut blocks = Vec::new();
            append_cache_block(&mut blocks, value, None, true);
            assert_eq!(blocks[0].tokens, crate::token::count_text(&canonical));
        }
    }

    /// #92 BDD：多模态媒体的字节长度不得改变本地缓存尺子；但完整 canonical
    /// 仍必须参与指纹，因此 payload 变化必须使 fingerprint 变化。
    #[test]
    fn multimodal_cache_ruler_uses_fixed_media_estimate_without_changing_identity() {
        let short = req_with_cached_system_and_content(json!([{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "AQID"}
        }]));
        let long = req_with_cached_system_and_content(json!([{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(20_000)}
        }]));
        let tracker = PromptCacheTracker::default();
        let short_profile = tracker.build_profile(&short).unwrap();
        let long_profile = tracker.build_profile(&long).unwrap();

        assert_eq!(
            short_profile.local_total_tokens(),
            long_profile.local_total_tokens(),
            "long base64 payload must not inflate the cache ruler"
        );
        assert_ne!(
            short_profile.breakpoints.last().unwrap().fingerprint,
            long_profile.breakpoints.last().unwrap().fingerprint,
            "canonical identity must retain the complete payload"
        );
        let short_blocks = flatten_cache_blocks(&short);
        let long_blocks = flatten_cache_blocks(&long);
        assert!(short_blocks.last().unwrap().canonical.contains("AQID"));
        assert!(
            long_blocks.last().unwrap().canonical.len()
                > short_blocks.last().unwrap().canonical.len()
        );
    }

    /// #92 BDD：相同可缓存前缀之后的长短多模态 suffix 应给出同样的命中比例。
    #[test]
    fn multimodal_suffix_length_does_not_dilute_matched_cache_ratio() {
        let short = req_with_cached_system_and_content(json!([{
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": "AQID"}
        }]));
        let long = req_with_cached_system_and_content(json!([{
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(20_000)}
        }]));
        let prefix = req_with_cached_system_and_content(Value::Null);
        let tracker = PromptCacheTracker::default();
        let prefix_profile = tracker.build_profile(&prefix).unwrap();
        let short_profile = tracker.build_profile(&short).unwrap();
        let long_profile = tracker.build_profile(&long).unwrap();
        assert_eq!(
            short_profile.local_total_tokens(),
            long_profile.local_total_tokens(),
            "base64 documents must use the same fixed ruler regardless of payload length"
        );
        tracker.update("same-prefix", Some(&prefix_profile), TEST_MIN_CACHEABLE);
        let short_usage = tracker.compute("same-prefix", Some(&short_profile), TEST_MIN_CACHEABLE);
        let long_usage = tracker.compute("same-prefix", Some(&long_profile), TEST_MIN_CACHEABLE);

        assert!(
            short_usage.cache_read_input_tokens > 0,
            "short suffix must hit the seeded prefix"
        );
        assert!(
            long_usage.cache_read_input_tokens > 0,
            "long suffix must hit the seeded prefix"
        );
        assert_eq!(
            short_usage.cache_read_input_tokens, long_usage.cache_read_input_tokens,
            "both profiles must hit the same prefix token count"
        );
        assert_eq!(
            i64::from(short_usage.cache_read_input_tokens)
                * i64::from(long_profile.local_total_tokens()),
            i64::from(long_usage.cache_read_input_tokens)
                * i64::from(short_profile.local_total_tokens()),
            "same prefix must keep the matched/local ratio despite suffix payload length"
        );
    }

    /// #92 BDD：固定媒体尺子应跨默认 1024 门槛但不跨 Opus 的 4096 门槛，
    /// 并锁定 min-1/min/min+1 三个 cache gate 边界。
    #[test]
    fn fixed_media_ruler_changes_opus_threshold_snapshot_at_boundaries() {
        let req = req_with_cached_system_and_content(json!([{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(20_000)}
        }]));
        let tracker = PromptCacheTracker::default();
        let profile = tracker.build_profile(&req).unwrap();
        let total = profile.local_total_tokens();

        assert!(
            total >= 1024,
            "fixed ruler must clear the default 1024 tier: total={total}"
        );
        assert!(
            total < 4096,
            "fixed ruler must not falsely clear the Opus 4096 tier: total={total}"
        );
        for (threshold, expected_creation) in [(total - 1, true), (total, true), (total + 1, false)]
        {
            let usage = tracker.compute("threshold-boundary", Some(&profile), threshold);
            assert_eq!(
                usage.cache_creation_input_tokens > 0,
                expected_creation,
                "threshold={threshold}, total={total}"
            );
        }
    }

    #[test]
    fn conservation_holds_without_relying_on_max_zero_floor() {
        let scaled = ScaledCacheUsage::Local {
            usage: PromptCacheUsage {
                cache_creation_input_tokens: 900_000,
                cache_read_input_tokens: 900_000,
                cache_creation_5m_input_tokens: 900_000,
                cache_creation_1h_input_tokens: 0,
            },
            local_total: 10_000, // 本地用量(1_800_000) 远超 local_total，ratio 顶满
        };
        let real_total = 5000;
        let real = scaled.into_real(real_total);

        let raw_subtraction =
            real_total - real.cache_creation_input_tokens - real.cache_read_input_tokens;
        assert!(
            raw_subtraction >= 0,
            "裸减法(未经 .max(0))本身就必须非负，否则守恒律是被 .max(0) 钳出来的假象：\
             raw_subtraction={raw_subtraction} cc={} cr={}",
            real.cache_creation_input_tokens,
            real.cache_read_input_tokens
        );

        let reported = uncached_input_tokens(real_total, real);
        assert_eq!(
            reported, raw_subtraction,
            ".max(0) 不该改变结果；若二者不等，说明守恒律依赖了钳位而非构造性恒等"
        );
    }
}
