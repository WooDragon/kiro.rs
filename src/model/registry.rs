use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ModelDefaults {
    #[serde(default = "default_context_window")]
    pub context_window: i32,
    #[serde(default = "default_min_cacheable_tokens")]
    pub min_cacheable_tokens: i32,
    /// models.toml `[defaults]` 段的兜底值，经 `default_max_tokens` 反序列化；
    /// 当前各模型条目都显式配了 max_tokens，故此默认值无读取方。
    #[allow(dead_code)]
    #[serde(default = "default_max_tokens")]
    pub max_tokens: i32,
}

impl Default for ModelDefaults {
    fn default() -> Self {
        Self {
            context_window: default_context_window(),
            min_cacheable_tokens: default_min_cacheable_tokens(),
            max_tokens: default_max_tokens(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    pub kiro_id: String,
    /// models.toml 里的模型族标注（如 "opus"/"sonnet"），当前仅作配置可读性说明；
    /// 实际族匹配走 `match_family` 子串判断，故此字段无读取方。
    #[allow(dead_code)]
    pub family: String,
    pub display_name: String,
    pub match_family: String,
    #[serde(default)]
    pub match_version: Vec<String>,
    #[serde(default = "default_context_window")]
    pub context_window: i32,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: i32,
    #[serde(default)]
    pub created: i64,
    #[serde(default = "default_tier")]
    pub tier: String,
    pub min_cacheable_tokens: Option<i32>,
    pub thinking_type: Option<String>,
    #[serde(default = "default_thinking_budget")]
    pub thinking_budget_tokens: i32,
    pub thinking_effort: Option<String>,
    #[serde(default = "default_true")]
    pub expose_thinking_variant: bool,
    /// crate 私有（`#98` 返工 SUGGESTION C2）：`credit_weight_by_kiro_id` 的
    /// `.filter(|w| w.is_finite() && *w > 0.0)` 是该字段唯一的 sanitize
    /// 收口点。字段若 `pub`，仓内任何地方都能绕过收口点直接读到未净化的
    /// `inf`/`nan`/`0.0`/负数；降级为 crate 私有，让"必须过收口点"由
    /// 类型系统强制而非靠纪律。
    #[serde(default = "default_credit_weight")]
    pub(crate) credit_weight: f64,
}

pub struct ThinkingOverride {
    pub thinking_type: String,
    pub budget_tokens: i32,
    pub effort: Option<String>,
}

pub struct AvailableModel {
    pub id: String,
    pub display_name: String,
    pub created: i64,
    pub max_tokens: i32,
}

#[derive(Debug, Deserialize)]
struct ModelsConfig {
    #[serde(default)]
    defaults: ModelDefaults,
    models: Vec<ModelEntry>,
}

pub struct ModelRegistry {
    entries: Vec<ModelEntry>,
    defaults: ModelDefaults,
}

impl ModelRegistry {
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let config: ModelsConfig = toml::from_str(toml_str)
            .map_err(|e| format!("Failed to parse models config: {}", e))?;
        Ok(Self::from_entries(config.models, config.defaults))
    }

    pub fn from_entries(mut entries: Vec<ModelEntry>, defaults: ModelDefaults) -> Self {
        entries.sort_by_key(|e| if e.match_version.is_empty() { 1 } else { 0 });
        Self { entries, defaults }
    }

    pub fn builtin() -> Self {
        Self::from_toml(include_str!("../../models.toml")).expect("built-in models.toml is invalid")
    }

    pub fn resolve(&self, anthropic_model: &str) -> Option<&ModelEntry> {
        let lowered = anthropic_model.to_lowercase();
        let model_lower = lowered.strip_suffix("-thinking").unwrap_or(&lowered);
        self.entries.iter().find(|entry| {
            if !model_lower.contains(&entry.match_family) {
                return false;
            }
            if entry.match_version.is_empty() {
                return true;
            }
            entry.match_version.iter().any(|v| model_lower.contains(v))
        })
    }

    pub fn map_model(&self, model: &str) -> Option<String> {
        self.resolve(model).map(|e| e.kiro_id.clone())
    }

    pub fn context_window(&self, model: &str) -> i32 {
        self.resolve(model)
            .map(|e| e.context_window)
            .unwrap_or(self.defaults.context_window)
    }

    pub fn min_cacheable_tokens(&self, model: &str) -> i32 {
        self.resolve(model)
            .and_then(|e| e.min_cacheable_tokens)
            .unwrap_or(self.defaults.min_cacheable_tokens)
    }

    pub fn thinking_override(&self, model: &str) -> Option<ThinkingOverride> {
        if !model.to_lowercase().ends_with("-thinking") {
            return None;
        }
        let entry = self.resolve(model)?;
        entry
            .thinking_type
            .as_ref()
            .map(|thinking_type| ThinkingOverride {
                thinking_type: thinking_type.clone(),
                budget_tokens: entry.thinking_budget_tokens,
                effort: entry.thinking_effort.clone(),
            })
    }

    /// 模型配置驱动的 thinking 配置，对任意模型名生效（不限 `-thinking` 后缀）。
    ///
    /// 与 `thinking_override`（只服务 `-thinking` 虚拟模型的后缀覆写场景）不同，
    /// 本方法是 converter 层判断 effort/thinking 透传分支的通用判据来源：
    /// PR #63 引入的结构化 effort 透传曾以「请求 thinking.type」为判据，但 Claude Code
    /// 实际只发标准 `enabled`，从不发 `adaptive`，导致普通模型（如 claude-sonnet-5，配置
    /// 早已是 adaptive）永远走不到结构化路径。修正为「模型配置 thinking_type」判据。
    ///
    /// 未显式配置 `thinking_type` 的模型按 "enabled" 兜底，与老行为保持一致
    /// （Never break userspace：不会有模型因为配置缺省而突然被判进 adaptive 分支）。
    pub fn thinking_config(&self, model: &str) -> ThinkingOverride {
        let entry = self.resolve(model);
        ThinkingOverride {
            thinking_type: entry
                .and_then(|e| e.thinking_type.clone())
                .unwrap_or_else(|| "enabled".to_string()),
            budget_tokens: entry
                .map(|e| e.thinking_budget_tokens)
                .unwrap_or_else(default_thinking_budget),
            effort: entry.and_then(|e| e.thinking_effort.clone()),
        }
    }

    pub fn available_models(&self) -> Vec<AvailableModel> {
        let mut models = Vec::new();
        for entry in &self.entries {
            models.push(AvailableModel {
                id: entry.id.clone(),
                display_name: entry.display_name.clone(),
                created: entry.created,
                max_tokens: entry.max_tokens,
            });
            if entry.expose_thinking_variant && entry.thinking_type.is_some() {
                models.push(AvailableModel {
                    id: format!("{}-thinking", entry.id),
                    display_name: format!("{} (thinking)", entry.display_name),
                    created: entry.created,
                    max_tokens: entry.max_tokens,
                });
            }
        }
        models
    }

    pub fn is_premium_tier(&self, model: &str) -> bool {
        self.resolve(model)
            .map(|e| e.tier == "pro")
            .unwrap_or(false)
    }

    /// 按 kiro_id **精确相等**反查该模型的 credit 权重（上游计费倍率）。
    ///
    /// 刻意**不复用** `resolve()`：`resolve()` 带族级兜底（`match_version = []` 的条目
    /// 会捞走同族任意版本号），未登记的新模型会被同族兜底条目捞走、拿到别人的权重，
    /// 违反「未登记一律 1.0」这条硬性要求。现在 kiro_id 恰好也能被 `resolve()` 命中，
    /// 只是 `match_version` 同时列了点号与连字符两种写法的**巧合，不是契约**。
    ///
    /// 本方法是权重 sanitize 的**唯一收口点**：`models.toml` 是 TOML，`inf` / `nan`
    /// 是合法浮点字面量；权重 `0.0` 会让一张凭据「永远免费」被独占选中，负数会让
    /// 负载倒着走。非有限、非正的取值一律回落 1.0。
    pub fn credit_weight_by_kiro_id(&self, kiro_id: Option<&str>) -> f64 {
        let Some(kiro_id) = kiro_id else {
            return 1.0;
        };
        let entry = self
            .entries
            .iter()
            .find(|e| e.kiro_id.eq_ignore_ascii_case(kiro_id));
        // `#98` 返工 SUGGESTION C3：未命中静默回落 1.0 是既定设计（未登记一律
        // 1.0），不是异常，故用 debug 而非 warn；但线上「某模型权重不对」的
        // 排查此前没有任何可观测信号，只能靠读代码推断，补一条日志留痕。
        if entry.is_none() {
            tracing::debug!(kiro_id, "credit_weight 查表未命中，回落默认权重 1.0");
        }
        entry
            .map(|e| e.credit_weight)
            .filter(|w| w.is_finite() && *w > 0.0)
            .unwrap_or(1.0)
    }
}

fn default_context_window() -> i32 {
    200_000
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

fn default_min_cacheable_tokens() -> i32 {
    1024
}

fn default_max_tokens() -> i32 {
    64000
}

fn default_tier() -> String {
    "free".to_string()
}

fn default_credit_weight() -> f64 {
    1.0
}

fn default_thinking_budget() -> i32 {
    20000
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ModelRegistry {
        let toml = r#"
[defaults]
context_window = 200000
min_cacheable_tokens = 1024
max_tokens = 64000

[[models]]
id = "claude-opus-4-8"
kiro_id = "claude-opus-4.8"
family = "opus"
display_name = "Claude Opus 4.8"
match_family = "opus"
match_version = ["4-8", "4.8"]
context_window = 1000000
max_tokens = 64000
created = 1717027200
tier = "pro"
min_cacheable_tokens = 2048
thinking_type = "adaptive"
thinking_budget_tokens = 20000
thinking_effort = "high"
expose_thinking_variant = true

[[models]]
id = "claude-haiku-4-5"
kiro_id = "claude-haiku-4.5"
family = "haiku"
display_name = "Claude Haiku 4.5"
match_family = "haiku"
match_version = ["4-5", "4.5"]
context_window = 200000
max_tokens = 64000
created = 1696896000
tier = "free"

[[models]]
id = "claude-opus-fallback"
kiro_id = "claude-opus-latest"
family = "opus"
display_name = "Claude Opus (fallback)"
match_family = "opus"
match_version = []
context_window = 200000
max_tokens = 64000
created = 1696896000
tier = "pro"
"#;
        ModelRegistry::from_toml(toml).unwrap()
    }

    #[test]
    fn test_resolve_specific_model() {
        let registry = test_config();
        let entry = registry.resolve("claude-opus-4-8-20260526").unwrap();
        assert_eq!(entry.id, "claude-opus-4-8");
        assert_eq!(entry.kiro_id, "claude-opus-4.8");
    }

    #[test]
    fn test_resolve_family_fallback() {
        let registry = test_config();
        let entry = registry.resolve("claude-opus-4-9").unwrap();
        assert_eq!(entry.id, "claude-opus-fallback");
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let registry = test_config();
        let entry = registry.resolve("Claude-Opus-4-8").unwrap();
        assert_eq!(entry.id, "claude-opus-4-8");
    }

    #[test]
    fn test_resolve_unknown_family() {
        let registry = test_config();
        assert!(registry.resolve("claude-fable-5").is_none());
    }

    #[test]
    fn test_map_model_returns_kiro_id() {
        let registry = test_config();
        assert_eq!(
            registry.map_model("claude-opus-4-8"),
            Some("claude-opus-4.8".to_string())
        );
        assert_eq!(
            registry.map_model("claude-haiku-4-5"),
            Some("claude-haiku-4.5".to_string())
        );
    }

    #[test]
    fn test_context_window() {
        let registry = test_config();
        assert_eq!(registry.context_window("claude-opus-4-8"), 1_000_000);
        assert_eq!(registry.context_window("claude-unknown"), 200_000);
    }

    #[test]
    fn test_thinking_override_with_suffix() {
        let registry = test_config();
        let override_opt = registry.thinking_override("claude-opus-4-8-thinking");
        assert!(override_opt.is_some());
        let override_val = override_opt.unwrap();
        assert_eq!(override_val.thinking_type, "adaptive");
        assert_eq!(override_val.budget_tokens, 20000);
        assert_eq!(override_val.effort, Some("high".to_string()));
    }

    #[test]
    fn test_thinking_override_without_suffix() {
        let registry = test_config();
        assert!(registry.thinking_override("claude-opus-4-8").is_none());
    }

    #[test]
    fn test_thinking_config_resolves_without_suffix() {
        let registry = test_config();
        // 无 -thinking 后缀也能拿到配置驱动的 thinking_type，这是本方法与
        // thinking_override 的核心差异（后者只服务 -thinking 虚拟模型）。
        let config = registry.thinking_config("claude-opus-4-8");
        assert_eq!(config.thinking_type, "adaptive");
        assert_eq!(config.budget_tokens, 20000);
        assert_eq!(config.effort, Some("high".to_string()));
    }

    #[test]
    fn test_thinking_config_defaults_to_enabled_when_unset() {
        let registry = test_config();
        // claude-haiku-4-5 配置未写 thinking_type，应兜底 enabled，避免老模型
        // 因配置缺省被误判进 adaptive 分支。
        let config = registry.thinking_config("claude-haiku-4-5");
        assert_eq!(config.thinking_type, "enabled");
        assert_eq!(config.effort, None);
    }

    #[test]
    fn test_thinking_config_unknown_model_defaults_to_enabled() {
        let registry = test_config();
        let config = registry.thinking_config("claude-totally-unknown");
        assert_eq!(config.thinking_type, "enabled");
        assert_eq!(config.budget_tokens, 20000);
        assert_eq!(config.effort, None);
    }

    #[test]
    fn test_available_models_includes_thinking_variants() {
        let registry = test_config();
        let models = registry.available_models();
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"claude-opus-4-8"));
        assert!(ids.contains(&"claude-opus-4-8-thinking"));
        assert!(ids.contains(&"claude-haiku-4-5"));
        assert!(!ids.contains(&"claude-haiku-4-5-thinking"));
    }

    #[test]
    fn test_is_premium_tier() {
        let registry = test_config();
        assert!(registry.is_premium_tier("claude-opus-4-8"));
        assert!(!registry.is_premium_tier("claude-haiku-4-5"));
    }

    #[test]
    fn test_from_toml_basic() {
        let toml = r#"
[[models]]
id = "test-model"
kiro_id = "test"
family = "test"
display_name = "Test"
match_family = "test"
"#;
        let registry = ModelRegistry::from_toml(toml).unwrap();
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.entries[0].id, "test-model");
    }

    #[test]
    fn test_credit_weight_not_captured_by_family_fallback() {
        // N11：未登记模型不会被族级兜底捞走权重。
        //
        // 不要用真实 models.toml 断言 credit_weight_by_kiro_id("claude-opus-9") == 1.0
        // —— 那是恒绿零覆盖：即使实现走了 resolve()，命中的 opus-4.6 兜底条目也没写权重
        // （默认就是 1.0），两种实现都返回 1.0，测不出区别。
        //
        // 正确构造 = 内联一份最小 TOML，让族级兜底条目（match_version = []）带一个**非 1.0**
        // 的权重（如 3.0），然后两条断言缺一不可。
        let toml = r#"
[[models]]
id = "claude-opus-fallback"
kiro_id = "claude-opus-latest"
family = "opus"
display_name = "Claude Opus (fallback)"
match_family = "opus"
match_version = []
credit_weight = 3.0
"#;
        let registry = ModelRegistry::from_toml(toml).unwrap();
        // 前提：族级兜底确实会命中这个未登记版本号
        assert!(
            registry.resolve("claude-opus-9").is_some(),
            "前提：族级兜底确实会命中这个未登记版本号"
        );
        // 实际测试：credit_weight_by_kiro_id 应该返回 1.0，不是兜底条目的 3.0
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("claude-opus-latest")),
            3.0,
            "兜底条目的权重可以被 kiro_id 精确匹配"
        );
        // 关键：未登记 kiro_id 应该返回 1.0
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("claude-opus-9")),
            1.0,
            "未登记 kiro_id 不会被族级兜底捞走权重"
        );
    }

    #[test]
    fn test_credit_weight_sanitize_zero_negative_inf_nan() {
        // N12：权重 sanitize —— 0.0 / -1.0 / inf / nan 全部回落 1.0。
        let toml = r#"
[[models]]
id = "test-zero"
kiro_id = "test-zero"
family = "test"
display_name = "Test Zero"
match_family = "test"
credit_weight = 0.0

[[models]]
id = "test-negative"
kiro_id = "test-negative"
family = "test"
display_name = "Test Negative"
match_family = "test"
credit_weight = -1.0

[[models]]
id = "test-infinity"
kiro_id = "test-infinity"
family = "test"
display_name = "Test Infinity"
match_family = "test"
credit_weight = inf

[[models]]
id = "test-nan"
kiro_id = "test-nan"
family = "test"
display_name = "Test NaN"
match_family = "test"
credit_weight = nan

[[models]]
id = "test-normal"
kiro_id = "test-normal"
family = "test"
display_name = "Test Normal"
match_family = "test"
credit_weight = 2.5
"#;
        let registry = ModelRegistry::from_toml(toml).unwrap();
        // 0.0 -> 1.0
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("test-zero")),
            1.0,
            "credit_weight 为 0.0 应回落 1.0"
        );
        // -1.0 -> 1.0
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("test-negative")),
            1.0,
            "credit_weight 为负数应回落 1.0"
        );
        // inf -> 1.0（被 sanitize 拦截）
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("test-infinity")),
            1.0,
            "credit_weight 为 inf 应回落 1.0"
        );
        // nan -> 1.0（被 sanitize 拦截）
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("test-nan")),
            1.0,
            "credit_weight 为 nan 应回落 1.0"
        );
        assert_eq!(
            registry.credit_weight_by_kiro_id(Some("test-normal")),
            2.5,
            "finite 且为正的权重原样返回"
        );
    }

    #[test]
    fn test_deleting_credit_weight_fields_maintains_functionality() {
        // N13：覆盖「删除全部权重字段后仍正常启动 / 选路 / 无 panic / 无 500」。
        //
        // 「无 500」在本层测不到（这里没有 HTTP 栈），由「能加载 + 回落 1.0 + 选路成功」推出：
        // 新路径唯一能产 500 的形态是 panic，而 panic 会让本测试直接失败。
        // 不要误以为这条测试真打了 HTTP。
        //
        // 「选路成功」这个前提**不**由本测试内的 `resolve()` 检查兑现（那只证明
        // 模型名能查到条目，从不涉及负载均衡挑凭据的路径，删不删权重字段两种
        // 实现下都会通过、对这条验收项零覆盖）。真正跑一遍 balanced 选路的
        // 用例在 `crate::kiro::token_manager` 测试模块的
        // `test_balanced_selection_survives_credit_weight_fields_removed`
        // （#98 返工 C1）——构造同一份剥离 credit_weight 的 registry 喂给
        // `MultiTokenManager`，跑 `acquire → record_upstream_call → acquire`
        // 断言选路真的换了凭据。两处 doc 以那条测试的断言为准，本测试下方
        // 第 3 段的 `resolve()` 检查只保留其本身「模型名仍能被查到」这一较
        // 窄的价值，不再重复声称覆盖选路。
        let raw = include_str!("../../models.toml");
        let stripped: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with("credit_weight"))
            .collect::<Vec<_>>()
            .join("\n");

        // 1. from_toml(&stripped) 返回 Ok，且条目数不变
        let registry_with_weights = ModelRegistry::from_toml(raw).unwrap();
        let registry_without_weights = ModelRegistry::from_toml(&stripped).unwrap();
        assert_eq!(
            registry_with_weights.available_models().len(),
            registry_without_weights.available_models().len(),
            "删除权重字段后，条目数（含思考变体）应不变"
        );

        // 2. 删除权重后，GPT-5.6-sol 应回落 1.0
        assert_eq!(
            registry_without_weights.credit_weight_by_kiro_id(Some("gpt-5.6-sol")),
            1.0,
            "删除权重字段后，应回落默认值 1.0"
        );

        // 3. resolve() 对若干真实模型名仍能查到条目（仅证明模型名解析不受
        //    影响；负载均衡选路的真实覆盖见上方 doc comment 指向的
        //    token_manager 测试，这里不重复声称）
        assert!(
            registry_without_weights
                .resolve("claude-opus-4-8")
                .is_some(),
            "删除权重后，模型名仍应能被解析到条目"
        );
        assert!(
            registry_without_weights.resolve("gpt-5.6-sol").is_some(),
            "GPT-5.6-sol 仍应能被解析到条目"
        );
    }

    #[test]
    fn test_credit_weight_values_in_production_models_toml() {
        // N14：权重数值护栏 —— 对真实 models.toml 断言数值完整性。
        //
        // `#99`：官方一手来源（https://kiro.dev/docs/models，2026-09-17 版本）
        // 更新前，claude 全族 9 条压根没配 credit_weight（走 serde default
        // 1.0 回落），GPT-5.6 三条的取值来自未背书的人工注释。现在 12 条
        // 全部有非默认权重，逐条断言官方值——不再对 claude 全族断言
        // "回落 1.0"，那个断言此后表达的是「忘记配置」而非「等权重」。
        let registry = ModelRegistry::builtin();

        let expected: &[(&str, f64)] = &[
            ("claude-opus-5", 2.2),
            ("claude-opus-4.8", 2.2),
            ("claude-opus-4.7", 2.2),
            ("claude-opus-4.6", 2.2),
            ("claude-opus-4.5", 2.2),
            ("claude-sonnet-5", 1.3),
            ("claude-sonnet-4.6", 1.3),
            ("claude-sonnet-4.5", 1.3),
            ("claude-haiku-4.5", 0.4),
            ("gpt-5.6-sol", 4.4),
            ("gpt-5.6-terra", 2.2),
            ("gpt-5.6-luna", 1.1),
        ];

        // 前提断言：长度相等推不出集合相等——若 expected 里把某一条误写成
        // 另一条已有的 kiro_id（重复），同时漏掉了 toml 里的另一条，两个
        // "12" 依然成立，而被漏掉的那条完全没有任何断言。改用
        // HashMap<kiro_id, weight> 承担「全表覆盖」：重复 key 会让 map 变
        // 短，`map.len() == registry.entries.len()` 随即失败，抓住的正是
        // 这个形态；expected 与 registry.entries 集合相等（非仅同长度）
        // 由此断言承担。
        let expected_by_id: std::collections::HashMap<&str, f64> =
            expected.iter().copied().collect();
        assert_eq!(
            expected_by_id.len(),
            registry.entries.len(),
            "前提：官方权重表去重后的 kiro_id 数量应与 models.toml 条目数一致；\
             expected_by_id={}, registry.entries={}，说明存在重复 kiro_id 或漏项",
            expected_by_id.len(),
            registry.entries.len()
        );

        for entry in &registry.entries {
            let expected_weight = expected_by_id
                .get(entry.kiro_id.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{} 出现在 models.toml 但不在官方权重表 expected 中，本测试未同步",
                        entry.kiro_id
                    )
                });
            assert_eq!(
                registry.credit_weight_by_kiro_id(Some(&entry.kiro_id)),
                *expected_weight,
                "{} credit_weight 应为 {expected_weight}（Kiro 官方倍率，基准 1.0x = Auto）",
                entry.kiro_id
            );
        }
    }
}
