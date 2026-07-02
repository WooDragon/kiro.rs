use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ModelDefaults {
    #[serde(default = "default_context_window")]
    pub context_window: i32,
    #[serde(default = "default_min_cacheable_tokens")]
    pub min_cacheable_tokens: i32,
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
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read models config from {}: {}", path, e))?;
        Self::from_toml(&content)
    }

    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let config: ModelsConfig = toml::from_str(toml_str)
            .map_err(|e| format!("Failed to parse models config: {}", e))?;
        Ok(Self::from_entries(config.models, config.defaults))
    }

    pub fn from_entries(mut entries: Vec<ModelEntry>, defaults: ModelDefaults) -> Self {
        entries.sort_by_key(|e| if e.match_version.is_empty() { 1 } else { 0 });
        Self { entries, defaults }
    }

    pub fn resolve(&self, anthropic_model: &str) -> Option<&ModelEntry> {
        let model_lower = anthropic_model.to_lowercase().replace("-thinking", "");
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
        if !model.ends_with("-thinking") {
            return None;
        }
        let entry = self.resolve(model)?;
        entry.thinking_type.as_ref().map(|thinking_type| ThinkingOverride {
            thinking_type: thinking_type.clone(),
            budget_tokens: entry.thinking_budget_tokens,
            effort: entry.thinking_effort.clone(),
        })
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
}

fn default_context_window() -> i32 {
    200_000
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
        assert_eq!(registry.map_model("claude-opus-4-8"), Some("claude-opus-4.8".to_string()));
        assert_eq!(registry.map_model("claude-haiku-4-5"), Some("claude-haiku-4.5".to_string()));
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
}
