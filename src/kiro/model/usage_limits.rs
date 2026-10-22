//! 使用额度查询数据模型
//!
//! 包含 getUsageLimits API 的响应类型定义

use serde::Deserialize;

/// 使用额度查询响应
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageLimitsResponse {
    /// 下次重置日期 (Unix 时间戳)
    #[serde(default)]
    pub next_date_reset: Option<f64>,

    /// 订阅信息
    #[serde(default)]
    pub subscription_info: Option<SubscriptionInfo>,

    /// 使用量明细列表
    #[serde(default)]
    pub usage_breakdown_list: Vec<UsageBreakdown>,
}

/// 订阅信息
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInfo {
    /// 订阅标题 (KIRO PRO+ / KIRO FREE 等)
    #[serde(default)]
    pub subscription_title: Option<String>,
}

/// 使用量明细
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct UsageBreakdown {
    /// 当前使用量
    #[serde(default)]
    pub current_usage: i64,

    /// 当前使用量（精确值）
    #[serde(default)]
    pub current_usage_with_precision: Option<f64>,

    /// 奖励额度列表
    #[serde(default)]
    pub bonuses: Vec<Bonus>,

    /// 免费试用信息
    #[serde(default)]
    pub free_trial_info: Option<FreeTrialInfo>,

    /// 下次重置日期 (Unix 时间戳)
    #[serde(default)]
    pub next_date_reset: Option<f64>,

    /// 使用限额
    #[serde(default)]
    pub usage_limit: i64,

    /// 使用限额（精确值）
    #[serde(default)]
    pub usage_limit_with_precision: Option<f64>,
}

/// 奖励额度
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bonus {
    /// 当前使用量
    #[serde(default)]
    pub current_usage: Option<f64>,

    /// 使用限额
    #[serde(default)]
    pub usage_limit: Option<f64>,

    /// 状态 (ACTIVE / EXPIRED)
    #[serde(default)]
    pub status: Option<String>,
}

impl Bonus {
    /// 检查 bonus 是否处于激活状态
    pub fn is_active(&self) -> bool {
        self.status
            .as_deref()
            .map(|s| s == "ACTIVE")
            .unwrap_or(false)
    }
}

/// 免费试用信息
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct FreeTrialInfo {
    /// 当前使用量
    #[serde(default)]
    pub current_usage: i64,

    /// 当前使用量（精确值）
    #[serde(default)]
    pub current_usage_with_precision: Option<f64>,

    /// 免费试用过期时间 (Unix 时间戳)
    #[serde(default)]
    pub free_trial_expiry: Option<f64>,

    /// 免费试用状态 (ACTIVE / EXPIRED)
    #[serde(default)]
    pub free_trial_status: Option<String>,

    /// 使用限额
    #[serde(default)]
    pub usage_limit: i64,

    /// 使用限额（精确值）
    #[serde(default)]
    pub usage_limit_with_precision: Option<f64>,
}

// ============ 便捷方法实现 ============

impl FreeTrialInfo {
    /// 检查免费试用是否处于激活状态
    pub fn is_active(&self) -> bool {
        self.free_trial_status
            .as_deref()
            .map(|s| s == "ACTIVE")
            .unwrap_or(false)
    }
}

impl UsageLimitsResponse {
    /// 缺失精确数值或未知附加额度状态时，不能证明额度已恢复。
    pub fn has_confirmed_remaining(&self) -> bool {
        self.confirmed_totals()
            .is_some_and(|(usage, limit)| limit > usage)
    }

    fn confirmed_totals(&self) -> Option<(f64, f64)> {
        let breakdown = self.primary_breakdown()?;
        let mut totals = valid_pair(
            breakdown.current_usage_with_precision,
            breakdown.usage_limit_with_precision,
        )?;
        if let Some(trial) = &breakdown.free_trial_info {
            match trial.free_trial_status.as_deref() {
                Some("ACTIVE") => add_pair(
                    &mut totals,
                    trial.current_usage_with_precision,
                    trial.usage_limit_with_precision,
                )?,
                Some("EXPIRED") => (),
                _ => return None,
            }
        }
        for bonus in &breakdown.bonuses {
            match bonus.status.as_deref() {
                Some("ACTIVE") => add_pair(&mut totals, bonus.current_usage, bonus.usage_limit)?,
                Some("EXPIRED") => (),
                _ => return None,
            }
        }
        Some(totals)
    }

    /// 获取订阅标题
    pub fn subscription_title(&self) -> Option<&str> {
        self.subscription_info
            .as_ref()
            .and_then(|info| info.subscription_title.as_deref())
    }

    /// 获取第一个使用量明细
    fn primary_breakdown(&self) -> Option<&UsageBreakdown> {
        self.usage_breakdown_list.first()
    }

    /// 获取总使用限额（精确值）
    ///
    /// 累加基础额度、激活的免费试用额度和激活的奖励额度
    pub fn usage_limit(&self) -> f64 {
        let Some(breakdown) = self.primary_breakdown() else {
            return 0.0;
        };

        let mut total = breakdown.usage_limit_with_precision.unwrap_or(0.0);

        // 累加激活的 free trial 额度
        if let Some(trial) = &breakdown.free_trial_info
            && trial.is_active()
        {
            total += trial.usage_limit_with_precision.unwrap_or(0.0);
        }

        // 累加激活的 bonus 额度
        for bonus in &breakdown.bonuses {
            if bonus.is_active() {
                total += bonus.usage_limit.unwrap_or(0.0);
            }
        }

        total
    }

    /// 获取总当前使用量（精确值）
    ///
    /// 累加基础使用量、激活的免费试用使用量和激活的奖励使用量
    pub fn current_usage(&self) -> f64 {
        let Some(breakdown) = self.primary_breakdown() else {
            return 0.0;
        };

        let mut total = breakdown.current_usage_with_precision.unwrap_or(0.0);

        // 累加激活的 free trial 使用量
        if let Some(trial) = &breakdown.free_trial_info
            && trial.is_active()
        {
            total += trial.current_usage_with_precision.unwrap_or(0.0);
        }

        // 累加激活的 bonus 使用量
        for bonus in &breakdown.bonuses {
            if bonus.is_active() {
                total += bonus.current_usage.unwrap_or(0.0);
            }
        }

        total
    }
}

fn valid_pair(usage: Option<f64>, limit: Option<f64>) -> Option<(f64, f64)> {
    let (usage, limit) = (usage?, limit?);
    (usage.is_finite() && limit.is_finite() && usage >= 0.0 && limit >= 0.0)
        .then_some((usage, limit))
}

fn add_pair(totals: &mut (f64, f64), usage: Option<f64>, limit: Option<f64>) -> Option<()> {
    let pair = valid_pair(usage, limit)?;
    totals.0 += pair.0;
    totals.1 += pair.1;
    (totals.0.is_finite() && totals.1.is_finite()).then_some(())
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use serde_json::{Value, json};

    fn response(breakdown: Value) -> UsageLimitsResponse {
        serde_json::from_value(json!({"usageBreakdownList": [breakdown]})).unwrap()
    }

    #[test]
    fn maintenance_balance_requires_complete_valid_precision() {
        for value in [
            json!({}),
            json!({"usageLimitWithPrecision":10}),
            json!({"currentUsageWithPrecision":0}),
            json!({"currentUsageWithPrecision":10,"usageLimitWithPrecision":10}),
            json!({"currentUsageWithPrecision":11,"usageLimitWithPrecision":10}),
            json!({"currentUsageWithPrecision":-1,"usageLimitWithPrecision":10}),
        ] {
            assert!(!response(value).has_confirmed_remaining());
        }
        let empty: UsageLimitsResponse = serde_json::from_value(json!({})).unwrap();
        assert!(!empty.has_confirmed_remaining());
        let mut valid =
            response(json!({"currentUsageWithPrecision":0,"usageLimitWithPrecision":10}));
        assert!(valid.has_confirmed_remaining());
        for invalid in [f64::NAN, f64::INFINITY, -1.0] {
            valid.usage_breakdown_list[0].current_usage_with_precision = Some(invalid);
            assert!(!valid.has_confirmed_remaining());
        }
    }

    #[test]
    fn maintenance_trial_bonus_and_display_compatibility() {
        let mut value = json!({"currentUsageWithPrecision":10,"usageLimitWithPrecision":10,
            "freeTrialInfo":{"freeTrialStatus":"ACTIVE","currentUsageWithPrecision":1,"usageLimitWithPrecision":5},
            "bonuses":[{"status":"ACTIVE","currentUsage":2,"usageLimit":3}]});
        let valid = response(value.clone());
        assert!(valid.has_confirmed_remaining());
        assert_eq!((valid.current_usage(), valid.usage_limit()), (13.0, 18.0));
        value["bonuses"][0]["currentUsage"] = Value::Null;
        let missing = response(value.clone());
        assert!(!missing.has_confirmed_remaining());
        assert_eq!(missing.current_usage(), 11.0);
        value["bonuses"][0]["status"] = json!("UNKNOWN");
        assert!(!response(value.clone()).has_confirmed_remaining());
        value["bonuses"][0]["status"] = json!("EXPIRED");
        assert!(response(value.clone()).has_confirmed_remaining());
        value["freeTrialInfo"]["freeTrialStatus"] = Value::Null;
        assert!(!response(value).has_confirmed_remaining());
    }

    #[test]
    fn maintenance_rejects_nonfinite_totals_and_uses_only_primary_breakdown() {
        let huge = response(
            json!({"currentUsageWithPrecision":0,"usageLimitWithPrecision":1e308,
            "bonuses":[{"status":"ACTIVE","currentUsage":0,"usageLimit":1e308}]}),
        );
        assert!(!huge.has_confirmed_remaining());
        for invalid in [f64::INFINITY, f64::NAN, -1.0] {
            let mut value =
                response(json!({"currentUsageWithPrecision":0,"usageLimitWithPrecision":10}));
            value.usage_breakdown_list[0].usage_limit_with_precision = Some(invalid);
            assert!(!value.has_confirmed_remaining());
        }
        let value: UsageLimitsResponse = serde_json::from_value(json!({"usageBreakdownList":[
            {"currentUsageWithPrecision":10,"usageLimitWithPrecision":10},
            {"currentUsageWithPrecision":0,"usageLimitWithPrecision":100}]}))
        .unwrap();
        assert!(!value.has_confirmed_remaining());
        assert_eq!((value.current_usage(), value.usage_limit()), (10.0, 10.0));
    }
}
