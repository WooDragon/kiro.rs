//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as TokioMutex;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::profiles::{
    ListAvailableProfilesResponse, is_valid_profile_arn, select_profile_arn,
};
use crate::kiro::model::token_refresh::{
    IdcRefreshRequest, IdcRefreshResponse, RefreshRequest, RefreshResponse,
};
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::kiro::{LOG_PAYLOAD_LIMIT, truncate_for_log};
use crate::model::config::Config;
use crate::model::registry::ModelRegistry;

/// 检查 Token 是否在指定时间内过期
pub(crate) fn is_token_expiring_within(
    credentials: &KiroCredentials,
    minutes: i64,
) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期（提前 5 分钟判断）
pub(crate) fn is_token_expired(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub(crate) fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 生成 API Key 脱敏展示(前 4 + ... + 后 4,长度不足或非 ASCII 回退 ***)
fn mask_api_key(key: &str) -> String {
    if key.is_ascii() && key.len() > 16 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "***".to_string()
    }
}

/// 验证 refreshToken 的基本有效性
pub(crate) fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100 || refresh_token.ends_with("...") || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// Refresh Token 永久失效错误
///
/// 当服务端返回永久性失败（如 400 `invalid_grant` 或 401 `invalid_client`）时，
/// 表示凭据已不可恢复（refreshToken 被撤销/过期，或 clientId/clientSecret 无效），
/// 不应重试，需立即禁用对应凭据。
///
/// `message` 刻意不拼接上游原始 body（#71 结构化日志改造前曾整段塞入，导致消费处
/// `error = %e` 打出的日志字段值本身就是一大段 JSON，grep/jq 精确抠字段困难）；
/// 完整 body 改由 [`classify_permanent_refresh_failure`] 就近发一条 debug 级日志
/// 携带 `upstream_body` 字段。`error_code` 让消费处可按字段精确匹配 invalid_grant /
/// invalid_client，无需再从 message 文本里正则抠。
#[derive(Debug)]
pub(crate) struct RefreshTokenInvalidError {
    pub message: String,
    /// OAuth 错误码：`"invalid_grant"` / `"invalid_client"`
    pub error_code: &'static str,
}

impl fmt::Display for RefreshTokenInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RefreshTokenInvalidError {}

/// Profile lookup observed a replacement credential on every bounded retry.
///
/// This carries no credential identity or token: callers only need to distinguish a stale
/// generation race from an actual refresh failure, so replacement credentials are never penalized.
#[derive(Debug)]
struct ProfileIdentityChangedError;

impl fmt::Display for ProfileIdentityChangedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("profile credential identity changed during lookup")
    }
}

impl std::error::Error for ProfileIdentityChangedError {}

/// 分类 token 刷新失败：返回 `Some` 表示凭据永久失效（不可重试，应立即禁用），
/// `None` 表示瞬态失败（交由 acquire 循环累计重试判定）。
///
/// "瞬态 vs 永久"的边界集中于此——新增永久失效场景只改这一处，IdC / Social 两条
/// 刷新路径同时生效。`source` 仅用于错误消息文案（`"IdC"` / `"Social"`）。
fn classify_permanent_refresh_failure(
    status: u16,
    body: &str,
    source: &str,
) -> Option<RefreshTokenInvalidError> {
    // 精确解析 OAuth `error` 字段，避免 error_description 偶含关键字时误杀可恢复凭据
    let json = serde_json::from_str::<serde_json::Value>(body).ok();
    let error_code = json
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| e.as_str())
        .unwrap_or("");

    // 400 + invalid_grant + "Invalid refresh token provided" → refreshToken 永久失效
    //
    // 此处刻意保守：invalid_grant 在真实上游含瞬态情形（时钟偏移 / 并发刷新竞态），
    // 不能仅凭 error=invalid_grant 就判永久失效，否则会错杀可恢复凭据。故需双重条件：
    // (1) JSON error 字段精确等于 invalid_grant；(2) body 含确切失效描述。
    // 描述串用 raw-body `contains`（而非 error_description 字段精确相等）是故意的宽松——
    // 不假设上游严格把该措辞放在 OAuth 标准字段，只要在已确认 error=invalid_grant 的
    // 响应里任何位置出现该字面即认（仅放宽 (2)，不放宽 (1)）。
    // 放宽此边界须先黑盒实测背书（CLAUDE.md：判定边界改动禁推断）。
    if status == 400
        && error_code == "invalid_grant"
        && body.contains("Invalid refresh token provided")
    {
        tracing::debug!(
            source,
            error_code = "invalid_grant",
            upstream_body = %truncate_for_log(body, LOG_PAYLOAD_LIMIT),
            "refreshToken 永久失效判定命中（invalid_grant）"
        );
        return Some(RefreshTokenInvalidError {
            message: format!("{} refreshToken 已失效 (invalid_grant)", source),
            error_code: "invalid_grant",
        });
    }

    // 401 + invalid_client → clientId/clientSecret 无效，永久失效。
    // Social 路径不发 client 凭证，对其为死分支但无害（更鲁棒）。
    if status == 401 && error_code == "invalid_client" {
        tracing::debug!(
            source,
            error_code = "invalid_client",
            upstream_body = %truncate_for_log(body, LOG_PAYLOAD_LIMIT),
            "refreshToken 永久失效判定命中（invalid_client）"
        );
        return Some(RefreshTokenInvalidError {
            message: format!("{} 客户端凭证无效 (invalid_client)", source),
            error_code: "invalid_client",
        });
    }

    None
}

/// 刷新 Token
pub(crate) async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    // API Key 凭据不支持 Token 刷新：底层契约级拦截
    // 其他调用点（try_ensure_token / 活跃路径 / add_credential）在调用前已显式分流 API Key；
    // 仅 force_refresh_token_for 未分流，此处 bail 让错误自然传播为 400 BAD_REQUEST。
    if credentials.is_api_key_credential() {
        bail!("API Key 凭据不支持刷新 Token");
    }

    validate_refresh_token(credentials)?;

    // 根据 auth_method 选择刷新方式
    // 如果未指定 auth_method，根据是否有 clientId/clientSecret 自动判断
    let auth_method = credentials.auth_method.as_deref().unwrap_or_else(|| {
        if credentials.client_id.is_some() && credentials.client_secret.is_some() {
            "idc"
        } else {
            "social"
        }
    });

    if auth_method.eq_ignore_ascii_case("idc")
        || auth_method.eq_ignore_ascii_case("builder-id")
        || auth_method.eq_ignore_ascii_case("iam")
    {
        refresh_idc_token(credentials, config, proxy).await
    } else {
        refresh_social_token(credentials, config, proxy).await
    }
}

/// 刷新 Social Token
async fn refresh_social_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 Social Token");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        if let Some(e) = classify_permanent_refresh_failure(status.as_u16(), &body_text, "Social") {
            return Err(e.into());
        }

        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

/// 刷新 IdC Token (AWS SSO OIDC)
async fn refresh_idc_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 IdC Token");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientId"))?;
    let client_secret = credentials
        .client_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientSecret"))?;

    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);
    let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let x_amz_user_agent = "aws-sdk-js/3.980.0 KiroIDE";
    let user_agent = format!(
        "aws-sdk-js/3.980.0 ua/2.1 os/{} lang/js md/nodejs#{} api/sso-oidc#3.980.0 m/E KiroIDE",
        os_name, node_version
    );

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = IdcRefreshRequest {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        refresh_token: refresh_token.to_string(),
        grant_type: "refresh_token".to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header("x-amz-user-agent", x_amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", format!("oidc.{}.amazonaws.com", region))
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=4")
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        if let Some(e) = classify_permanent_refresh_failure(status.as_u16(), &body_text, "IdC") {
            return Err(e.into());
        }

        let error_msg = match status.as_u16() {
            401 => "IdC 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OIDC 服务暂时不可用",
            _ => "IdC Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: IdcRefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    // 同步更新 profile_arn（如果 IdC 响应中包含）
    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    Ok(new_credentials)
}

/// Fetch usage limits from a fixed endpoint so module tests can use loopback without changing Config.
async fn get_usage_limits_at(
    endpoint: &str,
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息");

    let host = endpoint
        .split("//")
        .nth(1)
        .and_then(|value| value.split('/').next())
        .ok_or_else(|| anyhow::anyhow!("usage limits URL 缺少 host"))?;
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;
    let os_name = &config.system_version;
    let node_version = &config.node_version;
    let mut url = format!("{endpoint}?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST");

    if let Some(profile_arn) = &credentials.profile_arn {
        url.push_str(&format!("&profileArn={}", urlencoding::encode(profile_arn)));
    }

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);
    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut request = client
        .get(&url)
        .header("x-amz-user-agent", &amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", host)
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=1")
        .header("Authorization", format!("Bearer {}", token))
        .header("Connection", "close");

    if credentials.is_api_key_credential() {
        request = request.header("tokentype", "API_KEY");
    }

    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取使用额度",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取使用额度失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    Ok(response.json().await?)
}

// ============================================================================
// 多凭据 Token 管理器
// ============================================================================

/// 单个凭据条目的状态
struct CredentialEntry {
    /// 凭据唯一 ID
    id: u64,
    /// 凭据信息
    credentials: KiroCredentials,
    /// API 调用连续失败次数
    failure_count: u32,
    /// Token 刷新连续失败次数
    refresh_failure_count: u32,
    /// 是否已禁用
    disabled: bool,
    /// 禁用原因（用于区分手动禁用 vs 自动禁用，便于自愈）
    disabled_reason: Option<DisabledReason>,
    /// API 调用成功次数
    success_count: u64,
    /// balanced 模式的**加权负载**（单位 credit，非请求次数）。
    /// 惰性求值：写侧 `record_load` 就地衰减+累加，读侧 `current_load(now)` 纯函数
    /// 外推不写回——指数衰减可组合，两路径数学等价。恒为有限非负数。
    load: f64,
    /// `load` 上次就地更新的**墙钟 Unix 毫秒**。`0` = 哨兵"无时间基准"。
    load_updated_at_ms: u64,
    /// 当前已分配但尚未完成的 API 调用数
    in_flight_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
    /// Profile discovery 失败后的下次允许尝试时间（进程单调毫秒）。
    profile_lookup_retry_after_ms: Option<u64>,
    /// 同一凭据 profile discovery 的 single-flight 锁。
    profile_lookup_lock: Arc<TokioMutex<()>>,
}

impl CredentialEntry {
    /// 纯函数：把 `load` 按半衰期外推到 `now_unix_ms`，**不写回**任何字段。
    /// 指数衰减可组合，读侧外推与写侧就地衰减数学等价，读路径不需要 `&mut self`。
    fn current_load(&self, now_unix_ms: u64) -> f64 {
        if !self.load.is_finite() || self.load <= 0.0 {
            return 0.0;
        }
        if self.load_updated_at_ms == 0 {
            return self.load;
        }
        // saturating_sub 是 NTP 回拨的唯一防线：裸减法给出负 elapsed，
        // 经 powf 变成 >1 的因子，load 会反向**增长**。
        let elapsed = now_unix_ms.saturating_sub(self.load_updated_at_ms) as f64;
        if elapsed <= 0.0 {
            return self.load;
        }
        let decayed = self.load * 0.5f64.powf(elapsed / LOAD_HALF_LIFE_MS);
        if !decayed.is_finite() || decayed < LOAD_EPSILON {
            0.0
        } else {
            decayed
        }
    }

    /// 写侧：把 `load` 就地衰减到 `now_unix_ms`，并推进 `load_updated_at_ms`。
    fn decay_load_to(&mut self, now_unix_ms: u64) {
        // 基准合理性检查（#98 返工 MUST FIX）：若 `load_updated_at_ms` 超前当前墙钟
        // 超过一个半衰期，视其为不可信、强制拉回当前墙钟——`load` 本身不动，因为
        // 此刻已无法推断该衰减多少，保守地按"不衰减"处理。
        //
        // 触发场景：宿主墙钟被短暂校正前跳（chrony 收敛前 / VM 快照恢复 / RTC 故障），
        // 该凭据恰在前跳窗口内被记了一笔，`load_updated_at_ms` 被盖上一个远未来的戳；
        // 随后墙钟被 NTP 步进校正回正确时间。此时下面这段之前的逻辑会一直判定
        // `now_unix_ms <= load_updated_at_ms`（时钟"倒退"），既不衰减 `load` 也不
        // 推进基准——直到真实时间重新追上那个远未来的戳为止，其间该凭据的排序键
        // 单调只增不减，balanced 模式会一直跳过它。
        //
        // 阈值刻意取 `LOAD_HALF_LIFE_MS` 本身，不另立更小的常量：更小的阈值会把
        // T2（时钟小幅回退时暂停衰减、追上即自愈）那条既有路径一并破坏掉；取一个
        // 半衰期同时把这里能覆盖到的最坏冻结时间封顶到与"已知代价 4"（未被校正的
        // 前跳，一次性归零、自愈时间=一个半衰期）同一量级。
        //
        // 残留窗口（已知、有界）：本函数只在该凭据被 `record_load`/`decay_load_to`
        // 触达时才生效——若凭据因 load 偏高而一直不被选中、进程又不重启，这里够
        // 不着它，要等 `load_stats` 载入回填处（下次重启）才自愈。不为消灭这个残留
        // 窗口去改排序路径或引入定时扫描，那会引入更难推理的状态。
        if self.load_updated_at_ms > now_unix_ms
            && self.load_updated_at_ms - now_unix_ms > LOAD_HALF_LIFE_MS as u64
        {
            self.load_updated_at_ms = now_unix_ms;
        }
        self.load = self.current_load(now_unix_ms);
        // 时钟倒退时不推进基准，否则恢复正常后会一次性补算掉本不该衰减的那段。
        if now_unix_ms > self.load_updated_at_ms || self.load_updated_at_ms == 0 {
            self.load_updated_at_ms = now_unix_ms;
        }
    }

    /// 先就地衰减到当前时刻，再叠加本次调用的权重增量。
    fn record_load(&mut self, weight: f64, now_unix_ms: u64) {
        self.decay_load_to(now_unix_ms);
        let w = if weight.is_finite() && weight > 0.0 {
            weight
        } else {
            1.0
        };
        self.load += w;
    }
}

/// 禁用原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisabledReason {
    /// Admin API 手动禁用
    Manual,
    /// 连续失败达到阈值后自动禁用
    TooManyFailures,
    /// Token 刷新连续失败达到阈值后自动禁用
    TooManyRefreshFailures,
    /// 额度已用尽（如 MONTHLY_REQUEST_COUNT）
    QuotaExceeded,
    /// Refresh Token 永久失效（服务端返回 invalid_grant）
    InvalidRefreshToken,
    /// 凭据配置无效（如 authMethod=api_key 但缺少 kiroApiKey）
    InvalidConfig,
}

/// 统计数据持久化条目
#[derive(Serialize, Deserialize)]
struct StatsEntry {
    success_count: u64,
    #[serde(default, deserialize_with = "de_finite_load")]
    load: f64,
    #[serde(default)]
    load_updated_at_ms: u64,
    last_used_at: Option<String>,
}

/// `f64` 落盘防护的读侧收口点：`serde_json` 把非有限浮点静默写成 `null`，
/// 而裸 `Option<f64>` 反序列化遇 `null` 会报错——若不特殊处理，一个脏值就会
/// 让整份 `kiro_stats.json` 被 `load_stats` 判定解析失败、整文件丢弃，
/// 连带 success_count / last_used_at 一起归零。这里把任何非有限或负数一律
/// 兜底成 `0.0`，与写侧 `save_stats_locked_at` 的落盘防护对称。
fn de_finite_load<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<f64>::deserialize(d)?
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0))
}

/// sticky 子系统时钟抽象（#86），仅用于 TTL / LRU 判定。
///
/// 返回值语义：**自某个固定进程内基准点起的单调递增毫秒数**。绝对时刻无意义，只有差值有意义。
///
/// 单调性是硬约束：**生产实现只允许基于 `Instant`**，代码内禁止出现
/// `SystemTime` / `UNIX_EPOCH` / `chrono::Utc::now`。一旦生产 NTP 回退，回退超过
/// sticky TTL（6 小时）会让全表瞬间"过期"被清空——等于把本 PR 修的"未到阈值误清"
/// 缺陷以更狠的形式重新引入；回退期间新写入的 last_used_at 大于后续读到的 now_ms，
/// entry 则永不过期也永不被 LRU 选中。所有时间差调用方必须 `saturating_sub`，
/// 不做裸减法——即便实现被改坏也只退化成"不过期"，不会 underflow 成天文数字导致全表误清。
pub(crate) trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;

    /// `#98`：balanced 负载衰减用的**墙钟** Unix 毫秒。与上面的 `now_ms()`
    /// 是两条互不相通的时间轴——`now_ms()` 是进程内单调相对毫秒，重启后基准
    /// 归零；衰减需要跨进程重启仍能解释"停机了多久"，只能用墙钟。
    ///
    /// **sticky 子系统禁止调用这个方法**：sticky 的 TTL/LRU 判定必须留在
    /// `now_ms()` 的单调轴上（见上方 trait 文档的 NTP 回退论证），混用会把
    /// 两套时间语义绞在一起，NTP 回退时行为不再可预测。
    fn now_unix_ms(&self) -> u64;
}

/// 生产时钟实现：基于进程启动时捕获的 `Instant` 基准，天然单调不回退。
struct ProcessClock {
    base: Instant,
}

impl ProcessClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Clock for ProcessClock {
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn now_unix_ms(&self) -> u64 {
        Utc::now().timestamp_millis().max(0) as u64
    }
}

/// 会话粘性映射条目
struct StickySessionEntry {
    credential_id: u64,
    /// 相对 `Clock::now_ms()` 基准点的毫秒数，跨进程无意义，绝不进 `save_stats` 持久化载荷。
    last_used_at: u64,
}

// ============================================================================
// Admin API 公开结构
// ============================================================================

/// 凭据条目快照（用于 Admin API 读取）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntrySnapshot {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// Token 过期时间
    pub expires_at: Option<String>,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 端点名称（未显式配置时返回 None，由 Admin 层回退到默认值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// 凭据管理器状态快照
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSnapshot {
    /// 凭据条目列表
    pub entries: Vec<CredentialEntrySnapshot>,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 总凭据数量
    pub total: usize,
    /// 可用凭据数量
    pub available: usize,
}

/// 多凭据 Token 管理器
///
/// 支持多个凭据的管理，实现固定优先级 + 故障转移策略
/// 故障统计基于 API 调用结果，而非 Token 刷新结果
pub struct MultiTokenManager {
    config: Config,
    proxy: Option<ProxyConfig>,
    /// 凭据条目列表
    entries: Mutex<Vec<CredentialEntry>>,
    /// 当前活动凭据 ID
    current_id: Mutex<u64>,
    /// Token 刷新锁，确保同一时间只有一个刷新操作
    refresh_lock: TokioMutex<()>,
    /// 凭据文件路径（用于回写）
    credentials_path: Option<PathBuf>,
    /// 序列化 credentials 的快照、序列化和写入，防止旧快照覆盖新更新。
    credentials_save_lock: Mutex<()>,
    /// 是否为多凭据格式（数组格式才回写）
    is_multiple_format: bool,
    /// 负载均衡模式（运行时可修改）
    load_balancing_mode: Mutex<String>,
    /// 最近一次统计持久化*尝试*时间（用于 debounce；#86 返工 SUGGESTION：
    /// 无论落盘成败都推进，语义是"上次尝试"而非"上次成功"，与脏状态解耦——
    /// 否则坏盘场景下每个请求都会因快判恒真而去抢 `stats_save_lock`）
    last_stats_save_at: Mutex<Option<Instant>>,
    /// 统计数据变更版本号（#86 返工 MUST FIX 1）：`save_stats_debounced` 每次
    /// 标记变更时递增。与 `stats_saved_version` 配合表达"脏"语义，参见下方字段注释。
    stats_dirty_version: AtomicU64,
    /// 已成功落盘覆盖到的版本号。"脏" = `stats_dirty_version != stats_saved_version`。
    ///
    /// 用版本号取代原先的 `AtomicBool`，是因为布尔值无法区分"这次标记发生在快照
    /// 之前"还是"快照之后"：`save_stats_locked` 在取 entries 快照*之前*先读一次
    /// `stats_dirty_version`，成功落盘后只把 `stats_saved_version` 推进到那个读到
    /// 的值——若快照期间又有新变更把 `stats_dirty_version` 继续递增，两者就不相等，
    /// 状态依然是脏，`Drop` 会兜底重试。任何非成功出口（写失败/序列化失败/无路径）
    /// 一律不触碰 `stats_saved_version`，脏状态保持不变。
    stats_saved_version: AtomicU64,
    /// 统计落盘专用锁（#86 返工 MUST FIX 1）：序列化 `save_stats_locked` 的所有
    /// 调用方（`save_stats_debounced` 的惊群路径 + Admin API 直接调用 + `Drop`
    /// 兜底落盘），避免并发 truncate+write 同一个 tmp 路径产生 torn write。
    /// 锁序：`stats_save_lock → entries`，不得反向持锁。
    stats_save_lock: Mutex<()>,
    /// balanced 模式下的会话粘性映射：session_id -> credential_id
    sticky_sessions: Mutex<HashMap<String, StickySessionEntry>>,
    /// 最近一次会话粘性全量清理时间（Clock 相对毫秒数，#86 返工 S3：与 sticky
    /// 子系统其余时间量一致地经 Clock 取时，测试才能靠 TestClock 推进确定性
    /// 触发周期清扫分支，不必再靠撑爆 MAX_STICKY_SESSIONS 间接触发）
    last_sticky_prune_at: Mutex<Option<u64>>,
    /// 模型注册表
    model_registry: Arc<ModelRegistry>,
    /// sticky 子系统专用时钟（#86）。生产恒为 `ProcessClock`，经 `new()` 构造时注入；
    /// 测试通过 `new_with_clock` 在构造期传入可手动推进的实现以驱动 TTL/LRU 判定。
    ///
    /// 构造后从不更换（#86 返工 S2）：生产唯一构造入口 `main.rs` 只调用 `new()`，
    /// 故不需要运行期互斥保护，退化为普通 `Arc`。若改为运行期可换钟的 setter，
    /// 在已有 sticky entry 写入之后换钟，新钟读数可能小于既有 `last_used_at`，
    /// `saturating_sub` 恒为 0 会导致该 entry 永不过期——构造期一次性注入从设计上
    /// 排除了这个形态，不是"暂时没坑"而是"结构上不存在这条路径"。
    clock: Arc<dyn Clock>,
    /// Loopback-only endpoint override used by in-module integration tests.
    #[cfg(test)]
    test_profile_lookup_url: Mutex<Option<String>>,
    /// Loopback-only usage endpoint override used by in-module integration tests.
    #[cfg(test)]
    test_usage_limits_url: Mutex<Option<String>>,
    /// Counts discovery HTTP attempts in tests, including connection failures.
    #[cfg(test)]
    test_profile_lookup_request_count: AtomicUsize,
    /// Records attempts immediately before the per-credential lookup mutex in tests.
    #[cfg(test)]
    test_profile_lookup_lock_attempts: AtomicUsize,
    /// Wakes deterministic tests after a lookup attempt reaches the mutex boundary.
    #[cfg(test)]
    test_profile_lookup_lock_attempted: tokio::sync::Notify,
    /// Optional test-only barrier placed after a credentials snapshot and before its write.
    #[cfg(test)]
    test_persist_snapshot_hook: Mutex<Option<Arc<PersistSnapshotHook>>>,
    /// Records persist callers immediately before they contend for the save lock.
    #[cfg(test)]
    test_persist_save_lock_attempts: AtomicUsize,
    /// Wakes deterministic tests at the save-lock boundary.
    #[cfg(test)]
    test_persist_save_lock_attempted: tokio::sync::Notify,
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 3;

/// Deterministic test-only pause after the first credentials snapshot.
#[cfg(test)]
struct PersistSnapshotHook {
    snapshot_taken: std::sync::mpsc::SyncSender<()>,
    second_snapshot_taken: tokio::sync::Notify,
    allow_write: Mutex<std::sync::mpsc::Receiver<()>>,
    snapshots: AtomicUsize,
}

/// Profile discovery 失败后按凭据冷却一分钟，避免每个业务请求重复打上游。
const PROFILE_LOOKUP_COOLDOWN_MS: u64 = 60_000;
/// Identity of the credential generation that authorized a profile lookup.
///
/// Both bearer and refresh token participate: a reused numeric ID must never let an old bearer
/// authenticate a request for a replacement credential, even if its refresh token is absent or reused.
#[derive(Clone, PartialEq, Eq)]
struct ProfileLookupIdentity {
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl ProfileLookupIdentity {
    /// Capture the credential fields that make an in-flight profile lookup generation-specific.
    fn from_credentials(credentials: &KiroCredentials) -> Self {
        Self {
            access_token: credentials.access_token.clone(),
            refresh_token: credentials.refresh_token.clone(),
        }
    }

    /// Check whether a current credential is still the generation that created this lookup.
    fn matches(&self, credentials: &KiroCredentials) -> bool {
        self.access_token == credentials.access_token
            && self.refresh_token == credentials.refresh_token
    }
}

/// Result of a profile lookup attempt after the per-credential mutex is acquired.
enum ProfileLookupOutcome {
    Ready,
    IdentityChanged,
}

/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);
/// `#98`：balanced 负载半衰期，写死常量不做配置项——12 小时。
const LOAD_HALF_LIFE_MS: f64 = 12.0 * 60.0 * 60.0 * 1000.0;
/// `#98`：衰减后的 load 低于此阈值直接归零，避免长期停机后残留一个不为 0
/// 但无意义的极小浮点数。`0.5.powf(730) ≈ 2.9e-220`（停机 1 年）不会 panic，
/// 这条只是把"数学上非零但无意义"的尾巴剪掉。
const LOAD_EPSILON: f64 = 1e-6;
/// 会话粘性保留时间（毫秒），避免长期运行时无界增长
const STICKY_SESSION_TTL_MS: u64 = 6 * 60 * 60 * 1000;
/// 会话粘性映射最大容量
const MAX_STICKY_SESSIONS: usize = 10_000;
/// 会话粘性全量 TTL 清理的最小间隔
const STICKY_SESSION_PRUNE_INTERVAL_MS: u64 = 60_000;

/// API 调用上下文
///
/// 绑定特定凭据的调用上下文，确保 token、credentials 和 id 的一致性
/// 用于解决并发调用时 current_id 竞态问题
#[derive(Clone)]
pub struct CallContext {
    /// 凭据 ID（用于 report_success/report_failure）
    pub id: u64,
    /// 凭据信息（用于构建请求头）
    pub credentials: KiroCredentials,
    /// 访问 Token
    pub token: String,
    /// PR-0（可观测性，零行为变更）：本次凭据是否命中 balanced 模式的会话粘性表。
    /// 由 `acquire_context_for_session_excluding` 在返回前回填，`try_ensure_token`
    /// 构造时不知道调用来源，先占位 `None`。仅供 `request outcome` 日志聚合，
    /// 不参与任何凭据选择或故障转移判断。
    ///
    /// PR-0 返工（redteam MUST FIX 2）：三态而非二值——`priority` 模式下会话粘性
    /// 机制根本未启用，若仍用 `bool` 会被日志读者误读成"测量出的命中/未命中"，
    /// 实际是"这个维度压根不适用"。`None` = 粘性机制未启用（priority 模式）；
    /// `Some(true)` = balanced 模式下命中会话粘性表；`Some(false)` = balanced 模式下
    /// 未命中（含"表里有记录但窄竞态 reserve 失败"，见 `acquire_context_for_session_excluding`
    /// 内 sticky 命中但 reserve 返回 `None` 的分支）。
    pub sticky_hit: Option<bool>,
}

impl MultiTokenManager {
    /// 创建多凭据 Token 管理器
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `credentials` - 凭据列表
    /// * `proxy` - 可选的代理配置
    /// * `credentials_path` - 凭据文件路径（用于回写）
    /// * `is_multiple_format` - 是否为多凭据格式（数组格式才回写）
    /// * `model_registry` - 模型注册表
    pub fn new(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
        model_registry: Arc<ModelRegistry>,
    ) -> anyhow::Result<Self> {
        Self::new_with_clock(
            config,
            credentials,
            proxy,
            credentials_path,
            is_multiple_format,
            model_registry,
            Arc::new(ProcessClock::new()),
        )
    }

    /// 与 `new` 等价，额外接受一个显式 `Clock` 实现（#86 返工 S2）。
    ///
    /// 唯一存在理由是让测试在构造期注入可手动推进的时钟——`new()` 就是
    /// `new_with_clock(..., Arc::new(ProcessClock::new()))` 的薄包装，两者共享
    /// 全部构造逻辑，不重复。生产代码只应调用 `new()`。
    fn new_with_clock(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
        model_registry: Arc<ModelRegistry>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        // 计算当前最大 ID，为没有 ID 的凭据分配新 ID
        let max_existing_id = credentials.iter().filter_map(|c| c.id).max().unwrap_or(0);
        let mut next_id = max_existing_id + 1;
        let mut has_new_ids = false;
        let mut has_new_machine_ids = false;
        let config_ref = &config;

        let entries: Vec<CredentialEntry> = credentials
            .into_iter()
            .map(|mut cred| {
                cred.canonicalize_auth_method();
                let id = cred.id.unwrap_or_else(|| {
                    let id = next_id;
                    next_id += 1;
                    cred.id = Some(id);
                    has_new_ids = true;
                    id
                });
                if cred.machine_id.is_none() {
                    cred.machine_id =
                        Some(machine_id::generate_from_credentials(&cred, config_ref));
                    has_new_machine_ids = true;
                }
                CredentialEntry {
                    id,
                    credentials: cred.clone(),
                    failure_count: 0,
                    refresh_failure_count: 0,
                    disabled: cred.disabled, // 从配置文件读取 disabled 状态
                    disabled_reason: if cred.disabled {
                        Some(DisabledReason::Manual)
                    } else {
                        None
                    },
                    success_count: 0,
                    load: 0.0,
                    load_updated_at_ms: 0,
                    in_flight_count: 0,
                    last_used_at: None,
                    profile_lookup_retry_after_ms: None,
                    profile_lookup_lock: Arc::new(TokioMutex::new(())),
                }
            })
            .collect();

        // 校验 API Key 凭据配置完整性：authMethod=api_key 时必须提供 kiroApiKey
        let mut entries = entries;
        for entry in &mut entries {
            if entry.credentials.kiro_api_key.is_none()
                && entry
                    .credentials
                    .auth_method
                    .as_deref()
                    .map(|m| m.eq_ignore_ascii_case("api_key") || m.eq_ignore_ascii_case("apikey"))
                    .unwrap_or(false)
            {
                tracing::warn!(
                    credential_id = entry.id,
                    "凭据配置了 authMethod=api_key 但缺少 kiroApiKey 字段，已自动禁用"
                );
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::InvalidConfig);
            }
        }

        // 检测重复 ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicate_ids = Vec::new();
        for entry in &entries {
            if !seen_ids.insert(entry.id) {
                duplicate_ids.push(entry.id);
            }
        }
        if !duplicate_ids.is_empty() {
            anyhow::bail!("检测到重复的凭据 ID: {:?}", duplicate_ids);
        }

        // 选择初始凭据：优先级最高（priority 最小）的可用凭据，无可用凭据时为 0
        let initial_id = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            .map(|e| e.id)
            .unwrap_or(0);

        let load_balancing_mode = config.load_balancing_mode.clone();
        let manager = Self {
            config,
            proxy,
            entries: Mutex::new(entries),
            current_id: Mutex::new(initial_id),
            refresh_lock: TokioMutex::new(()),
            credentials_path,
            credentials_save_lock: Mutex::new(()),
            is_multiple_format,
            load_balancing_mode: Mutex::new(load_balancing_mode),
            last_stats_save_at: Mutex::new(None),
            stats_dirty_version: AtomicU64::new(0),
            stats_saved_version: AtomicU64::new(0),
            stats_save_lock: Mutex::new(()),
            sticky_sessions: Mutex::new(HashMap::new()),
            last_sticky_prune_at: Mutex::new(None),
            model_registry,
            clock,
            #[cfg(test)]
            test_profile_lookup_url: Mutex::new(None),
            #[cfg(test)]
            test_usage_limits_url: Mutex::new(None),
            #[cfg(test)]
            test_profile_lookup_request_count: AtomicUsize::new(0),
            #[cfg(test)]
            test_profile_lookup_lock_attempts: AtomicUsize::new(0),
            #[cfg(test)]
            test_profile_lookup_lock_attempted: tokio::sync::Notify::new(),
            #[cfg(test)]
            test_persist_snapshot_hook: Mutex::new(None),
            #[cfg(test)]
            test_persist_save_lock_attempts: AtomicUsize::new(0),
            #[cfg(test)]
            test_persist_save_lock_attempted: tokio::sync::Notify::new(),
        };

        // 如果有新分配的 ID 或新生成的 machineId，立即持久化到配置文件
        if has_new_ids || has_new_machine_ids {
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!(error = %e, "补全凭据 ID/machineId 后持久化失败");
            } else {
                tracing::info!("已补全凭据 ID/machineId 并写回配置文件");
            }
        }

        // 加载持久化的统计数据（success_count, last_used_at）
        manager.load_stats();

        Ok(manager)
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 获取凭据总数
    pub fn total_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// 获取可用凭据数量
    pub fn available_count(&self) -> usize {
        self.entries.lock().iter().filter(|e| !e.disabled).count()
    }

    /// sticky 子系统当前时钟读数（毫秒），生产恒经 `ProcessClock`。
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// `#98`：balanced 负载衰减当前墙钟读数（Unix 毫秒），生产恒经 `ProcessClock`。
    /// 不用于 sticky（见 `Clock::now_unix_ms` doc）。
    fn now_unix_ms(&self) -> u64 {
        self.clock.now_unix_ms()
    }

    fn is_entry_available_for_model(&self, entry: &CredentialEntry, model: Option<&str>) -> bool {
        if entry.disabled {
            return false;
        }
        if model
            .map(|m| self.model_registry.is_premium_tier(m))
            .unwrap_or(false)
            && !entry.credentials.supports_opus()
        {
            return false;
        }
        true
    }

    fn is_entry_available_for_model_excluding(
        &self,
        entry: &CredentialEntry,
        model: Option<&str>,
        excluded_ids: &HashSet<u64>,
    ) -> bool {
        !excluded_ids.contains(&entry.id) && self.is_entry_available_for_model(entry, model)
    }

    /// 关联函数（不带 `&self`）：调用方须自行提供 `now_ms`（走 `Clock`），
    /// 以便测试可脱离完整 `MultiTokenManager` 直接驱动 TTL / LRU 判定（#86）。
    fn prune_sticky_sessions(sessions: &mut HashMap<String, StickySessionEntry>, now_ms: u64) {
        sessions
            .retain(|_, entry| now_ms.saturating_sub(entry.last_used_at) <= STICKY_SESSION_TTL_MS);

        if sessions.len() <= MAX_STICKY_SESSIONS {
            return;
        }

        let mut entries: Vec<_> = sessions
            .iter()
            .map(|(session_id, entry)| (session_id.clone(), entry.last_used_at))
            .collect();
        entries.sort_by_key(|(_, last_used_at)| *last_used_at);

        let remove_count = sessions.len() - MAX_STICKY_SESSIONS;
        for (session_id, _) in entries.into_iter().take(remove_count) {
            sessions.remove(&session_id);
        }
    }

    fn maybe_prune_sticky_sessions(&self, sessions: &mut HashMap<String, StickySessionEntry>) {
        let now_ms = self.now_ms();
        let should_prune_by_time = {
            let last = *self.last_sticky_prune_at.lock();
            last.map(|last_ms| now_ms.saturating_sub(last_ms) >= STICKY_SESSION_PRUNE_INTERVAL_MS)
                .unwrap_or(true)
        };

        if should_prune_by_time || sessions.len() > MAX_STICKY_SESSIONS {
            Self::prune_sticky_sessions(sessions, now_ms);
            if should_prune_by_time {
                *self.last_sticky_prune_at.lock() = Some(now_ms);
            }
        }
    }

    fn bind_sticky_session(&self, session_id: &str, credential_id: u64) {
        if session_id.is_empty() {
            return;
        }

        let mut sessions = self.sticky_sessions.lock();
        self.maybe_prune_sticky_sessions(&mut sessions);

        let now_ms = self.now_ms();
        if let Some(entry) = sessions.get_mut(session_id) {
            // 已绑定，仅刷新 last_used_at 保活，绝不覆盖 credential_id。
            // 两种情形走此分支：①命中自己（正常保活）；②本次因 fallback 用了别的凭据
            // （重试漂移）——此时也只刷新时间、不改绑定，正是为防止漂移覆盖。
            // 不变量：bind 永不改写已存在 entry 的 credential_id；
            // credential_id 变更只能由"凭据真失效 → clear → 下次首绑"完成。
            // 热路径零 String 堆分配。
            entry.last_used_at = now_ms;
        } else {
            // 首次绑定：写入新 entry
            sessions.insert(
                session_id.to_string(),
                StickySessionEntry {
                    credential_id,
                    last_used_at: now_ms,
                },
            );
        }

        if sessions.len() > MAX_STICKY_SESSIONS {
            Self::prune_sticky_sessions(&mut sessions, now_ms);
        }
    }

    fn clear_sticky_session_if_matches(&self, session_id: &str, credential_id: u64) {
        let mut sessions = self.sticky_sessions.lock();
        let should_remove = sessions
            .get(session_id)
            .map(|entry| entry.credential_id == credential_id)
            .unwrap_or(false);
        if should_remove {
            sessions.remove(session_id);
        }
    }

    fn clear_sticky_sessions_for_credential(&self, credential_id: u64) {
        let mut sessions = self.sticky_sessions.lock();
        sessions.retain(|_, entry| entry.credential_id != credential_id);
    }

    fn select_sticky_credential(
        &self,
        session_id: &str,
        model: Option<&str>,
        excluded_ids: &HashSet<u64>,
    ) -> Option<(u64, KiroCredentials)> {
        let credential_id = {
            let now_ms = self.now_ms();
            let mut sessions = self.sticky_sessions.lock();
            let entry = sessions.get(session_id)?;
            if now_ms.saturating_sub(entry.last_used_at) > STICKY_SESSION_TTL_MS {
                sessions.remove(session_id);
                return None;
            }
            entry.credential_id
        };

        if excluded_ids.contains(&credential_id) {
            return None;
        }

        let hit = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == credential_id)
                .filter(|e| self.is_entry_available_for_model(e, model))
                .map(|e| (e.id, e.credentials.clone()))
        };

        if hit.is_none() {
            self.clear_sticky_session_if_matches(session_id, credential_id);
        }

        hit
    }

    fn reserve_credential(
        entry: &mut CredentialEntry,
        now: DateTime<Utc>,
    ) -> (u64, KiroCredentials) {
        entry.in_flight_count = entry.in_flight_count.saturating_add(1);
        entry.last_used_at = Some(now.to_rfc3339());
        (entry.id, entry.credentials.clone())
    }

    /// 根据负载均衡模式选择下一个凭据
    ///
    /// - priority 模式：选择优先级最高（priority 最小）的可用凭据
    /// - balanced 模式：均衡选择可用凭据
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    fn select_next_credential_excluding(
        &self,
        model: Option<&str>,
        excluded_ids: &HashSet<u64>,
    ) -> Option<(u64, KiroCredentials)> {
        let mut entries = self.entries.lock();

        // 过滤可用凭据
        let available: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.is_entry_available_for_model_excluding(entry, model, excluded_ids)
            })
            .map(|(idx, _)| idx)
            .collect();

        if available.is_empty() {
            return None;
        }

        let mode = self.load_balancing_mode.lock().clone();
        let mode = mode.as_str();

        match mode {
            "balanced" => {
                // 按衰减 credit 负载排序（#98）：load 是按调用权重累加、随时间
                // 指数衰减的读侧惰性值；in_flight 按本次请求权重折算成同一量纲
                // 一起参与比较，平局按优先级、再按 id 决胜。
                let now_unix_ms = self.now_unix_ms();
                let weight = self.model_registry.credit_weight_by_kiro_id(model);
                let idx = *available.iter().min_by(|a, b| {
                    let (ea, eb) = (&entries[**a], &entries[**b]);
                    let ka = ea.current_load(now_unix_ms) + ea.in_flight_count as f64 * weight;
                    let kb = eb.current_load(now_unix_ms) + eb.in_flight_count as f64 * weight;
                    // f64 非 Ord，必须显式全序。用 total_cmp 而非
                    // partial_cmp().unwrap_or(Equal)：前者把 NaN 排在所有数之后
                    // （NaN 凭据被避开，安全方向失败），后者把 NaN 当平局、让它
                    // 靠 priority 赢下选择。
                    ka.total_cmp(&kb)
                        .then_with(|| ea.credentials.priority.cmp(&eb.credentials.priority))
                        // 第三级 tiebreak：load 完全相等只发生在全 0 场景，而那
                        // 正是启动后第一批请求。无 id 兜底则结果依赖 Vec 迭代
                        // 顺序，测试会变成薛定谔的绿。独立覆盖见
                        // test_balanced_tiebreak_picks_smaller_id_regardless_of_insertion_order
                        // （构造插入序与 id 大小顺序相反的凭据）。
                        .then_with(|| ea.id.cmp(&eb.id))
                })?;

                Some(Self::reserve_credential(&mut entries[idx], Utc::now()))
            }
            _ => {
                // priority 模式（默认）：选择优先级最高的
                let idx = available
                    .iter()
                    .min_by_key(|idx| entries[**idx].credentials.priority)?;
                Some(Self::reserve_credential(&mut entries[*idx], Utc::now()))
            }
        }
    }

    fn reserve_existing_credential_excluding(
        &self,
        id: u64,
        model: Option<&str>,
        excluded_ids: &HashSet<u64>,
    ) -> Option<(u64, KiroCredentials)> {
        if excluded_ids.contains(&id) {
            return None;
        }
        let mut entries = self.entries.lock();
        let entry = entries
            .iter_mut()
            .find(|e| e.id == id && self.is_entry_available_for_model(e, model))?;
        Some(Self::reserve_credential(entry, Utc::now()))
    }

    /// 获取 API 调用上下文
    ///
    /// 返回绑定了 id、credentials 和 token 的调用上下文
    /// 确保整个 API 调用过程中使用一致的凭据信息
    ///
    /// 如果 Token 过期或即将过期，会自动刷新
    /// Token 刷新失败会累计到当前凭据，达到阈值后禁用并切换
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    #[allow(dead_code)]
    pub async fn acquire_context(&self, model: Option<&str>) -> anyhow::Result<CallContext> {
        self.acquire_context_for_session(model, None).await
    }

    /// 获取指定会话的 API 调用上下文。
    ///
    /// balanced 模式下会优先复用同一 session 最近成功绑定的凭据；
    /// priority 模式保持原有固定优先级行为。
    #[allow(dead_code)]
    pub async fn acquire_context_for_session(
        &self,
        model: Option<&str>,
        session_id: Option<&str>,
    ) -> anyhow::Result<CallContext> {
        self.acquire_context_for_session_excluding(model, session_id, &HashSet::new())
            .await
    }

    /// 获取指定会话的 API 调用上下文，并临时跳过本次请求中已失败的凭据。
    pub(crate) async fn acquire_context_for_session_excluding(
        &self,
        model: Option<&str>,
        session_id: Option<&str>,
        excluded_ids: &HashSet<u64>,
    ) -> anyhow::Result<CallContext> {
        self.acquire_context_for_session_excluding_pinned(model, session_id, excluded_ids, None)
            .await
    }

    /// `#101`：与 [`Self::acquire_context_for_session_excluding`] 完全相同，多接受一个
    /// `pinned_id`——调用方（目前只有 `call_api_with_retry` 的瞬态重试路径）传入
    /// "上一次尝试已选中、这次仍想复用"的凭据 id。
    ///
    /// 动机（裁决理由，见 PR #101 评审 MUST FIX 1）：D3 保留"5xx/429 重试但不切换
    /// 凭据"，其动机是换凭据会打断上游按内容前缀命中的缓存折扣（本仓黑盒结论
    /// ~47% credits）。`#98` 把 balanced 模式的选路依据从"success_count 累加、
    /// 瞬态失败不影响排序键"改成了"current_load + in_flight 实时重排"——而
    /// `record_upstream_call` 在 `send()` **之前**就已经给本张记了一笔 load，
    /// 于是紧跟着的瞬态重试在 balanced 模式下必然把它挤出"当前最低"，重试被
    /// 静默换到另一张凭据。更严重的是：换走之后一旦成功，
    /// `report_success_for_session` 会把整个会话的 sticky 绑到**新**凭据上——
    /// 一次瞬态错误就迁走了整条会话，是 `#86` 修掉的"大面积换号丢热缓存"同构
    /// 复发。本 PR 之前不存在这个问题：旧排序键（`success_count` 主导）在瞬态
    /// 失败时纹丝不动，下一轮自然还选同一张；是 `#98` 让 load 参与排序才打断
    /// 了这条不变量。
    ///
    /// 粘滞只是"偏好"：只在 balanced 模式下生效（`is_balanced` 判据之外，方法
    /// 体与旧签名逐字相同，对 priority 模式零观测差异——priority 本来就靠
    /// `current_id` 粘住，不需要也不该被这里的 pin 覆盖，避免并发场景下
    /// `current_id` 漂移与本调用自身的 pin 产生行为分叉）。命中优先于 sticky
    /// 会话表查找（这是"同一次调用内部的重试"，比跨请求的 session 级绑定更
    /// 具体）；pin 的凭据若在此期间变得不可用（被并发禁用、被 tier 过滤、已在
    /// `excluded_ids` 里）—— `reserve_existing_credential_excluding` 内部的
    /// `is_entry_available_for_model_excluding` 检查会自然返回 `None`——立即
    /// 回落到本方法原有的 sticky/current_id/balanced 选路逻辑，不 bail、不
    /// 空转。复用既有的"按指定 id 预留"能力（`reserve_existing_credential_excluding`，
    /// 本来就是 priority 模式 `current_hit` 用的那条路径），不另造一套平行选路。
    ///
    /// 调用契约：只负责"选谁"，不改变"记不记账"——`record_upstream_call` 仍由
    /// 调用方在 `send()` 之前对每次真实发出的上游调用调用一次；in_flight 的
    /// reserve/release 配对同样不变（pin 命中也走 `reserve_existing_credential_excluding`，
    /// 与非 pin 路径完全相同的 reserve 语义）。
    pub(crate) async fn acquire_context_for_session_excluding_pinned(
        &self,
        model: Option<&str>,
        session_id: Option<&str>,
        excluded_ids: &HashSet<u64>,
        pinned_id: Option<u64>,
    ) -> anyhow::Result<CallContext> {
        let total = self.total_count();
        let max_attempts = (total * MAX_FAILURES_PER_CREDENTIAL as usize).max(1);
        let mut attempt_count = 0;
        let session_id = session_id.filter(|s| !s.is_empty());
        // Identity churn is only a temporary exclusion for this acquire; never mutate the caller's set.
        let mut selection_excluded_ids = excluded_ids.clone();

        loop {
            if attempt_count >= max_attempts {
                anyhow::bail!(
                    "所有凭据均无法获取有效 Token（可用: {}/{}）",
                    self.available_count(),
                    total
                );
            }

            let (id, credentials, sticky_hit) = {
                let is_balanced = self.load_balancing_mode.lock().as_str() == "balanced";

                // `#101`：pin 只在 balanced 模式生效、且优先于 sticky 会话表查找
                // （见方法 doc comment）；priority 模式忽略 pinned_id，走下方与
                // 旧签名完全相同的 current_hit 分支，零观测差异。
                let pin_hit = if is_balanced {
                    pinned_id.and_then(|pid| {
                        self.reserve_existing_credential_excluding(
                            pid,
                            model,
                            &selection_excluded_ids,
                        )
                    })
                } else {
                    None
                };

                let sticky_hit = if pin_hit.is_none() && is_balanced {
                    session_id.and_then(|sid| {
                        self.select_sticky_credential(sid, model, &selection_excluded_ids)
                    })
                } else {
                    None
                };

                // balanced 模式：每次请求都重新均衡选择，不固定 current_id
                // priority 模式：优先使用 current_id 指向的凭据
                let current_hit = if pin_hit.is_some() || sticky_hit.is_some() || is_balanced {
                    None
                } else {
                    let current_id = *self.current_id.lock();
                    self.reserve_existing_credential_excluding(
                        current_id,
                        model,
                        &selection_excluded_ids,
                    )
                };

                if let Some((pin_id, pin_credentials)) = pin_hit {
                    // pin 命中：这次尝试沿用上一次尝试已选中的凭据。不是 sticky
                    // 会话表命中，也不是"粘性机制未启用"，三态里都不精确对应，
                    // 归为 N/A（None）——与 priority 模式 current_hit 分支同值，
                    // 对下游日志不新增第四态。
                    (pin_id, pin_credentials, None)
                } else if let Some((hit_id, _hit_credentials)) = sticky_hit {
                    match self.reserve_existing_credential_excluding(
                        hit_id,
                        model,
                        &selection_excluded_ids,
                    ) {
                        Some((reserved_id, reserved_credentials)) => {
                            (reserved_id, reserved_credentials, Some(true))
                        }
                        None => {
                            // sticky 命中但 reserve 失败（窄竞态：选择到 reserve 之间凭据被禁用）。
                            // 不清 sticky：凭据禁用时 report_quota_exhausted / report_refresh_failure
                            // 会调 clear_sticky_sessions_for_credential 批量清，acquire 路径不做 clear。
                            let mut best = self
                                .select_next_credential_excluding(model, &selection_excluded_ids);
                            if best.is_none() {
                                let mut entries = self.entries.lock();
                                if entries.iter().any(|e| {
                                    e.disabled
                                        && e.disabled_reason
                                            == Some(DisabledReason::TooManyFailures)
                                }) {
                                    tracing::warn!(
                                        "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
                                    );
                                    for e in entries.iter_mut() {
                                        if e.disabled_reason
                                            == Some(DisabledReason::TooManyFailures)
                                        {
                                            e.disabled = false;
                                            e.disabled_reason = None;
                                            e.failure_count = 0;
                                        }
                                    }
                                    drop(entries);
                                    best = self.select_next_credential_excluding(
                                        model,
                                        &selection_excluded_ids,
                                    );
                                }
                            }
                            if let Some((new_id, new_creds)) = best {
                                let mut current_id = self.current_id.lock();
                                *current_id = new_id;
                                // 窄竞态分支恒在 is_balanced==true 下触发（外层 `if let Some(...) =
                                // sticky_hit` 只在 balanced 模式才可能是 Some），故此处必为 balanced
                                // 下的真实"表里有记录但抢占失败"未命中，不是 N/A。
                                (new_id, new_creds, Some(false))
                            } else {
                                let entries = self.entries.lock();
                                let available = entries.iter().filter(|e| !e.disabled).count();
                                anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                            }
                        }
                    }
                } else if let Some((hit_id, hit_credentials)) = current_hit {
                    // current_hit 只在 is_balanced==false 时才可能非 None（见上方
                    // `let current_hit = if pin_hit.is_some() || sticky_hit.is_some() ||
                    // is_balanced { None } else {...}`；pin_hit 恒为 None 因为它本身只在
                    // is_balanced 时才会被求值为 Some），即此分支恒为 priority 模式，
                    // 粘性机制未启用，语义是 N/A 不是"未命中"。
                    (hit_id, hit_credentials, None)
                } else {
                    // 当前凭据不可用或 balanced 模式，根据负载均衡策略选择
                    let mut best =
                        self.select_next_credential_excluding(model, &selection_excluded_ids);

                    // 没有可用凭据：如果是"自动禁用导致全灭"，做一次类似重启的自愈
                    if best.is_none() {
                        let mut entries = self.entries.lock();
                        if entries.iter().any(|e| {
                            e.disabled && e.disabled_reason == Some(DisabledReason::TooManyFailures)
                        }) {
                            tracing::warn!(
                                "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
                            );
                            for e in entries.iter_mut() {
                                if e.disabled_reason == Some(DisabledReason::TooManyFailures) {
                                    e.disabled = false;
                                    e.disabled_reason = None;
                                    e.failure_count = 0;
                                }
                            }
                            drop(entries);
                            best = self
                                .select_next_credential_excluding(model, &selection_excluded_ids);
                        }
                    }

                    if let Some((new_id, new_creds)) = best {
                        // 更新 current_id
                        let mut current_id = self.current_id.lock();
                        *current_id = new_id;
                        // 这个分支在 balanced 模式（pin 未命中/未提供 + sticky 桶查无记录，
                        // 真实未命中）和 priority 模式（粘性机制未启用，current_hit 落空只是
                        // 常规选择）都会走到，必须靠 is_balanced 区分，不能像其余分支那样从
                        // 路径本身唯一推出结论。
                        (
                            new_id,
                            new_creds,
                            if is_balanced { Some(false) } else { None },
                        )
                    } else {
                        let entries = self.entries.lock();
                        // 注意：必须在 bail! 之前计算 available_count，
                        // 因为 available_count() 会尝试获取 entries 锁，
                        // 而此时我们已经持有该锁，会导致死锁
                        let available = entries.iter().filter(|e| !e.disabled).count();
                        anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                    }
                }
            };

            // 尝试获取/刷新 Token
            match self.try_ensure_token(id, &credentials).await {
                Ok(mut ctx) => {
                    // PR-0：try_ensure_token 不知道调用来源，真实 sticky_hit 由本层回填。
                    ctx.sticky_hit = sticky_hit;
                    return Ok(ctx);
                }
                Err(e) => {
                    // #98 §F：这次 reserve 恰好释放一次。下面按错误类型可能还会调
                    // report_refresh_token_invalid / report_refresh_failure，但那两个
                    // 函数自身已不再释放 in_flight（责任已收归此处），不会重复减。
                    self.report_no_result(id);
                    attempt_count += 1;
                    // A bounded identity race means this reservation lost its credential generation,
                    // not that the replacement failed to refresh. Keep its counters untouched and
                    // let the normal selection loop retry or choose another available credential.
                    if e.downcast_ref::<ProfileIdentityChangedError>().is_some() {
                        selection_excluded_ids.insert(id);
                        tracing::debug!(
                            credential_id = id,
                            "profile lookup identity changed; retrying credential selection"
                        );
                        continue;
                    }
                    // token 瞬态刷新失败 ≠ 凭据真失效，不清 sticky。
                    // 真失效（refreshToken 永久失效 / 过多失败）走 report_refresh_token_invalid /
                    // report_refresh_failure 累计禁用，禁用时 clear_sticky_sessions_for_credential 负责清。
                    // refreshToken 永久失效 → 立即禁用，不累计重试
                    let has_available =
                        if let Some(invalid) = e.downcast_ref::<RefreshTokenInvalidError>() {
                            tracing::warn!(
                                credential_id = id,
                                error_code = invalid.error_code,
                                error = %e,
                                "refreshToken 永久失效"
                            );
                            self.report_refresh_token_invalid(id)
                        } else {
                            tracing::warn!(credential_id = id, error = %e, "Token 刷新失败");
                            self.report_refresh_failure(id)
                        };
                    if !has_available {
                        anyhow::bail!("所有凭据均已禁用（0/{}）", total);
                    }
                }
            }
        }
    }

    fn release_in_flight(&self, id: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
        }
    }

    /// 选择优先级最高的未禁用凭据作为当前凭据（内部方法）
    ///
    /// 纯粹按优先级选择，不排除当前凭据，用于优先级变更后立即生效
    fn select_highest_priority(&self) {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（不排除当前凭据）
        if let Some(best) = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            && best.id != *current_id
        {
            tracing::info!(
                from_credential_id = *current_id,
                credential_id = best.id,
                priority = best.credentials.priority,
                "优先级变更后切换凭据"
            );
            *current_id = best.id;
        }
    }

    /// Fetch profiles from a fixed endpoint. This boundary is separate so tests can use loopback URLs.
    async fn list_available_profiles_at(
        full_url: &str,
        credentials: &KiroCredentials,
        config: &Config,
        token: &str,
        proxy: Option<&ProxyConfig>,
    ) -> anyhow::Result<ListAvailableProfilesResponse> {
        let region = credentials.effective_api_region(config);
        let host = full_url
            .split("//")
            .nth(1)
            .and_then(|value| value.split('/').next())
            .ok_or_else(|| anyhow::anyhow!("profile discovery URL 缺少 host"))?;
        let machine_id = machine_id::generate_from_credentials(credentials, config);
        let client = build_client(proxy, 60, config.tls_backend)?;
        let response = client
            .post(full_url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header(
                "x-amz-user-agent",
                format!(
                    "aws-sdk-js/1.0.0 KiroIDE-{}-{}",
                    config.kiro_version, machine_id
                ),
            )
            .header(
                "User-Agent",
                format!("KiroIDE-{}-{}", config.kiro_version, machine_id),
            )
            .header("host", host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close")
            .json(&serde_json::json!({}))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(
                target: "kiro_rs::payload",
                status = %status,
                region,
                upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                "ListAvailableProfiles returned a non-success status"
            );
            anyhow::bail!("ListAvailableProfiles failed: {} ({})", status, region);
        }
        Ok(response.json().await?)
    }

    /// Discover profiles through the production q host for this credential's effective API region.
    async fn list_available_profiles(
        &self,
        credentials: &KiroCredentials,
        token: &str,
    ) -> anyhow::Result<ListAvailableProfilesResponse> {
        let region = credentials.effective_api_region(&self.config);
        let production_url = format!("https://q.{}.amazonaws.com/ListAvailableProfiles", region);
        #[cfg(test)]
        let url = self
            .test_profile_lookup_url
            .lock()
            .clone()
            .unwrap_or(production_url);
        #[cfg(not(test))]
        let url = production_url;
        #[cfg(test)]
        self.test_profile_lookup_request_count
            .fetch_add(1, Ordering::SeqCst);
        let proxy = credentials.effective_proxy(self.proxy.as_ref());
        Self::list_available_profiles_at(&url, credentials, &self.config, token, proxy.as_ref())
            .await
    }

    /// Remove an invalid OAuth profile ARN from a request-only credentials snapshot.
    ///
    /// Discovery failure must preserve the operator-provided entry for a later retry, but callers
    /// must never emit malformed profile ARN values into business or usage requests.
    fn request_credentials_snapshot(mut credentials: KiroCredentials) -> KiroCredentials {
        if !credentials
            .profile_arn
            .as_deref()
            .is_some_and(is_valid_profile_arn)
        {
            credentials.profile_arn = None;
        }
        credentials
    }

    /// Acquire the newest credentials and token for one ID, then best-effort discover its profile ARN.
    async fn acquire_latest_credentials_and_token(
        &self,
        id: u64,
    ) -> anyhow::Result<(KiroCredentials, String)> {
        let initial = self.credentials_for_id(id)?;
        if initial.is_api_key_credential() {
            let token = initial
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok((initial, token));
        }

        if is_token_expired(&initial) || is_token_expiring_soon(&initial) {
            let refreshed = {
                let _refresh_guard = self.refresh_lock.lock().await;
                let current = self.credentials_for_id(id)?;
                if !is_token_expired(&current) && !is_token_expiring_soon(&current) {
                    None
                } else {
                    let refresh_token_identity = current.refresh_token.clone();
                    let proxy = current.effective_proxy(self.proxy.as_ref());
                    let refreshed = refresh_token(&current, &self.config, proxy.as_ref()).await?;
                    if is_token_expired(&refreshed) {
                        anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                    }
                    Some((refresh_token_identity, refreshed))
                }
            };
            if let Some((refresh_token_identity, refreshed)) = refreshed
                && self.replace_refreshed_credentials(
                    id,
                    refresh_token_identity.as_deref(),
                    refreshed,
                )
                && let Err(error) = self.persist_credentials()
            {
                tracing::warn!(error = %error, "Token 刷新后持久化失败（不影响本次请求）");
            }
        }

        // A replacement may happen while waiting for its profile mutex. Retry from a fresh snapshot
        // rather than returning its credentials paired with the old generation's bearer token.
        const MAX_PROFILE_IDENTITY_RETRIES: usize = 2;
        for _ in 0..MAX_PROFILE_IDENTITY_RETRIES {
            let current = self.credentials_for_id(id)?;
            let token = current
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;
            if current
                .profile_arn
                .as_deref()
                .is_some_and(is_valid_profile_arn)
            {
                return Ok((Self::request_credentials_snapshot(current), token));
            }

            let identity = ProfileLookupIdentity::from_credentials(&current);
            match self.discover_profile_arn(id, identity).await {
                ProfileLookupOutcome::Ready => {
                    let latest = self.credentials_for_id(id)?;
                    let latest_token = latest
                        .access_token
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;
                    return Ok((Self::request_credentials_snapshot(latest), latest_token));
                }
                ProfileLookupOutcome::IdentityChanged => continue,
            }
        }
        Err(ProfileIdentityChangedError.into())
    }

    /// Single-flight profile discovery. Failure is deliberately best-effort and only cools this credential.
    async fn discover_profile_arn(
        &self,
        id: u64,
        expected_identity: ProfileLookupIdentity,
    ) -> ProfileLookupOutcome {
        let lock = {
            let entries = self.entries.lock();
            match entries.iter().find(|entry| entry.id == id) {
                Some(entry) => entry.profile_lookup_lock.clone(),
                None => return ProfileLookupOutcome::IdentityChanged,
            }
        };
        #[cfg(test)]
        {
            self.test_profile_lookup_lock_attempts
                .fetch_add(1, Ordering::SeqCst);
            self.test_profile_lookup_lock_attempted.notify_waiters();
        }

        let discovered = {
            let _lookup_guard = lock.lock().await;
            let current = match self.credentials_for_id(id) {
                Ok(credentials) => credentials,
                Err(_) => return ProfileLookupOutcome::IdentityChanged,
            };
            // This is the final identity check immediately before HTTP. The token passed to reqwest
            // is obtained from this same current snapshot, never from the pre-mutex generation.
            if !expected_identity.matches(&current) {
                return ProfileLookupOutcome::IdentityChanged;
            }
            if current
                .profile_arn
                .as_deref()
                .is_some_and(is_valid_profile_arn)
            {
                return ProfileLookupOutcome::Ready;
            }
            let cooling = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|entry| entry.id == id)
                    .filter(|entry| expected_identity.matches(&entry.credentials))
                    .and_then(|entry| entry.profile_lookup_retry_after_ms)
                    .is_some_and(|deadline| self.now_ms() < deadline)
            };
            if cooling {
                return ProfileLookupOutcome::Ready;
            }
            let token = match current.access_token.as_deref() {
                Some(token) => token,
                None => return ProfileLookupOutcome::IdentityChanged,
            };

            match self
                .list_available_profiles(&current, token)
                .await
                .and_then(|response| {
                    select_profile_arn(
                        response.profiles,
                        current.effective_api_region(&self.config),
                    )
                    .ok_or_else(|| anyhow::anyhow!("ListAvailableProfiles 未返回可用 ARN"))
                }) {
                Ok(profile_arn) => {
                    let mut entries = self.entries.lock();
                    let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) else {
                        return ProfileLookupOutcome::IdentityChanged;
                    };
                    if !expected_identity.matches(&entry.credentials) {
                        return ProfileLookupOutcome::IdentityChanged;
                    }
                    entry.credentials.profile_arn = Some(profile_arn);
                    entry.profile_lookup_retry_after_ms = None;
                    true
                }
                Err(error) => {
                    let retry_after_ms = self.now_ms().saturating_add(PROFILE_LOOKUP_COOLDOWN_MS);
                    let mut entries = self.entries.lock();
                    let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) else {
                        return ProfileLookupOutcome::IdentityChanged;
                    };
                    if !expected_identity.matches(&entry.credentials) {
                        return ProfileLookupOutcome::IdentityChanged;
                    }
                    entry.profile_lookup_retry_after_ms = Some(retry_after_ms);
                    tracing::warn!(credential_id = id, error = %error, "profile discovery 失败，冷却后重试");
                    false
                }
            }
        };

        if discovered && let Err(error) = self.persist_credentials() {
            tracing::warn!(error = %error, "profile ARN 持久化失败（使用内存值继续本次请求）");
        }
        ProfileLookupOutcome::Ready
    }

    /// Merge a refresh response without allowing an omitted optional ARN to erase discovery.
    fn merge_refreshed_credentials(
        current: &KiroCredentials,
        mut refreshed: KiroCredentials,
    ) -> KiroCredentials {
        if refreshed.profile_arn.is_none() {
            refreshed.profile_arn = current.profile_arn.clone();
        }
        refreshed
    }

    /// Replace an OAuth credential only when its non-logged refresh-token identity still matches.
    ///
    /// Admin deletion followed by insertion can reuse a numeric ID while an HTTP request is pending.
    /// A mismatch means the old result is stale and must be discarded rather than contaminating the
    /// new entry.
    fn replace_refreshed_credentials(
        &self,
        id: u64,
        refresh_token_identity: Option<&str>,
        refreshed: KiroCredentials,
    ) -> bool {
        let mut entries = self.entries.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) else {
            return false;
        };
        if entry.credentials.refresh_token.as_deref() != refresh_token_identity {
            return false;
        }
        entry.credentials = Self::merge_refreshed_credentials(&entry.credentials, refreshed);
        true
    }

    /// Apply a forced-refresh response only to the credential generation that requested it.
    ///
    /// An admin delete/reinsert can reuse `id` while refresh HTTP is pending. Reporting success in
    /// that case lies to the caller and can leave them believing a replacement credential was refreshed.
    fn apply_forced_refresh(
        &self,
        id: u64,
        expected_refresh_token: Option<&str>,
        refreshed: KiroCredentials,
    ) -> anyhow::Result<()> {
        if !self.replace_refreshed_credentials(id, expected_refresh_token, refreshed) {
            anyhow::bail!(
                "凭据 #{} 在强制刷新期间已删除或替换，已丢弃过期刷新结果",
                id
            );
        }
        if let Some(entry) = self.entries.lock().iter_mut().find(|entry| entry.id == id) {
            entry.refresh_failure_count = 0;
        }
        if let Err(error) = self.persist_credentials() {
            tracing::warn!(error = %error, "强制刷新 Token 后持久化失败");
        }
        Ok(())
    }

    fn credentials_for_id(&self, id: u64) -> anyhow::Result<KiroCredentials> {
        self.entries
            .lock()
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.credentials.clone())
            .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))
    }

    /// Thin CallContext adapter that preserves the established refresh-failure counter behavior.
    async fn try_ensure_token(
        &self,
        id: u64,
        _credentials: &KiroCredentials,
    ) -> anyhow::Result<CallContext> {
        let (credentials, token) = self.acquire_latest_credentials_and_token(id).await?;
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                entry.refresh_failure_count = 0;
            }
        }
        Ok(CallContext {
            id,
            credentials,
            token,
            sticky_hit: None,
        })
    }

    /// 将凭据列表回写到源文件
    ///
    /// 仅在以下条件满足时回写：
    /// - 源文件是多凭据格式（数组）
    /// - credentials_path 已设置
    ///
    /// # Returns
    /// - `Ok(true)` - 成功写入文件
    /// - `Ok(false)` - 跳过写入（非多凭据格式或无路径配置）
    /// - `Err(_)` - 写入失败
    fn persist_credentials(&self) -> anyhow::Result<bool> {
        use anyhow::Context;

        // 仅多凭据格式才回写
        if !self.is_multiple_format {
            return Ok(false);
        }

        let path = match &self.credentials_path {
            Some(p) => p,
            None => return Ok(false),
        };

        // The entire synchronous critical section must leave Tokio workers, including waiting for
        // the parking_lot mutex. Entering block_in_place after lock() would still starve a worker.
        let persist = || -> anyhow::Result<()> {
            #[cfg(test)]
            {
                self.test_persist_save_lock_attempts
                    .fetch_add(1, Ordering::SeqCst);
                self.test_persist_save_lock_attempted.notify_waiters();
            }
            let _save_guard = self.credentials_save_lock.lock();
            let credentials: Vec<KiroCredentials> = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .map(|entry| {
                        let mut credential = entry.credentials.clone();
                        credential.canonicalize_auth_method();
                        credential.disabled = entry.disabled;
                        credential
                    })
                    .collect()
            };

            #[cfg(test)]
            if let Some(hook) = self.test_persist_snapshot_hook.lock().clone() {
                if hook.snapshots.fetch_add(1, Ordering::SeqCst) == 0 {
                    hook.snapshot_taken
                        .send(())
                        .expect("test must wait for the first credentials snapshot");
                    hook.allow_write
                        .lock()
                        .recv()
                        .expect("test must release the first credentials write");
                } else {
                    hook.second_snapshot_taken.notify_waiters();
                }
            }

            let json = serde_json::to_string_pretty(&credentials).context("序列化凭据失败")?;
            std::fs::write(path, &json).with_context(|| format!("回写凭据文件失败: {:?}", path))
        };

        let is_multi_thread_runtime = tokio::runtime::Handle::try_current()
            .map(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        if is_multi_thread_runtime {
            tokio::task::block_in_place(persist)?;
        } else {
            persist()?;
        }

        tracing::debug!(path = ?path, "已回写凭据到文件");
        Ok(true)
    }

    /// 获取缓存目录（凭据文件所在目录）
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.credentials_path
            .as_ref()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    /// 统计数据文件路径
    fn stats_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_stats.json"))
    }

    /// 从磁盘加载统计数据并应用到当前条目
    fn load_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };

        let stats: HashMap<String, StatsEntry> = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "解析统计缓存失败，将忽略");
                return;
            }
        };

        let now_unix_ms = self.now_unix_ms();
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.load = s.load;
                entry.load_updated_at_ms = s.load_updated_at_ms;
                entry.last_used_at = s.last_used_at.clone();
                // 基准合理性检查（#98 返工 MUST FIX，与 `decay_load_to` 同一判据）：
                // 磁盘上的 `load_updated_at_ms` 若超前当前墙钟超过一个半衰期，说明
                // 落盘时宿主墙钟正处于前跳窗口内、之后被校正——这是本缺陷"跨重启
                // 存活"的那一面：不重置就要靠该凭据下次被 `decay_load_to`/`record_load`
                // 触达才自愈，而它恰恰因排序键偏高一直选不中，导致只能手工改
                // `kiro_stats.json`。载入即重置让重启本身就是自愈点。`load` 值不动，
                // 理由同 `decay_load_to`。
                if entry.load_updated_at_ms > now_unix_ms
                    && entry.load_updated_at_ms - now_unix_ms > LOAD_HALF_LIFE_MS as u64
                {
                    entry.load_updated_at_ms = now_unix_ms;
                }
            }
        }
        *self.last_stats_save_at.lock() = Some(Instant::now());
        // 启动时加载即视为与磁盘一致：把已落盘版本推进到当前版本（此刻恒为 0，
        // 但写法上与 save_stats_locked 保持同一形状，不假设初始值）。
        let version = self.stats_dirty_version.load(Ordering::SeqCst);
        self.stats_saved_version.store(version, Ordering::SeqCst);
        tracing::info!(count = stats.len(), "已从缓存加载统计数据");
    }

    /// 实际执行统计数据落盘的写入逻辑。
    ///
    /// **调用方必须已持有 `stats_save_lock`**（#86 返工 MUST FIX 1）：本函数不
    /// 自行加锁，是给 `save_stats` / `save_stats_debounced` 复用的内部构件，
    /// 避免同一把 `parking_lot::Mutex`（不可重入）被同一线程二次获取而死锁。
    fn save_stats_locked(&self) {
        self.save_stats_locked_at(|| {});
    }

    /// `save_stats_locked` 的实现体，多接受一个 `at_snapshot` 钩子。
    ///
    /// 钩子在读完 `version_at_snapshot`、取 entries 快照之前被调用一次——这正是
    /// MUST FIX 1 修的竞态窗口本身（另一线程在此期间修改 entries 并标记脏，会被
    /// 当前落盘"看不见"）。生产路径（`save_stats_locked`）传空闭包，零行为影响；
    /// 测试用它在单线程、无 sleep 的前提下确定性地把"并发新变更"注入到这个真实
    /// 存在但无法用外部调用序列自然复现的窗口内，见 `test_stats_dirty_survives_change_during_inflight_flush`。
    ///
    /// # 调用契约
    /// 复述 `save_stats_locked`（`:1551`）的前提：调用方必须已持有
    /// `stats_save_lock`。且 `at_snapshot` 闭包在这把锁的临界区*内部*执行——
    /// 闭包内绝不能再去获取 `stats_save_lock`（`parking_lot::Mutex`
    /// 不可重入，同线程重入会死锁），也不能间接调用任何会获取它的方法
    /// （如 `save_stats`/`save_stats_locked`/`save_stats_debounced` 自身）。
    fn save_stats_locked_at(&self, at_snapshot: impl FnOnce()) {
        // #86 返工 SUGGESTION：防抖时钟在函数入口无条件推进，覆盖所有出口（无路径 /
        // 写失败 / 序列化失败 / 成功）——语义是"上次尝试落盘的时刻"而非"上次成功
        // 落盘的时刻"，与下面的脏版本号彻底解耦。否则坏盘时该时钟永远停在很久以前，
        // `save_stats_debounced` 的快判恒真，每个请求都会去抢 `stats_save_lock` 做
        // 一次注定失败的落盘 + 一条 warn 日志。
        *self.last_stats_save_at.lock() = Some(Instant::now());

        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        // #86 返工 MUST FIX 1：必须在取 entries 快照*之前*读版本号。若在快照之后
        // 读，会把快照期间发生的新变更也算作"这次落盘已覆盖"，与旧的 AtomicBool
        // 实现同样的 DCL 竞态——B 线程在 A 快照之后、写盘完成之前修改 entries 并
        // 标记脏，若 A 读到的是"快照之后"的版本号，成功写盘后会把这个更新版本号
        // 误判为"已覆盖"，B 的变更就此永久丢失且不会被 Drop 兜底。
        let version_at_snapshot = self.stats_dirty_version.load(Ordering::SeqCst);

        at_snapshot();

        let stats: HashMap<String, StatsEntry> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    (
                        e.id.to_string(),
                        StatsEntry {
                            success_count: e.success_count,
                            // `serde_json` 无法表示非有限浮点，会静默写成 `null`，
                            // 而 `null` 在读侧是解析错误——双重防护的写侧一半，
                            // 与 `de_finite_load`（读侧一半）对称。
                            load: if e.load.is_finite() && e.load >= 0.0 {
                                e.load
                            } else {
                                0.0
                            },
                            load_updated_at_ms: e.load_updated_at_ms,
                            last_used_at: e.last_used_at.clone(),
                        },
                    )
                })
                .collect()
        };

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => {
                // 原子写入：tmp 文件必须与目标同目录，再 rename 落地。
                // 生产环境跑 Docker，stats 目录可能是独立挂载卷，
                // 若 tmp 落在 std::env::temp_dir()/tmp 会导致跨设备 rename 报 EXDEV，
                // 把"偶发写坏"变成"永远落不了盘"，故禁止用系统临时目录。
                //
                // tmp 文件名是硬编码的固定路径（非唯一名），单靠它本身不足以防并发写坏
                // ——真正的原子性保证来自调用方持有的 stats_save_lock，把并发调用序列化
                // 成串行的 truncate+write+rename，任意时刻只有一个线程在操作这个 tmp 路径。
                let tmp_path = path.with_extension("json.tmp");
                if let Err(e) =
                    std::fs::write(&tmp_path, json).and_then(|_| std::fs::rename(&tmp_path, &path))
                {
                    tracing::warn!(error = %e, "保存统计缓存失败");
                    // 写失败：不推进 stats_saved_version，脏状态原样保留给 Drop 兜底重试。
                } else {
                    // 只把已落盘版本推进到"取快照那一刻"读到的版本，而不是当前最新版本
                    // ——若快照之后又有新变更把 stats_dirty_version 继续递增，两者不再相等，
                    // 状态依然是脏。
                    self.stats_saved_version
                        .store(version_at_snapshot, Ordering::SeqCst);
                }
            }
            Err(e) => tracing::warn!(error = %e, "序列化统计数据失败"),
            // 序列化失败：同上，不清脏。
        }
    }

    /// 将当前统计数据持久化到磁盘（无条件立即写，供 Admin API 直接调用点 /
    /// `Drop` 使用）。
    ///
    /// #86 返工二轮：本函数自己不产生任何版本标记（不调用
    /// `stats_dirty_version.fetch_add`），单看调用点容易被误当成"清脏但没标记
    /// 过，是不是漏了什么"的漏洞——实际不是，原因是 `save_stats_locked_at` 内部
    /// 的读取顺序保证了正确性，与"谁触发的落盘"无关：
    ///
    /// - `version_at_snapshot` 在 entries 快照*之前*读取，随后立刻加锁读
    ///   entries；由于每个标记方（`save_stats_debounced` 里的 `fetch_add`）总是
    ///   在对应的 entries 修改*之后*才调用（例如 `report_success` 先释放
    ///   entries 锁再调 `save_stats_debounced`），"entries 里已经包含某次修改"
    ///   与"该修改对应的版本号已经可见"之间存在稳定的先后关系：只要能读到某个
    ///   版本号 V，就必然已经能通过 entries 锁看到 V 及之前所有标记对应的
    ///   entries 状态（很可能还包含更晚的、正在被 debounce 压着还没触发落盘的
    ///   变更——那只会让快照包含更多数据，不会更少）。
    /// - 因此无论 `save_stats_locked_at` 是被谁触发的（`save_stats_debounced`
    ///   的惊群路径、Admin API 的这个直接调用点、还是 `Drop` 兜底），它读到的
    ///   `version_at_snapshot` 与它随后取到的 entries 快照永远是自洽的
    ///   ["快照至少覆盖到这个版本号"]，把 `stats_saved_version` 推进到这个值
    ///   就是安全的——不需要调用方自己先打标记再清标记。
    ///
    /// 调用方必须保证调这里之前**不持有 `entries` 锁**（锁序 `stats_save_lock →
    /// entries` 不可反向，否则 `save_stats_locked_at` 内部再取 entries 锁会
    /// 死锁）：`add_credential` / `delete_credential` 对 entries 的修改都在独立
    /// 的 `{ let mut entries = self.entries.lock(); ... }` 块内，块结束、锁释放
    /// 之后才分别调用 `persist_credentials()` / `save_stats()`，作用域已关闭，
    /// 本轮改动未触碰这两个函数、未破坏这个前提。
    ///
    /// **适用边界**：以上论证覆盖的是*已打版本标记*的变更。仓里还存在不打标记
    /// 却直接修改持久化字段的路径——`reserve_credential` 每次取凭据都改
    /// `entry.last_used_at`，全程不调 `save_stats_debounced`；`add_credential` /
    /// `delete_credential` 改完 entries 后自己也从不打标记，直接调这里。这些
    /// 修改不在脏门控的视野内：它们只会"落盘晚"（下次任意标记方触发落盘时随
    /// 快照一起带出去），不会"未落盘却被清脏"（清脏只推进到
    /// `version_at_snapshot`，与未标记的修改无关），但也就此得不到 `Drop` 兜底
    /// 重试的保障——若进程在它们修改之后、下一次成功落盘之前退出，这些未标记
    /// 的改动会连同 `Drop` 一起被跳过而丢失。这是存量行为（旧 `AtomicBool`
    /// 实现下同样如此），PR-1 范围不含改它们的调用时机。
    fn save_stats(&self) {
        let _guard = self.stats_save_lock.lock();
        self.save_stats_locked();
    }

    /// 标记统计数据已更新，并按 debounce 策略决定是否立即落盘。
    ///
    /// #86 返工 MUST FIX 1：原实现是无互斥的 check-then-act——读时间戳、判断、
    /// 直到写完成后才更新时间戳。多线程 runtime 下防抖窗口一到，所有在飞线程会
    /// 惊群式同时判定 should_flush 为真，并发调用 save_stats 对同一路径做
    /// truncate+write，产生 torn write（两份快照长度不同即可拼出非法 JSON，
    /// rename 又把这份垃圾"原子地"发布成 stats.json）。
    ///
    /// 修法是双重检查锁定：热路径（每次 report_success/report_failure 都会经过
    /// 这里）先做一次无锁快速判断，避免不需要刷新时也去抢锁；只有快速判断为真
    /// 才进锁，进锁后重读一次时间戳做第二次判定——惊群里若已有别的线程抢先刷新
    /// 完，这里会直接放弃，最终只有一个线程真写，冗余写入和并发写坏一起消除。
    ///
    /// 锁序钉死：`stats_save_lock → entries`（`save_stats_locked` 内部会取
    /// `entries` 锁构造载荷），全仓其余路径不得反向持锁。
    fn save_stats_debounced(&self) {
        // #86 返工 MUST FIX 1：递增版本号而非置位布尔——见 stats_dirty_version /
        // stats_saved_version 字段注释，这是让"脏"状态能区分"标记发生在快照之前
        // 还是之后"的关键。
        //
        // ⚠️ 不变量（`save_stats` 的 doc comment 有完整推导，这里只放告警）：
        // 本函数是当前唯一的标记点，且全部 6 个调用方
        // （report_success/report_quota_exhausted/report_failure/
        // report_refresh_failure/report_refresh_token_invalid/report_no_result，
        // 最后一个由 #98 新增）都保证先释放 entries 锁、完成对 entries 的修改，
        // 再调用本函数标记版本号。这个顺序
        // 是 `stats_saved_version` 清脏正确性的地基——新增任何调用点，都必须在
        // entries 修改**提交、锁释放之后**才调用本函数；一旦反过来（先标记后
        // 改 entries），落盘可能在标记之后、entries 修改之前完成，那次修改就会
        // 被静默当成"已覆盖"永久丢弃，且不会有任何测试变红。
        self.stats_dirty_version.fetch_add(1, Ordering::SeqCst);

        let maybe_should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if !maybe_should_flush {
            return;
        }

        let _guard = self.stats_save_lock.lock();
        let should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if should_flush {
            self.save_stats_locked();
        }
    }

    /// 报告指定凭据 API 调用成功
    ///
    /// 重置该凭据的失败计数
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_success(&self, id: u64) {
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.success_count += 1;
                entry.last_used_at = Some(Utc::now().to_rfc3339());
                tracing::debug!(
                    credential_id = id,
                    success_count = entry.success_count,
                    "API 调用成功"
                );
            }
        }
        self.save_stats_debounced();
    }

    /// 报告指定凭据 API 调用成功，并在 balanced 模式下绑定会话粘性。
    pub fn report_success_for_session(&self, id: u64, session_id: Option<&str>) {
        self.report_success(id);
        if self.load_balancing_mode.lock().as_str() == "balanced"
            && let Some(session_id) = session_id.filter(|s| !s.is_empty())
        {
            self.bind_sticky_session(session_id, id);
        }
    }

    /// 报告请求已结束但不应影响凭据健康或成功计数。
    pub fn report_no_result(&self, id: u64) {
        self.release_in_flight(id);
        // `#98`：这是 6 个 `report_*` 里唯一原本不标脏的一个，而它恰好是
        // 5xx/429/连接失败三条路径的收尾——也就是新增 load 增量里占比最大
        // 的那部分。此处调用时 `release_in_flight` 已释放 entries 锁，满足
        // 「先释放 entries 再标记版本号」的落盘不变量。
        self.save_stats_debounced();
    }

    /// `#98`：记录一次真实发生的上游调用，把它按 credit 权重计入 balanced 负载。
    ///
    /// # 调用契约（违反会静默产生错误的均衡，不会有任何编译或测试报错）
    /// - 必须在 `send()` **之前**调用——请求发出即消耗上游 credit，与结果无关，
    ///   **不退款**。
    /// - 每次上游调用只调一次，且必须在 `for attempt` 重试循环**内部**调用——
    ///   这是"一处改动同时覆盖失败可见与重试可见"成立的唯一位置：handlers 只
    ///   看得到 1 次顶层调用，看不见内部最多 9 次重试。
    /// - `model` 是 **kiro_id** 口径（不是 Anthropic 模型名），未登记的模型一律
    ///   按权重 1.0 计入（`credit_weight_by_kiro_id` 的既定回落行为）。
    pub fn record_upstream_call(&self, id: u64, model: Option<&str>) {
        // 先算权重取时钟再加锁：两者都不需要 entries，放锁外缩短临界区。
        let weight = self.model_registry.credit_weight_by_kiro_id(model);
        let now_unix_ms = self.now_unix_ms();
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.record_load(weight, now_unix_ms);
        }
    }

    /// 报告指定凭据 API 调用失败
    ///
    /// 增加失败计数，达到阈值时禁用凭据并切换到优先级最高的可用凭据
    /// 返回是否还有可用凭据可以重试
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_failure(&self, id: u64) -> bool {
        // #86：只有本次调用导致凭据被禁用（跨越阈值）才清 sticky，且清的是整个
        // 凭据下所有会话；未到阈值的失败一律不清任何绑定。
        let mut just_disabled = false;
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
            entry.failure_count += 1;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            let failure_count = entry.failure_count;

            tracing::warn!(
                credential_id = id,
                failure_count = failure_count,
                max_failures = MAX_FAILURES_PER_CREDENTIAL,
                "API 调用失败"
            );

            if failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::TooManyFailures);
                just_disabled = true;
                tracing::error!(
                    credential_id = id,
                    failure_count = failure_count,
                    "凭据已连续失败，已被禁用"
                );

                // 切换到优先级最高的可用凭据
                if let Some(next) = entries
                    .iter()
                    .filter(|e| !e.disabled)
                    .min_by_key(|e| e.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        credential_id = next.id,
                        priority = next.credentials.priority,
                        "已切换到新凭据"
                    );
                } else {
                    tracing::error!("所有凭据均已禁用！");
                }
            }

            entries.iter().any(|e| !e.disabled)
        };
        if just_disabled {
            self.clear_sticky_sessions_for_credential(id);
        }
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据额度已用尽
    ///
    /// 用于处理 402 Payment Required 且 reason 为 `MONTHLY_REQUEST_COUNT` 的场景：
    /// - 立即禁用该凭据（不等待连续失败阈值）
    /// - 切换到下一个可用凭据继续重试
    /// - 返回是否还有可用凭据
    pub fn report_quota_exhausted(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            // 设为阈值，便于在管理面板中直观看到该凭据已不可用
            entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;

            tracing::error!(
                credential_id = id,
                "凭据额度已用尽（MONTHLY_REQUEST_COUNT），已被禁用"
            );

            // 切换到优先级最高的可用凭据
            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    credential_id = next.id,
                    priority = next.credentials.priority,
                    "已切换到新凭据"
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.clear_sticky_sessions_for_credential(id);
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据刷新 Token 失败。
    ///
    /// 连续刷新失败达到阈值后禁用凭据并切换，阈值内保持当前凭据不切换，
    /// 与 API 401/403 的累计失败策略保持一致。
    pub fn report_refresh_failure(&self, id: u64) -> bool {
        // #86：与 report_failure 同构——仅在本次调用导致禁用时才清 sticky。
        // 控制流卫生（非语义修复）：原早 return 恰好跳过了清理（语义已经正确），
        // 但同时也会绕过尾部 save_stats_debounced()；改用 just_disabled 标志位
        // 落在统一返回路径上，避免后人往函数尾部加逻辑被这条分支静默绕过。
        let mut just_disabled = false;
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            // #98 §F：in_flight 的释放已收归调用方 acquire_context_for_session_excluding
            // 的 try_ensure_token 失败分支（该分支已无条件调 report_no_result 释放一次）。
            // 本函数同时被"有预留"（该分支）与"无预留"（handle_usage_refresh_error，
            // 余额查询路径从未 reserve 过）两类调用方共用，若在这里再减一次，前者会
            // 一次失败减两次，后者会凭空减到别人头上——两者都不对，故这里不再释放。
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.refresh_failure_count += 1;
            let refresh_failure_count = entry.refresh_failure_count;

            tracing::warn!(
                credential_id = id,
                failure_count = refresh_failure_count,
                max_failures = MAX_FAILURES_PER_CREDENTIAL,
                "Token 刷新失败"
            );

            if refresh_failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::TooManyRefreshFailures);
                just_disabled = true;

                tracing::error!(
                    credential_id = id,
                    failure_count = refresh_failure_count,
                    "Token 已连续刷新失败，已被禁用"
                );

                if let Some(next) = entries
                    .iter()
                    .filter(|e| !e.disabled)
                    .min_by_key(|e| e.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        credential_id = next.id,
                        priority = next.credentials.priority,
                        "已切换到新凭据"
                    );
                } else {
                    tracing::error!("所有凭据均已禁用！");
                }
            }

            entries.iter().any(|e| !e.disabled)
        };
        if just_disabled {
            self.clear_sticky_sessions_for_credential(id);
        }
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据的 refreshToken 永久失效（invalid_grant）。
    ///
    /// 立即禁用凭据，不累计、不重试。
    /// 返回是否还有可用凭据。
    pub fn report_refresh_token_invalid(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            // #98 §F：同上，释放已收归调用方，这里不再重复释放（详见
            // report_refresh_failure 同一处的注释）。
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::InvalidRefreshToken);

            tracing::error!(
                credential_id = id,
                "refreshToken 已失效 (invalid_grant)，已立即禁用"
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    credential_id = next.id,
                    priority = next.credentials.priority,
                    "已切换到新凭据"
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.clear_sticky_sessions_for_credential(id);
        self.save_stats_debounced();
        result
    }

    /// 切换到优先级最高的可用凭据
    ///
    /// 返回是否成功切换
    pub fn switch_to_next(&self) -> bool {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（排除当前凭据）
        if let Some(next) = entries
            .iter()
            .filter(|e| !e.disabled && e.id != *current_id)
            .min_by_key(|e| e.credentials.priority)
        {
            *current_id = next.id;
            tracing::info!(
                credential_id = next.id,
                priority = next.credentials.priority,
                "已切换到新凭据"
            );
            true
        } else {
            // 没有其他可用凭据，检查当前凭据是否可用
            entries.iter().any(|e| e.id == *current_id && !e.disabled)
        }
    }

    // ========================================================================
    // Admin API 方法
    // ========================================================================

    /// 获取管理器状态快照（用于 Admin API）
    pub fn snapshot(&self) -> ManagerSnapshot {
        let entries = self.entries.lock();
        let current_id = *self.current_id.lock();
        let available = entries.iter().filter(|e| !e.disabled).count();

        ManagerSnapshot {
            entries: entries
                .iter()
                .map(|e| CredentialEntrySnapshot {
                    id: e.id,
                    priority: e.credentials.priority,
                    disabled: e.disabled,
                    failure_count: e.failure_count,
                    auth_method: if e.credentials.is_api_key_credential() {
                        Some("api_key".to_string())
                    } else {
                        e.credentials.auth_method.as_deref().map(|m| {
                            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam")
                            {
                                "idc".to_string()
                            } else {
                                m.to_string()
                            }
                        })
                    },
                    has_profile_arn: e.credentials.profile_arn.is_some(),
                    expires_at: if e.credentials.is_api_key_credential() {
                        None // API Key 凭据本地不维护过期时间（服务端策略未知）
                    } else {
                        e.credentials.expires_at.clone()
                    },
                    refresh_token_hash: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    },
                    api_key_hash: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else {
                        None
                    },
                    masked_api_key: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(mask_api_key)
                    } else {
                        None
                    },
                    email: e.credentials.email.clone(),
                    success_count: e.success_count,
                    last_used_at: e.last_used_at.clone(),
                    has_proxy: e.credentials.proxy_url.is_some(),
                    proxy_url: e.credentials.proxy_url.clone(),
                    refresh_failure_count: e.refresh_failure_count,
                    disabled_reason: e.disabled_reason.map(|r| {
                        match r {
                            DisabledReason::Manual => "Manual",
                            DisabledReason::TooManyFailures => "TooManyFailures",
                            DisabledReason::TooManyRefreshFailures => "TooManyRefreshFailures",
                            DisabledReason::QuotaExceeded => "QuotaExceeded",
                            DisabledReason::InvalidRefreshToken => "InvalidRefreshToken",
                            DisabledReason::InvalidConfig => "InvalidConfig",
                        }
                        .to_string()
                    }),
                    endpoint: e.credentials.endpoint.clone(),
                })
                .collect(),
            current_id,
            total: entries.len(),
            available,
        }
    }

    /// 设置凭据禁用状态（Admin API）
    pub fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = disabled;
            if !disabled {
                // 启用时重置失败计数
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.disabled_reason = None;
            } else {
                entry.disabled_reason = Some(DisabledReason::Manual);
            }
        }
        if disabled {
            self.clear_sticky_sessions_for_credential(id);
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 设置凭据优先级（Admin API）
    ///
    /// 修改优先级后会立即按新优先级重新选择当前凭据。
    /// 即使持久化失败，内存中的优先级和当前凭据选择也会生效。
    pub fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.priority = priority;
        }
        // 立即按新优先级重新选择当前凭据（无论持久化是否成功）
        self.select_highest_priority();
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 重置凭据失败计数并重新启用（Admin API）
    pub fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            if entry.disabled_reason == Some(DisabledReason::InvalidConfig) {
                anyhow::bail!("凭据 #{} 因配置无效被禁用，请修正配置后重启服务", id);
            }
            entry.failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// Applies the Admin usage endpoint's refresh failure policy without changing the original error.
    fn handle_usage_refresh_error(&self, id: u64, error: &anyhow::Error) {
        if let Some(invalid) = error.downcast_ref::<RefreshTokenInvalidError>() {
            tracing::warn!(credential_id = id, error_code = invalid.error_code, error = %error, "Token 刷新永久失效（余额查询）");
            self.report_refresh_token_invalid(id);
        } else {
            tracing::warn!(credential_id = id, error = %error, "Token 刷新失败（余额查询）");
        }
    }

    /// 获取指定凭据的使用额度（Admin API）。
    ///
    /// 永久 refresh 错误仍隔离该 credential；profile discovery 失败只会返回可用 token，
    /// 不会走到这一隔离分支。
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let (credentials, token) = match self.acquire_latest_credentials_and_token(id).await {
            Ok(value) => value,
            Err(error) => {
                self.handle_usage_refresh_error(id, &error);
                return Err(error);
            }
        };
        let proxy = credentials.effective_proxy(self.proxy.as_ref());
        let region = credentials.effective_api_region(&self.config);
        let production_url = format!("https://q.{region}.amazonaws.com/getUsageLimits");
        #[cfg(test)]
        let usage_url = self
            .test_usage_limits_url
            .lock()
            .clone()
            .unwrap_or(production_url);
        #[cfg(not(test))]
        let usage_url = production_url;
        let usage_limits = get_usage_limits_at(
            &usage_url,
            &credentials,
            &self.config,
            &token,
            proxy.as_ref(),
        )
        .await?;
        if let Some(subscription_title) = usage_limits.subscription_title() {
            let changed = {
                let mut entries = self.entries.lock();
                entries
                    .iter_mut()
                    .find(|entry| entry.id == id)
                    .is_some_and(|entry| {
                        if entry.credentials.subscription_title.as_deref()
                            == Some(subscription_title)
                        {
                            false
                        } else {
                            entry.credentials.subscription_title =
                                Some(subscription_title.to_string());
                            true
                        }
                    })
            };
            if changed && let Err(error) = self.persist_credentials() {
                tracing::warn!(error = %error, "订阅等级更新后持久化失败（不影响本次请求）");
            }
        }
        Ok(usage_limits)
    }

    /// 添加新凭据（Admin API）
    ///
    /// # 流程
    /// 1. 验证凭据基本字段（API Key: kiroApiKey 不为空; OAuth: refreshToken 不为空）
    /// 2. 基于 kiroApiKey 或 refreshToken 的 SHA-256 哈希检测重复
    /// 3. OAuth: 尝试刷新 Token 验证凭据有效性; API Key: 跳过
    /// 4. 分配新 ID（当前最大 ID + 1）
    /// 5. 添加到 entries 列表
    /// 6. 持久化到配置文件
    ///
    /// # 返回
    /// - `Ok(u64)` - 新凭据 ID
    /// - `Err(_)` - 验证失败或添加失败
    pub async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        // 1. 基本验证
        if new_cred.is_api_key_credential() {
            let api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            if api_key.is_empty() {
                anyhow::bail!("kiroApiKey 为空");
            }
        } else {
            validate_refresh_token(&new_cred)?;
        }

        // 2. 基于哈希检测重复
        if new_cred.is_api_key_credential() {
            let new_api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?;
            let new_api_key_hash = sha256_hex(new_api_key);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（kiroApiKey 重复）");
            }
        } else {
            let new_refresh_token = new_cred
                .refresh_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;
            let new_refresh_token_hash = sha256_hex(new_refresh_token);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（refreshToken 重复）");
            }
        }

        // 3. 验证凭据有效性（API Key 无需网络刷新）
        let mut validated_cred = if new_cred.is_api_key_credential() {
            new_cred.clone()
        } else {
            let effective_proxy = new_cred.effective_proxy(self.proxy.as_ref());
            refresh_token(&new_cred, &self.config, effective_proxy.as_ref()).await?
        };

        // 4. 分配新 ID
        let new_id = {
            let entries = self.entries.lock();
            entries.iter().map(|e| e.id).max().unwrap_or(0) + 1
        };

        // 5. 设置 ID 并保留用户输入的元数据
        validated_cred.id = Some(new_id);
        validated_cred.priority = new_cred.priority;
        validated_cred.auth_method = new_cred.auth_method.map(|m| {
            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam") {
                "idc".to_string()
            } else {
                m
            }
        });
        validated_cred.client_id = new_cred.client_id;
        validated_cred.client_secret = new_cred.client_secret;
        validated_cred.region = new_cred.region;
        validated_cred.auth_region = new_cred.auth_region;
        validated_cred.api_region = new_cred.api_region;
        validated_cred.machine_id = new_cred.machine_id;
        validated_cred.email = new_cred.email;
        validated_cred.proxy_url = new_cred.proxy_url;
        validated_cred.proxy_username = new_cred.proxy_username;
        validated_cred.proxy_password = new_cred.proxy_password;
        validated_cred.kiro_api_key = new_cred.kiro_api_key;

        {
            let mut entries = self.entries.lock();
            // 必须先对每个条目做惰性衰减再取最小：load 是时点量，磁盘裸值分属不同时刻，
            // 直接比裸值等于拿不同时点的数做比较。current_load 是纯函数，只读不写。
            let now_unix_ms = self.now_unix_ms();
            let load = entries
                .iter()
                .filter(|e| !e.disabled)
                .map(|e| e.current_load(now_unix_ms))
                .fold(f64::INFINITY, f64::min); // f64::min 对 (NaN,x) 返回 x，天然滤脏值
            let load = if load.is_finite() { load } else { 0.0 };
            entries.push(CredentialEntry {
                id: new_id,
                credentials: validated_cred,
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                load,
                load_updated_at_ms: now_unix_ms,
                in_flight_count: 0,
                last_used_at: None,
                profile_lookup_retry_after_ms: None,
                profile_lookup_lock: Arc::new(TokioMutex::new(())),
            });
        }

        // 6. 持久化
        self.persist_credentials()?;
        self.save_stats();

        tracing::info!(credential_id = new_id, "成功添加凭据");
        Ok(new_id)
    }

    /// 删除凭据（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true）
    ///
    /// # 行为
    /// 1. 验证凭据存在
    /// 2. 验证凭据已禁用
    /// 3. 从 entries 移除
    /// 4. 如果删除的是当前凭据，切换到优先级最高的可用凭据
    /// 5. 如果删除后没有凭据，将 current_id 重置为 0
    /// 6. 持久化到文件
    ///
    /// # 返回
    /// - `Ok(())` - 删除成功
    /// - `Err(_)` - 凭据不存在、未禁用或持久化失败
    pub fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let was_current = {
            let mut entries = self.entries.lock();

            // 查找凭据
            let entry = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            // 检查是否已禁用
            if !entry.disabled {
                anyhow::bail!("只能删除已禁用的凭据（请先禁用凭据 #{}）", id);
            }

            // 记录是否是当前凭据
            let current_id = *self.current_id.lock();
            let was_current = current_id == id;

            // 删除凭据
            entries.retain(|e| e.id != id);

            was_current
        };

        // 如果删除的是当前凭据，切换到优先级最高的可用凭据
        if was_current {
            self.select_highest_priority();
        }
        self.clear_sticky_sessions_for_credential(id);

        // 如果删除后没有任何凭据，将 current_id 重置为 0（与初始化行为保持一致）
        {
            let entries = self.entries.lock();
            if entries.is_empty() {
                let mut current_id = self.current_id.lock();
                *current_id = 0;
                tracing::info!("所有凭据已删除，current_id 已重置为 0");
            }
        }

        // 持久化更改
        self.persist_credentials()?;

        // 立即回写统计数据，清除已删除凭据的残留条目
        self.save_stats();

        tracing::info!(credential_id = id, "已删除凭据");
        Ok(())
    }

    /// 强制刷新指定凭据的 Token（Admin API）
    ///
    /// 无条件调用上游 API 重新获取 access token，不检查是否过期。
    /// 适用于排查问题、Token 异常但未过期、主动更新凭据状态等场景。
    pub async fn force_refresh_token_for(&self, id: u64) -> anyhow::Result<()> {
        // Read only after serializing refreshes: a waiter must refresh the credential generation
        // that exists when it acquires the lock, not the snapshot it held while waiting.
        let (expected_refresh_token, refreshed) = {
            let _refresh_guard = self.refresh_lock.lock().await;
            let current = self.credentials_for_id(id)?;
            let expected_refresh_token = current.refresh_token.clone();
            let effective_proxy = current.effective_proxy(self.proxy.as_ref());
            let refreshed = refresh_token(&current, &self.config, effective_proxy.as_ref()).await?;
            (expected_refresh_token, refreshed)
        };

        self.apply_forced_refresh(id, expected_refresh_token.as_deref(), refreshed)?;
        tracing::info!(credential_id = id, "Token 已强制刷新");
        Ok(())
    }

    /// 获取负载均衡模式（Admin API）
    pub fn get_load_balancing_mode(&self) -> String {
        self.load_balancing_mode.lock().clone()
    }

    fn persist_load_balancing_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!(
                    mode = mode,
                    "配置文件路径未知，负载均衡模式仅在当前进程生效"
                );
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.load_balancing_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化负载均衡模式失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 设置负载均衡模式（Admin API）
    pub fn set_load_balancing_mode(&self, mode: String) -> anyhow::Result<()> {
        // 验证模式值
        if mode != "priority" && mode != "balanced" {
            anyhow::bail!("无效的负载均衡模式: {}", mode);
        }

        let previous_mode = self.get_load_balancing_mode();
        if previous_mode == mode {
            return Ok(());
        }

        *self.load_balancing_mode.lock() = mode.clone();

        if let Err(err) = self.persist_load_balancing_mode(&mode) {
            *self.load_balancing_mode.lock() = previous_mode;
            return Err(err);
        }

        tracing::info!(mode = mode.as_str(), "负载均衡模式已设置");
        Ok(())
    }
}

impl Drop for MultiTokenManager {
    fn drop(&mut self) {
        // #86 返工 MUST FIX 1：脏 = 变更版本号与已落盘版本号不相等。门控语义不变——
        // 有脏才写、写就是无条件立即写（save_stats 不经 debounce）。
        if self.stats_dirty_version.load(Ordering::SeqCst)
            != self.stats_saved_version.load(Ordering::SeqCst)
        {
            self.save_stats();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    /// 测试专用时钟（#86 + #98）：双 `AtomicU64`，`now_ms` 是 sticky 用的单调相对
    /// 毫秒（起点 0），`now_unix_ms` 是 balanced 负载衰减用的墙钟毫秒。
    ///
    /// `now_unix_ms` 起点故意取非 0（`1_700_000_000_000`，约 2023-11）：`0` 是
    /// `load_updated_at_ms` 的哨兵值（"无时间基准"），从 0 起步会让测试永远
    /// 落在哨兵分支、测不到真实的衰减路径。
    struct TestClock {
        now_ms: AtomicU64,
        now_unix_ms: AtomicU64,
    }

    impl TestClock {
        const INITIAL_WALL_MS: u64 = 1_700_000_000_000;

        fn new() -> Arc<Self> {
            Arc::new(Self {
                now_ms: AtomicU64::new(0),
                now_unix_ms: AtomicU64::new(Self::INITIAL_WALL_MS),
            })
        }

        /// 两条时间轴一起推进——既有 sticky 测试只读 `now_ms`，行为不变；
        /// 新增的负载衰减测试读 `now_unix_ms`。
        fn advance_ms(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
            self.now_unix_ms.fetch_add(delta_ms, Ordering::SeqCst);
        }

        /// 只拨墙钟、不动 sticky 的单调轴——用于 NTP 回退用例（N7），
        /// 单独验证 `current_load`/`decay_load_to` 面对时钟倒退时的自愈行为。
        fn set_wall_ms(&self, wall_ms: u64) {
            self.now_unix_ms.store(wall_ms, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }

        fn now_unix_ms(&self) -> u64 {
            self.now_unix_ms.load(Ordering::SeqCst)
        }
    }

    fn test_registry() -> Arc<ModelRegistry> {
        Arc::new(ModelRegistry::from_toml(include_str!("../../models.toml")).unwrap())
    }

    /// registry.rs N13 第三段专用（`#98`）：真实 `models.toml` 剥离全部
    /// `credit_weight` 行后构造的 registry。与 `registry.rs` 里
    /// `test_deleting_credit_weight_fields_maintains_functionality` 用的是
    /// 同一份过滤逻辑（按行前缀剔除），刻意不共享代码——那条测试在
    /// `model::registry` 模块、本模块在 `kiro::token_manager`，为一行
    /// 字符串过滤拉一条跨模块可见性通道不划算。
    fn test_registry_without_credit_weight_fields() -> Arc<ModelRegistry> {
        let raw = include_str!("../../models.toml");
        let stripped: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with("credit_weight"))
            .collect::<Vec<_>>()
            .join("\n");
        Arc::new(ModelRegistry::from_toml(&stripped).unwrap())
    }

    /// 构造一个 `stats_path()` 可写的 manager（#86 返工统计落盘回归测试专用）。
    /// 返回 `(manager, 临时凭据目录)`，调用方用完须 `remove_dir_all` 清理。
    /// 测试专用清理 guard：无论测试函数体正常返回还是因断言失败 panic 退出，
    /// `Drop` 都会执行，保证临时目录不残留——若把清理写成函数体末尾的裸调用，
    /// 断言先 panic 就会跳过它，泄漏临时目录。
    struct TempDirGuard(PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn test_manager_with_stats_path() -> (MultiTokenManager, PathBuf) {
        let cred_dir =
            std::env::temp_dir().join(format!("kiro-stats-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&cred_dir).unwrap();
        let cred_path = cred_dir.join("credentials.json");

        let config = Config::default();
        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let manager = MultiTokenManager::new(
            config,
            vec![cred],
            None,
            Some(cred_path),
            false,
            test_registry(),
        )
        .unwrap();

        (manager, cred_dir)
    }

    /// #86 返工 MUST FIX 1 回归测试。
    ///
    /// 复现时序表：T0 线程 A 已读完 `version_at_snapshot`、正要取 entries 快照；
    /// T1 线程 B 在此期间修改 entries 并调用 `save_stats_debounced` 标记新变更；
    /// T2 A 完成写盘。断言 T2 之后状态仍必须是脏的——B 的变更不能被 A 的成功
    /// 落盘掩盖，否则此后若无新变更再触发落盘，`Drop` 的脏门控也会跳过，B 的
    /// 变更永久丢失。
    ///
    /// 用 `save_stats_locked_at` 钩子在真实竞态窗口内（读完版本号之后、取
    /// entries 快照之前）确定性注入"B 的变更"，单线程、无 sleep，复现只有多
    /// 线程环境才会触发的 DCL 竞态；其余步骤（路径解析/entries 快照/序列化/
    /// 写盘/成功分支的版本号推进）全部走生产代码本身。
    ///
    /// 修复前必红：若把成功分支改回"存当前最新版本"而非"存快照前读到的
    /// version_at_snapshot"（旧 `AtomicBool` 实现的等价行为——落盘成功就无条件
    /// 清脏），T1 注入的变更会被这次成功覆盖，`assert_ne!` 会因两值相等而 panic。
    ///
    /// 落盘成功这个前提本身也被显式断言（`kiro_stats.json` 确实存在），而不是
    /// 隐含在"跑通了就算数"里——否则若环境前提悄悄变了（`stats_path()` 推导
    /// 改了 / 目录没建成 / 沙箱禁写）导致写盘分支根本没执行到，`assert_ne!`
    /// 依然会通过（失败分支本就不推进 `stats_saved_version`），这个测试就退化
    /// 成又一个恒绿测试——只是触发条件从"输入构造"换成了"环境前提"，跟
    /// `test_extract_session_id_non_char_boundary_does_not_panic` 曾经踩的是
    /// 同一类失效模式。
    #[test]
    fn test_stats_dirty_survives_change_during_inflight_flush() {
        let (manager, cred_dir) = test_manager_with_stats_path();
        let _cleanup = TempDirGuard(cred_dir.clone());

        manager.save_stats_locked_at(|| {
            // 等价于 save_stats_debounced 里唯一的标记语句：B 线程在 A 已读完
            // version_at_snapshot、但还没取 entries 快照之前，标记了一次新变更。
            manager.stats_dirty_version.fetch_add(1, Ordering::SeqCst);
        });

        assert!(
            cred_dir.join("kiro_stats.json").exists(),
            "前提断言：落盘必须真的成功执行到——否则下面的 assert_ne! 在写盘失败的\
             失败分支下也会通过（该分支本就不推进 stats_saved_version），测试会\
             退化成恒绿"
        );

        assert_ne!(
            manager.stats_dirty_version.load(Ordering::SeqCst),
            manager.stats_saved_version.load(Ordering::SeqCst),
            "B 在 A 落盘期间发生的新变更必须让状态保持脏，Drop 才会兜底重试"
        );
    }

    /// #86 返工 SUGGESTION 回归测试：落盘失败后，防抖时钟（`last_stats_save_at`）
    /// 仍必须推进，且脏状态必须继续保持真。
    ///
    /// 前者防止"每个请求都重新抢 `stats_save_lock` 做一次注定失败的落盘"；后者
    /// 保证 `Drop` 仍会在下一次（可能已恢复写权限的）尝试中兜底重试，不因为时钟
    /// 推进就误判为"已经落盘过了"。
    ///
    /// 用指向不存在目录的路径稳定复现"落盘失败"分支——`stats_path()` 基于纯字符
    /// 串拼接不检查存在性，返回 `Some`；但写 tmp 文件时目录不存在必然报错，不依赖
    /// 平台特定的权限设置，跨平台稳定复现。
    ///
    /// 修复前必红：若把 `last_stats_save_at` 的更新留在原位（只在成功分支里），
    /// 落盘失败后它仍是 `None`，第一个 `assert!` 会因 `is_none()` 为真而失败。
    #[test]
    fn test_debounce_clock_advances_on_save_failure() {
        let config = Config::default();
        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let cred_path = std::env::temp_dir()
            .join(format!("kiro-stats-nope-{}", uuid::Uuid::new_v4()))
            .join("credentials.json");

        let manager = MultiTokenManager::new(
            config,
            vec![cred],
            None,
            Some(cred_path),
            false,
            test_registry(),
        )
        .unwrap();

        assert!(manager.last_stats_save_at.lock().is_none());

        manager.stats_dirty_version.fetch_add(1, Ordering::SeqCst);
        manager.save_stats_locked();

        assert!(
            manager.last_stats_save_at.lock().is_some(),
            "落盘失败后防抖时钟仍必须推进，否则每个请求都会重新抢锁做一次注定失败的落盘"
        );
        assert_ne!(
            manager.stats_dirty_version.load(Ordering::SeqCst),
            manager.stats_saved_version.load(Ordering::SeqCst),
            "落盘失败不得清脏，Drop 仍要兜底重试"
        );
    }

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let credentials = KiroCredentials {
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let future = Utc::now() + Duration::hours(1);
        let credentials = KiroCredentials {
            expires_at: Some(future.to_rfc3339()),
            ..Default::default()
        };
        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let expires = Utc::now() + Duration::minutes(3);
        let credentials = KiroCredentials {
            expires_at: Some(expires.to_rfc3339()),
            ..Default::default()
        };
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let expires = Utc::now() + Duration::minutes(8);
        let credentials = KiroCredentials {
            expires_at: Some(expires.to_rfc3339()),
            ..Default::default()
        };
        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let expires = Utc::now() + Duration::minutes(15);
        let credentials = KiroCredentials {
            expires_at: Some(expires.to_rfc3339()),
            ..Default::default()
        };
        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let credentials = KiroCredentials {
            refresh_token: Some("a".repeat(150)),
            ..Default::default()
        };
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("test");
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_api_key_credential() {
        let config = Config::default();
        let credentials = KiroCredentials {
            kiro_api_key: Some("ksk_test_key_123".to_string()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let result = refresh_token(&credentials, &config, None).await;

        assert!(result.is_err(), "API Key 凭据应被 refresh_token 拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("API Key 凭据不支持刷新"),
            "期望错误消息包含 'API Key 凭据不支持刷新'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_refresh_token() {
        let config = Config::default();

        let existing = KiroCredentials {
            refresh_token: Some("a".repeat(150)),
            ..Default::default()
        };

        let manager =
            MultiTokenManager::new(config, vec![existing], None, None, false, test_registry())
                .unwrap();

        let duplicate = KiroCredentials {
            refresh_token: Some("a".repeat(150)),
            ..Default::default()
        };

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("凭据已存在"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_success() {
        let config = Config::default();
        let manager =
            MultiTokenManager::new(config, vec![], None, None, false, test_registry()).unwrap();

        let api_key_cred = KiroCredentials {
            kiro_api_key: Some("ksk_test_key_123".to_string()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_api_key() {
        let config = Config::default();

        let existing = KiroCredentials {
            kiro_api_key: Some("ksk_existing_key".to_string()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let manager =
            MultiTokenManager::new(config, vec![existing], None, None, false, test_registry())
                .unwrap();

        let duplicate = KiroCredentials {
            kiro_api_key: Some("ksk_existing_key".to_string()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 重复")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_empty_rejected() {
        let config = Config::default();
        let manager =
            MultiTokenManager::new(config, vec![], None, None, false, test_registry()).unwrap();

        let cred = KiroCredentials {
            kiro_api_key: Some(String::new()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 为空")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_missing_key_rejected() {
        let config = Config::default();
        let manager =
            MultiTokenManager::new(config, vec![], None, None, false, test_registry()).unwrap();

        let cred = KiroCredentials {
            auth_method: Some("api_key".to_string()),
            // kiro_api_key is None
            ..Default::default()
        };

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("缺少 kiroApiKey")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_and_oauth_coexist() {
        let config = Config::default();

        let oauth_cred = KiroCredentials {
            refresh_token: Some("a".repeat(150)),
            ..Default::default()
        };

        let manager =
            MultiTokenManager::new(config, vec![oauth_cred], None, None, false, test_registry())
                .unwrap();

        let api_key_cred = KiroCredentials {
            kiro_api_key: Some("ksk_new_key".to_string()),
            auth_method: Some("api_key".to_string()),
            ..Default::default()
        };

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    // MultiTokenManager 测试

    #[test]
    fn test_multi_token_manager_new() {
        let config = Config::default();
        let cred1 = KiroCredentials {
            priority: 0,
            ..Default::default()
        };
        let cred2 = KiroCredentials {
            priority: 1,
            ..Default::default()
        };

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    #[test]
    fn test_multi_token_manager_empty_credentials() {
        let config = Config::default();
        let result = MultiTokenManager::new(config, vec![], None, None, false, test_registry());
        // 支持 0 个凭据启动（可通过管理面板添加）
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_duplicate_ids() {
        let config = Config::default();
        let cred1 = KiroCredentials {
            id: Some(1),
            ..Default::default()
        };
        let cred2 = KiroCredentials {
            id: Some(1), // 重复 ID
            ..Default::default()
        };

        let result = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        );
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("重复的凭据 ID"),
            "错误消息应包含 '重复的凭据 ID'，实际: {}",
            err_msg
        );
    }

    #[test]
    fn test_multi_token_manager_api_key_missing_kiro_api_key_auto_disabled() {
        let config = Config::default();

        // auth_method=api_key 但缺少 kiro_api_key → 应被自动禁用
        let bad_cred = KiroCredentials {
            auth_method: Some("api_key".to_string()),
            // kiro_api_key 保持 None
            ..Default::default()
        };

        let good_cred = KiroCredentials {
            refresh_token: Some("valid_token".to_string()),
            ..Default::default()
        };

        let manager = MultiTokenManager::new(
            config,
            vec![bad_cred, good_cred],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 1); // bad_cred 被禁用，只剩 1 个可用
    }

    #[test]
    fn test_multi_token_manager_api_key_with_kiro_api_key_not_disabled() {
        let config = Config::default();

        // auth_method=api_key 且有 kiro_api_key → 不应被禁用
        let cred = KiroCredentials {
            auth_method: Some("api_key".to_string()),
            kiro_api_key: Some("ksk_test123".to_string()),
            ..Default::default()
        };

        let manager =
            MultiTokenManager::new(config, vec![cred], None, None, false, test_registry()).unwrap();
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_report_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        // 前两次失败不会禁用（使用 ID 1）
        assert!(manager.report_failure(1));
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 2);

        // 第三次失败会禁用第一个凭据
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 1);

        // 继续失败第二个凭据（使用 ID 2）
        assert!(manager.report_failure(2));
        assert!(manager.report_failure(2));
        assert!(!manager.report_failure(2)); // 所有凭据都禁用了
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_report_success() {
        let config = Config::default();
        let cred = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred], None, None, false, test_registry()).unwrap();

        // 失败两次（使用 ID 1）
        manager.report_failure(1);
        manager.report_failure(1);

        // 成功后重置计数（使用 ID 1）
        manager.report_success(1);

        // 再失败两次不会禁用
        manager.report_failure(1);
        manager.report_failure(1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_switch_to_next() {
        let config = Config::default();
        let cred1 = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let cred2 = KiroCredentials {
            refresh_token: Some("token2".to_string()),
            ..Default::default()
        };

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let initial_id = manager.snapshot().current_id;

        // 切换到下一个
        assert!(manager.switch_to_next());
        assert_ne!(manager.snapshot().current_id, initial_id);
    }

    #[test]
    fn test_set_load_balancing_mode_persists_to_config_file() {
        let config_path =
            std::env::temp_dir().join(format!("kiro-load-balancing-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&config_path, r#"{"loadBalancingMode":"priority"}"#).unwrap();

        let config = Config::load(&config_path).unwrap();
        let manager = MultiTokenManager::new(
            config,
            vec![KiroCredentials::default()],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager
            .set_load_balancing_mode("balanced".to_string())
            .unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(persisted.load_balancing_mode, "balanced");
        assert_eq!(manager.get_load_balancing_mode(), "balanced");

        std::fs::remove_file(&config_path).unwrap();
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_auto_recovers_all_disabled() {
        let config = Config::default();
        let cred1 = KiroCredentials {
            access_token: Some("t1".to_string()),
            expires_at: Some((Utc::now() + Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };
        let cred2 = KiroCredentials {
            access_token: Some("t2".to_string()),
            expires_at: Some((Utc::now() + Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(1);
        }
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(2);
        }

        assert_eq!(manager.available_count(), 0);

        // 应触发自愈：重置失败计数并重新启用，避免必须重启进程
        let ctx = manager.acquire_context(None).await.unwrap();
        assert!(ctx.token == "t1" || ctx.token == "t2");
        assert_eq!(manager.available_count(), 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_balanced_retries_until_bad_credential_disabled()
     {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let bad_cred = KiroCredentials {
            priority: 0,
            refresh_token: Some("bad".to_string()),
            ..Default::default()
        };

        let good_cred = KiroCredentials {
            priority: 1,
            access_token: Some("good-token".to_string()),
            expires_at: Some((Utc::now() + Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };

        let manager = MultiTokenManager::new(
            config,
            vec![bad_cred, good_cred],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "good-token");
    }

    fn valid_access_credential(token: &str, priority: u32) -> KiroCredentials {
        KiroCredentials {
            access_token: Some(token.to_string()),
            refresh_token: Some(format!("test-refresh-{token}")),
            expires_at: Some((Utc::now() + Duration::hours(1)).to_rfc3339()),
            priority,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_acquire_context_excluding_skips_failed_current_credential() {
        let config = Config::default();
        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager.acquire_context(None).await.unwrap();
        assert_eq!(first.id, 1);
        manager.report_no_result(first.id);

        let excluded = HashSet::from([first.id]);
        let retry = manager
            .acquire_context_for_session_excluding(None, None, &excluded)
            .await
            .unwrap();

        assert_eq!(retry.id, 2);
        manager.report_no_result(retry.id);
    }

    #[tokio::test]
    async fn test_acquire_context_excluding_ignores_sticky_failed_credential() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-1", 1);
        let excluded = HashSet::from([1]);
        let retry = manager
            .acquire_context_for_session_excluding(None, Some("session-1"), &excluded)
            .await
            .unwrap();

        assert_eq!(retry.id, 2);
        manager.report_no_result(retry.id);
    }

    #[tokio::test]
    async fn test_balanced_session_sticky_reuses_successful_credential() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        // provider 在 send() 之前会对本次上游调用计量；本测试直接调 token_manager
        // API 绕过了 provider，故显式补上这一步。缺了它，两张凭据的 load 恒为
        // 0，新排序键全等、只能靠 priority→id 决胜，跨 session 轮转就不会发生。
        manager.record_upstream_call(first.id, None);
        manager.report_success_for_session(first.id, Some("session-1"));
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-1")
                .map(|entry| entry.credential_id),
            Some(first.id)
        );

        let second_session = manager
            .acquire_context_for_session(None, Some("session-2"))
            .await
            .unwrap();
        assert_ne!(second_session.id, first.id);
        manager.record_upstream_call(second_session.id, None);
        manager.report_success_for_session(second_session.id, Some("session-2"));
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-2")
                .map(|entry| entry.credential_id),
            Some(second_session.id)
        );

        let sticky = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(sticky.id, first.id);
        assert_eq!(sticky.token, first.token);
    }

    #[tokio::test]
    async fn test_balanced_session_sticky_disabled_credential_falls_back() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(first.id, 1);
        manager.report_success_for_session(first.id, Some("session-1"));
        manager.set_disabled(first.id, true).unwrap();

        let fallback = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(fallback.id, 2);
        assert_eq!(fallback.token, "token-2");
    }

    #[tokio::test]
    async fn test_balanced_session_binds_only_after_success() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(first.id, 1);
        assert!(!manager.sticky_sessions.lock().contains_key("session-1"));

        manager.report_no_result(first.id);
        assert!(!manager.sticky_sessions.lock().contains_key("session-1"));

        let second = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        manager.report_success_for_session(second.id, Some("session-1"));
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-1")
                .map(|entry| entry.credential_id),
            Some(second.id)
        );
    }

    #[tokio::test]
    async fn test_balanced_selection_counts_in_flight_requests() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
                valid_access_credential("token-3", 2),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager.acquire_context(None).await.unwrap();
        let second = manager.acquire_context(None).await.unwrap();
        let third = manager.acquire_context(None).await.unwrap();

        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);
        assert_eq!(third.id, 3);

        // `#98`：此刻三张凭据 in_flight 均为 1、load 均为 0，新排序键完全打平，
        // 决胜落到 priority 一级即可分出胜负。
        // 注意：本夹具三张凭据的 priority(0/1/2) 恰好与 id 顺序重合，priority
        // 一级就已决出胜者，故本断言在新旧排序键下表现相同，**不是**针对新键
        // 的独立回归防护。区分新旧键的职责由 N1/N2/N3 承担；id 这一级
        // tiebreak 的独立覆盖由 N15
        // （test_balanced_tiebreak_picks_smaller_id_regardless_of_insertion_order）
        // 承担。
        let fourth = manager.acquire_context(None).await.unwrap();
        assert_eq!(fourth.id, 1);
        manager.report_no_result(fourth.id);

        manager.report_no_result(first.id);
        manager.report_no_result(second.id);
        manager.report_no_result(third.id);
    }

    #[tokio::test]
    async fn test_balanced_new_credential_seeds_load_from_current_minimum() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        // 用 TestClock 固定墙钟：真实时钟会在 add_credential 播种与随后两次
        // acquire 之间流逝几微秒，导致播种值相对 entries[0] 的哨兵值（永不
        // 衰减）产生浮点误差、打破本该精确相等的平局，使 tiebreak 断言变
        // flaky。
        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        {
            let mut entries = manager.entries.lock();
            entries[0].load = 100.0;
            entries[1].load = 120.0;
        }

        let new_credential = KiroCredentials {
            kiro_api_key: Some("ksk_new_key_123".to_string()),
            auth_method: Some("api_key".to_string()),
            priority: 2,
            ..Default::default()
        };

        let new_id = manager.add_credential(new_credential).await.unwrap();

        {
            let entries = manager.entries.lock();
            let new_entry = entries.iter().find(|e| e.id == new_id).unwrap();
            assert_eq!(new_entry.success_count, 0, "T4：success_count 不再参与播种");
            assert!(
                (new_entry.load - 100.0).abs() < 1e-9,
                "播种值应是未禁用凭据里 current_load 的最小值（100.0），而非 120.0"
            );
            assert_ne!(
                new_entry.load_updated_at_ms, 0,
                "播种时应记录时间基准，而非停在哨兵值"
            );
        }

        // `#98`：新排序键已在本 commit 生效，选路顺序断言随之补回。
        // 首选：token-1（load=100.0）与 new（播种值 100.0）平局，priority 0<2
        // 选 token-1（id 1）。
        let first = manager.acquire_context(None).await.unwrap();
        assert_eq!(first.id, 1);
        // 次选：token-1 因刚被选中 in_flight=1，键变成 101.0 > 100.0，new 反超
        // 当选。
        let second = manager.acquire_context(None).await.unwrap();
        assert_eq!(second.id, new_id);
    }

    // ===== #98 §B.3：新排序键（N1-N2） =====

    /// N1：根因 1（旧键以调用次数计量，不折算 credit 单位）。
    ///
    /// 凭据1 记 1 次 sol（权重 2.4）→ load=2.4；凭据2 记 2 次 luna（权重 0.6）
    /// → load=1.2。凭据2 次数更多但 credit 更少，新键应选它。
    #[tokio::test]
    async fn test_balanced_selection_weighs_by_credit_not_call_count() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.record_upstream_call(1, Some("gpt-5.6-sol"));
        manager.record_upstream_call(2, Some("gpt-5.6-luna"));
        manager.record_upstream_call(2, Some("gpt-5.6-luna"));

        let next = manager.acquire_context(None).await.unwrap();
        assert_eq!(
            next.id, 2,
            "凭据2 调用次数更多（2 次）但折算 credit 更少（1.2 < 2.4），新键应选它"
        );
    }

    /// registry.rs N13 第三段（`#98` 返工 MUST FIX C1）：删除全部
    /// `credit_weight` 字段后，balanced 选路仍然正常——用真实剥权重
    /// 的 registry 喂给一个 2 凭据 balanced manager，跑
    /// `acquire → record_upstream_call → acquire`，断言第二次选中
    /// 另一张凭据。
    ///
    /// 这段是 registry.rs 里 `test_deleting_credit_weight_fields_maintains_functionality`
    /// （N13）doc comment 承诺覆盖、但此前实际只测到 registry 层、从未
    /// 跑过选路的那一段验收——issue 验收清单「删除全部 credit_weight 字段后
    /// 选路正常、无 panic」由本测试兑现；registry.rs 处留了指引，不重复
    /// 描述覆盖内容避免两处 doc 打架。
    ///
    /// 第一次 `acquire_context` 的 `model` 参数传一个真实存在的 kiro_id
    /// （`gpt-5.6-sol`，剥权重后回落默认 1.0），让 `credit_weight_by_kiro_id`
    /// 的查表路径真的被走到，不是靠 `None` 的 1.0 短路蒙混过关。
    ///
    /// 反事实验证：把下方 `assert_eq!(next.id, ...)` 改成断言选中同一张
    /// （即预期值从"另一张"换成"第一次选中的那张"），会因 record 后该凭据
    /// 负载更高、选路选走另一张而断言失败——证明这段真的在观察选路结果，
    /// 不是恒绿。
    #[tokio::test]
    async fn test_balanced_selection_survives_credit_weight_fields_removed() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 0),
            ],
            None,
            None,
            false,
            test_registry_without_credit_weight_fields(),
        )
        .unwrap();

        let first = manager.acquire_context(Some("gpt-5.6-sol")).await.unwrap();
        manager.record_upstream_call(first.id, Some("gpt-5.6-sol"));

        let second = manager.acquire_context(None).await.unwrap();
        assert_ne!(
            second.id, first.id,
            "删除全部 credit_weight 字段后，balanced 选路仍应正常运作：\
             第一张凭据记过一次调用负载更高，第二次 acquire 应选中另一张"
        );
    }

    /// N2：根因 2（失败调用不计量，5xx 刷屏的凭据反而看起来"更闲"）。
    ///
    /// 凭据1 连续 5 次 5xx（`record_upstream_call` + `report_no_result`，一次
    /// 未成功）；凭据2 只成功 1 次。旧键（`success_count + in_flight`）下凭据1
    /// success=0、凭据2=1，会错误地继续把请求灌给已经在刷 5xx 的凭据1；新键
    /// 应选凭据2，直接钉死这条正反馈回路。
    #[tokio::test]
    async fn test_balanced_selection_counts_failed_calls_too() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        for _ in 0..5 {
            manager.record_upstream_call(1, None);
            manager.report_no_result(1);
        }
        manager.record_upstream_call(2, None);
        manager.report_success(2);

        let next = manager.acquire_context(None).await.unwrap();
        assert_eq!(
            next.id, 2,
            "凭据1 连续 5xx 应计入负载，不能因 success_count 仍是 0 而继续被选中"
        );
    }

    /// N15：新排序键第三级 tiebreak（`id`）的独立覆盖。
    ///
    /// `CredentialEntry.id` 可由调用方通过 `KiroCredentials.id` 显式指定，与
    /// `entries` 向量的插入顺序无必然关系（`new_with_clock`：`cred.id.unwrap_or_else(...)`
    /// 只在未指定时才按插入序自动分配）。本测试利用这一点，构造插入顺序与
    /// id 大小顺序**相反**的两张凭据——priority 相同、load 均 0、in_flight
    /// 均 0，前两级 tiebreak 全部打平，只有 id 这一级能决出胜者，从而把
    /// "选 id 较小者" 与 "选 Vec 迭代序中的第一个" 这两种可能行为区分开。
    #[tokio::test]
    async fn test_balanced_tiebreak_picks_smaller_id_regardless_of_insertion_order() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut cred_id2 = valid_access_credential("token-a", 0);
        cred_id2.id = Some(2);
        let mut cred_id1 = valid_access_credential("token-b", 0);
        cred_id1.id = Some(1);

        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            config,
            // 插入顺序：id 2 在前、id 1 在后——与 id 大小顺序相反。
            vec![cred_id2, cred_id1],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        let selected = manager.acquire_context(None).await.unwrap();
        assert_eq!(
            selected.id, 1,
            "priority/load/in_flight 全部打平时应选 id 较小者，而非插入序中的第一个"
        );
    }

    // ===== #98 §B：衰减与计量核心（N3-N8） =====

    /// N3：半衰期数学 + 根因 3（历史永不重置）。
    ///
    /// ⚠️数值断言与行为断言缺一不可——两者方向相同，单独一个不足以证明半衰期
    /// 常数真的生效（例如把 `LOAD_HALF_LIFE_MS` 改成 `INFINITY` 会让数值断言
    /// 先红，但若只断言行为方向，`INFINITY` 下"历史更重者反超"这个方向性结论
    /// 依然可能凑巧成立，测不出真正的半衰期数学）。
    #[test]
    fn test_current_load_decays_by_half_life_and_reorders_by_history() {
        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        let now0 = clock.now_unix_ms();
        {
            let mut entries = manager.entries.lock();
            entries[0].record_load(100.0, now0);
            entries[1].record_load(60.0, now0);
        }

        clock.advance_ms(12 * 60 * 60 * 1000);
        let now1 = clock.now_unix_ms();

        let (load1, load2) = {
            let entries = manager.entries.lock();
            (entries[0].current_load(now1), entries[1].current_load(now1))
        };
        assert!(
            (load1 - 50.0).abs() < 1e-6,
            "凭据1（历史 100）半衰期后应衰减到约 50.0，实际 {load1}"
        );
        assert!(
            (load2 - 30.0).abs() < 1e-6,
            "凭据2（历史 60）半衰期后应衰减到约 30.0，实际 {load2}"
        );

        // 行为段：凭据2 再记 45（30 + 45 = 75），历史更重的凭据1（50）此时反而更小，
        // 即衰减后"历史更重者"赢回更靠前的排位——历史包袱不再永久锁死排序。
        {
            let mut entries = manager.entries.lock();
            entries[1].record_load(45.0, now1);
        }
        let (load1_after, load2_after) = {
            let entries = manager.entries.lock();
            (entries[0].current_load(now1), entries[1].current_load(now1))
        };
        assert!(
            load1_after < load2_after,
            "历史更重的凭据1({load1_after}) 衰减后应小于凭据2({load2_after})，即会被优先选中"
        );
    }

    /// N4：重启 + 停机衰减。惰性求值的核心不变量——磁盘上存的是**衰减前**的
    /// 裸值，`load_stats` 只回填不计算，衰减只在 `current_load` 读侧发生。
    #[test]
    fn test_load_survives_restart_and_decays_only_on_read() {
        let cred_dir =
            std::env::temp_dir().join(format!("kiro-load-restart-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&cred_dir).unwrap();
        let _cleanup = TempDirGuard(cred_dir.clone());
        let cred_path = cred_dir.join("credentials.json");

        let clock_a = TestClock::new();
        let wall0 = clock_a.now_unix_ms();
        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let manager_a = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![cred.clone()],
            None,
            Some(cred_path.clone()),
            false,
            test_registry(),
            clock_a.clone(),
        )
        .unwrap();

        {
            let mut entries = manager_a.entries.lock();
            let entry = entries.iter_mut().find(|e| e.id == 1).unwrap();
            entry.record_load(80.0, wall0);
        }
        // 绕开防抖，立即落盘。
        manager_a.save_stats();

        let clock_b = TestClock::new();
        clock_b.set_wall_ms(wall0 + 24 * 60 * 60 * 1000); // A 之后 24 小时（2 个半衰期）重启
        let manager_b = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![cred],
            None,
            Some(cred_path),
            false,
            test_registry(),
            clock_b.clone(),
        )
        .unwrap();

        let entries = manager_b.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert!(
            (entry.load - 80.0).abs() < 1e-9,
            "磁盘原样读回，读取时不应就地衰减，实际 {}",
            entry.load
        );
        assert_eq!(
            entry.load_updated_at_ms, wall0,
            "应原样保留 A 写盘时的时间基准，而非重启时刻"
        );
        let decayed = entry.current_load(clock_b.now_unix_ms());
        assert!(
            (decayed - 20.0).abs() < 1e-6,
            "停机 24h（2 个半衰期）后 current_load 应约为 20.0，实际 {decayed}"
        );
    }

    /// N5：旧 `kiro_stats.json`（含 `balanced_offset`）兼容性。
    ///
    /// ⚠️只断言 `load == 0.0` 会恒绿——解析失败时新字段同样是 0.0（默认值）。
    /// `success_count == 728` 是关键断言：它证明整份文件确实被成功解析，而不
    /// 是解析失败后 `load_stats` 提前 return、entry 保持构造期默认值。
    #[test]
    fn test_load_stats_tolerates_legacy_balanced_offset_field() {
        let cred_dir =
            std::env::temp_dir().join(format!("kiro-load-legacy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&cred_dir).unwrap();
        let _cleanup = TempDirGuard(cred_dir.clone());
        std::fs::write(
            cred_dir.join("kiro_stats.json"),
            r#"{"1":{"success_count":728,"balanced_offset":100,"last_used_at":null}}"#,
        )
        .unwrap();

        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(cred_dir.join("credentials.json")),
            false,
            test_registry(),
        )
        .unwrap();

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert_eq!(
            entry.success_count, 728,
            "旧字段 balanced_offset 应被静默忽略，success_count 等其余字段须正常解析出来"
        );
        assert_eq!(entry.load, 0.0, "新字段缺失应回落默认值 0.0");
    }

    /// N6：`load` 字段为 `null` 时的读侧容错（对称写侧的 `save_stats_locked_at`
    /// 落盘防护：`serde_json` 把非有限浮点静默写成 `null`）。
    #[test]
    fn test_load_stats_tolerates_null_load_field() {
        let cred_dir =
            std::env::temp_dir().join(format!("kiro-load-null-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&cred_dir).unwrap();
        let _cleanup = TempDirGuard(cred_dir.clone());
        std::fs::write(
            cred_dir.join("kiro_stats.json"),
            r#"{"1":{"success_count":5,"load":null,"last_used_at":null}}"#,
        )
        .unwrap();

        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(cred_dir.join("credentials.json")),
            false,
            test_registry(),
        )
        .unwrap();

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert_eq!(
            entry.success_count, 5,
            "load 为 null 不应导致整个 HashMap 反序列化被拒绝"
        );
        assert_eq!(entry.load, 0.0, "null 应回落 0.0");
    }

    /// N7：NTP 回退自愈。`saturating_sub` 是唯一防线——裸减法会把负 elapsed
    /// 喂给 `powf`，变成 >1 的因子，让 load 在回拨期间反向增长。
    #[test]
    fn test_current_load_self_heals_after_clock_rollback() {
        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![valid_access_credential("token-1", 0)],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        let now0 = clock.now_unix_ms();
        {
            let mut entries = manager.entries.lock();
            entries[0].record_load(100.0, now0);
        }

        // NTP 回拨 1 小时。
        clock.set_wall_ms(now0.saturating_sub(60 * 60 * 1000));
        let rolled_back = clock.now_unix_ms();
        {
            let entries = manager.entries.lock();
            let load = entries[0].current_load(rolled_back);
            assert!(
                (load - 100.0).abs() < 1e-9,
                "回拨期间 saturating_sub 应把 elapsed 钳到 0，load 不增不塌不 NaN，实际 {load}"
            );
        }

        // 回拨期间再记一次：时间基准不应被拨回。
        {
            let mut entries = manager.entries.lock();
            entries[0].record_load(1.0, rolled_back);
            assert_eq!(
                entries[0].load_updated_at_ms, now0,
                "回拨期间不应把时间基准往回推，否则时钟恢复后会一次性补算掉不该衰减的那段"
            );
        }
        {
            let entries = manager.entries.lock();
            let load = entries[0].current_load(rolled_back);
            assert!((load - 101.0).abs() < 1e-9, "实际 {load}");
        }

        // 时钟恢复并越过原基准 12 小时——自愈：按 12h 半衰期正常衰减。
        clock.set_wall_ms(now0 + 12 * 60 * 60 * 1000);
        let now1 = clock.now_unix_ms();
        let load = {
            let entries = manager.entries.lock();
            entries[0].current_load(now1)
        };
        assert!(
            (load - 50.5).abs() < 1e-6,
            "时钟恢复后应从 101 按 12h 半衰期正常衰减到约 50.5，实际 {load}"
        );
    }

    /// N8：未登记权重的模型一律按 1.0 计入负载（`credit_weight_by_kiro_id` 的
    /// 既定回落行为，经 `record_upstream_call` 这条真实调用路径验证）。
    #[test]
    fn test_record_upstream_call_unknown_model_uses_default_weight() {
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![valid_access_credential("token-1", 0)],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.record_upstream_call(1, Some("some-model-nobody-registered"));

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert_eq!(
            entry.load, 1.0,
            "未登记模型应精确按权重 1.0 计入，实际 {}",
            entry.load
        );
    }

    /// N16（#98 返工 MUST FIX）：被校正的时钟前跳不应让衰减永久冻结。
    ///
    /// 场景还原：宿主墙钟一度前跳到 `now0`（chrony 收敛前 / VM 快照恢复），该
    /// 凭据恰在这一刻被记了一笔，`load_updated_at_ms` 被盖上 `now0` 这个"未来"
    /// 戳；随后 NTP 把墙钟校正回 `now0 - 24h`（超过 12h 半衰期阈值）。在旧逻辑
    /// 下，这之后每次 `decay_load_to` 都会判定"时钟倒退"而拒绝推进基准、也不
    /// 衰减——直到真实时间重新追上 `now0` 为止，load 只增不减，这个凭据在
    /// balanced 排序里会被冻结在高位、永不被选中。
    ///
    /// 反事实：把 `decay_load_to` 里的基准合理性检查删掉重跑本测试，最终
    /// `current_load` 应稳定停在 150.0（100 冻结未衰减 + 50 新记，advance 12h
    /// 后仍判定"倒退"不衰减），与断言的约 75.0 不符，真红。
    #[test]
    fn test_decay_load_to_resets_basis_after_corrected_clock_jump() {
        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![valid_access_credential("token-1", 0)],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        // 模拟前跳：在"未来"时刻 now0 记一笔，基准被盖上 now0。
        let now0 = clock.now_unix_ms();
        {
            let mut entries = manager.entries.lock();
            entries[0].record_load(100.0, now0);
        }

        // 模拟 NTP 校正：墙钟被拨回 now0 之前 24 小时（超过 12h 半衰期阈值，
        // 触发基准合理性检查；N7 覆盖的是 1 小时回拨，不越过阈值，两者互补）。
        let corrected = now0 - 24 * 60 * 60 * 1000;
        clock.set_wall_ms(corrected);
        {
            let mut entries = manager.entries.lock();
            entries[0].record_load(50.0, corrected);
        }

        {
            let entries = manager.entries.lock();
            assert_eq!(
                entries[0].load_updated_at_ms, corrected,
                "基准应被拉回校正后的墙钟，而非停在超前的 now0"
            );
            assert!(
                (entries[0].load - 150.0).abs() < 1e-9,
                "重置基准的那一刻不应衰减（无法推断该衰减多少），只叠加新权重：100 + 50 = 150，实际 {}",
                entries[0].load
            );
        }

        // 校正之后，时间照常往前走 12 小时——应恢复正常半衰期衰减。
        clock.advance_ms(12 * 60 * 60 * 1000);
        let after = clock.now_unix_ms();
        let load = {
            let entries = manager.entries.lock();
            entries[0].current_load(after)
        };
        assert!(
            (load - 75.0).abs() < 1e-6,
            "校正后正常前进 12h（1 个半衰期）应从 150 衰减到约 75.0，实际 {load}"
        );
    }

    /// N16 补充：`load_stats` 载入回填处的同一条基准合理性检查——覆盖"跨重启
    /// 存活"这一面。磁盘上的 `load_updated_at_ms` 本身就是前跳窗口内落盘的
    /// "未来"戳，新进程启动时墙钟已经是校正后的正常时间，载入应立即自愈，
    /// 不必等这枚凭据下次被 `record_load` 触达。
    ///
    /// 反事实：把 `load_stats` 里新增的重置检查删掉重跑本测试，`load_updated_at_ms`
    /// 会原样读回超前的 `future_basis`，`current_load(wall_at_restart)` 因
    /// `saturating_sub` 钳零而返回未衰减的 80.0，与断言的约 40.0 不符，真红。
    #[test]
    fn test_load_stats_resets_basis_when_disk_timestamp_is_ahead_of_wall_clock() {
        let cred_dir =
            std::env::temp_dir().join(format!("kiro-load-future-basis-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&cred_dir).unwrap();
        let _cleanup = TempDirGuard(cred_dir.clone());

        // 重启时的墙钟固定在某个基准点；磁盘上的 load_updated_at_ms 比它超前
        // 24 小时（同样越过 12h 半衰期阈值），模拟"前跳窗口内落盘、之后被
        // NTP 校正回来才重启"。
        let clock = TestClock::new();
        let wall_at_restart = clock.now_unix_ms();
        let future_basis = wall_at_restart + 24 * 60 * 60 * 1000;
        std::fs::write(
            cred_dir.join("kiro_stats.json"),
            format!(
                r#"{{"1":{{"success_count":3,"load":80.0,"load_updated_at_ms":{future_basis},"last_used_at":null}}}}"#
            ),
        )
        .unwrap();

        let cred = KiroCredentials {
            refresh_token: Some("token1".to_string()),
            ..Default::default()
        };
        let manager = MultiTokenManager::new_with_clock(
            Config::default(),
            vec![cred],
            None,
            Some(cred_dir.join("credentials.json")),
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        {
            let entries = manager.entries.lock();
            let entry = entries.iter().find(|e| e.id == 1).unwrap();
            assert_eq!(
                entry.load_updated_at_ms, wall_at_restart,
                "载入即应把超前的基准重置为当前墙钟，实际 {}",
                entry.load_updated_at_ms
            );
            assert!(
                (entry.load - 80.0).abs() < 1e-9,
                "重置基准不应连带改动 load 的裸值，实际 {}",
                entry.load
            );
        }

        clock.advance_ms(12 * 60 * 60 * 1000);
        let load = {
            let entries = manager.entries.lock();
            let entry = entries.iter().find(|e| e.id == 1).unwrap();
            entry.current_load(clock.now_unix_ms())
        };
        assert!(
            (load - 40.0).abs() < 1e-6,
            "重启后正常前进 12h（1 个半衰期）应从 80 衰减到约 40.0，实际 {load}"
        );
    }

    #[tokio::test]
    async fn test_balanced_session_sticky_quota_exhausted_falls_back() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        manager.report_success_for_session(first.id, Some("session-1"));
        assert!(manager.report_quota_exhausted(first.id));

        let fallback = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(fallback.id, 2);
    }

    #[tokio::test]
    async fn test_priority_mode_ignores_session_sticky_map() {
        let config = Config::default();
        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-1", 2);

        let ctx = manager
            .acquire_context_for_session(None, Some("session-1"))
            .await
            .unwrap();
        assert_eq!(ctx.id, 1);
        assert_eq!(ctx.token, "token-1");
    }

    #[tokio::test]
    async fn test_sticky_free_credential_is_not_used_for_opus() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut free_cred = valid_access_credential("free-token", 0);
        free_cred.subscription_title = Some("KIRO FREE".to_string());
        let mut pro_cred = valid_access_credential("pro-token", 1);
        pro_cred.subscription_title = Some("KIRO PRO".to_string());

        let manager = MultiTokenManager::new(
            config,
            vec![free_cred, pro_cred],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();
        manager.bind_sticky_session("session-1", 1);

        let ctx = manager
            .acquire_context_for_session(Some("claude-opus-4.7"), Some("session-1"))
            .await
            .unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "pro-token");
    }

    #[test]
    fn test_multi_token_manager_report_refresh_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        assert_eq!(manager.available_count(), 2);
        for _ in 0..(MAX_FAILURES_PER_CREDENTIAL - 1) {
            assert!(manager.report_refresh_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        assert!(manager.report_refresh_failure(1));
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.refresh_failure_count, MAX_FAILURES_PER_CREDENTIAL);
        assert_eq!(snapshot.current_id, 2);
    }

    // ===== #52: token 刷新永久失效分类器 =====

    #[test]
    fn test_classify_invalid_client_permanent() {
        let body = r#"{"error":"invalid_client","error_description":"Client not found"}"#;
        let r = classify_permanent_refresh_failure(401, body, "IdC");
        assert!(r.is_some(), "401 + invalid_client 应判永久失效");
        assert!(r.unwrap().message.contains("invalid_client"));
    }

    #[test]
    fn test_classify_invalid_grant_permanent() {
        let body =
            r#"{"error":"invalid_grant","error_description":"Invalid refresh token provided"}"#;
        let r = classify_permanent_refresh_failure(400, body, "Social");
        assert!(r.is_some(), "400 + invalid_grant + 描述匹配 应判永久失效");
        assert!(r.unwrap().message.contains("invalid_grant"));
    }

    #[test]
    fn test_classify_transient_returns_none() {
        assert!(
            classify_permanent_refresh_failure(500, "Internal Server Error", "IdC").is_none(),
            "5xx 是瞬态"
        );
        assert!(
            classify_permanent_refresh_failure(429, "Too Many Requests", "IdC").is_none(),
            "429 限流是瞬态"
        );
        assert!(
            classify_permanent_refresh_failure(401, r#"{"error":"server_error"}"#, "IdC").is_none(),
            "401 但 error 非 invalid_client 是瞬态"
        );
    }

    #[test]
    fn test_classify_no_false_kill() {
        // error_description 偶含 "invalid_client" 字样，但 error 字段非之 → 精确解析不误杀
        let body = r#"{"error":"server_error","error_description":"upstream said invalid_client"}"#;
        assert!(
            classify_permanent_refresh_failure(401, body, "IdC").is_none(),
            "error_description 含关键字不应误杀"
        );
        // invalid_grant 但缺 "Invalid refresh token provided" 描述 → 保守判瞬态（不放宽边界）
        let body = r#"{"error":"invalid_grant","error_description":"clock skew detected"}"#;
        assert!(
            classify_permanent_refresh_failure(400, body, "IdC").is_none(),
            "invalid_grant 无确切失效描述时保守判瞬态"
        );
    }

    #[test]
    fn test_report_refresh_token_invalid_disables_immediately() {
        let config = Config::default();
        let manager = MultiTokenManager::new(
            config,
            vec![KiroCredentials::default(), KiroCredentials::default()],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        assert_eq!(manager.available_count(), 2);
        // 永久失效一次即禁用（区别于 report_refresh_failure 的累计阈值）
        let has_available = manager.report_refresh_token_invalid(1);
        assert!(has_available, "禁用 #1 后仍有 #2 可用");
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled, "永久失效凭据应立即禁用");
        assert_eq!(snapshot.current_id, 2, "应已切换到存活凭据");
    }

    /// N9（#98 §F 缺陷1）：acquire_context 内 try_ensure_token 失败后走
    /// report_no_result + report_refresh_failure 两步，修复前会对 in_flight
    /// 减两次。用 saturating_sub 的陷阱是：从 1 减两次也饱和成 0，"acquire 后
    /// 断言 == 0" 在修复前后都绿——必须预置一个非零基线才能把两次减法与一次
    /// 减法区分开。
    ///
    /// 把 refresh_failure_count 预置到阈值-1，让这唯一一次失败的 acquire 尝试
    /// 直接触发禁用+bail，从而恰好只经历一次 Err 分支（不被内部重试循环再拖
    /// 着多跑几轮，避免多次失败的减法相互叠加、掩盖单次双减的信号）。
    #[tokio::test]
    async fn test_acquire_context_releases_in_flight_exactly_once_on_refresh_failure() {
        let config = Config::default();
        // 默认凭据缺少 refreshToken，try_ensure_token 会同步失败（validate_refresh_token
        // 报"缺少 refreshToken"），不发起任何网络请求，失败路径确定性触发。
        let manager = MultiTokenManager::new(
            config,
            vec![KiroCredentials::default()],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        {
            let mut entries = manager.entries.lock();
            let entry = entries.iter_mut().find(|e| e.id == 1).unwrap();
            // 阈值-1：这一次失败恰好把 refresh_failure_count 推到阈值，立即禁用+bail，
            // 保证 Err 分支只被执行一次。
            entry.refresh_failure_count = MAX_FAILURES_PER_CREDENTIAL - 1;
            // 预置一个非零基线（模拟并发中的其它在飞请求），使双减(-2)与单减(-1)
            // 的结果可区分（5 vs 4），而不是都饱和到 0。
            entry.in_flight_count = 5;
        }

        let err = manager.acquire_context(None).await.err();
        assert!(err.is_some(), "唯一凭据缺少 refreshToken，acquire 应失败");

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert_eq!(
            entry.in_flight_count, 5,
            "reserve(+1) 与唯一一次释放(-1) 应抵消，回到预置基线；\
             若 report_refresh_failure 仍重复释放会多减一次变成 4"
        );
    }

    /// N10（#98 §F 缺陷2）：report_refresh_token_invalid 同时被"有预留"
    /// （acquire_context 内部失败分支）与"无预留"（handle_usage_refresh_error，
    /// Admin 余额查询路径从未 reserve 过）两类调用方共用。修复后释放责任已
    /// 收归调用方，本函数自身不再改动 in_flight_count——直接调用它不应影响
    /// 该字段，否则"无预留"调用方会凭空偷走别的在飞请求的计数。
    #[test]
    fn test_report_refresh_token_invalid_does_not_touch_in_flight_without_reservation() {
        let config = Config::default();
        let manager = MultiTokenManager::new(
            config,
            vec![KiroCredentials::default(), KiroCredentials::default()],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        {
            let mut entries = manager.entries.lock();
            let entry = entries.iter_mut().find(|e| e.id == 1).unwrap();
            entry.in_flight_count = 3;
        }

        // 未经过任何 reserve，直接模拟 handle_usage_refresh_error 的调用形状。
        let has_available = manager.report_refresh_token_invalid(1);
        assert!(has_available, "禁用 #1 后仍有 #2 可用");

        let entries = manager.entries.lock();
        let entry = entries.iter().find(|e| e.id == 1).unwrap();
        assert_eq!(
            entry.in_flight_count, 3,
            "无预留的调用方不应释放 in_flight；若函数内仍有减法会变成 2"
        );
    }

    #[tokio::test]
    async fn test_multi_token_manager_refresh_failure_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_refresh_failure(1);
            manager.report_refresh_failure(2);
        }
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
    }

    #[test]
    fn test_multi_token_manager_report_quota_exhausted() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        assert_eq!(manager.available_count(), 2);
        assert!(manager.report_quota_exhausted(1));
        assert_eq!(manager.available_count(), 1);

        // 再禁用第二个后，无可用凭据
        assert!(!manager.report_quota_exhausted(2));
        assert_eq!(manager.available_count(), 0);
    }

    #[tokio::test]
    async fn test_multi_token_manager_quota_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager = MultiTokenManager::new(
            config,
            vec![cred1, cred2],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.report_quota_exhausted(1);
        manager.report_quota_exhausted(2);
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
        assert_eq!(manager.available_count(), 0);
    }

    // ============ 凭据级 Region 优先级测试 ============

    #[test]
    fn test_credential_region_priority_uses_credential_auth_region() {
        // 凭据配置了 auth_region 时，应使用凭据的 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            auth_region: Some("eu-west-1".to_string()),
            ..Default::default()
        };

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_credential_region() {
        // 凭据未配置 auth_region 但配置了 region 时，应回退到凭据.region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            region: Some("eu-central-1".to_string()),
            ..Default::default()
        };

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-central-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_config() {
        // 凭据未配置 auth_region 和 region 时，应回退到 config
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials::default();
        assert!(credentials.auth_region.is_none());
        assert!(credentials.region.is_none());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_multiple_credentials_use_respective_regions() {
        // 多凭据场景下，不同凭据使用各自的 auth_region
        let mut config = Config::default();
        config.region = "ap-northeast-1".to_string();

        let cred1 = KiroCredentials {
            auth_region: Some("us-east-1".to_string()),
            ..Default::default()
        };

        let cred2 = KiroCredentials {
            region: Some("eu-west-1".to_string()),
            ..Default::default()
        };

        let cred3 = KiroCredentials::default(); // 无 region，使用 config

        assert_eq!(cred1.effective_auth_region(&config), "us-east-1");
        assert_eq!(cred2.effective_auth_region(&config), "eu-west-1");
        assert_eq!(cred3.effective_auth_region(&config), "ap-northeast-1");
    }

    #[test]
    fn test_idc_oidc_endpoint_uses_credential_auth_region() {
        // 验证 IdC OIDC endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            auth_region: Some("eu-central-1".to_string()),
            ..Default::default()
        };

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);

        assert_eq!(refresh_url, "https://oidc.eu-central-1.amazonaws.com/token");
    }

    #[test]
    fn test_social_refresh_endpoint_uses_credential_auth_region() {
        // 验证 Social refresh endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            auth_region: Some("ap-southeast-1".to_string()),
            ..Default::default()
        };

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);

        assert_eq!(
            refresh_url,
            "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_api_call_uses_effective_api_region() {
        // 验证 API 调用使用 effective_api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            region: Some("eu-west-1".to_string()),
            ..Default::default()
        };

        // 凭据.region 不参与 api_region 回退链
        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.us-west-2.amazonaws.com");
    }

    #[test]
    fn test_api_call_uses_credential_api_region() {
        // 凭据配置了 api_region 时，API 调用应使用凭据的 api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            api_region: Some("eu-central-1".to_string()),
            ..Default::default()
        };

        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.eu-central-1.amazonaws.com");
    }

    #[test]
    fn test_credential_region_empty_string_treated_as_set() {
        // 空字符串 auth_region 被视为已设置（虽然不推荐，但行为应一致）
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials {
            auth_region: Some("".to_string()),
            ..Default::default()
        };

        let region = credentials.effective_auth_region(&config);
        // 空字符串被视为已设置，不会回退到 config
        assert_eq!(region, "");
    }

    #[test]
    fn test_auth_and_api_region_independent() {
        // auth_region 和 api_region 互不影响
        let mut config = Config::default();
        config.region = "default".to_string();

        let credentials = KiroCredentials {
            auth_region: Some("auth-only".to_string()),
            api_region: Some("api-only".to_string()),
            ..Default::default()
        };

        assert_eq!(credentials.effective_auth_region(&config), "auth-only");
        assert_eq!(credentials.effective_api_region(&config), "api-only");
    }

    // ----------------------------------------------------------------
    // BDD: sticky 路由稳定性（Step 4 不变量验证）
    // ----------------------------------------------------------------

    /// Scenario: 重试漂移不覆盖 sticky 绑定
    ///
    /// Given  balanced 模式，session-A 已成功绑定到凭据 1
    /// When   本次请求走 fallback，调 bind(session-A, 凭据 2)（模拟重试后绑回不同凭据）
    /// Then   sticky 仍指向凭据 1（bind 永不覆盖已有 entry 的 credential_id）
    #[test]
    fn test_retry_drift_preserves_sticky() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 首次绑定：session 绑到凭据 1
        manager.bind_sticky_session("session-A", 1);
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-A")
                .map(|e| e.credential_id),
            Some(1),
            "首次绑定后 sticky 应指向凭据 1"
        );

        // 模拟重试漂移：fallback 用凭据 2 成功，调 bind(session-A, 2)
        manager.bind_sticky_session("session-A", 2);

        // 不变量：credential_id 绝不被覆盖，仍为 1
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-A")
                .map(|e| e.credential_id),
            Some(1),
            "bind 不应覆盖已有 entry 的 credential_id（重试漂移保护）"
        );
    }

    /// Scenario: 凭据被禁用清除 sticky 后，允许重新首绑到新凭据
    ///
    /// Given  session-B 已绑定到凭据 1
    /// When   凭据 1 被禁用（report_quota_exhausted 触发 clear_sticky_sessions_for_credential）
    /// And    再次调 bind(session-B, 凭据 2)
    /// Then   sticky 指向凭据 2（首绑路径，clear 后视为新 entry）
    #[test]
    fn test_disabled_credential_allows_rebind() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 首次绑定：session 绑到凭据 1
        manager.bind_sticky_session("session-B", 1);
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-B")
                .map(|e| e.credential_id),
            Some(1),
            "首次绑定后 sticky 应指向凭据 1"
        );

        // 模拟凭据 1 真失效：report_quota_exhausted 内部调 clear_sticky_sessions_for_credential(1)
        // 此处直接调内部清除方法验证"首绑路径"，不走完整 acquire 流程
        manager.clear_sticky_sessions_for_credential(1);
        assert!(
            !manager.sticky_sessions.lock().contains_key("session-B"),
            "凭据禁用后 sticky 应被清除"
        );

        // 清除后首次绑定到凭据 2
        manager.bind_sticky_session("session-B", 2);
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-B")
                .map(|e| e.credential_id),
            Some(2),
            "凭据真失效清除 sticky 后，应允许重新绑定到新凭据"
        );
    }

    /// Scenario: token 刷新瞬态失败不清 sticky（acquire 路径收敛验证）
    ///
    /// 直接验证 bind 不变量：即使多次调用 bind(同 session, 不同 credential_id)，
    /// 已绑定的 credential_id 也绝不被覆盖。
    /// acquire 路径删除了 try_ensure_token 失败后的 clear，
    /// 该行为由代码审查（clear_sticky_session_if_matches 唯一调用方为 select_sticky_credential）
    /// + grep 确认（见交付报告）共同保证。
    #[test]
    fn test_token_refresh_failure_does_not_drift() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        // 建立初始绑定：session 绑到凭据 1
        manager.bind_sticky_session("session-C", 1);

        // 多次"重试漂移"模拟：token 刷新失败后重试可能选中任意凭据并 bind
        for _ in 0..5 {
            manager.bind_sticky_session("session-C", 2);
        }

        // 不变量：credential_id 永远不变
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-C")
                .map(|e| e.credential_id),
            Some(1),
            "多次 bind 不同 credential_id 不应改变已绑定的 sticky（token 瞬态失败保护）"
        );

        // 补充：clear_sticky_session_if_matches 唯一调用方应为 select_sticky_credential
        // （acquire 路径已删除两处 clear 调用，grep 确认见交付报告）
    }

    // ----------------------------------------------------------------
    // BDD: #86 —— sticky 清除时机可靠化
    // ----------------------------------------------------------------

    /// Scenario: 单次失败未达阈值时，绝不清任何 sticky 绑定（核心回归）
    ///
    /// Given  balanced 模式，凭据 1/2；session-A、session-B 均已绑定到凭据 1
    /// When   对凭据 1 上报一次失败（MAX_FAILURES_PER_CREDENTIAL=3，1 < 3，未达阈值）
    /// Then   两个 session 的 sticky 绑定原样保留，凭据 1 仍处于启用状态
    #[test]
    fn test_failure_below_threshold_clears_no_sticky() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-A", 1);
        manager.bind_sticky_session("session-B", 1);

        let has_available = manager.report_failure(1);

        assert!(has_available, "未达阈值时仍应有可用凭据");
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-A")
                .map(|e| e.credential_id),
            Some(1),
            "未达阈值的失败不应清除 session-A 的 sticky 绑定"
        );
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-B")
                .map(|e| e.credential_id),
            Some(1),
            "未达阈值的失败不应清除 session-B 的 sticky 绑定"
        );
        assert!(
            !manager
                .entries
                .lock()
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled,
            "未达阈值时凭据不应被禁用"
        );
    }

    /// Scenario: 累计失败达到阈值触发禁用时，批量清除该凭据下所有 session 的 sticky
    ///
    /// Given  balanced 模式，session-A、session-B 均已绑定到凭据 1
    /// When   连续 3 次上报失败，第 3 次跨越 MAX_FAILURES_PER_CREDENTIAL 触发禁用
    /// Then   凭据 1 被禁用，session-A、session-B 的 sticky 绑定均被清除
    #[test]
    fn test_failure_at_threshold_clears_all_sessions_on_credential() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-A", 1);
        manager.bind_sticky_session("session-B", 1);

        manager.report_failure(1);
        manager.report_failure(1);
        manager.report_failure(1); // 第 3 次达到阈值，触发禁用

        assert!(
            manager
                .entries
                .lock()
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled,
            "达到阈值后凭据应被禁用"
        );
        assert!(
            !manager.sticky_sessions.lock().contains_key("session-A"),
            "凭据被禁用后 session-A 的 sticky 绑定应被清除"
        );
        assert!(
            !manager.sticky_sessions.lock().contains_key("session-B"),
            "凭据被禁用后 session-B 的 sticky 绑定应被清除"
        );
    }

    /// Scenario: 路径一端到端——excluded_ids 只是本次请求临时跳过，不代表凭据真失效
    ///
    /// Given  session-X 已绑定凭据 1，凭据 1、2 均启用
    /// When   本次请求把凭据 1 放进 excluded_ids 后走完整 acquire 流程，回落到凭据 2 并成功
    /// Then   sticky 仍指向凭据 1（不因临时排除而被重新绑定到凭据 2）
    #[tokio::test]
    async fn test_excluded_credential_falls_back_without_rebinding() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-X", 1);

        let excluded = HashSet::from([1]);
        let ctx = manager
            .acquire_context_for_session_excluding(None, Some("session-X"), &excluded)
            .await
            .unwrap();
        assert_eq!(ctx.id, 2, "凭据 1 被本次请求排除时应回落到凭据 2");

        manager.report_success_for_session(ctx.id, Some("session-X"));

        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-X")
                .map(|e| e.credential_id),
            Some(1),
            "excluded 只是本次请求临时跳过，不代表凭据 1 真失效，sticky 不应被重新绑定到凭据 2"
        );
    }

    /// Scenario: 路径二端到端——凭据真失效后，session 迁移并重新粘住新凭据
    ///
    /// Given  session-Y 已成功绑定凭据 1
    /// When   凭据 1 连续失败到阈值被真实禁用（批量清 sticky），session-Y 再次请求
    /// Then   请求迁移到凭据 2 并成功，sticky 重新粘住凭据 2（不漂回也不失败）
    #[tokio::test]
    async fn test_disabled_credential_migrates_and_sticks_to_new() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        let first = manager
            .acquire_context_for_session(None, Some("session-Y"))
            .await
            .unwrap();
        assert_eq!(first.id, 1);
        manager.report_success_for_session(first.id, Some("session-Y"));

        // 凭据 1 连续失败到阈值，触发真实禁用 + 批量清 sticky
        manager.report_failure(1);
        manager.report_failure(1);
        manager.report_failure(1);
        assert!(
            manager
                .entries
                .lock()
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled
        );
        assert!(!manager.sticky_sessions.lock().contains_key("session-Y"));

        // 迁移：session-Y 再次请求应落到凭据 2 并重新首绑
        let migrated = manager
            .acquire_context_for_session(None, Some("session-Y"))
            .await
            .unwrap();
        assert_eq!(migrated.id, 2, "凭据 1 已禁用，session 应迁移到凭据 2");
        manager.report_success_for_session(migrated.id, Some("session-Y"));

        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-Y")
                .map(|e| e.credential_id),
            Some(2),
            "迁移后应重新粘住凭据 2，不漂回也不失败"
        );
    }

    /// Scenario: report_refresh_failure 控制流整理后，未达阈值仍不清 sticky（对称覆盖）
    ///
    /// 证明 #86 的控制流卫生改动（早 return 改为落在统一返回路径）没有改变清除语义：
    /// 未达阈值时 clear 这一步与整理前逐字节等价。
    ///
    /// 有意的行为差异（S1 更正，非等价声明）：整理前的早 return 会顺带跳过尾部
    /// `save_stats_debounced()`；整理后统一落到尾部，`save_stats_debounced()` 由
    /// "被跳过"变为"会执行"。这一变化本身无害（与 report_failure 未达阈值分支的
    /// 既有行为对齐），但属于有意收敛，不是"整理前后逐字节等价"——不应被后人当作
    /// 等价性证明来引用。
    #[test]
    fn test_refresh_failure_below_threshold_clears_no_sticky() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-A", 1);

        let has_available = manager.report_refresh_failure(1);

        assert!(has_available, "未达阈值时仍应有可用凭据");
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-A")
                .map(|e| e.credential_id),
            Some(1),
            "未达阈值的刷新失败不应清除 sticky 绑定（clear 语义整理前后等价）"
        );
        assert!(
            !manager
                .entries
                .lock()
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled,
            "未达阈值时凭据不应被禁用"
        );
    }

    /// Scenario: 窄竞态——sticky 命中后 reserve 失败，acquire 路径不直接清 sticky
    ///
    /// Given  session-Z 已通过 select_sticky_credential 真实命中凭据 1（凭据此时仍启用）
    /// When   命中与 reserve 之间凭据 1 被禁用（模拟并发窗口，不经过任何 report_*，
    ///        故不会触发批量清理），再调用 reserve_existing_credential_excluding(1, ...)
    ///        复现 acquire 路径紧接着的第二步
    /// Then   reserve 返回 None（凭据已不可用），但 sticky_sessions 中 session-Z 的绑定
    ///        原样保留——这条窄竞态分支不做自清理，交由触发禁用那次 report_* 的批量
    ///        清理收尾（是"够用"而非遗漏）
    #[test]
    fn test_narrow_race_reserve_fail_does_not_clear_sticky_directly() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-Z", 1);

        // 凭据仍启用时先真实命中，还原 acquire 路径的第一步
        let hit = manager.select_sticky_credential("session-Z", None, &HashSet::new());
        assert_eq!(hit.map(|(id, _)| id), Some(1), "命中时凭据 1 应仍启用");

        // 模拟窄竞态窗口：命中后、reserve 前凭据被禁用。直接改 entries 里的
        // disabled 标志，而不经过 set_disabled/report_failure/report_refresh_failure
        // 这些会顺带调用 clear_sticky_sessions_for_credential 的入口——生产中所有
        // 真实禁用路径都会触发批量清理，此处刻意绕开它们，才能精确复现
        // "只禁用、不批量清理"这条窄竞态窗口，验证 acquire 路径自身不做自清理。
        {
            let mut entries = manager.entries.lock();
            entries.iter_mut().find(|e| e.id == 1).unwrap().disabled = true;
        }

        let reserved = manager.reserve_existing_credential_excluding(1, None, &HashSet::new());
        assert!(reserved.is_none(), "凭据已禁用，reserve 应失败");

        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-Z")
                .map(|e| e.credential_id),
            Some(1),
            "reserve 失败的窄竞态分支不应自行清 sticky，交由禁用来源的批量清理负责"
        );
    }

    /// Scenario: excluded_ids 命中时 select_sticky_credential 直接返回 None，不清 entry
    ///
    /// Given  session-W 已绑定凭据 1，凭据 1 仍启用
    /// When   本次请求把凭据 1 放进 excluded_ids（临时跳过，非真失效）后调用
    ///        select_sticky_credential
    /// Then   返回 None，但 sticky_sessions 中的绑定原样保留
    #[test]
    fn test_excluded_ids_hit_does_not_clear_entry() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let manager = MultiTokenManager::new(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
        )
        .unwrap();

        manager.bind_sticky_session("session-W", 1);

        let excluded = HashSet::from([1]);
        let hit = manager.select_sticky_credential("session-W", None, &excluded);

        assert!(hit.is_none(), "凭据 1 在 excluded_ids 中时应直接未命中");
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-W")
                .map(|e| e.credential_id),
            Some(1),
            "excluded_ids 命中分支不应清除 entry（只是本次请求跳过，非凭据真失效）"
        );
    }

    /// Scenario: sticky 绑定超过 TTL（6 小时）后应被判定过期并移除
    #[test]
    fn test_sticky_ttl_expiry_removes_entry() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            config,
            vec![valid_access_credential("token-1", 0)],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        manager.bind_sticky_session("session-TTL", 1);
        assert_eq!(
            manager
                .sticky_sessions
                .lock()
                .get("session-TTL")
                .map(|e| e.credential_id),
            Some(1)
        );

        // 推进超过 TTL
        clock.advance_ms(STICKY_SESSION_TTL_MS + 1);

        let hit = manager.select_sticky_credential("session-TTL", None, &HashSet::new());
        assert!(hit.is_none(), "超过 TTL 的绑定不应再被命中");
        assert!(
            !manager.sticky_sessions.lock().contains_key("session-TTL"),
            "select_sticky_credential 判定过期时应顺带移除该 entry"
        );
    }

    /// Scenario: 会话粘性映射超过 LRU 容量上限时，最久未使用的 entry 应最先被淘汰
    ///
    /// 用 TestClock 手动推进而非真实 sleep：真实时钟在同一测试内几乎同时完成，
    /// 精度不足以让 last_used_at 彼此可区分，无法驱动确定性 LRU 断言，
    /// 这正是引入 Clock 抽象要解决的问题。
    #[test]
    fn test_sticky_lru_eviction_removes_oldest_first() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            config,
            vec![valid_access_credential("token-1", 0)],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        // 逐个绑定 MAX_STICKY_SESSIONS + 1 个 session，每次推进 1ms，
        // 保证 last_used_at 严格递增、彼此可区分。
        for i in 0..=MAX_STICKY_SESSIONS {
            manager.bind_sticky_session(&format!("session-{i}"), 1);
            clock.advance_ms(1);
        }

        let sessions = manager.sticky_sessions.lock();
        assert_eq!(
            sessions.len(),
            MAX_STICKY_SESSIONS,
            "超出上限后应被裁剪回容量上限"
        );
        assert!(
            !sessions.contains_key("session-0"),
            "最久未使用（最早绑定）的 session-0 应被优先淘汰"
        );
        assert!(
            sessions.contains_key(&format!("session-{MAX_STICKY_SESSIONS}")),
            "最近绑定的 session 应保留"
        );
    }

    /// Scenario: 周期清扫节流闸经 Clock 取时，能被 TestClock 精确驱动触发（#86 返工 S3）
    ///
    /// 背景：`maybe_prune_sticky_sessions` 的 60s 节流闸此前基于真实 `Instant`，
    /// TestClock 推进不触发它，只能靠撑爆 MAX_STICKY_SESSIONS 间接触发清扫，
    /// 周期性清扫这条路径本身零覆盖——半迁移的抽象。
    ///
    /// Given  session-old 在 t=0 绑定凭据 1，容量远未达上限（只有 1 个 entry）
    /// When   时钟推进超过 TTL（同时超过 60s 清扫节流间隔），随后绑定 session-new
    ///        触发 `maybe_prune_sticky_sessions` 的按时清扫分支（非容量触发）
    /// Then   session-old 应被这次周期清扫直接从底层 map 移除——断言直接读
    ///        `sticky_sessions` 原始 map，不经由 `select_sticky_credential`（它自己
    ///        对被查询 session 有独立的按需 TTL 检查，会掩盖周期清扫是否真的生效）
    #[test]
    fn test_periodic_sweep_driven_by_clock_not_wallclock() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let clock = TestClock::new();
        let manager = MultiTokenManager::new_with_clock(
            config,
            vec![
                valid_access_credential("token-1", 0),
                valid_access_credential("token-2", 1),
            ],
            None,
            None,
            false,
            test_registry(),
            clock.clone(),
        )
        .unwrap();

        manager.bind_sticky_session("session-old", 1);

        // 推进超过 TTL（远大于 60s 清扫节流间隔，两个条件同时满足）
        clock.advance_ms(STICKY_SESSION_TTL_MS + 1);

        // 绑定 session-new 触发 maybe_prune_sticky_sessions；prune 发生在
        // bind_sticky_session 内部插入新 entry 之前，故此刻 map 里只有 session-old
        // 可能被清扫，不存在"新 entry 混进被扫描集合"的干扰。
        manager.bind_sticky_session("session-new", 2);

        let sessions = manager.sticky_sessions.lock();
        assert!(
            !sessions.contains_key("session-old"),
            "按时触发的周期清扫应把过期的 session-old 一并清掉，证明清扫节流闸已切换到 Clock 驱动"
        );
        assert!(
            sessions.contains_key("session-new"),
            "本次刚绑定的 session-new 不应被清扫误伤"
        );
    }

    async fn profile_server(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8(request[..read].to_vec()).unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (format!("http://{address}/ListAvailableProfiles"), task)
    }

    fn profile_test_manager(
        clock: Arc<dyn Clock>,
        credentials: Vec<KiroCredentials>,
        path: Option<PathBuf>,
        multiple: bool,
    ) -> MultiTokenManager {
        MultiTokenManager::new_with_clock(
            Config::default(),
            credentials,
            None,
            path,
            multiple,
            test_registry(),
            clock,
        )
        .unwrap()
    }

    fn lookup_counts(manager: &MultiTokenManager, id: u64) -> (u32, u32, Option<String>) {
        let entries = manager.entries.lock();
        let entry = entries.iter().find(|entry| entry.id == id).unwrap();
        (
            entry.failure_count,
            entry.refresh_failure_count,
            entry.credentials.profile_arn.clone(),
        )
    }

    #[tokio::test]
    async fn b04_loopback_profile_request_uses_observed_schema_and_headers() {
        let (url, server) = profile_server("200 OK", r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a","unknown":true}],"nextToken":null}"#).await;
        let credentials = valid_access_credential("unit-access-token", 0);
        let response = MultiTokenManager::list_available_profiles_at(
            &url,
            &credentials,
            &Config::default(),
            "unit-access-token",
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            response.profiles.len(),
            1,
            "前提：必须实际解析 observed profiles schema"
        );
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /ListAvailableProfiles HTTP/1.1\r\n"));
        assert!(
            request.contains("content-type: application/json")
                || request.contains("Content-Type: application/json")
        );
        assert!(
            request.contains("authorization: Bearer unit-access-token")
                || request.contains("Authorization: Bearer unit-access-token")
        );
        assert!(request.ends_with("\r\n\r\n{}"), "请求体必须为空对象");
    }

    #[tokio::test]
    async fn b04_non_success_profile_response_keeps_body_out_of_error() {
        let body = r#"{"error":"fixed-safe-profile-error"}"#;
        let (url, server) = profile_server("403 Forbidden", body).await;
        let credentials = valid_access_credential("unit-access-token", 0);
        let error = MultiTokenManager::list_available_profiles_at(
            &url,
            &credentials,
            &Config::default(),
            "unit-access-token",
            None,
        )
        .await
        .unwrap_err();

        server.await.unwrap();
        let error_text = format!("{error:#}");
        assert!(error_text.contains("403 Forbidden"));
        assert!(error_text.contains("us-east-1"));
        assert!(!error_text.contains(body));
        assert!(!error_text.contains("unit-access-token"));
    }

    async fn assert_profile_lookup_failure_case(
        manager: &MultiTokenManager,
        url: String,
        server: Option<tokio::task::JoinHandle<String>>,
        case: &str,
    ) {
        let id = 1;
        let before = lookup_counts(manager, id);
        *manager.test_profile_lookup_url.lock() = Some(url);
        let (credentials, token) = manager
            .acquire_latest_credentials_and_token(id)
            .await
            .unwrap_or_else(|error| {
                panic!("{case}: lookup failure must keep the token usable: {error}")
            });
        assert_eq!(
            token, "token",
            "{case}: must return the current access token"
        );
        assert!(
            credentials.profile_arn.is_none(),
            "{case}: failed discovery must not synthesize an ARN"
        );
        if let Some(server) = server {
            let request = server.await.unwrap();
            assert!(
                request.starts_with("POST /ListAvailableProfiles"),
                "{case}: listener must observe the discovery request"
            );
        }
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            1,
            "{case}: discovery HTTP path must be entered exactly once"
        );
        let after = lookup_counts(manager, id);
        assert_eq!(
            (after.0, after.1),
            (before.0, before.1),
            "{case}: discovery failure is not an API or refresh failure"
        );
        assert!(after.2.is_none(), "{case}: entry ARN must remain absent");
        assert_eq!(
            manager.entries.lock()[0].profile_lookup_retry_after_ms,
            Some(PROFILE_LOOKUP_COOLDOWN_MS),
            "{case}: must start the 60-second cooldown"
        );
    }

    #[tokio::test]
    async fn b05_lookup_failures_cool_down_without_touching_failure_counters() {
        let (http_500_url, http_500_server) =
            profile_server("500 Internal Server Error", "{}").await;
        let http_500_manager = profile_test_manager(
            TestClock::new(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        assert_profile_lookup_failure_case(
            &http_500_manager,
            http_500_url,
            Some(http_500_server),
            "HTTP 500",
        )
        .await;

        let (malformed_url, malformed_server) = profile_server("200 OK", "{bad json").await;
        let malformed_manager = profile_test_manager(
            TestClock::new(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        assert_profile_lookup_failure_case(
            &malformed_manager,
            malformed_url,
            Some(malformed_server),
            "200 with malformed JSON",
        )
        .await;

        let connection_failure_manager = profile_test_manager(
            TestClock::new(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        assert_profile_lookup_failure_case(
            &connection_failure_manager,
            "http://127.0.0.1:1/ListAvailableProfiles".into(),
            None,
            "connection failure",
        )
        .await;

        let (empty_profiles_url, empty_profiles_server) =
            profile_server("200 OK", r#"{"profiles":[]}"#).await;
        let empty_profiles_manager = profile_test_manager(
            TestClock::new(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        assert_profile_lookup_failure_case(
            &empty_profiles_manager,
            empty_profiles_url,
            Some(empty_profiles_server),
            "200 with empty profiles",
        )
        .await;
    }

    #[tokio::test]
    async fn b05_outer_region_only_first_page_cools_down_without_persisting() {
        let directory = std::env::temp_dir().join(format!(
            "kiro-profile-other-region-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TempDirGuard(directory.clone());
        let path = directory.join("credentials.json");
        let original = b"[{\n  \"accessToken\": \"fixture\"\n}]\n";
        std::fs::write(&path, original).unwrap();
        let mut credential = valid_access_credential("token", 0);
        credential.id = Some(1);
        credential.machine_id = Some("test-machine-id".into());
        let manager =
            profile_test_manager(TestClock::new(), vec![credential], Some(path.clone()), true);
        let (url, server) = profile_server(
            "200 OK",
            r#"{"profiles":[{"arn":"arn:aws:codewhisperer:eu-west-1:111111111111:profile/other-region"}],"nextToken":"unverified-page"}"#,
        )
        .await;

        assert_profile_lookup_failure_case(
            &manager,
            url,
            Some(server),
            "200 with only other-region profiles on first page",
        )
        .await;
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "failed first-page selection must not persist an other-region ARN"
        );
    }

    #[tokio::test]
    async fn b06_api_key_skips_profile_lookup() {
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![KiroCredentials {
                kiro_api_key: Some("unit-api-key".into()),
                auth_method: Some("api_key".into()),
                profile_arn: Some(" ".into()),
                ..Default::default()
            }],
            None,
            false,
        );
        let id = 1;
        *manager.test_profile_lookup_url.lock() =
            Some("http://127.0.0.1:1/ListAvailableProfiles".into());
        let (credentials, token) = manager
            .acquire_latest_credentials_and_token(id)
            .await
            .unwrap();
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            0,
            "API key 不能进入 lookup HTTP 路径"
        );
        assert_eq!(token, "unit-api-key");
        assert_eq!(credentials.kiro_api_key.as_deref(), Some("unit-api-key"));
        assert_eq!(
            credentials.profile_arn.as_deref(),
            Some(" "),
            "API-key credentials must not be rewritten by OAuth profile validation"
        );
    }

    #[tokio::test]
    async fn b07_valid_existing_profile_arn_skips_profile_lookup_even_cross_region() {
        let mut credential = valid_access_credential("token", 0);
        credential.profile_arn =
            Some("arn:aws:codewhisperer:eu-west-1:111111111111:profile/explicit".into());
        let manager =
            profile_test_manager(Arc::new(ProcessClock::new()), vec![credential], None, false);
        *manager.test_profile_lookup_url.lock() =
            Some("http://127.0.0.1:1/ListAvailableProfiles".into());
        let (credentials, _) = manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        assert_eq!(
            credentials.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:eu-west-1:111111111111:profile/explicit")
        );
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            0,
            "a structurally valid explicit ARN must skip lookup regardless of region"
        );
    }

    #[tokio::test]
    async fn b07_invalid_oauth_arn_failure_returns_none_without_mutating_source() {
        for invalid_arn in [
            "   ",
            "arn::codewhisperer:us-east-1:111111111111:profile/name",
        ] {
            let directory = std::env::temp_dir().join(format!(
                "kiro-profile-invalid-snapshot-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let _cleanup = TempDirGuard(directory.clone());
            let path = directory.join("credentials.json");
            let original = format!(r#"[{{"profileArn":"{invalid_arn}"}}]"#);

            let clock = TestClock::new();
            let mut credential = valid_access_credential("token", 0);
            credential.profile_arn = Some(invalid_arn.into());
            let manager =
                profile_test_manager(clock.clone(), vec![credential], Some(path.clone()), true);
            *manager.test_profile_lookup_url.lock() =
                Some("http://127.0.0.1:1/ListAvailableProfiles".into());
            std::fs::write(&path, &original).unwrap();

            let before = lookup_counts(&manager, 1);
            let (first, _) = manager
                .acquire_latest_credentials_and_token(1)
                .await
                .unwrap();
            assert!(
                first.profile_arn.is_none(),
                "{invalid_arn:?}: failed discovery must suppress the invalid request snapshot"
            );
            assert_eq!(lookup_counts(&manager, 1), before);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                original,
                "{invalid_arn:?}: failed discovery must not rewrite the source file"
            );
            assert_eq!(
                manager.entries.lock()[0].credentials.profile_arn.as_deref(),
                Some(invalid_arn),
                "{invalid_arn:?}: entry must retain the operator-provided value for retry"
            );
            assert_eq!(
                manager
                    .test_profile_lookup_request_count
                    .load(Ordering::SeqCst),
                1
            );

            let (cooling, _) = manager
                .acquire_latest_credentials_and_token(1)
                .await
                .unwrap();
            assert!(cooling.profile_arn.is_none());
            assert_eq!(
                manager
                    .test_profile_lookup_request_count
                    .load(Ordering::SeqCst),
                1,
                "{invalid_arn:?}: cooldown must skip lookup"
            );

            clock.advance_ms(PROFILE_LOOKUP_COOLDOWN_MS);
            let (retried, _) = manager
                .acquire_latest_credentials_and_token(1)
                .await
                .unwrap();
            assert!(retried.profile_arn.is_none());
            assert_eq!(
                manager
                    .test_profile_lookup_request_count
                    .load(Ordering::SeqCst),
                2,
                "{invalid_arn:?}: retry must resume at the cooldown boundary"
            );
        }
    }

    #[tokio::test]
    async fn b07_empty_or_malformed_existing_profile_arn_reenters_lookup() {
        for existing_arn in [
            "",
            "   ",
            "arn:aws:codewhisperer:us-east-1:111111111111:profile/",
            "arn::codewhisperer:us-east-1:111111111111:profile/name",
            "arn:aws:codewhisperer:us-east-1::profile/name",
        ] {
            let mut credential = valid_access_credential("token", 0);
            credential.profile_arn = Some(existing_arn.into());
            let manager =
                profile_test_manager(Arc::new(ProcessClock::new()), vec![credential], None, false);
            let (url, server) = profile_server(
                "200 OK",
                r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/discovered"}]}"#,
            )
            .await;
            *manager.test_profile_lookup_url.lock() = Some(url);

            let (credentials, _) = manager
                .acquire_latest_credentials_and_token(1)
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(
                credentials.profile_arn.as_deref(),
                Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/discovered"),
                "{existing_arn:?} must be treated as missing"
            );
            assert_eq!(
                manager
                    .test_profile_lookup_request_count
                    .load(Ordering::SeqCst),
                1,
                "{existing_arn:?} must enter lookup exactly once"
            );
        }
    }

    #[tokio::test]
    async fn b08_successful_lookup_updates_return_and_entry() {
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        let (url, server) = profile_server("200 OK", r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a"}]}"#).await;
        *manager.test_profile_lookup_url.lock() = Some(url);
        let (credentials, _) = manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        server.await.unwrap();
        let expected = "arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a";
        assert_eq!(credentials.profile_arn.as_deref(), Some(expected));
        assert_eq!(lookup_counts(&manager, 1).2.as_deref(), Some(expected));
    }

    #[tokio::test]
    async fn b11_cooldown_retries_only_at_exact_clock_boundary() {
        let clock = TestClock::new();
        let manager = profile_test_manager(
            clock.clone(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        let (first_url, first_server) = profile_server("200 OK", "{bad json").await;
        *manager.test_profile_lookup_url.lock() = Some(first_url);
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        first_server.await.unwrap();
        assert_eq!(
            manager.entries.lock()[0].profile_lookup_retry_after_ms,
            Some(60_000)
        );
        clock.advance_ms(59_999);
        *manager.test_profile_lookup_url.lock() =
            Some("http://127.0.0.1:1/ListAvailableProfiles".into());
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        assert_eq!(
            manager.entries.lock()[0].profile_lookup_retry_after_ms,
            Some(60_000),
            "60 秒内不得重试"
        );
        clock.advance_ms(1);
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        assert_eq!(
            manager.entries.lock()[0].profile_lookup_retry_after_ms,
            Some(120_000),
            "恰到边界必须重试并重置冷却"
        );
    }

    #[tokio::test]
    async fn b12_array_persistence_round_trips_profile_arn() {
        let directory =
            std::env::temp_dir().join(format!("kiro-profile-array-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TempDirGuard(directory.clone());
        let path = directory.join("credentials.json");
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            Some(path.clone()),
            true,
        );
        let (url, server) = profile_server("200 OK", r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a"}]}"#).await;
        *manager.test_profile_lookup_url.lock() = Some(url);
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        server.await.unwrap();
        let loaded = crate::kiro::model::credentials::CredentialsConfig::load(&path).unwrap();
        let credentials = loaded.into_sorted_credentials();
        assert_eq!(
            credentials[0].profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a")
        );
    }

    #[tokio::test]
    async fn b13_single_object_keeps_source_bytes_unchanged() {
        let directory =
            std::env::temp_dir().join(format!("kiro-profile-single-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TempDirGuard(directory.clone());
        let path = directory.join("credentials.json");
        let original = b"{\n  \"accessToken\": \"fixture\"\n}\n";
        std::fs::write(&path, original).unwrap();
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            Some(path.clone()),
            false,
        );
        let (url, server) = profile_server("200 OK", r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a"}]}"#).await;
        *manager.test_profile_lookup_url.lock() = Some(url);
        let (credentials, _) = manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        server.await.unwrap();
        assert!(
            credentials.profile_arn.is_some(),
            "前提：当前内存必须已取得 ARN"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "single-object 绝不写盘"
        );
    }

    async fn profile_server_for_tokens(
        expected_requests: usize,
        held_token: String,
        first_lookup_entered: Arc<Notify>,
        release_first_lookup: Arc<Notify>,
        lookup_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut handlers = Vec::with_capacity(expected_requests);
            for _ in 0..expected_requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let held_token = held_token.clone();
                let first_lookup_entered = first_lookup_entered.clone();
                let release_first_lookup = release_first_lookup.clone();
                let lookup_count = lookup_count.clone();
                handlers.push(tokio::spawn(async move {
                    let mut request = vec![0; 4096];
                    let read = socket.read(&mut request).await.unwrap();
                    let request = String::from_utf8(request[..read].to_vec()).unwrap();
                    lookup_count.fetch_add(1, Ordering::SeqCst);
                    let held = request.contains(&format!("Bearer {held_token}"));
                    if held {
                        first_lookup_entered.notify_waiters();
                        release_first_lookup.notified().await;
                    }
                    let profile = if held { "profile/a" } else { "profile/b" };
                    let body = format!(r#"{{"profiles":[{{"arn":"arn:aws:codewhisperer:us-east-1:000000000000:{profile}"}}]}}"#);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                }));
            }
            for handler in handlers {
                handler.await.unwrap();
            }
        });
        (format!("http://{address}/ListAvailableProfiles"), task)
    }

    #[tokio::test]
    async fn b09_same_credential_lookup_is_single_flight() {
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token-a", 0)],
            None,
            false,
        ));
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let first_lookup_entered = Arc::new(Notify::new());
        let release_first_lookup = Arc::new(Notify::new());
        let (url, server) = profile_server_for_tokens(
            1,
            "token-a".into(),
            first_lookup_entered.clone(),
            release_first_lookup.clone(),
            lookup_count.clone(),
        )
        .await;
        *manager.test_profile_lookup_url.lock() = Some(url);

        let first_entered = first_lookup_entered.notified();
        let first_manager = manager.clone();
        let first =
            tokio::spawn(
                async move { first_manager.acquire_latest_credentials_and_token(1).await },
            );
        first_entered.await;
        assert_eq!(
            lookup_count.load(Ordering::SeqCst),
            1,
            "前提：首个调用必须实际进入 lookup"
        );

        let second_waiting = manager.test_profile_lookup_lock_attempted.notified();
        let second_manager = manager.clone();
        let second =
            tokio::spawn(
                async move { second_manager.acquire_latest_credentials_and_token(1).await },
            );
        second_waiting.await;
        assert_eq!(
            manager
                .test_profile_lookup_lock_attempts
                .load(Ordering::SeqCst),
            2,
            "第二调用必须已抵达同 ID mutex 边界"
        );
        assert_eq!(
            lookup_count.load(Ordering::SeqCst),
            1,
            "第二调用等待时不得发起第二次 lookup"
        );

        release_first_lookup.notify_waiters();
        let first_credentials = first.await.unwrap().unwrap().0;
        let second_credentials = second.await.unwrap().unwrap().0;
        server.await.unwrap();
        let expected = "arn:aws:codewhisperer:us-east-1:000000000000:profile/a";
        assert_eq!(
            lookup_count.load(Ordering::SeqCst),
            1,
            "同 ID lookup 必须恰好一次"
        );
        assert_eq!(first_credentials.profile_arn.as_deref(), Some(expected));
        assert_eq!(second_credentials.profile_arn.as_deref(), Some(expected));
        assert_eq!(lookup_counts(&manager, 1).2.as_deref(), Some(expected));
    }

    #[tokio::test]
    async fn b10_profile_lookup_for_other_credential_does_not_block() {
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![
                valid_access_credential("token-a", 0),
                valid_access_credential("token-b", 1),
            ],
            None,
            false,
        ));
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let first_lookup_entered = Arc::new(Notify::new());
        let release_first_lookup = Arc::new(Notify::new());
        let (url, server) = profile_server_for_tokens(
            2,
            "token-a".into(),
            first_lookup_entered.clone(),
            release_first_lookup.clone(),
            lookup_count.clone(),
        )
        .await;
        *manager.test_profile_lookup_url.lock() = Some(url);

        let first_entered = first_lookup_entered.notified();
        let first_manager = manager.clone();
        let first =
            tokio::spawn(
                async move { first_manager.acquire_latest_credentials_and_token(1).await },
            );
        first_entered.await;
        let second_manager = manager.clone();
        let second =
            tokio::spawn(
                async move { second_manager.acquire_latest_credentials_and_token(2).await },
            );
        let second_credentials = tokio::time::timeout(StdDuration::from_secs(2), second)
            .await
            .expect("credential B must complete before credential A is released")
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(
            second_credentials.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/b")
        );
        assert_eq!(
            lookup_count.load(Ordering::SeqCst),
            2,
            "A 和 B 必须各自 lookup 一次"
        );

        release_first_lookup.notify_waiters();
        let first_credentials = first.await.unwrap().unwrap().0;
        server.await.unwrap();
        assert_eq!(
            first_credentials.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/a")
        );
        assert_eq!(
            lookup_counts(&manager, 1).2.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/a")
        );
        assert_eq!(
            lookup_counts(&manager, 2).2.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/b")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn b15_persist_serializes_snapshots_to_prevent_stale_overwrite() {
        let directory =
            std::env::temp_dir().join(format!("kiro-profile-save-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TempDirGuard(directory.clone());
        let path = directory.join("credentials.json");
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![
                valid_access_credential("token-a", 0),
                valid_access_credential("token-b", 1),
            ],
            Some(path.clone()),
            true,
        ));
        let (snapshot_taken, snapshot_received) = std::sync::mpsc::sync_channel(1);
        let (allow_write, write_released) = std::sync::mpsc::sync_channel(1);
        let hook = Arc::new(PersistSnapshotHook {
            snapshot_taken,
            second_snapshot_taken: Notify::new(),
            allow_write: Mutex::new(write_released),
            snapshots: AtomicUsize::new(0),
        });
        // 构造器补全 machine ID 时可能已持久化；此场景只统计安装 hook 后的两个 writer。
        manager
            .test_persist_save_lock_attempts
            .store(0, Ordering::SeqCst);
        *manager.test_persist_snapshot_hook.lock() = Some(hook.clone());

        manager.entries.lock()[0].credentials.profile_arn =
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/a-new".into());
        let first_manager = manager.clone();
        let first = tokio::task::spawn_blocking(move || first_manager.persist_credentials());
        tokio::task::spawn_blocking(move || snapshot_received.recv())
            .await
            .unwrap()
            .unwrap();
        manager.entries.lock()[1].credentials.subscription_title = Some("b-new".into());

        let second_attempted = manager.test_persist_save_lock_attempted.notified();
        let second_manager = manager.clone();
        let second = tokio::task::spawn_blocking(move || second_manager.persist_credentials());
        second_attempted.await;
        assert_eq!(
            manager
                .test_persist_save_lock_attempts
                .load(Ordering::SeqCst),
            2,
            "第二 writer 必须已在 save lock 边界等待"
        );
        assert_eq!(
            hook.snapshots.load(Ordering::SeqCst),
            1,
            "save lock 必须阻止第二 writer 在第一份旧快照发布前取得快照"
        );

        let second_snapshot = hook.second_snapshot_taken.notified();
        allow_write.send(()).unwrap();
        first.await.unwrap().unwrap();
        second_snapshot.await;
        second.await.unwrap().unwrap();

        let credentials = crate::kiro::model::credentials::CredentialsConfig::load(&path)
            .unwrap()
            .into_sorted_credentials();
        assert_eq!(
            credentials[0].profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/a-new")
        );
        assert_eq!(credentials[1].subscription_title.as_deref(), Some("b-new"));
        assert_eq!(
            hook.snapshots.load(Ordering::SeqCst),
            2,
            "反事实：移除 save lock 时第二 writer 会在 release 前取得快照并先写新值，随后第一 writer 以旧快照稳定覆盖它"
        );
    }

    #[tokio::test]
    async fn b24_profile_identity_churn_is_typed_and_never_penalizes_replacement() {
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("generation-0", 0)],
            None,
            false,
        ));
        let old_lock = manager.entries.lock()[0].profile_lookup_lock.clone();
        let old_guard = old_lock.lock().await;
        let first_waiting = manager.test_profile_lookup_lock_attempted.notified();
        let lookup_manager = manager.clone();
        let lookup = tokio::spawn(async move {
            lookup_manager
                .try_ensure_token(1, &valid_access_credential("ignored", 0))
                .await
        });
        first_waiting.await;
        let next_lock = Arc::new(TokioMutex::new(()));
        let next_guard = next_lock.lock().await;
        manager.entries.lock()[0] = CredentialEntry {
            id: 1,
            credentials: valid_access_credential("generation-1", 0),
            failure_count: 0,
            refresh_failure_count: 0,
            disabled: false,
            disabled_reason: None,
            success_count: 0,
            load: 0.0,
            load_updated_at_ms: 0,
            in_flight_count: 0,
            last_used_at: None,
            profile_lookup_retry_after_ms: None,
            profile_lookup_lock: next_lock.clone(),
        };
        let second_waiting = manager.test_profile_lookup_lock_attempted.notified();
        drop(old_guard);
        second_waiting.await;
        let final_lock = Arc::new(TokioMutex::new(()));
        let final_guard = final_lock.lock().await;
        manager.entries.lock()[0] = CredentialEntry {
            id: 1,
            credentials: valid_access_credential("generation-2", 0),
            failure_count: 0,
            refresh_failure_count: 0,
            disabled: false,
            disabled_reason: None,
            success_count: 0,
            load: 0.0,
            load_updated_at_ms: 0,
            in_flight_count: 0,
            last_used_at: None,
            profile_lookup_retry_after_ms: None,
            profile_lookup_lock: final_lock.clone(),
        };
        drop(next_guard);
        drop(final_guard);

        let error = match lookup.await.unwrap() {
            Ok(_) => panic!("bounded churn must not return a call context"),
            Err(error) => error,
        };
        assert!(
            error
                .downcast_ref::<ProfileIdentityChangedError>()
                .is_some(),
            "bounded churn must remain machine-classifiable through try_ensure_token"
        );
        let entry = &manager.entries.lock()[0];
        assert_eq!(entry.in_flight_count, 0);
        assert_eq!(entry.failure_count, 0);
        assert_eq!(entry.refresh_failure_count, 0);
        assert!(!entry.disabled);
        assert_eq!(entry.disabled_reason, None);
    }

    #[tokio::test]
    async fn b25_identity_churn_acquire_retries_without_disabling_replacement() {
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![
                valid_access_credential("generation-0", 0),
                valid_access_credential("fallback", 1),
            ],
            None,
            false,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        *manager.test_profile_lookup_url.lock() = Some(format!(
            "http://{}/ListAvailableProfiles",
            listener.local_addr().unwrap()
        ));
        let (entered_send, mut entered_receive) = tokio::sync::mpsc::channel(1);
        let (release_send, mut release_receive) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                socket.read(&mut request).await.unwrap();
                entered_send.send(()).await.unwrap();
                release_receive.recv().await.unwrap();
                socket
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let lookup_manager = manager.clone();
        let acquire = tokio::spawn(async move { lookup_manager.acquire_context(None).await });

        // Two lookup retries exhaust ID 1; the next acquire attempt must use healthy ID 2.
        for generation in 1..=2 {
            entered_receive.recv().await.unwrap();
            manager.entries.lock()[0].credentials =
                valid_access_credential(&format!("generation-{generation}"), 0);
            release_send.send(()).await.unwrap();
        }
        entered_receive.recv().await.unwrap();
        release_send.send(()).await.unwrap();

        let context = acquire
            .await
            .unwrap()
            .expect("identity churn on one credential must fall back to the healthy credential");
        assert_eq!(context.id, 2);
        assert_eq!(context.token, "fallback");
        manager.report_no_result(context.id);
        server.await.unwrap();

        let entries = manager.entries.lock();
        let churned = entries.iter().find(|entry| entry.id == 1).unwrap();
        assert_eq!(
            churned.in_flight_count, 0,
            "counterfactual: deleting report_no_result(id) leaves ID 1 reserved"
        );
        assert_eq!(churned.failure_count, 0);
        assert_eq!(churned.refresh_failure_count, 0);
        assert!(!churned.disabled);
        let fallback = entries.iter().find(|entry| entry.id == 2).unwrap();
        assert_eq!(fallback.in_flight_count, 0);
        assert_eq!(fallback.failure_count, 0);
        assert_eq!(fallback.refresh_failure_count, 0);
        assert!(!fallback.disabled);

        // Counterfactual: deleting `selection_excluded_ids.insert(id)` makes the next loop reserve ID 1
        // again, exhaust the bounded acquire retries, and return an error instead of ID 2.
        assert_ne!(
            context.id, 1,
            "temporary identity exclusion must select ID 2"
        );
    }

    #[tokio::test]
    async fn b18_reused_id_waiting_on_old_mutex_uses_only_new_identity() {
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("old-access", 0)],
            None,
            false,
        ));
        let old_lock = manager.entries.lock()[0].profile_lookup_lock.clone();
        let old_guard = old_lock.lock().await;
        let (url, server) = profile_server(
            "200 OK",
            r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:000000000000:profile/new"}]}"#,
        )
        .await;
        *manager.test_profile_lookup_url.lock() = Some(url);

        let waiting = manager.test_profile_lookup_lock_attempted.notified();
        let lookup_manager = manager.clone();
        let lookup =
            tokio::spawn(
                async move { lookup_manager.acquire_latest_credentials_and_token(1).await },
            );
        waiting.await;
        {
            let mut entries = manager.entries.lock();
            entries.clear();
            entries.push(CredentialEntry {
                id: 1,
                credentials: valid_access_credential("new-access", 0),
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                load: 0.0,
                load_updated_at_ms: 0,
                in_flight_count: 0,
                last_used_at: None,
                profile_lookup_retry_after_ms: None,
                profile_lookup_lock: Arc::new(TokioMutex::new(())),
            });
        }
        drop(old_guard);

        let (returned, token) = lookup.await.unwrap().unwrap();
        let request = server.await.unwrap();
        assert!(request.contains("Bearer new-access"));
        assert!(!request.contains("Bearer old-access"));
        assert_eq!(token, "new-access");
        assert_eq!(
            returned.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/new")
        );
        assert!(
            manager.entries.lock()[0]
                .profile_lookup_retry_after_ms
                .is_none()
        );
    }

    #[tokio::test]
    async fn b22_old_http_failure_never_writes_replacement_cooldown() {
        let clock = TestClock::new();
        let manager = Arc::new(profile_test_manager(
            clock,
            vec![valid_access_credential("old-access", 0)],
            None,
            false,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        *manager.test_profile_lookup_url.lock() = Some(format!(
            "http://{}/ListAvailableProfiles",
            listener.local_addr().unwrap()
        ));
        let request_entered = Arc::new(Notify::new());
        let release_response = Arc::new(Notify::new());
        let server_entered = request_entered.clone();
        let server_release = release_response.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            server_entered.notify_waiters();
            server_release.notified().await;
            socket
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request[..read].to_vec()).unwrap()
        });

        let entered = request_entered.notified();
        let lookup_manager = manager.clone();
        let lookup =
            tokio::spawn(
                async move { lookup_manager.acquire_latest_credentials_and_token(1).await },
            );
        entered.await;
        {
            let mut replacement = valid_access_credential("new-access", 0);
            replacement.profile_arn =
                Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/replacement".into());
            let mut entries = manager.entries.lock();
            entries.clear();
            entries.push(CredentialEntry {
                id: 1,
                credentials: replacement,
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                load: 0.0,
                load_updated_at_ms: 0,
                in_flight_count: 0,
                last_used_at: None,
                profile_lookup_retry_after_ms: None,
                profile_lookup_lock: Arc::new(TokioMutex::new(())),
            });
        }
        release_response.notify_waiters();

        let (returned, token) = lookup.await.unwrap().unwrap();
        let request = server.await.unwrap();
        assert!(
            request.contains("Bearer old-access"),
            "precondition: old request entered loopback server"
        );
        assert_eq!(token, "new-access");
        assert_eq!(
            returned.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/replacement"),
            "old failure must not write an old ARN over the replacement"
        );
        let entry = &manager.entries.lock()[0];
        assert_eq!(entry.profile_lookup_retry_after_ms, None);
        assert_eq!(entry.failure_count, 0);
        assert_eq!(entry.refresh_failure_count, 0);
        assert!(!entry.disabled);
    }

    #[tokio::test]
    async fn b20_failure_cooldown_starts_when_delayed_lookup_fails() {
        let clock = TestClock::new();
        let manager = Arc::new(profile_test_manager(
            clock.clone(),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        ));
        clock.advance_ms(1_000);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/ListAvailableProfiles",
            listener.local_addr().unwrap()
        );
        *manager.test_profile_lookup_url.lock() = Some(url);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let server_entered = entered.clone();
        let server_release = release.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            socket.read(&mut request).await.unwrap();
            server_entered.notify_waiters();
            server_release.notified().await;
            socket
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let waiting_for_server = entered.notified();
        let first_manager = manager.clone();
        let first =
            tokio::spawn(
                async move { first_manager.acquire_latest_credentials_and_token(1).await },
            );
        waiting_for_server.await;
        clock.advance_ms(59_000);
        release.notify_waiters();
        first.await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(
            manager.entries.lock()[0].profile_lookup_retry_after_ms,
            Some(120_000),
            "cooldown must be based on failure time, not request start"
        );

        clock.advance_ms(59_999);
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            1,
            "119,999ms must still be inside the post-failure cooldown"
        );
        clock.advance_ms(1);
        manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            2,
            "120,000ms must retry without sleeping"
        );
    }

    #[test]
    fn b19_real_refresh_write_keeps_discovered_arn_when_response_omits_it() {
        let mut current = valid_access_credential("R1", 0);
        current.profile_arn =
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/current".into());
        let expected_identity = current.refresh_token.clone();
        let manager =
            profile_test_manager(Arc::new(ProcessClock::new()), vec![current], None, false);
        let refreshed = valid_access_credential("R2", 0);
        assert!(manager.replace_refreshed_credentials(1, expected_identity.as_deref(), refreshed));
        let entry = manager.credentials_for_id(1).unwrap();
        assert_eq!(entry.access_token.as_deref(), Some("R2"));
        assert_eq!(
            entry.profile_arn.as_deref(),
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/current"),
            "counterfactual: whole-object assignment in the real write path would erase ARN"
        );
    }

    #[test]
    fn b23_forced_refresh_apply_reports_stale_replacement_and_applies_matching_rotation() {
        let mut current = valid_access_credential("R1", 0);
        current.profile_arn =
            Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/current".into());
        let expected = current.refresh_token.clone();
        let manager =
            profile_test_manager(Arc::new(ProcessClock::new()), vec![current], None, false);
        manager
            .apply_forced_refresh(1, expected.as_deref(), valid_access_credential("R2", 0))
            .unwrap();
        assert_eq!(
            manager
                .credentials_for_id(1)
                .unwrap()
                .access_token
                .as_deref(),
            Some("R2")
        );

        let stale_identity = expected;
        manager.entries.lock()[0].credentials = valid_access_credential("replacement", 0);
        let error = manager
            .apply_forced_refresh(
                1,
                stale_identity.as_deref(),
                valid_access_credential("ignored", 0),
            )
            .unwrap_err();
        assert!(error.to_string().contains("已删除或替换"));
        assert_eq!(
            manager
                .credentials_for_id(1)
                .unwrap()
                .access_token
                .as_deref(),
            Some("replacement"),
            "applied=false must not overwrite a replacement credential"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn b21_save_lock_contention_does_not_starve_single_runtime_worker() {
        let directory =
            std::env::temp_dir().join(format!("kiro-save-contention-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TempDirGuard(directory.clone());
        let manager = Arc::new(profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            Some(directory.join("credentials.json")),
            true,
        ));
        let (locked, lock_held) = std::sync::mpsc::sync_channel(1);
        let (heartbeat_sent, heartbeat_received) = std::sync::mpsc::sync_channel(1);
        let (result_sent, result_received) = std::sync::mpsc::sync_channel(1);
        let lock_manager = manager.clone();
        std::thread::spawn(move || {
            let _guard = lock_manager.credentials_save_lock.lock();
            locked.send(()).unwrap();
            // Timeout only breaks a deadlock. It never establishes success: only a heartbeat permits
            // the external holder to report that the worker ran before it released the save lock.
            let observed_before_release = heartbeat_received
                .recv_timeout(StdDuration::from_secs(2))
                .is_ok();
            result_sent.send(observed_before_release).unwrap();
        });
        tokio::task::spawn_blocking(move || lock_held.recv())
            .await
            .unwrap()
            .unwrap();

        let attempted = manager.test_persist_save_lock_attempted.notified();
        let writer_manager = manager.clone();
        let writer = tokio::spawn(async move { writer_manager.persist_credentials() });
        attempted.await;
        let heartbeat = tokio::spawn(async move {
            tokio::task::yield_now().await;
            heartbeat_sent.send(()).unwrap();
        });

        let observed_before_release = tokio::task::spawn_blocking(move || result_received.recv())
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap().unwrap();
        heartbeat.await.unwrap();
        assert!(
            observed_before_release,
            "counterfactual: without block_in_place the sole Tokio worker parks on the save mutex, the external timeout releases it, and this channel result is false"
        );
    }

    #[tokio::test]
    async fn b14_persistence_failure_keeps_in_memory_arn_and_counters() {
        let absent = std::env::temp_dir()
            .join(format!("kiro-profile-absent-{}", uuid::Uuid::new_v4()))
            .join("credentials.json");
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            Some(absent),
            true,
        );
        let before = lookup_counts(&manager, 1);
        let (url, server) = profile_server("200 OK", r#"{"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a"}]}"#).await;
        *manager.test_profile_lookup_url.lock() = Some(url);
        let (credentials, _) = manager
            .acquire_latest_credentials_and_token(1)
            .await
            .unwrap();
        server.await.unwrap();
        let after = lookup_counts(&manager, 1);
        assert!(credentials.profile_arn.is_some());
        assert!(after.2.is_some());
        assert_eq!((after.0, after.1), (before.0, before.1));
    }

    async fn usage_server(body: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = body.to_string();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8(request[..read].to_vec()).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (format!("http://{address}/getUsageLimits"), task)
    }

    #[tokio::test]
    async fn b16_usage_query_discovers_missing_profile_arn_before_request() {
        let manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("usage-token", 0)],
            None,
            false,
        );
        let discovered_arn = "arn:aws:codewhisperer:us-east-1:111111111111:profile/test-a";
        let (profile_url, profile_server) = profile_server(
            "200 OK",
            &format!(r#"{{"profiles":[{{"arn":"{discovered_arn}"}}]}}"#),
        )
        .await;
        let (usage_url, usage_server) = usage_server(r#"{"usageBreakdownList":[]}"#).await;
        *manager.test_profile_lookup_url.lock() = Some(profile_url);
        *manager.test_usage_limits_url.lock() = Some(usage_url);

        let limits = manager.get_usage_limits_for(1).await.unwrap();
        assert!(
            limits.usage_breakdown_list.is_empty(),
            "precondition: loopback response parsed"
        );
        let profile_request = profile_server.await.unwrap();
        assert!(
            profile_request.starts_with("POST /ListAvailableProfiles"),
            "precondition: Admin query must first use shared profile discovery"
        );
        let usage_request = usage_server.await.unwrap();
        assert!(
            usage_request.starts_with("GET /getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&profileArn=arn%3Aaws%3Acodewhisperer%3Aus-east-1%3A111111111111%3Aprofile%2Ftest-a HTTP/1.1"),
            "usage request must include the newly discovered, URL-encoded profile ARN"
        );
        assert!(
            usage_request.contains("Authorization: Bearer usage-token")
                || usage_request.contains("authorization: Bearer usage-token"),
            "usage request must preserve the bearer token header"
        );
        assert_eq!(
            manager
                .test_profile_lookup_request_count
                .load(Ordering::SeqCst),
            1,
            "missing ARN must enter discovery exactly once before usage"
        );
    }

    #[test]
    fn b17_usage_refresh_error_policy_disables_only_permanent_errors() {
        let permanent_manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        let permanent = anyhow::Error::new(RefreshTokenInvalidError {
            message: "permanent refresh failure".into(),
            error_code: "invalid_grant",
        });
        permanent_manager.handle_usage_refresh_error(1, &permanent);
        let permanent_entry = permanent_manager.entries.lock();
        assert!(
            permanent_entry[0].disabled,
            "permanent refresh error must disable credential"
        );
        assert_eq!(
            permanent_entry[0].disabled_reason,
            Some(DisabledReason::InvalidRefreshToken),
            "permanent refresh error must preserve invalid_refresh_token reason"
        );
        drop(permanent_entry);

        let transient_manager = profile_test_manager(
            Arc::new(ProcessClock::new()),
            vec![valid_access_credential("token", 0)],
            None,
            false,
        );
        let transient = anyhow::anyhow!("transient refresh failure");
        let original_message = transient.to_string();
        transient_manager.handle_usage_refresh_error(1, &transient);
        let transient_entry = transient_manager.entries.lock();
        assert!(
            !transient_entry[0].disabled,
            "ordinary refresh error must not disable credential"
        );
        assert_eq!(
            transient_entry[0].disabled_reason, None,
            "ordinary refresh error must not gain a permanent-disabled reason"
        );
        assert_eq!(
            transient.to_string(),
            original_message,
            "policy must preserve the original transient error text for return"
        );
    }
}
