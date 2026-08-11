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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
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

/// 获取使用额度信息
pub(crate) async fn get_usage_limits(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息");

    // 优先级：凭据.api_region > config.api_region > config.region
    let region = credentials.effective_api_region(config);
    let host = format!("q.{}.amazonaws.com", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // 构建 URL
    let mut url = format!(
        "https://{}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST",
        host
    );

    // profileArn 是可选的
    if let Some(profile_arn) = &credentials.profile_arn {
        url.push_str(&format!("&profileArn={}", urlencoding::encode(profile_arn)));
    }

    // 构建 User-Agent headers
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
        .header("host", &host)
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

    let data: UsageLimitsResponse = response.json().await?;
    Ok(data)
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
    /// balanced 模式下的内部选路偏移，不计入对外成功次数
    balanced_offset: u64,
    /// 当前已分配但尚未完成的 API 调用数
    in_flight_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
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
    #[serde(default)]
    balanced_offset: u64,
    last_used_at: Option<String>,
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
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 3;
/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);
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
                    balanced_offset: 0,
                    in_flight_count: 0,
                    last_used_at: None,
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
                // Least-Used + in-flight 策略：选择已成功和正在处理请求总量最少的凭据
                // 平局时按优先级排序（数字越小优先级越高）
                let idx = available.iter().min_by_key(|idx| {
                    let e = &entries[**idx];
                    (
                        e.success_count
                            .saturating_add(e.balanced_offset)
                            .saturating_add(e.in_flight_count),
                        e.credentials.priority,
                    )
                })?;

                Some(Self::reserve_credential(&mut entries[*idx], Utc::now()))
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
        let total = self.total_count();
        let max_attempts = (total * MAX_FAILURES_PER_CREDENTIAL as usize).max(1);
        let mut attempt_count = 0;
        let session_id = session_id.filter(|s| !s.is_empty());

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

                let sticky_hit = if is_balanced {
                    session_id
                        .and_then(|sid| self.select_sticky_credential(sid, model, excluded_ids))
                } else {
                    None
                };

                // balanced 模式：每次请求都重新均衡选择，不固定 current_id
                // priority 模式：优先使用 current_id 指向的凭据
                let current_hit = if sticky_hit.is_some() || is_balanced {
                    None
                } else {
                    let current_id = *self.current_id.lock();
                    self.reserve_existing_credential_excluding(current_id, model, excluded_ids)
                };

                if let Some((hit_id, _hit_credentials)) = sticky_hit {
                    match self.reserve_existing_credential_excluding(hit_id, model, excluded_ids) {
                        Some((reserved_id, reserved_credentials)) => {
                            (reserved_id, reserved_credentials, Some(true))
                        }
                        None => {
                            // sticky 命中但 reserve 失败（窄竞态：选择到 reserve 之间凭据被禁用）。
                            // 不清 sticky：凭据禁用时 report_quota_exhausted / report_refresh_failure
                            // 会调 clear_sticky_sessions_for_credential 批量清，acquire 路径不做 clear。
                            let mut best =
                                self.select_next_credential_excluding(model, excluded_ids);
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
                                    best =
                                        self.select_next_credential_excluding(model, excluded_ids);
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
                    // `let current_hit = if sticky_hit.is_some() || is_balanced { None } else {...}`），
                    // 即此分支恒为 priority 模式，粘性机制未启用，语义是 N/A 不是"未命中"。
                    (hit_id, hit_credentials, None)
                } else {
                    // 当前凭据不可用或 balanced 模式，根据负载均衡策略选择
                    let mut best = self.select_next_credential_excluding(model, excluded_ids);

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
                            best = self.select_next_credential_excluding(model, excluded_ids);
                        }
                    }

                    if let Some((new_id, new_creds)) = best {
                        // 更新 current_id
                        let mut current_id = self.current_id.lock();
                        *current_id = new_id;
                        // 这个分支在 balanced 模式（sticky 桶查无记录，真实未命中）和 priority
                        // 模式（粘性机制未启用，current_hit 落空只是常规选择）都会走到，
                        // 必须靠 is_balanced 区分，不能像其余分支那样从路径本身唯一推出结论。
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
                    self.report_no_result(id);
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
                    attempt_count += 1;
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

    /// 尝试使用指定凭据获取有效 Token
    ///
    /// 使用双重检查锁定模式，确保同一时间只有一个刷新操作
    ///
    /// # Arguments
    /// * `id` - 凭据 ID，用于更新正确的条目
    /// * `credentials` - 凭据信息
    async fn try_ensure_token(
        &self,
        id: u64,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<CallContext> {
        // API Key 凭据直接使用 kiro_api_key 作为 Bearer Token，无需刷新
        if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok(CallContext {
                id,
                credentials: credentials.clone(),
                token,
                // 由调用方（acquire_context_for_session_excluding）回填真实值。
                sticky_hit: None,
            });
        }

        // 第一次检查（无锁）：快速判断是否需要刷新
        let needs_refresh = is_token_expired(credentials) || is_token_expiring_soon(credentials);

        let creds = if needs_refresh {
            // 获取刷新锁，确保同一时间只有一个刷新操作
            let _guard = self.refresh_lock.lock().await;

            // 第二次检查：获取锁后重新读取凭据，因为其他请求可能已经完成刷新
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                // 确实需要刷新
                let effective_proxy = current_creds.effective_proxy(self.proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;

                if is_token_expired(&new_creds) {
                    anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                }

                // 更新凭据
                {
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                        entry.credentials = new_creds.clone();
                    }
                }

                // 回写凭据到文件（仅多凭据格式），失败只记录警告
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!(error = %e, "Token 刷新后持久化失败（不影响本次请求）");
                }

                new_creds
            } else {
                // 其他请求已经完成刷新，直接使用新凭据
                tracing::debug!("Token 已被其他请求刷新，跳过刷新");
                current_creds
            }
        } else {
            credentials.clone()
        };

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.refresh_failure_count = 0;
            }
        }

        Ok(CallContext {
            id,
            credentials: creds,
            token,
            // 由调用方（acquire_context_for_session_excluding）回填真实值。
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

        // 收集所有凭据
        let credentials: Vec<KiroCredentials> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    let mut cred = e.credentials.clone();
                    cred.canonicalize_auth_method();
                    // 同步 disabled 状态到凭据对象
                    cred.disabled = e.disabled;
                    cred
                })
                .collect()
        };

        // 序列化为 pretty JSON
        let json = serde_json::to_string_pretty(&credentials).context("序列化凭据失败")?;

        // 写入文件（在 Tokio runtime 内使用 block_in_place 避免阻塞 worker）
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| std::fs::write(path, &json))
                .with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        } else {
            std::fs::write(path, &json).with_context(|| format!("回写凭据文件失败: {:?}", path))?;
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

        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.balanced_offset = s.balanced_offset;
                entry.last_used_at = s.last_used_at.clone();
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
                            balanced_offset: e.balanced_offset,
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

            entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
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

            entry.in_flight_count = entry.in_flight_count.saturating_sub(1);
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

    /// 获取指定凭据的使用额度（Admin API）
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 检查是否需要刷新 token
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let _guard = self.refresh_lock.lock().await;
                let current_creds = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.id == id)
                        .map(|e| e.credentials.clone())
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                };

                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let effective_proxy = current_creds.effective_proxy(self.proxy.as_ref());
                    let new_creds =
                        match refresh_token(&current_creds, &self.config, effective_proxy.as_ref())
                            .await
                        {
                            Ok(creds) => creds,
                            Err(e) => {
                                // 余额查询路径原先静默吞错误（#52）。补日志保证可观测，
                                // 并对不可重试的永久性刷新失败立即隔离凭据——与 acquire
                                // 主路径行为对齐，避免下个业务请求再撞上同一坏凭据白跑一轮。
                                if let Some(invalid) = e.downcast_ref::<RefreshTokenInvalidError>()
                                {
                                    tracing::warn!(
                                        credential_id = id,
                                        error_code = invalid.error_code,
                                        error = %e,
                                        "Token 刷新永久失效（余额查询）"
                                    );
                                    self.report_refresh_token_invalid(id);
                                } else {
                                    // 瞬态失败仅记日志，禁用交由 acquire 循环累计判定
                                    tracing::warn!(
                                        credential_id = id,
                                        error = %e,
                                        "Token 刷新失败（余额查询）"
                                    );
                                }
                                return Err(e);
                            }
                        };
                    {
                        let mut entries = self.entries.lock();
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.credentials = new_creds.clone();
                        }
                    }
                    // 持久化失败只记录警告，不影响本次请求
                    if let Err(e) = self.persist_credentials() {
                        tracing::warn!(error = %e, "Token 刷新后持久化失败（不影响本次请求）");
                    }
                    new_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
                } else {
                    current_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
                }
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());
        let usage_limits =
            get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await?;

        // 更新订阅等级到凭据（仅在发生变化时持久化）
        if let Some(subscription_title) = usage_limits.subscription_title() {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let old_title = entry.credentials.subscription_title.clone();
                    if old_title.as_deref() != Some(subscription_title) {
                        entry.credentials.subscription_title = Some(subscription_title.to_string());
                        tracing::info!(
                            credential_id = id,
                            old_subscription_title = ?old_title,
                            subscription_title = subscription_title,
                            "订阅等级已更新"
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if changed && let Err(e) = self.persist_credentials() {
                tracing::warn!(error = %e, "订阅等级更新后持久化失败（不影响本次请求）");
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
            let balanced_offset = entries
                .iter()
                .filter(|e| !e.disabled)
                .map(|e| e.success_count.saturating_add(e.balanced_offset))
                .min()
                .unwrap_or(0);
            entries.push(CredentialEntry {
                id: new_id,
                credentials: validated_cred,
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                balanced_offset,
                in_flight_count: 0,
                last_used_at: None,
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
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // 获取刷新锁防止并发刷新
        let _guard = self.refresh_lock.lock().await;

        // 无条件调用 refresh_token
        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());
        let new_creds = refresh_token(&credentials, &self.config, effective_proxy.as_ref()).await?;

        // 更新 entries 中对应凭据
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials = new_creds;
                entry.refresh_failure_count = 0;
            }
        }

        // 持久化
        if let Err(e) = self.persist_credentials() {
            tracing::warn!(error = %e, "强制刷新 Token 后持久化失败");
        }

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
    use std::sync::atomic::AtomicU64;

    /// 测试专用时钟（#86）：AtomicU64 手动推进，只增不减，
    /// 用于精确驱动 sticky TTL / LRU 的边界判定，避免真实 sleep 拖慢测试。
    struct TestClock {
        now_ms: AtomicU64,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now_ms: AtomicU64::new(0),
            })
        }

        fn advance_ms(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }
    }

    fn test_registry() -> Arc<ModelRegistry> {
        Arc::new(ModelRegistry::from_toml(include_str!("../../models.toml")).unwrap())
    }

    /// 构造一个 `stats_path()` 可写的 manager（#86 返工统计落盘回归测试专用）。
    /// 返回 `(manager, 临时凭据目录)`，调用方用完须 `remove_dir_all` 清理。
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
    #[test]
    fn test_stats_dirty_survives_change_during_inflight_flush() {
        let (manager, cred_dir) = test_manager_with_stats_path();

        manager.save_stats_locked_at(|| {
            // 等价于 save_stats_debounced 里唯一的标记语句：B 线程在 A 已读完
            // version_at_snapshot、但还没取 entries 快照之前，标记了一次新变更。
            manager.stats_dirty_version.fetch_add(1, Ordering::SeqCst);
        });

        assert_ne!(
            manager.stats_dirty_version.load(Ordering::SeqCst),
            manager.stats_saved_version.load(Ordering::SeqCst),
            "B 在 A 落盘期间发生的新变更必须让状态保持脏，Drop 才会兜底重试"
        );

        std::fs::remove_dir_all(&cred_dir).ok();
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

        manager.report_no_result(first.id);
        manager.report_no_result(second.id);
        manager.report_no_result(third.id);
    }

    #[tokio::test]
    async fn test_balanced_new_credential_uses_offset_without_changing_success_count() {
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

        {
            let mut entries = manager.entries.lock();
            entries[0].success_count = 100;
            entries[1].success_count = 120;
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
            assert_eq!(new_entry.success_count, 0);
            assert_eq!(new_entry.balanced_offset, 100);
        }

        let first = manager.acquire_context(None).await.unwrap();
        let second = manager.acquire_context(None).await.unwrap();

        assert_ne!(first.id, new_id);
        assert_eq!(second.id, new_id);

        manager.report_no_result(first.id);
        manager.report_no_result(second.id);
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
}
