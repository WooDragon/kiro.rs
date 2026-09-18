//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::http_client::{
    ProxyConfig, UPSTREAM_IDLE_TIMEOUT_SECS, build_client, build_idle_client,
};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::MultiTokenManager;
use crate::kiro::{LOG_PAYLOAD_LIMIT, truncate_for_log};
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// Provider 层类型化错误，供 handlers 层 downcast 后映射到正确 HTTP 状态码。
#[derive(Debug)]
pub enum ProviderError {
    /// 所有凭据均已禁用 — 503
    AllCredentialsDisabled { available: usize, total: usize },
    /// 所有凭据额度已用尽 — 429
    AllCredentialsQuotaExhausted { detail: String },
    /// Token 获取/刷新全部失败 — 503
    TokenAcquisitionFailed { available: usize, total: usize },
    /// 上游返回客户端错误（400系，非瞬态）— 透传或 502
    UpstreamClientError { status: u16, body: String },
    /// 上游瞬态错误重试耗尽 — 429 或 503
    UpstreamTransientExhausted { last_status: u16, body: String },
    /// 网络/连接失败重试耗尽 — 503
    ConnectionFailed { detail: String },
    /// 内部配置错误 — 500
    InternalConfig { detail: String },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::AllCredentialsDisabled { available, total } => {
                write!(f, "所有凭据均已禁用 ({}/{})", available, total)
            }
            ProviderError::AllCredentialsQuotaExhausted { detail } => {
                write!(f, "所有凭据额度已用尽: {}", detail)
            }
            ProviderError::TokenAcquisitionFailed { available, total } => {
                write!(f, "Token 获取失败 ({}/{})", available, total)
            }
            ProviderError::UpstreamClientError { status, body } => {
                // Display 是诊断表示，会被日志 `error=%err` 消费——body 必须截断，
                // 否则完整上游 body（可达数百 KB）连同其转义会糊进日志字段，抵消
                // #71 的结构化/可观测目标。
                write!(
                    f,
                    "上游客户端错误 {}: {}",
                    status,
                    truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                )
            }
            ProviderError::UpstreamTransientExhausted { last_status, body } => {
                write!(
                    f,
                    "上游瞬态错误重试耗尽 {}: {}",
                    last_status,
                    truncate_for_log(body, LOG_PAYLOAD_LIMIT)
                )
            }
            ProviderError::ConnectionFailed { detail } => {
                write!(f, "网络连接失败重试耗尽: {}", detail)
            }
            ProviderError::InternalConfig { detail } => {
                write!(f, "内部配置错误: {}", detail)
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
const MAX_TOTAL_RETRIES: usize = 9;

/// `#98`：5xx（上游服务端错误）独立于 429/408 的重试预算——与逐凭据/全局预算
/// 乘数完全正交，专治"同一次故障被乘以最多 9 次上游调用"（issue 排查数据：
/// 100 次额外调用 100/100 全是 500）。预算耗尽立即上抛，不换凭据（D3：保留
/// "5xx 不切换凭据"的既有设计）。
const MAX_5XX_RETRIES: usize = 1;

/// Client 类型：区分业务长响应与短请求，保证超时策略解耦。
///
/// - `Idle`：业务 generateAssistantResponse（流式/非流式），使用 idle/read 超时，
///   只要上游持续吐字节就不触发，避免误杀慢但健康的长响应。
/// - `Short`：MCP、WebSearch 等短请求，使用全局总超时死线，防止 Slowloris。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ClientKind {
    /// 业务长响应：idle/read 超时，无全局总超时
    Idle,
    /// 短请求：全局总超时
    Short,
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = (effective proxy config, ClientKind)
    ///
    /// 按代理+类型双维度缓存，业务 idle client 与短请求 total client 严格隔离，
    /// 防止超时策略交叉污染。
    client_cache: Mutex<HashMap<(Option<ProxyConfig>, ClientKind), Client>>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
}

pub struct KiroApiResponse {
    pub response: reqwest::Response,
    pub credential_id: u64,
    /// PR-0（可观测性，零行为变更）：本次凭据是否命中 balanced 模式的会话粘性表。
    /// 直接透传自 [`CallContext::sticky_hit`]，仅供日志聚合，不驱动任何决策。
    ///
    /// PR-0 返工（redteam MUST FIX 2）：三态而非二值，随 `CallContext::sticky_hit`
    /// 同步改为 `Option<bool>`——`None` 表示会话粘性机制根本未启用（priority 模式），
    /// 不是"测量出的未命中"。语义定义见 `CallContext::sticky_hit` 文档。
    pub sticky_hit: Option<bool>,
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的业务 idle client（短请求 client 按需懒创建）
        let initial_client =
            build_idle_client(proxy.as_ref(), UPSTREAM_IDLE_TIMEOUT_SECS, tls_backend)
                .expect("创建业务 HTTP 客户端失败");
        let mut cache = HashMap::new();
        cache.insert((proxy.clone(), ClientKind::Idle), initial_client);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(cache),
            tls_backend,
            endpoints,
            default_endpoint,
        }
    }

    /// 根据凭据的代理配置和 client 类型获取（或创建并缓存）对应的 `reqwest::Client`。
    ///
    /// 语义边界：
    /// - `ClientKind::Idle`：业务 generateAssistantResponse，idle/read 超时，无全局总超时。
    ///   只要上游持续吐字节就不触发，避免慢但健康的长流被误杀。
    /// - `ClientKind::Short`：MCP/WebSearch 等短请求，全局总超时 720s，防 Slowloris。
    ///
    /// # 参数
    /// * `credentials` - 当前凭据（用于提取 effective proxy）
    /// * `kind` - client 类型
    ///
    /// # 返回
    /// 缓存命中则克隆已有 client；未命中则按 kind 构建后写入缓存
    fn client_for(
        &self,
        credentials: &KiroCredentials,
        kind: ClientKind,
    ) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let cache_key = (effective.clone(), kind.clone());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&cache_key) {
            return Ok(client.clone());
        }
        let client = match kind {
            // 业务长响应：idle/read 超时，不设全局总超时
            ClientKind::Idle => build_idle_client(
                effective.as_ref(),
                UPSTREAM_IDLE_TIMEOUT_SECS,
                self.tls_backend,
            )?,
            // 短请求：全局总超时 720s，与业务 client 解耦，防 Slowloris
            ClientKind::Short => build_client(effective.as_ref(), 720, self.tls_backend)?,
        };
        cache.insert(cache_key, client.clone());
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints.get(name).cloned().ok_or_else(|| {
            ProviderError::InternalConfig {
                detail: format!("未知端点: {}", name),
            }
            .into()
        })
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）
    #[allow(dead_code)]
    pub async fn call_api(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_api_with_retry(request_body, false)
            .await
            .map(|r| r.response)
    }

    /// 发送流式 API 请求
    #[allow(dead_code)]
    pub async fn call_api_stream(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_api_with_retry(request_body, true)
            .await
            .map(|r| r.response)
    }

    pub async fn call_api_with_context(
        &self,
        request_body: &str,
    ) -> anyhow::Result<KiroApiResponse> {
        self.call_api_with_retry(request_body, false).await
    }

    pub async fn call_api_stream_with_context(
        &self,
        request_body: &str,
    ) -> anyhow::Result<KiroApiResponse> {
        self.call_api_with_retry(request_body, true).await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(
        &self,
        request_body: &str,
        session_id: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body, session_id).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(
        &self,
        request_body: &str,
        session_id: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let mut failed_credential_ids: HashSet<u64> = HashSet::new();
        let mut server_error_retries: usize = 0;

        for attempt in 0..max_retries {
            // MCP 调用（WebSearch 等工具）不涉及模型选择，无需按模型过滤凭据
            let ctx = match self
                .token_manager
                .acquire_context_for_session_excluding(None, session_id, &failed_credential_ids)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    failed_credential_ids.insert(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            // MCP/WebSearch 属于短请求，使用全局总超时 client，防止 Slowloris
            let client = match self.client_for(&ctx.credentials, ClientKind::Short) {
                Ok(client) => client,
                Err(e) => {
                    self.token_manager.report_no_result(ctx.id);
                    return Err(e);
                }
            };
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_mcp(base, &rctx);

            self.token_manager.record_upstream_call(ctx.id, None);
            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_retries,
                        error = %e,
                        "MCP 请求发送失败"
                    );
                    last_error = Some(e.into());
                    self.token_manager.report_no_result(ctx.id);
                    failed_credential_ids.insert(ctx.id);
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            //
            // #86 返工 S4：只读不写——只把 session_id 传给上面的
            // acquire_context_for_session_excluding 让 MCP 请求也能命中主链路已建立的
            // 粘性绑定，但成功后用 report_success（不绑定新粘性），不用
            // report_success_for_session。原因：MCP 调用不带模型名（第一个参数传
            // None），is_entry_available_for_model 因此不做 premium tier 过滤，可能
            // 选中并首绑一张不支持 opus 的凭据；若这次绑定恰好插在"主请求清掉
            // entry"与"主请求成功后首绑"之间，会把 session 重新绑回不支持 opus 的
            // 凭据，主请求 bind 被不变量拒绝，下一轮又清一次——来回抖动。读 sticky
            // 已能拿到全部缓存收益，写绑定对本 PR 目标零增量贡献。
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                return Ok(response);
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // 402 额度用尽
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "MCP 请求失败（所有凭据已用尽）: {} {}",
                        status,
                        truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                    );
                }
                last_error = Some(anyhow::anyhow!(
                    "MCP 请求失败: {} {}",
                    status,
                    truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                ));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                self.token_manager.report_no_result(ctx.id);
                anyhow::bail!(
                    "MCP 请求失败: {} {}",
                    status,
                    truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                );
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        self.token_manager.report_no_result(ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                failed_credential_ids.insert(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "MCP 请求失败（所有凭据已用尽）: {} {}",
                        status,
                        truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                    );
                }
                last_error = Some(anyhow::anyhow!(
                    "MCP 请求失败: {} {}",
                    status,
                    truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                ));
                continue;
            }

            // 瞬态错误：408/429
            if matches!(status.as_u16(), 408 | 429) {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "MCP 请求失败（上游瞬态错误）"
                );
                last_error = Some(anyhow::anyhow!(
                    "MCP 请求失败: {} {}",
                    status,
                    truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                ));
                self.token_manager.report_no_result(ctx.id);
                failed_credential_ids.insert(ctx.id);
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // `#98`：5xx（上游服务端错误）独立预算，与 408/429 分支彻底分开——
            // 统一两条链路的凭据切换行为是阶段三的范围，本 PR 只加预算、不改换
            // 凭据语义，故此处仍保留 MCP 既有的 failed_credential_ids.insert。
            //
            // `#101`：`is_server_error()` 把 500/502/503/504 全族绑在同一个
            // `MAX_5XX_RETRIES = 1` 上，是**有意收紧**不是漏拆——生产排查数据是
            // 100/100 全 500，这个预算对 500 对症；503/504 以前能跟 429 一样重
            // 试到 9 次，现在同样只给 1 次。若将来拿到 503/504 的黑盒数据表明
            // 它们更接近 408 的"瞬态但预算应更宽"语义，可再单独拆分出去，本次
            // 不改行为，只把这条取舍写清楚。
            if status.is_server_error() {
                server_error_retries += 1;
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    server_error_retries,
                    max_5xx_retries = MAX_5XX_RETRIES,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "MCP 请求失败（上游服务端错误）"
                );
                let transient = ProviderError::UpstreamTransientExhausted {
                    last_status: status.as_u16(),
                    body: body.clone(),
                };
                self.token_manager.report_no_result(ctx.id);
                failed_credential_ids.insert(ctx.id);
                if server_error_retries > MAX_5XX_RETRIES {
                    return Err(transient.into());
                }
                last_error = Some(transient.into());
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                self.token_manager.report_no_result(ctx.id);
                anyhow::bail!(
                    "MCP 请求失败: {} {}",
                    status,
                    truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
                );
            }

            // 兜底
            last_error = Some(anyhow::anyhow!(
                "MCP 请求失败: {} {}",
                status,
                truncate_for_log(&body, LOG_PAYLOAD_LIMIT)
            ));
            self.token_manager.report_no_result(ctx.id);
            failed_credential_ids.insert(ctx.id);
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
    ) -> anyhow::Result<KiroApiResponse> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<ProviderError> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let mut failed_credential_ids: HashSet<u64> = HashSet::new();
        let mut server_error_retries: usize = 0;
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);
        let session_id = Self::extract_session_id_from_request(request_body);

        // `#101` MUST FIX 1：瞬态重试粘住本轮凭据。见
        // `MultiTokenManager::acquire_context_for_session_excluding_pinned` 的
        // doc comment 讲清动机与不变量。这里只需一条不变量：把"上一次实际拿到
        // 的凭据"记下来，下一轮请求它。不必按分支手工设置/清除——凡是必须换
        // 凭据的分支（402/401·403 失败/未知状态兜底）本来就会把该 id 写进
        // `failed_credential_ids` 或让它被禁用，pin 在下一轮 reserve 时自然因
        // 排除/禁用而落空、回落到常规选路；凡是允许继续用同一张的分支（408/429、
        // 5xx、连接失败、以及 401/403 强制刷新成功后的同凭据重试）本来就不会
        // 把它排除，下一轮 pin 原样生效。按分支特判"哪些该粘哪些该清"反而是
        // 在复刻已经存在的排除逻辑，多一处就多一处两边失步的风险。
        let mut pinned_credential_id: Option<u64> = None;

        for attempt in 0..max_retries {
            // 获取调用上下文（绑定 index、credentials、token）
            let ctx = match self
                .token_manager
                .acquire_context_for_session_excluding_pinned(
                    model.as_deref(),
                    session_id.as_deref(),
                    &failed_credential_ids,
                    pinned_credential_id,
                )
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    let err_str = e.to_string();
                    let pe = if err_str.contains("所有凭据均已禁用") {
                        ProviderError::AllCredentialsDisabled {
                            available: self.token_manager.available_count(),
                            total: self.token_manager.total_count(),
                        }
                    } else {
                        ProviderError::TokenAcquisitionFailed {
                            available: self.token_manager.available_count(),
                            total: self.token_manager.total_count(),
                        }
                    };
                    return Err(pe.into());
                }
            };

            // 记下这一轮实际拿到的凭据，作为下一轮重试（若发生）的 pin 候选。
            // 是否真的粘住取决于下一轮 acquire 时它是否仍可预留——见上方
            // `pinned_credential_id` 声明处的注释。
            pinned_credential_id = Some(ctx.id);

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(ProviderError::InternalConfig {
                        detail: e.to_string(),
                    });
                    self.token_manager.report_failure(ctx.id);
                    failed_credential_ids.insert(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.api_url(&rctx);
            let body = endpoint.transform_api_body(request_body, &rctx);

            // generateAssistantResponse 属于业务长响应（流式/非流式），使用 idle/read 超时 client
            let client = match self.client_for(&ctx.credentials, ClientKind::Idle) {
                Ok(client) => client,
                Err(e) => {
                    self.token_manager.report_no_result(ctx.id);
                    return Err(e);
                }
            };
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_api(base, &rctx);

            self.token_manager
                .record_upstream_call(ctx.id, model.as_deref());
            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_retries,
                        error = %e,
                        "API 请求发送失败"
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    last_error = Some(ProviderError::ConnectionFailed {
                        detail: e.to_string(),
                    });
                    self.token_manager.report_no_result(ctx.id);
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                self.token_manager
                    .report_success_for_session(ctx.id, session_id.as_deref());
                return Ok(KiroApiResponse {
                    response,
                    credential_id: ctx.id,
                    sticky_hit: ctx.sticky_hit,
                });
            }

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();

            // 402 Payment Required 且额度用尽：禁用凭据并故障转移
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "API 请求失败（额度已用尽，禁用凭据并切换）"
                );

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    return Err(ProviderError::AllCredentialsQuotaExhausted {
                        detail: format!("{} {}", status, body),
                    }
                    .into());
                }

                last_error = Some(ProviderError::AllCredentialsQuotaExhausted {
                    detail: format!("{} {}", status, body),
                });
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换凭据无意义
            if status.as_u16() == 400 {
                self.token_manager.report_no_result(ctx.id);
                return Err(ProviderError::UpstreamClientError {
                    status: status.as_u16(),
                    body,
                }
                .into());
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "API 请求失败（可能为凭据错误）"
                );

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        self.token_manager.report_no_result(ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                failed_credential_ids.insert(ctx.id);
                if !has_available {
                    return Err(ProviderError::UpstreamClientError {
                        status: status.as_u16(),
                        body,
                    }
                    .into());
                }

                last_error = Some(ProviderError::UpstreamClientError {
                    status: status.as_u16(),
                    body: body.clone(),
                });
                continue;
            }

            // 429/408 - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "API 请求失败（上游瞬态错误）"
                );
                last_error = Some(ProviderError::UpstreamTransientExhausted {
                    last_status: status.as_u16(),
                    body: body.clone(),
                });
                self.token_manager.report_no_result(ctx.id);
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // `#98`：5xx（上游服务端错误）独立于 429/408 的重试预算——与全局预算
            // 乘数完全正交，专治"同一次故障被乘以最多 9 次上游调用"。
            //
            // `#101`：`is_server_error()` 把 500/502/503/504 全族绑在同一个
            // `MAX_5XX_RETRIES = 1` 上，是**有意收紧**不是漏拆——生产排查数据是
            // 100/100 全 500，这个预算对 500 对症；503/504 以前能跟 429 一样重
            // 试到 9 次，现在同样只给 1 次。若将来拿到 503/504 的黑盒数据表明
            // 它们更接近 408 的"瞬态但预算应更宽"语义，可再单独拆分出去，本次
            // 不改行为，只把这条取舍写清楚。
            if status.is_server_error() {
                server_error_retries += 1;
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries,
                    status = %status,
                    server_error_retries,
                    max_5xx_retries = MAX_5XX_RETRIES,
                    upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                    "API 请求失败（上游服务端错误）"
                );
                let transient = ProviderError::UpstreamTransientExhausted {
                    last_status: status.as_u16(),
                    body: body.clone(),
                };
                self.token_manager.report_no_result(ctx.id);
                if server_error_retries > MAX_5XX_RETRIES {
                    // 预算用尽立即上抛。刻意**不**插 failed_credential_ids——D3 保留"不换凭据"。
                    return Err(transient.into());
                }
                last_error = Some(transient);
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                self.token_manager.report_no_result(ctx.id);
                return Err(ProviderError::UpstreamClientError {
                    status: status.as_u16(),
                    body,
                }
                .into());
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            tracing::warn!(
                attempt = attempt + 1,
                max_retries,
                status = %status,
                upstream_body = %truncate_for_log(&body, LOG_PAYLOAD_LIMIT),
                "API 请求失败（未知错误）"
            );
            last_error = Some(ProviderError::UpstreamTransientExhausted {
                last_status: status.as_u16(),
                body: body.clone(),
            });
            self.token_manager.report_no_result(ctx.id);
            failed_credential_ids.insert(ctx.id);
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error
            .unwrap_or(ProviderError::UpstreamTransientExhausted {
                last_status: 0,
                body: format!(
                    "{} API 请求失败：已达到最大重试次数（{}次）",
                    api_type, max_retries
                ),
            })
            .into())
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// 从请求体中提取会话 ID
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.conversationId。
    fn extract_session_id_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("conversationId")?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }
}

/// `#98` provider 重试逻辑测试脚手架。
///
/// 脚手架选型论证（plan `测试设计` §"新增 —— provider.rs"）：本仓
/// dev-dependencies 当前为空，引入 `wiremock` 会带进十余个传递依赖，而
/// CI/本地全靠 `rust:1.92-alpine` 冷编译，每次都要多付这个代价；抽纯函数
/// 测的是新造的抽象而非真实重试循环，且"错误分类表"本身是阶段三的产出物，
/// 现在造半个会被下一个 PR 推翻。故选裸 `TcpListener` stub +
/// `#[cfg(test)] TestEndpoint`：零生产改动（`KiroProvider::with_proxy` 的
/// `endpoints` 本就是构造期注入的 `HashMap<String, Arc<dyn KiroEndpoint>>`，
/// URL 完全由 endpoint 自己拥有，`build_idle_client` 没有 `https_only`，
/// 明文 HTTP loopback 直接可用），且与 token_manager.rs 测试里已有的
/// loopback profile-lookup stub 是同一手法，仓内一致。
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::model::config::Config;
    use crate::model::registry::ModelRegistry;

    /// 测试专用清理 guard：无论测试函数体正常返回还是断言失败 panic 退出，
    /// `Drop` 都会执行，不残留临时目录（同 token_manager.rs 测试里的
    /// `TempDirGuard` 手法）。
    struct TempDirGuard(PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// 裸 loopback 上游 stub：起一个 TCP 服务，对每个连接原样回放固定的
    /// `status_line`/`body`，命中次数写入共享 `hits`。循环 `accept`，服务
    /// 测试期间的全部重试请求；随值 `Drop` 时 `abort` 后台任务，不残留。
    struct StubUpstream {
        url: String,
        hits: Arc<AtomicUsize>,
        server: tokio::task::JoinHandle<()>,
    }

    impl StubUpstream {
        async fn start(status_line: &'static str, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_for_server = hits.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    hits_for_server.fetch_add(1, Ordering::SeqCst);
                    let mut buf = vec![0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
            Self {
                url: format!("http://{addr}/generateAssistantResponse"),
                hits,
                server,
            }
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for StubUpstream {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// 最小 `KiroEndpoint` 实现：URL 固定指向 stub，请求体/头原样透传，
    /// `is_monthly_request_limit` / `is_bearer_token_invalid` 走 trait 默认
    /// 实现（body 文本判断，足够覆盖 P6 的 402 场景）。
    struct TestEndpoint {
        url: String,
    }

    impl KiroEndpoint for TestEndpoint {
        fn name(&self) -> &'static str {
            "test"
        }
        fn api_url(&self, _ctx: &RequestContext<'_>) -> String {
            self.url.clone()
        }
        fn mcp_url(&self, _ctx: &RequestContext<'_>) -> String {
            self.url.clone()
        }
        fn decorate_api(
            &self,
            req: reqwest::RequestBuilder,
            _ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            req
        }
        fn decorate_mcp(
            &self,
            req: reqwest::RequestBuilder,
            _ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            req
        }
        fn transform_api_body(&self, body: &str, _ctx: &RequestContext<'_>) -> String {
            body.to_string()
        }
    }

    /// `id` 号 API Key 凭据（跳过 token 刷新的全部网络交互）。`subscription_title`
    /// 传 `Some("KIRO FREE")` 构造不支持 opus 的凭据（P4/P5 的 tier 过滤探针）。
    fn api_key_credential(
        id: u64,
        priority: u32,
        subscription_title: Option<&str>,
    ) -> KiroCredentials {
        KiroCredentials {
            id: Some(id),
            kiro_api_key: Some(format!("ksk_test_{id}")),
            priority,
            subscription_title: subscription_title.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    fn endpoints_map(stub: &StubUpstream) -> HashMap<String, Arc<dyn KiroEndpoint>> {
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                url: stub.url.clone(),
            }) as Arc<dyn KiroEndpoint>,
        );
        endpoints
    }

    fn provider_with_stub(credentials: Vec<KiroCredentials>, stub: &StubUpstream) -> KiroProvider {
        let manager = MultiTokenManager::new(
            Config::default(),
            credentials,
            None,
            None,
            false,
            Arc::new(ModelRegistry::builtin()),
        )
        .unwrap();
        KiroProvider::with_proxy(
            Arc::new(manager),
            None,
            endpoints_map(stub),
            "test".to_string(),
        )
    }

    /// `#101`：与 [`Config::default`] 唯一区别是 `load_balancing_mode` 改
    /// `"balanced"`。已确证事实（本次派发 prompt）——priority 模式下的既有
    /// provider 测试从未覆盖过 balanced（`Config::default()` 的
    /// `load_balancing_mode` 来自 `default_load_balancing_mode()` 即
    /// `"priority"`），而生产落盘实测正是 balanced 模式下两次调用落在不同
    /// 凭据上，故 P1/429 基线的反事实验证必须切到这个配置才有辨识力。
    fn balanced_config() -> Config {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        config
    }

    /// 合法 JSON 请求体，携带 `extract_model_from_request` 需要的
    /// `conversationState.currentMessage.userInputMessage.modelId`，以及
    /// `extract_session_id_from_request` 需要的 `conversationId`。
    fn request_body(model_id: &str) -> String {
        format!(
            r#"{{"conversationState":{{"conversationId":"11111111-1111-1111-1111-111111111111","currentMessage":{{"userInputMessage":{{"modelId":"{model_id}","content":"hi"}}}}}}}}"#
        )
    }

    /// commit 5 基线测试：刻画改造前（本 commit 不改任何生产重试逻辑）的当前
    /// 行为——408|429|5xx 目前是同一条分支，且没有真正生效的逐凭据排除（见
    /// commit 6 doc：`MAX_RETRIES_PER_CREDENTIAL` 在 #98 之前只有"全局预算
    /// 乘数"这一个角色生效），3 张凭据、上游恒 429 时，总重试次数恒为
    /// `min(3*3,9)=9`。commit 6 落地 5xx 预算拆分后，这条测试的断言值不变
    /// （429 不受 5xx 预算影响，`min(3*3,9)` 这个算式的结果本就等于
    /// `MAX_TOTAL_RETRIES`），故它同时兼任 plan 测试设计表里的 P2——commit 6
    /// 不重复添加 P2，只在其反事实验证环节复用这条测试。
    ///
    /// `#101` 改造：原函数名 "across_all_credentials" 描述的其实是
    /// `min(3*3,9)=9` 这个总重试预算算式，不是"确实换过凭据"——priority 模式
    /// 下这条测试恒在同一张凭据上打满 9 次，名字名不副实。改到 balanced 模式
    /// 后，命名的名实关系反而更需要澄清：`#98` 引入的 load 排序本会在每次
    /// 429（瞬态、不排除）重试时把凭据换走（本 PR MUST FIX 1 修复前的真实
    /// 观测，见 `BLOCKED`/反事实记录），修复后又回到"9 次全部粘在同一张"——
    /// 与 priority 模式殊途同归，与函数名字面意思仍然相反。故改名去掉
    /// "across_all_credentials" 的误导，实际覆盖面见新 doc comment：
    /// balanced 模式 + 瞬态错误 + 粘滞修复，9 次重试应全部落在同一张凭据。
    #[tokio::test]
    async fn test_baseline_429_exhausts_all_retries_pinned_to_one_credential() {
        let temp_dir =
            std::env::temp_dir().join(format!("kiro-rs-test-429baseline-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let _guard = TempDirGuard(temp_dir.clone());

        let stub = StubUpstream::start("429 Too Many Requests", r#"{"message":"slow down"}"#).await;
        let credentials = vec![
            api_key_credential(1, 0, None),
            api_key_credential(2, 1, None),
            api_key_credential(3, 2, None),
        ];
        let (provider, manager) =
            provider_with_stub_and_manager_balanced(credentials, &stub, &temp_dir);
        let body = request_body("claude-sonnet-5");

        let result = provider.call_api_with_retry(&body, false).await;

        assert!(result.is_err(), "恒 429 必须以 Err 收尾");
        assert_eq!(
            stub.hits(),
            9,
            "min(3 张凭据 × MAX_RETRIES_PER_CREDENTIAL(3), MAX_TOTAL_RETRIES(9)) == 9，\
             该算式与本 PR 的粘滞修复正交（429 分支本就不受 failed_credential_ids/pin 影响\
             总重试次数，只影响落在哪张凭据上）"
        );

        drop(provider);
        drop(manager);

        let stats_path = temp_dir.join("kiro_stats.json");
        let raw = std::fs::read_to_string(&stats_path)
            .unwrap_or_else(|e| panic!("Drop 应已把 kiro_stats.json 落盘到 {stats_path:?}: {e}"));
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let nonzero_loads: Vec<&str> = ["1", "2", "3"]
            .into_iter()
            .filter(|id| json[*id]["load"].as_f64().unwrap_or(0.0) > 0.0)
            .collect();
        assert_eq!(
            nonzero_loads.len(),
            1,
            "MUST FIX 1：429 是瞬态分支，应粘住本轮凭据——9 次重试应全部落在同一张凭据上，\
             故有且仅有一个 entry 的 load 非零，实际非零的凭据: {nonzero_loads:?}，落盘原文: {raw}"
        );
    }

    /// 与 `provider_with_stub` 等价，但额外把 `Arc<MultiTokenManager>` 单独返回
    /// 给调用方持有——P1/P3 需要在 `provider` 用完后显式 drop 掉它内部的克隆，
    /// 让引用计数归零触发 `impl Drop for MultiTokenManager` 的落盘，绕开 30 秒
    /// 防抖窗口读到最终值（而非仅第一次调用触发的同步落盘）。
    ///
    /// 该 Drop 是**有条件**的（`stats_dirty_version != stats_saved_version` 才
    /// 写，见 `token_manager.rs` 字段注释），不是无条件兜底——这条测试今天能
    /// 依赖它落盘，依赖的是本 PR 新给 `report_no_result` 加的标脏（`#98` 之前
    /// 它是 6 个 `report_*` 里唯一不标脏的一个）；若后人删掉那处标脏，Drop 不
    /// 会兜底重写，这条测试会因文件不存在而失败，不是静默通过。
    /// `credentials_path` 指向临时目录下一个不存在的文件——`cache_dir()` 只取
    /// 其 parent，文件本身是否存在不影响 `stats_path()` 解析。
    fn provider_with_stub_and_manager(
        credentials: Vec<KiroCredentials>,
        stub: &StubUpstream,
        cache_dir: &std::path::Path,
    ) -> (KiroProvider, Arc<MultiTokenManager>) {
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                credentials,
                None,
                Some(cache_dir.join("credentials.json")),
                false,
                Arc::new(ModelRegistry::builtin()),
            )
            .unwrap(),
        );
        let provider = KiroProvider::with_proxy(
            manager.clone(),
            None,
            endpoints_map(stub),
            "test".to_string(),
        );
        (provider, manager)
    }

    /// 与 [`provider_with_stub_and_manager`] 等价，唯一区别是 [`balanced_config`]。
    fn provider_with_stub_and_manager_balanced(
        credentials: Vec<KiroCredentials>,
        stub: &StubUpstream,
        cache_dir: &std::path::Path,
    ) -> (KiroProvider, Arc<MultiTokenManager>) {
        let manager = Arc::new(
            MultiTokenManager::new(
                balanced_config(),
                credentials,
                None,
                Some(cache_dir.join("credentials.json")),
                false,
                Arc::new(ModelRegistry::builtin()),
            )
            .unwrap(),
        );
        let provider = KiroProvider::with_proxy(
            manager.clone(),
            None,
            endpoints_map(stub),
            "test".to_string(),
        );
        (provider, manager)
    }

    /// `Result::expect_err` 要求 `T: Debug`，但 `KiroApiResponse`（生产类型，
    /// 范围围栏之外，不改）没有派生 `Debug`——这个小 helper 手写等价逻辑，
    /// 不碰任何生产代码。
    fn expect_err(result: anyhow::Result<KiroApiResponse>, msg: &str) -> anyhow::Error {
        match result {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }

    /// P1：本 PR 最有价值的一条——恒 500 + 3 张健康凭据，验证 5xx 预算把总上游
    /// 调用次数从旧的 `min(3*3,9)=9` 降到 2，且预算耗尽后返回的仍是
    /// `UpstreamTransientExhausted{last_status:500}`（与今天跑满重试后同一变体，
    /// `handlers.rs` 零改动的前提）。
    ///
    /// 追加断言（D3：5xx 不换凭据，本函数内 5xx 分支处的注释所记的设计决策）：两次上游
    /// 调用必须落在同一张凭据上。单看 `hits==2` 无法辨识这条不变量——预算恒在
    /// 第 2 次终止，无论 5xx 分支是否误插一行 `failed_credential_ids.insert`，
    /// `hits` 都还是 2，反事实测不出来。改用 P3 已验证可用的落盘观测手法
    /// （`credentials_path` 挂临时目录、`drop(provider)`/`drop(manager)` 触发
    /// `MultiTokenManager` 落盘、解析 `kiro_stats.json`）：3 张凭据里应有且仅
    /// 有一张 `load` 非零。
    ///
    /// `#101` MUST FIX 2：改到 balanced 模式跑（[`provider_with_stub_and_manager_balanced`]）
    /// ——priority 模式下 `current_id` 本来就粘住，这条不变量在 priority 下测不出
    /// `#98` 引入的 load 排序问题；已确证事实（本次派发 prompt）：balanced 模式下
    /// 恒 500 的 3 凭据场景实测落盘 `load=1.0/1.0/0.0`，两次调用落在不同凭据上。
    /// `hits==2` 与错误变体断言原样保留（5xx 预算与选路正交，见上方 doc）。
    #[tokio::test]
    async fn test_p1_5xx_budget_caps_upstream_hits_at_two() {
        let temp_dir =
            std::env::temp_dir().join(format!("kiro-rs-test-p1-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let _guard = TempDirGuard(temp_dir.clone());

        let stub = StubUpstream::start("500 Internal Server Error", r#"{"message":"boom"}"#).await;
        let credentials = vec![
            api_key_credential(1, 0, None),
            api_key_credential(2, 1, None),
            api_key_credential(3, 2, None),
        ];
        let (provider, manager) =
            provider_with_stub_and_manager_balanced(credentials, &stub, &temp_dir);
        let body = request_body("claude-sonnet-5");

        let result = provider.call_api_with_retry(&body, false).await;

        assert_eq!(
            stub.hits(),
            2,
            "MAX_5XX_RETRIES=1：attempt#0 计数到 1（不越界，继续），attempt#1 计数到 2（越界，立即返回）"
        );
        let err = expect_err(result, "恒 500 必须以 Err 收尾");
        match err.downcast_ref::<ProviderError>() {
            Some(ProviderError::UpstreamTransientExhausted { last_status, .. }) => {
                assert_eq!(*last_status, 500);
            }
            other => panic!("期望 UpstreamTransientExhausted{{500}}，实际: {other:?}"),
        }

        drop(provider);
        drop(manager);

        let stats_path = temp_dir.join("kiro_stats.json");
        let raw = std::fs::read_to_string(&stats_path)
            .unwrap_or_else(|e| panic!("Drop 应已把 kiro_stats.json 落盘到 {stats_path:?}: {e}"));
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let nonzero_loads: Vec<&str> = ["1", "2", "3"]
            .into_iter()
            .filter(|id| json[*id]["load"].as_f64().unwrap_or(0.0) > 0.0)
            .collect();
        assert_eq!(
            nonzero_loads.len(),
            1,
            "D3：5xx 不换凭据，两次调用应落在同一张凭据上，故有且仅有一个 entry 的 load 非零，实际非零的凭据: {nonzero_loads:?}，落盘原文: {raw}"
        );
    }

    /// P3：计量恰好一次 + 不退款。恒 500、1 张凭据、`modelId="gpt-5.6-sol"`
    /// （`credit_weight_by_kiro_id` 精确命中 2.4）。两次上游调用各计一次权重，
    /// 预算耗尽后不退款，最终 `load` 应约等于 `2 * 2.4 = 4.8`。
    ///
    /// 断言容差：**不是** `1e-9` 的"f64 精确"（实测发现该断言过严会恒假红）
    /// ——两次 `record_upstream_call` 之间真实经过了一次 `retry_delay(0)`
    /// （约 200ms），`entry.record_load` 按半衰期对已记录部分做了真实衰减
    /// （§B 既有行为，非本 PR 引入），实测落盘 `load ≈ 4.799990`，与 4.8 相差
    /// 约 1e-5。这是"计量恰好两次、不退款"这条真实保证之外的另一个真实效应
    /// （衰减精度，已由 N3 覆盖），不该被这条测试的容差意外卡住。容差取
    /// `1e-2`——远宽于合理时钟抖动下的衰减量级（1e-5 ~ 1e-4 级），但仍严格
    /// 窄于"少计一次"(0.0 差 4.8)或"多计一次"(2.4 差 2.4)等真实回归的量级，
    /// 足以让下面的反事实（删计量行）可靠变红。
    #[tokio::test]
    async fn test_p3_record_upstream_call_meters_exactly_once_per_call_no_refund() {
        let temp_dir =
            std::env::temp_dir().join(format!("kiro-rs-test-p3-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let _guard = TempDirGuard(temp_dir.clone());

        let stub = StubUpstream::start("500 Internal Server Error", r#"{"message":"boom"}"#).await;
        let credentials = vec![api_key_credential(1, 0, None)];
        let (provider, manager) = provider_with_stub_and_manager(credentials, &stub, &temp_dir);
        let body = request_body("gpt-5.6-sol");

        let result = provider.call_api_with_retry(&body, false).await;
        assert!(result.is_err(), "恒 500 必须以 Err 收尾");
        assert_eq!(stub.hits(), 2, "5xx 预算=1，纯 500 序列总共 2 次上游调用");

        // 强制落盘：drop 掉 provider 内部克隆与本地持有的最后一份 Arc，引用计数
        // 归零触发 `impl Drop for MultiTokenManager` 的 `save_stats`——该 Drop 是
        // 有条件的（脏才写），这里能读到最终值依赖本 PR 新给 `report_no_result`
        // 加的标脏，见 `provider_with_stub_and_manager` 上方 doc comment。
        drop(provider);
        drop(manager);

        let stats_path = temp_dir.join("kiro_stats.json");
        let raw = std::fs::read_to_string(&stats_path)
            .unwrap_or_else(|e| panic!("Drop 应已把 kiro_stats.json 落盘到 {stats_path:?}: {e}"));
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let load = json["1"]["load"]
            .as_f64()
            .unwrap_or_else(|| panic!("落盘 JSON 缺少凭据 1 的 load 字段: {raw}"));
        assert!(
            (load - 4.8).abs() < 1e-2,
            "load 应约等于 2 次调用 × credit_weight(gpt-5.6-sol)=2.4 = 4.8（容差 1e-2 内，见上方 doc comment），实际: {load}"
        );
    }

    /// P6：分支穷尽——5xx 拆分动了 `if` 链顺序敏感区，验证 400/404/402(月度
    /// 配额) 三个既有分支未被误吞。各自独立 stub + 1 张凭据，`hits==1`
    /// （均不重试），错误变体与拆分前一致。
    ///
    /// 诚实说明（反事实实测偏离 plan 预期的一处）：plan 给出的反事实"把新
    /// 5xx 分支误写成 `status.as_u16() >= 400`"，预期 400/404 都被吞、
    /// `hits==2`。实测只有 **404** 真红——400 在函数里更早处 (`:711`) 已有
    /// 独立专属分支直接 `return`，根本走不到新 5xx 分支，对这条笔误没有辨识
    /// 力；404 没有专属分支、真正落进"其他 4xx"兜底，如实反映了笔误后果，
    /// 单独已确认真红。该测试仍对"5xx 拆分误吞其他状态码"这类回归保有效
    /// 力，只是覆盖来源是 404/402 两条而非三条都覆盖，如实记录不强行凑红。
    #[tokio::test]
    async fn test_p6_non_retryable_4xx_branches_still_short_circuit_at_one_hit() {
        // 400：有独立专属分支（早于本 PR 已存在，`:711` 一进函数就 return），
        // UpstreamClientError，不重试。反事实实测：本条不受"其他 4xx 兜底
        // 分支笔误"影响——它在到达那条分支之前就已 return，故对 400 这一路
        // 没有辨识力，见下方 doc comment 的诚实说明。

        {
            let stub = StubUpstream::start("400 Bad Request", r#"{"message":"bad"}"#).await;
            let provider = provider_with_stub(vec![api_key_credential(1, 0, None)], &stub);
            let result = provider
                .call_api_with_retry(&request_body("claude-sonnet-5"), false)
                .await;
            assert_eq!(stub.hits(), 1, "400 不重试");
            match expect_err(result, "400 必须 Err").downcast_ref::<ProviderError>() {
                Some(ProviderError::UpstreamClientError { status, .. }) => assert_eq!(*status, 400),
                other => panic!("期望 UpstreamClientError{{400}}，实际: {other:?}"),
            }
        }

        // 404：同样落在"其他 4xx"兜底分支。
        {
            let stub = StubUpstream::start("404 Not Found", r#"{"message":"missing"}"#).await;
            let provider = provider_with_stub(vec![api_key_credential(1, 0, None)], &stub);
            let result = provider
                .call_api_with_retry(&request_body("claude-sonnet-5"), false)
                .await;
            assert_eq!(stub.hits(), 1, "404 不重试");
            match expect_err(result, "404 必须 Err").downcast_ref::<ProviderError>() {
                Some(ProviderError::UpstreamClientError { status, .. }) => assert_eq!(*status, 404),
                other => panic!("期望 UpstreamClientError{{404}}，实际: {other:?}"),
            }
        }

        // 402 + MONTHLY_REQUEST_COUNT：唯一凭据被禁用后无可用凭据，
        // AllCredentialsQuotaExhausted，不重试。
        {
            let stub = StubUpstream::start(
                "402 Payment Required",
                r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#,
            )
            .await;
            let provider = provider_with_stub(vec![api_key_credential(1, 0, None)], &stub);
            let result = provider
                .call_api_with_retry(&request_body("claude-sonnet-5"), false)
                .await;
            assert_eq!(
                stub.hits(),
                1,
                "402 月度配额用尽、唯一凭据禁用后无可用凭据，不重试"
            );
            match expect_err(result, "402 月度配额用尽必须 Err").downcast_ref::<ProviderError>()
            {
                Some(ProviderError::AllCredentialsQuotaExhausted { .. }) => {}
                other => panic!("期望 AllCredentialsQuotaExhausted，实际: {other:?}"),
            }
        }
    }
}
