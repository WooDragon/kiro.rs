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
            if status.is_success() {
                self.token_manager
                    .report_success_for_session(ctx.id, session_id);
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

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
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
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);
        let session_id = Self::extract_session_id_from_request(request_body);

        for attempt in 0..max_retries {
            // 获取调用上下文（绑定 index、credentials、token）
            let ctx = match self
                .token_manager
                .acquire_context_for_session_excluding(
                    model.as_deref(),
                    session_id.as_deref(),
                    &failed_credential_ids,
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

            // 429/408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic / 502 high load 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
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
