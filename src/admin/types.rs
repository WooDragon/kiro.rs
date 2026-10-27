//! Admin API 类型定义

use serde::{Deserialize, Serialize};

// ============ 凭据状态 ============

/// 所有凭据状态响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsStatusResponse {
    /// 凭据总数
    pub total: usize,
    /// 可用凭据数量（未禁用）
    pub available: usize,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 运行时全局代理是否已配置
    pub global_proxy_configured: bool,
    /// 各凭据状态列表
    pub credentials: Vec<CredentialStatusItem>,
}

/// 单个凭据的状态信息
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusItem {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级（数字越小优先级越高）
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 是否为当前活跃凭据
    pub is_current: bool,
    /// Token 过期时间（RFC3339 格式）
    pub expires_at: Option<String>,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
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
    /// 是否配置了任何形式的代理（保留旧字段）
    pub has_proxy: bool,
    /// 代理 URL（已脱敏；仅内联/直连时有值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// 代理来源：inherit | direct | pool | inline
    pub proxy_mode: String,
    /// 池条目 ID（仅 pool 模式）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    /// 池条目名称（仅 pool 模式，便于前端直接展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_name: Option<String>,
    /// 该凭据实际使用的脱敏代理地址（不含密码，含继承来的全局代理）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 端点名称（决定该凭据走哪套 Kiro API，已回退到默认端点）
    pub endpoint: String,
}

// ============ 代理池 ============

/// 代理池列表响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyListResponse {
    pub proxies: Vec<ProxyItem>,
}

/// 单个池代理（不回传密码）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyItem {
    pub id: String,
    pub name: String,
    /// 已脱敏 URL
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub has_password: bool,
    pub reference_count: usize,
}

/// 新增池代理请求
///
/// `id` 由服务端生成：客户端传入的 id 会落在 URL 路径里，`.`/`..`/空格/斜杠
/// 这类值在浏览器路径解析中被改写，导致条目在 UI 里无法再定位、编辑或删除。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProxyRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// 编辑池代理请求（PATCH：字段缺省=保留，null=清除，值=替换）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProxyRequest {
    #[serde(default, deserialize_with = "double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub url: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub password: Option<Option<String>>,
}

fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl From<crate::kiro::token_manager::ProxyListItem> for ProxyItem {
    fn from(item: crate::kiro::token_manager::ProxyListItem) -> Self {
        Self {
            id: item.id,
            name: item.name,
            url: item.url,
            username: item.username,
            has_password: item.has_password,
            reference_count: item.reference_count,
        }
    }
}

impl From<UpdateProxyRequest> for crate::kiro::token_manager::ProxyUpdateRequest {
    fn from(request: UpdateProxyRequest) -> Self {
        Self {
            name: request.name,
            url: request.url,
            username: request.username,
            password: request.password,
        }
    }
}

impl From<BindProxyRequest> for crate::kiro::token_manager::ProxyBindingRequest {
    fn from(request: BindProxyRequest) -> Self {
        match request {
            BindProxyRequest::Inherit => Self::Inherit,
            BindProxyRequest::Direct => Self::Direct,
            BindProxyRequest::Pool { proxy_id } => Self::Pool { proxy_id },
            BindProxyRequest::Inline {
                url,
                username,
                password,
            } => Self::Inline {
                url,
                username,
                password,
            },
        }
    }
}

/// 绑定凭据代理请求（tagged by `mode`）
#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum BindProxyRequest {
    Inherit,
    Direct,
    Pool {
        #[serde(rename = "proxyId")]
        proxy_id: String,
    },
    Inline {
        url: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
}

// ============ 操作请求 ============

/// 启用/禁用凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisabledRequest {
    /// 是否禁用
    pub disabled: bool,
}

/// 修改优先级请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPriorityRequest {
    /// 新优先级值
    pub priority: u32,
}

/// 添加凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialRequest {
    /// 刷新令牌（OAuth 凭据必填，API Key 凭据不需要）
    pub refresh_token: Option<String>,

    /// 认证方式（可选，默认 social）
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// OIDC Client ID（IdC 认证需要）
    pub client_id: Option<String>,

    /// OIDC Client Secret（IdC 认证需要）
    pub client_secret: Option<String>,

    /// 优先级（可选，默认 0）
    #[serde(default)]
    pub priority: u32,

    /// 凭据级 Region 配置（用于 OIDC token 刷新）
    /// 未配置时回退到 config.json 的全局 region
    pub region: Option<String>,

    /// 凭据级 Auth Region（用于 Token 刷新）
    pub auth_region: Option<String>,

    /// 凭据级 API Region（用于 API 请求）
    pub api_region: Option<String>,

    /// 凭据级 Machine ID（可选，64 位字符串）
    /// 未配置时回退到 config.json 的 machineId
    pub machine_id: Option<String>,

    /// 用户邮箱（可选，用于前端显示）
    pub email: Option<String>,

    /// 凭据级代理 URL（可选，特殊值 "direct" 表示不使用代理）
    pub proxy_url: Option<String>,

    /// 凭据级代理认证用户名（可选）
    pub proxy_username: Option<String>,

    /// 凭据级代理认证密码（可选）
    pub proxy_password: Option<String>,

    /// 绑定的代理池条目 ID（与上面三个内联字段互斥）
    pub proxy_id: Option<String>,

    /// 新的 tagged 绑定写法（`mode = inherit|direct|pool|inline`）
    #[serde(default)]
    pub proxy: Option<BindProxyRequest>,

    /// Kiro API Key（API Key 凭据必填，格式: ksk_xxxxxxxx）
    /// 设置后直接作为 Bearer Token 使用，无需 refreshToken
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kiro_api_key: Option<String>,

    /// 端点名称（可选，未配置时使用 config.defaultEndpoint）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// 落盘的旧三字段形态：`(proxyUrl, proxyUsername, proxyPassword)`。
pub type LegacyProxyFields = (Option<String>, Option<String>, Option<String>);

impl AddCredentialRequest {
    /// 旧三字段是否出现（`proxyUrl`/`proxyUsername`/`proxyPassword`）。
    fn legacy_inline_present(&self) -> bool {
        self.proxy_url.is_some() || self.proxy_username.is_some() || self.proxy_password.is_some()
    }

    /// 把新旧两种代理表达合流成单一 `proxyId` 字段，并拒绝同时出现。
    ///
    /// 新旧表达同时出现会写出加载期拒绝的绑定组合（`proxyId` + 旧字段），
    /// 下次启动即 fail-fast，因此这里必须和 `validate_document` 的规则一致。
    pub fn proxy_binding_id(&self) -> Result<Option<String>, String> {
        if self.proxy.is_some() && (self.legacy_inline_present() || self.proxy_id.is_some()) {
            return Err(
                "proxy 与 proxyUrl/proxyUsername/proxyPassword/proxyId 不能同时提供".to_string(),
            );
        }
        if self.proxy_id.is_some() && self.legacy_inline_present() {
            return Err("proxyId 不能与 proxyUrl/proxyUsername/proxyPassword 同时提供".to_string());
        }
        Ok(match &self.proxy {
            Some(BindProxyRequest::Pool { proxy_id }) => Some(proxy_id.clone()),
            _ => self.proxy_id.clone(),
        })
    }

    /// 新写法里的内联/直连/继承需要落到旧三字段上（内联三字段的落盘形态不变）。
    ///
    /// 新表达的内联代理与 `PUT /credentials/{id}/proxy` 共用
    /// [`crate::kiro::model::proxy_pool::inline_proxy_config`] 校验；
    /// 旧三字段的既有行为保持不变（`proxyUrl:"direct"` 仍然有效）。
    pub fn apply_binding_fields(&self) -> Result<LegacyProxyFields, String> {
        Ok(match &self.proxy {
            Some(BindProxyRequest::Direct) => (Some("direct".to_string()), None, None),
            Some(BindProxyRequest::Inline {
                url,
                username,
                password,
            }) => {
                crate::kiro::model::proxy_pool::inline_proxy_config(
                    url,
                    username.as_deref(),
                    password.as_deref(),
                )?;
                (Some(url.clone()), username.clone(), password.clone())
            }
            _ => (
                self.proxy_url.clone(),
                self.proxy_username.clone(),
                self.proxy_password.clone(),
            ),
        })
    }
}

fn default_auth_method() -> String {
    "social".to_string()
}

/// 添加凭据成功响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialResponse {
    pub success: bool,
    pub message: String,
    /// 新添加的凭据 ID
    pub credential_id: u64,
    /// 用户邮箱（如果获取成功）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

// ============ 余额查询 ============

/// 余额查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    /// 凭据 ID
    pub id: u64,
    /// 订阅类型
    pub subscription_title: Option<String>,
    /// 当前使用量
    pub current_usage: f64,
    /// 使用限额
    pub usage_limit: f64,
    /// 剩余额度
    pub remaining: f64,
    /// 使用百分比
    pub usage_percentage: f64,
    /// 下次重置时间（Unix 时间戳）
    pub next_reset_at: Option<f64>,
}

// ============ 负载均衡配置 ============

/// 负载均衡模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancingModeResponse {
    /// 当前模式（"priority" 或 "balanced"）
    pub mode: String,
}

/// 设置负载均衡模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetLoadBalancingModeRequest {
    /// 模式（"priority" 或 "balanced"）
    pub mode: String,
}

// ============ 通用响应 ============

/// 操作成功响应
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

impl SuccessResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }
}

/// 错误响应
#[derive(Debug, Serialize)]
pub struct AdminErrorResponse {
    pub error: AdminError,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl AdminErrorResponse {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: AdminError {
                error_type: error_type.into(),
                message: message.into(),
            },
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }

    pub fn authentication_error() -> Self {
        Self::new("authentication_error", "Invalid or missing admin API key")
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn api_error(message: impl Into<String>) -> Self {
        Self::new("api_error", message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}
