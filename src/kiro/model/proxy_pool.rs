//! 代理池的纯数据层：池条目、绑定解析、URL 校验与凭据文件封套解析。
//!
//! 这里不做任何 I/O（文件读写归 `token_manager::proxy_pool`），也不持有运行时
//! 状态的锁；它的产物是"可验证的配置"，供启动加载与管理端提交两侧复用，
//! 保证两条入口用同一套规则判断什么是合法绑定。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::http_client::{ProxyConfig, RouteKey};

/// 凭据文件封套的当前版本。
pub const CREDENTIALS_ENVELOPE_VERSION: u32 = 1;

/// 池中的一个代理（可被多个凭据共享）。
///
/// `id`/`name` 只属于池管理，**不进入** [`RouteKey`]——给代理改名不会改变
/// 网络身份，因此不会重建 client、不会丢弃热连接（P3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyEntry {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl ProxyEntry {
    /// 池条目的网络身份。凭据的 route 只由它决定。
    pub fn to_proxy_config(&self) -> ProxyConfig {
        let mut config = ProxyConfig::new(self.url.clone());
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            config = config.with_auth(username, password);
        }
        config
    }

    /// 列表响应用的脱敏 URL。
    pub fn redacted_url(&self) -> String {
        crate::http_client::redact_proxy_url(&self.url)
    }
}

/// 凭据绑定的代理来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyBinding {
    /// 继承全局代理配置（未配置时为系统默认）
    Inherit,
    /// 显式直连
    Direct,
    /// 引用池条目
    Pool(String),
    /// 旧的内联三字段
    Inline(ProxyConfig),
}

/// 把凭据上的绑定字段解析成 [`ProxyBinding`]。
///
/// 优先级：`proxyId` > `proxyUrl == "direct"` > 内联 `proxyUrl` > 继承。
/// 两者同时存在是非法组合，由 [`validate_binding_fields`] 在入口拒绝。
pub fn resolve_binding(
    proxy_id: Option<&str>,
    proxy_url: Option<&str>,
    proxy_username: Option<&str>,
    proxy_password: Option<&str>,
) -> ProxyBinding {
    if let Some(id) = proxy_id.filter(|id| !id.is_empty()) {
        return ProxyBinding::Pool(id.to_string());
    }
    match proxy_url {
        Some(url) if url.eq_ignore_ascii_case("direct") => ProxyBinding::Direct,
        Some(url) => {
            let mut config = ProxyConfig::new(url);
            if let (Some(username), Some(password)) = (proxy_username, proxy_password) {
                config = config.with_auth(username, password);
            }
            ProxyBinding::Inline(config)
        }
        None => ProxyBinding::Inherit,
    }
}

/// 校验池绑定字段：空串 `proxyId` 与内联三字段互斥。
///
/// **空串 `proxyId` 一律拒绝**（F6）。其余路径用 `.filter(|id| !id.is_empty())`
/// 把它当成"未绑定"，两条口径必须在这里统一成"拒绝"，否则：
/// - 新增凭据会先经继承路由真实刷新一次 token，锁内复核再因 `proxy_config("")`
///   查不到而拒绝——拦在请求之后的危害是上游可能已轮换 refresh token；
/// - 绑定端点会因为同一个输入返回 404，与新增路径的 409 结论不一致；
/// - 反过来，若在锁内复核处统一过滤空串，`proxyId: ""` 会被写盘，而
///   `should_write_envelope` 按 `is_some()` 判定，会让没有池的部署写出封套格式。
///
/// 放在共享校验器的首条，是因为 `add_credential` 的第 0 步、加载期
/// `validate_document`、以及 `bind_credential_proxy` 的入口都调用它——
/// 三条路径由此得到同一结论，且都发生在任何网络请求之前。
pub fn validate_binding_fields(
    proxy_id: Option<&str>,
    proxy_url: Option<&str>,
    proxy_username: Option<&str>,
    proxy_password: Option<&str>,
) -> Result<(), String> {
    if proxy_id.is_some_and(str::is_empty) {
        return Err("proxyId 不能为空字符串（不绑定代理请省略该字段）".to_string());
    }
    if proxy_id.is_some()
        && (proxy_url.is_some() || proxy_username.is_some() || proxy_password.is_some())
    {
        return Err("proxyId 不能与 proxyUrl/proxyUsername/proxyPassword 同时设置".to_string());
    }
    if proxy_id.is_some() && proxy_username.is_some() {
        return Err("proxyId 不能与凭据级代理认证字段同时设置".to_string());
    }
    Ok(())
}

/// 单条凭据的绑定字段是否合法（互斥规则）。
///
/// 加载期（[`validate_document`]）与新增凭据（`add_credential`）共用这一份规则：
/// 任何调用路径都不得写出加载期会拒绝的绑定组合。
pub fn validate_credential_binding(credential: &KiroCredentialsPayload) -> Result<(), String> {
    validate_binding_fields(
        credential.proxy_id.as_deref(),
        credential.proxy_url.as_deref(),
        credential.proxy_username.as_deref(),
        credential.proxy_password.as_deref(),
    )
}

/// 新池条目的 URL 校验：只允许协议、host、port。
///
/// 拒绝 userinfo（认证走独立字段）、query、fragment 与非根路径；
/// **不**禁止 localhost / 私网地址——那是使用者的正当场景。
pub fn validate_pool_url(url: &str) -> Result<(), String> {
    if url.trim() != url {
        return Err("代理 URL 不能包含首尾空白".to_string());
    }
    if url.is_empty() {
        return Err("代理 URL 不能为空".to_string());
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("代理 URL 无法解析: {e}"))?;
    match parsed.scheme() {
        "socks5" | "socks5h" | "http" | "https" => {}
        other => {
            return Err(format!(
                "不支持的代理协议 \"{other}\"，只允许 socks5/socks5h/http/https"
            ));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("代理 URL 不能内联认证信息，请使用独立的用户名/密码字段".to_string());
    }
    if parsed.query().is_some() {
        return Err("代理 URL 不能包含查询参数".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("代理 URL 不能包含 fragment".to_string());
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err("代理 URL 不能包含路径".to_string());
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("代理 URL 缺少主机名".to_string());
    }
    Ok(())
}

/// 新表达里的内联代理：与 `PUT /credentials/{id}/proxy` 完全同一套规则。
///
/// 两个入口共用这一份实现，避免"同一个内联代理在两个端点得到不同结论"。
/// scheme 白名单在这里校验（**写入边界**）：这些 URL 都由 UI 构造、格式确定，
/// 收紧是对的；而加载期的旧内联配置不经过这里，保持改动前的 reqwest 语义
/// （无 scheme 的 `host:port` 仍可用，见 `http_client.rs` 的 F3 注释）。
pub fn inline_proxy_config(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<ProxyConfig, String> {
    if url.trim().is_empty() {
        return Err("代理 URL 不能为空".to_string());
    }
    if url.eq_ignore_ascii_case(super::credentials::KiroCredentials::PROXY_DIRECT) {
        return Err("内联代理不接受 \"direct\"，请改用 mode=direct".to_string());
    }
    validate_auth_pair(username, password)?;
    // 与池条目**同一套**严格规则（scheme 白名单之外还拒 userinfo / query /
    // fragment / 非根路径）。少拒一条 userinfo，新写入的内联代理就会把密码
    // 留在 `proxyUrl` 字段里（`redact_proxy_url` 只是展示脱敏，落盘的是原文），
    // 且与独立 username/password 字段叠加会变成对同一代理的双重认证。
    //
    // 加载期的旧内联配置不经过这里，继续沿用 reqwest 语义（F3 的分界不变）。
    validate_pool_url(url)?;
    let mut config = ProxyConfig::new(url);
    if let (Some(username), Some(password)) = (username, password) {
        config = config.with_auth(username, password);
    }
    Ok(config)
}

/// 池条目 id 的字符集与长度上限。
///
/// 管理端生成的 UUID 满足该规则。限制字符集是为了让 id 在 URL 路径里保持
/// 原样：`.`/`..`/空格/斜杠会被浏览器或路径解析改写，导致 UI 里无法再定位、
/// 编辑或删除该条目。加载期与提交边界共用这条规则，因此手改文件里的非法 id
/// 会在启动时 fail-fast。
const PROXY_ID_MAX_LEN: usize = 64;

pub fn validate_proxy_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("代理 id 不能为空".to_string());
    }
    if id.len() > PROXY_ID_MAX_LEN {
        return Err(format!(
            "代理 id 长度不能超过 {PROXY_ID_MAX_LEN} 个字符（当前 {}）",
            id.len()
        ));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("代理 id 只允许字母、数字、下划线与连字符".to_string());
    }
    Ok(())
}

/// 校验池条目：id 合法、URL 合法且认证字段成对。
pub fn validate_proxy_entry(entry: &ProxyEntry) -> Result<(), String> {
    validate_proxy_id(&entry.id)?;
    if entry.name.trim().is_empty() {
        return Err("代理名称不能为空".to_string());
    }
    validate_pool_url(&entry.url)?;
    validate_auth_pair(entry.username.as_deref(), entry.password.as_deref())
}

/// 认证字段必须成对出现，且用户名非空。
pub fn validate_auth_pair(username: Option<&str>, password: Option<&str>) -> Result<(), String> {
    match (username, password) {
        (None, None) => Ok(()),
        (Some(username), Some(_)) => {
            if username.is_empty() {
                return Err("代理用户名不能为空字符串".to_string());
            }
            Ok(())
        }
        _ => Err("代理用户名与密码必须同时提供".to_string()),
    }
}

/// 版本化封套：`{ version, proxies, credentials }`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsEnvelope {
    pub version: u32,
    #[serde(default)]
    pub proxies: Vec<ProxyEntry>,
    #[serde(default)]
    pub credentials: Vec<KiroCredentialsPayload>,
}

/// 封套里的凭据载荷即凭据本身，别名让封套定义自洽。
pub type KiroCredentialsPayload = super::credentials::KiroCredentials;

/// 凭据文件的原始形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsFileFormat {
    /// 单对象（旧格式，不回写）
    Single,
    /// 裸数组（旧格式，可回写）
    Array,
    /// 版本化封套
    Envelope,
}

/// 严格解析后的凭据文件。
#[derive(Debug, Clone)]
pub struct CredentialsFile {
    pub credentials: Vec<KiroCredentialsPayload>,
    pub proxies: Vec<ProxyEntry>,
    pub format: CredentialsFileFormat,
}

/// 按内容解析凭据文件文本。
///
/// - 顶层是含 `credentials` 键的对象 → 严格封套解析（未知版本/重复 ID/悬空或
///   冲突绑定一律拒绝）
/// - 顶层是数组 → 旧多凭据格式
/// - 顶层是其他对象 → 旧单对象格式
pub fn parse_credentials_file(content: &str) -> anyhow::Result<CredentialsFile> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    match &value {
        serde_json::Value::Array(_) => {
            let credentials: Vec<KiroCredentialsPayload> = serde_json::from_value(value)?;
            reject_legacy_pool_binding(&credentials)?;
            Ok(CredentialsFile {
                credentials,
                proxies: Vec::new(),
                format: CredentialsFileFormat::Array,
            })
        }
        serde_json::Value::Object(map) if map.contains_key("credentials") => {
            let envelope: CredentialsEnvelope = serde_json::from_value(value)?;
            if envelope.version != CREDENTIALS_ENVELOPE_VERSION {
                anyhow::bail!(
                    "不支持的凭据文件版本 {}（当前支持 {}）",
                    envelope.version,
                    CREDENTIALS_ENVELOPE_VERSION
                );
            }
            validate_document(&envelope.proxies, &envelope.credentials)?;
            Ok(CredentialsFile {
                credentials: envelope.credentials,
                proxies: envelope.proxies,
                format: CredentialsFileFormat::Envelope,
            })
        }
        serde_json::Value::Object(_) => {
            let credentials = vec![serde_json::from_value(value)?];
            reject_legacy_pool_binding(&credentials)?;
            Ok(CredentialsFile {
                credentials,
                proxies: Vec::new(),
                format: CredentialsFileFormat::Single,
            })
        }
        _ => anyhow::bail!("凭据文件顶层必须是对象或数组"),
    }
}

/// 旧数组/单对象格式没有代理池，任何 `proxyId` 都是悬空绑定。
///
/// 不在加载期拒绝的话，下一次落盘会把悬空 id 写进封套，再下次启动就起不来。
fn reject_legacy_pool_binding(credentials: &[KiroCredentialsPayload]) -> anyhow::Result<()> {
    for credential in credentials {
        if credential.proxy_id.is_some() {
            anyhow::bail!(
                "凭据 {:?} 引用了不存在的代理 {}（该文件格式没有代理池）",
                credential.id,
                credential.proxy_id.as_deref().unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// 加载期一致性校验：重复池 ID、悬空绑定、绑定与内联冲突。
pub fn validate_document(
    proxies: &[ProxyEntry],
    credentials: &[KiroCredentialsPayload],
) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for proxy in proxies {
        validate_proxy_entry(proxy)
            .map_err(|e| anyhow::anyhow!("代理 {} 配置无效: {}", proxy.id, e))?;
        if !seen.insert(proxy.id.as_str()) {
            anyhow::bail!("检测到重复的代理 ID: {}", proxy.id);
        }
    }
    for credential in credentials {
        let proxy_id = credential.proxy_id.as_deref().filter(|id| !id.is_empty());
        validate_credential_binding(credential)
            .map_err(|e| anyhow::anyhow!("凭据 {:?} 绑定无效: {}", credential.id, e))?;
        if let Some(id) = proxy_id
            && !seen.contains(id)
        {
            anyhow::bail!("凭据 {:?} 引用了不存在的代理 {}", credential.id, id);
        }
    }
    Ok(())
}

/// 决定落盘形态：只有真正用上代理池才写封套。
///
/// 池为空且没有任何 `proxyId` 时维持旧的裸数组，这样不用代理池的部署不会
/// 看到格式变化；删光池与绑定后自动回到数组，旧版本可直接回滚。
pub fn should_write_envelope(
    proxies: &[ProxyEntry],
    credentials: &[KiroCredentialsPayload],
) -> bool {
    !proxies.is_empty() || credentials.iter().any(|c| c.proxy_id.is_some())
}

/// 由凭据 + 池解析出网络路由标识。
///
/// `resolved_pool` 是池绑定的网络身份（悬空引用在加载/提交边界已拒绝）；
/// `global_proxy` 是 `config.proxyUrl`。`Inherit` 必须落到全局代理上——
/// 把它映射成 `System` 会让配置了全局代理的部署整条绕过代理（出口 IP 泄露）。
pub fn route_key_for(
    credential: &KiroCredentialsPayload,
    resolved_pool: Option<&ProxyConfig>,
    global_proxy: Option<&ProxyConfig>,
) -> RouteKey {
    match resolve_binding(
        credential.proxy_id.as_deref(),
        credential.proxy_url.as_deref(),
        credential.proxy_username.as_deref(),
        credential.proxy_password.as_deref(),
    ) {
        ProxyBinding::Direct => RouteKey::Direct,
        ProxyBinding::Inline(config) => RouteKey::Proxy(config),
        ProxyBinding::Pool(_) => match resolved_pool {
            Some(config) => RouteKey::Proxy(config.clone()),
            // 悬空引用不应出现在运行时（加载期已拒绝），保守回落到继承。
            None => inherit_route_key(global_proxy),
        },
        ProxyBinding::Inherit => inherit_route_key(global_proxy),
    }
}

/// 「继承」的网络身份：配置了全局代理就用它，否则是系统默认行为。
pub fn inherit_route_key(global_proxy: Option<&ProxyConfig>) -> RouteKey {
    match global_proxy {
        Some(proxy) => RouteKey::Global(proxy.clone()),
        None => RouteKey::System,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::model::credentials::KiroCredentials;

    fn entry(id: &str, url: &str) -> ProxyEntry {
        ProxyEntry {
            id: id.to_string(),
            name: id.to_string(),
            url: url.to_string(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn pool_url_accepts_supported_schemes_and_private_hosts() {
        for url in [
            "socks5://127.0.0.1:1080",
            "socks5h://proxy.internal:1080",
            "http://10.0.0.5:3128",
            "https://[::1]:8443",
        ] {
            assert!(validate_pool_url(url).is_ok(), "{url} 应被接受");
        }
    }

    #[test]
    fn pool_url_rejects_userinfo_query_fragment_and_path() {
        assert!(validate_pool_url("http://user:pass@host:3128").is_err());
        assert!(validate_pool_url("http://host:3128/?x=1").is_err());
        assert!(validate_pool_url("http://host:3128/#f").is_err());
        assert!(validate_pool_url("http://host:3128/path").is_err());
        assert!(validate_pool_url("ftp://host:21").is_err());
        assert!(validate_pool_url("").is_err());
    }

    #[test]
    fn binding_requires_exclusive_expression() {
        assert!(validate_binding_fields(Some("p1"), None, None, None).is_ok());
        assert!(validate_binding_fields(Some("p1"), Some("http://h:1"), None, None).is_err());
        assert!(validate_binding_fields(Some("p1"), None, Some("u"), None).is_err());
        assert!(validate_binding_fields(None, Some("direct"), None, None).is_ok());
    }

    #[test]
    fn resolve_binding_precedence() {
        assert_eq!(
            resolve_binding(None, None, None, None),
            ProxyBinding::Inherit
        );
        assert_eq!(
            resolve_binding(None, Some("DIRECT"), None, None),
            ProxyBinding::Direct
        );
        assert_eq!(
            resolve_binding(Some("p1"), None, None, None),
            ProxyBinding::Pool("p1".into())
        );
        assert_eq!(
            resolve_binding(None, Some("socks5://h:1"), Some("u"), Some("p")),
            ProxyBinding::Inline(ProxyConfig::new("socks5://h:1").with_auth("u", "p"))
        );
    }

    #[test]
    fn duplicate_proxy_ids_are_rejected() {
        let proxies = vec![entry("a", "socks5://h:1"), entry("a", "socks5://h:2")];
        assert!(validate_document(&proxies, &[]).is_err());
    }

    #[test]
    fn dangling_and_conflicting_bindings_are_rejected() {
        let proxies = vec![entry("a", "socks5://h:1")];
        let dangling = KiroCredentials {
            proxy_id: Some("missing".into()),
            ..Default::default()
        };
        assert!(validate_document(&proxies, &[dangling]).is_err());

        let conflicting = KiroCredentials {
            proxy_id: Some("a".into()),
            proxy_url: Some("socks5://other:1".into()),
            ..Default::default()
        };
        assert!(validate_document(&proxies, &[conflicting]).is_err());
    }

    #[test]
    fn parse_legacy_shapes_and_strict_envelope() {
        let array = parse_credentials_file(r#"[{"id":1,"priority":0}]"#).unwrap();
        assert_eq!(array.format, CredentialsFileFormat::Array);
        assert!(array.proxies.is_empty());

        let single = parse_credentials_file(r#"{"id":1,"priority":0}"#).unwrap();
        assert_eq!(single.format, CredentialsFileFormat::Single);

        let envelope = parse_credentials_file(
            r#"{"version":1,"proxies":[{"id":"a","name":"A","url":"socks5://h:1"}],
                "credentials":[{"id":2,"proxyId":"a"}]}"#,
        )
        .unwrap();
        assert_eq!(envelope.format, CredentialsFileFormat::Envelope);
        assert_eq!(envelope.proxies.len(), 1);

        assert!(
            parse_credentials_file(r#"{"version":2,"proxies":[],"credentials":[]}"#).is_err(),
            "未知版本必须拒绝"
        );
    }

    #[test]
    fn envelope_is_only_written_when_pool_is_used() {
        let cred = KiroCredentials::default();
        assert!(!should_write_envelope(&[], std::slice::from_ref(&cred)));
        let bound = KiroCredentials {
            proxy_id: Some("a".into()),
            ..Default::default()
        };
        assert!(should_write_envelope(&[], &[bound]));
        assert!(should_write_envelope(
            &[entry("a", "socks5://h:1")],
            &[cred]
        ));
    }

    #[test]
    fn route_key_excludes_pool_identity() {
        let cred = KiroCredentials {
            proxy_id: Some("a".into()),
            ..Default::default()
        };
        let pool = ProxyConfig::new("socks5://h:1");
        // 两个不同 id 的池条目只要网络身份相同，RouteKey 就必须相同——
        // 这是"改名/改 id 不重建 client"的结构性保证（P3）。
        let renamed = KiroCredentials {
            proxy_id: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(
            route_key_for(&cred, Some(&pool), None),
            route_key_for(&renamed, Some(&pool), None)
        );
    }

    /// J5：池条目 id 只允许 `[A-Za-z0-9_-]`，长度 1–64。
    ///
    /// 非法 id 会经 `encodeURIComponent` 原样进入 URL 路径，`.`/`..`/空格/斜杠
    /// 在浏览器或路径解析中被改写，条目就再也定位不到。
    ///
    /// 反事实：把 `validate_proxy_entry` 的 id 判断改回 `trim().is_empty()`，
    /// 下面所有 `is_err` 断言变红。
    #[test]
    fn proxy_id_charset_and_length_are_enforced() {
        for id in [".", "..", " p1", "p1 ", "a/b", "a\\b", "a:b", "代理", ""] {
            assert!(
                validate_proxy_id(id).is_err(),
                "id {id:?} 必须被拒绝（URL 路径不安全）"
            );
            let mut invalid = entry("ok", "socks5://h:1");
            invalid.id = id.to_string();
            assert!(validate_proxy_entry(&invalid).is_err(), "id {id:?}");
        }
        assert!(validate_proxy_id(&"a".repeat(65)).is_err(), "65 位必须拒绝");
        for id in ["p1", "P_1-2", &"a".repeat(64), "2b7e1516-28ae-11e6"] {
            assert!(validate_proxy_id(id).is_ok(), "id {id:?} 应被接受");
        }
        let uuid = uuid::Uuid::new_v4().to_string();
        assert!(
            validate_proxy_id(&uuid).is_ok(),
            "服务端生成的 UUID 必须合法"
        );
    }

    /// J9：旧数组/单对象格式没有代理池，任何 `proxyId` 都是悬空绑定。
    ///
    /// 不拒绝的话，下一次落盘会写出带悬空 id 的封套，再下次启动即 fail-fast。
    ///
    /// 反事实：去掉 `reject_legacy_pool_binding` 调用，下面两条变红。
    #[test]
    fn legacy_shapes_reject_any_proxy_id() {
        let array = parse_credentials_file(r#"[{"id":1,"priority":0,"proxyId":"p1"}]"#)
            .expect_err("数组格式出现 proxyId 必须拒绝");
        assert!(array.to_string().contains("p1"), "{array}");
        assert!(
            array.to_string().contains('1'),
            "错误必须带凭据标识: {array}"
        );

        let single = parse_credentials_file(r#"{"id":7,"priority":0,"proxyId":"p1"}"#)
            .expect_err("单对象格式出现 proxyId 必须拒绝");
        assert!(single.to_string().contains('7'), "{single}");

        let empty_id = parse_credentials_file(r#"[{"id":1,"priority":0,"proxyId":""}]"#)
            .expect_err("空串 proxyId 同样是悬空绑定");
        assert!(empty_id.to_string().contains("不存在的代理"), "{empty_id}");

        // 不带 proxyId 的旧文件仍然加载成功（不制造兼容性回归）。
        assert!(parse_credentials_file(r#"[{"id":1,"priority":0}]"#).is_ok());
        assert!(parse_credentials_file(r#"{"id":1,"priority":0}"#).is_ok());
    }

    /// J4：新表达的内联代理与 `PUT /credentials/{id}/proxy` 走同一个校验函数。
    ///
    /// 反事实：让 `apply_binding_fields` 绕开这个函数，`direct` 与半套认证会被放行。
    #[test]
    fn inline_binding_validation_is_shared() {
        assert!(
            inline_proxy_config("direct", None, None).is_err(),
            "direct 必须拒绝"
        );
        assert!(
            inline_proxy_config("DIRECT", None, None).is_err(),
            "direct 判定不区分大小写"
        );
        assert!(
            inline_proxy_config("  ", None, None).is_err(),
            "空 URL 必须拒绝"
        );
        assert!(
            inline_proxy_config("socks5://h:1", Some("u"), None).is_err(),
            "只有用户名没有密码必须拒绝"
        );
        assert!(
            inline_proxy_config("socks5://h:1", None, Some("p")).is_err(),
            "只有密码没有用户名必须拒绝"
        );
        let config = inline_proxy_config("socks5h://h:1", Some("u"), Some("p")).expect("成对认证");
        assert_eq!(config.username.as_deref(), Some("u"));
        assert_eq!(config.password.as_deref(), Some("p"));
    }

    /// 新写入的内联代理必须与池条目**同一套**严格 URL 规则。
    ///
    /// 缺陷形态：内联只查 scheme + 认证成对，于是
    /// `http://user:pass@host:port` 能进 `proxyUrl` 字段——密码
    /// 原文落盘，且与独立 username/password 同时存在时对代理做双重认证。
    ///
    /// 前置条件断言：同一组输入在 `validate_pool_url` 上确实被拒（证明比较的
    /// 是"两处结论一致"，而不是"两处都无脑放行/拒绝"）。
    ///
    /// 反事实（已现场验证）：把 `inline_proxy_config` 的校验换回
    /// `validate_proxy_scheme`，本条在 userinfo 用例处红（返回 Ok）。
    #[test]
    fn inline_proxy_url_rules_match_pool_rules() {
        let rejected = [
            "http://user:pass@host:3128",
            "http://user@host:3128",
            "http://host:3128/?x=1",
            "http://host:3128/#f",
            "http://host:3128/path",
            "ftp://host:21",
            "127.0.0.1:7890",
            " http://host:3128",
        ];
        for url in rejected {
            assert!(
                validate_pool_url(url).is_err(),
                "前置条件：池规则必须拒绝 {url}"
            );
            assert!(
                inline_proxy_config(url, None, None).is_err(),
                "内联必须与池同一结论，{url} 应被拒绝"
            );
        }
        let accepted = [
            "socks5://127.0.0.1:1080",
            "socks5h://proxy.internal:1080",
            "http://10.0.0.5:3128",
            "https://[::1]:8443",
        ];
        for url in accepted {
            assert!(validate_pool_url(url).is_ok(), "前置条件：池接受 {url}");
            assert!(
                inline_proxy_config(url, None, None).is_ok(),
                "内联必须与池同一结论，{url} 应被接受"
            );
        }
    }

    /// J1：新增路径与加载路径共用同一份绑定互斥规则。
    #[test]
    fn new_credential_binding_rule_matches_load_rule() {
        let conflicting = KiroCredentials {
            id: Some(9),
            proxy_id: Some("p1".into()),
            proxy_url: Some("socks5://h:1".into()),
            ..Default::default()
        };
        assert!(validate_credential_binding(&conflicting).is_err());
        assert!(validate_document(&[], std::slice::from_ref(&conflicting)).is_err());
        let username_only = KiroCredentials {
            proxy_id: Some("p1".into()),
            proxy_username: Some("u".into()),
            ..Default::default()
        };
        assert!(validate_credential_binding(&username_only).is_err());
        let password_only = KiroCredentials {
            proxy_id: Some("p1".into()),
            proxy_password: Some("p".into()),
            ..Default::default()
        };
        assert!(validate_credential_binding(&password_only).is_err());
        assert!(
            validate_credential_binding(&KiroCredentials {
                proxy_id: Some("p1".into()),
                ..Default::default()
            })
            .is_ok()
        );
    }

    /// 「继承」必须落到全局代理上；没有全局代理时才是系统默认行为。
    ///
    /// 反事实：把 `Inherit` 直接映射成 `RouteKey::System`（本次修复前的实现），
    /// 下面第一条断言变红——那正是"全局代理对所有凭据失效"的形态。
    #[test]
    fn inherit_binding_uses_configured_global_proxy() {
        let inherit = KiroCredentials::default();
        let global = ProxyConfig::new("http://global.example:3128");

        assert_eq!(
            route_key_for(&inherit, None, Some(&global)),
            RouteKey::Global(global.clone()),
            "配置了全局代理时，继承凭据必须走全局代理"
        );
        assert_eq!(
            route_key_for(&inherit, None, None),
            RouteKey::System,
            "未配置全局代理时，继承仍是系统默认行为"
        );
        // 直连与内联不受全局代理影响。
        let direct = KiroCredentials {
            proxy_url: Some("direct".into()),
            ..Default::default()
        };
        assert_eq!(
            route_key_for(&direct, None, Some(&global)),
            RouteKey::Direct
        );
        let inline = KiroCredentials {
            proxy_url: Some("socks5://own:1080".into()),
            ..Default::default()
        };
        assert_eq!(
            route_key_for(&inline, None, Some(&global)),
            RouteKey::Proxy(ProxyConfig::new("socks5://own:1080"))
        );
    }
}
