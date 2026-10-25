//! HTTP Client 构建模块
//!
//! 提供统一的 HTTP Client 构建功能，支持代理配置和两种超时模式：
//! - `build_client`：全局总超时（适合短请求 / MCP / WebSearch）
//! - `build_idle_client`：idle/read 超时 + connect 超时（适合业务长流式响应）

use reqwest::{Client, ClientBuilder, Proxy};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::model::config::TlsBackend;

/// 业务长响应的 idle/read 超时（秒）。
///
/// 设为 930s，略大于 ALB 默认 idle timeout 900s，
/// 让 ALB 先断开连接，消除等值竞态——我们超时比 ALB 晚一步，
/// 避免上游健康慢流被我方误杀。
pub const UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 930;

/// TCP 连接超时（秒）。
///
/// 覆盖建连阶段，防止 DNS/网络不可达时无限挂起。
/// 对 idle client 必须单独设置，因为它不设全局 `.timeout()`。
pub const CONNECT_TIMEOUT_SECS: u64 = 30;

/// 代理配置
///
/// `Debug` 手工实现而非派生：`password` 绝不能经 `{:?}` 进日志/错误链
/// （凭据在管理端提交、启动日志与上游错误信息里都会经过这些路径）。
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    /// 代理地址，支持 http/https/socks5/socks5h
    pub url: String,
    /// 代理认证用户名
    pub username: Option<String>,
    /// 代理认证密码
    pub password: Option<String>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("url", &redact_proxy_url(&self.url))
            // 用户名同样是认证材料的另一半（不少代理把口令塞在用户名段，
            // 或用户名本身可反推内网账号），`{:?}` 会经日志/错误链外泄。
            .field("has_username", &self.username.is_some())
            .field("has_password", &self.password.is_some())
            .finish()
    }
}

/// 无法安全脱敏时的固定占位：绝不拼接原文的任何片段。
pub const INVALID_PROXY_URL_PLACEHOLDER: &str = "<invalid proxy url>";

/// 把 URL 里的 userinfo 与敏感查询串抹掉，供日志/响应/Debug 使用。
///
/// 旧格式允许 `http://user:pass@host:port` 这种内联凭据，任何透出都必须脱敏。
///
/// 只有"能确定这不是秘密载体"时才输出内容：
/// - 解析失败 → 占位符；
/// - scheme 不在代理白名单 → 占位符（`admin:s3cret@10.0.0.1:1080` 会被
///   `Url::parse` 当成 scheme = `admin`、userinfo 为空的合法 URL，原样输出就泄密）；
/// - 没有主机名 → 占位符。
///
/// 特殊值 `direct` 不是 URL，由各调用方在调用本函数之前自行处理。
pub fn redact_proxy_url(url: &str) -> String {
    let Ok(mut redacted) = reqwest::Url::parse(url) else {
        return INVALID_PROXY_URL_PLACEHOLDER.to_string();
    };
    if !SUPPORTED_PROXY_SCHEMES.contains(&redacted.scheme()) || redacted.host_str().is_none() {
        return INVALID_PROXY_URL_PLACEHOLDER.to_string();
    }
    if !redacted.username().is_empty() || redacted.password().is_some() {
        let _ = redacted.set_username("");
        let _ = redacted.set_password(None);
    }
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

/// 测试观测点：`Route` 构建次数（按 `RouteKey`）。
///
/// thread-local，因为 `cargo test` 的用例并行跑在不同线程上；每个用例自己
/// `reset()` 后读自己的计数，不会互相污染。生产构建里整段不存在。
#[cfg(test)]
pub mod route_build_counter {
    use super::RouteKey;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    thread_local! {
        static COUNTS: RefCell<HashMap<RouteKey, usize>> = RefCell::new(HashMap::new());
        /// 当前线程是否处在管理写的 `credentials_save_lock` 临界区内。
        ///
        /// 管理写事务的临界区是**同步**的（无 `.await`、无跨线程移交），所以
        /// thread-local 就足够：`Route::build` 若在里面发生，一定记在同一线程上。
        static IN_SAVE_LOCK: Cell<bool> = const { Cell::new(false) };
        static BUILDS_IN_SAVE_LOCK: Cell<usize> = const { Cell::new(0) };
    }

    pub fn record(key: &RouteKey) {
        COUNTS.with(|counts| {
            *counts.borrow_mut().entry(key.clone()).or_insert(0) += 1;
        });
        if IN_SAVE_LOCK.with(Cell::get) {
            BUILDS_IN_SAVE_LOCK.with(|count| count.set(count.get() + 1));
        }
    }

    /// 某个 key 被构建的次数。
    pub fn count(key: &RouteKey) -> usize {
        COUNTS.with(|counts| counts.borrow().get(key).copied().unwrap_or(0))
    }

    /// 清空当前线程的计数。
    pub fn reset() {
        COUNTS.with(|counts| counts.borrow_mut().clear());
        BUILDS_IN_SAVE_LOCK.with(|count| count.set(0));
    }

    /// 管理写临界区守卫：进入时把本线程标记为「持 save lock」。
    ///
    /// 退出（含 panic 展开）时恢复。用于 F1 的观测点：`update_proxy` / `bind`
    /// 在锁内构建 route 会立刻被记到 [`builds_in_save_lock`] 上。
    pub struct SaveLockScope(());

    impl SaveLockScope {
        pub fn enter() -> Self {
            let previous = IN_SAVE_LOCK.with(|flag| flag.replace(true));
            debug_assert!(!previous, "save lock 临界区不得嵌套（guard 唯一）");
            Self(())
        }
    }

    impl Drop for SaveLockScope {
        fn drop(&mut self) {
            IN_SAVE_LOCK.with(|flag| flag.set(false));
        }
    }

    /// 当前线程在 save lock 临界区内发生的 `Route` 构建次数。
    pub fn builds_in_save_lock() -> usize {
        BUILDS_IN_SAVE_LOCK.with(Cell::get)
    }
}

/// 测试观测点：每个 `(RouteKey, client 角色)` 实际应用了哪些 reqwest 选项。
///
/// 记录点**就在施加该选项的那一行旁边**（`apply_proxy` / `apply_no_proxy` /
/// `apply_h2_keepalive`），不是另写一份与 builder 平行的声明——否则记录与实际
/// 会分叉，断言就恒绿了（P2 的旧测试正是这么失效的）。
///
/// thread-local，与 [`route_build_counter`] 同一隔离方式：`cargo test` 的用例
/// 跑在不同线程上，各自读自己的记录。生产构建里整段不存在。
#[cfg(test)]
pub mod route_option_log {
    use super::{ClientRole, RouteKey};
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// 某个 client 实际被施加的代理/保活选项。
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct AppliedOptions {
        /// 显式 `/ 继承了代理`（`builder.proxy(..)`）
        pub proxy: bool,
        /// 显式直连（`builder.no_proxy()`）
        pub no_proxy: bool,
        /// H2 keep-alive 三件套（interval + timeout + while_idle）
        pub keepalive: bool,
    }

    thread_local! {
        static OPTIONS: RefCell<HashMap<(RouteKey, ClientRole), AppliedOptions>> =
            RefCell::new(HashMap::new());
    }

    pub(super) fn record(
        key: &RouteKey,
        role: ClientRole,
        mutate: impl FnOnce(&mut AppliedOptions),
    ) {
        OPTIONS.with(|options| {
            mutate(options.borrow_mut().entry((key.clone(), role)).or_default());
        });
    }

    /// 某路由某个 client 实际应用到的选项；从未构建过则为 `None`。
    pub fn options(key: &RouteKey, role: ClientRole) -> Option<AppliedOptions> {
        OPTIONS.with(|options| options.borrow().get(&(key.clone(), role)).copied())
    }

    pub fn reset() {
        OPTIONS.with(|options| options.borrow_mut().clear());
    }
}

/// 一对 client 里的哪一个：idle = 业务长响应，short = 短请求。
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientRole {
    Idle,
    Short,
}

/// 「这是哪个路由的哪种 client」的**测试期作用域**。
///
/// 生产构建里这个模块整段不存在——三个 `apply_*` helper 在这种情况下不接受
/// 作用域参数，因此不留零尺寸参数、不留永假分支、不留 `let _ = ()` 之类噪音。
/// 测试构建里它是 thread-local：`Route::build_with` 在构建前 `enter()`，三个
/// helper 在施加选项的那一行旁边 `record_*()`，构建结束 `exit()`。
/// thread-local 与 [`route_build_counter`] 同一隔离方式（用例各跑各的线程）。
#[cfg(test)]
mod build_scope {
    use super::{ClientRole, RouteKey};
    use std::cell::RefCell;

    thread_local! {
        static CURRENT: RefCell<Option<(RouteKey, ClientRole)>> = const { RefCell::new(None) };
    }

    /// 进入某个路由某个 client 的构建作用域，并登记一条**全 false** 的空记录。
    ///
    /// 空记录本身就是断言对象：System / Global 这类"不施加任何代理专属选项"
    /// 的分支，正是靠这条默认值来证明"没有多设什么"。若只依赖 `apply_*` 里的
    /// 记录，System 会根本没有条目、断言只能退化成 `None`——那测不出"多加了
    /// 一个 no_proxy"这类回归。
    pub(super) fn enter(scope: (RouteKey, ClientRole)) {
        let (key, role) = scope.clone();
        CURRENT.with(|current| *current.borrow_mut() = Some(scope));
        crate::http_client::route_option_log::record(&key, role, |_| {});
    }

    pub(super) fn exit() {
        CURRENT.with(|current| *current.borrow_mut() = None);
    }

    pub(super) fn with_current(mutate: impl FnOnce(&RouteKey, ClientRole)) {
        CURRENT.with(|current| {
            if let Some((key, role)) = current.borrow().as_ref() {
                mutate(key, *role);
            }
        });
    }
}

/// 施加显式代理（含可选 basic auth）。记录点在 `.proxy(..)` 之后同一段代码内。
fn apply_proxy(mut builder: ClientBuilder, config: &ProxyConfig) -> anyhow::Result<ClientBuilder> {
    let mut proxy = Proxy::all(&config.url)?;

    // 设置代理认证
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        proxy = proxy.basic_auth(username, password);
    }

    builder = builder.proxy(proxy);
    tracing::debug!(
        proxy_url = %redact_proxy_url(&config.url),
        "HTTP Client 使用代理"
    );
    #[cfg(test)]
    build_scope::with_current(|key, role| {
        crate::http_client::route_option_log::record(key, role, |options| options.proxy = true);
    });
    Ok(builder)
}

/// 施加显式直连。记录点在 `no_proxy()` 之后同一段代码内。
fn apply_no_proxy(mut builder: ClientBuilder) -> ClientBuilder {
    builder = builder.no_proxy();
    #[cfg(test)]
    build_scope::with_current(|key, role| {
        crate::http_client::route_option_log::record(key, role, |options| options.no_proxy = true);
    });
    builder
}

/// 施加代理专属的 H2 keep-alive 三件套。记录点在三个 setter 之后同一段代码内。
///
/// 生产路径下 `http2_keep_alive_while_idle` 恒为 `true`——它是 P7 的承重点，
/// 不是可选项。
fn apply_h2_keepalive(
    mut builder: ClientBuilder,
    interval: Duration,
    timeout: Duration,
) -> ClientBuilder {
    builder = builder
        .http2_keep_alive_interval(interval)
        .http2_keep_alive_timeout(timeout)
        .http2_keep_alive_while_idle(true);
    #[cfg(test)]
    build_scope::with_current(|key, role| {
        crate::http_client::route_option_log::record(key, role, |options| options.keepalive = true);
    });
    builder
}

/// 一次请求走哪条网络路径。
///
/// 只承载**网络身份**：池条目的 id/name 不进这里，因此给代理改名不会改变
/// key、不会新建 client（P3）。代理专属的 keep-alive 只作用于 `Proxy`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteKey {
    /// 未配置全局代理时的「继承」：系统默认行为（含环境变量代理）
    System,
    /// 已配置全局 `config.proxyUrl` 时的「继承」。
    ///
    /// 必须与改动前 `build_client(Some(proxy), ..)` / `build_idle_client(Some(proxy), ..)`
    /// 逐项一致：显式使用该代理、**不带**代理专属 keep-alive、不调用 `no_proxy()`。
    /// 与 `Proxy` 刻意不合并：同一个 URL 作全局代理与作池代理是两种 client 参数，
    /// 网络身份虽同、client 语义不同。
    Global(ProxyConfig),
    /// 显式直连，即使进程环境里配了代理
    Direct,
    /// 指定的代理
    Proxy(ProxyConfig),
}

/// 代理路由的 HTTP/2 keep-alive：先于 reqwest 默认 90s 空闲回收探测，
/// 把被静默掐断的隧道在一次往返内剔除（P7）。PING 由 H2 层应答，
/// 与上游生成快慢无关，不会误杀慢而健康的长流。
const PROXY_H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const PROXY_H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// 随凭据常驻的一对 client。构造后不可变，靠 `Arc` 计数回收。
///
/// 每个请求只做一次 `Arc::clone`——不取锁、不建 client、不碰磁盘（P1）。
pub struct Route {
    key: RouteKey,
    /// 业务长响应（流式/非流式 generate）
    pub idle: Client,
    /// 短请求（MCP/WebSearch/OAuth/profile/usage）
    pub short: Client,
}

impl Route {
    /// 按 key 构建一对 client。
    ///
    /// 直连/系统路由的参数与改动前逐字相同；只有代理路由叠加 keep-alive（P2）。
    pub fn build(key: RouteKey, tls_backend: TlsBackend) -> anyhow::Result<Arc<Self>> {
        Self::build_with(key, tls_backend, false, None)
    }

    /// 测试专用：在完全相同的选项集合上，额外打开 h2c prior-knowledge / 覆盖
    /// keep-alive 间隔。本地夹具只能用明文 H2 观测连接复用与 PING 剔除——
    /// 生产路径（`build`）不受影响，两者共用同一段构建代码。
    #[cfg(test)]
    pub fn build_for_test(
        key: RouteKey,
        tls_backend: TlsBackend,
        h2_prior_knowledge: bool,
        keepalive: Option<(Duration, Duration)>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::build_with(key, tls_backend, h2_prior_knowledge, keepalive)
    }

    fn build_with(
        key: RouteKey,
        tls_backend: TlsBackend,
        h2_prior_knowledge: bool,
        keepalive: Option<(Duration, Duration)>,
    ) -> anyhow::Result<Arc<Self>> {
        #[cfg(test)]
        route_build_counter::record(&key);
        // 构建期**不做** scheme 白名单校验（F3）：这是改动前的语义。
        //
        // 分界的原因：
        // - `Global` 与「加载期读到的旧内联配置」是**既有配置**，必须与改动前
        //   逐字一致。reqwest 的 `IntoProxy` 会接受无 scheme 的 `host:port`
        //   （补 `http://` 重试）以及 `socks4`/`socks4a`；在这里拦白名单会让
        //   这些一直可用的部署在升级后启动失败，属破坏性回归。
        // - 而**新写入**的配置（新建/编辑池条目、新增凭据的内联输入）由各自
        //   的写边界严格校验（`validate_pool_url` / `validate_proxy_scheme`），
        //   那里的 URL 由 UI 构造、格式确定，收紧是对的。
        // 校验放在写边界而不是构建边界的另一个好处：`Route::build` 也服务启动
        // 加载路径，两种输入的合法性口径不同，不能共用同一道闸。
        // 每个分支的选项集合与 `git show master:src/http_client.rs` 的
        // `build_client` / `build_idle_client` 对应分支逐项一致：
        // - System  = `build_*client(None, ..)`        → 无 proxy / 无 no_proxy / 无 keep-alive
        // - Global  = `build_*client(Some(proxy), ..)` → 有 proxy / 无 no_proxy / 无 keep-alive
        // - Direct  = 本次新增的显式直连               → 有 no_proxy / 无 proxy / 无 keep-alive
        // - Proxy   = 本次新增的池代理                 → 有 proxy / 无 no_proxy / 有 keep-alive
        // 该对照由 `bdd_route_options_match_legacy_builders` 逐项锁死（P2）。
        let idle = {
            #[cfg(test)]
            build_scope::enter((key.clone(), ClientRole::Idle));
            let client = match &key {
                RouteKey::System => {
                    build_idle_client(None, UPSTREAM_IDLE_TIMEOUT_SECS, tls_backend)?
                }
                RouteKey::Global(proxy) => {
                    build_idle_client(Some(proxy), UPSTREAM_IDLE_TIMEOUT_SECS, tls_backend)?
                }
                RouteKey::Direct => build_direct_client(
                    Duration::from_secs(UPSTREAM_IDLE_TIMEOUT_SECS),
                    true,
                    tls_backend,
                )?,
                RouteKey::Proxy(proxy) => build_proxied_client(
                    proxy,
                    Duration::from_secs(UPSTREAM_IDLE_TIMEOUT_SECS),
                    true,
                    tls_backend,
                    h2_prior_knowledge,
                    keepalive,
                )?,
            };
            #[cfg(test)]
            build_scope::exit();
            client
        };
        let short = {
            #[cfg(test)]
            build_scope::enter((key.clone(), ClientRole::Short));
            let client = match &key {
                RouteKey::System => build_client(None, SHORT_REQUEST_TIMEOUT_SECS, tls_backend)?,
                RouteKey::Global(proxy) => {
                    build_client(Some(proxy), SHORT_REQUEST_TIMEOUT_SECS, tls_backend)?
                }
                RouteKey::Direct => build_direct_client(
                    Duration::from_secs(SHORT_REQUEST_TIMEOUT_SECS),
                    false,
                    tls_backend,
                )?,
                RouteKey::Proxy(proxy) => build_proxied_client(
                    proxy,
                    Duration::from_secs(SHORT_REQUEST_TIMEOUT_SECS),
                    false,
                    tls_backend,
                    h2_prior_knowledge,
                    keepalive,
                )?,
            };
            #[cfg(test)]
            build_scope::exit();
            client
        };
        Ok(Arc::new(Self { key, idle, short }))
    }

    /// 该路由的网络身份。生产路径不读它（凭据条目自己持有路由指针），
    /// 只有测试断言与排障日志用得上。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn key(&self) -> &RouteKey {
        &self.key
    }

    /// 该路由是否真的经代理出站（用于日志与测试断言）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_proxied(&self) -> bool {
        matches!(self.key, RouteKey::Proxy(_) | RouteKey::Global(_))
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// 短请求总超时（秒），与改动前 `client_for(Short)` 的取值一致。
pub const SHORT_REQUEST_TIMEOUT_SECS: u64 = 720;

/// 支持的代理协议（**新写入路径**的白名单）。
///
/// `Proxy::all` 本身不拒绝 ftp 这类 scheme（要到发请求时才失败），因此新配置
/// 的写边界必须显式校验，让"配置无效"在管理端提交时就暴露。
///
/// 这道校验**不**用在 `Route::build` 上：那里还要服务既有部署的全局代理与旧
/// 内联配置，口径必须与改动前一致（见 `Route::build_with` 的注释，F3）。
const SUPPORTED_PROXY_SCHEMES: [&str; 4] = ["http", "https", "socks5", "socks5h"];

/// 新写入代理 URL 的 scheme 白名单校验（管理端提交边界）。
pub fn validate_proxy_scheme(url: &str) -> anyhow::Result<()> {
    let parsed =
        reqwest::Url::parse(url).map_err(|error| anyhow::anyhow!("代理 URL 无法解析: {error}"))?;
    if !SUPPORTED_PROXY_SCHEMES.contains(&parsed.scheme()) {
        anyhow::bail!(
            "不支持的代理协议 \"{}\"，只允许 http/https/socks5/socks5h",
            parsed.scheme()
        );
    }
    Ok(())
}

impl ProxyConfig {
    /// 从 url 创建代理配置
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
        }
    }

    /// 设置认证信息
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
}

/// 内部 helper：装配代理与 TLS，返回 `ClientBuilder`。
///
/// 两类 client（短请求总超时 / 业务 idle 超时）共用此基础配置，
/// 调用方在其上叠加各自超时策略。
///
/// # 参数
/// * `proxy` - 可选代理配置
/// * `tls_backend` - TLS 后端选择
///
/// # 返回
/// 配置了代理与 TLS 的 `ClientBuilder`，尚未添加超时
fn base_builder(
    proxy: Option<&ProxyConfig>,
    tls_backend: TlsBackend,
) -> anyhow::Result<ClientBuilder> {
    let builder = apply_tls(Client::builder(), tls_backend)?;

    if let Some(proxy_config) = proxy {
        return apply_proxy(builder, proxy_config);
    }

    Ok(builder)
}

fn apply_tls(mut builder: ClientBuilder, tls_backend: TlsBackend) -> anyhow::Result<ClientBuilder> {
    match tls_backend {
        TlsBackend::Rustls => {
            builder = builder.use_rustls_tls();
        }
        TlsBackend::NativeTls => {
            #[cfg(feature = "native-tls")]
            {
                builder = builder.use_native_tls();
            }
            #[cfg(not(feature = "native-tls"))]
            {
                anyhow::bail!("此构建版本未包含 native-tls 后端，请在配置中改用 rustls");
            }
        }
    }
    Ok(builder)
}

/// 显式直连：`no_proxy()` 覆盖环境变量里的代理。
///
/// `total_timeout` 为 `Some` 时是短请求语义（全局总超时），`None` 时是业务
/// idle 语义（read + connect 超时、无总死线），与 `build_client` /
/// `build_idle_client` 的口径逐项对应。
fn build_direct_client(
    total_timeout: Duration,
    idle_semantics: bool,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    // 顺序与改动前逐字等价：先 `no_proxy()` 再套 TLS（`apply_tls` 不改代理）。
    let builder = apply_no_proxy(Client::builder());
    let builder = apply_tls(builder, tls_backend)?;
    let builder = if idle_semantics {
        builder
            .read_timeout(total_timeout)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
    } else {
        builder.timeout(total_timeout)
    };
    Ok(builder.build()?)
}

/// 代理路由的 client：与直连/系统口径相同，另加 H2 keep-alive。
///
/// 显式设置 `Proxy::all` 后 reqwest 自动停用系统代理，因此这里不需要 `no_proxy()`。
fn build_proxied_client(
    proxy: &ProxyConfig,
    total_timeout: Duration,
    idle_semantics: bool,
    tls_backend: TlsBackend,
    h2_prior_knowledge: bool,
    keepalive: Option<(Duration, Duration)>,
) -> anyhow::Result<Client> {
    let (interval, timeout) =
        keepalive.unwrap_or((PROXY_H2_KEEPALIVE_INTERVAL, PROXY_H2_KEEPALIVE_TIMEOUT));
    let builder = apply_proxy(Client::builder(), proxy)?;
    let builder = apply_tls(builder, tls_backend)?;
    let mut builder = apply_h2_keepalive(builder, interval, timeout);
    if h2_prior_knowledge {
        builder = builder.http2_prior_knowledge();
    }
    let builder = if idle_semantics {
        builder
            .read_timeout(total_timeout)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
    } else {
        builder.timeout(total_timeout)
    };
    Ok(builder.build()?)
}

/// 构建短请求 HTTP Client（全局总超时）。
///
/// 适合 MCP、WebSearch、OAuth 等短请求，设置全局总超时死线，
/// 防止 Slowloris 及上游挂起。
///
/// # 参数
/// * `proxy` - 可选代理配置
/// * `timeout_secs` - 全局总超时（秒），覆盖"连接+读完整 body"
/// * `tls_backend` - TLS 后端选择
///
/// # 返回
/// 配置好的 `reqwest::Client`
pub fn build_client(
    proxy: Option<&ProxyConfig>,
    timeout_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    Ok(base_builder(proxy, tls_backend)?
        .timeout(Duration::from_secs(timeout_secs))
        .build()?)
}

/// 构建业务长响应 HTTP Client（idle/read 超时 + connect 超时，无全局总超时）。
///
/// 适合 `generateAssistantResponse` 流式与非流式长响应。
/// 使用 idle/read 超时替代全局总超时，避免"慢但健康的长流"被误杀：
/// - `read_timeout`：每次成功读字节后重置，只要上游持续吐字节就不触发
/// - `connect_timeout`：覆盖建连阶段，替代被去掉的全局 `.timeout()` 的建连保护
///
/// 实际值：idle=930s（>ALB idle=900，让 ALB 先兜底断连），connect=30s。
///
/// # 参数
/// * `proxy` - 可选代理配置
/// * `idle_secs` - idle/read 超时（秒），建议传 `UPSTREAM_IDLE_TIMEOUT_SECS`
/// * `tls_backend` - TLS 后端选择
///
/// # 返回
/// 配置好的 `reqwest::Client`
pub fn build_idle_client(
    proxy: Option<&ProxyConfig>,
    idle_secs: u64,
    tls_backend: TlsBackend,
) -> anyhow::Result<Client> {
    Ok(base_builder(proxy, tls_backend)?
        .read_timeout(Duration::from_secs(idle_secs))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .build()?)
}

/// 将 `reqwest::Error` 解析为结构化诊断字符串，用于上游断连根因定位。
///
/// 背景：reqwest 在 body 读阶段的超时/重置会被无差别包成 `Kind::Decode`，
/// Display 恒为 "error decoding response body"，真实错因藏在 source chain。
/// 故 kind 判定必须先判 `is_timeout()`（reqwest issue #2839），否则超时会被误判为 decode。
///
/// # 参数
/// * `err` - reqwest 请求/响应过程中产生的错误
///
/// # 返回
/// 形如 `kind=timeout; display=...; source_chain=A -> B -> C` 的诊断串，
/// 便于从单行日志区分"我方 idle 超时 / 上游 reset / 真截断"
pub fn describe_reqwest_error(err: &reqwest::Error) -> String {
    // kind 判定顺序：先 timeout（#2839 硬要求），再 connect/body/decode/request
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else if err.is_body() {
        "body"
    } else if err.is_decode() {
        "decode"
    } else if err.is_request() {
        "request"
    } else {
        "other"
    };

    // walk source chain，逐层拼接 Display
    let mut chain: Vec<String> = Vec::new();
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        chain.push(inner.to_string());
        source = inner.source();
    }
    let chain_str = if chain.is_empty() {
        "<none>".to_string()
    } else {
        chain.join(" -> ")
    };

    format!("kind={}; display={}; source_chain={}", kind, err, chain_str)
}

/// 判定 reqwest 错误是否为瞬态（可重试）。
///
/// #64：上游 HTTP/2 层瞬态中断（RST_STREAM / `unexpected internal error`）或 body
/// 中途断连时，reqwest 在 `.bytes()`/`.bytes_stream()` 路径下统一 `map_err(decode)`，
/// 故 `is_decode()==true` 而 `is_body()==false`（Step 0 docker 实测坐实）。这类失败
/// 应被判为瞬态，让客户端感知失败并重试，而非被伪装成正常完成。
///
/// 判定顺序：先 `is_timeout()`（其内部已 walk source chain，覆盖被包进 decode 的
/// 超时，reqwest issue #2839），再 connect，最后传输层中断（decode/body）。
///
/// ⚠️ 仅用于原始字节读取分支（`.bytes()`/`.bytes_stream()`）——`is_decode()` 也覆盖
/// JSON 反序列化失败，禁止挪用到 `.json()` 失败分支（否则会把上游返回的格式错误
/// JSON 误判为瞬态而错误地诱导客户端无限重试）。
pub fn is_transient(err: &reqwest::Error) -> bool {
    if err.is_timeout() {
        return true; // 已 walk source chain，覆盖被包进 decode 的超时
    }
    if err.is_connect() {
        return true;
    }
    if err.is_decode() || err.is_body() {
        return true; // 非超时传输层中断（RST/FIN/reset）
    }
    false // is_request()/其他 = 构造/配置错误，非瞬态
}

#[cfg(test)]
mod tests {
    use super::*;

    /// J8：无法安全脱敏的旧值一律输出固定占位，绝不拼接原文片段。
    ///
    /// 事故形态：`admin:s3cret@10.0.0.1:1080` 被 `Url::parse` 当成
    /// scheme = `admin`、userinfo 为空的合法 URL，原样输出就泄密。
    ///
    /// 反事实：还原"解析失败只保留 scheme"的实现，前四条断言变红
    /// （`admin:s3cret@...` 返回原串、`pass@host` 返回 `pass@host` 变形）。
    #[test]
    fn redact_never_leaks_unparsable_or_non_proxy_values() {
        for leaky in [
            "admin:s3cret@10.0.0.1:1080",
            "pass@host",
            "user:pass@host:1080",
            "ftp://u:p@h:1",
            "socks5://",
            "http://",
        ] {
            let output = redact_proxy_url(leaky);
            assert_eq!(
                output, INVALID_PROXY_URL_PLACEHOLDER,
                "{leaky} 必须退化为固定占位"
            );
            assert!(!output.contains("s3cret"), "{leaky}");
            assert!(!output.contains("pass"), "{leaky}");
        }
    }

    /// 合法 URL 保持现有脱敏：去掉 userinfo、query、fragment，输出规范形态。
    #[test]
    fn redact_strips_userinfo_for_valid_proxy_urls() {
        assert_eq!(
            redact_proxy_url("http://u:p@h:1"),
            "http://h:1/",
            "userinfo 必须去掉"
        );
        assert_eq!(
            redact_proxy_url("socks5h://u:p@proxy.example:1080/?token=abc#frag"),
            "socks5h://proxy.example:1080/",
            "query 与 fragment 必须去掉"
        );
        assert_eq!(
            redact_proxy_url("http://proxy.example:3128"),
            "http://proxy.example:3128/",
            "无认证的地址保持可读"
        );
    }

    /// `ProxyConfig` 的 Debug 复用同一个脱敏函数：不可解析的值同样不得泄漏。
    #[test]
    fn proxy_config_debug_never_leaks() {
        let config = ProxyConfig::new("admin:s3cret@10.0.0.1:1080");
        let debug = format!("{config:?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(debug.contains(INVALID_PROXY_URL_PLACEHOLDER), "{debug}");
    }

    // ─────────────────────────────────────────────────────────────────
    // Mock 上游 helper
    // ─────────────────────────────────────────────────────────────────

    /// 启动一个 chunked HTTP/1.1 流式 mock 上游。
    ///
    /// 行为：accept 一个连接 → 丢弃请求头（读一次 buf 即可）→ 发 SSE 响应头
    /// → 每隔 `interval_ms` 毫秒发一个 chunked payload（`data: tick\n\n`）
    /// → 共 `chunk_count` 个 → 发终止帧 `0\r\n\r\n` 正常结束流。
    ///
    /// 返回 mock server 的 `SocketAddr`（端口由 OS 随机分配）。
    async fn spawn_dribbling_upstream(
        chunk_count: usize,
        interval_ms: u64,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");

            // 读掉客户端请求头（不做完整 HTTP 解析，读一次 buf 足够）
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            // 发 SSE 响应头
            let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");

            // 按 interval_ms 间隔发 chunk_count 个 chunked 帧
            let payload = b"data: tick\n\n";
            let chunk_header = format!("{:x}\r\n", payload.len());
            for _ in 0..chunk_count {
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
                stream
                    .write_all(chunk_header.as_bytes())
                    .await
                    .expect("写 chunk header 失败");
                stream
                    .write_all(payload)
                    .await
                    .expect("写 chunk payload 失败");
                stream.write_all(b"\r\n").await.expect("写 chunk CRLF 失败");
            }

            // 发终止帧，流正常结束
            stream.write_all(b"0\r\n\r\n").await.expect("写终止帧失败");
        });

        addr
    }

    /// 启动一个「假死」mock 上游。
    ///
    /// 行为：accept 一个连接 → 发响应头 + 1 个 chunk → 挂起 30s（不发终止帧、不关连接）。
    /// 用于坐实 idle 超时能正确检测上游静止场景。
    async fn spawn_hanging_upstream() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");

            // 读掉客户端请求头
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            // 发响应头
            let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");

            // 发 1 个 chunk，然后故意挂死 30s（模拟上游静止）
            let payload = b"data: first\n\n";
            let chunk_header = format!("{:x}\r\n", payload.len());
            stream
                .write_all(chunk_header.as_bytes())
                .await
                .expect("写 chunk header 失败");
            stream
                .write_all(payload)
                .await
                .expect("写 chunk payload 失败");
            stream.write_all(b"\r\n").await.expect("写 chunk CRLF 失败");

            // 挂死 30s，不发终止帧——触发 client 的 idle 超时
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        });

        addr
    }

    // ─────────────────────────────────────────────────────────────────
    // 黑盒坐实测试（#ignore 含 sleep，不进常规快测）
    // ─────────────────────────────────────────────────────────────────

    /// 坐实根因：全局 total 超时会误杀「慢但持续吐字节的健康长流」。
    ///
    /// mock 上游每 400ms 发一个 chunk，共 5 个（约 2s 才发完）；
    /// client 设 total=1s——上游一直在吐字节，但 total 超时不重置，
    /// 必然在 ~1s 时炸掉，即便流没有任何真实问题。
    #[ignore]
    #[tokio::test]
    async fn blackbox_idle_total_kills_healthy_long_stream() {
        use futures::StreamExt;

        // mock：每 400ms 发一个 chunk，共 5 个（≈2s 完成）
        let addr = spawn_dribbling_upstream(5, 400).await;

        // 旧策略：全局 total = 1s
        let client = build_client(None, 1, TlsBackend::Rustls).expect("构建 client 失败");

        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 时超时，而非 send 阶段）");

        let mut stream = resp.bytes_stream();
        let mut got_err: Option<reqwest::Error> = None;

        // 循环读 stream，预期在 total=1s 触发后收到 Err
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(_) => {}
                Err(e) => {
                    got_err = Some(e);
                    break;
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis();

        // 必须拿到 Err：total 超时撞线
        let err = got_err.expect("total=1s 应触发超时 Err，但流正常结束——断言失败");
        let desc = describe_reqwest_error(&err);

        println!("[A] total=1s client 在 {elapsed_ms}ms 后被杀；desc={desc}");

        // 超时必须在合理窗口内（0.5~3s），kind 必须为 timeout
        assert!(
            elapsed_ms >= 500 && elapsed_ms <= 3000,
            "超时耗时 {elapsed_ms}ms 不在预期窗口 [500, 3000]ms"
        );
        assert!(
            desc.contains("kind=timeout"),
            "期望 kind=timeout，实际：{desc}"
        );
    }

    /// 坐实修复：idle 超时不会杀「慢但持续吐字节的健康长流」。
    ///
    /// mock 上游与测试 A 完全相同（每 400ms 一个 chunk，共 5 个）；
    /// 唯一变量是 client 策略改为 idle=1s。
    /// 每 400ms < 1s idle，每次收到字节后 idle 计时器重置，永不触发——
    /// 流应完整读完、无任何 Err。
    #[ignore]
    #[tokio::test]
    async fn blackbox_idle_survives_healthy_long_stream() {
        use futures::StreamExt;

        // mock 与 A 完全相同：每 400ms 一个 chunk，共 5 个
        let addr = spawn_dribbling_upstream(5, 400).await;

        // 新策略：idle = 1s（每次收到字节后重置，400ms < 1s，永不触发）
        let client = build_idle_client(None, 1, TlsBackend::Rustls).expect("构建 client 失败");

        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");

        let mut stream = resp.bytes_stream();
        let mut total_bytes: usize = 0;

        // 循环读到 None（流正常结束），累计字节数
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => total_bytes += bytes.len(),
                Err(e) => {
                    panic!(
                        "idle=1s 不应触发超时，但收到 Err：{}",
                        describe_reqwest_error(&e)
                    );
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis();

        println!("[B] idle=1s client 完整读完 {total_bytes} 字节、耗时 {elapsed_ms}ms、无超时");

        // 流必须正常结束，累计字节数 > 0
        assert!(total_bytes > 0, "累计字节数为 0，mock 未发任何数据");
        // 总耗时应在 ~2s 附近（5 个 chunk × 400ms），放宽窗口 [1.5s, 5s]
        assert!(
            elapsed_ms >= 1500 && elapsed_ms <= 5000,
            "总耗时 {elapsed_ms}ms 不在预期窗口 [1500, 5000]ms"
        );
    }

    /// 坐实诊断：上游真实挂起（idle 静止）时，idle 超时触发 kind=timeout。
    ///
    /// mock 上游发 1 个 chunk 后挂死 30s；client idle=1s。
    /// 约 1s 后上游无字节到达，idle 超时触发——必须收到 Err 且 kind=timeout。
    ///
    /// 注：reqwest issue #2839——body 读阶段超时被包成 Kind::Decode，
    /// 但 `is_timeout()` 仍返回 true，故 describe_reqwest_error 先判 is_timeout()，
    /// 可正确分类为 kind=timeout 而非 kind=decode。
    #[ignore]
    #[tokio::test]
    async fn blackbox_idle_hang_classified_as_timeout() {
        use futures::StreamExt;

        // mock：发 1 个 chunk 后挂死 30s
        let addr = spawn_hanging_upstream().await;

        // idle=1s：上游挂死时约 1s 后触发
        let client = build_idle_client(None, 1, TlsBackend::Rustls).expect("构建 client 失败");

        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");

        let mut stream = resp.bytes_stream();
        let mut got_err: Option<reqwest::Error> = None;

        // 循环读 stream，预期在 idle=1s 触发后收到 Err
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(_) => {}
                Err(e) => {
                    got_err = Some(e);
                    break;
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis();

        // 必须拿到 Err
        let err = got_err.expect("idle=1s 上游挂死应触发 Err，但流正常结束——断言失败");
        let desc = describe_reqwest_error(&err);

        // 打印完整 desc（含 source_chain），让 reviewer 确认 timed out 字样
        println!("[C] idle=1s client 挂起 {elapsed_ms}ms 后超时；desc={desc}");

        // 超时必须在合理窗口内（0.5~3s）
        assert!(
            elapsed_ms >= 500 && elapsed_ms <= 3000,
            "idle 超时耗时 {elapsed_ms}ms 不在预期窗口 [500, 3000]ms"
        );
        // kind 必须为 timeout（#2839：is_timeout() 先于 is_decode() 判定）
        assert!(
            desc.contains("kind=timeout"),
            "期望 kind=timeout，实际：{desc}"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // [#64 诊断专用] Step 0 黑盒实验：H2 RST / body 中途断连 与
    // 「read timeout 被包成 decode」的错误分类坐实。
    //
    // 目的：#64 生产报错 source_chain 含
    // "stream error received: unexpected internal error encountered"
    // （H2 INTERNAL_ERROR / RST_STREAM），reqwest 无差别包装，真因藏在
    // source chain。本组测试用 mock 上游在 HTTP/1.1 层近似「响应头已发、
    // body 中途异常终止」与「body 中途挂起触发 read timeout」两种场景，
    // 实测 is_*() 与 describe_reqwest_error 的真实分类落点，为
    // is_transient 判定逻辑提供实测依据（而非凭 reqwest 文档推断）。
    // 诊断价值持续，保留为常备诊断测试（同 blackbox_* 系列先例）。
    // ─────────────────────────────────────────────────────────────────

    /// 启动一个「响应头已发、body 中途异常终止连接」的 mock 上游。
    ///
    /// 行为：accept 连接 → 丢弃请求头 → 发 200 响应头（chunked）
    /// → 发一个**不完整**的 chunked 帧（chunk-size 声明 100 字节，
    /// 实际只发 10 字节 payload，不发完整 payload、不发终止帧 `0\r\n\r\n`）
    /// → `force_rst=true` 时对 socket 设置 `SO_LINGER(0)` 后 drop，
    /// 触发 TCP RST（近似 H2 RST_STREAM / INTERNAL_ERROR 对连接的冲断效果）；
    /// `force_rst=false` 时直接 drop，触发正常 FIN（body 读到一半遇 EOF，
    /// 无完整 chunk 边界，触发 h1 framing 错误）。
    ///
    /// 两种断连方式都是「header 已到、body 中途断」的近似，用于对照
    /// RST 和 FIN 两种传输层终止方式是否在 reqwest 分类上有差异。
    async fn spawn_mid_body_reset_upstream(force_rst: bool) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");

            // 读掉客户端请求头
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            // 发 200 响应头（chunked，非 SSE，纯粹测试 body 读取本身）
            let headers =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");

            // chunk-size 声明 0x64=100 字节，但只发 10 字节 payload——
            // 声明值与实际值不符，body 读到一半必炸（不完整 chunk 帧）
            stream
                .write_all(b"64\r\n")
                .await
                .expect("写 chunk header 失败");
            stream
                .write_all(b"partial...")
                .await
                .expect("写不完整 payload 失败");

            if force_rst {
                // SO_LINGER(0)：drop 时 OS 发 RST 而非优雅 FIN，
                // 近似 H2 层 RST_STREAM / INTERNAL_ERROR 的冲断效果
                let _ = stream.set_linger(Some(std::time::Duration::ZERO));
            }
            // 不发终止帧、不发完整 payload，直接 drop 连接
            drop(stream);
        });

        addr
    }

    /// [#64 诊断] 任务1：H2 RST / body 中途断连的错误分类落点。
    ///
    /// 对 `force_rst=false`（FIN）与 `force_rst=true`（RST）两种断连方式，
    /// 用 `.bytes()`（对齐 `handle_non_stream_request` 的实际读取方式）
    /// 触发失败，打印 is_*() 真值表与完整 `describe_reqwest_error` 输出。
    #[ignore]
    #[tokio::test]
    async fn diag_issue64_mid_body_abrupt_close_classification() {
        for force_rst in [false, true] {
            let addr = spawn_mid_body_reset_upstream(force_rst).await;
            let client = build_idle_client(None, 30, TlsBackend::Rustls).expect("构建 client 失败");

            let resp = client
                .get(format!("http://{addr}"))
                .send()
                .await
                .expect("send 失败（预期在读 body 阶段失败，而非 send 阶段）");

            let result = resp.bytes().await;
            let err = result.expect_err(&format!(
                "force_rst={force_rst}：预期 body 读取失败（中途断连），但读取成功"
            ));
            let desc = describe_reqwest_error(&err);

            println!(
                "[T1 force_rst={force_rst}] is_timeout={} is_connect={} is_body={} is_decode={} is_request={} | {desc}",
                err.is_timeout(),
                err.is_connect(),
                err.is_body(),
                err.is_decode(),
                err.is_request(),
            );
        }
    }

    /// 启动一个「200 但立即空 body」的 mock 上游（用于 #64 任务3 S4 旁证）。
    ///
    /// 行为：accept 连接 → 丢弃请求头 → 发 200 响应头（chunked）
    /// → 立即发终止帧 `0\r\n\r\n`（不发任何 payload chunk）→ 正常结束连接。
    /// 用于验证「上游 200 + 空 body」在 reqwest 层是否表现为 Ok(空字节)
    /// 而非 Err——即这类情况不会被 describe_reqwest_error 分类捕获，
    /// 而是会正常进入业务层 EventStreamDecoder。
    async fn spawn_empty_body_200_upstream() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock server bind 失败");
        let addr = listener.local_addr().expect("获取 mock server 地址失败");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept 失败");
            let mut req_buf = vec![0u8; 4096];
            let _ = stream.read(&mut req_buf).await;

            let headers =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(headers).await.expect("写响应头失败");
            // 立即发终止帧，不发任何 payload——空 body 但连接正常结束
            stream.write_all(b"0\r\n\r\n").await.expect("写终止帧失败");
        });

        addr
    }

    /// [#64 诊断] 任务3旁证：上游「200 但空 body」在 reqwest 层的表现。
    ///
    /// 核心问题：这类响应是 `Err`（会被 describe_reqwest_error 分类）还是
    /// `Ok(空字节)`（会静默流入业务层 EventStreamDecoder，decode_iter 空
    /// 迭代，最终产出 content=[] 的「正常」200 响应，无任何错误日志）？
    #[ignore]
    #[tokio::test]
    async fn diag_issue64_empty_body_200_is_ok_not_err() {
        let addr = spawn_empty_body_200_upstream().await;
        let client = build_idle_client(None, 30, TlsBackend::Rustls).expect("构建 client 失败");

        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");
        let status = resp.status();
        let result = resp.bytes().await;

        match &result {
            Ok(bytes) => println!(
                "[T3] status={status} .bytes() 返回 Ok，长度={}（预期 0，即空 body 不是 Err）",
                bytes.len()
            ),
            Err(e) => println!(
                "[T3] status={status} .bytes() 返回 Err：{}",
                describe_reqwest_error(e)
            ),
        }

        // 核心断言：空 body 是 Ok(空字节)，不是 Err——不会被 describe_reqwest_error 捕获
        let bytes = result.expect("预期空 body 是 Ok(空字节) 而非 Err");
        assert_eq!(bytes.len(), 0, "预期空 body 长度为 0");
    }

    /// [#64 诊断] 任务2：验证「read timeout 被包成 decode」陷阱。
    ///
    /// 复用 `spawn_hanging_upstream`（发 1 chunk 后挂起 30s），client
    /// 设短 `read_timeout=1s`。用 `.bytes()`（对齐生产非流式读取路径）
    /// 触发超时，核心验证：`is_decode()==true` 且 `is_timeout()` 是否
    /// 仍能通过 walk source chain 正确识别为 true（而非被 decode 掩盖）。
    #[ignore]
    #[tokio::test]
    async fn diag_issue64_read_timeout_hides_in_decode() {
        let addr = spawn_hanging_upstream().await;
        let client = build_idle_client(None, 1, TlsBackend::Rustls).expect("构建 client 失败");

        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");

        let start = std::time::Instant::now();
        let result = resp.bytes().await;
        let elapsed_ms = start.elapsed().as_millis();

        let err = result.expect_err("read_timeout=1s 应触发 body 读取失败，但读取成功");
        let desc = describe_reqwest_error(&err);

        println!(
            "[T2] 耗时{elapsed_ms}ms is_timeout={} is_connect={} is_body={} is_decode={} is_request={} | {desc}",
            err.is_timeout(),
            err.is_connect(),
            err.is_body(),
            err.is_decode(),
            err.is_request(),
        );

        // 核心断言：验证「陷阱」确实存在——is_decode 为 true 的同时，
        // is_timeout 必须仍能通过 walk source chain 识别为 true
        assert!(
            err.is_decode(),
            "预期 is_decode()==true（.bytes() 外层恒包 Decode），实际 desc={desc}"
        );
        assert!(
            err.is_timeout(),
            "陷阱验证失败：is_timeout() 应为 true（walk source chain 找到 TimedOut），实际 desc={desc}"
        );
    }

    #[test]
    fn test_proxy_config_new() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        assert_eq!(config.url, "http://127.0.0.1:7890");
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_proxy_config_with_auth() {
        let config = ProxyConfig::new("socks5://127.0.0.1:1080").with_auth("user", "pass");
        assert_eq!(config.url, "socks5://127.0.0.1:1080");
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    #[test]
    fn test_build_client_without_proxy() {
        let client = build_client(None, 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_with_proxy() {
        let config = ProxyConfig::new("http://127.0.0.1:7890");
        let client = build_client(Some(&config), 30, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_idle_client_without_proxy() {
        let client = build_idle_client(None, UPSTREAM_IDLE_TIMEOUT_SECS, TlsBackend::Rustls);
        assert!(client.is_ok());
    }

    /// 测试 describe_reqwest_error 对 connect 类错误的分类。
    ///
    /// reqwest::Error 无公开构造器，只能用真实请求拿到 error。为稳定产生 connect
    /// 类错误（ECONNREFUSED）而非偶发超时：绑定 `127.0.0.1:0` 让 OS 分配一个空闲
    /// 端口，随即释放监听——该端口短期内无人占用，连接必被立即拒绝。client 显式设
    /// 短 connect_timeout，避免极端环境（如防火墙 DROP）下连接挂起拖死测试。
    #[tokio::test]
    async fn test_describe_reqwest_error_connect_kind() {
        // 绑定临时端口后立即释放，得到一个确定无人监听的本地地址
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定临时端口失败");
        let addr = listener.local_addr().expect("获取本地地址失败");
        drop(listener);

        // 显式短 connect_timeout，确保即便连接不被立即拒绝也不会挂死
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("构建测试 client 失败");
        let err = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect_err("预期连接被拒绝，但请求意外成功");

        let desc = describe_reqwest_error(&err);

        // 核心断言：connect 类错误必须被分类为 kind=connect
        assert!(
            desc.contains("kind=connect"),
            "期望 kind=connect，实际诊断串：{desc}"
        );
        // 诊断串必须包含 display= 和 source_chain= 字段（格式完整性）
        assert!(
            desc.contains("display="),
            "诊断串缺少 display= 字段：{desc}"
        );
        assert!(
            desc.contains("source_chain="),
            "诊断串缺少 source_chain= 字段：{desc}"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // #64 BDD S3 — is_transient 真值表单元测试
    //
    // 复用本文件已有的 mock 上游 helper（均无 sleep，快速确定性）与
    // test_describe_reqwest_error_connect_kind 的 bind-then-drop 模式，
    // 拿到真实 reqwest::Error 实例后断言 is_transient 分类结果。
    // 这些测试常规运行（不带 #[ignore]），区别于上方仅供人工诊断的
    // diag_issue64_* / blackbox_* 系列。
    // ─────────────────────────────────────────────────────────────────

    /// is_transient 对 connect 类错误（ECONNREFUSED）应判定为 true。
    #[tokio::test]
    async fn test_is_transient_true_for_connect_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定临时端口失败");
        let addr = listener.local_addr().expect("获取本地地址失败");
        drop(listener);

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("构建测试 client 失败");
        let err = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect_err("预期连接被拒绝，但请求意外成功");

        assert!(err.is_connect(), "前提：应先证实是 connect 类错误");
        assert!(is_transient(&err), "connect 类错误应判定为瞬态（可重试）");
    }

    /// is_transient 对 body 中途以 FIN 断连（无完整 chunk 边界）应判定为 true。
    ///
    /// 复用 #64 诊断用 spawn_mid_body_reset_upstream(false)：声明 100 字节
    /// chunk 实际只发 10 字节后直接 drop（正常 FIN，非 RST）。
    #[tokio::test]
    async fn test_is_transient_true_for_mid_body_reset_fin() {
        let addr = spawn_mid_body_reset_upstream(false).await;
        let client = build_idle_client(None, 30, TlsBackend::Rustls).expect("构建 client 失败");

        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败，而非 send 阶段）");
        let err = resp
            .bytes()
            .await
            .expect_err("预期 body 读取失败（中途断连），但读取成功");

        assert!(
            is_transient(&err),
            "body 中途 FIN 断连应判定为瞬态；desc={}",
            describe_reqwest_error(&err)
        );
    }

    /// is_transient 对 body 中途以 TCP RST 断连应判定为 true。
    ///
    /// 复用 spawn_mid_body_reset_upstream(true)：SO_LINGER(0) 后 drop，
    /// 近似 H2 RST_STREAM/INTERNAL_ERROR 对连接的冲断效果。
    #[tokio::test]
    async fn test_is_transient_true_for_mid_body_reset_rst() {
        let addr = spawn_mid_body_reset_upstream(true).await;
        let client = build_idle_client(None, 30, TlsBackend::Rustls).expect("构建 client 失败");

        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败（预期在读 body 阶段失败，而非 send 阶段）");
        let err = resp
            .bytes()
            .await
            .expect_err("预期 body 读取失败（中途断连），但读取成功");

        assert!(
            is_transient(&err),
            "body 中途 RST 断连应判定为瞬态；desc={}",
            describe_reqwest_error(&err)
        );
    }

    /// is_transient 对 read timeout（#2839 陷阱：外层包成 Decode）仍应判定为 true。
    ///
    /// 复用 spawn_hanging_upstream（发 1 chunk 后挂起 30s），client 侧设短
    /// read_timeout（500ms）主动触发超时——不等待 mock 上游的 30s，测试本身
    /// 在 ~500ms 内完成，快速确定性。核心验证 is_timeout() 通过 walk source
    /// chain 正确识别，不被 is_decode()==true 掩盖（判定顺序已在 is_transient
    /// 内先判 is_timeout）。
    #[tokio::test]
    async fn test_is_transient_true_for_read_timeout() {
        let addr = spawn_hanging_upstream().await;
        // build_idle_client 不暴露自定义短超时的入口，直接用 ClientBuilder
        // 构造一个等价配置但 read_timeout 短至 500ms 的 client，避免测试等待 30s。
        let client = reqwest::Client::builder()
            .read_timeout(std::time::Duration::from_millis(500))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("构建短超时测试 client 失败");

        let resp = client
            .get(format!("http://{addr}"))
            .send()
            .await
            .expect("send 失败");
        let err = resp
            .bytes()
            .await
            .expect_err("read_timeout=500ms 应触发 body 读取失败，但读取成功");

        assert!(
            is_transient(&err),
            "read timeout 应判定为瞬态（即便被包成 decode）；desc={}",
            describe_reqwest_error(&err)
        );
    }

    /// is_transient 对 builder 类错误（非法 URL scheme，同步失败无网络 I/O）应判定为 false。
    ///
    /// 复用 reqwest 自身测试 `execute_request_rejects_invalid_urls` 的构造方式
    /// （故意拼错的 "hxxps://" scheme）：`execute_request` 在发起任何网络 I/O 之前
    /// 就同步校验 scheme，是 Kind::Builder 错误，非瞬态（构造/配置类问题，重试无意义）。
    #[tokio::test]
    async fn test_is_transient_false_for_builder_error() {
        let client = reqwest::Client::new();
        let err = client
            .get("hxxps://example.invalid/")
            .send()
            .await
            .expect_err("非法 scheme 应同步返回 builder 错误");

        assert!(err.is_builder(), "前提：应先证实是 builder 类错误");
        assert!(
            !is_transient(&err),
            "builder/配置类错误不应判定为瞬态（重试无意义）"
        );
    }
}
