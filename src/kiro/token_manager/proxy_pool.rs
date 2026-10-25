//! 代理池运行期：路由注册表、绑定发布与管理端写事务。
//!
//! 设计要点（对应计划的 P1–P7）：
//! - 路由挂在凭据条目上（`CredentialEntry.route`），请求路径只做一次 `Arc::clone`；
//!   本模块只出现在启动、管理提交与后台刷新路径上。
//! - 注册表按 [`RouteKey`] 去重，池条目的 id/name 不参与 key，因此改名不重建。
//! - 发布只改绑定字段与 route 指针，绝不重建 `CredentialEntry`——刷新锁、失败计数、
//!   在途计数等运行时状态必须原样保留。
//!
//! # 锁序契约（本模块唯一权威）
//!
//! `credentials_save_lock → entries → pool`。三条规则把它变成可检查的机械约束：
//!
//! 1. **能不嵌套就不嵌套**：能在一把锁下拷出数据、释放、再取下一把，就不嵌套。
//!    嵌套只允许严格按上述顺序**向内**取，且离开前全部释放。
//! 2. `entries` 与 `pool` 锁**绝不跨 `.await` 或磁盘 I/O**。
//! 3. 落盘（`write_document`）在释放 `entries`/`pool` 之后、仅在 save lock 之内进行。
//!
//! 本模块不存在任何"先 pool 后 entries"的取锁路径：`list_proxies` / `prune_routes`
//! 用两份互不重叠的独立快照（各自取锁释放），写事务在 save lock 内按
//! entries → pool 单向取锁。因此不会与 `snapshot()` / `persist_credentials()`
//! 构成 ABBA 倒置。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::*;
use crate::http_client::{Route, RouteKey};
use crate::model::config::TlsBackend;

/// 绑定提交的测试闸门：绑定方报告"已到达"后等待一次放行。
///
/// 与 `Barrier` 的区别是单向——测试方只放行、不参与配对，因此可以精确地
/// 在"锁外校验完成、持锁复核之前"插入一次并发编辑而不死锁。
///
/// # 为什么不是 `Notify::notify_one` + 裸 `Semaphore`
///
/// 旧形态是「绑定方 `arrived.notify_one()`，测试方 `notified().await`」。
/// `Notify` 最多**保存一个**许可：多次 bind 并发到达时，第二个及以后的
/// `notify_one` 在无等待者时互相覆盖，测试方随后只能被唤醒一次——
/// 剩下的 bind 永远不会被放行，表现为用例挂死而不是断言失败。
///
/// 现在的形态与 `ProxyStats::wait_tunnel_closed` 同构：**先登记条件再唤醒**
/// （到达计数 `fetch_add` 之后 `notify_waiters`），等待方先 `notified()` 再
/// 复查计数，因此唤醒不会丢失，且允许多次到达排队。
#[cfg(test)]
pub(crate) struct BindGate {
    /// 累计到达次数。这是"条件"，不是提示信号。
    arrivals: std::sync::atomic::AtomicUsize,
    /// 每次到达都唤醒全部等待者。`notify_waiters` 不保存许可，所以判定必须
    /// 依赖上面的计数复查，而不是"收到一次通知就等于一次到达"。
    arrived: tokio::sync::Notify,
    /// 放行许可：测试每放行一次加一个。
    release: tokio::sync::Semaphore,
}

#[cfg(test)]
impl BindGate {
    pub(crate) fn new() -> Self {
        Self {
            arrivals: std::sync::atomic::AtomicUsize::new(0),
            arrived: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        }
    }

    /// 绑定方调用：登记一次到达，然后等待一次放行。
    pub(crate) async fn arrive_and_wait(&self) {
        self.arrivals
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.arrived.notify_waiters();
        self.release
            .acquire()
            .await
            .expect("BindGate 的 Semaphore 从不 close")
            .forget();
    }

    /// 累计到达次数。
    pub(crate) fn arrival_count(&self) -> usize {
        self.arrivals.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 等待累计到达次数达到 `target`（先建 `notified()` 再复查，不会丢失唤醒）。
    pub(crate) async fn wait_arrivals(&self, target: usize) {
        loop {
            let notified = self.arrived.notified();
            if self.arrival_count() >= target {
                return;
            }
            notified.await;
        }
    }

    /// 测试方：等待第 1 次到达，然后放行一次。
    pub(crate) async fn wait_arrival_and_release(&self) {
        self.wait_arrivals(1).await;
        self.release.add_permits(1);
    }

    /// 测试方：放行一次（用于需要先等到全部到达、再逐次放行的压力用例）。
    pub(crate) fn release_one_for_test(&self) {
        self.release.add_permits(1);
    }
}

/// 管理写事务的测试闸门：写入方在"锁外预建完成、取 save lock 之前"报告到达
/// 并等待放行。用于确定性构造管理写交错时序，不靠 sleep。
#[cfg(test)]
pub(crate) struct AdminWriteGate {
    pub(crate) arrived: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Semaphore,
}

#[cfg(test)]
impl AdminWriteGate {
    pub(crate) fn new() -> Self {
        Self {
            arrived: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        }
    }

    /// 测试方：等待写入方到达，然后放行。
    pub(crate) async fn wait_arrival_and_release(&self) {
        self.arrived.notified().await;
        self.release.add_permits(1);
    }
}

/// 管理写事务的**写盘**闸门：`write_document` 在真正调用原子写之前报告到达并
/// 阻塞，直到测试放行。用于把事务卡在"已经持有 save lock、entries/proxies 都已
/// 释放、正在写盘"这个精确状态上（P6 的观测点）。
///
/// 阻塞而非 `await`：`write_document` 处在持有 `parking_lot` save lock 的同步
/// 临界区内（实际写经 `block_in_place`），不能用异步原语等待。到达通知用
/// `notify_one`（带许可），因此测试方即使晚于写入方开始等待也不会丢唤醒。
#[cfg(test)]
pub(crate) struct PoolWriteGate {
    pub(crate) entered: tokio::sync::Notify,
    allow: parking_lot::Mutex<std::sync::mpsc::Receiver<()>>,
    /// 写入方在闸门处观测到的锁状态：`entries` / `pool` 两把锁此刻是否可获取。
    /// `None` = 尚未观测；`Some((entries_free, pool_free))` = 已观测。
    observed_locks: parking_lot::Mutex<Option<(bool, bool)>>,
}

/// 路由回收的**非阻塞**观测点（F7）。
///
/// `prune_routes` 跑在写事务的同步临界区（持 `parking_lot` save lock）里，
/// 在这里阻塞会占住 worker 线程：断言失败或测试超时后卡住的等待永不返回，
/// 进程表现为挂死而不是失败。所以这里只记录状态、从不等候。
///
/// 记录的是每次回收执行时 `credentials_save_lock` 是否空闲：
/// `false` = 由调用方持有（修复后应有的形态），`true` = 锁外执行（F7 的缺陷形态）。
#[cfg(test)]
#[derive(Default)]
pub(crate) struct PruneObserver {
    save_free_observations: parking_lot::Mutex<Vec<bool>>,
}

#[cfg(test)]
impl PruneObserver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, save_free: bool) {
        self.save_free_observations.lock().push(save_free);
    }

    /// 一次回收都没记录时为 `None`；否则返回全部观测（按发生顺序）。
    pub(crate) fn observations(&self) -> Option<Vec<bool>> {
        let observed = self.save_free_observations.lock();
        (!observed.is_empty()).then(|| observed.clone())
    }
}

#[cfg(test)]
impl PoolWriteGate {
    /// 返回闸门与放行端；每收到一次放行信号，放行一次写盘。
    pub(crate) fn new() -> (Arc<Self>, std::sync::mpsc::SyncSender<()>) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        (
            Arc::new(Self {
                entered: tokio::sync::Notify::new(),
                allow: parking_lot::Mutex::new(receiver),
                observed_locks: parking_lot::Mutex::new(None),
            }),
            sender,
        )
    }

    /// 写入方调用：在闸门处记录 `entries` / `pool` 两把锁是否可获取。
    ///
    /// 这是「落盘前 entries 已释放」的直接证据——若落盘发生在 entries 临界区内，
    /// 这里观测到的 `entries_free` 就是 `false`。
    pub(crate) fn observe_locks(&self, entries_free: bool, pool_free: bool) {
        *self.observed_locks.lock() = Some((entries_free, pool_free));
    }

    /// 测试方：取写入方在闸门处观测到的锁状态。
    pub(crate) fn observed_locks(&self) -> Option<(bool, bool)> {
        *self.observed_locks.lock()
    }

    /// 写入方调用：报告已到达写盘边界，并阻塞到测试放行。
    pub(crate) fn arrive_and_wait(&self) {
        self.entered.notify_one();
        let _ = self.allow.lock().recv();
    }

    /// 测试方：等写入方到达写盘边界（`notify_one` 带许可，不丢唤醒）。
    pub(crate) async fn wait_arrival(&self) {
        self.entered.notified().await;
    }
}

pub(super) struct PoolState {
    pub(super) proxies: Vec<ProxyEntry>,
    routes: HashMap<RouteKey, Arc<Route>>,
}

impl PoolState {
    pub(super) fn new(proxies: Vec<ProxyEntry>) -> Self {
        Self {
            proxies,
            routes: HashMap::new(),
        }
    }

    /// 注册表查找（不构建）。调用方须持有 pool 锁。
    pub(super) fn probe(&self, key: &RouteKey) -> Option<Arc<Route>> {
        self.routes.get(key).cloned()
    }

    /// 把已构建的 route 发布进注册表；同 key 已存在时保留既有实例并返回它。
    ///
    /// 幂等性是 P3 的结构保证：同一网络身份永远只有一个 client，不会因为
    /// 并发提交出现两份连接池。
    fn publish(&mut self, key: RouteKey, route: Arc<Route>) -> Arc<Route> {
        self.routes.entry(key).or_insert(route).clone()
    }

    /// 取（必要时构建）某个 key 的路由。
    ///
    /// 会**在持锁状态下构建 client**（加载 TLS 根证书），因此只允许两条路径调用：
    /// 启动期预建，以及管理提交里"并发编辑让网络身份在锁外预建之后又变了"的
    /// 罕见锁内重建。正常提交路径用 `route_get_or_build`（锁外）。
    pub(super) fn route(&mut self, key: &RouteKey, tls: TlsBackend) -> anyhow::Result<Arc<Route>> {
        if let Some(existing) = self.routes.get(key) {
            return Ok(existing.clone());
        }
        let route = Route::build(key.clone(), tls)?;
        self.routes.insert(key.clone(), route.clone());
        Ok(route)
    }

    /// 用当前活引用集合回收不再被引用的路由。
    ///
    /// 在途请求持有旧 `Arc`，回收只影响新请求；没有容量上限，所以不会
    /// 出现"一账号一代理"被淘汰后冷启动（P4）。
    fn retain_live(&mut self, live: &HashSet<RouteKey>) {
        self.routes.retain(|key, _| live.contains(key));
    }

    pub(super) fn proxy_config(&self, id: &str) -> Option<ProxyConfig> {
        self.proxies
            .iter()
            .find(|entry| entry.id == id)
            .map(ProxyEntry::to_proxy_config)
    }
}

/// 管理端池操作错误，供 Admin 层映射到 400/404/409/500。
///
/// 新增凭据路径也用它表达代理相关失败（`add_credential` 的 anyhow 链），
/// 这样 Admin 层可以按类型而不是关键字得到 404/400/409。
#[derive(Debug, Clone)]
pub enum ProxyPoolError {
    NotFound(String),
    Conflict(String),
    Invalid(String),
    Storage(String),
}

impl fmt::Display for ProxyPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{msg}"),
            Self::Conflict(msg) => write!(f, "{msg}"),
            Self::Invalid(msg) => write!(f, "{msg}"),
            Self::Storage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ProxyPoolError {}

/// 路由构建失败 → 类型化的代理错误。
///
/// 构建失败意味着这条代理配置当下不可用（URL 非法 / TLS 后端初始化失败），
/// 属于客户端可修正的输入问题，映射成 400 而不是 500。
pub(super) fn proxy_unavailable_error(error: &anyhow::Error) -> ProxyPoolError {
    ProxyPoolError::Invalid(format!("代理不可用: {error}"))
}

/// 池条目在列表响应中的形态（不含密码）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyListItem {
    pub id: String,
    pub name: String,
    /// 已脱敏 URL
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub has_password: bool,
    /// 引用该代理的凭据数量
    pub reference_count: usize,
}

/// 凭据绑定的请求形态。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum ProxyBindingRequest {
    /// 继承全局配置
    Inherit,
    /// 显式直连
    Direct,
    /// 引用池条目
    Pool {
        #[serde(rename = "proxyId")]
        proxy_id: String,
    },
    /// 旧的内联三字段
    Inline {
        url: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
}

/// PATCH 池条目的三态字段：missing / null / value。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyUpdateRequest {
    #[serde(default, deserialize_with = "double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub url: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub password: Option<Option<String>>,
}

/// serde double-option 惯用法：缺省 = 保留，`null` = 清除，值 = 替换。
fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// 一次管理写事务：**候选文档**（落盘用）+ **发布清单**（写盘成功后才落地）。
///
/// 两者都在 save lock 内、基于同一份复核后的状态生成，因此"写进文件的"
/// 与"发布到内存的"严格一致。
struct PoolCommit {
    credentials: Vec<KiroCredentials>,
    proxies: Vec<ProxyEntry>,
    publish: PoolPublish,
}

/// 写盘成功后要提交的内存变更。
#[derive(Default)]
struct PoolPublish {
    /// 新增或替换一个池条目，并注册它的 route
    upsert: Option<(ProxyEntry, RouteKey, Arc<Route>)>,
    /// 删除一个池条目
    remove: Option<String>,
    /// 改绑凭据（绑定字段 + route 指针 + state_revision）
    rebinds: Vec<CredentialRebind>,
}

struct CredentialRebind {
    id: u64,
    proxy_id: Option<String>,
    proxy_url: Option<String>,
    proxy_username: Option<String>,
    proxy_password: Option<String>,
    route: Arc<Route>,
}

impl MultiTokenManager {
    // ─────────────────────────────────────────────────────────────
    // 启动期路由构建
    // ─────────────────────────────────────────────────────────────

    /// 启动期：按凭据与池构建全部路由，返回带 route 的条目。
    ///
    /// 无法构建的旧内联 URL 沿用既有先例（`InvalidConfig` 自动禁用），回落目标
    /// **只允许是继承路由（全局代理/系统）**，绝不回落直连；全局代理构建失败
    /// 由构造函数先行 fail-fast（`pool.route` 上抛）。
    pub(super) fn build_routes_for_entries(
        &self,
        mut entries: Vec<CredentialEntry>,
        pool: &mut PoolState,
    ) -> anyhow::Result<Vec<CredentialEntry>> {
        let tls = self.config.tls_backend;
        let fallback_key = inherit_route_key(self.proxy.as_ref());
        let fallback = pool.route(&fallback_key, tls).map_err(|error| {
            anyhow::anyhow!("创建继承（全局代理/系统）HTTP 客户端失败: {error}")
        })?;

        for entry in &mut entries {
            let pool_config = entry
                .credentials
                .proxy_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .and_then(|id| pool.proxy_config(id));
            let key = entry
                .credentials
                .effective_route_key(pool_config.as_ref(), self.proxy.as_ref());
            match pool.route(&key, tls) {
                Ok(route) => {
                    entry.route = route;
                    entry.route_build_failed = false;
                }
                Err(error) => {
                    tracing::warn!(
                        credential_id = entry.id,
                        proxy = ?key,
                        error = %error,
                        "凭据代理配置无效，已自动禁用"
                    );
                    entry.set_reason(Some(DisabledReason::InvalidConfig));
                    entry.route = fallback.clone();
                    // 运行时事实：这条回落才是"配置无效"的权威判据（F2）。
                    entry.route_build_failed = true;
                }
            }
        }
        Ok(entries)
    }

    fn live_route_keys(
        &self,
        proxies: &[ProxyEntry],
        entries: &[CredentialEntry],
    ) -> HashSet<RouteKey> {
        let mut live = HashSet::from([inherit_route_key(self.proxy.as_ref())]);
        for entry in entries {
            let pool_config = entry
                .credentials
                .proxy_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .and_then(|id| proxies.iter().find(|proxy| proxy.id == id))
                .map(ProxyEntry::to_proxy_config);
            live.insert(
                entry
                    .credentials
                    .effective_route_key(pool_config.as_ref(), self.proxy.as_ref()),
            );
        }
        live
    }

    // ─────────────────────────────────────────────────────────────
    // 只读视图：两份独立快照，绝不嵌套 entries 与 pool
    // ─────────────────────────────────────────────────────────────

    /// 池条目列表（含引用数），按名称排序。
    pub fn list_proxies(&self) -> Vec<ProxyListItem> {
        let proxies = self.pool.lock().proxies.clone();
        let referenced: HashMap<String, usize> = {
            let entries = self.entries.lock();
            let mut counts: HashMap<String, usize> = HashMap::new();
            for entry in entries.iter() {
                if let Some(id) = entry.credentials.proxy_id.as_deref()
                    && !id.is_empty()
                {
                    *counts.entry(id.to_string()).or_insert(0) += 1;
                }
            }
            counts
        };

        let mut items: Vec<ProxyListItem> = proxies
            .iter()
            .map(|proxy| ProxyListItem {
                id: proxy.id.clone(),
                name: proxy.name.clone(),
                url: proxy.redacted_url(),
                username: proxy.username.clone(),
                has_password: proxy.password.is_some(),
                reference_count: referenced.get(&proxy.id).copied().unwrap_or(0),
            })
            .collect();
        items.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        items
    }

    /// 回收不再被引用的路由。
    ///
    /// 先池、释放；再 entries、释放；最后再取池回收——没有任何一处同时持两把锁。
    ///
    /// **调用方必须持有 `credentials_save_lock`**（F7）。存活集合的计算与回收
    /// 必须与"发布新绑定"互斥：若 prune 在释放 save 锁之后执行，另一条写事务可以
    /// 在 prune 算出存活集合之后、`retain_live` 之前发布一个新 inline 路由，
    /// 于是这个正在被引用的路由被剔出注册表；下一个绑到同一代理的凭据注册表未命中，
    /// 会新建出第二份 client，破坏 P3 的共享。
    ///
    /// 本函数依次取 pool、entries、pool 且三者不嵌套，符合既有锁序
    /// （`save → entries → pool`）；在 save 锁内调用不会与调用方已持有的锁重复
    /// 加锁——调用点只持有 save 锁，`parking_lot::Mutex` 不可重入这点因此不成立
    /// （见三个调用点处 `commit_pool_write` 已返回、其内部 guard 均已析构）。
    fn prune_routes(&self) {
        let proxies = self.pool.lock().proxies.clone();
        let live = {
            let entries = self.entries.lock();
            self.live_route_keys(&proxies, &entries)
        };
        // 测试观测点（F7）：记录此刻 `credentials_save_lock` 是否由调用方持有。
        //
        // 刻意用**非阻塞**观测而不是闸门：`prune_routes` 跑在写事务的同步临界区里，
        // 在这里阻塞会占住 worker 线程，一旦断言失败/超时，卡住的 `recv()` 永不返回，
        // 进程会挂死而不是给出失败信号。`try_lock` 无论成败都立即返回。
        #[cfg(test)]
        if let Some(observer) = self.test_prune_observer.lock().clone() {
            let save_free = self.credentials_save_lock.try_lock().is_some();
            observer.record(save_free);
        }
        self.pool.lock().retain_live(&live);
    }

    // ─────────────────────────────────────────────────────────────
    // 锁外 get-or-build（P3 共享 / P6 不阻塞）
    // ─────────────────────────────────────────────────────────────

    /// 幂等的 get-or-build：注册表命中则复用同一个 `Arc`，未命中才新建。
    ///
    /// 取 pool 锁只为查表（不构建），随后释放再构建；构建要加载 TLS 根证书，
    /// 绝不能发生在 save lock 里（P6）。
    ///
    /// 返回 `(实际命中的 key, Arc)`，**调用方必须把 Arc 带进 save lock 使用**
    /// （F1）：只构建不返回会让锁内重新 `pool.route()` 再建一次，锁外那次白干，
    /// 且磁盘 I/O 落回锁内。
    fn route_get_or_build(&self, key: &RouteKey) -> anyhow::Result<(RouteKey, Arc<Route>)> {
        if let Some(existing) = self.pool.lock().probe(key) {
            return Ok((key.clone(), existing));
        }
        let route = Route::build(key.clone(), self.config.tls_backend)?;
        Ok((key.clone(), route))
    }

    // ─────────────────────────────────────────────────────────────
    // 管理写事务
    // ─────────────────────────────────────────────────────────────

    /// 新增池条目。
    pub async fn create_proxy(&self, entry: ProxyEntry) -> Result<(), ProxyPoolError> {
        validate_proxy_entry(&entry).map_err(ProxyPoolError::Invalid)?;
        self.require_writable()?;

        // 锁外预建（get-or-build）：构建失败的代理身份不该被写进配置。
        let key = RouteKey::Proxy(entry.to_proxy_config());
        let (key, route) = self
            .route_get_or_build(&key)
            .map_err(|error| ProxyPoolError::Invalid(format!("代理不可用: {error}")))?;
        self.pass_admin_gate().await;

        // save guard 必须覆盖整个事务：候选文档构建 + 写盘 + 发布。
        // 若只覆盖前半段，两个写者会同时写同一个 `credentials.json.tmp`，
        // 一个 rename 走了另一个的 tmp，报 "No such file or directory"。
        let save = self.credentials_save_lock.lock();
        let _save_scope = save_log_scope();
        let commit = {
            // entries 快照先取先放，再取 pool——两把锁不嵌套（锁序契约第 1 条）。
            let credentials = self.snapshot_credentials();
            let mut proxies = {
                let pool = self.pool.lock();
                if pool.proxies.iter().any(|existing| existing.id == entry.id) {
                    return Err(ProxyPoolError::Conflict(format!(
                        "代理 ID 已存在: {}",
                        entry.id
                    )));
                }
                pool.proxies.clone()
            };
            proxies.push(entry.clone());
            PoolCommit {
                credentials,
                proxies,
                publish: PoolPublish {
                    upsert: Some((entry, key, route)),
                    ..Default::default()
                },
            }
        };
        self.commit_pool_write(commit)?;
        drop(save);
        tracing::info!("新增代理池条目");
        Ok(())
    }

    /// 编辑池条目。只重建网络身份发生变化的路由；改名不重建（P3）。
    pub async fn update_proxy(
        &self,
        id: &str,
        patch: ProxyUpdateRequest,
    ) -> Result<(), ProxyPoolError> {
        self.require_writable()?;

        // 锁外：读当前条目（不持 save lock），算候选并预建候选 route。
        let current = {
            let pool = self.pool.lock();
            pool.proxies
                .iter()
                .find(|entry| entry.id == id)
                .cloned()
                .ok_or_else(|| ProxyPoolError::NotFound(format!("代理不存在: {id}")))?
        };
        let mut prebuilt_candidate = current.clone();
        patch
            .apply(&mut prebuilt_candidate)
            .map_err(ProxyPoolError::Invalid)?;
        validate_proxy_entry(&prebuilt_candidate).map_err(ProxyPoolError::Invalid)?;
        let prebuilt_key = RouteKey::Proxy(prebuilt_candidate.to_proxy_config());
        let identity_changed = prebuilt_key != RouteKey::Proxy(current.to_proxy_config());
        // get-or-build：同一网络身份复用既有 Arc，全局只建一次（I7(2)）。
        // 返回的 Arc 会被带进锁内直接发布（F1）——锁外构建+锁内重建等于建两遍，
        // 且第二遍（含 TLS 根证书加载）落在 save lock 里。
        let prebuilt = if identity_changed {
            Some(
                self.route_get_or_build(&prebuilt_key)
                    .map_err(|error| ProxyPoolError::Invalid(format!("代理不可用: {error}")))?,
            )
        } else {
            None
        };
        self.pass_admin_gate().await;

        // save guard 覆盖复核 + 写盘 + 发布整段（见 create_proxy 的说明）。
        let save = self.credentials_save_lock.lock();
        let _save_scope = save_log_scope();
        let commit = {
            // 复核：锁外读到的可能已被并发编辑改掉，以此刻已发布的状态为准。
            let published = {
                let pool = self.pool.lock();
                pool.proxies
                    .iter()
                    .find(|entry| entry.id == id)
                    .cloned()
                    .ok_or_else(|| ProxyPoolError::NotFound(format!("代理不存在: {id}")))?
            };
            let published_key = RouteKey::Proxy(published.to_proxy_config());
            let mut candidate = published;
            patch
                .apply(&mut candidate)
                .map_err(ProxyPoolError::Invalid)?;
            validate_proxy_entry(&candidate).map_err(ProxyPoolError::Invalid)?;
            let candidate_key = RouteKey::Proxy(candidate.to_proxy_config());

            let (credentials, affected) = {
                let entries = self.entries.lock();
                let affected: Vec<u64> = entries
                    .iter()
                    .filter(|entry| entry.credentials.proxy_id.as_deref() == Some(id))
                    .map(|entry| entry.id)
                    .collect();
                (snapshot_entries(&entries), affected)
            };

            let route = {
                let mut pool = self.pool.lock();
                match pool.probe(&candidate_key) {
                    // 注册表里已有：直接用（可能是别的写者刚发布的同一个 Arc）。
                    Some(existing) => existing,
                    None => match &prebuilt {
                        // 最常见：候选身份与锁外预建时一致，直接发布那个 Arc —— 本次
                        // 事务不再构建第二次（F1）。
                        Some((prebuilt_key, prebuilt_route)) if prebuilt_key == &candidate_key => {
                            pool.publish(candidate_key.clone(), prebuilt_route.clone())
                        }
                        // 罕见并发回退：锁外预建之后，另一个写者改了网络身份，或本次
                        // 提交算出的身份与预建的不同。此时没有可复用的 Arc，只能在
                        // 锁内构建一次并立刻注册，避免发布一个未注册的 client。
                        _ => {
                            let built =
                                Route::build(candidate_key.clone(), self.config.tls_backend)
                                    .map_err(|error| {
                                        ProxyPoolError::Invalid(format!("代理不可用: {error}"))
                                    })?;
                            pool.publish(candidate_key.clone(), built)
                        }
                    },
                }
            };

            let mut proxies = self.pool.lock().proxies.clone();
            if let Some(slot) = proxies.iter_mut().find(|entry| entry.id == id) {
                *slot = candidate.clone();
            }

            let rebinds = if candidate_key != published_key {
                affected
                    .into_iter()
                    .map(|entry_id| CredentialRebind {
                        id: entry_id,
                        proxy_id: Some(id.to_string()),
                        proxy_url: None,
                        proxy_username: None,
                        proxy_password: None,
                        route: route.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let rebinds = rebinds
                .into_iter()
                .map(|mut rebind| {
                    // 这些凭据的绑定字段没变（仍是同一个 proxyId），只换 route 指针。
                    if let Some(credential) = credentials
                        .iter()
                        .find(|credential| credential.id == Some(rebind.id))
                    {
                        rebind.proxy_url = credential.proxy_url.clone();
                        rebind.proxy_username = credential.proxy_username.clone();
                        rebind.proxy_password = credential.proxy_password.clone();
                    }
                    rebind
                })
                .collect();

            PoolCommit {
                credentials,
                proxies,
                publish: PoolPublish {
                    upsert: Some((candidate, candidate_key, route)),
                    rebinds,
                    ..Default::default()
                },
            }
        };
        self.commit_pool_write(commit)?;
        // F7：回收必须在 save 锁内——存活集合的计算与回收是同一个临界区的一部分，
        // 否则并发写事务可以在"算出存活集合"与"retain"之间发布新路由，把活 route 剔掉。
        self.prune_routes();
        drop(save);
        tracing::info!(proxy_id = id, "代理池条目已更新");
        Ok(())
    }

    /// 删除池条目；仍被引用时返回冲突（含被禁用凭据的引用）。
    pub async fn delete_proxy(&self, id: &str) -> Result<(), ProxyPoolError> {
        self.require_writable()?;
        self.pass_admin_gate().await;

        // save guard 覆盖复核 + 写盘 + 发布整段（见 create_proxy 的说明）。
        let save = self.credentials_save_lock.lock();
        let _save_scope = save_log_scope();
        let commit = {
            let credentials = {
                let entries = self.entries.lock();
                let referenced = entries
                    .iter()
                    .filter(|entry| entry.credentials.proxy_id.as_deref() == Some(id))
                    .count();
                if referenced > 0 {
                    return Err(ProxyPoolError::Conflict(format!(
                        "代理仍被 {} 个凭据引用，请先解除绑定",
                        referenced
                    )));
                }
                snapshot_entries(&entries)
            };
            let mut proxies = self.pool.lock().proxies.clone();
            if !proxies.iter().any(|entry| entry.id == id) {
                return Err(ProxyPoolError::NotFound(format!("代理不存在: {id}")));
            }
            proxies.retain(|entry| entry.id != id);
            PoolCommit {
                credentials,
                proxies,
                publish: PoolPublish {
                    remove: Some(id.to_string()),
                    ..Default::default()
                },
            }
        };
        self.commit_pool_write(commit)?;
        // F7：回收必须在 save 锁内——存活集合的计算与回收是同一个临界区的一部分，
        // 否则并发写事务可以在"算出存活集合"与"retain"之间发布新路由，把活 route 剔掉。
        self.prune_routes();
        drop(save);
        tracing::info!(proxy_id = id, "代理池条目已删除");
        Ok(())
    }

    /// 绑定凭据的代理来源。
    ///
    /// 提交阶段一律采用池中**当前已发布**条目的路由身份：锁外校验期间代理可能被
    /// 并发改 URL/认证，沿用旧候选 Route 会留下与池不一致的 route。
    pub async fn bind_credential_proxy(
        &self,
        id: u64,
        binding: ProxyBindingRequest,
    ) -> Result<(), ProxyPoolError> {
        self.require_writable()?;
        let (proxy_id_value, inline) = match &binding {
            ProxyBindingRequest::Pool { proxy_id } => (Some(proxy_id.clone()), None),
            ProxyBindingRequest::Inline {
                url,
                username,
                password,
            } => (
                None,
                Some(
                    crate::kiro::model::proxy_pool::inline_proxy_config(
                        url,
                        username.as_deref(),
                        password.as_deref(),
                    )
                    .map_err(ProxyPoolError::Invalid)?,
                ),
            ),
            ProxyBindingRequest::Direct => (None, None),
            ProxyBindingRequest::Inherit => (None, None),
        };
        let direct = matches!(binding, ProxyBindingRequest::Direct);

        // F6：与 `add_credential` / 加载期共用同一份绑定校验。不调它的话，
        // 空串 `proxyId` 会走到下面的 `proxy_config("")` 查池，得到 404
        // 「代理不存在: 」——与新增路径的结论不一致，且这条校验本该与
        // "任何调用路径都不得写出加载期会拒绝的绑定"同源。
        crate::kiro::model::proxy_pool::validate_binding_fields(
            proxy_id_value.as_deref(),
            inline.as_ref().map(|config| config.url.as_str()),
            inline
                .as_ref()
                .and_then(|config| config.username.as_deref()),
            inline
                .as_ref()
                .and_then(|config| config.password.as_deref()),
        )
        .map_err(ProxyPoolError::Invalid)?;

        // 锁外：解析候选 key（池绑定查池，其余直接由绑定决定）。
        let candidate_key = match &proxy_id_value {
            Some(proxy_id) => {
                let config =
                    self.pool.lock().proxy_config(proxy_id).ok_or_else(|| {
                        ProxyPoolError::NotFound(format!("代理不存在: {proxy_id}"))
                    })?;
                RouteKey::Proxy(config)
            }
            None if direct => RouteKey::Direct,
            None => match &inline {
                Some(config) => RouteKey::Proxy(config.clone()),
                None => inherit_route_key(self.proxy.as_ref()),
            },
        };
        // 锁外 get-or-build（P6 / I7(1)）：构建在取 save lock 之前完成，并把
        // 得到的 `(key, Arc)` 带进锁内直接发布（F1）——锁内再 `pool.route()`
        // 会重建一遍（含 TLS 根证书加载），把磁盘 I/O 带回 save lock。
        let prebuilt = self
            .route_get_or_build(&candidate_key)
            .map_err(|error| ProxyPoolError::Invalid(format!("代理不可用: {error}")))?;

        // 闸门：测试在此插入一次并发编辑，验证下面的复核确实以"此刻已发布"
        // 的条目为准（生产路径无闸门，直接通过）。
        self.pass_bind_gate().await;

        // save guard 覆盖复核 + 写盘 + 发布整段（见 create_proxy 的说明）。
        let save = self.credentials_save_lock.lock();
        let _save_scope = save_log_scope();
        let commit = {
            // 复核：绑定期间池可能已变化，必须以此刻已发布的条目为准。
            let published_key = match &proxy_id_value {
                Some(proxy_id) => {
                    let config = self.pool.lock().proxy_config(proxy_id).ok_or_else(|| {
                        ProxyPoolError::Conflict(format!("代理已被删除: {proxy_id}"))
                    })?;
                    RouteKey::Proxy(config)
                }
                None => candidate_key.clone(),
            };
            let route = {
                let mut pool = self.pool.lock();
                match pool.probe(&published_key) {
                    Some(existing) => existing,
                    None => {
                        let (prebuilt_key, prebuilt_route) = &prebuilt;
                        if prebuilt_key == &published_key {
                            // 锁外构建的那个 Arc 就是本次要发布的路由（F1）。
                            pool.publish(published_key.clone(), prebuilt_route.clone())
                        } else {
                            // 罕见并发回退：绑定期间池条目被并发改成了另一个网络
                            // 身份，锁外预建的不再适用。只在锁内构建一次并注册。
                            let built =
                                Route::build(published_key.clone(), self.config.tls_backend)
                                    .map_err(|error| {
                                        ProxyPoolError::Invalid(format!("代理不可用: {error}"))
                                    })?;
                            pool.publish(published_key.clone(), built)
                        }
                    }
                }
            };

            let proxy_url = if direct {
                Some(KiroCredentials::PROXY_DIRECT.to_string())
            } else {
                inline.as_ref().map(|config| config.url.clone())
            };
            let proxy_username = inline.as_ref().and_then(|config| config.username.clone());
            let proxy_password = inline.as_ref().and_then(|config| config.password.clone());

            let credentials = {
                let entries = self.entries.lock();
                if !entries.iter().any(|entry| entry.id == id) {
                    return Err(ProxyPoolError::NotFound(format!("凭据不存在: {id}")));
                }
                let mut credentials = snapshot_entries(&entries);
                // 候选文档必须反映本次绑定：在**克隆出的**凭据上改字段，
                // 共享条目保持调用前原样（I3）。
                if let Some(target) = credentials
                    .iter_mut()
                    .find(|credential| credential.id == Some(id))
                {
                    target.proxy_id = proxy_id_value.clone();
                    target.proxy_url = proxy_url.clone();
                    target.proxy_username = proxy_username.clone();
                    target.proxy_password = proxy_password.clone();
                }
                credentials
            };
            let proxies = self.pool.lock().proxies.clone();

            PoolCommit {
                credentials,
                proxies,
                publish: PoolPublish {
                    rebinds: vec![CredentialRebind {
                        id,
                        proxy_id: proxy_id_value,
                        proxy_url,
                        proxy_username,
                        proxy_password,
                        route,
                    }],
                    ..Default::default()
                },
            }
        };
        self.commit_pool_write(commit)?;
        // F7：回收必须在 save 锁内——存活集合的计算与回收是同一个临界区的一部分，
        // 否则并发写事务可以在"算出存活集合"与"retain"之间发布新路由，把活 route 剔掉。
        self.prune_routes();
        drop(save);
        tracing::info!(credential_id = id, "凭据代理绑定已更新");
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // 提交：落盘成功才发布内存
    // ─────────────────────────────────────────────────────────────

    /// 落盘 → 成功才发布内存；失败时池条目、凭据绑定字段、`entry.route`、
    /// 路由注册表、`state_revision` 全部保持调用前原样。
    ///
    /// 调用方必须已持有 `credentials_save_lock`，且已释放 entries/pool。
    /// 这里重新短暂取锁只为发布；锁内不含 I/O（写盘已在此函数开头完成）。
    fn commit_pool_write(&self, commit: PoolCommit) -> Result<(), ProxyPoolError> {
        self.write_document(&commit.credentials, &commit.proxies)?;

        // 发布池条目 + 注册 route（只取 pool）
        if let Some((entry, key, route)) = commit.publish.upsert {
            let mut pool = self.pool.lock();
            if let Some(slot) = pool.proxies.iter_mut().find(|slot| slot.id == entry.id) {
                *slot = entry;
            } else {
                pool.proxies.push(entry);
            }
            pool.publish(key, route);
        }
        if let Some(id) = commit.publish.remove {
            self.pool.lock().proxies.retain(|entry| entry.id != id);
        }

        if !commit.publish.rebinds.is_empty() {
            // route 已随 submit 时的 get-or-build 注册进池（或在 upsert 里刚发布），
            // 这里只取 entries 一把锁，绝不再取 pool——两把锁不嵌套。
            let mut entries = self.entries.lock();
            for rebind in commit.publish.rebinds {
                let Some(entry) = entries.iter_mut().find(|entry| entry.id == rebind.id) else {
                    continue;
                };
                entry.credentials.proxy_id = rebind.proxy_id;
                entry.credentials.proxy_url = rebind.proxy_url;
                entry.credentials.proxy_username = rebind.proxy_username;
                entry.credentials.proxy_password = rebind.proxy_password;
                entry.route = rebind.route;
                // F2(b)：绑定/编辑提交成功意味着新配置**确实能构建**（锁外
                // get-or-build 已经证明），所以"配置无效"这个运行时事实到此结束，
                // 由 route 构建失败导致的禁用状态也必须一并解除——否则管理员
                // 改好绑定后仍然无法启用，只能手改 JSON。
                entry.route_build_failed = false;
                // 只清除「由 route 构建失败导致的」InvalidConfig；`authMethod=api_key`
                // 缺 key 这类与 route 无关的配置无效仍由 `config_currently_invalid`
                // 兜住，不清。
                if !api_key_without_key(&entry.credentials)
                    && entry.disabled_reason == Some(DisabledReason::InvalidConfig)
                {
                    entry.set_reason(None);
                } else {
                    entry.state_revision = entry.state_revision.wrapping_add(1);
                }
            }
        }
        Ok(())
    }

    /// 存储是否可回写：单对象文件与无路径都拒绝代理管理写操作。
    fn require_writable(&self) -> Result<(), ProxyPoolError> {
        let writable = *self.credentials_save_lock.lock();
        if !writable || self.credentials_path.is_none() {
            return Err(ProxyPoolError::Storage(
                "凭据文件不可回写（单对象格式或无保存路径），代理池操作被拒绝".to_string(),
            ));
        }
        Ok(())
    }

    /// 按内容决定落盘形态并原子写入。调用方必须已持有 `credentials_save_lock`。
    fn write_document(
        &self,
        credentials: &[KiroCredentials],
        proxies: &[ProxyEntry],
    ) -> Result<(), ProxyPoolError> {
        let path = self
            .credentials_path
            .as_ref()
            .ok_or_else(|| ProxyPoolError::Storage("无凭据保存路径".to_string()))?;
        let json = if should_write_envelope(proxies, credentials) {
            serde_json::to_string_pretty(&CredentialsEnvelope {
                version: CREDENTIALS_ENVELOPE_VERSION,
                proxies: proxies.to_vec(),
                credentials: credentials.to_vec(),
            })
        } else {
            serde_json::to_string_pretty(credentials)
        }
        .map_err(|error| ProxyPoolError::Storage(format!("序列化凭据失败: {error}")))?;

        // 测试闸门：卡在"已持 save lock、entries/proxies 均已释放、正要写盘"这一刻。
        //
        // 闸门处先实测两把读路径锁是否空闲：这是 P6「写盘期间不持有 entries」
        // 的直接观测点，与 T7 的刷新落盘闸门同构。断言它比断言"获取上下文很快
        // 返回"更稳定——同步锁被跨 await 持有时，后者会表现为线程饥饿而非超时。
        #[cfg(test)]
        if let Some(gate) = self.test_pool_write_gate.lock().clone() {
            let entries_free = self.entries.try_lock().is_some();
            let pool_free = self.pool.try_lock().is_some();
            gate.observe_locks(entries_free, pool_free);
            gate.arrive_and_wait();
        }

        write_blocking(|| crate::common::atomic_file::write_atomically(path, json.as_bytes()))
            .map_err(|error| ProxyPoolError::Storage(format!("回写凭据文件失败: {error}")))
    }
}

impl ProxyUpdateRequest {
    /// 测试用：只关心"三态字段如何落到条目上"，忽略不可空字段的拒绝结果
    /// （那条规则由 `update_proxy` 的用例覆盖）。
    #[cfg(test)]
    pub(crate) fn apply_for_test(&self, entry: &mut ProxyEntry) {
        let _ = self.apply(entry);
    }

    /// 应用三态字段：缺省=保留，`null`=清除，值=替换。
    ///
    /// `name` 与 `url` 不可空——它们清除后条目就没有身份/地址了，`null` 一律
    /// 拒绝并指明字段名。`username`/`password` 的 `null` 语义仍是"清除认证"。
    fn apply(&self, entry: &mut ProxyEntry) -> Result<(), String> {
        if let Some(name) = &self.name {
            entry.name = name.clone().ok_or_else(|| "name 不能为 null".to_string())?;
        }
        if let Some(url) = &self.url {
            entry.url = url.clone().ok_or_else(|| "url 不能为 null".to_string())?;
        }
        if let Some(username) = &self.username {
            entry.username = username.clone();
        }
        if let Some(password) = &self.password {
            entry.password = password.clone();
        }
        Ok(())
    }
}

/// 测试观测：把「正在管理写的 save lock 临界区内」这件事标记到本线程。
///
/// 用于 F1 直接测量「锁内 Route 构建次数」。返回的守卫必须在 save guard
/// 之后声明、在同一作用域内 drop（逆序释放，先解除标记再放锁）。
/// 生产构建里是 `()`，零成本、零符号。
#[cfg(test)]
fn save_log_scope() -> Option<crate::http_client::route_build_counter::SaveLockScope> {
    Some(crate::http_client::route_build_counter::SaveLockScope::enter())
}

#[cfg(not(test))]
fn save_log_scope() -> Option<std::convert::Infallible> {
    None
}

pub(super) fn snapshot_entries(entries: &[CredentialEntry]) -> Vec<KiroCredentials> {
    entries
        .iter()
        .map(|entry| {
            let mut credential = entry.credentials.clone();
            credential.canonicalize_auth_method();
            credential.disabled = entry.disabled;
            credential.disabled_reason = entry.disabled.then(|| {
                entry
                    .disabled_reason
                    .unwrap_or(DisabledReason::Manual)
                    .name()
                    .to_string()
            });
            credential
        })
        .collect()
}

/// 在 Tokio 多线程 runtime 上把阻塞 I/O 移出 worker 线程。
fn write_blocking<F, T>(operation: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T>,
{
    let is_multi_thread = tokio::runtime::Handle::try_current()
        .map(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        .unwrap_or(false);
    if is_multi_thread {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}
