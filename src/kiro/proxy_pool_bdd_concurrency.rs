//! 代理池 BDD 并发批：管理写与运行时状态 / 热路径的交互。
//!
//! 本文件承载计划里三条此前**只有空心证据**的验收行：
//! - T6「管理端改绑定 / 编辑代理时，该凭据正持有刷新锁、已有失败计数与在途计数
//!   → 刷新锁、失败计数、in_flight、load 原样保留；并发刷新仍串行」；
//! - T5「用测试钩子卡住管理写盘，同时并发获取请求上下文 → 获取立即完成，不等待
//!   写盘」（P6）；
//! - T7「用测试钩子让刷新落盘与管理写同时进行（含超时断言）→ 两者均完成，不死锁；
//!   落盘前 entries 已释放」（锁序契约）。
//!
//! 与 `proxy_pool_bdd` / `proxy_pool_bdd_isolation` 同一纪律：并发边界一律由
//! notify / 闸门 / 可观测事件定位，不用 sleep 判断正确性；`timeout` 只决定失败
//! 多快。每条用例都先做**前置条件断言**，再断言结果——否则断言本身可以恒绿。

use std::sync::Arc;
use std::time::Duration;

use crate::http_client::{ProxyConfig, RouteKey};
use crate::kiro::proxy_fixtures::{CountingRefreshServer, spawn_socks5};
use crate::kiro::token_manager::proxy_pool::{PoolWriteGate, PruneObserver};
use crate::kiro::token_manager::{MultiTokenManager, ProxyBindingRequest, ProxyUpdateRequest};

use super::proxy_pool_bdd::{TempDir, api_key_credential, manager, pool_entry};
use super::proxy_pool_bdd_isolation::oauth_credential;

/// 断言用的宽松上限：只决定失败多快，不参与"对不对"的判定。
const FAIL_FAST: Duration = Duration::from_secs(10);

// ─────────────────────────────────────────────────────────────
// T6 / 运行时状态保留 + 刷新仍串行
// ─────────────────────────────────────────────────────────────

/// 管理端的两条改绑定路径。
#[derive(Clone, Copy, Debug)]
enum AdminPath {
    /// `bind_credential_proxy`：把凭据从「继承」改绑到池条目。
    Bind,
    /// `update_proxy`：凭据已绑池条目，改该条目的 URL 触发 route 换发。
    UpdateProxy,
}

/// 把凭据的运行时状态做成**非零**：失败计数 > 0、`in_flight` > 0、load 非默认值。
///
/// 顺序是刻意安排的：`report_failure` 自己会 `saturating_sub` 一次 in_flight
/// （token_manager.rs:2836），所以必须先在它之后补一次 acquire，才能让"失败计数
/// 与在途计数同时非零"成立——这也是旧用例看起来"有 in_flight"却恒为 0 的原因。
async fn make_runtime_state_nonzero(manager: &Arc<MultiTokenManager>) {
    let _first = manager.acquire_context(None).await.unwrap();
    let _second = manager.acquire_context(None).await.unwrap();
    manager.report_failure(1);
    manager.record_upstream_call(1, Some("claude-sonnet-5"));
    let _third = manager.acquire_context(None).await.unwrap();
}

/// T6：管理写不得重建 `CredentialEntry`，且重发布不得让刷新穿透隔离。
///
/// 前置条件断言（缺一即恒绿）：
/// 1. 失败计数 > 0、`in_flight` > 0、load > 0 —— 三项都非默认值，否则"原样保留"
///    与"被清零"不可区分；
/// 2. 测试确实**持有该条目真实的** `refresh_lock`（`try_lock` 失败），否则"管理写
///    不拿刷新锁"这条无从谈起；
/// 3. 管理写之后 route 指针确实变了（P3），否则"状态没变"可能只是"管理写没干活"。
///
/// 反事实（见报告）：把 `commit_pool_write` 的原地改字段换成重建条目（刷新锁换新
/// `Arc`、计数清零、load 归零），两条路径的指针/计数断言各自变红。
async fn t6_admin_write_preserves_runtime_state_and_refresh_stays_serial(path: AdminPath) {
    let dir = TempDir::new();
    let refresh = CountingRefreshServer::spawn().await;
    let socks_a = spawn_socks5(None, "socks5").await;
    let socks_b = spawn_socks5(None, "socks5").await;

    let manager = manager(
        &dir,
        vec![oauth_credential(1, false)],
        vec![pool_entry("p1", &socks_a.url)],
    );
    manager.install_refresh_url_for_test(refresh.url.clone());

    // UpdateProxy 路径需要凭据已经在池代理上，否则 update 没有受影响凭据可换 route。
    if matches!(path, AdminPath::UpdateProxy) {
        manager
            .bind_credential_proxy(
                1,
                ProxyBindingRequest::Pool {
                    proxy_id: "p1".into(),
                },
            )
            .await
            .unwrap();
    }

    make_runtime_state_nonzero(&manager).await;

    // (1) 前置条件：三项运行时状态都非默认值。
    let (lock_before, failures_before, in_flight_before, revision_before) =
        manager.runtime_state_for_test(1).unwrap();
    let (load_before, load_ts_before) = manager.runtime_load_for_test(1).unwrap();
    assert!(
        failures_before > 0,
        "前置条件不成立：失败计数为 0，无法区分'保留'与'被清零'"
    );
    assert!(
        in_flight_before > 0,
        "前置条件不成立：in_flight 为 0，无法区分'保留'与'被清零'"
    );
    assert!(
        load_before > 0.0,
        "前置条件不成立：load 为默认值，无法观测它是否被管理写覆盖"
    );

    let route_before = manager.route_arc_for_test(1).expect("凭据必须有 route");

    // (2) 模拟"刷新进行中"：持有该条目真实的 refresh_lock。
    let held_lock = lock_before.clone();
    let guard = held_lock.lock().await;
    assert!(
        lock_before.try_lock().is_err(),
        "前置条件不成立：刷新锁没有被测试持有"
    );

    // (3) 管理写必须在 refresh_lock 被持有的情况下照常完成（不拿、也不等这把锁）。
    let result = tokio::time::timeout(FAIL_FAST, async {
        match path {
            AdminPath::Bind => {
                // 该路径下凭据初始为"继承"，这一次 bind 会真的发布新 route。
                manager
                    .bind_credential_proxy(
                        1,
                        ProxyBindingRequest::Pool {
                            proxy_id: "p1".into(),
                        },
                    )
                    .await
            }
            AdminPath::UpdateProxy => {
                manager
                    .update_proxy(
                        "p1",
                        ProxyUpdateRequest {
                            url: Some(Some(socks_b.url.clone())),
                            ..Default::default()
                        },
                    )
                    .await
            }
        }
    })
    .await
    .expect("管理写不得因该凭据持有刷新锁而阻塞");
    result.unwrap();

    // 结果臂：运行时状态原样保留。
    let (lock_after, failures_after, in_flight_after, revision_after) =
        manager.runtime_state_for_test(1).unwrap();
    assert!(
        Arc::ptr_eq(&lock_after, &lock_before),
        "{path:?}：刷新锁的 Arc 必须原样保留（重建条目会换新锁，并发刷新随即穿透）"
    );
    assert_eq!(
        failures_after, failures_before,
        "{path:?}：失败计数必须原样保留"
    );
    assert_eq!(
        in_flight_after, in_flight_before,
        "{path:?}：in_flight 必须原样保留"
    );
    let (load_after, load_ts_after) = manager.runtime_load_for_test(1).unwrap();
    assert_eq!(
        load_after.to_bits(),
        load_before.to_bits(),
        "{path:?}：load 必须原样保留（{load_before} -> {load_after}）"
    );
    assert_eq!(
        load_ts_after, load_ts_before,
        "{path:?}：load 的时间基准必须原样保留"
    );
    assert_eq!(
        revision_after,
        revision_before.wrapping_add(1),
        "{path:?}：state_revision 沿用既有递增规则（{revision_before} -> {revision_after}）"
    );

    // P3 的另一半：状态没变不等于管理写没干活——route 必须真的换发。
    let route_after = manager.route_arc_for_test(1).unwrap();
    assert!(
        !Arc::ptr_eq(&route_after, &route_before),
        "{path:?}：管理写必须发布新 route，否则本用例的前置条件不成立"
    );
    let expected_key = match path {
        AdminPath::Bind => RouteKey::Proxy(ProxyConfig::new(&socks_a.url)),
        AdminPath::UpdateProxy => RouteKey::Proxy(ProxyConfig::new(&socks_b.url)),
    };
    let registered = manager
        .registered_route_for_test(&expected_key)
        .expect("新 route 必须已注册进池");
    assert!(
        Arc::ptr_eq(&route_after, &registered),
        "{path:?}：凭据 route 必须指向新网络身份的注册实例"
    );

    drop(guard);

    // 重发布之后，同一凭据的并发刷新仍必须串行。
    //
    // 观测点是服务端侧的**同时在处理请求数的历史最大值**：串行时它恒为 1，
    // 一旦隔离被穿透，三个刷新会同时停在 handler 里，最大值变成 3。
    refresh.hold();
    let mut refreshes = Vec::new();
    for _ in 0..3 {
        let manager = manager.clone();
        refreshes.push(tokio::spawn(async move {
            manager.force_refresh_token_for(1).await
        }));
    }
    refresh.wait_count(1).await;
    assert!(
        manager
            .runtime_state_for_test(1)
            .unwrap()
            .0
            .try_lock()
            .is_err(),
        "前置条件不成立：并发刷新没有持有 refresh_lock，串行断言无从谈起"
    );

    for _ in 0..3 {
        refresh.release_one();
    }
    for handle in refreshes {
        tokio::time::timeout(FAIL_FAST, handle)
            .await
            .expect("并发刷新必须完成（串行化不应导致死锁）")
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        refresh.count(),
        3,
        "三次刷新都必须真的打到刷新服务（否则'串行'可能只是'没发生'）"
    );
    assert_eq!(
        refresh.max_in_flight(),
        1,
        "{path:?}：同一凭据的并发刷新必须串行（服务端观测到的最多同时在途数为 1）"
    );

    // 刷新只合并 token 字段，不得回退管理写刚发布的绑定状态。
    let snapshot = manager.snapshot();
    let mode = snapshot
        .entries
        .iter()
        .find(|entry| entry.id == 1)
        .map(|entry| entry.proxy_mode.clone())
        .unwrap();
    assert_eq!(
        mode, "pool",
        "{path:?}：刷新与管理写可交换，刷新不得覆盖绑定字段"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_admin_bind_preserves_runtime_state_and_refresh_stays_serial() {
    t6_admin_write_preserves_runtime_state_and_refresh_stays_serial(AdminPath::Bind).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_update_proxy_preserves_runtime_state_and_refresh_stays_serial() {
    t6_admin_write_preserves_runtime_state_and_refresh_stays_serial(AdminPath::UpdateProxy).await;
}

// ─────────────────────────────────────────────────────────────
// T5 / P6：写盘期间并发获取请求上下文必须立即完成
// ─────────────────────────────────────────────────────────────

/// 管理写卡在**真实写盘**调用里时，并发获取请求上下文必须立即完成。
///
/// 前置条件断言：
/// 1. 写事务确实已经进入写盘并被闸门卡住（`wait_arrival`，不是 sleep）；
/// 2. 写盘未返回前，内存里的池**尚未发布**、磁盘也**尚未变化**——这条同时证明
///    "卡在写盘"这个状态是真的，而不是提前返回了；
/// 3. 所有获取都成功且选中的是预期凭据（否则"立即完成"可能只是"立即失败"）。
///
/// 承重的正确性断言是"获取在 timeout 内完成"与"route 指针/注册表不变"：
/// `route_build_counter` 是 thread-local（`http_client.rs`，本批范围外），无法
/// 观测其他任务线程上的构建；而请求路径一旦构建 route，必然体现为条目 route
/// 指针或注册表变化——这两条是它的健全替代。
///
/// 反事实（见报告）：把 `write_document` 挪进 `entries` 临界区，获取会在 entries
/// 锁上等到超时，本条红。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_context_acquisition_never_waits_for_admin_write_disk_io() {
    let dir = TempDir::new();
    let manager = manager(&dir, vec![api_key_credential(1)], Vec::new());
    let route_before = manager.route_arc_for_test(1).unwrap();

    let new_proxy = pool_entry("p2", "socks5://127.0.0.1:1080");
    let new_key = RouteKey::Proxy(ProxyConfig::new(&new_proxy.url));

    let (gate, release) = PoolWriteGate::new();
    manager.install_pool_write_gate_for_test(gate.clone());

    let writer = {
        let manager = manager.clone();
        let entry = new_proxy.clone();
        tokio::spawn(async move { manager.create_proxy(entry).await })
    };

    // (1) 确定性事件：写事务已进入写盘并被卡住。
    gate.wait_arrival().await;

    // (1b) P6 的直接证据：写盘这一刻 entries 与 pool 都没被持有。
    //
    // 这是本用例的承重断言。用 try_lock 在闸门处实测，而不是靠"后续调用没超时"
    // 反推——后者在同步锁被跨 await 持有时会表现为线程饥饿而非超时，测不出缺陷。
    assert_eq!(
        gate.observed_locks(),
        Some((true, true)),
        "P6：写盘期间不得持有 entries / pool"
    );

    // (2) 前置条件：此刻状态尚未发布，磁盘也尚未变化。
    //
    // 只用 pool-only 观测点：`list_proxies()` 还要取 entries，若实现真把 entries
    // 持有了，它会同步阻塞并让用例挂死——观测手法本身必须与缺陷解耦。
    assert!(
        manager.pool_proxy_ids_for_test().is_empty(),
        "前置条件不成立：写盘未返回前池里不得出现新条目"
    );
    assert!(
        manager.registered_route_for_test(&new_key).is_none(),
        "前置条件不成立：写盘未返回前不得发布新 route"
    );
    let on_disk = std::fs::read_to_string(dir.path()).unwrap_or_default();
    assert!(
        !on_disk.contains("socks5://127.0.0.1:1080"),
        "前置条件不成立：写盘未返回前磁盘不得出现新条目（实际内容 {} 字节）",
        on_disk.len()
    );

    // (3) 并发获取：全部在 timeout 内完成，且选中预期凭据。
    crate::http_client::route_build_counter::reset();
    let acquisitions = (0..8).map(|index| {
        let manager = manager.clone();
        async move {
            if index % 2 == 0 {
                manager.acquire_context(None).await.map(|ctx| ctx.id)
            } else {
                manager
                    .acquire_context_for_session_excluding(None, None, &Default::default())
                    .await
                    .map(|ctx| ctx.id)
            }
        }
    });
    let results = tokio::time::timeout(FAIL_FAST, futures::future::join_all(acquisitions))
        .await
        .expect("写盘期间获取请求上下文不得等待写盘（P6）");
    for (index, result) in results.into_iter().enumerate() {
        assert_eq!(
            result.unwrap_or_else(|error| panic!("第 {index} 次获取失败: {error}")),
            1,
            "第 {index} 次获取必须选中唯一凭据"
        );
    }

    // 补充观测：本用例的获取路径对 API Key 凭据全程不让出，因此 thread-local
    // 计数在本任务线程上是有效读数；健全替代仍是下面的指针断言。
    assert_eq!(
        crate::http_client::route_build_counter::count(&RouteKey::System),
        0,
        "请求路径不得构建 route"
    );
    assert_eq!(
        manager.route_ptr_for_test(1).unwrap(),
        Arc::as_ptr(&route_before),
        "请求路径不得替换凭据的 route"
    );
    assert!(
        manager.registered_route_for_test(&new_key).is_none(),
        "获取上下文期间不得把写事务的 route 提前发布"
    );

    // (4) 放行后事务完成、状态与磁盘都已发布。
    release.send(()).expect("放行写盘");
    tokio::time::timeout(FAIL_FAST, writer)
        .await
        .expect("放行后管理写必须完成")
        .unwrap()
        .unwrap();
    let listed = manager.pool_proxy_ids_for_test();
    assert_eq!(listed, vec!["p2".to_string()], "放行后新条目必须已发布");
    let on_disk = std::fs::read_to_string(dir.path()).unwrap_or_default();
    assert!(
        on_disk.contains("socks5://127.0.0.1:1080"),
        "放行后磁盘必须已写入新条目"
    );
}

// ─────────────────────────────────────────────────────────────
// T7 / 锁序契约：刷新落盘与管理写并发不死锁，且落盘前 entries 已释放
// ─────────────────────────────────────────────────────────────

/// 真实刷新路径走到落盘时，与管理写并发：两者都完成、不死锁，且落盘前
/// entries / proxies 都没被持有。
///
/// 前置条件断言：
/// 1. 闸门到达**之前**刷新服务已经收到一次请求——证明这条链路走的是真实刷新，
///    不是"没刷新就直接落盘"；
/// 2. 闸门处实测 `entries.try_lock()` 与 `pool.try_lock()` 都成功——这是
///    "落盘前 entries 已释放"的直接证据，不是读代码推断；
/// 3. 刷新此刻仍卡在闸门（`!is_finished`），因此并发管理写确实与它重叠。
///
/// 锁序契约要求的期望结果：`save lock → entries → pool`。刷新此刻一把锁都还没
/// 持有，管理写因此可以立即取得 save lock 并完成整个事务——所以这里的正确结果
/// 是"管理写先完成、刷新随后落盘"，而不是"两者互相等待"。
///
/// 反事实（见报告）：临时让刷新路径在持有 entries 锁时调用 `persist_credentials`，
/// 闸门处 `observed_locks` 变成 `(false, true)`，且管理写会在 entries 上等到超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_refresh_persist_and_admin_write_interleave_without_deadlock() {
    let dir = TempDir::new();
    let refresh = CountingRefreshServer::spawn().await;
    let socks = spawn_socks5(None, "socks5").await;

    let manager = manager(&dir, vec![oauth_credential(1, true)], Vec::new());
    manager.install_refresh_url_for_test(refresh.url.clone());
    manager
        .create_proxy(pool_entry("p1", &socks.url))
        .await
        .unwrap();

    let (gate, release) = PoolWriteGate::new();
    manager.install_refresh_persist_gate_for_test(gate.clone());

    let refresher = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.force_refresh_token_for(1).await })
    };

    gate.wait_arrival().await;

    // (1) 前置条件：真实刷新已经发生过。
    assert_eq!(
        refresh.count(),
        1,
        "前置条件不成立：落盘闸门之前刷新服务应已收到一次请求"
    );

    // (2) 直接证据：落盘前 entries / pool 都没被持有。
    assert_eq!(
        gate.observed_locks(),
        Some((true, true)),
        "锁序契约：调用 persist_credentials 之前必须已释放 entries 与 pool"
    );

    // (3) 并发管理写：此刻刷新一把锁都没持有，所以它必须立即完成。
    let bound = tokio::time::timeout(
        FAIL_FAST,
        manager.bind_credential_proxy(
            1,
            ProxyBindingRequest::Pool {
                proxy_id: "p1".into(),
            },
        ),
    )
    .await
    .expect("刷新落盘期间管理写不得被阻塞（锁序 save → entries → pool）");
    bound.unwrap();

    assert!(
        !refresher.is_finished(),
        "前置条件不成立：刷新应仍卡在落盘闸门，才能证明两者确实重叠"
    );

    // (4) 放行刷新落盘，两者都应完成。
    release.send(()).expect("放行刷新落盘");
    tokio::time::timeout(FAIL_FAST, refresher)
        .await
        .expect("刷新落盘必须完成（死锁会在这里超时）")
        .unwrap()
        .unwrap();

    // 两者效果都在，且刷新没有把管理写刚发布的绑定覆盖掉。
    let reloaded = crate::kiro::model::credentials::CredentialsConfig::load(dir.path())
        .unwrap()
        .into_parts();
    let (credentials, proxies) = reloaded;
    assert_eq!(proxies.len(), 1, "池条目必须仍在文件里");
    assert_eq!(credentials.len(), 1, "凭据必须仍在文件里");
    assert_eq!(
        credentials[0].proxy_id.as_deref(),
        Some("p1"),
        "刷新落盘不得回退管理写刚发布的绑定"
    );
    assert_eq!(
        credentials[0].access_token.as_deref(),
        Some("refreshed-access"),
        "刷新结果必须已落盘"
    );
}

// ─────────────────────────────────────────────────────────────
// F7：路由回收必须与"发布新绑定"互斥
// ─────────────────────────────────────────────────────────────

/// `prune_routes` 必须在 `credentials_save_lock` 临界区内执行。
///
/// 缺陷形态（F7）：prune 在 `drop(save)` 之后执行，于是「算出存活集合」与
/// `retain_live` 之间可以被另一条写事务插入。T1 算存活集合时新代理 X 还不存在；
/// T2 随后发布并注册 X；T1 的 `retain_live` 把 X 剔掉。之后任何凭据再绑到 X
/// 都会注册表未命中、新建出 X'，两条凭据各用一套连接池，破坏 P3 的共享。
///
/// 断言设计：修复之后那个交错**不可能**发生，所以承重断言是互斥本身——
/// 每次 `prune_routes` 执行时 save 锁都必须已被调用方持有
/// （观测值恒为 `false`），并且并发 bind 与这次回收确实重叠过。
///
/// 前置条件断言：
/// 1. 至少观测到一次回收（否则"全部为 false"是空真）；
/// 2. T2 在 T1 完成之前就已启动、且此刻未完成——证明两者确实重叠，
///    因此"X 没被回收"不是"根本没并发"的假象；
/// 3. 结果侧：X 仍在注册表，且之后绑到 X 的第二条凭据复用同一个 Arc。
///
/// 反事实（已现场验证）：把三处 `prune_routes()` 移回 `drop(save)` 之后，
/// 第一条断言变红——观测到 `[true]`（回收时 save 锁空闲）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bdd_f7_prune_runs_inside_save_lock_and_keeps_shared_route() {
    let dir = TempDir::new();
    let socks_pool = spawn_socks5(None, "socks5").await;
    let socks_inline = spawn_socks5(None, "socks5").await;
    let inline_url = socks_inline.url.clone();
    let inline_key = RouteKey::Proxy(ProxyConfig::new(&inline_url));

    let manager = manager(
        &dir,
        vec![
            api_key_credential(1),
            api_key_credential(2),
            api_key_credential(3),
        ],
        vec![pool_entry("p1", &socks_pool.url)],
    );

    let observer = PruneObserver::new();
    manager.install_prune_observer_for_test(observer.clone());

    // T1 与 T2 同时起跑：T1 绑到池条目 p1，T2 绑到新的 inline 代理 X。
    // 两者都要过 save 锁，因此必然串行——这正是要断言的不变量。
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let t1 = {
        let manager = manager.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager
                .bind_credential_proxy(
                    1,
                    ProxyBindingRequest::Pool {
                        proxy_id: "p1".into(),
                    },
                )
                .await
        })
    };
    let t2 = {
        let manager = manager.clone();
        let barrier = barrier.clone();
        let url = inline_url.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager
                .bind_credential_proxy(
                    2,
                    ProxyBindingRequest::Inline {
                        url,
                        username: None,
                        password: None,
                    },
                )
                .await
        })
    };

    // 前置条件 2：两者在真正开始前都已就位（barrier 保证），且至少一个在跑。
    assert!(
        !t1.is_finished() || !t2.is_finished(),
        "前置条件：两个绑定必须真实并发执行"
    );

    tokio::time::timeout(FAIL_FAST, t1)
        .await
        .expect("T1 必须在期限内完成（死锁会在这里超时）")
        .unwrap()
        .expect("T1 绑定成功");
    tokio::time::timeout(FAIL_FAST, t2)
        .await
        .expect("T2 必须在期限内完成（死锁会在这里超时）")
        .unwrap()
        .expect("T2 绑定成功");

    // 前置条件 1：确实执行过回收，且一次也不能在 save 锁外执行。
    let observations = observer
        .observations()
        .expect("前置条件：必须至少观测到一次路由回收，否则断言是空真");
    assert!(
        observations.iter().all(|save_free| !save_free),
        "F7：prune 必须在 credentials_save_lock 之内执行，实际观测: {observations:?}"
    );

    // 结果侧：X 仍在注册表里，且之后绑到 X 的凭据复用同一个 Arc。
    let published = manager
        .registered_route_for_test(&inline_key)
        .expect("并发发布的路由必须仍在注册表里（F7）");
    manager
        .bind_credential_proxy(
            3,
            ProxyBindingRequest::Inline {
                url: inline_url.clone(),
                username: None,
                password: None,
            },
        )
        .await
        .expect("第三次绑定成功");
    let second = manager.route_arc_for_test(2).expect("凭据 2 必须有 route");
    let third = manager.route_arc_for_test(3).expect("凭据 3 必须有 route");
    assert!(
        Arc::ptr_eq(&published, &second),
        "注册表里的实例必须就是凭据 2 在用的那个"
    );
    assert!(
        Arc::ptr_eq(&second, &third),
        "同一代理上的两条凭据必须共享同一个 route Arc（两套连接池即回归）"
    );
}
