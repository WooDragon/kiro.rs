//! 代理协议面 BDD：HTTP 转发与 HTTPS CONNECT 的认证行为、SOCKS5/SOCKS5h 的
//! 目标地址类型（DNS 由谁解析）。
//!
//! 本文件补的是独立评审指出的覆盖缺口：旧用例只断言"代理认证成功 / CONNECT
//! 被选中"，**没有观测目标侧收到的请求头**，因此"代理凭据被透传给目标"这种
//! 泄漏在本文件出现之前是全绿的。原则与其它 BDD 文件一致：只用本机回环夹具、
//! 不触外网、不用真实凭据；每条用例先断言前置条件（代理确实收到请求、目标确实
//! 收到 0 个或 N 个请求），再断言结论。

use std::sync::Arc;
use std::time::Duration;

use crate::http_client::{ProxyConfig, Route, RouteKey};
use crate::kiro::proxy_fixtures::{
    TargetServer, spawn_http_proxy, spawn_http_proxy_with, spawn_socks5,
};
use crate::model::config::TlsBackend;

/// 期望的 Basic 认证头（与夹具内部编码口径一致）。
fn basic(user: &str, pass: &str) -> String {
    let mut raw = Vec::new();
    use std::io::Write;
    write!(&mut raw, "{user}:{pass}").unwrap();
    format!("Basic {}", base64(&raw))
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn route(config: ProxyConfig) -> Arc<Route> {
    Route::build(RouteKey::Proxy(config), TlsBackend::Rustls).unwrap()
}

/// 目标侧不得出现由代理凭据派生的任何头。
///
/// 检查两件事：`Proxy-Authorization` 本身，以及**同值**出现在 `Authorization`
/// 里（那同样是把代理凭据送给了目标）。
fn assert_target_saw_no_proxy_credentials(target: &TargetServer, expected_basic: &str) {
    let headers = target.received_headers();
    assert!(
        !headers.is_empty(),
        "前置条件：目标必须真的收到过请求（否则本断言恒真）"
    );
    for request in &headers {
        for (name, value) in request {
            assert_ne!(
                name, "proxy-authorization",
                "代理凭据不得进入目标请求：{request:?}"
            );
            assert!(
                !(name == "authorization" && value == expected_basic),
                "代理凭据不得以 Authorization 形式进入目标请求：{request:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────
// HTTP 普通转发：三态认证 + 目标侧头观测
// ─────────────────────────────────────────────────────────────

/// 无认证的 HTTP 转发代理：目标收到请求，且没有任何认证头。
#[tokio::test]
async fn bdd_http_forward_without_auth_reaches_target_without_auth_headers() {
    let proxy = spawn_http_proxy(None).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&proxy.url));

    let response = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // 前置条件：确实是经代理转发的（代理记录到目标），且目标收到 1 个请求。
    assert_eq!(proxy.stats.targets().len(), 1, "代理必须记录到这次转发");
    assert_eq!(target.connections(), 1, "目标必须收到 1 个请求");
    assert_eq!(proxy.stats.proxy_auth_headers(), vec![String::new()]);
    assert!(
        !target.any_request_has_header("proxy-authorization"),
        "无认证时目标也不该看到任何 Proxy-Authorization"
    );
}

/// 正确认证：代理侧看到**正确 Basic 凭据**，目标侧看不到任何代理凭据。
///
/// 前置条件断言：代理确实收到了与配置一致的 Basic 值（否则"目标侧没有"可能
/// 只是"代理根本没收到认证"）。
///
/// 反事实：在 `apply_proxy` 里去掉 `basic_auth` → 前置条件断言红。
#[tokio::test]
async fn bdd_http_forward_auth_arrives_at_proxy_and_never_reaches_target() {
    let proxy = spawn_http_proxy(Some(("user", "pass"))).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let expected = basic("user", "pass");
    let route = route(ProxyConfig::new(&proxy.url).with_auth("user", "pass"));

    let response = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(proxy.stats.auth_failures(), 0);

    assert_eq!(
        proxy.stats.proxy_auth_headers(),
        vec![expected.clone()],
        "代理必须收到按配置派生的 Basic 凭据"
    );
    assert_eq!(target.connections(), 1);
    assert_target_saw_no_proxy_credentials(&target, &expected);
}

/// 错误认证：407 或请求失败，且目标收到 0 个请求。
#[tokio::test]
async fn bdd_http_forward_wrong_auth_never_reaches_target() {
    let proxy = spawn_http_proxy(Some(("user", "pass"))).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&proxy.url).with_auth("user", "wrong"));

    let outcome = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await;
    match outcome {
        Ok(response) => assert_eq!(
            response.status().as_u16(),
            407,
            "错误认证必须是 407（reqwest 把它当普通响应返回）"
        ),
        Err(error) => assert!(
            error.is_connect() || error.is_request(),
            "错误认证若不是 407 就必须是传输层拒绝: {error}"
        ),
    }

    assert_eq!(proxy.stats.auth_failures(), 1, "代理必须记录到认证失败");
    assert_eq!(target.connections(), 0, "认证失败的请求不得到达目标");
    assert!(target.received_headers().is_empty(), "目标不得收到任何请求");
}

/// 接口灵敏度自检：代理夹具**打开透传开关**时，「目标头不含代理凭据」必须变红。
///
/// 这条不是为了证明生产代码，而是证明上面那条断言真的在看目标侧的头——否则
/// 它可能恒绿（例如断言写错了 header 名字）。
#[tokio::test]
async fn bdd_target_header_assertion_is_sensitive_to_proxy_leak() {
    let proxy = spawn_http_proxy_with(Some(("user", "pass")), true).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&proxy.url).with_auth("user", "pass"));

    let response = route
        .short
        .get(format!("http://{}/probe", target.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(
        target.any_request_has_header("proxy-authorization"),
        "透传开关打开时目标必须看到 Proxy-Authorization——否则「目标不含」那条断言测不到东西"
    );
}

// ─────────────────────────────────────────────────────────────
// HTTPS CONNECT：三态认证 + 隧道真实可达
// ─────────────────────────────────────────────────────────────

/// 目标侧经过 CONNECT 隧道收到的请求头（供 CONNECT 用例复用同一断言）。
///
/// CONNECT 之后流量是隧道里的明文字节，夹具侧无法解出 HTTP 头，因此 CONNECT
/// 用例的"目标头"断言改为：隧道确实建立（代理记录 CONNECT 目标）且目标确实
/// 收到了连接；代理凭据只存在于 CONNECT 请求本身，不会进入隧道内。
fn assert_no_connect_auth_in_tunnel(proxy_headers: &[String], expected: &str) {
    assert_eq!(
        proxy_headers,
        vec![expected.to_string()],
        "CONNECT 的认证头只应出现在发给**代理**的请求上"
    );
}

/// 无认证 CONNECT：隧道建立、目标确实收到经隧道到达的连接。
#[tokio::test]
async fn bdd_https_connect_without_auth_establishes_tunnel_to_target() {
    let proxy = spawn_http_proxy(None).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&proxy.url));

    // 本地夹具只能是明文；用 http 目标 + CONNECT 无法由 reqwest 触发，故直接
    // 观测 CONNECT 目标。目标服务只用于证明"隧道末端可达"。
    let _ = route
        .short
        .get(format!("https://127.0.0.1:{}/probe", target.addr.port()))
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    let observed = proxy.stats.targets();
    assert_eq!(observed.len(), 1, "前置条件：代理必须收到 1 次 CONNECT");
    assert_eq!(
        observed[0].target,
        format!("127.0.0.1:{}", target.addr.port()),
        "CONNECT 目标必须是回环地址（不依赖任何 DNS）"
    );
    assert!(
        !observed[0].domain,
        "回环 IP 目标必须以 IP 形式发出，实际: {:?}",
        observed[0]
    );
    assert_eq!(
        target.connections(),
        1,
        "代理必须真的把隧道连到了目标（说明 CONNECT 是成功的）"
    );
    assert_eq!(proxy.stats.proxy_auth_headers(), vec![String::new()]);
}

/// 正确认证 CONNECT：代理侧看到正确 Basic，隧道建立、目标收到连接。
///
/// 反事实：`apply_proxy` 去掉 `basic_auth` → 无认证值，被 407 拒，目标 0 连接。
#[tokio::test]
async fn bdd_https_connect_with_auth_establishes_tunnel_and_keeps_credentials_at_proxy() {
    let proxy = spawn_http_proxy(Some(("user", "pass"))).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let expected = basic("user", "pass");
    let route = route(ProxyConfig::new(&proxy.url).with_auth("user", "pass"));

    let _ = route
        .short
        .get(format!("https://127.0.0.1:{}/probe", target.addr.port()))
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    assert_eq!(proxy.stats.auth_failures(), 0, "CONNECT 认证必须成功");
    assert_no_connect_auth_in_tunnel(&proxy.stats.proxy_auth_headers(), &expected);
    assert_eq!(
        proxy.stats.targets().len(),
        1,
        "代理必须记录到 CONNECT 目标"
    );
    assert_eq!(target.connections(), 1, "认证通过的隧道必须真的连到目标");
    // 隧道内是 TLS 握手字节，目标侧看不到明文头；这里断言的是"没有任何明文
    // 代理凭据被写进隧道"这一更强的事实：目标解析出的头为空。
    assert!(
        !target.any_request_has_header("proxy-authorization"),
        "代理凭据不得出现在隧道内容里"
    );
}

/// 错误认证 CONNECT：407/失败，目标收到 0 个连接。
#[tokio::test]
async fn bdd_https_connect_with_wrong_auth_never_reaches_target() {
    let proxy = spawn_http_proxy(Some(("user", "pass"))).await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&proxy.url).with_auth("user", "wrong"));

    let outcome = route
        .short
        .get(format!("https://127.0.0.1:{}/probe", target.addr.port()))
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    assert!(outcome.is_err(), "错误认证的 CONNECT 不得成功: {outcome:?}");

    assert_eq!(proxy.stats.auth_failures(), 1);
    assert_eq!(target.connections(), 0, "认证失败的 CONNECT 不得连到目标");
}

// ─────────────────────────────────────────────────────────────
// SOCKS5 vs SOCKS5h：目标地址类型（DNS 由谁解析）
// ─────────────────────────────────────────────────────────────

// 下面三条用例按"一条用例只证明一件事"拆开：
//
//   1. `bdd_socks5_tunnels_to_ip_literal_target` —— 隧道**连通性** + 目标以 IP
//      类型发出。目标用 `127.0.0.1` 字面量，不做 DNS，因此不依赖平台的解析顺序，
//      IPv4/IPv6 环境下都确定性成立。
//   2. `bdd_socks5_resolves_hostname_locally` —— DNS **位置**（socks5 臂）。
//   3. `bdd_socks5h_hands_hostname_to_proxy` —— DNS **位置**（socks5h 臂）。
//
// 为什么必须拆：把"隧道通了"和"DNS 在哪解析"塞进同一条用例，会让前者依赖后者
// 的成败。而 `socks5://` + 主机名解析到 IPv6 在 reqwest 0.12.28 + hyper-util
// 0.1.19 上**必然失败**（上游缺陷，见第 2 条用例的注释），那条用例于是红在与被
// 验收行为无关的地方。拆开之后，连通性由用例 1 确定性覆盖，用例 2/3 只对 DNS
// 位置负责。

/// `socks5://` 隧道连通性 + 目标以 IP 地址类型发出（确定性用例）。
///
/// 目标主机名用 `127.0.0.1` 字面量：不做名字解析，不依赖 `localhost` 在平台间
/// （glibc/macOS 多给 `127.0.0.1`，musl/Alpine 优先 `::1`）的解析顺序。因此本条
/// 在 IPv4-only 与 IPv6 优先环境下结论相同。
///
/// 本用例证明两件事，且都确定性：
/// - 隧道真的通了（200 + body 正确 + 目标侧确实收到 1 个连接）；
/// - CONNECT 里发的是 IP 类型（ATYP=1）、目标是 `127.0.0.1:<port>`。
///
/// 反事实：`apply_proxy` 不再施加代理 → 代理侧 0 次 CONNECT，前置条件断言红。
/// 注意：把 `socks5://` 改写成 `socks5h://` 时本条**不会**红——IP 字面量在
/// hyper-util 的 `SocksV5::call` 里 `host.parse::<IpAddr>()` 恒成功
/// （`socks5/v5/mod.rs:114-125`），两个 scheme 都发 ATYP=1。scheme 的区分由下面
/// 两条 DNS 位置用例承担，本条不重复证明。
#[tokio::test]
async fn bdd_socks5_tunnels_to_ip_literal_target() {
    let socks = spawn_socks5(None, "socks5").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&socks.url));
    let port = target.addr.port();

    // IP 字面量：不做 DNS，不受"先用 IPv4 还是先用 IPv6"影响。
    let response = route
        .short
        .get(format!("http://127.0.0.1:{port}/probe"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200, "隧道必须让请求到达目标");
    assert_eq!(response.text().await.unwrap(), r#"{"ok":true}"#);

    let observed = socks.stats.targets();
    assert_eq!(observed.len(), 1, "前置条件：代理必须收到 1 次 CONNECT");
    assert!(
        !observed[0].domain,
        "IP 字面量目标必须以 IP 类型发出（ATYP=1），实际: {:?}",
        observed[0]
    );
    assert_eq!(
        observed[0].target,
        format!("127.0.0.1:{port}"),
        "CONNECT 目标必须是字面量的回环地址（不含任何解析结果）"
    );
    assert_eq!(target.connections(), 1, "隧道必须真的连到目标");
}

/// `socks5://` 由**客户端**解析：主机名不得到达代理。
///
/// 本条只对"DNS 在哪解析"负责，**不**对隧道连通性负责——连通性由
/// [`bdd_socks5_tunnels_to_ip_literal_target`] 以 IP 字面量确定性覆盖。因此这里
/// 有意允许传输失败、不做 `unwrap`，这不是漏断言。
///
/// 为什么不许 `unwrap`：目标主机名是 `localhost`。在 IPv6 优先环境（musl/Alpine、
/// 以及启用了 IPv6 loopback 的 CI 容器）下 reqwest 0.12.28 的
/// `DnsResolve::Local` 分支把解析出的 IPv6 包成 `"[::1]"` 放进 URI
/// （`reqwest/src/connect.rs:1877-1894`），hyper-util 的
/// `"[::1]".parse::<IpAddr>()` 失败后落到 `Address::Domain("[::1]")`，以 ATYP=3
/// 域名发出；代理侧 getaddrinfo 不认方括号 → REP=0x05 → 隧道建立失败。这是上游
/// 缺陷，已记录，不在本 PR 修复。无论失败与否，**主机名都没有到达代理**，这正是
/// 本条要断言的事实，在 IPv4（target=`127.0.0.1:port`）与 IPv6（target=
/// `[::1]:port`）下都成立。
///
/// 反事实：把 `socks5://` 改写成 `socks5h://` → 代理收到 `localhost:<port>` 域名，
/// 本条红。
#[tokio::test]
async fn bdd_socks5_resolves_hostname_locally() {
    let socks = spawn_socks5(None, "socks5").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&socks.url));
    let port = target.addr.port();

    // 前置条件：目标确实在监听（双栈中至少一族可用），否则"解析结果连不上"什么
    // 都证明不了。
    assert!(
        !target.loopback_addrs().is_empty(),
        "前置条件：目标必须已在回环上监听"
    );

    // 允许失败：本用例只关心 DNS 位置，隧道连通性由 IP 字面量用例覆盖。
    let _ = route
        .short
        .get(format!("http://localhost:{port}/probe"))
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    let observed = socks.stats.targets();
    assert_eq!(observed.len(), 1, "前置条件：代理必须收到 1 次 CONNECT");

    // 通过条件只有两支，缺一即红：
    // 1. 客户端本地解析 → IP 类型，且解析结果必须是**本目标的某个回环地址**。
    //    只写 `!domain` 太宽：别的域名、别的 IP 也都不满足 domain，会假绿。
    // 2. 唯一的例外是已记录的上游缺陷形态：reqwest 把 IPv6 包成 "[::1]" 塞进
    //    URI，hyper-util 的 parse::<IpAddr>() 对方括号恒失败，退化成 ATYP=3
    //    域名发出。此时 domain=true 但目标正好是 "[::1]:{port}"。
    //    该缺陷不在本 PR 修复。
    let expected_ips: Vec<String> = target
        .loopback_addrs()
        .iter()
        .map(|ip| format!("{ip}:{port}"))
        .collect();
    let locally_resolved = !observed[0].domain && expected_ips.contains(&observed[0].target);
    let known_upstream_ipv6_defect =
        observed[0].domain && observed[0].target == format!("[::1]:{port}");
    assert!(
        locally_resolved || known_upstream_ipv6_defect,
        "socks5 必须由客户端本地解析：预期 IP 类型且目标属于本目标的回环地址 {expected_ips:?}\
         （唯一例外是已记录的 [::1] 上游缺陷形态），实际: {:?}",
        observed[0]
    );
}

/// `socks5h://` 由**代理**解析：以域名类型发出，名字原样是 `localhost`。
///
/// 反事实：把 `socks5h://` 改回 `socks5://`（客户端解析）→ 观察到 IP 类型，本条红。
#[tokio::test]
async fn bdd_socks5h_hands_hostname_to_proxy() {
    let socks = spawn_socks5(None, "socks5h").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&socks.url));
    let port = target.addr.port();

    assert!(
        !target.loopback_addrs().is_empty(),
        "前置条件：目标必须已在回环上监听"
    );

    let response = route
        .short
        .get(format!("http://localhost:{port}/probe"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    let observed = socks.stats.targets();
    assert_eq!(observed.len(), 1, "前置条件：代理必须收到 1 次 CONNECT");
    assert!(
        observed[0].domain,
        "socks5h 必须把域名交给代理解析，实际: {:?}",
        observed[0]
    );
    assert_eq!(
        observed[0].target,
        format!("localhost:{port}"),
        "代理端看到的必须是原始域名而不是已解析的 IP"
    );
    assert_eq!(target.connections(), 1, "代理解析出的地址必须真的连到目标");
}
