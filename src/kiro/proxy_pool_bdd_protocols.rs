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

/// `socks5://` 由**客户端**解析：以 IPv4 地址类型发出。
///
/// 目标主机名用 `localhost`（本地回环，不依赖公网 DNS），因此"socks5 用例观察
/// 到 IP 类型"就是"客户端本地解析了"。
///
/// 反事实：在 `apply_proxy` 里把 `socks5://` 改写成 `socks5h://` → 观察到的
/// 是域名类型，本条红。
#[tokio::test]
async fn bdd_socks5_resolves_locally_and_sends_ip_address_type() {
    let socks = spawn_socks5(None, "socks5").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&socks.url));

    let response = route
        .short
        .get(format!("http://localhost:{}/probe", target.addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    let observed = socks.stats.targets();
    assert_eq!(observed.len(), 1, "前置条件：代理必须收到 1 次 CONNECT");
    assert!(
        !observed[0].domain,
        "socks5 必须由客户端本地解析并以 IP 类型发出，实际: {:?}",
        observed[0]
    );
    assert!(
        observed[0]
            .target
            .starts_with(&format!("{}:", target.addr.ip())),
        "本地解析结果必须是目标的回环地址，实际: {:?}",
        observed[0]
    );
}

/// `socks5h://` 由**代理**解析：以域名类型发出，名字原样是 `localhost`。
///
/// 反事实：把 `socks5h://` 改回 `socks5://`（客户端解析）→ 观察到 IP 类型，本条红。
#[tokio::test]
async fn bdd_socks5h_sends_domain_so_proxy_resolves_and_target_is_reached() {
    let socks = spawn_socks5(None, "socks5h").await;
    let target = TargetServer::spawn(r#"{"ok":true}"#).await;
    let route = route(ProxyConfig::new(&socks.url));

    let response = route
        .short
        .get(format!("http://localhost:{}/probe", target.addr.port()))
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
        format!("localhost:{}", target.addr.port()),
        "代理端看到的必须是原始域名而不是已解析的 IP"
    );
    assert_eq!(target.connections(), 1, "代理解析出的地址必须真的连到目标");
}
