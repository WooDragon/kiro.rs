//! Test-only local proxy fixtures: a real SOCKS5 server (with optional user/pass
//! auth) and a real HTTP forward/CONNECT proxy.
//!
//! 这些夹具在进程内真实说协议，不是 mock：SOCKS5 按 RFC1928 握手、按 ATYP
//! 记录目标地址类型（域名 vs IPv4）——这正是"DNS 由谁解析"这条验收项的观测点。
//! 全部只监听 loopback，不触外网、不用任何账号凭据。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 一次被观察到的代理请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTarget {
    /// `true` = 客户端发来的是域名（由代理解析），`false` = 客户端已解析成 IP
    pub domain: bool,
    /// 目标 host:port 原文
    pub target: String,
}

#[derive(Default)]
pub struct ProxyStats {
    /// 建连（含握手）次数
    pub connections: AtomicUsize,
    /// 观察到的目标
    pub targets: parking_lot::Mutex<Vec<ObservedTarget>>,
    /// 认证失败次数
    pub auth_failures: AtomicUsize,
    /// 每个请求上**客户端实际发来的** `Proxy-Authorization` 值（原样，缺省为空串）。
    ///
    /// 这是"代理凭据确实以 Basic 形式到达代理"的观测点：值本身要能被断言成
    /// 期望的 Basic token，而不是只断言"认证成功了"。
    pub proxy_auth_headers: parking_lot::Mutex<Vec<String>>,
    /// 被**客户端**主动关闭的隧道数（已冻结/黑洞化的隧道的 EOF 观测点）
    pub tunnels_closed: AtomicUsize,
    /// 有隧道被客户端关闭时唤醒等待者
    pub tunnel_closed: tokio::sync::Notify,
    /// 客户端→上游方向累计字节数。
    ///
    /// 空闲期这个数字还在涨，就说明客户端确实在往这条隧道里写帧（H2 PING 是
    /// 17 字节的 DATA-less 帧）——用来区分"没有发 PING"与"发了 PING 但没关连接"。
    pub bytes_from_client: AtomicUsize,
    /// 有新的客户端字节计入 `bytes_from_client` 时唤醒等待者。
    pub bytes_observed: tokio::sync::Notify,
}

impl ProxyStats {
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn targets(&self) -> Vec<ObservedTarget> {
        self.targets.lock().clone()
    }

    pub fn auth_failures(&self) -> usize {
        self.auth_failures.load(Ordering::SeqCst)
    }

    /// 客户端发来的 `Proxy-Authorization` 值（按到达顺序，缺省记为 `""`）。
    pub fn proxy_auth_headers(&self) -> Vec<String> {
        self.proxy_auth_headers.lock().clone()
    }

    pub fn tunnels_closed(&self) -> usize {
        self.tunnels_closed.load(Ordering::SeqCst)
    }

    pub fn bytes_from_client(&self) -> usize {
        self.bytes_from_client.load(Ordering::SeqCst)
    }

    /// 等到"客户端关掉了某条隧道"这个确定性事件；外层 `timeout` 只决定失败多快。
    pub async fn wait_tunnel_closed(&self) {
        loop {
            let notified = self.tunnel_closed.notified();
            if self.tunnels_closed() > 0 {
                return;
            }
            notified.await;
        }
    }

    /// 等到"客户端→上游累计字节数超过 `target`"这个确定性事件。
    ///
    /// 与 [`Self::wait_tunnel_closed`] 同一形态：先建 `notified()` 再复查条件，
    /// 避免"条件已成立但 notify 已经过去"的丢失唤醒。外层 `timeout` 只决定失败
    /// 多快，判定依据是这个事件本身。
    pub async fn wait_bytes_over(&self, target: usize) {
        loop {
            let notified = self.bytes_observed.notified();
            if self.bytes_from_client() > target {
                return;
            }
            notified.await;
        }
    }
}

pub struct LocalProxy {
    pub url: String,
    pub stats: Arc<ProxyStats>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 启动真实 SOCKS5 代理；`auth` 为 `Some((user, pass))` 时要求用户名密码认证。
///
/// 只处理 CONNECT（TCP）；UDP ASSOCIATE 不在本项目范围内，直接拒绝。
pub async fn spawn_socks5(auth: Option<(&str, &str)>, scheme: &str) -> LocalProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::default());
    let stats_for_task = stats.clone();
    let auth = auth.map(|(user, pass)| (user.to_string(), pass.to_string()));

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            stats_for_task.connections.fetch_add(1, Ordering::SeqCst);
            let stats = stats_for_task.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                let _ = handle_socks5(stream, auth, stats).await;
            });
        }
    });

    LocalProxy {
        url: format!("{scheme}://{addr}"),
        stats,
        task,
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    auth: Option<(String, String)>,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;

    match &auth {
        None => {
            if !methods.contains(&0x00) {
                stream.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            stream.write_all(&[5, 0x00]).await?;
        }
        Some((user, pass)) => {
            if !methods.contains(&0x02) {
                stream.write_all(&[5, 0xff]).await?;
                return Ok(());
            }
            stream.write_all(&[5, 0x02]).await?;

            let mut ver = [0u8; 1];
            stream.read_exact(&mut ver).await?;
            let mut ulen = [0u8; 1];
            stream.read_exact(&mut ulen).await?;
            let mut got_user = vec![0u8; ulen[0] as usize];
            stream.read_exact(&mut got_user).await?;
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut got_pass = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut got_pass).await?;

            let ok = got_user == user.as_bytes() && got_pass == pass.as_bytes();
            if !ok {
                stats.auth_failures.fetch_add(1, Ordering::SeqCst);
                stream.write_all(&[1, 1]).await?;
                return Ok(());
            }
            stream.write_all(&[1, 0]).await?;
        }
    }

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[1] != 0x01 {
        // 只支持 CONNECT
        stream.write_all(&[5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    }

    let (domain, host) = match request[3] {
        0x01 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            (false, std::net::Ipv4Addr::from(raw).to_string())
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            (true, String::from_utf8_lossy(&raw).to_string())
        }
        0x04 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            (false, std::net::Ipv6Addr::from(raw).to_string())
        }
        _ => {
            stream.write_all(&[5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };
    let mut port_raw = [0u8; 2];
    stream.read_exact(&mut port_raw).await?;
    let port = u16::from_be_bytes(port_raw);

    stats.targets.lock().push(ObservedTarget {
        domain,
        target: format!("{host}:{port}"),
    });

    // 用域名时由代理解析（socks5h 语义）；用 IP 时直接连。
    let upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(_) => {
            stream.write_all(&[5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };
    stream
        .write_all(&[5, 0x00, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    relay(stream, upstream).await
}

/// 启动真实 HTTP 代理：支持 CONNECT 隧道与绝对 URI 的普通转发。
pub async fn spawn_http_proxy(auth: Option<(&str, &str)>) -> LocalProxy {
    spawn_http_proxy_with(auth, false).await
}

/// 与 [`spawn_http_proxy`] 相同，但 `forward_proxy_auth = true` 时故意把客户端的
/// `Proxy-Authorization` 透传给目标。
///
/// 这个开关只为**证明断言灵敏**而存在：它让"目标侧请求头不含代理凭据"这条断言
/// 有确定的反事实形态（打开它就必须红）。生产代理不会这么做。
pub async fn spawn_http_proxy_with(
    auth: Option<(&str, &str)>,
    forward_proxy_auth: bool,
) -> LocalProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::default());
    let stats_for_task = stats.clone();
    let auth = auth.map(|(user, pass)| {
        use std::io::Write;
        let mut encoded = Vec::new();
        write!(&mut encoded, "{user}:{pass}").unwrap();
        format!("Basic {}", base64(&encoded))
    });

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            stats_for_task.connections.fetch_add(1, Ordering::SeqCst);
            let stats = stats_for_task.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                let _ = handle_http(stream, auth, forward_proxy_auth, stats).await;
            });
        }
    });

    LocalProxy {
        url: format!("http://{addr}"),
        stats,
        task,
    }
}

async fn handle_http(
    mut stream: TcpStream,
    auth: Option<String>,
    forward_proxy_auth: bool,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    let head = read_http_head(&mut stream).await?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let got = lines
        .clone()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("proxy-authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    stats.proxy_auth_headers.lock().push(got.clone());

    if auth.as_ref().is_some_and(|expected| &got != expected) {
        stats.auth_failures.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        stats.targets.lock().push(ObservedTarget {
            domain: target
                .rsplit_once(':')
                .map(|(host, _)| host.parse::<std::net::IpAddr>().is_err())
                .unwrap_or(false),
            target: target.clone(),
        });
        let (host, port) = target.rsplit_once(':').unwrap_or((target.as_str(), "443"));
        let port: u16 = port.parse().unwrap_or(443);
        let upstream = match TcpStream::connect((host, port)).await {
            Ok(stream) => stream,
            Err(_) => {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return relay(stream, upstream).await;
    }

    // 普通转发：target 是绝对 URI，改写成 origin-form 再转发。
    let parsed = match reqwest::Url::parse(&target) {
        Ok(url) => url,
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    };
    let host = parsed.host_str().unwrap_or_default().to_string();
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    stats.targets.lock().push(ObservedTarget {
        domain: true,
        target: format!("{host}:{port}"),
    });

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    let origin_form = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let forwarded: Vec<String> = lines
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let name = line.split(':').next().unwrap_or_default();
            let proxy_auth = name.eq_ignore_ascii_case("proxy-authorization");
            let proxy_conn = name.eq_ignore_ascii_case("proxy-connection");
            !proxy_conn && (!proxy_auth || forward_proxy_auth)
        })
        .map(|line| line.to_string())
        .collect();
    let request = format!(
        "{method} {origin_form} HTTP/1.1\r\nHost: {host}\r\n{}\r\n\r\n",
        forwarded.join("\r\n")
    );
    upstream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = upstream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n")
            && let Some(split) = response.windows(4).position(|w| w == b"\r\n\r\n")
        {
            let head_len = split + 4;
            let head = String::from_utf8_lossy(&response[..head_len]).to_string();
            let content_length = head
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if response.len() >= head_len + content_length {
                break;
            }
        }
    }
    stream.write_all(&response).await?;
    Ok(())
}

async fn read_http_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let mut rest = buffer.split_off(position + 4);
            // 请求体（普通转发时可能有）按 Content-Length 补读。
            let head = String::from_utf8_lossy(&buffer).to_string();
            let content_length = head
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let mut remaining = content_length.saturating_sub(rest.len());
            while remaining > 0 {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                rest.extend_from_slice(&chunk[..read]);
                remaining = remaining.saturating_sub(read);
            }
            let mut head = head;
            head.push_str("\r\n\r\n");
            head.push_str(&String::from_utf8_lossy(&rest));
            return Ok(head);
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

async fn relay(mut client: TcpStream, mut upstream: TcpStream) -> std::io::Result<()> {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
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

/// 一个请求收到的全部头：`(name, value)`，name 已转小写。
pub type RequestHeaders = Vec<(String, String)>;

/// 受控的 TCP 目标服务：接受连接并回一句固定响应，记录被连次数与收到的请求头。
pub struct TargetServer {
    pub addr: std::net::SocketAddr,
    pub connections: Arc<AtomicUsize>,
    /// 每个请求收到的请求头（`(name, value)`，name 转小写）。
    ///
    /// 这是「代理凭据不得进入目标请求」的唯一有效观测面：只看代理侧认证成功
    /// 无法排除"顺带把 Proxy-Authorization 也转发给目标"。
    pub received_headers: Arc<parking_lot::Mutex<Vec<RequestHeaders>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TargetServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TargetServer {
    /// `body` 作为 HTTP 响应体返回；`connections` 记录连接建立次数。
    pub async fn spawn(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let received_headers = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let counter = connections.clone();
        let headers = received_headers.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let headers = headers.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 8192];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    headers.lock().push(parse_request_headers(&buffer[..read]));
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            addr,
            connections,
            received_headers,
            task,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// 所有请求收到的全部请求头（每个请求一份）。
    pub fn received_headers(&self) -> Vec<RequestHeaders> {
        self.received_headers.lock().clone()
    }

    /// 是否有任一请求带指定头（name 不区分大小写）。
    pub fn any_request_has_header(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.received_headers()
            .iter()
            .any(|headers| headers.iter().any(|(got, _)| *got == name))
    }
}

/// 解析 HTTP 请求头（只看报文头，忽略 body）。
fn parse_request_headers(raw: &[u8]) -> RequestHeaders {
    let text = String::from_utf8_lossy(raw);
    text.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

/// 明文 HTTP/2（h2c）目标：用于观测"代理隧道上是否复用同一条 H2 连接"。
pub struct H2TargetServer {
    pub addr: std::net::SocketAddr,
    /// 目标侧接受的 TCP 连接数（等于经代理建立的隧道数）
    pub connections: Arc<AtomicUsize>,
    /// 处理过的 H2 请求数
    pub requests: Arc<AtomicUsize>,
    /// 置位后**当时已建立的**连接停止被 poll：TCP 仍打开，但任何帧（含 PING）
    /// 都不再被处理——这才是"被静默掐断的隧道"的真实形态。之后新建的连接
    /// 保持健康，否则测试无法区分"剔除旧隧道"与"整台目标都死了"。
    blackhole: Arc<tokio::sync::watch::Sender<usize>>,
    /// 请求处理闸门：`Some(_)` 时 handler 在**读到请求之后、回响应之前**停住，
    /// 直到测试放行。用于把"多个请求真的同时在途"变成确定性事件，而不是
    /// 用墙钟推断并发度。
    hold: Arc<tokio::sync::watch::Sender<bool>>,
    /// 每有一个请求进入 handler（并已停在闸门处）就唤醒一次。
    arrived: Arc<tokio::sync::Notify>,
    /// 当前停在闸门里、尚未被放行的请求数。
    held: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for H2TargetServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl H2TargetServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (blackhole, _) = tokio::sync::watch::channel(0usize);
        let blackhole = Arc::new(blackhole);
        let (hold, _) = tokio::sync::watch::channel(false);
        let hold = Arc::new(hold);
        let arrived = Arc::new(tokio::sync::Notify::new());
        let held = Arc::new(AtomicUsize::new(0));
        let (connections_for_task, requests_for_task) = (connections.clone(), requests.clone());
        let blackhole_for_task = blackhole.clone();
        let hold_for_task = hold.clone();
        let arrived_for_task = arrived.clone();
        let held_for_task = held.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                // 连接序号从 1 开始，黑洞阈值就是"当时已建立的条数"。
                let connection_index = connections_for_task.fetch_add(1, Ordering::SeqCst) + 1;
                let requests = requests_for_task.clone();
                let mut blackhole = blackhole_for_task.subscribe();
                let mut hold = hold_for_task.subscribe();
                let arrived = arrived_for_task.clone();
                let held = held_for_task.clone();
                tokio::spawn(async move {
                    let mut connection = match h2::server::handshake(stream).await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    loop {
                        // h2 的 PING 由 `accept()` 驱动的连接任务在帧层自动应答。
                        // 因此"黑洞"必须是停止 poll 本连接（而不是等到某个请求到来
                        // 才不应答）——否则空闲期的 PING 仍会被回，隧道永远看起来健康。
                        if connection_index <= *blackhole.borrow() {
                            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                            return;
                        }
                        tokio::select! {
                            flag = blackhole.changed() => {
                                let closed = flag.is_err();
                                if closed || connection_index <= *blackhole.borrow() {
                                    // 不再 poll：TCP 保持打开，帧全部滞留不处理。
                                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                                    return;
                                }
                            }
                            accepted = connection.accept() => {
                                let Some(accepted) = accepted else { break };
                                let Ok((_request, mut respond)) = accepted else {
                                    break;
                                };
                                // 请求到达数目本身就是隧道复用的证据（同一连接承载 N 次请求）。
                                requests.fetch_add(1, Ordering::SeqCst);
                                // 请求闸门：把"多个请求同时在途"变成可观测事件。
                                if *hold.borrow() {
                                    held.fetch_add(1, Ordering::SeqCst);
                                    arrived.notify_waiters();
                                    // 等待放行；`hold` 翻回 false 也放行（收尾用）。
                                    while *hold.borrow() {
                                        if hold.changed().await.is_err() {
                                            break;
                                        }
                                    }
                                    held.fetch_sub(1, Ordering::SeqCst);
                                }
                                let body = r#"{"ok":true}"#;
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(())
                                    .unwrap();
                                if let Ok(mut send) = respond.send_response(response, false) {
                                    let _ = send.send_data(
                                        bytes::Bytes::from_static(body.as_bytes()),
                                        true,
                                    );
                                }
                            }
                        }
                    }
                });
            }
        });

        Self {
            addr,
            connections,
            requests,
            blackhole,
            hold,
            arrived,
            held,
            task,
        }
    }

    /// 让**当前已建立的**连接停止应答（含 PING），但不断开 TCP。
    /// 之后新建的连接不受影响。
    pub fn blackhole(&self) {
        self.blackhole
            .send_replace(self.connections.load(Ordering::SeqCst));
    }

    /// 打开请求闸门：之后到达的请求停在 handler 里，直到 [`Self::release_held`]。
    pub fn hold_requests(&self) {
        self.hold.send_replace(true);
    }

    /// 放行闸门里所有停住的请求，并关闭闸门。
    pub fn release_held(&self) {
        self.hold.send_replace(false);
    }

    /// 当前停在闸门里、未被放行的请求数。
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    /// 等到"累计 `target` 个请求正同时停在闸门里"这个确定性事件。
    ///
    /// 与 [`ProxyStats::wait_tunnel_closed`] 同一形态：先建 `notified()` 再复查
    /// 条件，避免条件已成立而 notify 已经过去造成的丢失唤醒。
    pub async fn wait_held(&self, target: usize) {
        loop {
            let notified = self.arrived.notified();
            if self.held() >= target {
                return;
            }
            notified.await;
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// 可观测**并发度**的 loopback OAuth 刷新服务。
///
/// 与 `proxy_pool_bdd_isolation::RefreshServer` 的差别只有一个目的：这里额外记录
/// "同一时刻在 handler 里的请求数" 与它的历史最大值，并在需要时把 handler 卡住。
/// 这直接回答「并发刷新是否仍被串行」——串行时最大值恒为 1，穿透时会出现 2。
///
/// 只监听 loopback，不触外网。
pub struct CountingRefreshServer {
    pub url: String,
    state: Arc<CountingRefreshState>,
    task: tokio::task::JoinHandle<()>,
}

struct CountingRefreshState {
    requests: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    /// 每次进入 handler 时唤醒
    entered: tokio::sync::Notify,
    /// 为真时 handler 阻塞，直到收到一次放行
    hold: std::sync::atomic::AtomicBool,
    release: tokio::sync::Semaphore,
}

impl Drop for CountingRefreshServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CountingRefreshServer {
    pub async fn spawn() -> Self {
        use axum::{Router, routing::any};
        let state = Arc::new(CountingRefreshState {
            requests: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            hold: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Semaphore::new(0),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let state_for_route = state.clone();
        let app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let state = state_for_route.clone();
            async move {
                use axum::body::to_bytes;
                let _ = to_bytes(request.into_body(), 16384).await;
                state.requests.fetch_add(1, Ordering::SeqCst);
                let now = state.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                state.max_in_flight.fetch_max(now, Ordering::SeqCst);
                state.entered.notify_waiters();
                if state.hold.load(Ordering::SeqCst) {
                    state.release.acquire().await.unwrap().forget();
                }
                state.in_flight.fetch_sub(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({
                    "accessToken": "refreshed-access",
                    "refreshToken": format!("{}x", "r".repeat(120)),
                    "expiresIn": 3600,
                    "profileArn": "arn:aws:codewhisperer:us-east-1:111111111111:profile/test",
                }))
            }
        }));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }

    pub fn count(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    /// handler 内同时处理的请求数的历史最大值。
    pub fn max_in_flight(&self) -> usize {
        self.state.max_in_flight.load(Ordering::SeqCst)
    }

    /// 让之后的 handler 进入后阻塞，直到 [`Self::release_one`]。
    pub fn hold(&self) {
        self.state.hold.store(true, Ordering::SeqCst);
    }

    pub fn release_one(&self) {
        self.state.release.add_permits(1);
    }

    /// 等到刷新服务累计收到至少 `count` 个请求；`timeout` 由调用方给出。
    pub async fn wait_count(&self, count: usize) {
        loop {
            let notified = self.state.entered.notified();
            if self.count() >= count {
                return;
            }
            notified.await;
        }
    }
}

/// 真实 SOCKS5 代理，但把 CONNECT 目标整体转发到一个固定地址（透明重定向）。
///
/// 用于让 HTTP/2 客户端经真实 SOCKS5 握手连到本地明文 H2 目标——TLS/ALPN 不参与，
/// 观测的是"隧道复用"本身。
pub async fn spawn_socks5_redirect(redirect_to: std::net::SocketAddr) -> LocalProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::default());
    let stats_for_task = stats.clone();

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            stats_for_task.connections.fetch_add(1, Ordering::SeqCst);
            let stats = stats_for_task.clone();
            tokio::spawn(async move {
                let _ = handle_socks5_redirect(stream, redirect_to, stats).await;
            });
        }
    });

    LocalProxy {
        url: format!("socks5://{addr}"),
        stats,
        task,
    }
}

async fn handle_socks5_redirect(
    mut stream: TcpStream,
    redirect_to: std::net::SocketAddr,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0x00]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let (domain, host) = match request[3] {
        0x01 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            (false, std::net::Ipv4Addr::from(raw).to_string())
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            (true, String::from_utf8_lossy(&raw).to_string())
        }
        _ => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            (false, std::net::Ipv6Addr::from(raw).to_string())
        }
    };
    let mut port_raw = [0u8; 2];
    stream.read_exact(&mut port_raw).await?;
    let port = u16::from_be_bytes(port_raw);
    stats.targets.lock().push(ObservedTarget {
        domain,
        target: format!("{host}:{port}"),
    });

    let upstream = TcpStream::connect(redirect_to).await?;
    stream
        .write_all(&[5, 0x00, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    relay_observe_client_close(stream, upstream, stats).await
}

/// 与 [`relay`] 等价，但额外观测**客户端**是否关掉了自己那一侧。
///
/// 不能用 `copy_bidirectional`：它要等两个方向都结束才返回，而黑洞化的目标
/// 永不关闭 TCP，于是"客户端已放弃隧道"这个事件永远观测不到。这里分方向转发，
/// 客户端读端 EOF 即是剔除证据。
async fn relay_observe_client_close(
    client: TcpStream,
    upstream: TcpStream,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let stats_for_upstream = stats.clone();
    let to_upstream = async {
        let mut total = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            let read = match client_read.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            };
            total += read;
            stats_for_upstream
                .bytes_from_client
                .fetch_add(read, Ordering::SeqCst);
            stats_for_upstream.bytes_observed.notify_waiters();
            if upstream_write.write_all(&chunk[..read]).await.is_err() {
                break;
            }
        }
        // 客户端已关闭（FIN/RST）：这正是 keep-alive 剔除隧道的可观测终点。
        stats.tunnels_closed.fetch_add(1, Ordering::SeqCst);
        stats.tunnel_closed.notify_waiters();
        let _ = upstream_write.shutdown().await;
        Ok::<usize, std::io::Error>(total)
    };
    let to_client = async {
        let copied = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
        copied
    };
    tokio::pin!(to_upstream);
    tokio::pin!(to_client);
    // 任一方向结束就收拾这条隧道：黑洞化的目标不会主动关，若等双方都结束，
    // "客户端已放弃"这个事件就永远观测不到。
    tokio::select! {
        result = &mut to_upstream => result.map(|_| ()),
        result = &mut to_client => result.map(|_| ()),
    }
}
