//! HTTP Client 构建模块
//!
//! 提供统一的 HTTP Client 构建功能，支持代理配置和两种超时模式：
//! - `build_client`：全局总超时（适合短请求 / MCP / WebSearch）
//! - `build_idle_client`：idle/read 超时 + connect 超时（适合业务长流式响应）

use reqwest::{Client, ClientBuilder, Proxy};
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ProxyConfig {
    /// 代理地址，支持 http/https/socks5
    pub url: String,
    /// 代理认证用户名
    pub username: Option<String>,
    /// 代理认证密码
    pub password: Option<String>,
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
    let mut builder = Client::builder();

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

    if let Some(proxy_config) = proxy {
        let mut proxy = Proxy::all(&proxy_config.url)?;

        // 设置代理认证
        if let (Some(username), Some(password)) = (&proxy_config.username, &proxy_config.password) {
            proxy = proxy.basic_auth(username, password);
        }

        builder = builder.proxy(proxy);
        tracing::debug!("HTTP Client 使用代理: {}", proxy_config.url);
    }

    Ok(builder)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
