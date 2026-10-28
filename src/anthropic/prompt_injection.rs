use super::types::Message;

/// 每次 HTTP 请求只在客户端原历史中准备一次，后续转换和计量共享结果。
pub(super) fn apply(messages: &mut [Message], prompt: &str) {
    if prompt.is_empty() {
        return;
    }
    let Some(message) = messages.iter_mut().find(|message| message.role == "user") else {
        return;
    };
    match &mut message.content {
        serde_json::Value::String(text) => prepend(text, prompt),
        serde_json::Value::Array(blocks) => {
            let text = blocks.iter_mut().find_map(|block| {
                if block.get("type").and_then(serde_json::Value::as_str) != Some("text") {
                    return None;
                }
                block.get_mut("text").filter(|text| text.is_string())
            });
            if let Some(serde_json::Value::String(text)) = text {
                prepend(text, prompt);
            } else {
                blocks.insert(0, serde_json::json!({"type":"text", "text":prompt}));
            }
        }
        _ => {}
    }
}

fn prepend(text: &mut String, prompt: &str) {
    *text = if text.is_empty() {
        prompt.to_owned()
    } else {
        format!("{prompt}\n\n{text}")
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn messages(content: Value) -> Vec<Message> {
        serde_json::from_value(json!([
            {"role":"assistant","content":"before"},
            {"role":"user","content":content},
            {"role":"user","content":"later"}
        ]))
        .unwrap()
    }

    #[test]
    fn first_user_string_preserves_bytes_and_never_guesses_deduplication() {
        for original in ["", "hello", " \r\n中文\t ", "PREFIX\n\nalready"] {
            let mut actual = messages(json!(original));
            apply(&mut actual, "PREFIX");
            let expected = if original.is_empty() {
                "PREFIX".into()
            } else {
                format!("PREFIX\n\n{original}")
            };
            assert_eq!(actual[1].content, expected);
            assert_eq!(actual[0].content, "before");
            assert_eq!(actual[2].content, "later");
        }
    }

    #[test]
    fn array_only_changes_first_valid_top_level_text() {
        for text in ["", " original\r\n "] {
            let content = json!([
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}},
                {"type":"text","text":42},
                {"type":"tool_result","tool_use_id":"id","content":[{"type":"text","text":"nested"}]},
                {"type":"text","text":text,"cache_control":{"type":"ephemeral"},"extra":true},
                {"type":"text","text":"last"}
            ]);
            let mut expected = content.clone();
            expected[3]["text"] = json!(if text.is_empty() {
                "PREFIX".into()
            } else {
                format!("PREFIX\n\n{text}")
            });
            let mut actual = messages(content);
            apply(&mut actual, "PREFIX");
            assert_eq!(actual[1].content, expected);
        }
    }

    #[test]
    fn arrays_without_valid_text_get_one_block_without_touching_originals() {
        for content in [
            json!([]),
            json!([{"type":"text"},{"type":"text","text":null}]),
            json!([
                {"type":"image","source":{"data":"unchanged"}},
                {"type":"tool_result","content":[{"type":"text","text":"nested"}]}
            ]),
        ] {
            let mut actual = messages(content.clone());
            apply(&mut actual, "PREFIX");
            assert_eq!(actual[1].content[0], json!({"type":"text","text":"PREFIX"}));
            assert_eq!(
                &actual[1].content.as_array().unwrap()[1..],
                content.as_array().unwrap()
            );
        }
    }

    #[test]
    fn disabled_invalid_and_no_user_are_unchanged() {
        for content in [
            Value::Null,
            json!(17),
            json!({"text":"invalid"}),
            json!(false),
        ] {
            let mut actual = messages(content);
            let original = serde_json::to_value(&actual).unwrap();
            apply(&mut actual, "PREFIX");
            assert_eq!(serde_json::to_value(actual).unwrap(), original);
        }
        let mut actual = messages(json!([{"type":"text","text":"original"}]));
        let original = serde_json::to_value(&actual).unwrap();
        apply(&mut actual, "");
        assert_eq!(serde_json::to_value(&actual).unwrap(), original);
        actual.retain(|message| message.role != "user");
        let original = serde_json::to_value(&actual).unwrap();
        apply(&mut actual, "PREFIX");
        assert_eq!(serde_json::to_value(actual).unwrap(), original);
    }

    #[test]
    fn resent_history_and_compaction_prepare_each_http_independently() {
        let original = messages(json!("first"));
        for _ in 0..2 {
            let mut request = original.clone();
            apply(&mut request, "PREFIX");
            assert_eq!(request[1].content, "PREFIX\n\nfirst");
        }
        let mut compacted = vec![Message {
            role: "user".into(),
            content: json!("summary"),
        }];
        apply(&mut compacted, "NEW");
        assert_eq!(compacted[0].content, "NEW\n\nsummary");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::apply;
    use crate::anthropic::{
        middleware::AppState, prompt_cache::PromptCacheTracker,
        router::create_router_with_provider, types::MessagesRequest,
    };
    use crate::kiro::{
        endpoint::{KiroEndpoint, RequestContext},
        model::credentials::KiroCredentials,
        provider::KiroProvider,
        token_manager::MultiTokenManager,
    };
    use crate::model::{
        config::{CcStreamingMode, Config, PromptCacheMode},
        registry::ModelRegistry,
    };
    use axum::{Json, Router, routing::post};
    use serde_json::{Value, json};
    use std::{collections::HashMap, sync::Arc, time::Duration};
    use tokio::sync::mpsc;

    struct Server {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Server {
        async fn start(router: Router) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            Self { url, task }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct LocalEndpoint(String);

    impl KiroEndpoint for LocalEndpoint {
        fn name(&self) -> &'static str {
            "local"
        }
        fn api_url(&self, _: &RequestContext<'_>) -> String {
            format!("{}/api", self.0)
        }
        fn mcp_url(&self, _: &RequestContext<'_>) -> String {
            format!("{}/mcp", self.0)
        }
        fn decorate_api(
            &self,
            request: reqwest::RequestBuilder,
            _: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            request
        }
        fn decorate_mcp(
            &self,
            request: reqwest::RequestBuilder,
            _: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            request
        }
        fn transform_api_body(&self, body: &str, _: &RequestContext<'_>) -> String {
            body.to_owned()
        }
    }

    fn response_frame() -> Vec<u8> {
        use crate::kiro::parser::crc::crc32;
        let mut headers = Vec::new();
        for (name, value) in [
            (":message-type", "event"),
            (":event-type", "assistantResponseEvent"),
        ] {
            headers.push(name.len() as u8);
            headers.extend_from_slice(name.as_bytes());
            headers.push(7);
            headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
            headers.extend_from_slice(value.as_bytes());
        }
        let payload = br#"{"content":"OK"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&((16 + headers.len() + payload.len()) as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame.extend(headers);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&crc32(&frame).to_be_bytes());
        frame
    }

    async fn upstream() -> (Server, mpsc::UnboundedReceiver<Value>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let api_sender = sender.clone();
        let router = Router::new().route("/api", post(move |Json(body): Json<Value>| {
            let sender = api_sender.clone();
            async move {
                assert!(body.pointer("/conversationState/currentMessage/userInputMessage/modelId").unwrap().is_string());
                sender.send(body).unwrap();
                response_frame()
            }
        })).route("/mcp", post(move |Json(body): Json<Value>| {
            let sender = sender.clone();
            async move {
                assert_eq!(body["method"], "tools/call");
                sender.send(body).unwrap();
                Json(json!({"jsonrpc":"2.0","id":"test","result":{"content":[],"isError":false}}))
            }
        }));
        (Server::start(router).await, receiver)
    }

    fn provider(url: &str) -> (KiroProvider, Arc<MultiTokenManager>) {
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![KiroCredentials {
                    id: Some(1),
                    kiro_api_key: Some("ksk_local_test".into()),
                    ..Default::default()
                }],
                None,
                None,
                false,
                Arc::new(ModelRegistry::builtin()),
            )
            .unwrap(),
        );
        let endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::from([(
            "local".into(),
            Arc::new(LocalEndpoint(url.into())) as Arc<dyn KiroEndpoint>,
        )]);
        (
            KiroProvider::with_proxy(manager.clone(), None, endpoints, "local".into()),
            manager,
        )
    }

    async fn app(
        url: &str,
        prompt: &str,
        mode: CcStreamingMode,
    ) -> (Server, Arc<parking_lot::RwLock<String>>) {
        let (provider, manager) = provider(url);
        let handle = manager.prompt_injection_handle();
        *handle.write() = prompt.into();
        let router = create_router_with_provider(
            "local-key",
            Some(provider),
            false,
            PromptCacheMode::Emulated,
            mode,
            Arc::new(ModelRegistry::builtin()),
            handle.clone(),
        );
        (Server::start(router).await, handle)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap()
    }

    async fn send(app: &Server, path: &str, body: &Value) -> reqwest::Response {
        let response = client()
            .post(format!("{}{path}", app.url))
            .header("x-api-key", "local-key")
            .json(body)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{}", response.status());
        response
    }

    async fn capture(receiver: &mut mpsc::UnboundedReceiver<Value>) -> Value {
        tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn fixture(content: Value) -> Value {
        json!({"model":"claude-sonnet-4-5","max_tokens":128,"system":"system plan reminder",
            "messages":[{"role":"user","content":content},{"role":"user","content":"consecutive"},
                {"role":"assistant","content":[{"type":"tool_use","id":"tool-id","name":"lookup","input":{"keep":"bytes"}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"tool-id","content":[{"type":"text","text":"result bytes"}]}]},
                {"role":"assistant","content":"done"},{"role":"user","content":"latest"}],
            "tools":[{"name":"lookup","description":"lookup","input_schema":{"type":"object"}}]})
    }

    fn without_random_id(mut body: Value) -> Value {
        body["conversationState"]["conversationId"] = json!("fixed");
        body["conversationState"]["agentContinuationId"] = json!("fixed");
        body
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_routes_preserve_system_history_media_and_tool_structure() {
        let (upstream, mut receiver) = upstream().await;
        let (app, handle) = app(&upstream.url, "", CcStreamingMode::Prefix).await;
        for path in ["/v1/messages", "/cc/v1/messages"] {
            for content in [
                json!(" original\r\n "),
                json!([
                    {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}},
                    {"type":"text","text":" original\r\n ","cache_control":{"type":"ephemeral"}},
                    {"type":"text","text":"second"}
                ]),
            ] {
                let request = fixture(content);
                *handle.write() = String::new();
                let baseline_usage: Value = send(&app, path, &request).await.json().await.unwrap();
                let baseline = without_random_id(capture(&mut receiver).await);
                *handle.write() = "PREFIX".into();
                let injected_usage: Value = send(&app, path, &request).await.json().await.unwrap();
                let mut injected = without_random_id(capture(&mut receiver).await);
                let history = injected["conversationState"]["history"]
                    .as_array_mut()
                    .unwrap();
                assert!(
                    history[0]["userInputMessage"]["content"]
                        .as_str()
                        .unwrap()
                        .starts_with("system plan reminder")
                );
                let text = history[2]["userInputMessage"]["content"].as_str().unwrap();
                assert!(text.starts_with("PREFIX\n\n original\r\n "));
                assert_eq!(text.matches("PREFIX").count(), 1);
                history[2]["userInputMessage"]["content"] =
                    json!(text.strip_prefix("PREFIX\n\n").unwrap());
                assert_eq!(
                    injected, baseline,
                    "all other converted fields must survive"
                );
                let total = |response: &Value| {
                    response["usage"]["input_tokens"].as_i64().unwrap()
                        + response["usage"]["cache_creation_input_tokens"]
                            .as_i64()
                            .unwrap_or(0)
                        + response["usage"]["cache_read_input_tokens"]
                            .as_i64()
                            .unwrap_or(0)
                };
                let original: MessagesRequest = serde_json::from_value(request).unwrap();
                assert_eq!(
                    total(&baseline_usage),
                    crate::token::count_all_tokens(
                        original.model,
                        original.system,
                        original.messages,
                        original.tools
                    ) as i64
                );
                assert!(total(&injected_usage) > total(&baseline_usage));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_streaming_mode_uses_the_same_preparation() {
        let (upstream, mut receiver) = upstream().await;
        for mode in [
            CcStreamingMode::Buffered,
            CcStreamingMode::Prefix,
            CcStreamingMode::Streaming,
        ] {
            let (app, _) = app(&upstream.url, "PREFIX", mode).await;
            for path in ["/v1/messages", "/cc/v1/messages"] {
                let body = json!({"model":"claude-sonnet-4-5","max_tokens":128,"stream":true,"messages":[{"role":"user","content":"original"}]});
                let output = send(&app, path, &body).await.text().await.unwrap();
                assert!(output.contains("message_stop"));
                let sent = capture(&mut receiver).await;
                assert_eq!(
                    sent.pointer("/conversationState/currentMessage/userInputMessage/content")
                        .unwrap(),
                    "PREFIX\n\noriginal"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn count_tokens_routes_and_websearch_bypass_share_the_same_rule() {
        let (upstream, mut receiver) = upstream().await;
        let (app, handle) = app(&upstream.url, "PREFIX", CcStreamingMode::Prefix).await;
        for prefix in ["/v1", "/cc/v1"] {
            for (tools, bypass) in [
                (json!(null), false),
                (json!([]), false),
                (json!([{"name":"web_search","input_schema":{}}]), true),
                (json!([{"name":"lookup","input_schema":{}}]), false),
                (
                    json!([{"name":"web_search","input_schema":{}},{"name":"other","input_schema":{}}]),
                    false,
                ),
            ] {
                let body = json!({"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"query"}],"tools":tools});
                let result: Value = send(&app, &format!("{prefix}/messages/count_tokens"), &body)
                    .await
                    .json()
                    .await
                    .unwrap();
                let mut expected: MessagesRequest = serde_json::from_value(json!({"max_tokens":128,"model":body["model"],"messages":body["messages"],"tools":tools})).unwrap();
                if !bypass {
                    apply(&mut expected.messages, "PREFIX");
                }
                let count = crate::token::count_all_tokens(
                    expected.model,
                    expected.system,
                    expected.messages,
                    expected.tools,
                );
                assert_eq!(result["input_tokens"], count);
            }
            let body = json!({"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":"Perform a web search for the query: query"}],"tools":[{"name":"web_search","input_schema":{}}]});
            let count_path = format!("{prefix}/messages/count_tokens");
            let baseline_count: Value = send(&app, &count_path, &body).await.json().await.unwrap();
            send(&app, &format!("{prefix}/messages"), &body)
                .await
                .text()
                .await
                .unwrap();
            let injected = capture(&mut receiver).await;
            *handle.write() = String::new();
            let disabled_count: Value = send(&app, &count_path, &body).await.json().await.unwrap();
            send(&app, &format!("{prefix}/messages"), &body)
                .await
                .text()
                .await
                .unwrap();
            let disabled = capture(&mut receiver).await;
            assert_eq!(injected["params"], disabled["params"]);
            assert_eq!(injected["params"]["arguments"]["query"], "query");
            assert_eq!(baseline_count, disabled_count);
            *handle.write() = "PREFIX".into();
        }
    }

    #[test]
    fn cache_prefix_change_invalidates_only_breakpoints_after_injection() {
        let tracker = PromptCacheTracker::default();
        let original = json!({"model":"claude-sonnet-4-5","max_tokens":128,
            "system":[{"text":"system ".repeat(1200),"cache_control":{"type":"ephemeral"}}],
            "messages":[{"role":"user","content":[{"type":"text","text":"message ".repeat(1200),"cache_control":{"type":"ephemeral"}}]}]});
        let prepare = |prompt: &str| {
            let mut request: MessagesRequest = serde_json::from_value(original.clone()).unwrap();
            apply(&mut request.messages, prompt);
            tracker.build_profile(&request).unwrap()
        };
        let profile_a = prepare("A");
        tracker.update("account", Some(&profile_a), 1);
        let hit = tracker.compute("account", Some(&prepare("A")), 1);
        assert!(hit.cache_read_input_tokens > 0);
        assert_eq!(hit.cache_creation_input_tokens, 0);
        let partial = tracker.compute("account", Some(&prepare("B")), 1);
        assert!(
            partial.cache_read_input_tokens > 0,
            "earlier system breakpoint remains valid"
        );
        assert!(
            partial.cache_creation_input_tokens > 0,
            "crossing injection must miss"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn image_only_and_tool_result_first_users_are_prefixed_without_losing_structure() {
        let (upstream, mut receiver) = upstream().await;
        let (app, handle) = app(&upstream.url, "", CcStreamingMode::Prefix).await;
        let image = json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}});
        let image_request = json!({"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":[image]}]});
        let mut tool_request = fixture(json!("unused"));
        tool_request["messages"].as_array_mut().unwrap().drain(..2);
        for path in ["/v1/messages", "/cc/v1/messages"] {
            for (request, pointer) in [
                (
                    &image_request,
                    "/conversationState/currentMessage/userInputMessage/content",
                ),
                (
                    &tool_request,
                    "/conversationState/history/3/userInputMessage/content",
                ),
            ] {
                *handle.write() = String::new();
                send(&app, path, request).await.text().await.unwrap();
                let baseline = without_random_id(capture(&mut receiver).await);
                *handle.write() = "PREFIX".into();
                send(&app, path, request).await.text().await.unwrap();
                let mut injected = without_random_id(capture(&mut receiver).await);
                assert_eq!(injected.pointer(pointer).unwrap(), "PREFIX");
                *injected.pointer_mut(pointer).unwrap() = json!("");
                assert_eq!(injected, baseline);
            }
        }
    }

    #[test]
    fn tools_breakpoint_survives_prompt_updates_and_disabled_profile_is_unchanged() {
        let tracker = PromptCacheTracker::default();
        let mut request: MessagesRequest = serde_json::from_value(json!({"model":"claude-sonnet-4-5","max_tokens":128,
            "tools":[{"name":"lookup","description":"tool ".repeat(1200),"input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],
            "messages":[{"role":"user","content":[{"type":"text","text":"original ".repeat(1200),"cache_control":{"type":"ephemeral"}}]}]})).unwrap();
        let baseline = tracker.build_profile(&request).unwrap();
        apply(&mut request.messages, "");
        let disabled = tracker.build_profile(&request).unwrap();
        tracker.update("disabled", Some(&baseline), 1);
        assert_eq!(baseline.local_total_tokens(), disabled.local_total_tokens());
        assert_eq!(
            tracker
                .compute("disabled", Some(&disabled), 1)
                .cache_creation_input_tokens,
            0
        );
        apply(&mut request.messages, "PREFIX");
        let changed = tracker.build_profile(&request).unwrap();
        let usage = tracker.compute("disabled", Some(&changed), 1);
        assert!(usage.cache_read_input_tokens > 0);
        assert!(usage.cache_creation_input_tokens > 0);
    }

    #[test]
    fn injected_cache_keeps_media_identity_separate_from_token_ruler() {
        let tracker = PromptCacheTracker::default();
        for nested in [false, true] {
            let prepare = |data: &str| {
                let image = json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":data}});
                let block = if nested {
                    json!({"type":"tool_result","tool_use_id":"tool-id","content":[image]})
                } else {
                    image
                };
                let mut request: MessagesRequest = serde_json::from_value(json!({"model":"claude-sonnet-4-5","max_tokens":128,
                    "messages":[{"role":"user","content":[{"type":"text","text":"original","cache_control":{"type":"ephemeral"}},block]}]})).unwrap();
                apply(&mut request.messages, "PREFIX");
                tracker.build_profile(&request).unwrap()
            };
            let short = prepare("AA==");
            let long = prepare(&"AQID".repeat(10000));
            assert_eq!(short.local_total_tokens(), long.local_total_tokens());
            tracker.update("media", Some(&short), 1);
            let same = tracker.compute("media", Some(&short), 1);
            let changed = tracker.compute("media", Some(&long), 1);
            assert_eq!(same.cache_creation_input_tokens, 0);
            assert!(changed.cache_creation_input_tokens > 0);
            assert!(changed.cache_read_input_tokens < same.cache_read_input_tokens);
        }
    }

    #[test]
    fn external_counter_and_inflight_snapshot_are_isolated() {
        const CHILD: &str = "KIRO_PROMPT_INJECTION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "anthropic::prompt_injection::integration_tests::external_counter_and_inflight_snapshot_are_isolated", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "child stdout: {}\nchild stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            return;
        }
        // OnceLock 只在独立子进程中初始化，不修改生产计数接口或其他测试的配置。
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(remote_snapshot_scenario());
    }

    async fn remote_snapshot_scenario() {
        let (sender, mut counts) = mpsc::unbounded_channel();
        let counter = Server::start(Router::new().route(
            "/count",
            post(
                move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                    let sender = sender.clone();
                    async move {
                        assert_eq!(headers["x-api-key"], "counter-key");
                        let (release, wait) = tokio::sync::oneshot::channel();
                        sender.send((body, release)).unwrap();
                        tokio::time::timeout(Duration::from_secs(15), wait)
                            .await
                            .unwrap()
                            .unwrap();
                        Json(json!({"input_tokens":6000}))
                    }
                },
            ),
        ))
        .await;
        crate::token::init_config(crate::token::CountTokensConfig {
            api_url: Some(format!("{}/count", counter.url)),
            api_key: Some("counter-key".into()),
            auth_type: "x-api-key".into(),
            ..Default::default()
        });
        let (upstream, mut sent) = upstream().await;
        let (provider, manager) = provider(&upstream.url);
        let handle = manager.prompt_injection_handle();
        let mut state = AppState::new(
            "local-key",
            false,
            PromptCacheMode::Emulated,
            CcStreamingMode::Prefix,
            Arc::new(ModelRegistry::builtin()),
        )
        .with_kiro_provider(provider);
        state.prompt_injection = handle.clone();
        let router = Router::new()
            .route(
                "/v1/messages",
                post(crate::anthropic::handlers::post_messages),
            )
            .route(
                "/cc/v1/messages",
                post(crate::anthropic::handlers::post_messages_cc),
            )
            .route(
                "/v1/messages/count_tokens",
                post(crate::anthropic::handlers::count_tokens),
            )
            .route(
                "/cc/v1/messages/count_tokens",
                post(crate::anthropic::handlers::count_tokens),
            )
            .with_state(state.clone());
        let app = Server::start(router).await;
        let original = json!({"model":"claude-sonnet-4-5","max_tokens":128,
        "system":[{"text":"x-anthropic-billing-header: remove me"}],
        "messages":[{"role":"user","content":[
            {"type":"text","text":"original ".repeat(2500),"cache_control":{"type":"ephemeral"}},
            {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}
        ]}]});
        for prefix in ["/v1", "/cc/v1"] {
            *handle.write() = "DO NOT INJECT INTO SEARCH".into();
            let search = json!({"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":"Perform a web search for the query: query"}],"tools":[{"name":"web_search","input_schema":{}}]});
            for suffix in ["/messages/count_tokens", "/messages"] {
                let request = client()
                    .post(format!("{}{prefix}{suffix}", app.url))
                    .json(&search);
                let response =
                    tokio::spawn(
                        async move { request.send().await.unwrap().text().await.unwrap() },
                    );
                let (counted, release) =
                    tokio::time::timeout(Duration::from_secs(15), counts.recv())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(counted["messages"], search["messages"]);
                release.send(()).unwrap();
                response.await.unwrap();
                if suffix == "/messages" {
                    assert_eq!(
                        capture(&mut sent).await["params"]["arguments"]["query"],
                        "query"
                    );
                }
            }
            let mut original = original.clone();
            original["messages"][0]["content"][0]["text"] =
                json!(format!("{prefix} {}", "original ".repeat(2500)));
            let prepared = |prompt: &str| {
                let mut request: MessagesRequest =
                    serde_json::from_value(original.clone()).unwrap();
                request.strip_anthropic_billing_headers();
                apply(&mut request.messages, prompt);
                request
            };
            for counting in [true, false] {
                let path = if counting {
                    format!("{prefix}/messages/count_tokens")
                } else {
                    format!("{prefix}/messages")
                };
                let profile_a = state.prompt_cache.build_profile(&prepared("A")).unwrap();
                if !counting {
                    state.prompt_cache.update("cred:1", Some(&profile_a), 1);
                }
                for prompt in ["A", "B with more words"] {
                    *handle.write() = prompt.into();
                    let request = client()
                        .post(format!("{}{path}", app.url))
                        .header("x-api-key", "local-key")
                        .json(&original);
                    let response = tokio::spawn(async move {
                        request.send().await.unwrap().json::<Value>().await.unwrap()
                    });
                    let (counted, release) =
                        tokio::time::timeout(Duration::from_secs(15), counts.recv())
                            .await
                            .unwrap()
                            .unwrap();
                    let expected = prepared(prompt);
                    assert_eq!(
                        counted["messages"],
                        serde_json::to_value(&expected.messages).unwrap()
                    );
                    assert!(counted["system"].is_null() || counted["system"] == json!([]));
                    // HTTP 计数已进入：此时更新配置，后续 cache 构建和发送不得再读 B。
                    *handle.write() = "B with more words".into();
                    release.send(()).unwrap();
                    let response = response.await.unwrap();
                    if counting {
                        assert_eq!(response["input_tokens"], 6000);
                    } else {
                        let body = capture(&mut sent).await;
                        let user = body
                            .pointer("/conversationState/currentMessage/userInputMessage")
                            .unwrap();
                        assert_eq!(user["content"], expected.messages[0].content[0]["text"]);
                        assert_eq!(user["images"][0]["source"]["bytes"], "AA==");
                        let usage = &response["usage"];
                        if prompt == "A" {
                            assert!(usage["cache_read_input_tokens"].as_i64().unwrap() > 0);
                            assert_eq!(usage["cache_creation_input_tokens"], 0);
                        } else {
                            assert_eq!(usage["cache_read_input_tokens"], 0);
                            assert!(usage["cache_creation_input_tokens"].as_i64().unwrap() > 0);
                        }
                        assert_eq!(
                            usage["input_tokens"].as_i64().unwrap()
                                + usage["cache_read_input_tokens"].as_i64().unwrap()
                                + usage["cache_creation_input_tokens"].as_i64().unwrap(),
                            6000
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn app_state_defaults_to_disabled_and_clones_share_the_handle() {
        let state = AppState::new(
            "key",
            false,
            PromptCacheMode::Off,
            CcStreamingMode::Prefix,
            Arc::new(ModelRegistry::builtin()),
        );
        assert!(state.prompt_injection.read().is_empty());
        *state.clone().prompt_injection.write() = "B".into();
        assert_eq!(*state.prompt_injection.read(), "B");
    }
}
