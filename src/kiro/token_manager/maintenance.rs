//! 认证维护与业务禁用状态分离；所有 deadline 都是进程单调毫秒。
use super::*;

const RETRY_MS: u64 = 15 * 60_000;

/// 同一个认证 deadline 同时记录等待是成功调度还是失败退避，防止 usage 绕过退避。
#[derive(Clone, Copy)]
pub(super) enum AuthSchedule {
    Refreshed(u64),
    Failed(u64),
}

impl AuthSchedule {
    fn blocks(self, now_ms: u64, reason: Option<DisabledReason>) -> bool {
        match self {
            Self::Refreshed(at) => now_ms < at && !reason.is_some_and(DisabledReason::is_auth),
            Self::Failed(at) => now_ms < at,
        }
    }
}

#[derive(Clone)]
pub(super) struct EntryIdentity {
    instance: Arc<TokioMutex<()>>,
    revision: u64,
}

impl EntryIdentity {
    pub(super) fn of(entry: &CredentialEntry) -> Self {
        Self {
            instance: entry.profile_lookup_lock.clone(),
            revision: entry.state_revision,
        }
    }

    pub(super) fn same_instance(&self, entry: &CredentialEntry) -> bool {
        Arc::ptr_eq(&self.instance, &entry.profile_lookup_lock)
    }

    pub(super) fn matches(&self, entry: &CredentialEntry) -> bool {
        self.same_instance(entry) && self.revision == entry.state_revision
    }
}

impl DisabledReason {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::TooManyFailures => "TooManyFailures",
            Self::TooManyRefreshFailures => "TooManyRefreshFailures",
            Self::QuotaExceeded => "QuotaExceeded",
            Self::InvalidRefreshToken => "InvalidRefreshToken",
            Self::InvalidConfig => "InvalidConfig",
        }
    }

    pub(super) fn from_saved(reason: Option<&str>) -> Self {
        match reason {
            Some("TooManyFailures") => Self::TooManyFailures,
            Some("TooManyRefreshFailures") => Self::TooManyRefreshFailures,
            Some("QuotaExceeded") => Self::QuotaExceeded,
            Some("InvalidRefreshToken") => Self::InvalidRefreshToken,
            Some("InvalidConfig") => Self::InvalidConfig,
            _ => Self::Manual,
        }
    }

    fn is_auth(self) -> bool {
        matches!(
            self,
            Self::InvalidRefreshToken | Self::TooManyRefreshFailures
        )
    }
}

impl CredentialEntry {
    pub(super) fn set_reason(&mut self, reason: Option<DisabledReason>) {
        if self.disabled_reason != reason || self.disabled != reason.is_some() {
            self.state_revision = self.state_revision.wrapping_add(1);
            self.quota_retry_after_ms = None;
        }
        self.disabled = reason.is_some();
        self.disabled_reason = reason;
    }
}

pub(super) enum RefreshMode<'a> {
    Business,
    Force,
    Maintenance(&'a EntryIdentity),
}

fn same_auth_material(left: &KiroCredentials, right: &KiroCredentials) -> bool {
    left.access_token == right.access_token
        && left.refresh_token == right.refresh_token
        && left.auth_method == right.auth_method
        && left.client_id == right.client_id
        && left.client_secret == right.client_secret
        && left.auth_region == right.auth_region
        && left.region == right.region
        && left.kiro_api_key == right.kiro_api_key
}

pub(super) fn auth_delay_ms(credentials: &KiroCredentials, now: DateTime<Utc>) -> u64 {
    let remaining = credentials
        .expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|expires| {
            (expires.with_timezone(&Utc) - now)
                .num_milliseconds()
                .max(0) as u64
        })
        .unwrap_or(0);
    remaining.saturating_sub((remaining / 5).min(10 * 60_000))
}

pub(super) fn quota_delay_ms(reset: Option<f64>, now_unix_ms: u64) -> u64 {
    let Some(reset) = reset.filter(|reset| reset.is_finite()) else {
        return RETRY_MS;
    };
    let milliseconds = reset * 1000.0;
    if !milliseconds.is_finite()
        || milliseconds >= u64::MAX as f64
        || milliseconds <= now_unix_ms as f64
    {
        return RETRY_MS;
    }
    (milliseconds as u64)
        .saturating_sub(now_unix_ms)
        .min(RETRY_MS)
}

impl MultiTokenManager {
    pub(super) fn persist_credentials_observed(&self) {
        if let Err(error) = self.persist_credentials() {
            tracing::warn!(error = %error, "凭据持久化失败，内存状态已更新但未保存");
        }
    }

    pub(super) async fn refresh_credentials(
        &self,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<KiroCredentials> {
        let proxy = credentials.effective_proxy(self.proxy.as_ref());
        #[cfg(test)]
        {
            let url = self.test_refresh_url.lock().clone();
            refresh_token_at(credentials, &self.config, proxy.as_ref(), url.as_deref()).await
        }
        #[cfg(not(test))]
        refresh_token(credentials, &self.config, proxy.as_ref()).await
    }

    /// 全局锁覆盖重读、HTTP 和内存 apply；保存始终在锁外。
    pub(super) async fn refresh_auth(
        &self,
        id: u64,
        mode: RefreshMode<'_>,
    ) -> anyhow::Result<bool> {
        if matches!(mode, RefreshMode::Business) {
            let current = self.credentials_for_id(id)?;
            if current.is_api_key_credential()
                || (!is_token_expired(&current) && !is_token_expiring_soon(&current))
            {
                return Ok(false);
            }
        }
        let (refreshed, restored) = {
            let _guard = self.refresh_lock.lock().await;
            self.refresh_auth_locked(id, mode).await?
        };
        if refreshed {
            if restored {
                self.select_highest_priority();
            }
            self.persist_credentials_observed();
        }
        Ok(refreshed)
    }

    async fn refresh_auth_locked(
        &self,
        id: u64,
        mode: RefreshMode<'_>,
    ) -> anyhow::Result<(bool, bool)> {
        let (current, identity, auth_disabled) = {
            let entries = self.entries.lock();
            let entry = entries
                .iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?;
            if let RefreshMode::Maintenance(expected) = &mode {
                if !expected.matches(entry) {
                    bail!("凭据在维护期间已改变");
                }
                if entry
                    .auth_retry_after_ms
                    .is_some_and(|deadline| deadline.blocks(self.now_ms(), entry.disabled_reason))
                {
                    return Ok((false, false));
                }
            }
            (
                entry.credentials.clone(),
                EntryIdentity::of(entry),
                entry.disabled_reason.is_some_and(DisabledReason::is_auth),
            )
        };
        if current.is_api_key_credential() {
            if matches!(mode, RefreshMode::Force) {
                bail!("API Key 凭据不支持刷新 Token");
            }
            return Ok((false, false));
        }
        let force = matches!(mode, RefreshMode::Force)
            || (matches!(mode, RefreshMode::Maintenance(_)) && auth_disabled);
        if !force && !is_token_expired(&current) && !is_token_expiring_soon(&current) {
            return Ok((false, false));
        }
        let result = self.refresh_credentials(&current).await;
        let still_current = self.entries.lock().iter().any(|entry| {
            entry.id == id
                && identity.same_instance(entry)
                && same_auth_material(&entry.credentials, &current)
        });
        // Even an HTTP error belongs to the old generation, not to its replacement's health.
        if !still_current {
            return Err(Self::stale_refresh_error(id));
        }
        let refreshed = result?;
        // 后台允许短 TTL；不能把旧的 5 分钟业务窗口当成响应有效期下限。
        let invalid = refreshed.access_token.as_deref().is_none_or(str::is_empty)
            || is_token_expiring_within(&refreshed, 0).unwrap_or(true)
            || (matches!(mode, RefreshMode::Business) && is_token_expired(&refreshed));
        if !matches!(mode, RefreshMode::Force) && invalid {
            bail!("刷新后的 Token 仍然无效或已过期");
        }
        self.apply_refresh_response(id, &current, &identity, refreshed, mode)
    }

    pub(super) fn apply_refresh_response(
        &self,
        id: u64,
        current: &KiroCredentials,
        identity: &EntryIdentity,
        refreshed: KiroCredentials,
        mode: RefreshMode<'_>,
    ) -> anyhow::Result<(bool, bool)> {
        let mut entries = self.entries.lock();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .filter(|entry| {
                identity.same_instance(entry) && same_auth_material(&entry.credentials, current)
            })
            .ok_or_else(|| Self::stale_refresh_error(id))?;
        entry.credentials = Self::merge_refreshed_credentials(&entry.credentials, refreshed);
        let restore = matches!(mode, RefreshMode::Maintenance(_))
            && identity.matches(entry)
            && entry.disabled_reason.is_some_and(DisabledReason::is_auth);
        if restore {
            entry.set_reason(None);
            entry.refresh_failure_count = 0;
            tracing::info!(credential_id = id, "后台实际刷新成功，解除认证禁用");
        }
        if matches!(mode, RefreshMode::Force) {
            entry.refresh_failure_count = 0;
        }
        // 业务/强制刷新也可使后台沿新 TTL 等待，但不约束业务和显式刷新。
        entry.auth_retry_after_ms = Some(AuthSchedule::Refreshed(
            self.now_ms()
                .saturating_add(auth_delay_ms(&entry.credentials, Utc::now())),
        ));
        Ok((true, restore))
    }

    /// 首轮立即运行；顺序轮次无重叠，跳过网络耗时期间积压的 tick。
    pub fn spawn_maintenance(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_maintenance_every(StdDuration::from_secs(60))
    }

    pub(super) fn spawn_maintenance_every(
        self: &Arc<Self>,
        period: StdDuration,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let Some(manager) = weak.upgrade() else { break };
                manager.maintain_once().await;
            }
        })
    }

    pub(super) async fn maintain_once(&self) {
        #[cfg(test)]
        self.test_maintenance_round_count
            .fetch_add(1, Ordering::SeqCst);
        let snapshots: Vec<_> = self
            .entries
            .lock()
            .iter()
            .map(|entry| (entry.id, EntryIdentity::of(entry)))
            .collect();
        for (id, identity) in snapshots {
            self.maintain_entry(id, identity).await;
        }
    }

    async fn maintain_entry(&self, id: u64, identity: EntryIdentity) {
        let oauth = {
            let entries = self.entries.lock();
            let Some(entry) = entries
                .iter()
                .find(|entry| entry.id == id && identity.matches(entry))
            else {
                return;
            };
            if entry
                .auth_retry_after_ms
                .is_some_and(|deadline| deadline.blocks(self.now_ms(), entry.disabled_reason))
            {
                // 成功后的等待允许 quota 查询；失败后的等待不允许绕过认证节流。
                if matches!(entry.auth_retry_after_ms, Some(AuthSchedule::Failed(_))) {
                    return;
                }
                false
            } else {
                !entry.credentials.is_api_key_credential()
            }
        };
        if oauth
            && let Err(error) = self
                .refresh_auth(id, RefreshMode::Maintenance(&identity))
                .await
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.id == id && identity.matches(entry))
            {
                entry.auth_retry_after_ms =
                    Some(AuthSchedule::Failed(self.now_ms().saturating_add(RETRY_MS)));
            }
            if let Some(invalid) = error.downcast_ref::<RefreshTokenInvalidError>() {
                tracing::warn!(
                    credential_id = id,
                    error_code = invalid.error_code,
                    "后台认证失败，需要重新授权；15分钟后重试"
                );
            } else {
                // 不打印包含上游 body 的错误，避免 token/PII 被回显。
                tracing::warn!(credential_id = id, "后台认证失败，15分钟后重试");
            }
            return;
        }
        let quota_identity = {
            let mut entries = self.entries.lock();
            let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.id == id && identity.same_instance(entry))
            else {
                return;
            };
            // 锁等待期间也可能进入失败退避；正常 skip 不得让 quota 绕过它。
            if matches!(entry.auth_retry_after_ms, Some(AuthSchedule::Failed(at)) if self.now_ms() < at)
            {
                return;
            }
            if entry.disabled_reason != Some(DisabledReason::QuotaExceeded)
                || !identity.matches(entry)
                || entry
                    .quota_retry_after_ms
                    .is_some_and(|deadline| self.now_ms() < deadline)
            {
                return;
            }
            EntryIdentity::of(entry)
        };
        let result = self.get_usage_limits_inner(id, Some(&quota_identity)).await;
        let restored = {
            let mut entries = self.entries.lock();
            let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.id == id && quota_identity.matches(entry))
            else {
                return;
            };
            let delay = result
                .as_ref()
                .ok()
                .map(|limits| quota_delay_ms(limits.next_date_reset, self.now_unix_ms()))
                .unwrap_or(RETRY_MS);
            entry.quota_retry_after_ms = Some(self.now_ms().saturating_add(delay));
            if result
                .as_ref()
                .is_ok_and(UsageLimitsResponse::has_confirmed_remaining)
                && entry.disabled_reason == Some(DisabledReason::QuotaExceeded)
            {
                entry.set_reason(None);
                entry.failure_count = 0;
                tracing::info!(credential_id = id, "余额确认恢复，解除额度禁用");
                true
            } else {
                false
            }
        };
        if result.is_err() {
            tracing::warn!(credential_id = id, "后台余额查询失败，稍后重试");
        }
        if restored {
            self.select_highest_priority();
            self.persist_credentials_observed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TestClock, profile_test_manager, valid_access_credential};
    use super::*;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::any,
    };
    use serde_json::{Value, json};
    use std::sync::atomic::AtomicBool;
    use tokio::sync::{Notify, Semaphore};

    struct HttpState {
        requests: Mutex<Vec<(String, Value)>>,
        status: Mutex<StatusCode>,
        ttl: AtomicU64,
        usage: Mutex<Value>,
        pause: AtomicBool,
        entered: Notify,
        release: Semaphore,
    }

    struct Server {
        state: Arc<HttpState>,
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn handle(
        State(state): State<Arc<HttpState>>,
        request: Request<Body>,
    ) -> axum::response::Response {
        let path = request.uri().path().to_string();
        if path == "/getUsageLimits" {
            assert!(request.headers().contains_key("authorization"));
        }
        let body = to_bytes(request.into_body(), 16384).await.unwrap();
        let body: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        state.requests.lock().push((path.clone(), body.clone()));
        state.entered.notify_one();
        if state.pause.load(Ordering::SeqCst) {
            state.release.acquire().await.unwrap().forget();
        }
        if path == "/token" {
            assert!(body["refreshToken"].as_str().unwrap().len() >= 100);
            if body.get("clientId").is_some() {
                assert_eq!(body["grantType"], "refresh_token");
                assert_eq!(body["clientSecret"], "synthetic-secret");
            }
            let status = *state.status.lock();
            let response = if status.is_success() {
                json!({"accessToken":"new-access", "refreshToken":format!("{}x", body["refreshToken"].as_str().unwrap()), "expiresIn":state.ttl.load(Ordering::SeqCst)})
            } else {
                json!({"error":"invalid_client"})
            };
            return (status, Json(response)).into_response();
        }
        assert_eq!(path, "/getUsageLimits");
        Json(state.usage.lock().clone()).into_response()
    }

    impl Server {
        async fn new() -> Self {
            let state = Arc::new(HttpState {
                requests: Mutex::new(vec![]),
                status: Mutex::new(StatusCode::OK),
                ttl: AtomicU64::new(3600),
                usage: Mutex::new(
                    json!({"usageBreakdownList":[{"currentUsageWithPrecision":10,"usageLimitWithPrecision":10}]}),
                ),
                pause: AtomicBool::new(false),
                entered: Notify::new(),
                release: Semaphore::new(0),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let app = Router::new()
                .fallback(any(handle))
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self { state, url, task }
        }
        fn attach(&self, manager: &MultiTokenManager) {
            *manager.test_refresh_url.lock() = Some(format!("{}/token", self.url));
            *manager.test_usage_limits_url.lock() = Some(format!("{}/getUsageLimits", self.url));
        }
        fn count(&self, path: &str) -> usize {
            self.state
                .requests
                .lock()
                .iter()
                .filter(|request| request.0 == path)
                .count()
        }
        async fn wait_count(&self, path: &str, count: usize) {
            tokio::time::timeout(StdDuration::from_secs(5), async {
                while self.count(path) < count {
                    self.state.entered.notified().await;
                }
            })
            .await
            .unwrap();
        }
    }

    fn oauth(id: u64, expired: bool) -> KiroCredentials {
        let mut credential = valid_access_credential(&format!("access-{id}"), 0);
        credential.id = Some(id);
        credential.refresh_token = Some(format!("{id}{}", "r".repeat(120)));
        credential.profile_arn =
            Some("arn:aws:codewhisperer:us-east-1:111111111111:profile/test".into());
        if expired {
            credential.expires_at = Some((Utc::now() - Duration::minutes(1)).to_rfc3339());
        }
        credential
    }

    fn manager(clock: Arc<TestClock>, credentials: Vec<KiroCredentials>) -> Arc<MultiTokenManager> {
        Arc::new(profile_test_manager(clock, credentials, None, true))
    }

    async fn poll_waiter_pending(
        future: std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) {
        let mut future = future;
        std::future::poll_fn(|context| {
            assert!(
                future.as_mut().poll(context).is_pending(),
                "maintenance must wait for refresh lock"
            );
            std::task::Poll::Ready(())
        })
        .await;
    }

    fn refreshed_deadline(manager: &MultiTokenManager) -> u64 {
        match manager.entries.lock()[0].auth_retry_after_ms {
            Some(AuthSchedule::Refreshed(deadline)) => deadline,
            _ => panic!("successful refresh schedule must be preserved"),
        }
    }

    #[tokio::test]
    async fn maintenance_waiter_preserves_concurrent_refresh_schedule() {
        for force in [true, false] {
            let server = Server::new().await;
            server
                .state
                .ttl
                .store(if force { 300 } else { 360 }, Ordering::SeqCst);
            server.state.pause.store(true, Ordering::SeqCst);
            let clock = TestClock::new();
            let manager = manager(clock.clone(), vec![oauth(1, true)]);
            server.attach(&manager);
            manager.report_quota_exhausted(1);
            let worker = manager.clone();
            let first = tokio::spawn(async move {
                worker
                    .refresh_auth(
                        1,
                        if force {
                            RefreshMode::Force
                        } else {
                            RefreshMode::Business
                        },
                    )
                    .await
            });
            server.wait_count("/token", 1).await;
            let mut waiter = Box::pin(manager.maintain_once());
            poll_waiter_pending(waiter.as_mut()).await;
            server.state.pause.store(false, Ordering::SeqCst);
            server.state.release.add_permits(1);
            assert!(first.await.unwrap().unwrap());
            let deadline = refreshed_deadline(&manager);
            waiter.await;
            assert_eq!(refreshed_deadline(&manager), deadline);
            assert_eq!(server.count("/token"), 1);
            assert_eq!(
                server.count("/getUsageLimits"),
                1,
                "successful wait must not block quota"
            );
            clock.advance_ms(deadline - manager.now_ms() - 1);
            manager.maintain_once().await;
            assert_eq!(server.count("/token"), 1);
            clock.advance_ms(1);
            manager.maintain_once().await;
            assert_eq!(
                server.count("/token"),
                2,
                "short TTL must renew at its original deadline"
            );
            assert!(refreshed_deadline(&manager) > deadline);
        }
    }

    #[tokio::test]
    async fn maintenance_waiter_preserves_existing_failure_backoff() {
        let server = Server::new().await;
        let clock = TestClock::new();
        let manager = manager(clock.clone(), vec![oauth(1, true)]);
        server.attach(&manager);
        manager.report_quota_exhausted(1);
        let guard = manager.refresh_lock.lock().await;
        let mut waiter = Box::pin(manager.maintain_once());
        poll_waiter_pending(waiter.as_mut()).await;
        let deadline = manager.now_ms() + RETRY_MS;
        manager.entries.lock()[0].auth_retry_after_ms = Some(AuthSchedule::Failed(deadline));
        clock.advance_ms(1000);
        drop(guard);
        waiter.await;
        assert!(matches!(manager.entries.lock()[0].auth_retry_after_ms,
            Some(AuthSchedule::Failed(at)) if at == deadline));
        assert_eq!(
            server.state.requests.lock().len(),
            0,
            "failed wait must not reach quota"
        );
    }

    #[tokio::test]
    async fn maintenance_add_short_ttl_retains_validation_refresh_schedule() {
        let server = Server::new().await;
        server.state.ttl.store(300, Ordering::SeqCst);
        let clock = TestClock::new();
        let manager = manager(clock.clone(), vec![]);
        server.attach(&manager);
        manager.add_credential(oauth(1, true)).await.unwrap();
        assert_eq!(server.count("/token"), 1);
        manager.maintain_once().await;
        assert_eq!(
            server.count("/token"),
            1,
            "add validation already refreshed this token"
        );
        let deadline = refreshed_deadline(&manager);
        clock.advance_ms(deadline - manager.now_ms() - 1);
        manager.maintain_once().await;
        assert_eq!(server.count("/token"), 1);
        clock.advance_ms(1);
        manager.maintain_once().await;
        assert_eq!(server.count("/token"), 2);
        assert!(refreshed_deadline(&manager) > deadline);
        assert_eq!(server.count("/getUsageLimits"), 0);
        let id = manager
            .add_credential(KiroCredentials {
                kiro_api_key: Some("synthetic-new-key".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            manager
                .entries
                .lock()
                .iter()
                .find(|entry| entry.id == id)
                .unwrap()
                .auth_retry_after_ms
                .is_none()
        );
        assert_eq!(server.count("/token"), 2);
    }

    #[tokio::test]
    async fn maintenance_manual_quota_refresh_and_short_ttl_budget() {
        let server = Server::new().await;
        server.state.ttl.store(300, Ordering::SeqCst);
        let clock = TestClock::new();
        let manager = manager(clock.clone(), vec![oauth(1, true), oauth(2, true)]);
        server.attach(&manager);
        manager.set_disabled(1, true).unwrap();
        manager.report_quota_exhausted(2);
        manager.maintain_once().await;
        assert_eq!(server.count("/token"), 2);
        assert_eq!(server.count("/getUsageLimits"), 1);
        assert_eq!(
            manager.entries.lock()[0].disabled_reason,
            Some(DisabledReason::Manual)
        );
        assert_eq!(
            manager.entries.lock()[1].disabled_reason,
            Some(DisabledReason::QuotaExceeded)
        );
        for _ in 0..3 {
            clock.advance_ms(60_000);
            manager.maintain_once().await;
        }
        assert_eq!(
            server.count("/token"),
            2,
            "short TTL must not refresh every minute"
        );
        assert_eq!(server.count("/getUsageLimits"), 1);
        clock.advance_ms(60_000);
        manager.maintain_once().await;
        assert_eq!(
            server.count("/token"),
            4,
            "300 seconds TTL qualifies after 240 seconds"
        );
        let entries = manager.entries.lock();
        for entry in entries.iter() {
            assert_eq!(
                entry.credentials.access_token.as_deref(),
                Some("new-access")
            );
            assert!(
                entry
                    .credentials
                    .refresh_token
                    .as_deref()
                    .unwrap()
                    .ends_with("xx")
            );
            assert_eq!(
                (
                    entry.failure_count,
                    entry.refresh_failure_count,
                    entry.success_count,
                    entry.in_flight_count
                ),
                (
                    if entry.id == 2 {
                        MAX_FAILURES_PER_CREDENTIAL
                    } else {
                        0
                    },
                    0,
                    0,
                    0
                )
            );
        }
    }

    #[tokio::test]
    async fn maintenance_unexpired_and_api_key_make_zero_http() {
        let server = Server::new().await;
        let clock = TestClock::new();
        let api = KiroCredentials {
            id: Some(2),
            kiro_api_key: Some("synthetic-key".into()),
            ..Default::default()
        };
        let manager = manager(clock.clone(), vec![oauth(1, false), api]);
        server.attach(&manager);
        for _ in 0..5 {
            manager.maintain_once().await;
            clock.advance_ms(60_000);
        }
        assert_eq!(server.state.requests.lock().len(), 0);
        assert!(manager.force_refresh_token_for(2).await.is_err());
        assert_eq!(server.count("/token"), 0);
    }

    #[tokio::test]
    async fn maintenance_auth_failure_throttles_quota_and_continues_scan() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::SERVICE_UNAVAILABLE] {
            let server = Server::new().await;
            *server.state.status.lock() = status;
            let clock = TestClock::new();
            let manager = manager(clock.clone(), vec![oauth(1, true), oauth(2, true)]);
            server.attach(&manager);
            manager.report_quota_exhausted(1);
            manager.set_disabled(2, true).unwrap();
            manager.maintain_once().await;
            assert_eq!(
                server.count("/token"),
                2,
                "one failure must not terminate the round"
            );
            assert_eq!(server.count("/getUsageLimits"), 0);
            for _ in 0..14 {
                clock.advance_ms(60_000);
                manager.maintain_once().await;
            }
            assert_eq!(server.count("/token"), 2);
            clock.advance_ms(60_000);
            manager.maintain_once().await;
            assert_eq!(server.count("/token"), 4);
            *server.state.status.lock() = StatusCode::OK;
            clock.advance_ms(RETRY_MS);
            manager.maintain_once().await;
            assert_eq!(server.count("/token"), 6);
            assert_eq!(server.count("/getUsageLimits"), 1);
            let entries = manager.entries.lock();
            assert_eq!(
                entries[0].disabled_reason,
                Some(DisabledReason::QuotaExceeded)
            );
            assert_eq!(entries[1].disabled_reason, Some(DisabledReason::Manual));
            assert_eq!(
                (
                    entries[0].refresh_failure_count,
                    entries[1].refresh_failure_count
                ),
                (0, 0)
            );
        }
    }

    #[tokio::test]
    async fn maintenance_auth_reason_requires_real_refresh_and_preserves_manual() {
        let server = Server::new().await;
        let manager = manager(
            TestClock::new(),
            vec![oauth(1, false), oauth(2, false), oauth(3, false)],
        );
        server.attach(&manager);
        manager.report_refresh_token_invalid(1);
        for _ in 0..3 {
            manager.report_refresh_failure(2);
        }
        manager.set_disabled(3, true).unwrap();
        manager.maintain_once().await;
        assert_eq!(
            server.count("/token"),
            2,
            "unexpired old tokens cannot recover auth-disabled entries"
        );
        let entries = manager.entries.lock();
        assert!(!entries[0].disabled && !entries[1].disabled);
        assert_eq!(entries[2].disabled_reason, Some(DisabledReason::Manual));
    }

    #[tokio::test]
    async fn maintenance_quota_confirmed_balance_restores_business_and_mcp() {
        let server = Server::new().await;
        let clock = TestClock::new();
        let manager = manager(clock.clone(), vec![oauth(1, false)]);
        server.attach(&manager);
        manager.report_quota_exhausted(1);
        manager.maintain_once().await;
        assert!(manager.entries.lock()[0].disabled);
        *server.state.usage.lock() = json!({"usageBreakdownList":[{"currentUsageWithPrecision":0,"usageLimitWithPrecision":10}]});
        clock.advance_ms(RETRY_MS - 1);
        manager.maintain_once().await;
        assert_eq!(server.count("/getUsageLimits"), 1);
        clock.advance_ms(1);
        manager.maintain_once().await;
        assert_eq!(server.count("/getUsageLimits"), 2);
        assert_eq!(manager.entries.lock()[0].failure_count, 0);
        assert!(!manager.entries.lock()[0].disabled);
        let context = manager
            .acquire_context(Some("claude-sonnet-5"))
            .await
            .unwrap();
        assert_eq!(context.id, 1);
        manager.report_no_result(1);
        // MCP uses the same disabled-aware reservation path with model=None.
        let context = manager
            .acquire_context_for_session_excluding(None, Some("maintenance-mcp"), &HashSet::new())
            .await
            .unwrap();
        assert_eq!(context.id, 1);
        manager.report_no_result(1);
    }

    #[tokio::test]
    async fn maintenance_refresh_serializes_rotation_and_merges_current_config() {
        let server = Server::new().await;
        server.state.pause.store(true, Ordering::SeqCst);
        let mut credential = oauth(1, true);
        credential.auth_method = Some("idc".into());
        credential.client_id = Some("synthetic-client".into());
        credential.client_secret = Some("synthetic-secret".into());
        let manager = manager(TestClock::new(), vec![credential]);
        server.attach(&manager);
        let first_manager = manager.clone();
        let first =
            tokio::spawn(async move { first_manager.refresh_auth(1, RefreshMode::Business).await });
        server.wait_count("/token", 1).await;
        manager.set_priority(1, 42).unwrap();
        manager.set_disabled(1, true).unwrap();
        let second_manager = manager.clone();
        let second =
            tokio::spawn(
                async move { second_manager.refresh_auth(1, RefreshMode::Business).await },
            );
        server.state.pause.store(false, Ordering::SeqCst);
        server.state.release.add_permits(1);
        assert!(first.await.unwrap().unwrap());
        assert!(!second.await.unwrap().unwrap());
        assert_eq!(
            server.count("/token"),
            1,
            "waiter must observe applied rotation while serialized"
        );
        manager.force_refresh_token_for(1).await.unwrap();
        assert_eq!(
            server.count("/token"),
            2,
            "Admin force retains unconditional semantics"
        );
        let requests = server.state.requests.lock();
        let first_token = requests[0].1["refreshToken"].as_str().unwrap();
        assert_eq!(requests[1].1["refreshToken"], format!("{first_token}x"));
        let entries = manager.entries.lock();
        assert_eq!(entries[0].credentials.priority, 42);
        assert_eq!(entries[0].disabled_reason, Some(DisabledReason::Manual));
    }

    #[tokio::test]
    async fn maintenance_stale_refresh_never_recovers_manual_or_replacement() {
        for replacement in [false, true] {
            let server = Server::new().await;
            server.state.pause.store(true, Ordering::SeqCst);
            let manager = manager(TestClock::new(), vec![oauth(1, false)]);
            server.attach(&manager);
            manager.report_refresh_token_invalid(1);
            let worker = manager.clone();
            let task = tokio::spawn(async move { worker.maintain_once().await });
            server.wait_count("/token", 1).await;
            if replacement {
                // Same ID and exact same OAuth material, different entry instance.
                let mut credential = manager.credentials_for_id(1).unwrap();
                credential.disabled = true;
                credential.disabled_reason = Some("InvalidRefreshToken".into());
                let fresh = profile_test_manager(TestClock::new(), vec![credential], None, true);
                let entry = fresh.entries.lock().pop().unwrap();
                manager.delete_credential(1).unwrap();
                manager.entries.lock().push(entry);
            } else {
                manager.set_disabled(1, true).unwrap();
            }
            server.state.release.add_permits(1);
            task.await.unwrap();
            let entries = manager.entries.lock();
            assert!(entries[0].disabled);
            if replacement {
                assert_ne!(
                    entries[0].credentials.access_token.as_deref(),
                    Some("new-access")
                );
                assert!(entries[0].auth_retry_after_ms.is_none());
            } else {
                assert_eq!(entries[0].disabled_reason, Some(DisabledReason::Manual));
            }
        }
    }

    #[tokio::test]
    async fn maintenance_stale_quota_results_cannot_override_new_decisions() {
        for change in ["manual", "enable-quota", "replace"] {
            let server = Server::new().await;
            *server.state.usage.lock() = json!({"subscriptionInfo":{"subscriptionTitle":"old-subscription"},"usageBreakdownList":[{"currentUsageWithPrecision":0,"usageLimitWithPrecision":10}]});
            server.state.pause.store(true, Ordering::SeqCst);
            let manager = manager(TestClock::new(), vec![oauth(1, false)]);
            server.attach(&manager);
            manager.report_quota_exhausted(1);
            let worker = manager.clone();
            let task = tokio::spawn(async move { worker.maintain_once().await });
            server.wait_count("/getUsageLimits", 1).await;
            match change {
                "manual" => manager.set_disabled(1, true).unwrap(),
                "enable-quota" => {
                    manager.set_disabled(1, false).unwrap();
                    manager.report_quota_exhausted(1);
                }
                _ => {
                    let mut credential = manager.credentials_for_id(1).unwrap();
                    credential.disabled = true;
                    credential.disabled_reason = Some("QuotaExceeded".into());
                    let fresh =
                        profile_test_manager(TestClock::new(), vec![credential], None, true);
                    let entry = fresh.entries.lock().pop().unwrap();
                    manager.delete_credential(1).unwrap();
                    manager.entries.lock().push(entry);
                }
            }
            server.state.release.add_permits(1);
            task.await.unwrap();
            let entries = manager.entries.lock();
            assert!(
                entries[0].disabled,
                "{change}: old positive balance must not enable current state"
            );
            assert!(
                entries[0].quota_retry_after_ms.is_none(),
                "{change}: old scheduling must not throttle new quota state"
            );
            if change == "replace" {
                assert!(entries[0].credentials.subscription_title.is_none());
            }
        }
    }

    #[tokio::test]
    async fn maintenance_admin_add_persistence_and_legacy_boundaries() {
        use crate::kiro::model::credentials::CredentialsConfig;
        let directory =
            std::env::temp_dir().join(format!("kiro-maintenance-add-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        for (name, multiple, path_present, write_fails) in [
            ("array", true, true, false),
            ("single", false, true, false),
            ("memory", true, false, false),
            ("failure", true, true, true),
        ] {
            let path = if write_fails {
                directory.join("absent/credentials.json")
            } else {
                directory.join(format!("{name}.json"))
            };
            if !write_fails {
                std::fs::write(&path, if multiple { "[]" } else { "{}" }).unwrap();
            }
            let manager = profile_test_manager(
                TestClock::new(),
                vec![],
                path_present.then(|| path.clone()),
                multiple,
            );
            let added = KiroCredentials {
                kiro_api_key: Some(format!("synthetic-{name}")),
                ..Default::default()
            };
            let result = manager.add_credential(added).await;
            assert_eq!(result.is_err(), write_fails);
            assert_eq!(
                manager.total_count(),
                1,
                "{name}: existing memory-success boundary"
            );
            if name == "array" {
                let loaded = CredentialsConfig::load(&path)
                    .unwrap()
                    .into_sorted_credentials();
                let restarted = profile_test_manager(TestClock::new(), loaded, None, true);
                assert_eq!(restarted.total_count(), 1);
                assert_eq!(
                    restarted
                        .credentials_for_id(1)
                        .unwrap()
                        .kiro_api_key
                        .as_deref(),
                    Some("synthetic-array")
                );
            } else if !write_fails {
                assert_eq!(
                    std::fs::read_to_string(path).unwrap(),
                    if multiple { "[]" } else { "{}" }
                );
            }
        }
    }

    #[tokio::test]
    async fn maintenance_saved_reasons_restart_and_quota_recovery() {
        let server = Server::new().await;
        *server.state.usage.lock() = json!({"usageBreakdownList":[{"currentUsageWithPrecision":0,"usageLimitWithPrecision":1}]});
        let mut credentials = vec![];
        for (id, reason) in [(1, None), (2, Some("unknown")), (3, Some("QuotaExceeded"))] {
            let mut credential = oauth(id, true);
            credential.disabled = true;
            credential.disabled_reason = reason.map(str::to_string);
            credentials.push(credential);
        }
        let manager = manager(TestClock::new(), credentials);
        server.attach(&manager);
        manager.maintain_once().await;
        assert_eq!(server.count("/token"), 3);
        assert_eq!(server.count("/getUsageLimits"), 1);
        let entries = manager.entries.lock();
        assert_eq!(entries[0].disabled_reason, Some(DisabledReason::Manual));
        assert_eq!(entries[1].disabled_reason, Some(DisabledReason::Manual));
        assert!(!entries[2].disabled);
    }
}
