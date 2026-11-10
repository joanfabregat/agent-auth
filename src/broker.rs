use crate::{APPROVAL_TIMEOUT, AppResult, MAX_PENDING, Provider, storage};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, oneshot, watch};

#[derive(Serialize, Deserialize)]
pub struct Registration {
    pub provider: Provider,
    pub state: String,
    pub wait_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Registered {
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct WaitRequest {
    pub wait_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Outcome {
    pub code: Option<String>,
    pub denied: bool,
}

struct Pending {
    id: String,
    provider: Provider,
    wait_token: String,
    expires: Instant,
    sender: Option<oneshot::Sender<Outcome>>,
    receiver: Option<oneshot::Receiver<Outcome>>,
}

struct Inner {
    pending: HashMap<String, Pending>,
    last_activity: Instant,
}

struct Broker {
    control_token: String,
    inner: Mutex<Inner>,
}

fn opaque(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn authorized(headers: &HeaderMap, broker: &Broker) -> Result<(), StatusCode> {
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if bool::from(provided.as_bytes().ct_eq(broker.control_token.as_bytes())) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn register(
    State(broker): State<Arc<Broker>>,
    headers: HeaderMap,
    Json(input): Json<Registration>,
) -> Result<Json<Registered>, StatusCode> {
    authorized(&headers, &broker)?;
    if !opaque(&input.state) || !opaque(&input.wait_token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut inner = broker.inner.lock().await;
    inner
        .pending
        .retain(|_, pending| pending.expires > Instant::now());
    if inner.pending.len() >= MAX_PENDING {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if inner.pending.contains_key(&input.state) {
        return Err(StatusCode::CONFLICT);
    }
    let id = CsrfToken::new_random().secret().clone();
    let (sender, receiver) = oneshot::channel();
    inner.pending.insert(
        input.state,
        Pending {
            id: id.clone(),
            provider: input.provider,
            wait_token: input.wait_token,
            expires: Instant::now() + APPROVAL_TIMEOUT,
            sender: Some(sender),
            receiver: Some(receiver),
        },
    );
    inner.last_activity = Instant::now();
    Ok(Json(Registered { id }))
}

async fn wait(
    State(broker): State<Arc<Broker>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<WaitRequest>,
) -> Result<Json<Outcome>, StatusCode> {
    authorized(&headers, &broker)?;
    let (state, receiver, expires) = {
        let mut inner = broker.inner.lock().await;
        let (state, pending) = inner
            .pending
            .iter_mut()
            .find(|(_, pending)| pending.id == id)
            .ok_or(StatusCode::NOT_FOUND)?;
        if !bool::from(
            input
                .wait_token
                .as_bytes()
                .ct_eq(pending.wait_token.as_bytes()),
        ) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if pending.expires <= Instant::now() {
            return Err(StatusCode::GONE);
        }
        (
            state.clone(),
            pending.receiver.take().ok_or(StatusCode::CONFLICT)?,
            pending.expires,
        )
    };
    let result = tokio::time::timeout_at(expires.into(), receiver).await;
    let mut inner = broker.inner.lock().await;
    inner.pending.remove(&state);
    inner.last_activity = Instant::now();
    match result {
        Ok(Ok(outcome)) => Ok(Json(outcome)),
        _ => Err(StatusCode::GONE),
    }
}

#[derive(Deserialize)]
struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

fn page(status: StatusCode, text: &'static str) -> Response {
    let mut response = (status, Html(text)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

async fn callback(
    State(broker): State<Arc<Broker>>,
    Path(provider): Path<String>,
    Query(input): Query<Callback>,
) -> Response {
    let Some(state) = input.state.filter(|state| opaque(state)) else {
        return page(StatusCode::BAD_REQUEST, "Invalid approval response.");
    };
    let mut inner = broker.inner.lock().await;
    let Some(pending) = inner.pending.get_mut(&state) else {
        return page(
            StatusCode::BAD_REQUEST,
            "This approval request is unknown or expired.",
        );
    };
    if pending.provider.name() != provider || pending.expires <= Instant::now() {
        return page(
            StatusCode::BAD_REQUEST,
            "This approval does not match a waiting request.",
        );
    }
    // Never echo provider-supplied error text or authorization codes to HTML.
    let outcome = if input.error.is_some() {
        Outcome {
            code: None,
            denied: true,
        }
    } else if let Some(code) = input
        .code
        .filter(|code| !code.is_empty() && code.len() <= 4096)
    {
        Outcome {
            code: Some(code),
            denied: false,
        }
    } else {
        return page(StatusCode::BAD_REQUEST, "Missing approval code.");
    };
    let Some(sender) = pending.sender.take() else {
        return page(StatusCode::CONFLICT, "This approval was already received.");
    };
    if sender.send(outcome).is_err() {
        return page(
            StatusCode::GONE,
            "The requesting login process is no longer waiting.",
        );
    }
    inner.last_activity = Instant::now();
    page(
        StatusCode::OK,
        "<!doctype html><meta charset=utf-8><title>Approval received</title><h1>Approval received</h1><p>You can return to your agent. It will verify the account and complete the login.</p>",
    )
}

fn routers(broker: Arc<Broker>) -> (Router, Router) {
    let callbacks = Router::new()
        .route("/callback/{provider}", get(callback))
        .route("/healthz", get(|| async { "ready" }))
        .with_state(broker.clone());
    let control = Router::new()
        .route("/v1/sessions", post(register))
        .route("/v1/sessions/{id}/wait", post(wait))
        .layer(DefaultBodyLimit::max(8192))
        .with_state(broker);
    (callbacks, control)
}

pub async fn serve(
    runtime: PathBuf,
    callback_address: SocketAddr,
    control_address: SocketAddr,
) -> AppResult<()> {
    storage::private_dir(&runtime)?;
    if !callback_address.ip().is_loopback() || !control_address.ip().is_loopback() {
        return Err(
            "both listeners must bind loopback; publish only callbacks through a TLS reverse proxy"
                .into(),
        );
    }
    // Bind before touching control state: a second instance must not rotate a
    // running instance's control credential.
    let callback_listener = tokio::net::TcpListener::bind(callback_address).await?;
    let control_listener = tokio::net::TcpListener::bind(control_address).await?;
    let token_file = runtime.join("control.token");
    if token_file.exists() {
        storage::read_secret(&token_file)?;
        std::fs::remove_file(&token_file)?;
    }
    let control_token = CsrfToken::new_random().secret().clone();
    storage::write_new(&token_file, control_token.as_bytes())?;
    let broker = Arc::new(Broker {
        control_token,
        inner: Mutex::new(Inner {
            pending: HashMap::new(),
            last_activity: Instant::now(),
        }),
    });
    let (callbacks, control) = routers(broker.clone());
    let (shutdown, callback_shutdown) = watch::channel(false);
    let mut control_shutdown = callback_shutdown.clone();
    let mut callback_shutdown = callback_shutdown;
    let callbacks_task = tokio::spawn(async move {
        axum::serve(callback_listener, callbacks)
            .with_graceful_shutdown(async move {
                let _ = callback_shutdown.changed().await;
            })
            .await
    });
    let control_task = tokio::spawn(async move {
        axum::serve(control_listener, control)
            .with_graceful_shutdown(async move {
                let _ = control_shutdown.changed().await;
            })
            .await
    });
    println!(
        "{}",
        serde_json::json!({"event":"ready","callback_listen":callback_address.to_string(),"control_listen":control_address.to_string()})
    );
    let idle = async {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let mut inner = broker.inner.lock().await;
            inner
                .pending
                .retain(|_, pending| pending.expires > Instant::now());
            if inner.pending.is_empty() && inner.last_activity.elapsed() >= Duration::from_secs(300)
            {
                break;
            }
        }
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {}, _ = idle => {} }
    // Drop senders to end outstanding local waits before graceful shutdown.
    broker.inner.lock().await.pending.clear();
    let _ = shutdown.send(true);
    let _ = tokio::join!(callbacks_task, control_task);
    if storage::read_secret(&token_file).is_ok_and(|value| value == broker.control_token) {
        std::fs::remove_file(&token_file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> Arc<Broker> {
        Arc::new(Broker {
            control_token: "fixture-control".into(),
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                last_activity: Instant::now(),
            }),
        })
    }
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer fixture-control".parse().unwrap(),
        );
        headers
    }
    fn request() -> Registration {
        Registration {
            state: "a".repeat(43),
            wait_token: "b".repeat(43),
            provider: Provider::Google,
        }
    }

    #[tokio::test]
    async fn rejects_control_access_without_credentials_and_duplicate_state() {
        let state = broker();
        assert!(matches!(
            register(State(state.clone()), HeaderMap::new(), Json(request())).await,
            Err(StatusCode::UNAUTHORIZED)
        ));
        assert!(
            register(State(state.clone()), headers(), Json(request()))
                .await
                .is_ok()
        );
        assert!(matches!(
            register(State(state), headers(), Json(request())).await,
            Err(StatusCode::CONFLICT)
        ));
    }

    #[tokio::test]
    async fn binds_provider_and_delivers_code_only_once() {
        let state = broker();
        let Json(registered) = register(State(state.clone()), headers(), Json(request()))
            .await
            .unwrap();
        let wrong = callback(
            State(state.clone()),
            Path("digitalocean".into()),
            Query(Callback {
                state: Some("a".repeat(43)),
                code: Some("fixture-code".into()),
                error: None,
            }),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        let accepted = callback(
            State(state.clone()),
            Path("google".into()),
            Query(Callback {
                state: Some("a".repeat(43)),
                code: Some("fixture-code".into()),
                error: None,
            }),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        let replay = callback(
            State(state.clone()),
            Path("google".into()),
            Query(Callback {
                state: Some("a".repeat(43)),
                code: Some("other-code".into()),
                error: None,
            }),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        let Json(outcome) = wait(
            State(state.clone()),
            headers(),
            Path(registered.id.clone()),
            Json(WaitRequest {
                wait_token: "b".repeat(43),
            }),
        )
        .await
        .unwrap();
        assert_eq!(outcome.code.as_deref(), Some("fixture-code"));
        assert!(matches!(
            wait(
                State(state),
                headers(),
                Path(registered.id),
                Json(WaitRequest {
                    wait_token: "b".repeat(43)
                })
            )
            .await,
            Err(StatusCode::NOT_FOUND)
        ));
    }

    #[tokio::test]
    async fn rejects_expired_approvals() {
        let state = broker();
        let _ = register(State(state.clone()), headers(), Json(request()))
            .await
            .unwrap();
        state
            .inner
            .lock()
            .await
            .pending
            .get_mut(&"a".repeat(43))
            .unwrap()
            .expires = Instant::now();
        let response = callback(
            State(state),
            Path("google".into()),
            Query(Callback {
                state: Some("a".repeat(43)),
                code: Some("fixture-code".into()),
                error: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn separates_http_routes_and_hides_callback_input() {
        let (callbacks, control) = routers(broker());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let callback_address = listener.local_addr().unwrap();
        let callback_task = tokio::spawn(async move { axum::serve(listener, callbacks).await });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = listener.local_addr().unwrap();
        let control_task = tokio::spawn(async move { axum::serve(listener, control).await });
        let http = reqwest::Client::new();
        assert_eq!(
            http.post(format!("http://{callback_address}/v1/sessions"))
                .json(&request())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            http.get(format!("http://{control_address}/callback/google"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            http.post(format!("http://{control_address}/v1/sessions"))
                .json(&request())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let registered: Registered = http
            .post(format!("http://{control_address}/v1/sessions"))
            .bearer_auth("fixture-control")
            .json(&request())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let response = http
            .get(format!("http://{callback_address}/callback/google"))
            .query(&[
                ("state", "a".repeat(43)),
                ("error", "synthetic-sensitive-value".into()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            !response
                .text()
                .await
                .unwrap()
                .contains("synthetic-sensitive-value")
        );
        let url = format!(
            "http://{control_address}/v1/sessions/{}/wait",
            registered.id
        );
        assert_eq!(
            http.post(&url)
                .bearer_auth("fixture-control")
                .json(&WaitRequest {
                    wait_token: "incorrect".into()
                })
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let outcome: Outcome = http
            .post(url)
            .bearer_auth("fixture-control")
            .json(&WaitRequest {
                wait_token: "b".repeat(43),
            })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(outcome.denied);
        assert!(outcome.code.is_none());
        callback_task.abort();
        control_task.abort();
    }

    #[tokio::test]
    async fn bounds_pending_requests() {
        let state = broker();
        for number in 0..MAX_PENDING {
            let mut input = request();
            input.state = format!("{number:043}");
            assert!(
                register(State(state.clone()), headers(), Json(input))
                    .await
                    .is_ok()
            );
        }
        assert!(matches!(
            register(State(state), headers(), Json(request())).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
    }
}
