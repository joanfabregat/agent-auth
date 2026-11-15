use crate::{APPROVAL_TIMEOUT, AppResult, Provider, broker, storage};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{collections::VecDeque, path::PathBuf, time::Duration};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use url::Url;

struct Approval {
    url: Url,
    redirect: Url,
    state: String,
}

fn parameter(url: &Url, name: &str) -> AppResult<String> {
    let values: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .collect();
    if values.len() != 1 || values[0].is_empty() {
        return Err("missing or duplicate authorization parameter".into());
    }
    Ok(values[0].clone())
}

fn loopback(url: &Url, scheme: &str) -> bool {
    url.scheme() == scheme
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn approval(provider: Provider, value: &str) -> AppResult<Approval> {
    if value.len() > 16384 {
        return Err("authorization URL too large".into());
    }
    let url = Url::parse(value.trim())?;
    let allowed = match provider {
        Provider::Google => {
            url.host_str() == Some("accounts.google.com")
                && matches!(url.path(), "/o/oauth2/auth" | "/o/oauth2/v2/auth")
        }
        Provider::Digitalocean => {
            url.host_str() == Some("cloud.digitalocean.com") && url.path() == "/v1/oauth/authorize"
        }
    };
    if !allowed
        || url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || parameter(&url, "response_type")? != "code"
        || parameter(&url, "code_challenge_method")? != "S256"
    {
        return Err("unsupported native CLI authorization URL".into());
    }
    parameter(&url, "client_id")?;
    let challenge = parameter(&url, "code_challenge")?;
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid PKCE challenge".into());
    }
    let state = parameter(&url, "state")?;
    if !broker::valid_state(&state) {
        return Err("invalid CLI state".into());
    }
    let redirect = Url::parse(&parameter(&url, "redirect_uri")?)?;
    let path = match provider {
        Provider::Google => "/",
        Provider::Digitalocean => "/callback",
    };
    if !loopback(&redirect, "http")
        || redirect.port().is_none_or(|port| port < 1024)
        || redirect.path() != path
        || redirect.query().is_some()
    {
        return Err("CLI redirect must be a high-port loopback callback".into());
    }
    Ok(Approval {
        url,
        redirect,
        state,
    })
}

fn callback_query(approval: &Approval, value: &str) -> AppResult<String> {
    let url = Url::parse(value)?;
    if url.origin() != approval.redirect.origin()
        || url.path() != approval.redirect.path()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("callback destination mismatch".into());
    }
    let raw = url.query().ok_or("missing callback query")?;
    let state = broker::validate_query(raw)?;
    if state != approval.state {
        return Err("callback state mismatch".into());
    }
    Ok(raw.to_owned())
}

struct Browser {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    events: VecDeque<Value>,
}
impl Browser {
    async fn receive(&mut self) -> AppResult<Value> {
        loop {
            match self.socket.next().await.ok_or("browser disconnected")?? {
                Message::Text(text) => return Ok(serde_json::from_str(&text)?),
                Message::Ping(bytes) => self.socket.send(Message::Pong(bytes)).await?,
                Message::Close(_) => return Err("browser disconnected".into()),
                _ => {}
            }
        }
    }
    async fn command(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> AppResult<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut request = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            request["sessionId"] = json!(session);
        }
        self.socket
            .send(Message::Text(request.to_string().into()))
            .await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let message = self.receive().await?;
                if message["id"].as_u64() == Some(id) {
                    if message.get("error").is_some() {
                        return Err("browser command failed".into());
                    }
                    return Ok(message["result"].clone());
                }
                if message.get("method").is_some() {
                    if self.events.len() >= 128 {
                        return Err("browser event limit exceeded".into());
                    }
                    self.events.push_back(message);
                }
            }
        })
        .await?
    }
    async fn event(&mut self) -> AppResult<Value> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        self.receive().await
    }
}

fn local_endpoint(value: &str) -> AppResult<Url> {
    let url = Url::parse(value)?;
    if !loopback(&url, "http") || url.path() != "/" || url.query().is_some() {
        return Err("endpoint must be a loopback HTTP origin".into());
    }
    Ok(url)
}

async fn connect(http: &reqwest::Client, origin: &Url) -> AppResult<Browser> {
    let version: Value = http
        .get(origin.join("json/version")?)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let socket = Url::parse(
        version["webSocketDebuggerUrl"]
            .as_str()
            .ok_or("missing browser websocket")?,
    )?;
    if !loopback(&socket, "ws")
        || socket.port_or_known_default() != origin.port_or_known_default()
        || !socket.path().starts_with("/devtools/browser/")
        || socket.query().is_some()
    {
        return Err("browser websocket must remain on the configured loopback port".into());
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(256 * 1024))
        .max_frame_size(Some(256 * 1024));
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_with_config(socket.as_str(), Some(config), true),
    )
    .await??;
    Ok(Browser {
        socket,
        next_id: 0,
        events: VecDeque::new(),
    })
}

async fn intercept(
    browser: &mut Browser,
    session: &str,
    approval: &Approval,
    callback: &Url,
) -> AppResult<()> {
    loop {
        let event = browser.event().await?;
        if event["sessionId"].as_str() != Some(session) || event["method"] != "Fetch.requestPaused"
        {
            continue;
        }
        let params = &event["params"];
        let request_id = params["requestId"].as_str().ok_or("missing request ID")?;
        let query = if params["request"]["method"] == "GET" && params["resourceType"] == "Document"
        {
            callback_query(
                approval,
                params["request"]["url"].as_str().unwrap_or_default(),
            )
        } else {
            Err("invalid callback request".into())
        };
        let Ok(query) = query else {
            browser
                .command(
                    Some(session),
                    "Fetch.failRequest",
                    json!({"requestId":request_id,"errorReason":"BlockedByClient"}),
                )
                .await?;
            return Err("invalid callback intercepted".into());
        };
        let mut destination = callback.clone();
        destination.set_query(Some(&query));
        browser
            .command(
                Some(session),
                "Fetch.fulfillRequest",
                json!({
                    "requestId":request_id,"responseCode":302,"responseHeaders":[
                        {"name":"Location","value":destination.as_str()},
                        {"name":"Cache-Control","value":"no-store"},
                        {"name":"Referrer-Policy","value":"no-referrer"}
                    ]
                }),
            )
            .await?;
        return Ok(());
    }
}

async fn forward(http: &reqwest::Client, approval: &Approval, query: &str) -> AppResult<()> {
    let mut destination = approval.redirect.clone();
    destination.set_query(Some(query));
    callback_query(approval, destination.as_str())?;
    // No DNS, proxy, or redirect may send the code outside loopback.
    if destination.host_str() == Some("localhost") {
        destination.set_host(Some("127.0.0.1"))?;
    }
    let response = http.get(destination).send().await?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err("CLI callback rejected".into());
    }
    Ok(())
}

pub async fn run(
    provider: Provider,
    file: PathBuf,
    runtime: PathBuf,
    control: String,
    browser_url: String,
    callback_base: String,
) -> AppResult<()> {
    let approval = approval(provider, &storage::read_secret(&file)?)?;
    let control = local_endpoint(&control)?;
    let browser_url = local_endpoint(&browser_url)?;
    let mut callback = Url::parse(&callback_base)?;
    if callback.scheme() != "https"
        || callback.host_str().is_none()
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.query().is_some()
        || callback.fragment().is_some()
        || callback.path() != "/"
    {
        return Err("callback base must be an HTTPS origin".into());
    }
    callback.set_path(&format!("/callback/{}", provider.name()));
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let token = storage::read_secret(&runtime.join("control.token"))?;
    let wait_token = crate::random_token().secret().clone();
    // Fail before registering or opening a login if the browser bridge is absent.
    let mut browser = connect(&http, &browser_url).await?;
    let registered: broker::Registered = http
        .post(control.join("v1/sessions")?)
        .bearer_auth(&token)
        .json(&broker::Registration {
            provider,
            state: approval.state.clone(),
            wait_token: wait_token.clone(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let target = browser
        .command(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    let target = target["targetId"]
        .as_str()
        .ok_or("missing browser target")?
        .to_owned();
    let session = browser
        .command(
            None,
            "Target.attachToTarget",
            json!({"targetId":target,"flatten":true}),
        )
        .await?;
    let session = session["sessionId"]
        .as_str()
        .ok_or("missing browser session")?
        .to_owned();
    let result = tokio::time::timeout(APPROVAL_TIMEOUT, async {
        browser.command(Some(&session), "Fetch.enable", json!({"patterns":[{"urlPattern":format!("{}*", approval.redirect),"resourceType":"Document","requestStage":"Request"}]})).await?;
        browser.command(Some(&session), "Page.navigate", json!({"url":approval.url.as_str()})).await?;
        println!("{}", json!({"event":"approval_requested","provider":provider.name()}));
        intercept(&mut browser, &session, &approval, &callback).await?;
        let outcome: broker::Outcome = http.post(control.join(&format!("v1/sessions/{}/wait", registered.id))?).timeout(APPROVAL_TIMEOUT).bearer_auth(&token).json(&broker::WaitRequest { wait_token }).send().await?.error_for_status()?.json().await?;
        let query = outcome.query.ok_or("missing callback query")?;
        forward(&http, &approval, &query).await?;
        println!("{}", json!({"event":"callback_forwarded","provider":provider.name(),"denied":outcome.denied}));
        Ok(())
    }).await;
    // Detach only our own target. Never inspect other tabs or browser cookies.
    let _ = browser
        .command(Some(&session), "Fetch.disable", json!({}))
        .await;
    let _ = browser
        .command(
            None,
            "Target.detachFromTarget",
            json!({"sessionId":session}),
        )
        .await;
    result?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_to_native_listener_without_following_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sender = std::sync::Arc::new(tokio::sync::Mutex::new(Some(sender)));
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(
                move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                    let sender = sender.clone();
                    async move {
                        sender
                            .lock()
                            .await
                            .take()
                            .unwrap()
                            .send(query.unwrap())
                            .unwrap();
                        axum::response::Redirect::to("https://example.com/must-not-follow")
                    }
                },
            ),
        );
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut approval = approval(Provider::Google, &fixture(Provider::Google)).unwrap();
        approval.redirect.set_port(Some(port)).unwrap();
        let query = "state=synthetic_state_123456789012345&code=fixture%2Bcode&scope=one%20two";
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        forward(&http, &approval, query).await.unwrap();
        assert_eq!(receiver.await.unwrap(), query);
        assert!(
            forward(&http, &approval, "state=wrong-state-123456789&code=x")
                .await
                .is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn cdp_intercepts_only_own_callback_and_preserves_query() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Other tabs are ignored, even if their URL resembles our callback.
            for session in ["unrelated-tab", "own-tab"] {
                socket.send(Message::Text(json!({"sessionId":session,"method":"Fetch.requestPaused","params":{
                    "requestId":"fixture-request","resourceType":"Document","request":{"method":"GET",
                    "url":"http://localhost:8085/?state=synthetic_state_123456789012345&code=fixture%2Bcode&scope=one%20two"}
                }}).to_string().into())).await.unwrap();
            }
            let request: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(request["sessionId"], "own-tab");
            assert_eq!(request["method"], "Fetch.fulfillRequest");
            assert_eq!(request["params"]["responseCode"], 302);
            assert_eq!(
                request["params"]["responseHeaders"][0]["value"],
                "https://agent-auth.example.com/callback/google?state=synthetic_state_123456789012345&code=fixture%2Bcode&scope=one%20two"
            );
            socket
                .send(Message::Text(
                    json!({"id":request["id"],"result":{}}).to_string().into(),
                ))
                .await
                .unwrap();
        });
        let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let mut browser = Browser {
            socket,
            next_id: 0,
            events: VecDeque::new(),
        };
        intercept(
            &mut browser,
            "own-tab",
            &approval(Provider::Google, &fixture(Provider::Google)).unwrap(),
            &Url::parse("https://agent-auth.example.com/callback/google").unwrap(),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cdp_rejects_mismatched_state_instead_of_forwarding() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket.send(Message::Text(json!({"sessionId":"own-tab","method":"Fetch.requestPaused","params":{
                "requestId":"fixture-request","resourceType":"Document","request":{"method":"GET",
                "url":"http://localhost:8085/?state=wrong-state-123456789&code=fixture"}
            }}).to_string().into())).await.unwrap();
            let request: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(request["method"], "Fetch.failRequest");
            socket
                .send(Message::Text(
                    json!({"id":request["id"],"result":{}}).to_string().into(),
                ))
                .await
                .unwrap();
        });
        let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let mut browser = Browser {
            socket,
            next_id: 0,
            events: VecDeque::new(),
        };
        assert!(
            intercept(
                &mut browser,
                "own-tab",
                &approval(Provider::Google, &fixture(Provider::Google)).unwrap(),
                &Url::parse("https://agent-auth.example.com/callback/google").unwrap()
            )
            .await
            .is_err()
        );
        server.await.unwrap();
    }
    fn fixture(provider: Provider) -> String {
        let (base, redirect) = match provider {
            Provider::Google => (
                "https://accounts.google.com/o/oauth2/auth",
                "http://localhost:8085/",
            ),
            Provider::Digitalocean => (
                "https://cloud.digitalocean.com/v1/oauth/authorize",
                "http://127.0.0.1:43210/callback",
            ),
        };
        let mut url = Url::parse(base).unwrap();
        url.query_pairs_mut().extend_pairs([
            ("client_id", "synthetic-client"),
            ("redirect_uri", redirect),
            ("state", "synthetic_state_123456789012345"),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ]);
        url.to_string()
    }
    #[test]
    fn native_urls_and_exact_callback_binding() {
        for provider in [Provider::Google, Provider::Digitalocean] {
            let approval = approval(provider, &fixture(provider)).unwrap();
            let mut callback = approval.redirect.clone();
            callback.set_query(Some(
                "state=synthetic_state_123456789012345&code=fixture%2Bcode&scope=extra",
            ));
            assert_eq!(
                callback_query(&approval, callback.as_str()).unwrap(),
                callback.query().unwrap()
            );
            callback.set_query(Some("state=wrong-state-value-123456789&code=fixture"));
            assert!(callback_query(&approval, callback.as_str()).is_err());
            callback.set_port(Some(44444)).unwrap();
            assert!(callback_query(&approval, callback.as_str()).is_err());
        }
    }
    #[test]
    fn refuses_unsafe_authorization_and_endpoints() {
        let base = fixture(Provider::Google);
        for bad in [
            base.replace("accounts.google.com", "example.com"),
            base.replace("S256", "plain"),
            format!("{base}&state=duplicate"),
            base.replace("localhost", "example.com"),
            base.replace("8085", "80"),
            base.replace("/o/oauth2/auth", "/untrusted"),
        ] {
            assert!(approval(Provider::Google, &bad).is_err());
        }
        for bad in [
            "https://127.0.0.1:9222",
            "http://example.com:9222",
            "http://user@localhost:9222",
            "http://127.0.0.1:9222/path",
        ] {
            assert!(local_endpoint(bad).is_err());
        }
    }
}
