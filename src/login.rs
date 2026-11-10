use crate::{
    APPROVAL_TIMEOUT, AppResult, Provider,
    broker::{Outcome, Registered, Registration, WaitRequest},
    storage,
};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    client_id: String,
    client_secret: Option<String>,
    expected_email: String,
    expected_team_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Grant {
    provider: Provider,
    client_id: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    session_deadline: u64,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct Identity {
    email: String,
    team_id: Option<String>,
    team_name: Option<String>,
}

fn now() -> AppResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn http() -> AppResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?)
}

fn client(config: &ClientConfig, provider: Provider, redirect: &str) -> AppResult<Client> {
    if config.client_id.is_empty() || config.expected_email.is_empty() {
        return Err("client ID and expected email are required".into());
    }
    match provider {
        Provider::Google if config.client_secret.as_deref().is_none_or(str::is_empty) => {
            return Err(
                "Google HTTPS callbacks require a registered web client and its secret".into(),
            );
        }
        Provider::Digitalocean if config.expected_team_id.as_deref().is_none_or(str::is_empty) => {
            return Err("DigitalOcean login requires an expected team ID".into());
        }
        _ => {}
    }
    let (auth, token) = match provider {
        Provider::Google => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        ),
        Provider::Digitalocean => (
            "https://cloud.digitalocean.com/v1/oauth/authorize",
            "https://cloud.digitalocean.com/v1/oauth/token",
        ),
    };
    let mut client = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_auth_uri(AuthUrl::new(auth.into())?)
        .set_token_uri(TokenUrl::new(token.into())?)
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(RedirectUrl::new(redirect.into())?);
    if let Some(secret) = &config.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }
    Ok(client)
}

fn control_url(value: &str) -> AppResult<Url> {
    let url = Url::parse(value)?;
    if url.scheme() != "http"
        || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("control URL must be an HTTP loopback origin".into());
    }
    Ok(url)
}

fn redirect_url(base: &str, provider: Provider) -> AppResult<Url> {
    let url = Url::parse(base)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("callback base must be an HTTPS origin".into());
    }
    Ok(url.join(&format!("callback/{}", provider.name()))?)
}

async fn identity(
    http: &reqwest::Client,
    grant: &Grant,
    config: &ClientConfig,
) -> AppResult<Identity> {
    let endpoint = identity_endpoint(grant.provider);
    let response = http
        .get(endpoint)
        .bearer_auth(&grant.access_token)
        .send()
        .await
        .map_err(|_| "account verification request failed")?;
    if !response.status().is_success() {
        return Err(
            "provider refused account verification; retained credentials require cleanup".into(),
        );
    }
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|_| "invalid account verification response")?;
    let identity = match grant.provider {
        Provider::Google => {
            if value["email_verified"] != true {
                return Err(
                    "Google email identity was not verified; retained credentials require cleanup"
                        .into(),
                );
            }
            Identity {
                email: value["email"].as_str().unwrap_or_default().into(),
                team_id: None,
                team_name: None,
            }
        }
        Provider::Digitalocean => Identity {
            email: value["account"]["email"]
                .as_str()
                .unwrap_or_default()
                .into(),
            team_id: value["account"]["team"]["uuid"].as_str().map(String::from),
            team_name: value["account"]["team"]["name"].as_str().map(String::from),
        },
    };
    if !identity.email.eq_ignore_ascii_case(&config.expected_email)
        || (grant.provider == Provider::Digitalocean && identity.team_id != config.expected_team_id)
    {
        return Err("approved account or team did not match expectations; retained credentials require cleanup".into());
    }
    Ok(identity)
}

fn identity_endpoint(provider: Provider) -> &'static str {
    match provider {
        Provider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
        Provider::Digitalocean => "https://api.digitalocean.com/v2/account",
    }
}

pub async fn run(
    provider: Provider,
    client_file: PathBuf,
    runtime: PathBuf,
    session: PathBuf,
    control: String,
    callback_base: String,
) -> AppResult<()> {
    storage::private_dir(&session)?;
    if session.join("grant.json").exists() || session.join("ready.json").exists() {
        return Err("session already contains a login".into());
    }
    let config: ClientConfig = serde_json::from_str(&storage::read_secret(&client_file)?)
        .map_err(|_| "invalid client configuration")?;
    let token = storage::read_secret(&runtime.join("control.token"))?;
    let control = control_url(&control)?;
    let redirect = redirect_url(&callback_base, provider)?;
    let client = client(&config, provider, redirect.as_str())?;
    let http = http()?;
    let deadline = now()? + 45 * 60;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge);
    let scopes: &[&str] = match provider {
        Provider::Google => &[
            "openid",
            "email",
            "https://www.googleapis.com/auth/cloud-platform",
        ],
        Provider::Digitalocean => &["read", "write"],
    };
    for scope in scopes {
        request = request.add_scope(Scope::new((*scope).into()));
    }
    // Google access tokens are sufficient for a bounded session; do not ask
    // for durable offline access or merge unrelated application permissions.
    if provider == Provider::Google {
        request = request
            .add_extra_param("access_type", "online")
            .add_extra_param("prompt", "select_account");
    }
    let (url, csrf) = request.url();
    let wait_token = CsrfToken::new_random().secret().clone();
    let registered = http
        .post(control.join("v1/sessions")?)
        .bearer_auth(&token)
        .json(&Registration {
            provider,
            state: csrf.secret().clone(),
            wait_token: wait_token.clone(),
        })
        .send()
        .await
        .map_err(|_| "callback relay is unavailable")?;
    if !registered.status().is_success() {
        return Err("callback relay rejected the login request".into());
    }
    let registered: Registered = registered
        .json()
        .await
        .map_err(|_| "invalid relay registration response")?;
    if !registered
        .id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("invalid relay session identifier".into());
    }
    println!(
        "{}",
        serde_json::json!({"event":"authorize","provider":provider.name(),"url":url.as_str()})
    );
    let response = http
        .post(control.join(&format!("v1/sessions/{}/wait", registered.id))?)
        .bearer_auth(&token)
        .timeout(APPROVAL_TIMEOUT + Duration::from_secs(5))
        .json(&WaitRequest { wait_token })
        .send()
        .await
        .map_err(|_| "browser approval timed out or relay disconnected")?;
    if !response.status().is_success() {
        return Err("browser approval is no longer available".into());
    }
    let outcome: Outcome = response
        .json()
        .await
        .map_err(|_| "invalid callback relay response")?;
    if outcome.denied {
        return Err("browser authorization was denied".into());
    }
    let code = outcome
        .code
        .filter(|code| !code.is_empty())
        .ok_or("provider returned no authorization code")?;
    let response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .map_err(|_| "provider rejected authorization-code exchange")?;
    // Even an incomplete provider response can contain usable credentials.
    // Retain them for revocation before rejecting a missing expiry.
    let expires_at = now()?.saturating_add(response.expires_in().unwrap_or_default().as_secs());
    let grant = Grant {
        provider,
        client_id: config.client_id.clone(),
        access_token: response.access_token().secret().clone(),
        refresh_token: response.refresh_token().map(|token| token.secret().clone()),
        expires_at,
        session_deadline: deadline.min(expires_at),
        scopes: response
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|scope| scope.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default(),
    };
    // Persist issued credentials before identity verification, so an identity
    // mismatch or interrupted request does not lose the means to revoke them.
    storage::write_new(&session.join("grant.json"), &serde_json::to_vec(&grant)?)?;
    if response.expires_in().is_none() {
        return Err("provider omitted token expiry; retained credentials require cleanup".into());
    }
    let identity = identity(&http, &grant, &config).await?;
    storage::write_new(&session.join("access-token"), grant.access_token.as_bytes())?;
    if provider == Provider::Digitalocean {
        let context = serde_json::json!({"context":"elevated","auth-contexts":{"elevated":grant.access_token}});
        storage::write_new(&session.join("doctl.yaml"), &serde_json::to_vec(&context)?)?;
    }
    storage::write_new(
        &session.join("ready.json"),
        &serde_json::to_vec(
            &serde_json::json!({"provider":provider,"identity":identity,"deadline":grant.session_deadline}),
        )?,
    )?;
    println!(
        "{}",
        serde_json::json!({"event":"ready","provider":provider.name(),"identity":identity,"deadline":grant.session_deadline})
    );
    Ok(())
}

pub async fn revoke(client_file: PathBuf, session: PathBuf) -> AppResult<()> {
    storage::private_dir(&session)?;
    let config: ClientConfig = serde_json::from_str(&storage::read_secret(&client_file)?)
        .map_err(|_| "invalid client configuration")?;
    let grant_path = if session.join("rotated-grant.json").exists() {
        session.join("rotated-grant.json")
    } else {
        session.join("grant.json")
    };
    let grant: Grant = serde_json::from_str(&storage::read_secret(&grant_path)?)
        .map_err(|_| "invalid stored grant")?;
    if grant.client_id != config.client_id {
        return Err("cleanup client does not match the issued grant".into());
    }
    // Close to wrapper commands before remote operations, including retries.
    if !session.join("closed").exists() {
        storage::write_new(&session.join("closed"), b"closed")?;
    }
    let http = http()?;
    let response = match grant.provider {
        Provider::Google => {
            http.post("https://oauth2.googleapis.com/revoke")
                .form(&[(
                    "token",
                    grant.refresh_token.as_ref().unwrap_or(&grant.access_token),
                )])
                .send()
                .await
        }
        Provider::Digitalocean => {
            http.post("https://cloud.digitalocean.com/v1/oauth/revoke")
                .bearer_auth(&grant.access_token)
                .form(&[("token", &grant.access_token)])
                .send()
                .await
        }
    }
    .map_err(|_| "revocation request failed; closed session retained for retry")?;
    if !response.status().is_success()
        && response.status() != reqwest::StatusCode::UNAUTHORIZED
        && response.status() != reqwest::StatusCode::BAD_REQUEST
    {
        return Err("provider refused revocation; closed session retained for retry".into());
    }
    let check = http
        .get(identity_endpoint(grant.provider))
        .bearer_auth(&grant.access_token)
        .send()
        .await
        .map_err(|_| "unable to verify access-token rejection; closed session retained")?;
    if check.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err("access token rejection is unconfirmed; closed session retained".into());
    }
    if let Some(refresh) = grant.refresh_token.clone() {
        let client = client(&config, grant.provider, "https://unused.invalid/callback")?;
        let result = client
            .exchange_refresh_token(&RefreshToken::new(refresh))
            .request_async(&http)
            .await;
        match result {
            Err(oauth2::RequestTokenError::ServerResponse(error))
                if refresh_rejected(
                    error.error().as_ref(),
                    error.error_description().map(String::as_str),
                ) => {}
            Ok(rotated) => {
                // Keep rotated credentials private for recovery. Never declare
                // success merely because a local config was deleted.
                let rotated = Grant {
                    access_token: rotated.access_token().secret().clone(),
                    refresh_token: rotated
                        .refresh_token()
                        .map(|value| value.secret().clone())
                        .or(grant.refresh_token),
                    ..grant
                };
                storage::replace_secret(
                    &session.join("rotated-grant.json"),
                    &serde_json::to_vec(&rotated)?,
                )?;
                return Err("refresh remains usable; rotated credentials retained; revoke the application grant with your provider".into());
            }
            _ => return Err("refresh rejection is unconfirmed; closed session retained".into()),
        }
    }
    for name in [
        "grant.json",
        "rotated-grant.json",
        "access-token",
        "doctl.yaml",
        "ready.json",
    ] {
        match std::fs::remove_file(session.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"revoked","provider":grant.provider.name()})
    );
    Ok(())
}

fn refresh_rejected(error: &str, description: Option<&str>) -> bool {
    error == "invalid_grant"
        || (error == "invalid_request"
            && description
                == Some(
                    "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
                ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricts_callback_and_control_origins() {
        assert!(control_url("http://127.0.0.1:8054").is_ok());
        assert!(control_url("https://example.com").is_err());
        assert!(control_url("http://127.0.0.1:8054/anything").is_err());
        assert!(control_url("http://user@127.0.0.1:8054").is_err());
        assert!(redirect_url("http://example.com", Provider::Google).is_err());
        assert!(redirect_url("https://example.com/path", Provider::Google).is_err());
        assert_eq!(
            redirect_url("https://auth.example.com", Provider::Digitalocean)
                .unwrap()
                .as_str(),
            "https://auth.example.com/callback/digitalocean"
        );
    }

    #[test]
    fn does_not_mistake_unrelated_provider_errors_for_revocation() {
        assert!(refresh_rejected("invalid_grant", None));
        assert!(!refresh_rejected(
            "invalid_request",
            Some("Missing client_id")
        ));
        assert!(!refresh_rejected("server_error", None));
    }
}
