#![forbid(unsafe_code)]

mod broker;
mod capture;
mod storage;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_PENDING: usize = 128;
type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn random_token() -> oauth2::CsrfToken {
    oauth2::CsrfToken::new_random_len(32)
}

#[derive(Clone, Copy, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Provider {
    Google,
    Digitalocean,
}
impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Digitalocean => "digitalocean",
        }
    }
}

#[derive(Parser)]
#[command(
    version,
    about = "Forward native cloud CLI approval callbacks through your browser"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve callbacks and a separate authenticated local control API.
    Serve {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8053")]
        callback_listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8054")]
        control_listen: SocketAddr,
    },
    /// Open a CLI-generated login in Chrome and forward only its final callback.
    Capture {
        #[arg(long, value_enum)]
        provider: Provider,
        /// Owned mode-0600 file in a private tmpfs directory; never a token file.
        #[arg(long)]
        authorization_url_file: PathBuf,
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8054")]
        control_url: String,
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        browser_url: String,
        #[arg(long)]
        callback_base: String,
    },
}

#[tokio::main]
async fn main() {
    let result = match Args::parse().command {
        Command::Serve {
            runtime_dir,
            callback_listen,
            control_listen,
        } => broker::serve(runtime_dir, callback_listen, control_listen).await,
        Command::Capture {
            provider,
            authorization_url_file,
            runtime_dir,
            control_url,
            browser_url,
            callback_base,
        } => {
            capture::run(
                provider,
                authorization_url_file,
                runtime_dir,
                control_url,
                browser_url,
                callback_base,
            )
            .await
        }
    };
    if result.is_err() {
        // Network/CDP errors can contain authorization URLs. Never print them.
        eprintln!(
            "agent-auth: operation failed; check relay/browser availability and restart the isolated CLI login"
        );
        std::process::exit(1);
    }
}
