#![forbid(unsafe_code)]

mod broker;
mod login;
mod storage;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_PENDING: usize = 128;

type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
#[command(version, about = "Private OAuth callback relay and cloud login client")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve browser callbacks and a separate, authenticated local control API.
    Serve {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8053")]
        callback_listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8054")]
        control_listen: SocketAddr,
    },
    /// Request approval and exchange the code locally; never print credentials.
    Login {
        #[arg(long, value_enum)]
        provider: Provider,
        #[arg(long)]
        client_file: PathBuf,
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        session_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8054")]
        control_url: String,
        #[arg(long)]
        callback_base: String,
    },
    /// Revoke session credentials and verify that they cannot be reused.
    Revoke {
        #[arg(long)]
        client_file: PathBuf,
        #[arg(long)]
        session_dir: PathBuf,
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
        Command::Login {
            provider,
            client_file,
            runtime_dir,
            session_dir,
            control_url,
            callback_base,
        } => {
            login::run(
                provider,
                client_file,
                runtime_dir,
                session_dir,
                control_url,
                callback_base,
            )
            .await
        }
        Command::Revoke {
            client_file,
            session_dir,
        } => login::revoke(client_file, session_dir).await,
    };
    if let Err(error) = result {
        // All errors at credential boundaries are mapped to fixed messages.
        eprintln!("agent-auth: {error}");
        std::process::exit(1);
    }
}
