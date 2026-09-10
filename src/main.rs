use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use clap::Parser;
use russh::client;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(version, about = "Single-process SSH client over embedded Arti Tor")]
struct Cli {
    /// SSH destination in user@host form.
    destination: String,

    /// SSH port.
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,

    /// OpenSSH private key. Default: fresh in-memory Ed25519 key.
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,

    /// Password. If omitted, prompt only after public-key authentication fails.
    #[arg(long)]
    password: Option<String>,

    /// Expected server SHA256 fingerprint. Without this, the key is accepted for this run only.
    #[arg(long)]
    fingerprint: Option<String>,

    /// Persist Arti state/cache in this directory. Default: temporary and deleted on exit.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Execute a command instead of opening an interactive shell.
    #[arg(long)]
    cmd: Option<String>,

    /// Show Arti/Russh diagnostics.
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Clone)]
struct Handler {
    expected_fingerprint: Option<String>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let got = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        if let Some(expected) = &self.expected_fingerprint {
            return Ok(normalize_fingerprint(expected) == normalize_fingerprint(&got));
        }
        eprintln!("anonssh: accepted host key for this run: {got}");
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_writer(std::io::stderr)
            .init();
    }

    let (user, host) = parse_destination(&cli.destination)?;
    let (_temporary_storage, tor_config) = tor_config(cli.state_dir.as_ref())?;

    eprintln!("anonssh: bootstrapping in-process Tor (Arti)...");
    let tor = TorClient::create_bootstrapped(tor_config)
        .await
        .context("bootstrap Arti")?;
    let isolated = tor.isolated_client();
    let stream = isolated
        .connect((host.as_str(), cli.port))
        .await
        .with_context(|| format!("connect through Tor to {host}:{}", cli.port))?;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    });
    let handler = Handler {
        expected_fingerprint: cli.fingerprint,
    };
    let mut ssh = client::connect_stream(config, stream, handler)
        .await
        .context("SSH handshake")?;

    let key = load_or_generate_key(cli.key.as_ref())?;
    let publickey = ssh
        .authenticate_publickey(
            &user,
            PrivateKeyWithHashAlg::new(Arc::new(key), ssh.best_supported_rsa_hash().await?.flatten()),
        )
        .await
        .context("public-key authentication")?;

    if !publickey.success() {
        let password = match cli.password {
            Some(password) => password,
            None => rpassword::prompt_password("SSH password: ").context("read password")?,
        };
        let password_result = ssh
            .authenticate_password(&user, password)
            .await
            .context("password authentication")?;
        if !password_result.success() {
            bail!("SSH authentication failed");
        }
    }

    let exit = match cli.cmd {
        Some(command) => run_command(&ssh, &command).await?,
        None => run_shell(&ssh).await?,
    };
    ssh.disconnect(Disconnect::ByApplication, "", "")
        .await
        .context("disconnect SSH")?;
    std::process::exit(exit as i32);
}

fn parse_destination(destination: &str) -> Result<(String, String)> {
    let Some((user, host)) = destination.rsplit_once('@') else {
        bail!("destination must be user@host");
    };
    if user.is_empty() || host.is_empty() {
        bail!("destination must be user@host");
    }
    Ok((user.to_owned(), host.to_owned()))
}

fn tor_config(state_dir: Option<&PathBuf>) -> Result<(Option<TempDir>, TorClientConfig)> {
    if let Some(state_dir) = state_dir {
        let cache_dir = state_dir.join("cache");
        let state_dir = state_dir.join("state");
        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .context("build persistent Arti configuration")?;
        return Ok((None, config));
    }

    let storage = tempfile::tempdir().context("create temporary Arti storage")?;
    let config = TorClientConfigBuilder::from_directories(
        storage.path().join("state"),
        storage.path().join("cache"),
    )
    .build()
    .context("build temporary Arti configuration")?;
    Ok((Some(storage), config))
}

fn load_or_generate_key(path: Option<&PathBuf>) -> Result<PrivateKey> {
    match path {
        Some(path) => PrivateKey::read_openssh_file(path)
            .with_context(|| format!("read private key {}", path.display())),
        None => PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .context("generate ephemeral Ed25519 key"),
    }
}

async fn run_command<H: client::Handler>(ssh: &client::Handle<H>, command: &str) -> Result<u32>
where
    H::Error: Send,
{
    let mut channel = ssh.channel_open_session().await?;
    channel.exec(true, command).await?;
    receive_channel(&mut channel).await
}

async fn run_shell<H: client::Handler>(ssh: &client::Handle<H>) -> Result<u32>
where
    H::Error: Send,
{
    let mut channel = ssh.channel_open_session().await?;
    let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));
    channel
        .request_pty(true, "xterm-256color", width.into(), height.into(), 0, 0, &[])
        .await?;
    channel.request_shell(true).await?;

    crossterm::terminal::enable_raw_mode().context("enable terminal raw mode")?;
    let result = interact(&mut channel).await;
    crossterm::terminal::disable_raw_mode().context("disable terminal raw mode")?;
    result
}

async fn interact(channel: &mut russh::Channel<client::Msg>) -> Result<u32> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut input = [0_u8; 4096];
    let mut exit_status = 0;

    loop {
        tokio::select! {
            read = stdin.read(&mut input) => {
                let count = read?;
                if count == 0 {
                    channel.eof().await?;
                } else {
                    channel.data(&input[..count]).await?;
                }
            }
            message = channel.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stderr.write_all(&data).await?;
                        stderr.flush().await?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = status,
                    None => break,
                    _ => {}
                }
            }
        }
    }
    Ok(exit_status)
}

async fn receive_channel(channel: &mut russh::Channel<client::Msg>) -> Result<u32> {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit_status = 0;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.write_all(&data).await?,
            ChannelMsg::ExtendedData { data, .. } => stderr.write_all(&data).await?,
            ChannelMsg::ExitStatus { exit_status: status } => exit_status = status,
            _ => {}
        }
    }
    stdout.flush().await?;
    stderr.flush().await?;
    Ok(exit_status)
}

fn normalize_fingerprint(value: &str) -> String {
    value.trim().trim_start_matches("SHA256:").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_destination_from_last_at() {
        assert_eq!(
            parse_destination("name@realm@example.com").unwrap(),
            ("name@realm".into(), "example.com".into())
        );
    }

    #[test]
    fn normalizes_sha256_fingerprint() {
        assert_eq!(normalize_fingerprint("SHA256:abc"), "abc");
        assert_eq!(normalize_fingerprint("abc"), "abc");
    }
}
