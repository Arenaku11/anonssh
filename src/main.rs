use std::borrow::Cow;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{CountryCode, StreamPrefs, TorClient, TorClientConfig};
use clap::Parser;
use russh::client;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{
    ChannelMsg, Disconnect, MethodKind, MethodSet, Preferred, SshId, cipher, compression, kex, mac,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_chanmgr::ProxyProtocol;

fn install_crypto_provider() {
    // Arti, rustls, and russh all use the same process-wide ring provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Parser, Debug)]
#[command(version, about = "Single-process SSH client over embedded Arti Tor")]
struct Cli {
    /// SSH destination in user@host form.
    destination: Option<String>,

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

    /// Bridge line to reach the Tor network (repeatable). Requires --pt-path.
    #[arg(long = "bridge")]
    bridges: Vec<String>,

    /// Path to the pluggable transport binary (e.g. Tor Browser's lyrebird.exe).
    #[arg(long)]
    pt_path: Option<PathBuf>,

    /// Upstream proxy for all Tor connections, e.g. socks5h://127.0.0.1:7890.
    #[arg(long)]
    proxy: Option<String>,

    /// Restrict the Tor exit to this two-letter country code. This reduces the anonymity set.
    #[arg(long)]
    exit_country: Option<CountryCode>,

    /// Execute a command instead of opening an interactive shell.
    #[arg(long)]
    cmd: Option<String>,

    /// Show Arti/Russh diagnostics.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Bootstrap in-process Tor and exit. Intended for installation/CI verification.
    #[arg(long, hide = true)]
    bootstrap_only: bool,
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
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("anonssh: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<u8> {
    install_crypto_provider();
    let cli = Cli::parse();
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_writer(std::io::stderr)
            .init();
    }

    let destination = if cli.bootstrap_only {
        None
    } else {
        let destination = cli
            .destination
            .as_deref()
            .context("destination must be user@host")?;
        let (user, host) = parse_destination(destination)?;
        validate_exit_country_target(cli.exit_country.as_ref(), &host)?;
        Some((user, host))
    };

    let (_temporary_storage, tor_config) = tor_config_with_bridges(
        cli.state_dir.as_ref(),
        &cli.bridges,
        cli.pt_path.as_ref(),
        cli.proxy.as_deref(),
    )?;

    eprintln!("anonssh: bootstrapping in-process Tor (Arti)...");
    let tor = tokio::select! {
        result = TorClient::create_bootstrapped(tor_config) => result.context("bootstrap Arti")?,
        result = tokio::signal::ctrl_c() => {
            result.context("install Ctrl+C handler")?;
            bail!("cancelled while bootstrapping Tor");
        }
    };
    if cli.bootstrap_only {
        eprintln!("anonssh: in-process Tor bootstrap complete");
        return Ok(0);
    }

    let (user, host) = destination.expect("validated non-bootstrap destination");
    let isolated = tor.isolated_client();
    let mut prefs = StreamPrefs::new();
    prefs.new_isolation_group();
    if let Some(country) = cli.exit_country {
        eprintln!("anonssh: restricting exit country to {country}; this reduces the anonymity set");
        prefs.exit_country(country);
    }
    let stream = tokio::select! {
        result = isolated.connect_with_prefs((host.as_str(), cli.port), &prefs) => {
            result.with_context(|| format!("connect through Tor to {host}:{}", cli.port))?
        }
        result = tokio::signal::ctrl_c() => {
            result.context("install Ctrl+C handler")?;
            bail!("cancelled while connecting through Tor");
        }
    };

    let config = Arc::new(ssh_client_config());
    let handler = Handler {
        expected_fingerprint: cli.fingerprint,
    };
    let mut ssh = client::connect_stream(config, stream, handler)
        .await
        .context("SSH handshake")?;

    authenticate(&mut ssh, &user, cli.key.as_ref(), cli.password.as_deref()).await?;

    let exit = match cli.cmd {
        Some(command) => run_command(&ssh, &command).await?,
        None => run_shell(&ssh).await?,
    };
    ssh.disconnect(Disconnect::ByApplication, "", "")
        .await
        .context("disconnect SSH")?;
    Ok(exit.min(u8::MAX as u32) as u8)
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

fn validate_exit_country_target(country: Option<&CountryCode>, host: &str) -> Result<()> {
    if country.is_some() && host.to_ascii_lowercase().ends_with(".onion") {
        bail!("--exit-country cannot be used with an onion service");
    }
    Ok(())
}

fn tor_config_with_bridges(
    state_dir: Option<&PathBuf>,
    bridges: &[String],
    pt_path: Option<&PathBuf>,
    proxy: Option<&str>,
) -> Result<(Option<TempDir>, TorClientConfig)> {
    if let Some(state_dir) = state_dir {
        let cache_dir = state_dir.join("cache");
        let state_dir = state_dir.join("state");
        let mut builder = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
        apply_upstream_proxy(&mut builder, proxy)?;
        apply_bridges(&mut builder, bridges, pt_path)?;
        let config = builder
            .build()
            .context("build persistent Arti configuration")?;
        return Ok((None, config));
    }

    let storage = tempfile::tempdir().context("create temporary Arti storage")?;
    let mut builder = TorClientConfigBuilder::from_directories(
        storage.path().join("state"),
        storage.path().join("cache"),
    );
    apply_upstream_proxy(&mut builder, proxy)?;
    apply_bridges(&mut builder, bridges, pt_path)?;
    let config = builder
        .build()
        .context("build temporary Arti configuration")?;
    Ok((Some(storage), config))
}

fn apply_upstream_proxy(builder: &mut TorClientConfigBuilder, proxy: Option<&str>) -> Result<()> {
    let Some(proxy) = proxy else {
        return Ok(());
    };
    let proxy: ProxyProtocol = proxy
        .parse()
        .with_context(|| format!("parse upstream proxy URI: {proxy}"))?;
    builder.channel().outbound_proxy(proxy);
    Ok(())
}

fn apply_bridges(
    builder: &mut TorClientConfigBuilder,
    bridges: &[String],
    pt_path: Option<&PathBuf>,
) -> Result<()> {
    if bridges.is_empty() {
        return Ok(());
    }
    let pt_path = resolve_pt_path(pt_path)?;

    let mut parsed_bridges = Vec::with_capacity(bridges.len());
    let mut protocols = Vec::new();
    for line in bridges {
        let bridge: BridgeConfigBuilder = line
            .parse()
            .with_context(|| format!("parse bridge line: {line}"))?;
        let protocol = bridge
            .get_transport()
            .context("bridge line does not name a pluggable transport")?
            .parse()
            .with_context(|| format!("parse transport name in bridge line: {line}"))?;
        if !protocols.contains(&protocol) {
            protocols.push(protocol);
        }
        parsed_bridges.push(bridge);
    }

    let mut transport = TransportConfigBuilder::default();
    // lyrebird.exe implements obfs4, snowflake, meek_lite and webtunnel.
    // The transport name inside each bridge line selects the protocol.
    transport
        .protocols(protocols)
        .path(CfgPath::new(pt_path.to_string_lossy().into_owned()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    builder.bridges().enabled(BoolOrAuto::Explicit(true));

    for bridge in parsed_bridges {
        builder.bridges().bridges().push(bridge);
    }
    Ok(())
}

fn resolve_pt_path(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    let candidate = explicit
        .cloned()
        .or_else(|| std::env::var_os("ANONSSH_PT_PATH").map(PathBuf::from))
        .or_else(find_pt_on_path)
        .or_else(find_tor_browser_pt)
        .context(
            "bridge requires --pt-path, ANONSSH_PT_PATH, or a discoverable lyrebird executable",
        )?;
    if !candidate.is_file() {
        bail!("pluggable transport is not a file: {}", candidate.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if candidate.metadata()?.permissions().mode() & 0o111 == 0 {
            bail!(
                "pluggable transport is not executable: {}",
                candidate.display()
            );
        }
    }
    Ok(candidate)
}

fn find_pt_on_path() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["lyrebird.exe", "snowflake-client.exe"]
    } else {
        &["lyrebird", "snowflake-client"]
    };
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
            .find(|candidate| candidate.is_file())
    })
}

fn find_tor_browser_pt() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .map(|base| {
            base.join("Tor Browser/Browser/TorBrowser/Tor/PluggableTransports/lyrebird.exe")
        })
        .find(|candidate| candidate.is_file())
}

fn load_or_generate_key(path: Option<&PathBuf>) -> Result<PrivateKey> {
    match path {
        Some(path) => match russh::keys::load_secret_key(path, None) {
            Ok(key) => Ok(key),
            Err(russh::keys::Error::KeyIsEncrypted) => {
                let passphrase = rpassword::prompt_password("Private key passphrase: ")
                    .context("read private key passphrase")?;
                russh::keys::load_secret_key(path, Some(&passphrase))
                    .with_context(|| format!("decrypt private key {}", path.display()))
            }
            Err(error) => {
                Err(error).with_context(|| format!("read private key {}", path.display()))
            }
        },
        None => PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .context("generate ephemeral Ed25519 key"),
    }
}

async fn authenticate<H: client::Handler>(
    ssh: &mut client::Handle<H>,
    user: &str,
    key_path: Option<&PathBuf>,
    configured_password: Option<&str>,
) -> Result<()>
where
    H::Error: Send,
{
    let key = load_or_generate_key(key_path)?;
    let publickey = ssh
        .authenticate_publickey(
            user,
            PrivateKeyWithHashAlg::new(
                Arc::new(key),
                ssh.best_supported_rsa_hash().await?.flatten(),
            ),
        )
        .await
        .context("public-key authentication")?;
    if publickey.success() {
        return Ok(());
    }

    let mut remaining = auth_remaining(&publickey);
    if remaining
        .iter()
        .any(|method| *method == MethodKind::Password)
    {
        let password = match configured_password {
            Some(password) => password.to_owned(),
            None => rpassword::prompt_password("SSH password: ").context("read password")?,
        };
        let password_result = ssh
            .authenticate_password(user, password)
            .await
            .context("password authentication")?;
        if password_result.success() {
            return Ok(());
        }
        remaining = auth_remaining(&password_result);
    }

    if remaining
        .iter()
        .any(|method| *method == MethodKind::KeyboardInteractive)
    {
        let mut response = ssh
            .authenticate_keyboard_interactive_start(user, None)
            .await
            .context("start keyboard-interactive authentication")?;
        loop {
            match response {
                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    bail!(
                        "SSH authentication failed (remaining methods: {}; partial success: {partial_success})",
                        format_methods(&remaining_methods)
                    );
                }
                KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    if !name.is_empty() {
                        eprintln!("{name}");
                    }
                    if !instructions.is_empty() {
                        eprintln!("{instructions}");
                    }
                    let use_configured =
                        configured_password.filter(|_| prompts.len() == 1 && !prompts[0].echo);
                    let mut answers = Vec::with_capacity(prompts.len());
                    for prompt in prompts {
                        let answer = if let Some(password) = use_configured {
                            password.to_owned()
                        } else if prompt.echo {
                            use std::io::Write as _;
                            eprint!("{}", prompt.prompt);
                            std::io::stderr().flush()?;
                            let mut answer = String::new();
                            std::io::stdin().read_line(&mut answer)?;
                            answer.trim_end_matches(['\r', '\n']).to_owned()
                        } else {
                            rpassword::prompt_password(prompt.prompt)?
                        };
                        answers.push(answer);
                    }
                    response = ssh
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .context("respond to keyboard-interactive authentication")?;
                }
            }
        }
    }

    bail!(
        "SSH authentication failed (remaining methods: {})",
        format_methods(&remaining)
    )
}

fn auth_remaining(result: &AuthResult) -> MethodSet {
    match result {
        AuthResult::Success => MethodSet::empty(),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods.clone(),
    }
}

fn format_methods(methods: &MethodSet) -> String {
    if methods.is_empty() {
        return "none".to_owned();
    }
    methods
        .iter()
        .map(|method| <&str>::from(method))
        .collect::<Vec<_>>()
        .join(",")
}

async fn run_command<H: client::Handler>(ssh: &client::Handle<H>, command: &str) -> Result<u32>
where
    H::Error: Send,
{
    let mut channel = ssh.channel_open_session().await?;
    channel.exec(true, command).await?;
    interact(&mut channel).await
}

async fn run_shell<H: client::Handler>(ssh: &client::Handle<H>) -> Result<u32>
where
    H::Error: Send,
{
    let mut channel = ssh.channel_open_session().await?;
    let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));
    channel
        .request_pty(
            true,
            "xterm-256color",
            width.into(),
            height.into(),
            0,
            0,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    let _raw_mode = RawModeGuard::enable()?;
    interact(&mut channel).await
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("enable terminal raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

async fn interact(channel: &mut russh::Channel<client::Msg>) -> Result<u32> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut input = [0_u8; 4096];
    let mut exit_status = 0;
    let mut stdin_open = true;

    loop {
        tokio::select! {
            read = stdin.read(&mut input), if stdin_open => {
                let count = read?;
                if count == 0 {
                    channel.eof().await?;
                    stdin_open = false;
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

fn normalize_fingerprint(value: &str) -> String {
    value.trim().trim_start_matches("SHA256:").to_owned()
}

const PROFILE_KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_G14_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_GEX_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

const PROFILE_CIPHERS: &[cipher::Name] = &[
    cipher::AES_128_GCM,
    cipher::AES_256_GCM,
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
];

const PROFILE_MACS: &[mac::Name] = &[
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256,
    mac::HMAC_SHA512,
    mac::HMAC_SHA1,
];

const PROFILE_COMPRESSION: &[compression::Name] = &[compression::NONE];

fn ssh_client_config() -> client::Config {
    let default = Preferred::DEFAULT;
    client::Config {
        // x/crypto/ssh's conventional banner and SupportedAlgorithms order.
        // A single population profile avoids rare per-session combinations.
        client_id: SshId::Standard(Cow::Borrowed("SSH-2.0-Go")),
        preferred: Preferred {
            kex: Cow::Borrowed(PROFILE_KEX),
            key: default.key,
            host_key_certificates: default.host_key_certificates,
            cipher: Cow::Borrowed(PROFILE_CIPHERS),
            mac: Cow::Borrowed(PROFILE_MACS),
            compression: Cow::Borrowed(PROFILE_COMPRESSION),
        },
        inactivity_timeout: None,
        ..Default::default()
    }
}

#[cfg(test)]
fn hassh_source(preferred: &Preferred) -> String {
    fn names<T: AsRef<str>>(values: &[T]) -> String {
        values
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(",")
    }

    [
        names(&preferred.kex),
        names(&preferred.cipher),
        names(&preferred.mac),
        names(&preferred.compression),
    ]
    .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn formats_remaining_authentication_methods() {
        let methods = MethodSet::from(&[MethodKind::Password, MethodKind::KeyboardInteractive][..]);
        assert_eq!(format_methods(&methods), "password,keyboard-interactive");
        assert_eq!(format_methods(&MethodSet::empty()), "none");
    }

    #[test]
    fn validates_explicit_pluggable_transport_path() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(if cfg!(windows) {
            "lyrebird.exe"
        } else {
            "lyrebird"
        });
        fs::write(&file, b"test").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(resolve_pt_path(Some(&file)).unwrap(), file);
    }

    #[test]
    fn rejects_missing_pluggable_transport_path() {
        let missing = PathBuf::from("definitely-missing-anonssh-lyrebird");
        let error = resolve_pt_path(Some(&missing)).unwrap_err().to_string();
        assert!(error.contains("not a file"));
    }

    #[test]
    fn rejects_exit_country_for_onion_service() {
        let cli =
            Cli::try_parse_from(["anonssh", "--exit-country", "DE", "user@example.onion"]).unwrap();
        let country = cli.exit_country.unwrap();
        assert_eq!(country.as_ref(), "DE");
        let error = validate_exit_country_target(Some(&country), &cli.destination.unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("onion service"));
    }

    #[tokio::test]
    async fn wire_kexinit_has_stable_hassh() {
        let (client_stream, mut peer) = tokio::io::duplex(64 * 1024);
        let connection = tokio::spawn(client::connect_stream(
            Arc::new(ssh_client_config()),
            client_stream,
            Handler {
                expected_fingerprint: None,
            },
        ));

        let mut banner = Vec::new();
        loop {
            let byte = peer.read_u8().await.unwrap();
            banner.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        assert_eq!(banner, b"SSH-2.0-Go\r\n");
        peer.write_all(b"SSH-2.0-test-server\r\n").await.unwrap();

        let packet_len = peer.read_u32().await.unwrap() as usize;
        let mut packet = vec![0_u8; packet_len];
        peer.read_exact(&mut packet).await.unwrap();
        let padding_len = packet[0] as usize;
        let payload = &packet[1..packet_len - padding_len];
        assert_eq!(payload[0], 20, "first packet must be SSH_MSG_KEXINIT");

        let mut offset = 17; // message number + 16-byte cookie
        let mut read_name_list = || {
            let len = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let value = std::str::from_utf8(&payload[offset..offset + len])
                .unwrap()
                .to_owned();
            offset += len;
            value
        };
        let kex = read_name_list();
        let _host_keys = read_name_list();
        let ciphers_client_server = read_name_list();
        let _ciphers_server_client = read_name_list();
        let macs_client_server = read_name_list();
        let _macs_server_client = read_name_list();
        let compression_client_server = read_name_list();

        let source = [
            kex,
            ciphers_client_server,
            macs_client_server,
            compression_client_server,
        ]
        .join(";");
        assert_eq!(source, hassh_source(&ssh_client_config().preferred));
        assert_eq!(
            source,
            "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,ext-info-c,kex-strict-c-v00@openssh.com;aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr;hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none"
        );
        assert_eq!(
            format!("{:x}", md5::compute(source.as_bytes())),
            "905ba763813042a5e5327b92d4a053a0"
        );

        connection.abort();
    }
}
