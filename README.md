# anonssh

Single-process SSH client whose network connection is created by the embedded
Arti Tor implementation. No external Tor daemon is required.

```text
anonssh user@host [-p 22] [--cmd "uname -a"] [--key id_ed25519]
                  [--fingerprint SHA256:...]
                  [--exit-country DE]
                  [--proxy socks5h://127.0.0.1:7890]
                  [--bridge "snowflake ..."] [--pt-path lyrebird]
```

## Session behavior

1. Bootstraps Tor in-process with Arti.
2. Creates an isolated Arti client for the SSH connection.
3. Uses an in-memory Ed25519 authentication key by default. `--key` loads
   OpenSSH, PEM, PKCS#8, or PuTTY keys and prompts for encrypted-key
   passphrases without placing them on the command line.
4. Accepts the server host key for the current run only, or verifies the exact
   SHA256 fingerprint supplied by `--fingerprint`.
5. Opens an SSH command or interactive terminal through the Tor circuit.
6. Deletes temporary Arti state on exit unless `--state-dir` is supplied.

`--proxy` sets an upstream SOCKS4/SOCKS5/HTTP CONNECT proxy for every direct
Arti connection. Use `socks5h://127.0.0.1:7890` when a local proxy is needed to
reach Tor without local DNS resolution.

`--bridge` is repeatable and accepts Tor bridge lines. Managed pluggable
transports use `--pt-path`, `ANONSSH_PT_PATH`, a `lyrebird` found on `PATH`, or
Tor Browser's common Windows installation path. Tor Browser's `lyrebird`
supports obfs4, Snowflake, meek_lite, and WebTunnel.

`--exit-country DE` constrains Arti's actual exit-circuit selection to the
given two-letter country code. This reduces the anonymity set and can make
connections fail when few exits in that country permit the destination port.
It is rejected for `.onion` destinations, which do not use exit relays.

After public-key authentication fails, anonssh supports password and
keyboard-interactive authentication, including PAM and multi-prompt OTP/2FA.
Command mode forwards stdin as well as stdout, stderr, and the remote exit
status.

## Fingerprint discipline

- SSH banner and KEXINIT use one stable population profile rather than random,
  internally inconsistent combinations.
- The wire-level HASSH source is covered by a regression test; its current MD5
  is `905ba763813042a5e5327b92d4a053a0`.
- Authentication keys are generated per process unless `--key` is used.
- Host keys are not persisted by anonssh.
- Arti circuits are isolated per SSH connection.

## Limits

Tor is a low-latency anonymity network and does not defeat a global traffic
correlation observer. Reused passwords, usernames, commands, timing, and
application behavior can still link sessions. A Tor exit sees the destination
IP and port; SSH content remains end-to-end encrypted.

Direct Tor bootstrap may be blocked or degraded on censored networks. Use a
working upstream proxy and/or current bridge lines. Bridge availability is an
external network property, not bundled into this executable.

## Build

```text
cargo build --release --locked
cargo test --locked
```

Pre-release assets are published as bare executables for Windows x86-64,
Linux x86-64/ARM64, and macOS Intel/Apple Silicon, plus `SHA256SUMS`.

## License

MIT. Third-party Rust dependencies retain their own licenses; see
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
