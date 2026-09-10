# anonssh

Single-process SSH client whose network connection is created by the embedded
Arti Tor implementation. No external Tor daemon is required.

```text
anonssh user@host [-p 22] [--cmd "uname -a"] [--key id_ed25519]
                  [--fingerprint SHA256:...]
                  [--proxy socks5h://127.0.0.1:7890]
                  [--bridge "snowflake ..."] [--pt-path lyrebird]
```

## Session behavior

1. Bootstraps Tor in-process with Arti.
2. Creates an isolated Arti client for the SSH connection.
3. Uses an in-memory Ed25519 authentication key by default. `--key` loads an
   OpenSSH private key instead.
4. Accepts the server host key for the current run only, or verifies the exact
   SHA256 fingerprint supplied by `--fingerprint`.
5. Opens an SSH command or interactive terminal through the Tor circuit.
6. Deletes temporary Arti state on exit unless `--state-dir` is supplied.

`--proxy` sets an upstream SOCKS4/SOCKS5/HTTP CONNECT proxy for every direct
Arti connection. Use `socks5h://127.0.0.1:7890` when a local proxy is needed to
reach Tor without local DNS resolution.

`--bridge` is repeatable and accepts Tor bridge lines. Managed pluggable
transports require `--pt-path`; Tor Browser's `lyrebird` supports obfs4,
Snowflake, meek_lite, and WebTunnel.

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

## License

MIT. Third-party Rust dependencies retain their own licenses; see
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
