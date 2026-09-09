# anonssh

Single-binary anonymous SSH client. The tor daemon and pluggable transports
are embedded; no external dependencies at run time.

```
anonssh user@host [-p 22] [--cmd "uname -a"] [--key id_ed25519]
                  [--exit-country US,DE] [--bridges obfs4|snowflake]
```

What it does per session:

1. Extracts an embedded tor build into a fresh temp directory and bootstraps
   (progress on stderr).
2. Queries the Onionoo directory **through tor** for exit relays whose policy
   permits the target port, filters by `--exit-country` if given, pins one at
   random (rotates every session).
3. Connects through that exit with a randomized OpenSSH client banner
   (fingerprint pool, drawn fresh per session).
4. Authenticates with a session-ephemeral ed25519 key by default (never
   reused, never persisted; falls back to a password prompt on refusal).
   `--key` uses your own identity file instead.
5. Validates the host key in memory only (TOFU per run, never written to
   disk). `--fingerprint` pins an expected fingerprint.
6. On exit: tor is stopped, the temp directory is deleted, nothing remains.

## Fingerprint discipline

- Client version banner: randomized from a pool of common OpenSSH versions.
- Host key: verified in memory per run; never touches `known_hosts`.
- Client auth key: ephemeral by default; the server never sees the same
  public key twice across sessions.
- Exit relay: different every session by default.
- Tor state (guards, cached consensuses): fresh temp dir per run unless
  `--tor-state-dir` is given.

Known limits: tor hides the network path, not local traffic correlation; a
local observer can still see that connections happen. Password authentication
is kept as a fallback but a reused password is itself a fingerprint.

## License

MIT. Embedded third-party components are BSD/Apache-licensed; see
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
