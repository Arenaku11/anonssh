# Third-party licenses and provenance

`anonssh` is MIT-licensed. It embeds and links the following third-party
components, each under its own permissive license.

Embedded binaries are produced by this repository's CI from pinned,
hash-verified upstream sources (see `.github/workflows/embed.yml`).

## tor

- Version: pinned tag recorded in `internal/embed/manifest.txt` at build time
- Upstream: https://gitlab.torproject.org/tpo/core/tor
- License: BSD 3-Clause (upstream `LICENSE`), dependencies zlib (zlib),
  libevent (BSD 3-Clause), OpenSSL (Apache-2.0)
- Provenance: built from the official source tarball whose SHA256 is pinned
  in `.github/workflows/embed.yml`; static binaries for each platform are
  committed under `internal/embed/bin/`

## obfs4proxy

- Upstream: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/obfs4proxy
- License: BSD 2-Clause
- Provenance: built from a pinned upstream tag by CI

## snowflake-client

- Upstream: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake
- License: BSD 3-Clause
- Provenance: built from a pinned upstream tag by CI

## Go dependencies

| Module | License |
|---|---|
| golang.org/x/crypto | BSD 3-Clause |
| golang.org/x/term | BSD 3-Clause |
| golang.org/x/net | BSD 3-Clause |
| github.com/cretz/bine | MIT |
