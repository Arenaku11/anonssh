# Third-party licenses and provenance

`anonssh` is MIT-licensed and links Rust crates recorded with exact versions
and checksums in `Cargo.lock`.

Primary components:

- Arti / `arti-client` and Tor Project crates: MIT OR Apache-2.0
  - https://gitlab.torproject.org/tpo/core/arti
- Russh and related crates: Apache-2.0
  - https://github.com/Eugeny/russh
- Tokio: MIT
  - https://github.com/tokio-rs/tokio
- rustls: Apache-2.0 OR ISC OR MIT
  - https://github.com/rustls/rustls
- ring: ISC-style license with bundled third-party notices
  - https://github.com/briansmith/ring
- SQLite / `libsqlite3-sys`: public domain SQLite plus crate-specific terms
  - https://www.sqlite.org/copyright.html

The complete dependency graph is defined by `Cargo.lock`. Release builders must
retain license and notice files required by each dependency. No Tor daemon,
GeoIP database, obfs4proxy, Snowflake client, or other third-party executable is
embedded in the repository or release binary.
