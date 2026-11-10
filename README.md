# AKRAT

AKRAT is an open source peer to peer messenger project. The repository currently contains a Rust workspace, a native desktop interface, Ed25519 identity management, and an encrypted local identity vault. It is not yet a messenger: there is no cryptographic handshake, listener, contact verification, or message transport. The interface deliberately presents these capabilities as unavailable.

## Current status

| Area | Status |
| --- | --- |
| Rust workspace and module boundaries | Implemented |
| Dioxus Desktop shell | Implemented |
| Identity and trust domain types | Implemented |
| Ed25519 multi-identity creation and public fingerprints | Implemented in the desktop UI and `akrat-crypto` |
| Argon2id and AES-256-GCM vault file API | Implemented and connected to the desktop UI |
| Unlock, lock, and reopen local identities | Implemented |
| X25519 and ML-KEM-768 handshake | Not implemented |
| AES-256-GCM message protocol | Not implemented |
| Direct network transport | Not implemented |
| Persistent conversations | Not implemented |

No cryptographic or network security claim should be inferred from this preview.

## Development

Requirements: stable Rust and the Windows desktop prerequisites for Dioxus Desktop, including the Microsoft C++ build tools and WebView2 runtime.

```powershell
cargo run -p akrat-app
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The interface uses system fonts and does not require an external service to start.

On Windows, the encrypted vault is stored at `%LOCALAPPDATA%\AKRAT\identities.vault`. New vault creation requires a passphrase of at least 12 characters; the storage library caps passphrases at 1024 bytes. The current vault format uses Argon2id (64 MiB, 3 passes, 1 lane) and AES-256-GCM with random 16-byte salt and 12-byte nonce. It is a local storage format, not the message protocol.

## Project structure

- `akrat-app` contains the Dioxus Desktop interface.
- `akrat-core` contains shared identity and trust domain types.
- `akrat-crypto` generates independent Ed25519 identities and signs/verifies messages.
- `akrat-protocol` is reserved for versioned wire types.
- `akrat-network` is reserved for direct peer transport.
- `akrat-storage` encodes identity records in a versioned encrypted vault envelope and reads/writes vault files.

The protocol and network crates remain empty boundaries. The crypto and storage code is library functionality only; it is not yet a functioning desktop identity workflow or message backend.

## Security posture

AKRAT is not suitable for sending messages in this state. Identity generation and local vault encryption are operational, but there is no contact verification, session handshake, message transport, or end-to-end message encryption. Review [the threat model](docs/THREAT_MODEL.md), [the architecture](docs/ARCHITECTURE.md), and [the protocol status](docs/PROTOCOL.md) before contributing to security-sensitive work.

`cargo audit` currently reports five transitive warnings: unmaintained `fxhash`, `paste`, and `proc-macro-error`, plus unsoundness advisories for `glib 0.18.5` and build dependency `rand 0.7.3`. They arrive through Dioxus Desktop's cross-platform Wry dependency tree. The `glib` and `rand 0.7.3` entries are not part of the Windows target build in this checkout, but affect other target dependency graphs. No advisory is suppressed; the dependency path needs follow-up as the desktop stack evolves.

## Third-party protocol integration

Signal's `libsignal` is currently distributed under AGPL-3.0-only and its repository does not offer a simple stable Rust library interface matching this desktop application's requirements. Any future adoption requires an explicit compatibility and maintenance review. No Double Ratchet guarantee is present today.

## License

This project is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).
