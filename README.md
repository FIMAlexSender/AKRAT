# AKRAT

AKRAT is an open source peer to peer messenger project. The repository currently contains the Rust workspace foundation and a native desktop interface. It is not yet a messaging application: no identity keys, encrypted vault, cryptographic handshake, listener, or message transport is implemented. The interface deliberately presents these capabilities as unavailable.

## Current status

| Area | Status |
| --- | --- |
| Rust workspace and module boundaries | Implemented |
| Dioxus Desktop shell | Implemented |
| Identity and trust domain types | Initial types only |
| Identity generation and encrypted vault | Not implemented |
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

## Project structure

- `akrat-app` contains the Dioxus Desktop interface.
- `akrat-core` contains shared identity and trust domain types.
- `akrat-crypto` is reserved for cryptographic mechanisms.
- `akrat-protocol` is reserved for versioned wire types.
- `akrat-network` is reserved for direct peer transport.
- `akrat-storage` is reserved for the local encrypted vault.

The cryptography, protocol, network, and storage crates are currently empty boundaries. They are not fake implementations or functioning backends.

## Security posture

AKRAT is not suitable for sending sensitive messages in this state. There is no end-to-end encryption because there is not yet any messaging transport. Review [the threat model](docs/THREAT_MODEL.md), [the architecture](docs/ARCHITECTURE.md), and [the protocol status](docs/PROTOCOL.md) before contributing to security-sensitive work.

## Third-party protocol integration

Signal's `libsignal` is currently distributed under AGPL-3.0-only and its repository does not offer a simple stable Rust library interface matching this desktop application's requirements. Any future adoption requires an explicit compatibility and maintenance review. No Double Ratchet guarantee is present today.

## License

This project is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).
