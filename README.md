# AKRAT

AKRAT is an experimental peer-to-peer desktop messenger. Version 0.1.0 connects a Windows desktop interface to direct TCP sessions, invitation import/export, manual fingerprint verification, and encrypted local conversation history.

## Current capabilities

| Area | Status |
| --- | --- |
| Windows Dioxus Desktop interface and encrypted vault | Implemented |
| Multiple Ed25519 identities and locally labeled contacts | Implemented |
| Versioned `akrat://v1/` invitation format with canonical encoding and validation | Implemented |
| IPv4/IPv6 dual-stack TCP listener and outbound connection | Implemented; internet reachability depends on firewall, port forwarding, and NAT |
| Manual fingerprint comparison and pinned identity key | Implemented; invitation contents alone do not verify a person |
| Experimental X25519 + ML-KEM-768 authenticated handshake | Integrated into app, unaudited |
| AES-256-GCM session messages, acknowledgements, bounded queues, replay ordering | Integrated; experimental protocol |
| Encrypted local conversation history, deduplication, lock/reopen | Implemented |
| Double Ratchet and post-compromise recovery | Not implemented; deferred |
| Independent cryptographic audit and real internet deployment validation | Not completed |

Do not use this release for sensitive communications. The cryptographic construction, ML-KEM implementation, application integration, dependency tree, and Windows distribution need independent review. Direct TCP does not traverse all firewalls, NATs, or CGNAT configurations; AKRAT has no relay service.

## Build and run on Windows

Install stable Rust, Microsoft C++ build tools, and the WebView2 runtime. Then run:

```powershell
cargo run -p akrat-app
```

Build a standalone Windows executable with:

```powershell
cargo build --release -p akrat-app
```

The executable is `target\release\akrat-app.exe`. It does not require Rust to run, but requires the Windows WebView2 runtime and system WebView dependencies. The vault is stored in `%LOCALAPPDATA%\AKRAT\identities.vault`.

## Two local application profiles

To launch two isolated copies on one Windows machine, build the app and run the helper from PowerShell 7.4 or later. It assigns separate local data directories. The listening copy can use port 49444; import its invitation into the second copy and compare fingerprints through an independent channel.

```powershell
.\scripts\run-two-local-profiles.ps1
```

This validates two local processes only. For two separate computers, install/run the standalone executable on each, permit the chosen inbound TCP port in the host firewall, and configure router port forwarding where needed. Share the `akrat://` invitation through a trusted channel and verify its full fingerprint independently. CGNAT may prevent direct connections.

Create a portable Windows ZIP using `scripts\build-windows-package.ps1`. This environment does not have WiX, Inno Setup, or the Dioxus CLI, so it cannot generate or validate an MSI/installer. The ZIP contains the standalone executable, README, license, and security/architecture documents; it does not bundle WebView2.

## Checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p akrat-app
cargo audit
```

`cargo audit` currently reports five transitive advisories in the Dioxus desktop dependency graph. They are not suppressed; details and reachability are documented in [the security review](docs/SECURITY_REVIEW.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol status](docs/PROTOCOL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Dependency and security review](docs/SECURITY_REVIEW.md)

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
