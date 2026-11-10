# Threat model and current guarantees

## Intended adversary

The design treats the network as hostile. A network adversary may observe, modify, delay, block, replay, or inject traffic. An IP address is a routing hint, not an identity. A first-seen identity must remain unverified until people compare a fingerprint over an independent channel. A changed key must not silently inherit a verified state.

The project also intends to protect stored conversation content and identity private keys from someone who can read the local data files but does not know the vault secret.

## Out of scope

No software can protect a user from a compromised endpoint while it is unlocked, screen capture, coercion, malware with process access, or denial of service. Direct IP connectivity does not promise reachability through NATs or firewalls. Traffic analysis and metadata protection are not specified.

## Guarantees today

Identity creation, Ed25519 signatures, and encrypted vault file APIs are integrated into the Windows application. Vault files are protected by Argon2id and AES-256-GCM. A passphrase protects the records if someone reads the vault file, subject to the strength of that passphrase and the correctness of the implementation. There is no peer handshake, contact verification, message transport, session, or end-to-end message encryption. This application must not be used for messaging or sensitive communication.

## Security review required

Before sensitive use, the chosen handshake construction, post-quantum implementation, persistence design, dependency set, and complete application require independent security review. Automated checks cannot establish cryptographic correctness.

The current `cargo audit` report contains transitive warnings for three unmaintained crates and two unsoundness advisories in the Dioxus Desktop dependency graph. The Windows release build does not compile the GTK `glib` or `rand 0.7.3` dependency paths, but other platform builds may. The advisory output is retained in CI and is not suppressed.
