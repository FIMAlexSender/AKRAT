# Threat model and current guarantees

## Intended adversary

The network is hostile: an adversary may observe, delay, block, modify, replay, or inject traffic. An IP address is only a routing hint. A first-seen key remains unverified until the user compares the complete fingerprint over a trusted independent channel. A changed key is rejected instead of inheriting the stored trust decision.

The encrypted vault is intended to protect identity private keys, contacts, and local conversation history from someone who can read the vault file but does not know the passphrase. It does not protect data while the app is unlocked from malware, a compromised operating system, memory inspection, screenshots, or another process with access to the user account.

## Implemented behavior

The Windows app can create and select Ed25519 identities, import/export versioned invitations, listen and connect over TCP, require manual fingerprint verification on first contact, exchange encrypted session messages, and store conversation text in the encrypted local vault. Outgoing text is persisted before transport enqueue. Incoming text is authenticated, deduplicated and persisted before the application acknowledgement is sent. TCP write completion is labeled as transmission, not receipt. Acknowledgement state is persisted separately. After a disconnect or restart, pending/transmitted outgoing messages become unconfirmed and may be retried with the same ID. Session keys are not saved; reconnect performs a fresh handshake.

## Known limitations

The X25519 + ML-KEM-768 handshake, key schedule, session state machine, message actor, and application integration are experimental and have not received independent security review. The ML-KEM crate has no independent audit claim. No Double Ratchet or post-compromise recovery is implemented. Fresh keys per connection are not equivalent to a Double Ratchet. The protocol expects ordered TCP delivery and does not support offline messages, out-of-order delivery, or a relay.

Direct IP reachability depends on local firewall settings, router port forwarding, ISP policy, and NAT/CGNAT. AKRAT cannot guarantee connectivity between arbitrary computers. The UI stores plaintext message content only in the authenticated encrypted vault; text necessarily exists in process memory while displayed or sent. File and network denial-of-service risks remain subject to operational limits and review.

## Dependency advisories

`cargo audit` reports five transitive advisories in the desktop dependency graph. No advisory is ignored or allowed through an audit exception. Details and current target reachability are in [SECURITY_REVIEW.md](SECURITY_REVIEW.md). These findings do not establish a vulnerability in AKRAT's cryptographic message path, but they remain dependency maintenance and platform risks.

## Release posture

Do not use AKRAT 0.1.1 for sensitive communications. Independent cryptographic review, dependency remediation or documented acceptance, installer validation, and two-computer network testing remain necessary before a security-sensitive release.
