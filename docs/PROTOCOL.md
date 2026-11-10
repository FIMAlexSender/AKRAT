# Protocol status

## Invitations

The current invitation URI is `akrat://v1/<base64url-no-pad>`. Its decoded document is canonical compact JSON containing format version 1, a SHA-256 identity ID, a 32-byte Ed25519 public key in lowercase hex, and up to eight canonical socket addresses. The parser rejects unknown fields, noncanonical encodings, inconsistent IDs, invalid keys/addresses, duplicates, zero ports, unspecified, multicast, and IPv4 broadcast addresses. Invitations contain no private or session key. An invitation is a routing and key-pinning hint; it does not prove who sent it.

## Handshake and sessions

The experimental handshake is a three-message exchange over length-prefixed JSON TCP frames. `akrat-crypto::session` signs the initiator hello and responder response, validates the fixed version/suite, combines an ephemeral X25519 secret with an ML-KEM-768 shared secret, hashes the signed transcript into HKDF-SHA-256 context, derives distinct directional AES-256-GCM keys and a session ID, and uses key confirmation before accepting the session. The network API returns an unverified session until the app checks the expected identity ID and public key. On first contact, that expected key is accepted only after the user compares the complete fingerprint over an independent channel. The responder does not have an expected key until the inbound request is manually approved; no application payload is accepted before approval.

Session payloads are AES-256-GCM encrypted. Nonces combine the first four session-ID bytes with a 64-bit sequence counter; the session ID, sender, recipient, version, and sequence are authenticated as associated data. Receivers require the next exact sequence number, rejecting old or skipped sequences. TCP supplies ordering and retransmission while connected. A fresh handshake creates fresh session keys after reconnect; no session secret is persisted. Unacknowledged application messages retain their message ID in the vault and may be resent under a new session, where receiver-side message-ID deduplication prevents duplicate history entries.

Frames are capped at 256 KiB, message text at 10 KiB in the session actor, and session command/event queues are bounded. The text limit keeps the JSON array encoding of encrypted byte vectors within the frame cap even when JSON escaping expands control characters. At most 32 inbound handshakes are processed concurrently. The listener is IPv4/IPv6 dual-stack where the operating system supports IPv4-mapped IPv6 sockets. The app has no relay, NAT traversal, or guaranteed public reachability.

## Experimental guarantees and open review

The cryptographic integration is not independently audited, and the ML-KEM Rust crate has not undergone an independent audit. The UI's manual fingerprint check provides human key continuity only if users compare the complete fingerprint correctly over a trusted independent channel. This is not equivalent to a reviewed identity transparency system.

There is no Double Ratchet, per-message ratchet, out-of-order message support, skipped-message key store, or post-compromise recovery. Fresh session keys on reconnect do not provide the Double Ratchet's guarantees. Traffic analysis, endpoint compromise, denial of service, and malicious local process access are out of scope. The protocol needs independent cryptographic and interoperability review before sensitive use.
