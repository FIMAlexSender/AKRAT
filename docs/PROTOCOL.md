# Protocol status

## Invitations

The invitation URI remains `akrat://v1/<base64url-no-pad>`. Its decoded document is canonical compact JSON containing invitation format version 1, a SHA-256 identity ID, a 32-byte Ed25519 public key in lowercase hex, and up to eight canonical socket addresses. The parser rejects unknown fields, noncanonical encodings, inconsistent IDs, malformed keys and addresses, duplicates, zero ports, unspecified, multicast, and IPv4 broadcast addresses. Invitations contain no private or session key. An invitation is a routing and key-pinning hint; it does not prove who sent it.

## Handshake V2

The handshake has its own `version = 2` and exact suite identifier `AKRAT_X25519_MLKEM768_HKDFSHA256_ED25519_AES256GCM_V2`. Invitation versioning is independent. A V1 peer or an unrecognized suite is rejected with an explicit incompatible-protocol error. There is no version negotiation or silent fallback.

The TCP handshake is a three-frame exchange:

1. The initiator sends a signed hello containing its stable Ed25519 identity, ephemeral X25519 public key, ephemeral ML-KEM-768 public key, 32-byte random challenge, protocol version and exact suite.
2. The responder validates sizes, version, suite, identity ID/public-key binding and the hello signature before doing KEM encapsulation. Its signed response carries a fresh X25519 key, ML-KEM ciphertext, challenge, identity, suite and a transcript-bound confirmation tag.
3. The initiator checks the expected peer key when pinned, verifies the response signature and responder key confirmation, then sends a signed finish with initiator key confirmation. The responder validates it before returning an unverified session to the app. The app still requires the user's manual fingerprint check before either direction can use the session.

The transcript uses explicit V2 domains, role markers (`I` and `R`), and length-prefixed canonical encodings. It covers both ordered identity IDs and Ed25519 keys, both X25519 keys, the ML-KEM public key and ciphertext, challenges, version and suite. The HKDF-SHA-256 salt is the transcript digest. The X25519 and ML-KEM secrets are length-prefixed in a V2 domain-separated input. Separate HKDF labels derive the session ID and each directional AES-256-GCM key. Role-specific HMAC confirmation labels prevent reflection of the responder confirmation as initiator confirmation. Message AAD binds a V2 domain, suite, version, session ID, sender, recipient and sequence.

The signatures and checks demonstrate transcript integrity and key possession in these code paths; they do not prove the human identity associated with a key. The invitation key is untrusted until manually compared over a separate channel.

## Message protection and ordering

Every active connection uses two distinct AES-256-GCM keys, one per direction. The 96-bit nonce is the first 32 bits of the derived session ID followed by the 64-bit big-endian per-direction sequence. The key is unique to the handshake transcript and direction; a connection accepts only the next exact sequence. A duplicate, skipped, modified or cross-session message fails closed. Because the transport is TCP, AKRAT currently rejects out-of-order messages and has no skipped-message key store.

The send counter advances after successful encryption. The receive counter advances only after tag verification. The network actor drops and closes its engine on I/O, authentication, payload or close termination. Plaintext returned from authenticated decryption is held in a zeroizing buffer while the payload is parsed. The app persists an incoming text before issuing its receipt acknowledgement.

## Session recovery and persistence

No live session key, ratchet state or message key is serialized. A session cannot be restored from a vault. Closing, network failure or process restart invalidates it; reconnection requires a new authenticated V2 handshake and a new ephemeral key set. An outgoing logical message remains in the encrypted vault with its message ID and plaintext until acknowledged; retrying it creates new ciphertext under the new session while preserving the application ID for recipient deduplication.

This policy avoids restoring a stale AES key/counter pair. The vault stores conversation and delivery state only; it does not store cryptographic sequence counters. A successful atomic vault replacement is not a session-state checkpoint. If atomic persistence fails before a message is queued, the app rolls the in-memory message append back. If persistence or send status is uncertain later, the message is marked unconfirmed when possible; retry uses a fresh session and duplicate IDs are not appended twice.

## Limits

Frames are capped at 256 KiB, application text at 10 KiB, and session command/event queues are bounded. The plaintext limit leaves room for JSON escaping and cryptographic metadata. At most 32 inbound handshakes are processed concurrently. The listener is IPv4/IPv6 dual-stack where the operating system supports IPv4-mapped IPv6 sockets. There is no relay, NAT traversal, or guaranteed public reachability.

## Guarantees not provided

V2 still uses one pair of static directional AES-GCM keys for the lifetime of a TCP session. Sequence-derived nonces are unique within that key while the in-memory session is live; they do not rotate the key or erase prior message keys. If a live session key is compromised, captured messages under that key, including prior messages, can be decrypted, and future messages in that session are exposed until the session ends. A fresh handshake helps only if the attacker no longer controls an endpoint and cannot influence the new handshake.

There is no Double Ratchet, per-message forward secrecy, DH ratchet, Sparse Post-Quantum Ratchet, Triple Ratchet, skipped-message recovery, or post-compromise recovery. The handshake uses ephemeral X25519 plus ephemeral ML-KEM-768 for a hybrid shared secret. This provides no post-quantum authentication: the stable identity and signatures are Ed25519, and an active sufficiently capable quantum attacker could forge that identity. This handshake must not be described as equivalent to a post-quantum ratchet.

The code and tests are not an independent cryptographic audit. Do not use AKRAT for sensitive communications.
