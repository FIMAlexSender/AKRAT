# Architecture

The workspace has six crates. `akrat-app` provides the Dioxus Desktop interface and coordinates identity selection, network events, contact trust decisions, messages, and vault persistence. `akrat-core` defines identities, contacts, conversations, message direction, and delivery state. `akrat-crypto` provides Ed25519 identity signatures and an experimental X25519 plus ML-KEM-768 handshake/session cipher. `akrat-protocol` defines invitation, handshake, frame, and session payload types. `akrat-network` provides dual-stack TCP listening, outbound connect, bounded JSON framing, handshake execution, and session actors. `akrat-storage` stores identities, contacts, conversations, and message text in an authenticated encrypted vault.

## Application flow

The user unlocks a vault and selects a local identity. An invitation is parsed and validated before its contact record is saved as known but unverified, or as manually verified only after the user enters the matching complete fingerprint. Outbound connections pin the expected contact key during handshake. Inbound peers remain pending and do not open a message session until the user verifies the full fingerprint and the handshake identity matches that key. A changed key is rejected and cannot replace the stored contact key.

Each conversation is keyed by a local identity and a remote contact. The session actor handles encrypted text and acknowledgements over a single reliable TCP stream. The app persists outgoing text before enqueueing it, persists incoming text before acknowledging it, and deduplicates message IDs in the encrypted vault. TCP transmission is not treated as application receipt. Unacknowledged messages are marked uncertain after disconnection or restart and can be retried with the same ID. Session keys are ephemeral and are not stored; a reconnect performs a fresh handshake.

The vault file uses Argon2id (64 MiB, three passes, one lane) and AES-256-GCM. Unlock derives a key kept in memory for subsequent writes; each write uses a fresh random nonce and the vault format's fixed salt until the next unlock. The in-memory key is discarded when locking. Vault updates use a temporary file, flush the file, then rename it into place.

## Limits

The TCP protocol is experimental and not yet an interoperability specification. IPv4 and IPv6 dual-stack listening is attempted with a dual-stack IPv6 socket; actual route availability is operating-system and network dependent. The app has no relay, NAT traversal, or guaranteed firewall configuration. Inbound listener identity is fixed when listening starts; outbound sessions use the currently selected identity. The UI runs persistence operations synchronously and may briefly pause during larger vault rewrites.

The session actor expects reliable, ordered TCP delivery and rejects sequence gaps or replays. Message acknowledgements are application events; there is no durable server-side queue. There is no Double Ratchet, skipped-message key handling, forward secrecy between messages, or post-compromise recovery beyond fresh keys on reconnect.
