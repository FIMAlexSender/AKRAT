# Architecture

## Current implementation

The Cargo workspace divides the application into six crates. `akrat-app` owns the Dioxus Desktop shell and identity vault flow. `akrat-core` owns identity domain types and private signing-key handling. The crypto crate creates Ed25519 identities using operating-system randomness, derives the identity ID and displayed fingerprint from SHA-256 of the public key, verifies signatures, and contains an experimental X25519 plus ML-KEM-768 session implementation. The protocol crate defines version 1 JSON structures with a 256 KiB frame cap. The network crate provides direct TCP connect/listen and length-prefixed JSON framing with a 30-second I/O deadline. The storage crate serializes identity records into a bounded Argon2id-derived AES-256-GCM envelope and reads/writes vault files with a temporary-file rename. The interface connects identity and vault functions only; session, protocol, and network functions are not used by the app.

The core types distinguish an unknown peer, a known but unverified peer, and a manually verified peer. Local identity lifecycle states are represented separately. Private identity keys are not exposed by a key getter and are zeroized on drop. The vault uses Argon2id with 65,536 KiB memory, three iterations, and one lane, then AES-256-GCM; the parameters are fixed in vault version 1.

## Intended boundaries

- `akrat-core`: identity, contact, and conversation domain models and application-level interfaces.
- `akrat-crypto`: identity key handling, authenticated hybrid key establishment, key derivation, and authenticated encryption.
- `akrat-protocol`: bounded, versioned wire messages independent of the transport.
- `akrat-network`: direct TCP connections, framing, and deadlines. It drives the experimental handshake and returns an `UnverifiedSession` whose API withholds the message cipher until the caller confirms the expected peer identity ID and public key. It must handle ciphertext only after that transition. Current primitives do not include conversation multiplexing, persistence, or a message queue.
- `akrat-storage`: encrypted local records and transactional persistence.
- `akrat-app`: user interaction and explicit presentation of trust and connection states.

Future implementations must define and review their protocol before enabling message sending. UI states must come from real backend results, never canned demo data.
