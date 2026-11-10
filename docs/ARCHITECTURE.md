# Architecture

## Current implementation

The Cargo workspace divides the application into six crates. `akrat-app` owns the Dioxus Desktop shell and identity vault flow. `akrat-core` owns identity domain types and private signing-key handling. The crypto crate creates Ed25519 identities using operating-system randomness, derives the identity ID and displayed fingerprint from SHA-256 of the public key, and verifies signatures. The storage crate serializes identity records into a bounded Argon2id-derived AES-256-GCM envelope and reads/writes vault files with a temporary-file rename. The interface connects these functions for first-time setup, multi-identity creation, locking, and unlocking. There is no protocol or network implementation.

The core types distinguish an unknown peer, a known but unverified peer, and a manually verified peer. Local identity lifecycle states are represented separately. Private identity keys are not exposed by a key getter and are zeroized on drop. The vault uses Argon2id with 65,536 KiB memory, three iterations, and one lane, then AES-256-GCM; the parameters are fixed in vault version 1.

## Intended boundaries

- `akrat-core`: identity, contact, and conversation domain models and application-level interfaces.
- `akrat-crypto`: identity key handling, authenticated hybrid key establishment, key derivation, and authenticated encryption.
- `akrat-protocol`: bounded, versioned wire messages independent of the transport.
- `akrat-network`: direct TCP connections, framing, deadlines, and backpressure; it must handle ciphertext only.
- `akrat-storage`: encrypted local records and transactional persistence.
- `akrat-app`: user interaction and explicit presentation of trust and connection states.

Future implementations must define and review their protocol before enabling message sending. UI states must come from real backend results, never canned demo data.
