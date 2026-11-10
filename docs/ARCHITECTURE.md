# Architecture

## Current implementation

The Cargo workspace divides the application into six crates. `akrat-app` owns the Dioxus Desktop shell and depends on `akrat-core` for shared domain types. The other four crates are empty boundaries at this stage. There are no calls between the UI and cryptographic, networking, or storage backends because those backends do not exist yet.

The initial core types distinguish an unknown peer, a known but unverified peer, and a manually verified peer. Local identity lifecycle states are represented separately. These are data types only; no trust decision or identity persistence logic is implemented.

## Intended boundaries

- `akrat-core`: identity, contact, and conversation domain models and application-level interfaces.
- `akrat-crypto`: identity key handling, authenticated hybrid key establishment, key derivation, and authenticated encryption.
- `akrat-protocol`: bounded, versioned wire messages independent of the transport.
- `akrat-network`: direct TCP connections, framing, deadlines, and backpressure; it must handle ciphertext only.
- `akrat-storage`: encrypted local records and transactional persistence.
- `akrat-app`: user interaction and explicit presentation of trust and connection states.

Future implementations must define and review their protocol before enabling message sending. UI states must come from real backend results, never canned demo data.
