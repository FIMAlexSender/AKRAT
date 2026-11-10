# Protocol status

There is no AKRAT wire protocol implemented or specified for interoperability yet. No listener or outbound connection is enabled. The local encrypted vault envelope is version 1, but it is not a network protocol.

The protocol design must remain versioned and bounded. Its eventual handshake must authenticate identities and transcript parameters, combine fresh X25519 and ML-KEM-768 shared secrets using an explicitly reviewed construction, derive separate directional keys, and confirm possession before application data is accepted. Application messages are required to use AES-256-GCM with critical routing and sequence metadata bound as associated data. Replays, malformed frames, oversized input, unsupported versions, and identity changes must fail closed.

These are requirements, not claims about the current code. The first implementation should be reviewed against NIST FIPS 203, the Signal PQXDH and Double Ratchet specifications, and the selected libraries' API, maintenance, and licensing. Do not enable user messaging until the handshake and persistence behavior are testable end to end.
