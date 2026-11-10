# Session audit and Ratchet decision for v0.1.2

## Scope and conclusion

AKRAT v0.1.1 did not implement a Ratchet. Its handshake was signed and transcript-bound, and derived separate direction keys, but a live TCP session kept one AES-256-GCM key per direction with sequence-derived nonces. The session object was not serialized. A reconnect or restart performed a new ephemeral X25519 + ML-KEM-768 handshake.

V0.1.2 hardens that existing V2 handshake and makes the no-restore rule explicit. It adds an engine boundary for the established session cipher and a `FreshAuthenticatedHandshakeRequired` recovery policy. It does not implement a Double, Sparse Post-Quantum, or Triple Ratchet. That is deliberate: none of the candidate integrations was sufficiently drop-in, compatible with all AKRAT requirements, and maintainable to adopt without a larger, separately reviewed protocol migration.

## Audit of the current handshake

| Area | Code behavior | Review result and remaining limit |
| --- | --- | --- |
| Ephemeral secrets | Fresh X25519 key pair on each handshake; fresh ML-KEM-768 keypair at initiator and encapsulation at responder. Shared secret buffers and derived AES keys use zeroizing wrappers; ML-KEM is built with its zeroize feature. | No ephemeral private key is stored in the vault. This is hybrid initial key establishment only, not a continuing PQ ratchet. |
| Stable identities | Ed25519 signs the hello, response and finish. Identity IDs are SHA-256 of the corresponding signing public key. `verify_strict` checks signatures. The app additionally compares the complete public-key fingerprint through a user-supplied independent channel. | Human key verification is not a proof that a name or address maps to the person the user expects. Ed25519 authentication is not post-quantum. |
| Transcript | V2 adds explicit hello, response and transcript domains; initiator/responder role markers and length prefixes; exact version/suite; identity keys and IDs; both X25519 keys; ML-KEM public key/ciphertext; and challenges. Response signatures cover the transcript and response confirmation. Finish signatures and role-specific confirmation tags bind the transcript and session. | This is code-level binding, not an independent protocol proof. There is no negotiation: unsupported versions and suites fail rather than falling back. |
| Hybrid KDF | X25519 and ML-KEM shared secrets are length-prefixed under a V2 domain. HKDF-SHA-256 uses the transcript hash as salt and separate labels for session ID and each direction's AES-256-GCM key. | Hybrid security depends on correct implementation and at least one secure component, but does not make Ed25519 authentication post-quantum. |
| Message AEAD | AES-256-GCM remains mandatory. Direction-specific keys, a session-scoped sequence nonce and AAD binding suite/version/session/sender/recipient/sequence are used. Authentication failures do not advance the receive sequence. | The AES key is static until the TCP session ends. This is not per-message forward secrecy or recovery after live key compromise. |
| Replay/order | Receive side requires the exact next sequence and rejects duplicates, old sessions, changed metadata and skipped messages. | TCP is ordered, so v2 intentionally has no out-of-order delivery or skipped-message key cache. |
| Application IDs and receipts | The app persists an outgoing logical message before enqueueing it. A receipt is sent only after the incoming authenticated message is persisted. A retry retains its application ID and is re-encrypted after a new handshake; the vault rejects duplicate IDs. | Disk and network failures can leave delivery uncertain. The app must present that as uncertain and may retry; TCP write completion alone is not an application receipt. |
| Cryptographic state persistence | Session keys, nonces, counters and ratchet state are absent from `VaultData` and have no serialization API. The network actor closes and zeroizes the engine on exit; `Zeroizing` fields also clear on drop. | Restarting cannot continue a previous session. Recovery is always a new authenticated handshake; this sacrifices continuity to avoid stale key/counter restoration. |

## Recovery and persistence boundaries

The application persists the logical outbox and conversation history, not the live crypto engine. During an active connection, encryption consumes the next sequence in memory before network transmission. If transmission is uncertain, the actor is dropped and the engine cannot be restored. On a later connection, the handshake creates new keys and counters, then the same logical message ID can be sent again. The receiver persists before acknowledging and deduplicates before appending, so a crash after persistence but before acknowledgement does not create a second history item.

On receive, a failed AEAD tag leaves the sequence unchanged. Once an authenticated ciphertext is decrypted the sequence advances; if the authenticated payload is malformed, the actor fails closed and discards the session. The plaintext staging buffer is zeroizing while parsed. The GUI persists only the resulting message text in the encrypted vault. A vault-write failure prevents a receipt acknowledgement.

The atomic vault replacement applies to a complete encrypted JSON file, not to a Ratchet checkpoint. The app never attempts to serialize a partially advanced Ratchet. Power-loss fault injection at every CPU instruction and filesystem boundary has not been implemented. Existing integration coverage exercises retry, duplicate delivery, reconnect and vault reopening, not exhaustive crash injection.

## Ratchet alternatives

### Double Ratchet

The Signal design advances a sending/receiving KDF chain for each message and combines it with a DH ratchet when a new public ratchet key arrives. Old message keys can be deleted; later chain keys do not derive earlier message keys. Fresh DH inputs can provide recovery after a temporary compromise once an uncompromised contribution arrives. Headers carry ratchet key and message counters; a bounded skipped-key store supports loss and out-of-order messages. The state machine, rollback rules, skipped-key limits and persistence must all be correct. A symmetric chain alone does not provide break-in recovery.

### Sparse Post-Quantum Ratchet

Signal's SPQR uses a sparse continuous key agreement based on the ML-KEM Braid and chunk/erasure coding so post-quantum contributions can be delivered across unreliable message streams. It supplies fresh post-quantum message-key material and retains only a bounded number of epoch states in the specified design. Compared with the existing TCP cipher this adds KEM public material and ciphertext/header bandwidth, KEM computation and memory, coding redundancy, epoch synchronization, skipped-key management, and more persistence/parser state. AKRAT has no measurements for those costs.

### Triple Ratchet

Signal's Triple Ratchet runs the classical Double Ratchet and SPQR in parallel, combines their per-message keys with a KDF, and authenticates a composite header containing classical and post-quantum ratchet data. This targets hybrid classical and post-quantum confidentiality across a continuing conversation, rather than only at initial key establishment. It carries both state machines, combines their ordering/loss/persistence rules, and costs more bandwidth, computation and memory than either component alone. Correctly combining two message keys does not eliminate the need to validate each state machine and the header binding.

No AKRAT performance benchmark has been run for Double Ratchet, SPQR or Triple Ratchet. The bandwidth and state costs above are qualitative consequences of the specified headers, KEM operations, chunk coding and per-epoch state, not measured numbers.

## Rust implementation review

| Candidate | Useful properties | Why it is not integrated in v0.1.2 |
| --- | --- | --- |
| [Signal libsignal](https://github.com/signalapp/libsignal) | First-party Rust protocol implementation used by Signal; AGPL-3.0 is aligned with this repository's license. It contains Double Ratchet code and AES-GCM primitives. | Signal explicitly says use outside Signal is unsupported; internal Rust APIs and implementations can change without notice. Its current message-key type includes CBC key, MAC key and IV, so the shipped Signal wire cipher does not preserve AKRAT's AES-GCM requirement as a direct integration. This would also replace the current handshake/session wire format and require compatibility, persistence, Windows-build and license review. |
| [Matrix vodozemac](https://github.com/matrix-org/vodozemac) | Pure Rust Olm Double Ratchet used in Matrix; Apache-2.0; the project reports a Least Authority audit with no significant findings. | Olm's specified message AEAD is AES-256-CBC with truncated HMAC-SHA-256, not AES-256-GCM. It is not PQXDH, SPQR or Triple Ratchet. Adapting its key/state internals to a different AEAD would cease to be a direct use of its reviewed protocol implementation. |
| `light-double-ratchet`, `ksi-double-ratchet`, and similar crates | Provide study material or a classic Double Ratchet API in Rust. | The reviewed crate documentation describes `light-double-ratchet` as in development and unaudited; `ksi-double-ratchet` is a community reimplementation rather than a protocol implementation with demonstrated independent review. Neither supplies the required integrated PQ Triple Ratchet. Not suitable as a security foundation for this release. |
| [Signal SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet) | Official Rust SPQR implementation, AGPL-3.0, includes formal-verification workflow and ProVerif models; outputs message keys for a containing messaging protocol. | It is a component, not a complete conversation/session protocol. It requires careful composition with Double Ratchet, message headers, AES-GCM, bounded ordering/replay and encrypted state persistence. It is specifically described as usable with libsignal. There is no released, drop-in AKRAT integration and no independent review of the composition. |

The [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/) (revision 4), [PQXDH specification](https://signal.org/docs/specifications/pqxdh/), [Triple Ratchet/SPQR implementation](https://github.com/signalapp/SparsePostQuantumRatchet), [libsignal repository](https://github.com/signalapp/libsignal), and [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final) were examined. NIST SP 800-227 gives KEM implementation and use recommendations; it does not standardize a secure-messaging ratchet.

The chosen v0.1.2 step is to keep AES-256-GCM, use an explicit V2 transcript/suite, isolate established session operations behind `SessionEngine`, and make fresh-handshake-only recovery explicit. A future Double or Triple Ratchet requires a separately designed wire version, a vetted implementation-compatible AEAD, a bounded and authenticated state-store transaction model, reference vectors, interoperability tests, fault injection and independent cryptographic review. V0.1.2 does not claim any Ratchet property.

## Compromise scenarios

| Compromise | Consequence under v2 |
| --- | --- |
| Ed25519 identity private key | Attacker can impersonate that identity in future handshakes. Existing manually verified contacts may block an unexpected key change, but theft of the same private key is not distinguishable from the owner. No Ratchet fixes identity-key theft. |
| Live session AES key | Captured ciphertexts using that directional key can be decrypted; the static key also reveals later messages in the same direction until session closure. Directional separation limits compromise to that direction unless both keys are taken. There is no per-message key erasure or PCS within the session. |
| Encrypted vault file only | Messages, contacts, trust state and identity private keys remain encrypted under the passphrase-derived vault key. The attack can still delete or roll back the file. Weak passphrases permit offline guessing. |
| Unlocked process memory | A memory adversary may recover identity keys, the vault key, displayed/history plaintext and current session keys. Current-session traffic becomes readable. Later recovery requires the adversary to lose endpoint access and a new handshake to contribute fresh uncompromised randomness. |
| Passive future quantum attacker | The ephemeral ML-KEM-768 contribution is intended to resist harvest-now/decrypt-later recovery of the handshake secret if the KEM implementation and hybrid combiner are sound. Ed25519 signatures are not post-quantum, and the protocol has no post-quantum ratchet after the handshake. |
| Active future quantum attacker | Ed25519 authentication can be forged if the quantum threat includes solving the underlying discrete-log problem. The V2 handshake does not provide post-quantum identity authentication. |

This analysis is a code review, not a proof or an independent audit.
