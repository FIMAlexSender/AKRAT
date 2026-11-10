# Threat model and current guarantees

## Intended adversary

The design treats the network as hostile. A network adversary may observe, modify, delay, block, replay, or inject traffic. An IP address is a routing hint, not an identity. A first-seen identity must remain unverified until people compare a fingerprint over an independent channel. A changed key must not silently inherit a verified state.

The project also intends to protect stored conversation content and identity private keys from someone who can read the local data files but does not know the vault secret.

## Out of scope

No software can protect a user from a compromised endpoint while it is unlocked, screen capture, coercion, malware with process access, or denial of service. Direct IP connectivity does not promise reachability through NATs or firewalls. Traffic analysis and metadata protection are not specified.

## Guarantees today

None of the planned cryptographic or network guarantees are implemented. The current application has no identity keys, vault, message transport, session, or ciphertext. The UI indicates that these functions are unavailable. This repository is a development foundation and must not be used for sensitive communication.

## Security review required

Before sensitive use, the chosen handshake construction, post-quantum implementation, persistence design, dependency set, and complete application require independent security review. Automated checks cannot establish cryptographic correctness.
