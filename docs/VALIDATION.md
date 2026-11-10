# Validation for v0.1.2

## Automated checks

Run these commands from the repository root on Windows with Rust stable, the MSVC build tools, and WebView2 available:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p akrat-app
cargo audit
pwsh ./scripts/build-windows-package.ps1
```

The workspace test run retains all 27 v0.1.1 tests and adds handshake V2 signature/transcript and downgrade failures, nonces/sequences, out-of-order and replay rejection, key clearing on close, stale-message rejection after a new handshake, and the fresh-handshake recovery policy. The protocol parser tests use fixed-seed `proptest` cases for arbitrary length-bounded frame bytes, handshake/message frames, session payloads, and invitation text. Size caps are enforced before parsing or allocation.

`cargo fuzz` is not installed in the Windows environment. No libFuzzer run is claimed. The proptest parser checks are repeatable property tests with 256 fixed-seed cases per property; they are not a substitute for sustained coverage-guided fuzzing or an external security review.

The two-vault localhost integration test still covers bidirectional message delivery, fresh handshake after reconnect, retry with the same logical ID, receiver deduplication, and reopening both encrypted JSON vaults. The 0.1.2 source-level V2 protocol runs in this integration test. It is not a two-computer network test.

## Session recovery boundaries

No session key, nonce counter, or Ratchet state is serialized. A live session cannot be restored; after failure or process restart the app must establish a new authenticated V2 session. The tests check that an old session's ciphertext is rejected after a new handshake and that closing a session zeroizes its directional keys. There is no process-kill injection at every instruction or filesystem boundary. The precise state/receipt analysis and its limitations are in [SESSION_DESIGN.md](SESSION_DESIGN.md).

The vault is an encrypted JSON document, not SQLite. Atomic replacement and authenticated decryption are tested; SQLite transactions do not apply. Crash recovery around network writes and acknowledgements is covered through logical retry/deduplication and vault-reopen integration, not exhaustive power-loss injection.

## Graphical and physical network checks

The complete two-profile GUI workflow (independent vaults, invitation copy/import, fingerprint comparison, bidirectional exchange and offline history after closing one window) was manually run with v0.1.1. The v0.1.2 changes its handshake transcript and session engine; the GUI has not yet been manually re-run against two v0.1.2 instances. The current automated TCP integration uses the v0.1.2 code. Only one dark theme exists.

For a LAN check, use two separate computers on the same trusted network. Start listening on the receiving computer, import the invitation on the sender, compare the full fingerprint through an independent channel, verify and connect. Then repeat in the opposite direction. A localhost test does not demonstrate physical LAN reachability.

For an Internet check, first confirm the LAN case. Then configure inbound port forwarding or a globally reachable IPv6 address and matching firewall rule, and attempt from a separate network. Record address family, router and firewall configuration, and CGNAT status. No Internet reachability is implied by local tests.

## Portable ZIP

The archive contains `akrat-app.exe` and documentation; it does not bundle Rust or WebView2. Install the Microsoft Edge WebView2 Runtime on the target computer. The launch check should use a `PATH` without Rust tool directories; WebView2 remains an operating-system prerequisite.
