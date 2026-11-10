# Validation for v0.1.1

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

The workspace tests cover trust-state distinctions, handshake key pinning, tampered ciphertext, sequence ordering, bounded framing, the 10 KiB worst-case control-character payload, localhost bidirectional TCP exchange, and independent encrypted vaults. The vault integration test sends messages both ways, reconnects with fresh session keys, resends the same logical message ID, confirms recipient deduplication, and reopens both vaults.

In the v0.1.1 manual Windows run, two independently configured profiles were opened from the portable ZIP with Rust tool directories removed from `PATH`. The native **Copier l'invitation** action was pasted into the other instance and validated. The receiving instance displayed the complete incoming fingerprint; after comparison with the initiating profile, confirmation created a manually verified contact and opened the channel. A message in each direction appeared as **Reçu et authentifié** and **Reçu et confirmé par le pair**. Closing the initiating window left the other profile offline with both messages visible in its local history. Both windows were then closed. The GUI was not relaunched after that full close in this run; vault reopen is covered by the integration test above.

The protocol uses an encrypted JSON vault, not SQLite. Atomic replacement and authenticated decryption are tested; SQLite transactions do not apply. The tests do not inject a process kill at each instruction boundary around socket writes and acknowledgement persistence. Their crash-recovery guarantee is therefore reasoned from persisted states and the retry/deduplication tests, not demonstrated by exhaustive fault injection.

## Two-profile GUI scenario

Launch two independent application instances with distinct `LOCALAPPDATA` values:

```powershell
pwsh ./scripts/run-two-local-profiles.ps1
```

In the first window, create a vault and identity, go to **Connexion**, start TCP listening, choose the detected private IPv4 address, create and copy an invitation. In the second window, create a separate vault and identity, paste and validate the invitation, compare the displayed full fingerprint against the first window through an independent channel, mark the contact as verified, and connect. Exchange one message in each direction, disconnect, reconnect, retry an unconfirmed message, then close and reopen each vault to confirm the conversations remain.

This scenario validates two app processes on one Windows computer and loopback/local-host routing only. It does not prove connectivity between two physical computers. The current stylesheet contains one dark theme; no second theme or theme switch is implemented in v0.1.1.

## Physical network checks

For a LAN check, use two separate computers on the same trusted network. On the receiving computer, allow the chosen inbound TCP port on its private network profile and start listening. Put its LAN address and port into the invitation. Import it on the sending computer, compare the complete identity fingerprint using a separate trusted channel, verify the contact, and connect. Repeat in the opposite direction with the roles reversed.

For an Internet check, first confirm the LAN case. Then configure an inbound port-forward on the receiving router or use a globally reachable IPv6 address with a matching firewall rule. Share the advertised public address and port, and attempt the connection from a separate network such as a mobile hotspot. Record the router, firewall profile, address family, and whether the ISP uses CGNAT. A successful local test is not evidence of Internet reachability.

## Portable ZIP

The archive contains `akrat-app.exe` and documentation; it does not bundle Rust or WebView2. Install the Microsoft Edge WebView2 Runtime on the target computer. The ZIP launch check must be performed with Rust tool directories removed from `PATH`; an installed WebView2 runtime remains an operating-system prerequisite.
