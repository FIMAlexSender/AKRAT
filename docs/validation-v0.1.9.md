# Validation AKRAT v0.1.9

## Résultats locaux

- Workspace Rust : 50 tests réussis sous Windows x64 et 50 tests réussis sous Ubuntu 24.04 x64, dont les scénarios interprocessus Alice/Bob et la fédération A–B–C après arrêt du bootstrap.
- `cargo fmt --all -- --check`, Clippy strict (`-D warnings`) et `cargo check --locked --workspace --all-targets` : réussis sous Windows et Linux.
- `cargo audit` : aucune vulnérabilité publiée classée exploitable dans `Cargo.lock`. Six avertissements de dépendances persistent : `glib 0.18.5` (RUSTSEC-2024-0429), `rand 0.7.3` (RUSTSEC-2026-0097), et les crates non maintenues `fxhash`, `paste`, `proc-macro-error`, `proc-macro-error2`.
- Smoke test de la CLI serveur : initialisation, rotation des clés de reçus, révocation de l'ancienne clé et rechargement de la configuration réussis.
- Windows x64 : Desktop, CLI et Mailbox compilés en release ; installateur NSIS v0.1.9 généré.
- Linux x64 : Desktop, CLI et Mailbox compilés en release dans WSL2 Ubuntu 24.04. Le binaire Mailbox se charge sans dépendance dynamique manquante dans cet environnement.
- Android arm64 : APK v0.1.9 / versionCode 1009 construit, icône AKRAT présente dans les ressources adaptatives, signature vérifiée. Le certificat correspond à la clé de test persistante utilisée par les versions précédentes.
- macOS et installation sur téléphone physique : non testés ; aucun Mac ni appareil Android n'est connecté.

## Limites de sécurité

La racine de continuité serveur demeure une clé persistante qui doit être sauvegardée. Sa compromission exige un réépinglage hors bande. Le limiteur est en mémoire, repart à zéro au redémarrage et ne prévient pas un déni de service distribué. AKRAT utilise libsignal pour PQXDH et Double Ratchet, mais ne publie qu'un prekey Kyber signé de longue durée, sans pool de prekeys PQ à usage unique. L'intégration AKRAT n'a pas fait l'objet d'un audit cryptographique indépendant. Ces limites ne sont pas présentées comme des garanties établies.

## CI et diffusion

Le workflow construit Windows, Linux et Android sur les runners auto-hébergés configurés pour AKRAT ; il n'utilise aucun runner macOS. Les travaux de pull request provenant de dépôts externes sont exclus des runners privés. Les sommes des fichiers de distribution sont produites dans `SHA256SUMS`.
