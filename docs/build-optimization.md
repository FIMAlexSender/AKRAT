# Phase 0 — optimisation du système de build

État des changements au 13 novembre 2026. Les mesures « après » seront ajoutées après une validation complète de la branche avec le nouveau pipeline.

## Référence observée

Les temps ci-dessous viennent des journaux GitHub Actions, pas de mesures RAM ou disque. Ce sont des durées de jobs/étapes relevées sur des runners personnels; la charge des runners n’était pas instrumentée.

| Cible / étape | Avant | Source et limite |
|---|---:|---|
| Windows, job complet | 25 min 29 s | Run `43388562207`; validation 9 min 30 s, Release 12 min 47 s, NSIS 23 s. |
| Windows, job complet sous forte concurrence | 37 min 42 s | Run `43396923592`; Linux et Android compilent en parallèle sur la même machine physique. Ce n’est pas une référence de build isolée. |
| Linux, job complet | 16 min 01 s | Run `43388562207`; tests/formatage 6 min 15 s, audit/outils 2 min 15 s, Release 5 min 07 s, upload 1 min 51 s. |
| Android, job complet | 15 min 32 s | Run `43388562207`; génération APK Dioxus observée à 9 min 39 s. |
| Iroh Relay séparé | Non mesuré séparément | La commande `cargo install` ne précisait pas de `--target-dir`; elle ne partageait donc pas explicitement le répertoire de build du workspace. |
| RAM, CPU, E/S par commande | Non mesurés | Les anciens workflows ne produisaient aucune mesure de ressources. |
| Tailles individuelles des exécutables | Non mesurées | Seule la taille des artefacts CI complets était disponible : Windows 49 046 860 octets, Linux 34 675 128 octets, APK Android 29 318 151 octets dans le run `43388562207`. |

## Changements réalisés

- Les validations courantes utilisent `validate-fast.yml`: formatage, métadonnées Cargo, contrôle du diff et tests des crates modifiées. Un changement aux manifests, au verrou Cargo ou à la configuration de compilation déclenche `cargo check` du workspace.
- Le workflow complet reste requis pour les validations et publications : Clippy, tests complets, audits, exécutables Release, Windows, Linux, Android, packaging et contrôles de publication restent présents.
- Le workflow complet s’exécute dans l’ordre Windows, Linux, Android. Les validations rapide et complète partagent un groupe de concurrence par branche; un tag utilise son propre groupe non annulable.
- Les checkouts persistants utilisent `clean: false`. Cela préserve le `target` local, tandis que chaque OS garde son propre environnement de build. Linux et Android utilisent le même runner WSL et ne nettoient plus le `target` de l’autre job.
- `Swatinem/rust-cache` a été retiré des runners persistants. Les logs Linux/Android disaient `No cache found`; l’action désactivait aussi l’incrémentalité quand elle n’était pas déjà définie. Les builds de test utilisent `CARGO_INCREMENTAL=1`; les builds Release et les outils d’audit gardent `CARGO_INCREMENTAL=0`.
- Le toolchain CI est fixé à Rust `1.100.0` pour Windows, Linux et Android. Windows l’installe une fois avec `rustup`; la prochaine exécution vérifiera que le build MSVC passe avec ce compilateur commun.
- Le workspace Release est construit en une commande. L’installation de `iroh-relay` et des outils Cargo précise `--target-dir target`, afin de partager les artefacts compatibles avec les autres commandes Cargo.
- Protobuf, NSIS et Dioxus CLI sont conservés dans des répertoires durables des runners et leur archive est contrôlée par SHA-256 avant usage. Les installations SDK Android restent explicitement versionnées.
- Les tests d’intégration Iroh qui lancent des relais locaux sont sérialisés. Le délai de 15 secondes reste inchangé; l’erreur affiche les chemins observés en cas de nouvel échec.
- `akrat-core` expose le feature `p2p`; `akrat-mailbox` le dépend déjà avec `default-features = false`. L’API Iroh client est désormais optionnelle et les identifiants restent validés via `iroh-base`. Libsignal et les vérifications cryptographiques utilisées par Mailbox restent dans son graphe.
- La collecte CI écrit des JSON par commande avec la durée, le RSS maximal du groupe de processus, la mémoire disponible minimale, le CPU et les octets lus/écrits. Les sorties comprennent aussi les tailles exactes des exécutables et de l’APK. Le collecteur utilise un échantillonnage de 0,5 s sous Linux et 1 s sous Windows; les processus plus courts qu’un intervalle peuvent être manqués.

## Vérification du graphe Cargo

Commande : `cargo tree --locked -e normal --format '{p}' -p akrat-mailbox | sort -Unique`.

| Mesure | Avant | Après |
|---|---:|---:|
| Identifiants de paquets distincts (nom + version + source) | 471 | 455 |
| Dépendance Iroh client `iroh` | Présente | Absente |
| Base d’identifiants `iroh-base` | Transitive via Iroh | Directe, version `1.4.1` |
| Libsignal | Présente | Présente, nécessaire aux validations cryptographiques Mailbox |

La réduction mesurée est de 16 identifiants de paquets, soit 3,4 % pour le graphe de dépendances normales de Mailbox. Ce chiffre n’est pas le nombre de crates compilés dans toutes les cibles, et ne couvre pas les dépendances de test.

## Après validation complète

| Indicateur | Avant | Après | Gain |
|---|---:|---:|
| Validation Windows | 9 min 30 s de tests/formatage | À mesurer | À calculer |
| Release Windows | 12 min 47 s + 23 s NSIS | À mesurer | À calculer |
| Build Linux | 16 min 01 s total | À mesurer | À calculer |
| Build Android | 15 min 32 s total | À mesurer | À calculer |
| Compilation Iroh Relay | Non mesurée séparément | À mesurer | Non calculable |
| RAM maximale | Non mesurée | À mesurer | Non calculable |
| Graphe Mailbox | 471 identifiants | 455 identifiants | −16 (−3,4 %) |
| Taille des exécutables | Non mesurée par fichier | À mesurer | Non calculable |

Le seuil de réduction Windows de 30 % et l’objectif inférieur à 15 minutes restent des objectifs. Ils ne seront évalués qu’avec des mesures après validation, en précisant si la machine était chargée.

## Prérequis des runners auto-hébergés

### Windows x64 (`akrat-local`)

- Rust `1.100.0`, MSVC C++ Build Tools et le SDK Windows requis par le toolchain.
- Python 3 pour enregistrer les tailles de fichiers.
- Les archives Protobuf `36.2` et NSIS `3.13`, vérifiées par SHA-256 puis mises en cache dans `%LOCALAPPDATA%\AKRAT\ci-tools`.
- Espace disponible pour les cibles Cargo Debug/Release et les exécutables.

### Linux x64 / WSL (`akrat-linux-local`)

- Utilisateur runner non-root, Rust `1.100.0`, composants `rustfmt` et `clippy`.
- `pkg-config`, WebKitGTK 4.1, GTK 3, OpenSSL et `protoc` 36.2.
- Python 3, Bash, `zip`, Java 17, Android SDK/NDK versionnés, CMake 3.22.1 et les cibles Rust Android.
- Espace suffisant pour un `target` partagé entre les jobs Linux et Android.

Les dépôts locaux Cargo, `target`, SDK et outils conservés ne doivent pas être effacés pour résoudre un échec sans diagnostic préalable.
