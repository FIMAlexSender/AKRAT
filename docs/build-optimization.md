# Phase 0 — optimisation du système de build

Rapport de validation de la Phase 0, branche `v0.1.13-node-autoupdate`, commit final `9796b5b2367e8d403f32014c1b6b4b37a63c865d`. Le run complet `43465990888` a réussi sur Windows, Linux et Android. Les mesures après viennent des runners auto-hébergés avec leurs caches persistants; elles décrivent un parcours chaud, pas un build à froid.

## Référence observée

Les temps ci-dessous viennent des journaux GitHub Actions, pas de mesures RAM ou disque. Ce sont des durées de jobs/étapes relevées sur des runners personnels; la charge des runners n’était pas instrumentée.

| Cible / étape | Avant | Source et limite |
|---|---:|---|
| Windows, job complet | 25 min 29 s | Run `43388562207`; validation 9 min 30 s, Release 12 min 47 s, NSIS 23 s. |
| Linux, job complet | 16 min 01 s | Run `43388562207`; tests/formatage 6 min 15 s, audit/outils 2 min 15 s, Release 5 min 07 s, upload 1 min 51 s. |
| Android, job complet | 15 min 32 s | Run `43388562207`; génération APK Dioxus observée à 9 min 39 s. |
| Compilation Iroh Relay | Non mesurée comme étape distincte | La commande `cargo install` n’avait pas de `--target-dir`; elle ne partageait donc pas explicitement les artefacts Cargo du workspace. |
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

## Résultats de la validation complète

Le run final `43465990888` valide le commit indiqué en tête du rapport. Durées de job relevées dans GitHub Actions :

| Cible | Avant | Après, cache chaud | Gain observé |
|---|---:|---:|---:|
| Windows | 25 min 29 s | 7 min 49 s | −69,3 % |
| Linux | 16 min 01 s | 5 min 31 s | −65,6 % |
| Android | 15 min 32 s | 9 min 12 s | −40,8 % |

Ce sont des durées murales par job, comparant le run de référence `43388562207` au run final. Les jobs n’ont pas été exécutés dans les mêmes conditions de charge et le run final a bénéficié des caches persistants; ces pourcentages décrivent cette exécution, ils ne garantissent pas le même gain à froid. Le run de référence effectuait plusieurs builds Release distincts; le nouveau pipeline les séquence et les partage sur les runners locaux.

### Mesures par commande

Les tailles mémoire sont des pics mesurés sur le groupe de processus. La mémoire disponible minimale est celle de l’hôte pendant la commande. Sous Windows l’échantillonnage est à 1 s; sous Linux à 0,5 s.

| Commande | Durée | Pic mémoire processus | Mémoire hôte minimale | CPU | Lecture / écriture |
|---|---:|---:|---:|---:|---:|
| Windows Clippy + tests | 416,1 s | 398 MB | 19,5 GB | 256,5 s | 418 / 148 MB |
| Windows Release + installation Iroh Relay | 11,3 s | 160 MB | 19,6 GB | 2,1 s | 70 / 0,3 MB |
| Linux Clippy | 2,5 s | 175 MB | 15,7 GB | 0,5 s | 101 / 0,2 MB |
| Linux tests complets | 269,2 s | 2,45 GB | 13,4 GB | 196,9 s | 663 / 312 MB |
| Linux Release workspace | 4,5 s | 513 MB | 15,4 GB | 11,1 s | 285 / 3,1 MB |
| Installation Iroh Relay, cache chaud | 0,5 s | Mesure trop courte pour être représentative | 15,8 GB | Mesure trop courte | 0 / 0 MB observés |
| Android Release APK | 458,9 s | 2,04 GB | 13,8 GB | 302,2 s | 2,54 / 814 MB |
| Packaging/signature Android | 12,0 s | 1,32 GB | 12,5 GB | 49,5 s | < 1 / 44 MB |

Au premier run optimisé `43409072958`, avant que les caches soient chauds, le Release Linux a pris 146,9 s et `cargo install iroh-relay` 36,9 s (pic de 2,97 GB). Les deux commandes utilisaient déjà le même `target`; l’installation n’a compilé qu’une partie supplémentaire du graphe. Au run final, le build Release du workspace a pris 4,5 s et l’installation Iroh Relay 0,5 s, sans compilation observable. L’ancien pipeline ne mesurait pas séparément l’installation, donc aucun gain direct avant/après n’est revendiqué pour cette étape.

### Crates compilés dans les journaux Cargo

Le décompte ci-dessous vient des lignes `Compiling` des étapes Linux, et non du nombre de paquets du `Cargo.lock`. Les lignes comptent les compilations par configuration/commande; le nombre entre parenthèses déduplique les couples nom-version dans la fenêtre considérée.

| Étapes Linux | Avant, run `43388562207` | Premier run optimisé, `43409072958` | Écart observé |
|---|---:|---:|---:|
| Vérifications, Clippy et tests Debug | 850 (652 couples distincts) | 427 (427 couples distincts) | −49,8 % de compilations observées |
| Outils d’audit | 431 (388 distincts) | 431 (388 distincts) | Aucun gain initial; les installations sont réutilisées ensuite |
| Cibles Release et Iroh Relay | 1 174 (704 distincts) | 732 (640 distincts) | −37,6 % de compilations observées |

Le run final chaud n’a pas affiché de lignes `Compiling` pour les étapes Linux Release/audit; leurs commandes ont respectivement duré 4,5 s et 4 s. La CI ne génère pas encore de rapports Cargo Timing HTML; les durées, nombres de lignes Cargo et ressources proviennent des journaux et des mesures de processus. Un build réellement à froid n’a pas été lancé : il aurait exigé d’effacer les caches locaux, ce qui aurait contredit la consigne de les préserver. Ces limites sont à garder à l’esprit pour toute comparaison.

## Vérification du graphe Cargo

Décompte du graphe normal de `akrat-mailbox`, avec les entrées de l’arbre ramenées aux couples uniques nom-version : `cargo tree --locked -e normal --prefix none --format '{p}' -p akrat-mailbox`.

| Mesure | Base `19a1d7d8` | Commit optimisé `9796b5b2` |
|---|---:|---:|
| Couples nom-version uniques | 343 | 218 |
| Noms de paquets uniques | 313 | 196 |
| Dépendance cliente `iroh` | Présente | Absente |
| `iroh-base` | Présente via Iroh | Directe, version `1.4.1` |
| Libsignal | Présente | Présente |

Le graphe normal de Mailbox contient 125 couples nom-version de moins (−36,4 %). Le comptage exclut les dépendances de développement/tests et ne représente pas toutes les cibles du workspace. L’ancienne estimation `471 → 455` utilisait des lignes répétées de l’arbre Cargo; elle est remplacée ici par le comptage des entrées uniques corrigé.

Libsignal est conservé : Mailbox valide et traite les bundles, accusés et messages PQXDH utilisés par son protocole. Iroh client est retiré de son graphe normal; l’API de transport Iroh dans `akrat-core` est maintenant derrière le feature `p2p`, et Mailbox dépend du core avec ses features par défaut désactivées. `iroh-base` reste partagé pour valider les identifiants.

## Tailles mesurées

Tailles brutes des exécutables/APK issus des artefacts CI. Les versions de référence `43388562207` et optimisée `43465990888` ne contiennent pas exactement le même code applicatif; les différences de taille ne sont donc pas attribuées aux seuls changements de build.

| Fichier | Avant | Après | Écart |
|---|---:|---:|---:|
| Windows `akrat-desktop.exe` | 34 138 112 | 34 144 768 | +0,02 % |
| Windows `akrat.exe` | 16 681 984 | 16 717 312 | +0,21 % |
| Windows `akrat-mailbox.exe` | 5 280 256 | 5 298 688 | +0,35 % |
| Windows `akrat-relay.exe` | 2 589 696 | 3 454 976 | +33,41 % |
| Windows `iroh-relay.exe` | 9 654 272 | 9 654 272 | 0 % |
| Windows installeur | 21 641 055 | 21 688 621 | +0,22 % |
| Linux `akrat-desktop` | 49 295 664 | 49 363 952 | +0,14 % |
| Linux `akrat` | 27 077 088 | 27 303 880 | +0,84 % |
| Linux `akrat-mailbox` | 7 455 584 | 7 814 736 | +4,82 % |
| Linux `akrat-relay` | 3 393 224 | 4 702 864 | +38,60 % |
| Linux `iroh-relay` | 13 379 048 | 13 379 048 | 0 % |
| APK Android signé | 30 533 663 | 30 533 663 | 0 % |

Les tailles compressées des artefacts GitHub sont passées de 49 046 860 à 49 456 687 octets sous Windows (+0,84 %), de 34 675 128 à 35 252 926 sous Linux (+1,67 %), et de 29 318 151 à 29 318 278 pour Android. Aucun gain général de taille binaire n’est mesuré. L’augmentation de `akrat-relay` est observée entre deux commits applicatifs différents et doit être analysée dans une comparaison de builds de code identique avant toute attribution.

## Stabilité et verrou Phase 0

- Le workflow complet `43465990888` a réussi sur Windows, Linux et Android; les artefacts incluent les exécutables, l’installeur, l’APK signé et les mesures JSON.
- 115 tests Linux ont réussi dans 15 suites. `favorite_relay_is_preferred_for_an_open_p2p_path` passe sans changement de délai (15 s); les trois tests utilisant un relais local sont sérialisés afin d’éviter leur concurrence dans le même processus. Le timeout n’a pas été augmenté.
- `cargo audit`, `cargo deny`, `cargo machete`, `cargo metadata`, `cargo fmt` et Clippy ont été exécutés et sont verts.
- Les versions d’outils restent épinglées; les archives Protobuf, NSIS et Dioxus CLI sont contrôlées par SHA-256. Audit et builds ciblent le `target` persistant; Linux et Android partagent le runner WSL sans lancer leurs compilations simultanément.
- Les profils d’optimisation, LTO, stripping et nombre de jobs n’ont pas été modifiés : aucune mesure n’a justifié le risque d’un changement de comportement ou d’une baisse de diagnostic.
- Les filtres de validation rapide évitent les builds pour les changements Markdown. Les builds obsolètes d’une branche peuvent être remplacés; les runs de tags ont un groupe distinct non annulable.

La cible d’au moins 30 % de baisse du parcours Windows chaud est dépassée dans ce run. Le build à froid n’a pas été mesuré et une seule exécution complète n’établit pas une distribution statistique. La Phase 0 est considérée validée pour reprendre la v0.1.13, avec ces limites explicites.

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
