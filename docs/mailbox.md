# Serveur AKRAT Mailbox — préversion v0.1.9

## État

Le workspace contient maintenant `akrat-mailbox`, un serveur TCP autonome Windows/Linux. Le transport réseau utilise Noise XX et impose au client de vérifier l'empreinte Noise du serveur. Les reçus de dépôt sont signés avec une clé Ed25519 distincte. SQLite conserve des octets opaques, des empreintes, des échéances et des tombstones ; les capacités de dépôt et de récupération sont aléatoires, distinctes et enregistrées sous forme de condensats.

Le noyau `akrat-core::async_crypto` utilise l'API Rust publique de libsignal pour PQXDH et les messages Double Ratchet. Le test vérifie un message initial pendant que Bob est hors ligne, restaure l'état de Bob depuis des octets persistés, puis vérifie le message suivant. Un test interprocessus lance le serveur autonome et des processus clients séparés pour publier le bundle, chiffrer/déposer pendant l'absence de Bob, redémarrer Bob, déchiffrer et acquitter. Les états privés sont conservés dans le coffre v3 chiffré par la phrase secrète. Les coffres v1 et v2 sont migrés à leur prochaine ouverture.

Le serveur applique des buckets token au niveau global, de la source IP, de l'identité Noise cliente et de la boîte ciblée. Les connexions simultanées par source sont bornées, les trames sont plafonnées à 60 Kio et les échanges ont un délai maximal. Les limites sont modifiables avec `akrat-mailbox --config ./server.json limits show` et `limits set --identity-per-minute 300 --identity-burst 60`; elles sont appliquées au redémarrage. L'adresse IP est un signal anti-abus, pas une identité, et des utilisateurs partageant un NAT peuvent partager la limite source.

Le serveur publie des bundles authentifiés. Le dépôt et la publication utilisent la capacité d'écriture ; la lecture des bundles utilise une troisième capacité séparée. La consommation du prekey EC à usage unique est atomique. Une seule clé Kyber signée est publiée à la fois : AKRAT n'implémente pas le pool de signed one-time PQ KEM prekeys d'une implémentation PQXDH complète. Les bundles expirent après 30 jours ; les secrets gardés dans le coffre sont purgés après leur période de rétention. Les capacités créées avec l'ancien schéma sans capacité de bundle doivent être recréées.

Dans Desktop, l'utilisateur configure séparément sa boîte personnelle et la route de boîte du contact vérifié. Coffre déverrouillé, AKRAT publie les bundles et relève la boîte. Si la session directe ne peut pas livrer, le helper Desktop chiffre le message avec le protocole libsignal, conserve le ciphertext dans le coffre et le dépose. Il vérifie le reçu signé du serveur. Quand le destinataire revient, il authentifie, déchiffre et enregistre le message dans le coffre avant d'envoyer un reçu signé avec son identité. Le serveur vérifie ce reçu, le conserve pour l'expéditeur et supprime atomiquement l'enveloppe. Le client expéditeur vérifie la signature, l'identité du destinataire, l'identifiant du message et le condensat avant de passer à « remis ».

Le reçu de dépôt prouve que la clé de signature du serveur a accepté un condensat ; il ne prouve pas la conservation physique du ciphertext. Le reçu du destinataire prouve que sa clé d'identité a signé l'affirmation d'enregistrement ; il ne prouve pas une lecture humaine ni une persistance matérielle au-delà de l'état logiciel. À expiration, le serveur conserve jusqu'à 30 jours un événement d'expiration signé, que l'expéditeur peut récupérer. L'interface propose alors de renvoyer le texte comme un nouvel envoi avec un nouvel identifiant. Le stockage opaque ne prouve pas que tout dépôt arbitraire est chiffré.

L'adaptateur est épinglé à la révision libsignal `0abcfd4044a5827d73b657c1170ab3638d660330`, sous licence AGPL-3.0-only, compatible avec la licence d'AKRAT. Signal indique que l'utilisation de ses bibliothèques hors de ses propres produits n'est pas prise en charge et que les API peuvent changer. L'adaptateur reste isolé dans `akrat-core::async_crypto`; toute mise à jour du commit doit repasser les tests de compatibilité et de migration. Il n'y a pas eu d'audit cryptographique indépendant de l'intégration AKRAT.

## Compilation et commandes

Depuis la racine du dépôt, avec Rust 1.93.1 ou plus récent et `protoc` 36.2 :

```powershell
cargo build --release -p akrat-mailbox
```

libsignal compile des schémas protobuf. Sur Windows, utilisez l'archive officielle `protoc-36.2-win64.zip` avec SHA-256 `f0c128dc0d8492eceece83bb459a4c0e316764b929ffbf1aa416357fd644edd3`; la CI vérifie cette empreinte. Linux et macOS doivent disposer de `protoc` dans le `PATH`.

```sh
cargo build --release -p akrat-mailbox
```

Initialiser la configuration. Sans `--name`, le programme demande un nom dans le terminal. L'écoute par défaut est locale (`127.0.0.1:47475`) ; pour un serveur accessible depuis Internet, choisir explicitement une adresse et configurer le pare-feu :

```sh
akrat-mailbox --config ./server.json init --name "Mon nœud" --bind 0.0.0.0:47475 --data-dir ./data
```

La configuration contient les clés privées Noise et Ed25519. Gardez-la lisible uniquement par le compte de service, sauvegardez-la séparément et ne la publiez jamais. Sous Linux/macOS, le fichier est écrit avec les permissions `0600`. Sous Windows, il hérite des ACL du dossier de configuration ; placez-le dans un répertoire privé du compte de service.

Démarrer le serveur :

```sh
akrat-mailbox --config ./server.json serve
```

État local, création administrative d'une boîte et vérification réseau locale :

```sh
akrat-mailbox --config ./server.json status
akrat-mailbox --config ./server.json mailbox create
akrat-mailbox --config ./server.json health
```

Le profil public reste déclaratif ; l'identité durable du serveur est sa racine Ed25519, distincte de la clé active qui signe les reçus. Configurez son nom, sa description, l'hébergeur et le pseudonyme local depuis le terminal. Pour publier le profil dans le registre fédéré, ajoutez l'endpoint public puis redémarrez le service. Un renommage émet une annonce de séquence supérieure signée par la même racine, sans toucher aux boîtes ni aux reçus :

```sh
akrat-mailbox --config ./server.json profile show
akrat-mailbox --config ./server.json profile name "Le Refuge des Ombres"
akrat-mailbox --config ./server.json profile description "Boîte communautaire auto-hébergée"
akrat-mailbox --config ./server.json profile operator "Collectif local"
akrat-mailbox --config ./server.json profile host-name "Équipe du Refuge"
akrat-mailbox --config ./server.json profile endpoint "mail.example:47475"
akrat-mailbox --config ./server.json serve
```

Les noms peuvent être identiques. Ils ne créent aucune confiance et ne remplacent pas la vérification des empreintes.

La commande `key show` affiche la racine durable et la clé de reçus active. `key rotate` crée une nouvelle clé de reçus et écrit une transition persistante signée par la racine, l'ancienne clé et la nouvelle. Si le profil a un endpoint fédéré, la transition est republiée dans la prochaine annonce signée. `key revoke <empreinte>` révoque une ancienne clé avec une déclaration signée par la racine ; la clé active doit d'abord être tournée. Les clients vérifient le numéro de génération et le numéro de révocation, refusent les annonces en retour arrière et n'acceptent les anciennes signatures de reçus que pour leur période d'activité. Si la racine durable est compromise, une nouvelle racine doit être vérifiée et épinglée hors bande.

La création d'une boîte affiche une fois son identifiant et trois secrets : capacité de dépôt (pour Bob et les expéditeurs autorisés), capacité de récupération (à conserver par Bob) et capacité de lecture des préclés (à transmettre aux expéditeurs autorisés). Ne transmettez jamais la capacité de récupération aux expéditeurs. Une perte de capacité ne peut pas être réparée. Les capacités sont des bearer tokens : toute personne qui les obtient peut utiliser les opérations correspondantes.

## Configuration et réseau

`init` accepte `--bind`, `--data-dir`, `--max-total-bytes`, `--max-mailboxes`, `--mailbox-quota` et `--retention-seconds`. La valeur `0.0.0.0:47475` écoute sur toutes les interfaces IPv4 ; ouvrez le port TCP correspondant dans le pare-feu seulement si l'accès distant est voulu. Le transport Noise chiffre la liaison et le client doit épingler l'empreinte Noise publiée au démarrage. Le serveur ne chiffre pas lui-même les enveloppes applicatives.

Le serveur limite une enveloppe réseau à 40 KiB, une récupération à 128 entrées (et tronque la réponse à la taille de trame), le nombre de connexions simultanées à 64, les boîtes à leur quota et le stockage global au quota configuré. Les dépôts identiques sont idempotents ; réutiliser un identifiant de message avec un contenu différent est refusé. Les tombstones et reçus ont des plafonds et expirent après 30 jours. Le nettoyage des enveloppes expirées tourne à intervalle régulier et avant un dépôt.

## Fédérer des serveurs

La fédération active est une synchronisation incrémentale de deltas signés, limitée à 12 annonces par page et persistée par curseur. Elle s'exécute automatiquement toutes les 15 secondes lorsque le service est actif. Le serveur épingle une source par sa clé de signature et vérifie aussi sa clé Noise à chaque connexion. La clé de signature inscrite dans la configuration doit être reçue d'un canal authentifié et vérifiée manuellement.

Sur chaque serveur, ajouter explicitement l'autre côté de la relation ; pour une fédération mutuelle, chaque opérateur épingle l'autre serveur :

Les ajouts et retraits de pairs modifient `server.json`. Redémarrez le service après une modification pour qu'il recharge la liste épinglée.

```sh
akrat-mailbox --config ./server.json federation peer add --endpoint "mail.example:47475" --noise-key "<clé-publique-noise-hex>" --signing-key "<clé-publique-signature-hex>"
akrat-mailbox --config ./server.json federation peer list
akrat-mailbox --config ./server.json federation nodes
akrat-mailbox --config ./server.json federation node approve "<empreinte>"
akrat-mailbox --config ./server.json federation node block "<empreinte>"
akrat-mailbox --config ./server.json federation peer remove --fingerprint "<empreinte-source>"
```

Une clé source approuvée localement peut propager des annonces signées. Ces annonces gardent le statut `discovered`; elles ne deviennent pas automatiquement approuvées et cette découverte n'autorise pas leur boîte comme destination de message. Les opérateurs configurent séparément les boîtes qu'ils autorisent. Le registre SQLite local et ses curseurs doivent être sauvegardés avec le serveur. Aucun serveur n'est une autorité globale ; après synchronisation, les nœuds continuent à échanger directement si le bootstrap disparaît. La fédération ne réplique pas les messages.

Les métadonnées du serveur comprennent les adresses IP des connexions, les horaires, les identifiants de boîte, les tailles, les expirations et les fréquences de récupération. Le chiffrement du transport ne rend pas ces métadonnées anonymes.

## Service systemd (exemple Ubuntu/Debian)

Après installation du binaire dans `/usr/local/bin/akrat-mailbox`, créer le compte puis initialiser la configuration en tant que ce compte. Fixez `data_dir` à `/var/lib/akrat-mailbox/data` en passant `--data-dir` :

```sh
sudo useradd --system --home-dir /var/lib/akrat-mailbox --create-home --shell /usr/sbin/nologin akrat-mailbox
sudo install -d -o akrat-mailbox -g akrat-mailbox -m 0700 /etc/akrat-mailbox
sudo -u akrat-mailbox /usr/local/bin/akrat-mailbox --config /etc/akrat-mailbox/server.json init --name "Mon nœud" --bind 0.0.0.0:47475 --data-dir /var/lib/akrat-mailbox/data
```

Créer `/etc/systemd/system/akrat-mailbox.service` :

```ini
[Unit]
Description=AKRAT Mailbox
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=akrat-mailbox
Group=akrat-mailbox
ExecStart=/usr/local/bin/akrat-mailbox --config /etc/akrat-mailbox/server.json serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/akrat-mailbox

[Install]
WantedBy=multi-user.target
```

Créer `/etc/akrat-mailbox`, transférer le fichier de configuration en conservant son propriétaire `akrat-mailbox` et des permissions `0600`, puis activer le service :

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now akrat-mailbox
sudo systemctl status akrat-mailbox
```

L'exemple systemd configure le redémarrage automatique. Ouvrez TCP/47475 dans le pare-feu uniquement si le service doit être joignable publiquement. Il n'y a pas de TLS HTTP : la liaison actuelle est le protocole Noise AKRAT du serveur.

## Sauvegarde et restauration

Sauvegardez ensemble `server.json` et une copie cohérente de la base SQLite. La configuration contient les clés servant à vérifier l'identité de service et les reçus ; perdre ou remplacer ces clés change l'identité du serveur. Pendant que le service tourne, utilisez l'API de sauvegarde SQLite plutôt qu'une copie brute de la base WAL :

```sh
sqlite3 /var/lib/akrat-mailbox/data/mailbox.sqlite3 ".backup '/var/backups/akrat-mailbox.sqlite3'"
```

Restaurez les deux fichiers avec le service arrêté et les permissions du compte de service. La racine Ed25519 et la clé Noise doivent rester sauvegardées avec `server.json`. La clé de reçus peut tourner sans changer la racine ; l'historique authentifié est transmis par les annonces fédérées et le protocole d'identité direct. Le protocole fédéré synchronise les annonces automatiquement ; il ne réplique pas les boîtes ni les messages.

## Vérification et limites restantes

Les tests couvrent les opérations de coffre et de boîte, le chiffrement Noise client-serveur, les bundles, les signatures, les quotas, les déduplications, la pagination et le rejet du rejeu des deltas. Les scénarios d'intégration démarrent un vrai serveur autonome plus deux processus clients, testent les helpers Desktop avec deux coffres, et lancent trois serveurs A–B–C puis coupent A avant que C finisse d'apprendre le registre via B. Les tests confirment que les annonces restent `Discovered`.

Les limites actuelles comprennent l'absence d'audit cryptographique indépendant et le rate limiter en mémoire, réinitialisé au redémarrage. Les capacités restent les seules autorisations d'accès aux boîtes ; le limiteur ne remplace pas les quotas de stockage et ne prévient pas un déni de service distribué.

Pour la redondance applicative, chaque contact vérifié accepte une route principale et au plus deux routes secondaires explicites. Les copies portent le même ciphertext et identifiant logique ; chaque route a ses propres capacités et reçus. Une panne d'une route n'empêche pas la remise si une autre fonctionne. Une copie déjà livrée est acquittée après comparaison exacte du ciphertext, et une expiration n'est déclarée que si toutes les routes retournent un reçu d'expiration signé. La fédération ne réplique pas les boîtes ni les messages.

Le renvoi crée un nouvel identifiant de message, tout en conservant l'ancien message expiré dans l'historique. Les tests interprocessus de livraison et de fédération sont exécutés localement sous Windows et Linux. Le workflow de CI utilise des runners auto-hébergés Windows et Linux ; aucun runner macOS n'est utilisé ni validé pour cette version.
