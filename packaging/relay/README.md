# Déployer une Mailbox et un relais AKRAT

Le paquet contient la Mailbox AKRAT et le relais Iroh amont, accompagné du service `akrat-relay` qui publie une identité Ed25519 vérifiable. Les deux services peuvent être lancés ensemble ou séparément. Le relais Iroh utilise son protocole natif; le service d’identité AKRAT écoute sur TCP 8090.

## Préparer un serveur

Utilisez un VPS Linux x64 avec un nom DNS public pointant vers lui. Ouvrez les ports suivants dans le pare-feu du VPS et celui de l’hébergeur :

| Port | Protocole | Usage |
| --- | --- | --- |
| 80 | TCP | Validation ACME Let’s Encrypt du relais Iroh |
| 443 | TCP | HTTPS du relais Iroh |
| 7842 | UDP | Relais QUIC Iroh |
| 8090 | TCP | Défi d’identité Ed25519 AKRAT |

Copiez `iroh-relay.toml.example` en `iroh-relay.toml`, puis remplacez `relay.example.org` et l’adresse de contact par vos valeurs. Le relais demande un certificat Let’s Encrypt. Le service d’identité utilise HTTP, mais ne renvoie qu’une preuve publique signée pour un défi aléatoire; aucun secret client ne transite par ce port.

Gardez le fichier de configuration Mailbox distinct de celui du relais. Initialisez-le avec `akrat-mailbox --help`, puis configurez la base de données et les limites selon les options de cette version. Le relais n’est pas une Mailbox : il transporte des flux Iroh en direct, tandis que la Mailbox stocke temporairement des messages chiffrés pour les destinataires hors ligne.

## Lancer les services

Définissez `AKRAT_RELAY_URL=https://votre-domaine.example`, puis lancez `./akrat-node.sh both`. Les modes `mailbox` et `relay` permettent de démarrer chaque service seul. Le premier démarrage crée une identité de relais persistante et affiche son empreinte Ed25519.

Sauvegardez `akrat-relay-identity.key` dans un emplacement privé et persistant. Ne la publiez pas et ne la régénérez pas lors d’une mise à jour. Si cette clé est perdue ou compromise, l’identité change et les clients doivent comparer puis approuver la nouvelle empreinte hors bande.

Pour activer le niveau de confiance 1 dans AKRAT, ajoutez l’URL du relais et son empreinte après l’avoir reçue de l’opérateur par un canal indépendant. Le client lance un défi frais, vérifie la signature et refuse une clé différente. Le niveau 2 vérifie en plus le manifeste signé de la distribution. Le relais sert les fichiers `AKRAT-v<VERSION>-release-attestation.json` et `.sig` présents à côté de son exécutable; les archives officielles les incluent. Le client vérifie leur signature locale sans demander d’accès aux assets GitHub privés. Le niveau 0 peut accepter un relais non épinglé selon le choix local. Sans relais admissible, AKRAT conserve les connexions directes; le transport différé reste assuré par les Mailbox configurées.

## Limites de confiance

Le niveau 2 atteste la provenance et l’empreinte déclarée d’un binaire; il ne prouve pas que le relais exécute ce binaire. Le niveau 3 requiert une attestation matérielle et reste indisponible. La disponibilité et la latence sont des mesures locales, pas une preuve d’honnêteté. AKRAT peut vérifier des preuves signées d’équivoque. Elles peuvent être partagées comme fichier JSON ou explicitement via une session chiffrée avec un contact déjà vérifié; le destinataire les associe à son identité de relais épinglée avant de les enregistrer. La décision de quarantaine reste locale, sans bannissement distant. La diffusion automatique entre pairs et les autres catégories de preuve ne sont pas disponibles. Un relais peut observer les adresses IP, les horaires, les volumes et les durées de connexion, retarder ou bloquer le trafic. Il ne reçoit pas les clés de conversation et ne peut pas lire les messages protégés de bout en bout.

Le fichier d’exemple utilise l’accès Iroh `everyone`. Les administrateurs restent responsables des limites de débit, de la capacité réseau, des sauvegardes, des mises à jour et de la surveillance système. Le service fournit un point de relais optionnel et ne constitue pas une autorité centrale du réseau.

## Gestionnaire de mises à jour Linux x64

L’archive Linux inclut `akrat-node-updater`. Il télécharge les métadonnées de release depuis l’API officielle GitHub, vérifie leur attestation Ed25519 avec la racine déjà intégrée à `akrat-trust`, puis vérifie l’empreinte de chaque binaire avant de le préparer. Le SHA-256 seul ne sert jamais de preuve d’origine. Les releases stables seulement sont admissibles au mode automatique; les rétrogradations et les mises à jour concurrentes sont refusées.

Le gestionnaire ne modifie que les exécutables et ses fichiers d’état. Les chemins de base de données SQLite doivent être renseignés : il en crée une sauvegarde cohérente SQLite avant l’installation. Une erreur de redémarrage ou de contrôle de santé déclenche la restauration des exécutables et des bases sauvegardées. Les clés de relais, configurations, messages et données persistantes restent à leurs emplacements existants. Les sauvegardes sont conservées dans des sous-dossiers versionnés de `database_backups`; prévoyez l’espace disque et gérez leur rétention.

L’exemple `akrat-node-updater.json.example` démarre en politique `manual`. Copiez-le sous `/etc/akrat/updater.json`, vérifiez les chemins réels des bases, puis testez :

```sh
akrat-node-updater check --config /etc/akrat/updater.json
akrat-node-updater apply --config /etc/akrat/updater.json --approve
```

Le service et le timer systemd fournis exécutent le mode `auto` chaque jour à 03:15, avec une attente aléatoire, pendant la fenêtre configurée. Pour l’activer, réglez `policy` à `automatic`, gardez `channel` à `stable`, confirmez les chemins de bases et, si Mailbox est sélectionnée, mettez `allow_mailbox_auto_update` à `true` après examen de la compatibilité de schéma de la version visée. Les sauvegardes SQLite protégées par root sont gardées sous `/var/lib/akrat-updater`. Installez `akrat-node-updater.service` et `akrat-node-updater.timer`, puis activez le timer. Pour un dépôt GitHub privé, fournissez un jeton de lecture du dépôt uniquement dans `/etc/akrat/updater.env` (permissions `0600`) sous la variable `AKRAT_GITHUB_TOKEN`; ne le mettez jamais dans le fichier JSON, les journaux ou Git. Pour un dépôt accessible publiquement, aucun jeton n’est nécessaire.

Installation initiale depuis l’archive Linux x64, après avoir configuré le service principal et vérifié les chemins :

```sh
install -o root -g root -m 0755 akrat-node-updater /usr/local/bin/akrat-node-updater
install -o root -g root -m 0644 akrat-node-updater.service akrat-node-updater.timer /etc/systemd/system/
install -d -o root -g root -m 0700 /etc/akrat
install -o root -g root -m 0600 akrat-node-updater.json.example /etc/akrat/updater.json
install -d -o root -g root -m 0700 /var/lib/akrat-updater/backups
systemctl daemon-reload
akrat-node-updater check --config /etc/akrat/updater.json
```

N’activez le timer qu’après avoir configuré les chemins, le jeton de lecture si le dépôt est privé, `policy: "automatic"`, `channel: "stable"` et confirmé les migrations. Pour un nœud Mailbox, laissez `allow_mailbox_auto_update: false` tant que cette compatibilité n’est pas approuvée. Le mode manuel reste disponible avec `apply --approve` sans activer le timer.

Le contrôle Mailbox utilise sa commande `health` avec le fichier de configuration; le contrôle Relay exige une URL HTTP locale `/health`. Le service d’update doit avoir les droits d’écriture sur le répertoire d’installation et le dossier de sauvegardes. `journalctl -u akrat-node-updater.service` affiche le résultat de chaque exécution. Les scripts `akrat-node.ps1` et outils de service Windows restent inchangés; l’auto-update n’est fourni ici que pour Linux x64.

Cet updater effectue le déploiement signé des binaires, mais la validation de production exige encore des scénarios d’intégration sur VPS, notamment le disque plein, les permissions, les redémarrages refusés et l’actualisation d’un nœud réel. Ne l’activez pas en automatique sur un nœud contenant des données critiques avant ces validations.
