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

Le niveau 2 atteste la provenance et l’empreinte déclarée d’un binaire; il ne prouve pas que le relais exécute ce binaire. Le niveau 3 requiert une attestation matérielle et reste indisponible. La disponibilité et la latence sont des mesures locales, pas une preuve d’honnêteté. AKRAT peut vérifier des preuves signées d’équivoque et les partager manuellement en JSON; après vérification, le relais est mis en quarantaine sur cet appareil. La diffusion automatique entre pairs et les autres catégories de preuve ne sont pas disponibles. Un relais peut observer les adresses IP, les horaires, les volumes et les durées de connexion, retarder ou bloquer le trafic. Il ne reçoit pas les clés de conversation et ne peut pas lire les messages protégés de bout en bout.

Le fichier d’exemple utilise l’accès Iroh `everyone`. Les administrateurs restent responsables des limites de débit, de la capacité réseau, des sauvegardes, des mises à jour et de la surveillance système. Le service fournit un point de relais optionnel et ne constitue pas une autorité centrale du réseau.
