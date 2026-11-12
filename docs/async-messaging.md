# Utiliser les boîtes aux lettres dans AKRAT Desktop

## Préparer les deux appareils

1. Sur le PC ou VPS choisi, lancez `akrat-mailbox init`, puis `serve`. La configuration doit écouter sur une adresse publique ou un nom DNS et TCP/47475 doit être autorisé par le pare-feu.
2. Créez une boîte avec `akrat-mailbox mailbox create`. Conservez l'identifiant et les trois capacités affichées dans un gestionnaire sûr.
3. Dans AKRAT sur Bob, ouvrez un coffre déverrouillé et ajoutez la boîte comme boîte personnelle avec son endpoint, sa clé Noise, son identifiant et les capacités d'écriture, de lecture et de bundle. La page Réseau publie ensuite le bundle et relève périodiquement la boîte.
4. Sur Alice, ajoutez Bob comme contact, vérifiez son empreinte par un canal indépendant, puis saisissez la route de boîte autorisée : endpoint, clé Noise, clé de signature du serveur, identifiant, capacité d'écriture et capacité de lecture du bundle. Ne lui transmettez pas la capacité de récupération de Bob.
5. Quand la session directe est indisponible, envoyez normalement le message. L'application conserve le ciphertext dans le coffre et tente le dépôt. À son retour en ligne et coffre déverrouillé, Bob récupère et déchiffre le message ; Alice passe à « remis » après vérification du reçu signé de Bob.

Le client ne relève pas les boîtes lorsque le coffre est verrouillé. Le serveur conserve les enveloppes pendant la durée de rétention configurée, mais il ne peut pas réveiller un appareil éteint. Si la boîte de Bob est sur un PC éteint, elle est elle-même inaccessible.

## Copies sur plusieurs Mailbox

Un contact vérifié peut avoir une route principale et jusqu'à deux routes de copie, ajoutées explicitement dans sa fiche Contact. Chaque route contient ses propres clés épinglées, capacités et identifiant de boîte ; la découverte fédérée ne donne jamais automatiquement le droit de stocker un message. AKRAT chiffre le message une fois et dépose le même ciphertext et le même identifiant logique sur les routes. Chaque serveur signe son propre reçu de dépôt. Une route indisponible n'empêche pas le succès partiel si une autre accepte le message ; les retransmissions réessaient les destinations manquantes avec le ciphertext conservé dans le coffre.

Le destinataire traite une copie et acquitte ensuite chaque doublon exact avec un reçu lié au même identifiant et au même ciphertext. Un doublon au contenu différent est rejeté. L'expéditeur considère le message remis dès qu'un reçu du destinataire est vérifié depuis une route ; les copies restantes sont supprimées à la prochaine récupération et à l'envoi du reçu. Une expiration n'est déclarée que lorsque toutes les routes configurées retournent un reçu d'expiration signé. La disparition d'une Mailbox sans reçu laisse l'état non confirmé.

Cette politique fournit au plus trois destinations configurées par contact, pas une garantie de disponibilité ou de conservation. Les quotas et les limites de chaque serveur s'appliquent indépendamment. Les copies ne sont pas diffusées aux nœuds fédérés.

## Parcours privé d'un message

Les détails techniques d'un message présentent une chronologie stockée dans l'enregistrement du message. Cet enregistrement est chiffré avec la clé de stockage indépendante de sa conversation, dans le coffre local. La chronologie n'est jamais publiée dans le registre fédéré. Les événements observés par le client sont indiqués comme tels ; les dépôts et confirmations ne sont marqués vérifiés qu'après validation de la signature correspondante. Les événements d'un historique plus ancien peuvent être absents sans affecter son affichage.

## Déployer sur un VPS Contabo (guide générique)

Contabo est un fournisseur de VPS ; aucun accès au compte ni déploiement réel n'a été effectué pour cette préversion. Sur une instance Ubuntu/Debian, installez le binaire Linux `akrat-mailbox`, configurez `data_dir` sous `/var/lib/akrat-mailbox/data`, et suivez la procédure systemd de [mailbox.md](mailbox.md). Autorisez uniquement TCP/47475 dans le pare-feu du système et dans le pare-feu réseau du fournisseur. N'exposez pas le port tant que la version n'a pas été examinée et testée sur le réseau visé.

Lors de l'inscription d'un second serveur, échangez les clés Noise et de signature par un canal authentifié, comparez leurs empreintes, puis exécutez `federation peer add` sur les deux serveurs si une synchronisation mutuelle est souhaitée. La fédération ne partage pas les boîtes ni les messages.

Ne copiez pas `server.json`, ses secrets, les capacités de boîte, les coffres de clients ou les fichiers de clés dans un dépôt Git ou un ticket. Sauvegardez la configuration et les bases SQLite dans un emplacement chiffré, à accès limité et séparé du VPS.
