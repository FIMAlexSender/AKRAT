# AKRAT

Messagerie Rust pair à pair. La communication directe existante utilise Iroh et Noise XX. Les historiques et états privés sont conservés dans des coffres locaux chiffrés.

La branche `v0.1.9-mailbox-federation` ajoute une voie de livraison asynchrone : bundles libsignal, chiffrement de bout en bout avec Double Ratchet, boîtes opaques, reçu de dépôt signé et accusé de réception signé par l'identité du destinataire. Un processus serveur indépendant stocke uniquement des ciphertexts. Le client ne relève sa boîte que lorsque le coffre est déverrouillé.

La fédération échange automatiquement des deltas signés entre serveurs explicitement épinglés. Les annonces reçues restent au statut « découvert » jusqu'à approbation locale. La découverte est persistante et continue de fonctionner sans le serveur de bootstrap déjà synchronisé.

La v0.1.9 inclut la rotation et la révocation des clés de reçus, leurs preuves de continuité dans les annonces fédérées, des limites de débit configurables et la livraison différée avec libsignal. Les tests couvrent notamment la migration des coffres, le transport direct, Alice/Bob en processus séparés, la rotation après redémarrage, la fédération A–B–C et les limites anti-abus.

La v0.1.10 refond la gestion des coffres : sélection du dernier coffre disponible au démarrage, formulaires indépendants pour ouvrir et créer, importation portable, copie de coffre sur Android, renommage du fichier sans rechiffrement, dissociation distincte de la suppression et catalogue versionné avec récupération non destructive. Voir le [guide des coffres](docs/vault-manager.md).

Les artefacts Windows x64, Linux x64 et Android sont construits sur des runners auto-hébergés afin de ne pas consommer de minutes CI hébergées. macOS n'est pas compilé ni annoncé comme validé dans cette version. La génération et la signature de l'APK Android sont automatisées ; un appareil Android physique est requis pour valider l'installation et le comportement sur téléphone.

Consulter le [guide Mailbox](docs/mailbox.md) et le [rapport de sécurité](docs/security-mailbox.md) pour les garanties, les limites et les procédures d'administration.
