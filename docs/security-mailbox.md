# Rapport de sécurité — messagerie différée AKRAT

## Portée

Cette revue décrit le code local de la branche `v0.1.9-mailbox-federation` et ses tests. Elle n'est pas un audit indépendant ni une certification de sécurité. L'implémentation du protocole Signal est fournie par la révision libsignal `0abcfd4044a5827d73b657c1170ab3638d660330`; l'adaptateur AKRAT, le stockage, l'interface, les migrations et la fédération ne sont pas couverts par l'audit de Signal.

## Chemin cryptographique

Le client destinataire publie une identité AKRAT liée au bundle, un prekey EC signé, un prekey EC à usage unique et un prekey Kyber1024 signé. L'expéditeur vérifie que l'identité du bundle est celle du contact vérifié et valide les signatures avant de demander à libsignal d'initialiser la session et de chiffrer. Les secrets et sessions libsignal sont sérialisés dans le coffre chiffré ; ils ne sont jamais envoyés à la boîte.

La bibliothèque libsignal fournit le protocole PQXDH et le Double Ratchet. Le Double Ratchet dérive une clé de message différente par message et effectue des rotations DH ; les garanties exactes dépendent de l'état courant et de son effacement sécurisé. Références : [spécification PQXDH](https://signal.org/docs/specifications/pqxdh/) et [spécification Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).

**Limite importante :** AKRAT ne publie qu'un prekey Kyber signé de longue durée à la fois. Il ne maintient pas le lot de signed one-time PQ KEM prekeys prévu dans l'architecture PQXDH. Le prekey EC à usage unique est consommé atomiquement, mais cela ne remplace pas un lot PQ à usage unique et ne permet pas de revendiquer les mêmes propriétés de confidentialité persistante en cas de compromission d'une clé PQ statique. Ne pas présenter AKRAT v0.1.9 comme une implémentation complète ou auditée de PQXDH.

L'API de signature d'identité utilise les clés Curve25519 de libsignal et son format compatible XEdDSA ; la clé d'identité est liée au reçu du destinataire. Cette signature atteste que l'identité a signé le reçu, pas qu'une personne a lu le message ou que les données survivront à une perte de disque.

## Stockage et transport

- Les boîtes stockent des octets opaques et des métadonnées de livraison. Elles ne reçoivent pas les clés privées de session.
- Noise XX chiffre la liaison client-serveur ; le client vérifie une clé Noise épinglée. Cela ne masque pas l'adresse IP, les horaires, les tailles, ni les identifiants de boîte au serveur.
- Les capacités de dépôt, de récupération et de lecture de bundle sont des bearer tokens distincts. Leur fuite autorise l'opération correspondante ; elles doivent être transmises séparément et conservées dans le coffre.
- Un reçu de dépôt signé prouve l'acceptation par la clé de serveur, pas la conservation physique. Un reçu de livraison est signé par l'identité vérifiée du destinataire, lie boîte, identifiant logique, expéditeur, destinataire et condensat du ciphertext, puis est conservé avant suppression de l'enveloppe dans une transaction.
- Le client envoie le reçu après que la sauvegarde du coffre a réussi. Cela établit l'ordre logiciel « sauvegarder puis acquitter », mais pas une preuve matérielle de persistance.
- La chronologie détaillée est chiffrée avec l'enregistrement du message et sa clé de stockage propre à la conversation. Les événements locaux sont des observations client ; les événements Mailbox et destinataire marqués vérifiés correspondent à des reçus dont les signatures ont été contrôlées. La fédération ne reçoit pas cette chronologie.
- Les octets déposés ne sont pas inspectés pour démontrer qu'ils sont chiffrés ; le serveur fournit un stockage opaque, pas un validateur de chiffrement.

## Fédération et confiance

Chaque source fédérée est configurée explicitement avec endpoint, clé Noise et clé de signature épinglées. Les deltas sont signés, paginés par 12 annonces et suivis par curseurs persistés. Les annonces conservent leur signature de nœud ; une source reconnue peut en faciliter la découverte, mais l'import les marque `Discovered`. L'approbation d'un nœud reste une décision locale et ne donne pas à ce nœud l'autorisation d'héberger des messages.

La fédération ne réplique pas les ciphertexts. Elle ne garantit pas la disponibilité, l'honnêteté, la confidentialité des métadonnées ou l'absence de déni de service des serveurs. Une source signataire malveillante peut propager de fausses annonces auto-signées ; l'approbation locale et la vérification manuelle des empreintes restent nécessaires.

Chaque Mailbox possède une racine Ed25519 durable distincte de sa clé de reçus active. Une rotation de clé de reçus est signée par la racine, l'ancienne clé et la nouvelle clé ; les profils fédérés version 3 transportent la chaîne et les révocations dans l'annonce signée par la racine. Les clients épinglent la racine, mémorisent les générations et rejettent tout retour en arrière. Les reçus anciens restent vérifiables uniquement pendant la période où leur clé était active ; une clé révoquée n'est acceptée que pour un reçu antérieur à l'heure de révocation. La révocation exige la racine. Si cette racine est compromise, la continuité ne suffit plus et l'opérateur doit faire réépingler une nouvelle racine par un canal indépendant.

## Limites résiduelles

- Pas d'audit cryptographique indépendant, de fuzzing complet ni de test formel des migrations adversariales.
- La racine de signature reste persistante dans `server.json` et n'est pas remplaçable par une rotation distante. Sa compromission exige un réépinglage hors bande. L'historique de continuité est borné à 64 rotations et 64 révocations ; les transitions expirent après dix ans. Les clients qui restent hors ligne au-delà de cette durée doivent rétablir la confiance hors bande.
- Les reçus d'expiration sont conservés 30 jours ; après leur purge, un client resté hors ligne peut ne plus retrouver l'événement.
- Une route principale et jusqu'à deux routes de copie peuvent être configurées explicitement par contact. Le ciphertext et son identifiant logique sont réutilisés sur les copies ; la création initiale garde une seule enveloppe chiffrée. Les reçus de dépôt sont indépendants par serveur. Le reçu destinataire est vérifié cryptographiquement ; la suppression des copies qui ne sont pas consultées est différée jusqu'à leur prochaine récupération. L'expiration n'est établie que par des reçus signés pour toutes les routes. Ce mécanisme ne prévient ni la panne simultanée, ni la perte silencieuse ou malveillante d'une copie.
- Les limites token-bucket globales, par IP, identité Noise et boîte sont en mémoire et repartent à zéro au redémarrage. Une IP partagée peut entraîner une limite commune ; les quotas de stockage demeurent la protection contre l'épuisement du disque. Cette mesure ne prévient pas un déni de service distribué.
- Pas de preuve qu'un opérateur conserve réellement une enveloppe jusqu'à expiration.
- Les builds et tests macOS ne sont pas inclus à cette livraison. La licence AGPL-3.0-only de libsignal est compatible avec la licence du workspace, mais son usage par des applications autres que Signal est indiqué comme non pris en charge par les mainteneurs [du dépôt libsignal](https://github.com/signalapp/libsignal).

`cargo audit` n'a trouvé aucune vulnérabilité publiée exploitable dans le verrou de dépendances. Il signale toutefois six avertissements informatifs : `glib 0.18.5` a une implémentation non sûre de `VariantStrIter` (RustSec RUSTSEC-2024-0429), `rand 0.7.3` est signalé non sûr pour l'usage avec un logger personnalisé, et `fxhash`, `paste`, `proc-macro-error` et `proc-macro-error2` ne sont plus maintenus. La dépendance `glib` vient de la chaîne GTK/Linux de Dioxus ; AKRAT n'appelle pas directement `VariantStrIter`. Aucune mise à niveau compatible de la chaîne GTK/Dioxus n'a été appliquée.

Utiliser uniquement des serveurs dont les opérateurs sont connus et dont les clés ont été vérifiées hors bande. Ne pas placer de données sensibles sur un serveur public avant une revue indépendante et la fermeture des limites listées ci-dessus.
