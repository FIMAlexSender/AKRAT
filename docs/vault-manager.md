# Coffres AKRAT

## Ouverture et sélection

AKRAT restaure le coffre disponible choisi en dernier. Si cet emplacement a disparu, le premier fichier existant du catalogue est sélectionné. La sélection affichée est le chemin utilisé pour le déverrouillage. Un catalogue vide ne transforme pas le chemin local par défaut en coffre enregistré.

L’onglet **Ouvrir un coffre** affiche les fichiers connus, leur disponibilité et leur chemin. Un coffre introuvable reste dans la liste afin de représenter un volume externe temporairement déconnecté. Sur ordinateur, l’action **Localiser le coffre** permet de choisir son nouvel emplacement. Elle met à jour le chemin dans le catalogue sans déplacer ni modifier le fichier.

## Création et importation

Dans **Créer un coffre**, donnez un nom et choisissez un dossier. AKRAT ajoute automatiquement l’extension `.akrat` et refuse de remplacer un fichier existant. La phrase secrète et sa confirmation sont conservées dans des champs indépendants de ceux de l’onglet d’ouverture. Entrée valide la création depuis le champ de confirmation.

Sur Windows et Linux, l’importation ouvre le sélecteur de fichiers natif. Le coffre reste à son emplacement d’origine. Sur Android, choisissez le fichier `.akrat` via le sélecteur de fichiers du téléphone. AKRAT en copie le contenu chiffré dans le stockage privé de l’application, car l’accès fourni par Android au fichier choisi n’est pas un chemin permanent utilisable par l’application. Le fichier source reste intact. Les copies Android sont limitées à 16 Mio.

## Renommage, dissociation et suppression

Le renommage change le nom de fichier dans le même dossier sans déchiffrer ni réécrire le coffre. Le catalogue conserve l’identifiant local de l’entrée. Les identités, clés, conversations, historiques, boîtes Mailbox, préclés et états de protocole restent octet pour octet dans le fichier chiffré.

**Dissocier sans supprimer** enlève une référence du catalogue et conserve le fichier. **Supprimer** demande la phrase secrète du coffre et une confirmation distincte. Sur Windows et Linux, AKRAT essaie de déplacer le fichier vers la Corbeille. Si cette opération échoue, la suppression est annulée et la référence au coffre est restaurée. Sur Android, le fichier du stockage privé est supprimé directement. Aucune de ces opérations ne garantit l’effacement physique des données d’un SSD ou d’une mémoire flash.

## Catalogue et récupération

Le fichier `vaults.json` est placé à côté du chemin local par défaut de l’application. Il contient des identifiants d’entrée, des chemins et la préférence de sélection, mais aucune phrase secrète, clé privée ou capacité Mailbox. Les anciennes listes JSON de chemins sont lues et converties lors du prochain enregistrement.

Chaque mise à jour écrit un fichier temporaire puis remplace le catalogue. La précédente version valide est gardée dans `vaults.json.bak`. Si le fichier courant est endommagé, AKRAT tente de charger cette copie de récupération sans modifier les fichiers `.akrat`. Si les deux catalogues sont illisibles, réimportez manuellement les coffres ; les fichiers eux-mêmes ne sont ni supprimés ni déplacés.

## Portabilité cryptographique

Les identités, clés de conversation, messages chiffrés, états asynchrones, préclés, boîtes locales, éléments de file d’attente et reçus persistants sont sérialisés dans le coffre chiffré. Les reçus de Mailbox et les capacités nécessaires au client sont inclus dans l’état chiffré. Le catalogue local n’est pas requis pour déchiffrer un coffre déplacé : il sert uniquement à mémoriser ses emplacements sur cet appareil.
