README Frontend - Explication complete (non technique)

But du frontend
Le frontend est la partie visible de l'application. C'est l'interface que les utilisateurs voient et utilisent. Il sert a:

- afficher les ecrans et les informations
- permettre aux utilisateurs d'agir (se connecter, consulter, modifier)
- envoyer les actions au backend
- guider l'utilisateur avec des messages clairs

Image simple du flux

1. L'utilisateur interagit avec l'ecran.
2. Le frontend envoie une demande au backend (API).
3. Le backend repond (ok ou erreur).
4. Le frontend affiche le resultat (message, page, donnees).

Pourquoi le frontend est necessaire

- Sans frontend, l'utilisateur n'a pas d'interface simple.
- Le frontend rend l'application utilisable par tous.
- Il transforme des donnees techniques en ecrans compréhensibles.

Ce que fait ce frontend exactement
Le frontend gere:

- l'ecran de connexion
- la double verification (OTP) pour les assistants
- le tableau de bord
- la gestion des utilisateurs (roles, permissions)
- les pages de settings (apparence, roles, liste, etc.)
- l'affichage des etats (chargement, erreurs)

Composants principaux (en mots simples)

1. Pages (src/app)
   Chaque dossier represente une page visible.
   Exemples:

- / (page de login)
- /two-factor (page OTP)
- /dashboard (page principale apres connexion)

2. Sections et composants (src/app/components, src/components)
   Ce sont des morceaux reutilisables de l'interface.
   Exemples:

- formulaire de login
- carte OTP
- en-tete de page
- fond d'ecran decoratif

3. Features (src/features)
   Regroupe les modules metier, par exemple la gestion des utilisateurs.
   Chaque feature contient:

- des composants
- des types de donnees
- des appels API
- des adaptateurs (traduction donnees API -> UI)

4. Lib / API (src/lib/api)
   Contient le client HTTP et les appels vers le backend:

- login
- verification OTP
- recuperation des utilisateurs, roles, permissions
  Le frontend utilise toujours ces fonctions pour parler au backend.

5. Styles (src/styles)
   Contient les fichiers CSS globaux.
   Ils definissent:

- la base visuelle (couleurs, typographie)
- les themes
- les utilitaires

Parcours utilisateur (quoi, pourquoi, comment)

1. Ecran de connexion
   But: permettre a l'utilisateur de se connecter.
   Comment: l'utilisateur saisit email + mot de passe.
   Pourquoi: controle d'acces securise.

2. Reponse du backend
   Le backend peut renvoyer:

- des tokens (access + refresh) si admin
- un message OTP (si assistant)
  Le frontend decide quoi afficher selon la reponse.

3. Ecran OTP (assistants)
   But: verifier que l'assistant est autorise.
   Comment: l'utilisateur saisit un code recu.
   Pourquoi: securite renforcee.

4. Acces au dashboard
   Une fois connecte:

- l'utilisateur voit le tableau de bord
- il peut aller vers la gestion des utilisateurs
- il peut modifier ses preferences

Gestion de l'etat et des erreurs (en clair)
Le frontend affiche:

- un message de chargement pendant l'envoi des requetes
- un message d'erreur si le backend refuse
- un message de succes si tout est ok
  Cela rassure l'utilisateur et l'aide a comprendre.

Pourquoi les tokens sont importants
Le backend donne un access token + un refresh token apres connexion.
Le frontend garde ces tokens pour:

- prouver que l'utilisateur est connecte
- envoyer des requetes autorisees
  Sans access token, les pages protegees ne fonctionnent pas.

Exemple simple (connexion)

1. Tu ouvres la page.
2. Tu ecris ton email et ton mot de passe.
3. Le frontend envoie la demande.
4. Si ok:
   - tu arrives au dashboard.
   - les tokens sont stockes.
5. Si pas ok:
   - un message d'erreur s'affiche.

Organisation des fichiers (version simple)
src/
app/ -> pages visibles
components/ -> composants reutilisables (UI)
features/ -> logique metier par module
lib/ -> appels API + outils communs
styles/ -> styles globaux
types/ -> types partages

Ce que doit retenir une personne non technique

- Le frontend est la vitrine de l'application.
- Il permet de naviguer et d'agir facilement.
- Il ne stocke pas les donnees sensibles: il les demande au backend.
- Il affiche toujours un retour clair (erreur/succes).

Lexique simple

- UI: l'interface visible.
- Page: un ecran complet.
- Composant: un morceau reutilisable d'ecran.
- API: la porte d'entree vers le backend.
- Token: preuve temporaire d'identite (access token + refresh token).
