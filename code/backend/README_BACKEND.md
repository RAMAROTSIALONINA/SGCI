README Backend - Explication complete (non technique)

But du backend
Le backend est la partie serveur de l'application. Il recoit les demandes du front-end (interface), applique les regles de gestion, parle a la base de donnees, et renvoie des reponses. Il sert a:
- securiser l'acces aux donnees
- centraliser la logique metier
- tracer qui a fait quoi
- garantir que les regles sont respectees partout

Image simple du flux
1) L'utilisateur fait une action dans l'interface.
2) L'interface envoie une requete au backend (API).
3) Le backend verifie les droits et la validite.
4) Le backend lit ou ecrit en base de donnees.
5) Le backend renvoie une reponse propre a l'interface.

Pourquoi une API (backend) est necessaire
- Sans backend, n'importe qui pourrait modifier des donnees depuis le navigateur.
- Le backend decide qui peut faire quoi (roles, permissions).
- Le backend gere la securite (mots de passe hashes, tokens, OTP).
- Le backend assure une logique uniforme pour tous.

Ce que fait ce backend exactement
Le backend gere:
- l'authentification (connexion, tokens)
- la creation des utilisateurs (admins et assistants)
- la gestion des roles et permissions
- le 2FA pour les assistants (OTP par email)
- les preferences d'apparence (theme/palette)
- les seeds (donnees par defaut)

Composants principaux (en mots simples)
1) Routes (app/routes)
Les routes sont les "portes d'entree" de l'API.
Exemples:
- /auth/login pour se connecter
- /auth/signup pour creer un compte
- /roles pour lister les roles
- /users pour lister les utilisateurs

2) Services (app/service)
Les services contiennent la logique metier.
Ils decident "quoi faire" et dans quel ordre.
Exemples:
- UserService: creation utilisateur, login, OTP, mise a jour du profil
- RoleService: creation roles, permissions, seeds

3) Repositories (app/db/repository)
Les repositories parlent a la base de donnees.
Ils s'occupent du "comment ecrire/lire".
Exemples:
- UserRepository: creer, lire, modifier, supprimer des utilisateurs
- RoleRepository / PermissionRepository

4) Models (app/db/models)
Les models decrivent les tables en base.
Exemples:
- Users (utilisateurs)
- Roles (roles)
- Permissions
- TwoFACodes (codes 2FA)
- UserPreferences (preferences d'apparence)

5) Schemas (app/db/schema)
Les schemas decrivent les formats de donnees qui entrent et sortent de l'API.
Ils servent de contrat et de validation.

6) Securite
- Hash des mots de passe (jamais en clair)
- JWT pour l'identite de l'utilisateur
- OTP 2FA pour les assistants

Parcours utilisateur (quoi, pourquoi, comment)
1) Creation des comptes admin
But: avoir des comptes d'administration.
Comment: endpoint /users/seed cree des comptes par defaut.
Pourquoi: demarrer rapidement les tests et la gestion.

2) Connexion admin
But: obtenir un token.
Comment: /auth/login renvoie un token JWT.
Pourquoi: le token sert a prouver l'identite sur les autres routes.

3) Creation d'un role assistant
But: definir ce qu'un assistant a le droit de faire.
Comment: /roles (POST) cree un role avec une liste de permissions.
Pourquoi: un assistant ne doit pas avoir tous les droits d'un admin.

4) Creation d'un assistant
But: creer un utilisateur limite.
Comment: /auth/signup par un admin.
Pourquoi: securiser l'accès et tracer qui a cree l'assistant.

5) Connexion assistant avec 2FA
But: renforcer la securite.
Comment: l'assistant se connecte, le backend envoie un code OTP a l'assistant.
Pourquoi: eviter qu'un mot de passe vole suffise.

6) Verification OTP
But: valider la connexion.
Comment: /auth/verify-otp verifie le code et renvoie un token.
Pourquoi: assurer que l'assistant est bien valide.

Gestion des droits (roles et permissions)
- Un role = un "profil" (ex: admin_ubs, admin_c2a, assistant).
- Une permission = un droit precis (ex: ubs.read, site.export.view).
- Un utilisateur a un role.
- Le role donne un ensemble de permissions.
- Certaines actions sont bloquees si la permission manque.

Exemple clair
- Un admin_ubs peut lire le module UBS et gerer UBS.
- Un assistant peut avoir seulement "ubs.read".
- Un super_admin peut tout faire.

Pourquoi la base de donnees est necessaire
Les donnees doivent etre:
- stockees durablement
- partagees entre utilisateurs
- securisees et coherentes
La base de donnees (PostgreSQL) stocke toutes les infos (users, roles, permissions, OTP).

Que signifie "seed"
Le seed est un chargement automatique de donnees de depart:
- roles systemes
- permissions standard
- comptes admin par defaut
Cela permet de commencer sans tout creer a la main.

Securite (explication simple)
- Mot de passe: transforme en hash, impossible a relire.
- Token JWT: preuve d'identite, expire apres un certain temps.
- OTP: code temporaire pour les assistants.
- Verification des permissions: chaque route sensible controle les droits.

Comment le backend demarre
1) Le serveur demarre.
2) Il verifie/cree les tables de base.
3) Il seed les roles et permissions.
4) Il est pret a recevoir des requetes.

Ce que doit retenir une personne non technique
- Le backend est le "cerveau" qui applique les regles.
- Il protege les donnees et decide qui a le droit.
- Il fonctionne avec une base de donnees pour tout stocker.
- Il fait des controles de securite (mots de passe, tokens, OTP).
- Les roles/permissions permettent une gestion fine des acces.

Lexique simple
- API: porte d'entree pour parler au backend.
- JWT: badge temporaire pour prouver son identite.
- OTP: code de verification a usage unique.
- Role: profil utilisateur.
- Permission: droit precis.
- Seed: donnees de depart pour initialiser.
