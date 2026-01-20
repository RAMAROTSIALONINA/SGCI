Tsiry Hasina

Voici le ligne de code pour avoir docker

docker rm -f postgres-db
docker run --name postgres-db `
  -e POSTGRES_USER=user `
  -e POSTGRES_PASSWORD=password `
  -e POSTGRES_DB=postgres `
  -p 5433:5432 `
  -d postgres

---

Authentification 2FA pour le signup (Assistant uniquement)

Objectif
- Lors du signup, l'assistant doit valider un code a usage unique (OTP).
- Les autres roles existent deja en base, donc pas de signup pour eux.

Logique generale
1) L'utilisateur envoie ses infos de signup (email, mot de passe, etc.).
2) Le backend cree un compte "en attente" avec role = assistant.
3) Le backend genere un code OTP (ex: 6 chiffres) avec une expiration courte.
4) Le code est envoye par email ou SMS.
5) L'utilisateur appelle un endpoint de verification avec le code OTP.
6) Si le code est bon et pas expire, le compte devient actif et on renvoie un token.

Comment on le fait (etapes simples)
- Base de donnees:
  - Ajouter des champs a Users: role, is_active, is_verified.
  - Ou creer une table 2fa_codes: user_id, code_hash, expires_at, used_at.
- Endpoints:
  - POST /auth/signup:
    - Cree l'utilisateur en attente (role = assistant, is_active=false).
    - Genere un OTP, le hash, et stocke l'expiration.
    - Envoie le code par email/SMS.
    - Renvoie un message "Code envoye".
  - POST /auth/verify-otp:
    - Recoit email + code.
    - Verifie le hash et l'expiration.
    - Active l'utilisateur (is_active=true, is_verified=true).
    - Renvoie un token JWT.
- Securite:
  - Ne jamais stocker l'OTP en clair, toujours un hash.
  - Mettre une expiration courte (ex: 5 minutes).
  - Bloquer apres X tentatives.
  - Supprimer ou marquer le code comme utilise apres succes.

Flux minimal
Signup -> OTP envoye -> Verify OTP -> Compte actif -> Login/Token


