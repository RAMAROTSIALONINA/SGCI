Tsiry Hasina

Voici le ligne de code pour avoir docker

docker rm -f postgres-db
docker run --name postgres-db `
  -e POSTGRES_USER=user `
  -e POSTGRES_PASSWORD=password `
  -e POSTGRES_DB=postgres `
  -p 5433:5432 `
  -d postgres


Tests (Thunder Client)

Prerequis
- PostgreSQL en marche (voir commande Docker ci-dessus).
- API lancee (ex: depuis `backend`, `uvicorn main:app --reload`).
- Variables SMTP configurees si tu veux vraiment recevoir les OTP par email.

0) Health check
- GET http://localhost:8000/health
- Attendu: {"status":"Running"}

1) Seed des utilisateurs (hors assistants)
- POST http://localhost:8000/users/seed
- Attendu (premiere fois): {"created":5,"skipped":0}
- Attendu (relance): {"created":0,"skipped":5}
- Comptes crees (mot de passe: Admin123!):
- lionsclaudius17@gmail.com (role super_admin)
  - admin.ubs@sgci.com (role admin_ubs)
  - admin.c2a@sgci.com (role admin_c2a)
  - admin.site@sgci.com (role admin_site)
  - admin.acr@sgci.com (role admin_acr)

2) Login admin/superadmin (token direct)
- POST http://localhost:8000/auth/login
- Body:
  {"email":"lionsclaudius17@gmail.com","password":"Admin123!"}
- Attendu: {"token":"..."}

3) Seed des roles/permissions (optionnel, deja fait au demarrage)
- POST http://localhost:8000/roles/seed
- Headers: Authorization: Bearer <token_admin>
- Attendu: {"created":X,"updated":Y}
- Si tout est deja en place: {"created":0,"updated":0}

4) Liste des roles
- GET http://localhost:8000/roles
- Attendu: 6 roles avec `code`, `name`, `level`, `is_system`, `is_assistant`

4.1) Liste des permissions
- GET http://localhost:8000/roles/permissions
- Headers: Authorization: Bearer <token_admin>
- Attendu: liste des permissions (codes, modules, descriptions)

4.2) Permissions assignables par un admin
- GET http://localhost:8000/roles/assignable-permissions
- Headers: Authorization: Bearer <token_admin>
- Attendu: permissions que l'admin peut donner a un assistant

4.3) Creation d'un role assistant
- POST http://localhost:8000/roles
- Headers: Authorization: Bearer <token_admin>
- Body:
  {"code":"assistant_ubs_lite","name":"Assistant UBS Lite","permission_codes":["ubs.read","ubs.validation.manage"],"is_assistant":true}
- Attendu: role cree avec ses permissions

4.4) Mise a jour des permissions d'un role
- PUT http://localhost:8000/roles/assistant_ubs_lite/permissions
- Headers: Authorization: Bearer <token_admin>
- Body:
  {"permission_codes":["ubs.read","ubs.validation.manage","ubs.tresorerie.manage"]}
- Attendu: role mis a jour avec ses permissions

5) Creation d'un assistant (par admin/superadmin)
- POST http://localhost:8000/auth/signup
- Headers: Authorization: Bearer <token_admin>
- Body:
  {"first_name":"Nina","last_name":"Morel","email":"nina.morel@sgci.com","password":"Temp123!","role_code":"assistant_ubs_lite"}
- Attendu: {"message":"Assistant cree."}

6) Login assistant (2FA vers le createur)
- POST http://localhost:8000/auth/login
- Body:
  {"email":"nina.morel@sgci.com","password":"Temp123!"}
- Attendu: {"message":"Code envoye au createur."}
- Le code est envoye a l'email de l'admin createur.

7) Verification OTP (login assistant)
- POST http://localhost:8000/auth/verify-otp
- Body:
  {"email":"nina.morel@sgci.com","code":"XXXXXX"}
- Attendu: {"token":"..."}

8) Cas d'erreur OTP
- Code invalide:
  - Attendu: 400 "Invalid code. Please try again."
- Trop de tentatives (>=5):
  - Attendu: 400 "Maximum attempts exceeded. Please request a new code."
- Code expire/absent:
  - Attendu: 400 "No valid code found. Please request a new one."

9) Cas d'erreur login
- Email inconnu:
  - Attendu: 404 "Please, create an account."
- Mot de passe invalide:
  - Attendu: 400 "Invalid credentials."
- Compte inactif:
  - Attendu: 403 "User account is inactive."
- Compte non verifie:
  - Attendu: 403 "User account is not verified."

10) Suppression d'un assistant
- DELETE http://localhost:8000/users/assistants/{id}
- Headers: Authorization: Bearer <token_admin>
- Attendu si admin createur: {"message":"Assistant deleted."}
- Attendu si admin different: 403 "Only the creator admin can delete this assistant."
- Attendu si superadmin: {"message":"Assistant deleted."}
- Attendu si l'utilisateur cible n'est pas assistant: 403 "Only assistant accounts can be deleted with this endpoint."
- Attendu si role non autorise: 403 "User is not allowed to perform this action."
