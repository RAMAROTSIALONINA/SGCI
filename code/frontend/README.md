This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Login flow (pas a pas, debutant)

Cette section explique, simplement, comment le frontend fonctionne quand tu te connectes.

### Fichiers utilises

- `src/app/page.tsx`: page d'accueil qui affiche le formulaire de login.
- `src/app/components/sections/login/login-card.tsx`: logique du formulaire (saisie, envoi, messages).
- `src/lib/api/auth.ts`: appels HTTP vers le backend pour le login et l'OTP.
- `src/lib/api/client.ts`: client HTTP commun (base URL, POST JSON).
- `src/app/two-factor/page.tsx` + `src/app/components/sections/two-factor/two-factor-card.tsx`: ecran OTP.

### 1) La page d'accueil affiche le formulaire

1. Tu ouvres `http://localhost:3000/`.
2. `src/app/page.tsx` charge `LoginCard`.
3. `LoginCard` est un composant "client" (`'use client'`) pour:
   - stocker ce que tu tapes,
   - appeler l'API,
   - utiliser `localStorage` et la navigation.

### 2) Tu saisis email et mot de passe

Dans `src/app/components/sections/login/login-card.tsx`:

- Le champ email met a jour `email` (state React).
- Le champ mot de passe met a jour `password`.
- `required` force la saisie avant envoi.

### 3) Tu cliques sur "Se connecter"

1. `handleSubmit` est appele.
2. `event.preventDefault()` evite le rechargement de la page.
3. `status` passe a `loading` pour activer le spinner du bouton.
4. Le code appelle `login({ email, password })`.

### 4) L'appel HTTP est fait

Dans `src/lib/api/auth.ts`:

- `login(...)` utilise `postJson(...)`.
- `postJson` se trouve dans `src/lib/api/client.ts`.

Dans `src/lib/api/client.ts`:

- `API_BASE_URL` prend `NEXT_PUBLIC_API_BASE_URL` si defini,
  sinon `http://localhost:8000`.
- `postJson` envoie un POST JSON vers `/auth/login`.

### 5) Le backend repond

Le backend renvoie soit:

- `{"access_token":"...","refresh_token":"..."}` si l'utilisateur est admin/superadmin.
- `{"message":"Code envoye..."}` si l'utilisateur est assistant (OTP requis).

Dans `login-card.tsx`:

- Si `access_token` + `refresh_token` existent:
  - ils sont stockes dans `localStorage` sous `sgci_access_token` et `sgci_refresh_token`,
  - redirection vers `/dashboard`.
- Si `message` existe:
  - l'email est stocke sous `sgci_pending_email`,
  - redirection vers `/two-factor`,
  - un message est affiche a l'ecran.
- Sinon, un message d'erreur est affiche.

### 6) L'ecran OTP (assistants)

Dans `src/app/components/sections/two-factor/two-factor-card.tsx`:

1. L'email est recupere soit depuis l'URL (`?email=...`), soit depuis `localStorage`.
2. Tu saisis le code OTP (6 chiffres).
3. L'app appelle `verifyOtp({ email, code })` dans `src/lib/api/auth.ts`.
4. Si OK:
   - `sgci_access_token` et `sgci_refresh_token` sont enregistres,
   - `sgci_pending_email` est supprime,
   - redirection vers `/dashboard`.
5. Si erreur:
   - compteur d'essais augmente,
   - message d'erreur affiche,
   - blocage apres plusieurs erreurs.

### 7) Apres la connexion

Les tokens sont stockes pour les appels proteges.
Les futures requetes devront ajouter un header:

```
Authorization: Bearer <access_token>
```

### Variable d'environnement

- `NEXT_PUBLIC_API_BASE_URL`  
  Exemple: `http://localhost:8000`

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
