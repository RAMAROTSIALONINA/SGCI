import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from '@/components/ui';

export function SignupCard() {
  return (
    <Card className="w-full max-w-md border-border/70 bg-card/90 shadow-soft-lg backdrop-blur">
      <CardHeader className="space-y-2 text-center">
        <div className="text-xs font-semibold tracking-[0.3em] text-muted-foreground">
          SGCI
        </div>
        <CardTitle className="text-2xl font-semibold">
          Creer un compte
        </CardTitle>
        <CardDescription>
          Un design moderne et professionnel pour demarrer rapidement.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4">
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="last-name">Nom</Label>
              <Input
                id="last-name"
                placeholder="Traore"
                autoComplete="family-name"
                size="lg"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="first-name">Prenom</Label>
              <Input
                id="first-name"
                placeholder="Awa"
                autoComplete="given-name"
                size="lg"
              />
            </div>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="awa@entreprise.com"
              autoComplete="email"
              size="lg"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="password">Mot de passe</Label>
            <Input
              id="password"
              type="password"
              placeholder="Votre mot de passe"
              autoComplete="new-password"
              size="lg"
            />
          </div>

          <Button type="submit" size="lg" className="w-full">
            Creer mon compte
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
