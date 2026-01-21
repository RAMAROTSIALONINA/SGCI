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

export function LoginCard() {
  return (
    <Card className="w-full max-w-md border-border/70 bg-card/90 shadow-soft-lg backdrop-blur">
      <CardHeader className="space-y-2 text-center">
        <div className="text-xs font-semibold tracking-[0.3em] text-muted-foreground">
          SGCI
        </div>
        <CardTitle className="text-2xl font-semibold">Se connecter</CardTitle>
        <CardDescription>
          Accedez a votre espace securise en quelques secondes.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="login-email">Email</Label>
            <Input
              id="login-email"
              type="email"
              placeholder="awa@entreprise.com"
              autoComplete="email"
              size="lg"
            />
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="login-password">Mot de passe</Label>
              <Button variant="link" size="sm" type="button" className="px-0">
                Mot de passe oublie
              </Button>
            </div>
            <Input
              id="login-password"
              type="password"
              placeholder="Votre mot de passe"
              autoComplete="current-password"
              size="lg"
            />
          </div>

          <Button type="submit" size="lg" className="w-full">
            Se connecter
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
