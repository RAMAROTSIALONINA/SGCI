import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components';
import { assistantRoles } from '@/features/gestion-des-utilisateurs';

export default function NewUserPage() {
  return (
    <main className="mt-6 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="mx-auto w-full max-w-3xl">
        <Card className="border-border/70 bg-background/70 shadow-soft">
          <CardHeader className="space-y-2">
            <CardTitle>Nouvel assistant</CardTitle>
            <CardDescription>
              Renseignez les informations essentielles pour creer un compte assistant.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form id="new-user-form" className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="new-user-last-name">Nom</Label>
                <Input id="new-user-last-name" placeholder="Ex: Dupont" />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="new-user-first-name">Prenom</Label>
                <Input id="new-user-first-name" placeholder="Ex: Amina" />
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-email">Email</Label>
                <Input
                  id="new-user-email"
                  type="email"
                  placeholder="nom@entreprise.com"
                  autoComplete="email"
                />
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-role">Role assistant</Label>
                <Select>
                  <SelectTrigger id="new-user-role">
                    <SelectValue placeholder="Selectionner un role" />
                  </SelectTrigger>
                  <SelectContent>
                    {assistantRoles.map((role) => (
                      <SelectItem key={role.id} value={role.id}>
                        {role.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="new-user-password">Mot de passe</Label>
                <Input
                  id="new-user-password"
                  type="password"
                  placeholder="Definir un mot de passe provisoire"
                  autoComplete="new-password"
                />
                <span className="text-xs text-muted-foreground">
                  L&apos;utilisateur pourra changer ce mot de passe a sa premiere connexion.
                </span>
              </div>
            </form>
          </CardContent>
          <CardFooter className="justify-end">
            <Button type="submit" form="new-user-form">
              Creer l&apos;assistant
            </Button>
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}
