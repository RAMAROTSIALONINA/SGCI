import type { Meta, StoryObj } from '@storybook/react';

import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '.';

const meta: Meta<typeof Card> = {
  title: 'UI/Card',
  component: Card,
};

export default meta;
type Story = StoryObj<typeof Card>;

export const Basic: Story = {
  render: () => (
    <Card>
      <CardHeader>
        <CardTitle>Carte premium</CardTitle>
        <CardDescription>Sous-titre doux et lisible.</CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Un bloc idéal pour mettre en avant un contenu clé avec une surface douce et un léger flou
          de fond.
        </p>
      </CardContent>
      <CardFooter className="justify-end">
        <button className="text-sm text-primary underline-offset-4 hover:underline">
          En savoir plus
        </button>
      </CardFooter>
    </Card>
  ),
};

export const Interactive: Story = {
  render: () => (
    <Card interactive>
      <CardHeader>
        <CardTitle>Carte interactive</CardTitle>
        <CardDescription>Survoler pour voir l’ombre renforcée.</CardDescription>
      </CardHeader>
      <CardContent className="flex items-center gap-4">
        <div className="size-10 rounded-xl bg-accent/70" />
        <div>
          <p className="text-sm font-medium">Statistique</p>
          <p className="text-xs text-muted-foreground">+24% vs. le mois dernier</p>
        </div>
      </CardContent>
    </Card>
  ),
};

export const CompactPadding: Story = {
  render: () => (
    <Card padding="sm">
      <CardContent>
        <p className="text-sm">Une variante compacte pour des listes ou tableaux.</p>
      </CardContent>
    </Card>
  ),
};
