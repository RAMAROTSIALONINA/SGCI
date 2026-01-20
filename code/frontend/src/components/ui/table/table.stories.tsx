import type { Meta, StoryObj } from '@storybook/react';

import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '.';

const meta: Meta<typeof Table> = {
  title: 'UI/Table',
  component: Table,
};

export default meta;
type Story = StoryObj<typeof Table>;

export const Default: Story = {
  render: () => (
    <Table>
      <TableCaption>Factures recentes</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>Projet</TableHead>
          <TableHead>Client</TableHead>
          <TableHead className="text-right">Montant</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {[
          { project: 'Dashboard', client: 'Nova', amount: '€2,400' },
          { project: 'Landing', client: 'Studio', amount: '€1,250' },
        ].map((row) => (
          <TableRow key={row.project}>
            <TableCell className="font-medium">{row.project}</TableCell>
            <TableCell className="text-muted-foreground">{row.client}</TableCell>
            <TableCell className="text-right">{row.amount}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  ),
};
