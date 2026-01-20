import type { Meta, StoryObj } from '@storybook/react';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '.';

const meta: Meta<typeof Tabs> = {
  title: 'UI/Tabs',
  component: Tabs,
};

export default meta;
type Story = StoryObj<typeof Tabs>;

export const Default: Story = {
  render: () => (
    <Tabs defaultValue="overview">
      <TabsList>
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="details">Details</TabsTrigger>
        <TabsTrigger value="team">Team</TabsTrigger>
      </TabsList>
      <TabsContent value="overview">Vue d&apos;ensemble.</TabsContent>
      <TabsContent value="details">Informations detaillees.</TabsContent>
      <TabsContent value="team">Equipe.</TabsContent>
    </Tabs>
  ),
};

export const Sizes: Story = {
  render: () => (
    <div className="space-y-4">
      <Tabs defaultValue="a">
        <TabsList size="sm">
          <TabsTrigger value="a" size="sm">
            Small
          </TabsTrigger>
          <TabsTrigger value="b" size="sm">
            Small 2
          </TabsTrigger>
        </TabsList>
        <TabsContent value="a">Petit format.</TabsContent>
        <TabsContent value="b">Petit format 2.</TabsContent>
      </Tabs>
      <Tabs defaultValue="c">
        <TabsList size="lg">
          <TabsTrigger value="c" size="lg">
            Large
          </TabsTrigger>
          <TabsTrigger value="d" size="lg">
            Large 2
          </TabsTrigger>
        </TabsList>
        <TabsContent value="c">Grand format.</TabsContent>
        <TabsContent value="d">Grand format 2.</TabsContent>
      </Tabs>
    </div>
  ),
};
