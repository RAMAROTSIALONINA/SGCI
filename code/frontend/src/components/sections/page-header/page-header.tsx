import { cn } from '@/components/utils';

type PageHeaderProps = {
  title: string;
  description: string;
  className?: string;
};

export function PageHeader({ title, description, className }: PageHeaderProps) {
  return (
    <header
      className={cn(
        'rounded-3xl border border-border bg-surface-muted px-6 py-5 text-center shadow-soft backdrop-blur motion-safe:animate-soften-up',
        className,
      )}
    >
      <h1 className="text-3xl font-semibold tracking-tight text-foreground motion-safe:animate-soften-up-1">
        {title}
      </h1>
      <p className="mt-2 text-sm text-muted-foreground motion-safe:animate-soften-up-2">
        {description}
      </p>
    </header>
  );
}
