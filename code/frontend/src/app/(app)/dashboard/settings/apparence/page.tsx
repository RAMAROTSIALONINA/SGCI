'use client';

import { useTheme } from 'next-themes';
import * as React from 'react';

import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  cn,
  ThemeToggle,
} from '@/components';
import { DEFAULT_PALETTE, PALETTE_STORAGE_KEY } from '@/components/providers/palette-provider';
import { updateCurrentUser } from '@/lib/api';
import { getAccessToken } from '@/lib/auth/tokens';

const paletteOptions = [
  {
    id: 'oasis',
    name: 'Oasis',
    description: 'Teal + ambre',
    colors: ['#1f7a6d', '#f4b740', '#fac45e'],
  },
  {
    id: 'ocean',
    name: 'Ocean',
    description: 'Bleu + aqua',
    colors: ['#2f6fdd', '#22c1c3', '#7bdff2'],
  },
  {
    id: 'sunset',
    name: 'Sunset',
    description: 'Corail + or',
    colors: ['#e55947', '#f6c453', '#ffd6a5'],
  },
  {
    id: 'berry',
    name: 'Berry',
    description: 'Violet + rose',
    colors: ['#7b2cbf', '#f72585', '#ff97d5'],
  },
  {
    id: 'forest',
    name: 'Forest',
    description: 'Vert profond',
    colors: ['#2d6a4f', '#52b788', '#95d5b2'],
  },
  {
    id: 'citrus',
    name: 'Citrus',
    description: 'Lime + soleil',
    colors: ['#5bb318', '#f4d35e', '#f9f871'],
  },
  {
    id: 'royal',
    name: 'Royal',
    description: 'Indigo + or',
    colors: ['#3f37c9', '#f8961e', '#ffd166'],
  },
  {
    id: 'slate',
    name: 'Slate',
    description: 'Ardoise + cyan',
    colors: ['#334155', '#14b8a6', '#67e8f9'],
  },
];

export default function SettingsAppearancePage() {
  const { resolvedTheme, setTheme } = useTheme();
  const [activePalette, setActivePalette] = React.useState(DEFAULT_PALETTE);
  const [isAppearanceReady, setIsAppearanceReady] = React.useState(false);

  React.useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const stored = localStorage.getItem(PALETTE_STORAGE_KEY);
    const initialPalette =
      stored ?? document.documentElement.getAttribute('data-palette') ?? DEFAULT_PALETTE;
    setActivePalette(initialPalette);
    setIsAppearanceReady(true);
  }, []);

  const currentTheme = resolvedTheme ?? 'light';

  const persistTheme = (nextTheme: 'light' | 'dark') => {
    if (typeof window === 'undefined') {
      return;
    }
    const token = getAccessToken();
    if (!token) {
      return;
    }
    void updateCurrentUser(token, { theme_mode: nextTheme }).catch(() => {
      // Keep UI responsive even if saving fails.
    });
  };

  const handleThemeChange = (nextTheme: 'light' | 'dark') => {
    setTheme(nextTheme);
    persistTheme(nextTheme);
  };

  const handlePaletteChange = (paletteId: string) => {
    setActivePalette(paletteId);
    if (typeof window === 'undefined') {
      return;
    }
    localStorage.setItem(PALETTE_STORAGE_KEY, paletteId);
    document.documentElement.setAttribute('data-palette', paletteId);
    const token = getAccessToken();
    if (!token) {
      return;
    }
    void updateCurrentUser(token, { palette: paletteId }).catch(() => {
      // Ignore persistence errors.
    });
  };

  const handleResetAppearance = () => {
    setTheme('light');
    setActivePalette(DEFAULT_PALETTE);
    if (typeof window === 'undefined') {
      return;
    }
    localStorage.setItem(PALETTE_STORAGE_KEY, DEFAULT_PALETTE);
    document.documentElement.setAttribute('data-palette', DEFAULT_PALETTE);
    const token = getAccessToken();
    if (!token) {
      return;
    }
    void updateCurrentUser(token, {
      theme_mode: 'light',
      palette: DEFAULT_PALETTE,
    }).catch(() => {
      // Ignore persistence errors.
    });
  };

  return (
    <main className="mt-8 flex-1 rounded-3xl border border-dashed border-border bg-surface/60 p-10 shadow-soft backdrop-blur">
      <div className="mx-auto w-full max-w-3xl">
        <Card className="border-border/70 bg-background/70 shadow-soft">
          <CardHeader className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <CardTitle>Apparence</CardTitle>
                <CardDescription>
                  Choisissez le theme et la palette qui vous correspond.
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={handleResetAppearance}>
                  Par defaut
                </Button>
                <ThemeToggle onThemeChange={persistTheme} />
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-semibold text-foreground">Mode</h4>
                <Badge variant="secondary">Live</Badge>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {(['light', 'dark'] as const).map((mode) => {
                  const isActive = currentTheme === mode;
                  return (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => handleThemeChange(mode)}
                      aria-pressed={isActive}
                      className={cn(
                        'group relative overflow-hidden rounded-2xl border px-4 py-4 text-left transition-all duration-200',
                        isActive
                          ? 'border-primary/60 bg-[linear-gradient(120deg,_rgba(var(--palette-primary-rgb)_/_0.12),_rgba(var(--palette-accent-rgb)_/_0.2))] shadow-soft-lg'
                          : 'border-border/70 bg-surface/70 hover:border-primary/40 hover:shadow-soft',
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="text-sm font-semibold capitalize">
                            {mode === 'light' ? 'Light' : 'Dark'}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {mode === 'light'
                              ? 'Clair, lumineux, net.'
                              : 'Sombre, premium, contraste eleve.'}
                          </p>
                        </div>
                        {isActive ? (
                          <Badge>Actif</Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">Choisir</span>
                        )}
                      </div>
                      <div className="mt-4 flex items-center gap-2">
                        <span
                          className={cn(
                            'h-8 w-14 rounded-xl border border-border/60 shadow-sm transition',
                            mode === 'light'
                              ? 'bg-[linear-gradient(120deg,_rgba(var(--palette-primary-rgb)_/_0.2),_rgba(var(--palette-accent-rgb)_/_0.3))]'
                              : 'bg-[linear-gradient(120deg,_rgba(15,24,23,0.9),_rgba(11,19,18,0.95))]',
                          )}
                        />
                        <span className="text-xs text-muted-foreground">Disponible</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-semibold text-foreground">Palettes</h4>
                <Badge variant="secondary">Nouveautes</Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Selectionnez une palette moderne et professionnelle. Le choix s&apos;applique
                immediatement.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                {paletteOptions.map((palette) => {
                  const isActive = activePalette === palette.id;
                  return (
                    <button
                      key={palette.id}
                      type="button"
                      onClick={() => handlePaletteChange(palette.id)}
                      aria-pressed={isActive}
                      className={cn(
                        'group relative overflow-hidden rounded-2xl border px-4 py-4 text-left transition-all duration-200',
                        isActive
                          ? 'border-primary/70 bg-[linear-gradient(120deg,_rgba(var(--palette-primary-rgb)_/_0.12),_rgba(var(--palette-accent-rgb)_/_0.2))] shadow-soft-lg'
                          : 'border-border/70 bg-surface/70 hover:border-primary/40 hover:shadow-soft',
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <p className="text-sm font-semibold">{palette.name}</p>
                          <p className="text-xs text-muted-foreground">{palette.description}</p>
                        </div>
                        {isActive ? (
                          <Badge>Actif</Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">Choisir</span>
                        )}
                      </div>
                      <div className="mt-4 flex items-center gap-2">
                        {palette.colors.map((color) => (
                          <span
                            key={color}
                            className="h-6 w-6 rounded-full border border-white/50 shadow-sm"
                            style={{ backgroundColor: color }}
                          />
                        ))}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </CardContent>
          <CardFooter className="text-xs text-muted-foreground">
            {isAppearanceReady
              ? "Vos preferences d'apparence sont sauvegardees localement."
              : "Chargement des preferences d'apparence..."}
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}
