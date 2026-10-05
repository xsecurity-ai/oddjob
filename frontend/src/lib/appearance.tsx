import { createContext, useCallback, useContext, useEffect, useMemo, useState,
         type ReactNode } from 'react'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { DEFAULT_THEME, THEMES, byId, type ThemeDef } from '../palettes'
import { applyPalette, buildTheme } from '../theme'

/**
 * Theme and Neon Dreams, held together because they are one decision:
 * both are per-viewer presentation with no effect on anyone else's screen.
 *
 * Stored in localStorage rather than on the user record. It is a per-device
 * preference — the same person wants the dark theme on a laptop at night
 * and the light one on a projector — and a round trip to the server to
 * learn which colours to paint would mean a flash of the wrong theme on
 * every load. Reads and writes are wrapped because localStorage throws in
 * a private window and comes back empty after a data clear.
 *
 * Changing the palette REMOUNTS the tree. `alpha(neon.pink, 0.2)` is
 * evaluated during render in ~23 components, so new colours only reach the
 * screen when those functions run again; bumping a key is what guarantees
 * that, and a theme switch is rare enough that the cost does not matter.
 */

const THEME_KEY = 'oddjob.theme'
const DREAMS_KEY = 'oddjob.neonDreams'

function read(key: string, fallback: string): string {
  try {
    return window.localStorage.getItem(key) ?? fallback
  } catch {
    return fallback
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    /* private window, or site data blocked — the choice just will not persist */
  }
}

interface Appearance {
  theme: ThemeDef
  themes: ThemeDef[]
  setTheme: (id: string) => void
  dreams: boolean
  setDreams: (on: boolean) => void
  /** False on themes where a halo would hurt contrast rather than help. */
  dreamsAvailable: boolean
}

const Ctx = createContext<Appearance | null>(null)

export function useAppearance(): Appearance {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAppearance outside AppearanceProvider')
  return c
}

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [id, setId] = useState(() => byId(read(THEME_KEY, DEFAULT_THEME)).id)
  const [dreams, setDreamsState] = useState(() => read(DREAMS_KEY, '0') === '1')
  const [gen, setGen] = useState(0)

  // Applied synchronously on first render too, so the page never paints
  // the default palette before switching to the chosen one.
  const def = useMemo(() => {
    const d = applyPalette(id)
    return d
  }, [id])

  useEffect(() => {
    document.body.classList.toggle('neon-dreams', dreams && def.glow)
  }, [dreams, def])

  const setTheme = useCallback((next: string) => {
    setId(byId(next).id)
    write(THEME_KEY, byId(next).id)
    setGen((g) => g + 1)
  }, [])

  const setDreams = useCallback((on: boolean) => {
    setDreamsState(on)
    write(DREAMS_KEY, on ? '1' : '0')
  }, [])

  const value = useMemo<Appearance>(() => ({
    theme: def, themes: THEMES, setTheme, dreams, setDreams,
    dreamsAvailable: def.glow,
  }), [def, setTheme, dreams, setDreams])

  const mui = useMemo(() => buildTheme(def), [def])

  return (
    <Ctx.Provider value={value}>
      <ThemeProvider theme={mui} defaultMode={def.mode}>
        <CssBaseline />
        {/* The remount: see the note at the top. */}
        <div key={`${def.id}-${gen}`} style={{ display: 'contents' }}>
          {children}
        </div>
      </ThemeProvider>
    </Ctx.Provider>
  )
}
