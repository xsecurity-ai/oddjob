import { createTheme, alpha } from '@mui/material/styles'
import { DEFAULT_THEME, byId, type ThemeDef } from './palettes'

/**
 * The active palette.
 *
 * The rule applied throughout: the accent colours are for CHROME, not for
 * DATA. Headers, borders, counts and accents are coloured; the actual cell
 * text stays at full contrast. A table where every row glows is unreadable
 * after about ten seconds, which defeats the point of the tool.
 *
 * `neon` is a MUTABLE object, deliberately. Twenty-three components call
 * `alpha(neon.pink, 0.2)` at render time, and `alpha()` needs a real colour
 * — it cannot take a CSS variable. So switching themes rewrites this
 * object in place and remounts the tree, which re-runs every one of those
 * calls with the new values. The alternative was threading a palette prop
 * through twenty-three files for no behavioural gain.
 *
 * The key names are historical (they come from Synthwave '84) and are read
 * as semantic slots — see palettes.ts.
 */
export const neon = { ...byId(DEFAULT_THEME).palette }

/** The whole active theme definition, not just its colours. */
export let active: ThemeDef = byId(DEFAULT_THEME)

/** Accent halo. Kept subtle — two layers, not five.
 *
 *  Returns nothing on a theme that does not suit it: on a light scheme a
 *  halo reduces contrast rather than adding emphasis, so Solarized Light
 *  gets flat text however enthusiastic the caller is. */
export const glow = (c: string, strength = 1) =>
  active.glow
    ? `0 0 ${2 * strength}px ${alpha(c, 0.9)}, 0 0 ${10 * strength}px ${alpha(c, 0.45)}`
    : 'none'

/** Swap the palette in place. Callers must remount for it to take effect. */
export function applyPalette(id: string): ThemeDef {
  const def = byId(id)
  Object.assign(neon, def.palette)
  active = def
  const root = document.documentElement
  root.dataset.theme = def.id
  root.dataset.decor = def.decor
  root.dataset.scanlines = def.scanlines ? 'on' : 'off'
  root.dataset.mode = def.mode
  // Exposed for index.css, which draws the background treatment and the
  // Neon Dreams bloom and cannot import from TypeScript.
  for (const [k, v] of Object.entries(def.palette)) {
    root.style.setProperty(`--c-${k}`, v)
  }
  document.body.style.background = def.palette.bg
  return def
}

export const buildTheme = (def: ThemeDef = active) => createTheme({
  palette: {
    mode: def.mode,
    background: { default: neon.bg, paper: neon.paper },
    primary: { main: neon.pink },
    secondary: { main: neon.cyan },
    error: { main: neon.red },
    warning: { main: neon.orange },
    success: { main: neon.green },
    info: { main: neon.cyan },
    text: { primary: neon.text, secondary: neon.muted },
    divider: alpha(neon.pink, 0.22),
  },
  // Windows 9x had no rounded corners anywhere.
  shape: { borderRadius: def.chrome === 'win9x' ? 0 : 6 },
  typography: {
    // A theme may bring its own face. Windows 95 in Orbitron is not
    // Windows 95; it is Synthwave with grey boxes.
    fontFamily: def.font
      ?? `'Share Tech Mono', ui-monospace, SFMono-Regular, Menlo, monospace`,
    fontSize: 13.5,
    h1: { fontFamily: def.font ?? `'Orbitron', sans-serif`, fontWeight: 800,
          letterSpacing: def.font ? 0 : '0.14em' },
    h6: { fontFamily: def.font ?? `'Orbitron', sans-serif`, fontWeight: 700,
          letterSpacing: def.font ? 0 : '0.18em' },
    button: { fontFamily: def.font ?? `'Orbitron', sans-serif`, fontWeight: 600,
              letterSpacing: def.font ? 0 : '0.1em' },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        '*::-webkit-scrollbar': { width: 10, height: 10 },
        '*::-webkit-scrollbar-track': { background: neon.bgDeep },
        '*::-webkit-scrollbar-thumb': {
          background: alpha(neon.pink, 0.35),
          borderRadius: 8,
          '&:hover': { background: alpha(neon.pink, 0.6) },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: alpha(neon.bgDeep, 0.86),
          backdropFilter: 'blur(10px)',
          borderBottom: `1px solid ${alpha(neon.pink, 0.4)}`,
          boxShadow: `0 1px 18px ${alpha(neon.pink, 0.28)}`,
          backgroundImage: 'none',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: `1px solid ${alpha(neon.purple, 0.22)}`,
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          fontFamily: `'Orbitron', sans-serif`,
          letterSpacing: '0.14em',
          color: neon.muted,
          '&.Mui-selected': { color: neon.cyan, textShadow: glow(neon.cyan, 0.8) },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontFamily: `'Share Tech Mono', monospace`, fontWeight: 700 },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: neon.bgDeep,
          border: `1px solid ${alpha(neon.cyan, 0.5)}`,
          color: neon.text,
          fontFamily: `'Share Tech Mono', monospace`,
          fontSize: 12.5,
        },
      },
    },
  },
})
