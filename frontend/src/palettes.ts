/**
 * Colour schemes.
 *
 * Every palette fills the same thirteen slots, because ~23 components
 * reference them by name (`neon.pink`, `neon.cyan`, …). Those names are
 * historical — they come from the original Synthwave '84 scheme — and are
 * now read as SEMANTIC SLOTS rather than literal colours:
 *
 *   bg / bgDeep / paper / raised   surfaces, lightest to darkest in a dark
 *                                  theme and the reverse in a light one
 *   pink      the primary accent   headings, the active nav item, the logo
 *   cyan      the secondary accent links, section titles, "info"
 *   green     success / alive / confirmed
 *   yellow    caution / medium severity
 *   orange    high severity
 *   red       critical / pwned / destructive
 *   purple    structural chrome, borders, dividers
 *   text      body text at full contrast
 *   muted     secondary text
 *
 * So `neon.pink` in a Windows 95 theme is navy, and that is correct: the
 * slot means "primary accent", not "pink". Renaming the slots across 23
 * files would be churn with no behavioural gain.
 *
 * `decor` controls the background treatment. The animated grid horizon and
 * the scanlines belong to Synthwave '84 specifically; drawing them over
 * Solarized Light looks like a rendering fault rather than a style.
 *
 * `glow` controls whether text gets a neon halo. On light themes a halo
 * actively reduces contrast, so it is off and the Neon Dreams toggle has
 * no effect there.
 */

export interface Palette {
  bg: string
  bgDeep: string
  paper: string
  raised: string
  pink: string
  cyan: string
  yellow: string
  orange: string
  green: string
  red: string
  purple: string
  text: string
  muted: string
}

export interface ThemeDef {
  id: string
  name: string
  group: 'Dark' | 'Light' | 'Retro'
  mode: 'dark' | 'light'
  /** Background treatment: the grid + scanlines, or nothing. */
  decor: 'synthwave' | 'none'
  /** Whether text glow suits this scheme at all. */
  glow: boolean
  /** CRT scanline overlay. Only for schemes that are meant to evoke a
   *  monitor from that era — over Catppuccin Latte it is not a style, it
   *  is a dirty screen. */
  scanlines?: boolean
  /** Square corners and hard borders, for the Windows themes. */
  chrome?: 'flat' | 'win9x'
  font?: string
  palette: Palette
}

export const THEMES: ThemeDef[] = [
  {
    id: 'synthwave84', scanlines: true, name: "Synthwave '84", group: 'Dark', mode: 'dark',
    decor: 'synthwave', glow: true,
    palette: {
      bg: '#241b2f', bgDeep: '#1a1526', paper: '#2a2139', raised: '#34294f',
      pink: '#ff7edb', cyan: '#36f9f6', yellow: '#fede5d', orange: '#ff8b39',
      green: '#72f1b8', red: '#fe4450', purple: '#b893ce',
      text: '#f4f4f8', muted: '#a99fc4',
    },
  },
  {
    id: 'dracula', name: 'Dracula', group: 'Dark', mode: 'dark',
    decor: 'none', glow: true,
    palette: {
      bg: '#282a36', bgDeep: '#21222c', paper: '#2f3141', raised: '#44475a',
      pink: '#ff79c6', cyan: '#8be9fd', yellow: '#f1fa8c', orange: '#ffb86c',
      green: '#50fa7b', red: '#ff5555', purple: '#bd93f9',
      text: '#f8f8f2', muted: '#6272a4',
    },
  },
  {
    id: 'tokyonight', name: 'Tokyo Night', group: 'Dark', mode: 'dark',
    decor: 'none', glow: true,
    palette: {
      bg: '#1a1b26', bgDeep: '#16161e', paper: '#1f2335', raised: '#292e42',
      pink: '#bb9af7', cyan: '#7dcfff', yellow: '#e0af68', orange: '#ff9e64',
      green: '#9ece6a', red: '#f7768e', purple: '#7aa2f7',
      text: '#c0caf5', muted: '#565f89',
    },
  },
  {
    id: 'nord', name: 'Nord', group: 'Dark', mode: 'dark',
    decor: 'none', glow: false,
    palette: {
      bg: '#2e3440', bgDeep: '#272c36', paper: '#3b4252', raised: '#434c5e',
      pink: '#88c0d0', cyan: '#8fbcbb', yellow: '#ebcb8b', orange: '#d08770',
      green: '#a3be8c', red: '#bf616a', purple: '#b48ead',
      text: '#eceff4', muted: '#7b88a1',
    },
  },
  {
    id: 'gruvboxdark', name: 'Gruvbox Dark', group: 'Dark', mode: 'dark',
    decor: 'none', glow: false,
    palette: {
      bg: '#282828', bgDeep: '#1d2021', paper: '#32302f', raised: '#3c3836',
      pink: '#d3869b', cyan: '#8ec07c', yellow: '#fabd2f', orange: '#fe8019',
      green: '#b8bb26', red: '#fb4934', purple: '#d3869b',
      text: '#ebdbb2', muted: '#928374',
    },
  },
  {
    id: 'onedark', name: 'One Dark', group: 'Dark', mode: 'dark',
    decor: 'none', glow: false,
    palette: {
      bg: '#282c34', bgDeep: '#21252b', paper: '#2c313c', raised: '#3b4048',
      pink: '#c678dd', cyan: '#56b6c2', yellow: '#e5c07b', orange: '#d19a66',
      green: '#98c379', red: '#e06c75', purple: '#61afef',
      text: '#abb2bf', muted: '#5c6370',
    },
  },
  {
    id: 'mocha', name: 'Catppuccin Mocha', group: 'Dark', mode: 'dark',
    decor: 'none', glow: true,
    palette: {
      bg: '#1e1e2e', bgDeep: '#181825', paper: '#242438', raised: '#313244',
      pink: '#f5c2e7', cyan: '#89dceb', yellow: '#f9e2af', orange: '#fab387',
      green: '#a6e3a1', red: '#f38ba8', purple: '#cba6f7',
      text: '#cdd6f4', muted: '#9399b2',
    },
  },

  // ------------------------------------------------------------- retro
  {
    id: 'winxp', scanlines: true, name: 'Windows XP', group: 'Retro', mode: 'light',
    decor: 'none', glow: false, chrome: 'win9x',
    font: `'Trebuchet MS', 'Segoe UI', Tahoma, sans-serif`,
    palette: {
      // Luna: the classic #ECE9D8 window face with the blue title bar.
      bg: '#ECE9D8', bgDeep: '#D4D0C8', paper: '#FFFFFF', raised: '#F1EFE2',
      pink: '#0A246A', cyan: '#316AC5', yellow: '#D6A700', orange: '#D45B00',
      green: '#1E7B1E', red: '#C00000', purple: '#7A8CB8',
      text: '#000000', muted: '#5A5A5A',
    },
  },
  {
    id: 'win95', scanlines: true, name: 'Windows 95', group: 'Retro', mode: 'light',
    decor: 'none', glow: false, chrome: 'win9x',
    font: `'MS Sans Serif', 'Pixelated MS Sans Serif', Tahoma, sans-serif`,
    palette: {
      // The whole OS was three greys and a navy title bar.
      bg: '#C0C0C0', bgDeep: '#A8A8A8', paper: '#FFFFFF', raised: '#DFDFDF',
      pink: '#000080', cyan: '#000080', yellow: '#808000', orange: '#804000',
      green: '#008000', red: '#800000', purple: '#808080',
      text: '#000000', muted: '#404040',
    },
  },

  // ------------------------------------------------------------- light
  {
    id: 'solarizedlight', name: 'Solarized Light', group: 'Light', mode: 'light',
    decor: 'none', glow: false,
    palette: {
      bg: '#fdf6e3', bgDeep: '#eee8d5', paper: '#fffbf0', raised: '#eee8d5',
      pink: '#d33682', cyan: '#268bd2', yellow: '#b58900', orange: '#cb4b16',
      green: '#859900', red: '#dc322f', purple: '#6c71c4',
      text: '#073642', muted: '#657b83',
    },
  },
  {
    id: 'githublight', name: 'GitHub Light', group: 'Light', mode: 'light',
    decor: 'none', glow: false,
    font: `'Segoe UI', -apple-system, BlinkMacSystemFont, Helvetica, Arial, sans-serif`,
    palette: {
      bg: '#ffffff', bgDeep: '#f6f8fa', paper: '#ffffff', raised: '#f6f8fa',
      pink: '#0969da', cyan: '#0550ae', yellow: '#9a6700', orange: '#bc4c00',
      green: '#1a7f37', red: '#cf222e', purple: '#8250df',
      text: '#1f2328', muted: '#656d76',
    },
  },
  {
    id: 'onelight', name: 'One Light', group: 'Light', mode: 'light',
    decor: 'none', glow: false,
    palette: {
      bg: '#fafafa', bgDeep: '#eaeaeb', paper: '#ffffff', raised: '#f0f0f1',
      pink: '#a626a4', cyan: '#0184bc', yellow: '#c18401', orange: '#d75f00',
      green: '#50a14f', red: '#e45649', purple: '#4078f2',
      text: '#383a42', muted: '#8b8c92',
    },
  },
  {
    id: 'gruvboxlight', name: 'Gruvbox Light', group: 'Light', mode: 'light',
    decor: 'none', glow: false,
    palette: {
      bg: '#fbf1c7', bgDeep: '#f2e5bc', paper: '#f9f5d7', raised: '#ebdbb2',
      pink: '#8f3f71', cyan: '#076678', yellow: '#b57614', orange: '#af3a03',
      green: '#79740e', red: '#9d0006', purple: '#427b58',
      text: '#3c3836', muted: '#7c6f64',
    },
  },
  {
    id: 'latte', name: 'Catppuccin Latte', group: 'Light', mode: 'light',
    decor: 'none', glow: false,
    palette: {
      bg: '#eff1f5', bgDeep: '#e6e9ef', paper: '#ffffff', raised: '#dce0e8',
      pink: '#ea76cb', cyan: '#179299', yellow: '#df8e1d', orange: '#fe640b',
      green: '#40a02b', red: '#d20f39', purple: '#8839ef',
      text: '#4c4f69', muted: '#6c6f85',
    },
  },
]

export const DEFAULT_THEME = 'synthwave84'

export const byId = (id: string): ThemeDef =>
  THEMES.find((t) => t.id === id) ?? THEMES[0]
