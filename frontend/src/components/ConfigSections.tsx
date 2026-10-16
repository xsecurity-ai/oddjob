/**
 * One settings screen, one section at a time.
 *
 * Site Config is six groups and forty-seven fields in a single
 * scroll, and Project Config is a similar run of stacked panels.
 * Everything is reachable and nothing is findable: the only way to
 * know whether a setting exists is to scroll past all of them.
 *
 * **Hidden sections stay mounted.** They are hidden with `display:
 * none`, not unmounted. Two reasons, and the first is the one that
 * matters:
 *
 *  - these are forms. Unmounting a section discards whatever was
 *    typed into it, so changing the dropdown to go and check
 *    something would silently throw away an unsaved edit. A
 *    settings page that loses work when you look away is worse than
 *    a long one.
 *  - it keeps mount and query behaviour identical to the single
 *    scroll this replaces, so nothing about loading or refetching
 *    changes. This is a layout change and should be only that.
 *
 * The cost is that every section renders. That is exactly what
 * happens today, so it is not a new cost.
 *
 * The choice is remembered per screen, because coming back to a
 * settings page usually means coming back to the same setting.
 * localStorage rather than the URL: it is a preference about how you
 * are reading the page, not a place — and `lib/route.ts` deliberately
 * keeps the route table to things worth pasting to someone.
 */
import { useState } from 'react'
import { Box, MenuItem, Stack, TextField, Typography, alpha } from '@mui/material'
import { neon } from '../theme'

export interface ConfigSection {
  /** Stable across renames: this is what gets remembered. */
  key: string
  label: string
  /** Shown beside the label in the dropdown — a count, a warning. */
  hint?: string
  node: React.ReactNode
}

function remembered(id: string, fallback: string): string {
  try {
    return window.localStorage.getItem(`oddjob.config-section.${id}`) || fallback
  } catch {
    // Private windows throw. A forgotten tab is a smaller problem
    // than a settings page that will not render.
    return fallback
  }
}

export function ConfigSections({ id, sections }: {
  /** Distinguishes one screen's memory from another's. */
  id: string
  sections: ConfigSection[]
}) {
  const first = sections[0]?.key ?? ''
  const [picked, setPicked] = useState(() => remembered(id, first))
  // A remembered section that no longer exists — renamed, or hidden
  // because the user lost a permission — must not render a blank
  // page. Falling back is the whole handling.
  const current = sections.some((s) => s.key === picked) ? picked : first

  const choose = (k: string) => {
    setPicked(k)
    try {
      window.localStorage.setItem(`oddjob.config-section.${id}`, k)
    } catch { /* best effort */ }
  }

  return (
    <Stack spacing={2}>
      <Stack
        direction="row"
        spacing={1.5}
        sx={{
          alignItems: "center",
          flexWrap: 'wrap'
        }}>
        <TextField select size="small" label="Section" value={current}
          onChange={(e) => choose(e.target.value)}
          sx={{ minWidth: 240 }}>
          {sections.map((s) => (
            <MenuItem key={s.key} value={s.key} sx={{ fontSize: 12.5 }}>
              {s.label}
              {s.hint && (
                <Box component="span"
                  sx={{ ml: 1, color: neon.muted, fontSize: 11 }}>
                  {s.hint}
                </Box>
              )}
            </MenuItem>
          ))}
        </TextField>
        <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
          {sections.length} sections. Unsaved edits in a section you
          switch away from are kept.
        </Typography>
      </Stack>

      <Box sx={{ borderTop: `1px solid ${alpha(neon.cyan, 0.15)}`, pt: 2 }}>
        {sections.map((s) => (
          <Box key={s.key}
            sx={{ display: s.key === current ? 'block' : 'none' }}>
            {s.node}
          </Box>
        ))}
      </Box>
    </Stack>
  );
}
