/**
 * The furniture every enumeration dialog needs: the same shell, the
 * same agent chooser, and one place that says what the fleet can do.
 *
 * Split out because three dialogs asking "which Jaws, and can it
 * actually run this?" in three slightly different ways is how one of
 * them ends up quietly omitting the raw-sockets caveat.
 */
import type { ReactNode } from 'react'
import {
  Alert, Box, Chip, Dialog, DialogTitle, MenuItem, Stack, TextField,
  Typography, alpha,
} from '@mui/material'
import { neon, glow } from '../theme'
import { needsRegion, type AgentChoice, type Fleet } from './jawsTasking'

export const paperSx = (accent: string) => ({
  backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
  border: `1px solid ${alpha(accent, 0.45)}`,
  boxShadow: `0 0 44px ${alpha(accent, 0.22)}`,
})

export const titleSx = (accent: string) => ({
  fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
  letterSpacing: '0.14em', color: accent, textShadow: glow(accent, 0.5),
  borderBottom: `1px solid ${alpha(accent, 0.28)}`,
})

export const chipSx = (c: string) => ({
  height: 18, fontSize: 10, bgcolor: alpha(c, 0.15), color: c,
  border: `1px solid ${alpha(c, 0.45)}`,
})

/** Monospace block for "this is the command that will run". */
export function Argv({ text }: { text: string }) {
  return (
    <Box sx={{
      fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
      color: neon.green, bgcolor: alpha(neon.bgDeep, 0.6),
      border: `1px solid ${alpha(neon.green, 0.25)}`, borderRadius: 1,
      px: 1.2, py: 0.9, overflowX: 'auto', whiteSpace: 'pre-wrap',
      wordBreak: 'break-all',
    }}>{text}</Box>
  )
}

export function EnumerateDialog({ accent, title, open, onClose, children }: {
  accent: string; title: string; open?: boolean
  onClose: () => void; children: ReactNode
}) {
  return (
    <Dialog open={open ?? true} onClose={onClose} maxWidth="md" fullWidth
      slotProps={{ paper: { sx: { ...paperSx(accent), width: '94vw', maxWidth: 820 } } }}>
      <DialogTitle sx={titleSx(accent)}>{title}</DialogTitle>
      {children}
    </Dialog>
  )
}

/**
 * What the fleet can do, said plainly.
 *
 * `blocked` is an error because nothing will run; `caution` is a
 * warning because something will, later. The difference matters more
 * than it looks: a queued task with no agent behind it reads on the
 * Jaws page exactly like one that is running.
 */
export function FleetNotice({ fleet }: { fleet: Fleet }) {
  if (fleet.loading) return null
  if (fleet.blocked) {
    return <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
      {fleet.blocked}
    </Alert>
  }
  if (fleet.caution) {
    return <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
      {fleet.caution}
    </Alert>
  }
  return null
}

/**
 * Pick the agent, or the pool. Raw-socket capability is on the row
 * because it changes which scan nmap actually runs, and finding that
 * out from the report six weeks later is the failure this avoids.
 */
export function AgentChooser({ fleet, value, onChange, region, onRegion }: {
  fleet: Fleet
  value: AgentChoice
  onChange: (v: AgentChoice) => void
  region: string
  onRegion: (v: string) => void
}) {
  const mode = fleet.routing?.mode ?? 'mesh'
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems="flex-start">
      <TextField
        select size="small" label="Run on" sx={{ minWidth: 300 }}
        value={value === null ? 'pool' : String(value)}
        onChange={(e) => onChange(e.target.value === 'pool' ? null : Number(e.target.value))}
        helperText={value === null
          ? `Project pool — ${mode} routing decides which Jaws takes it.`
          : 'Addressed to this agent. The routing policy does not override it.'}>
        <MenuItem value="pool">Any available agent (project pool)</MenuItem>
        {fleet.agents.map((a) => (
          <MenuItem key={a.id} value={String(a.id)} disabled={a.status === 'disabled'}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ width: '100%' }}>
              <Box sx={{ flex: 1 }}>{a.name}</Box>
              <Chip size="small" label={a.status}
                sx={chipSx(a.status === 'online' ? neon.green : neon.muted)} />
              <Chip size="small" label={a.privileged ? 'raw sockets' : 'no raw sockets'}
                sx={chipSx(a.privileged ? neon.green : neon.yellow)} />
            </Stack>
          </MenuItem>
        ))}
      </TextField>
      {needsRegion(fleet, value) && (
        <TextField
          size="small" label="Region" value={region} sx={{ minWidth: 180 }}
          onChange={(e) => onRegion(e.target.value)}
          error={!region.trim()}
          helperText={region.trim()
            ? 'Only an agent serving this region will take it.'
            : 'This project routes by region, so a pooled task needs one.'} />
      )}
    </Stack>
  )
}

/** Small muted paragraph. Used for the "what this does not do" notes. */
export function Caveat({ children }: { children: ReactNode }) {
  return (
    <Typography sx={{ fontSize: 11, color: neon.muted, lineHeight: 1.5 }}>
      {children}
    </Typography>
  )
}
