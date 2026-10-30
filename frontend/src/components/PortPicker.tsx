/**
 * Picking several ports, with the ones worth picking offered.
 *
 * Shared by the Ghost's edit dialog and the C2 page, because two
 * controls for one idea is how the two end up disagreeing about what
 * a valid port is — and the server would then refuse a form that
 * looked fine.
 *
 * **The suggested ports are not arbitrary and their order is the
 * point.** A client's egress is usually filtered to browser ports, so
 * a listener on 47000 is refused by the client's own firewall and the
 * test then reports "not vulnerable" about the firewall rather than
 * about the target. This is the same list, in the same order, as the
 * task-level callback feature binds in.
 */
import { useState } from 'react'
import { Box, Chip, Stack, TextField, Tooltip, Typography, alpha } from '@mui/material'
import { neon } from '../theme'

/** The ports a callback is most likely to get out on, in the order
 *  the agent's own callback feature tries them. */
export const LIKELY_PORTS = [443, 80, 8443, 8080, 8000, 10000]

/** Below this a bind needs CAP_NET_BIND_SERVICE on the Ghost.
 *  `ghost/docker-compose.yml` grants it, so this is a note and not a
 *  refusal — but a Ghost started without it fails to bind 443, and
 *  saying so here is cheaper than reading a failure later. */
const PRIVILEGED_BELOW = 1024

/** Ports out of a typed list. Commas, spaces and newlines all
 *  separate, because people paste from all three. */
export function parsePorts(text: string): { ports: number[]; bad: string[] } {
  const ports: number[] = []
  const bad: string[] = []
  for (const piece of text.split(/[\s,;]+/)) {
    if (!piece) continue
    const n = Number(piece)
    if (!Number.isInteger(n) || n < 1 || n > 65535) { bad.push(piece); continue }
    if (!ports.includes(n)) ports.push(n)
  }
  return { ports, bad }
}

export function PortPicker({ label, help, value, onChange, disabled }: {
  label: string
  help?: string
  value: number[]
  onChange: (ports: number[]) => void
  disabled?: boolean
}) {
  const [draft, setDraft] = useState('')

  const add = (text: string) => {
    const { ports } = parsePorts(text)
    if (!ports.length) return
    onChange([...value, ...ports.filter((p) => !value.includes(p))]
      .sort((a, b) => a - b))
    setDraft('')
  }

  return (
    <Box>
      <TextField size="small" fullWidth label={label} value={draft}
        disabled={disabled}
        placeholder="443, 8080, 9001"
        helperText={help}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          // Enter and comma both commit. A field that only takes
          // Enter loses what was typed when the dialog is saved
          // with text still in the box.
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault()
            add(draft)
          }
        }}
        onBlur={() => add(draft)} />

      <Stack direction="row" spacing={0.5} useFlexGap
        sx={{ flexWrap: 'wrap', mt: 0.8 }}>
        {value.map((p) => (
          <Tooltip key={p} disableHoverListener={p >= PRIVILEGED_BELOW}
            title={`Below ${PRIVILEGED_BELOW}, so the ghost needs `
                   + 'CAP_NET_BIND_SERVICE to bind it. The shipped '
                   + 'compose file grants that.'}>
            <Chip size="small" label={p}
              onDelete={disabled ? undefined
                                 : () => onChange(value.filter((x) => x !== p))}
              sx={{
                height: 20, fontSize: 11,
                bgcolor: alpha(neon.cyan, 0.12), color: neon.cyan,
                border: `1px solid ${alpha(
                  p < PRIVILEGED_BELOW ? neon.yellow : neon.cyan, 0.45)}`,
              }} />
          </Tooltip>
        ))}
        {!value.length && (
          <Typography sx={{ fontSize: 11, color: neon.muted }}>
            None. This ghost holds no {label.toLowerCase()}.
          </Typography>
        )}
      </Stack>

      <Stack direction="row" spacing={0.5} useFlexGap
        sx={{ flexWrap: 'wrap', mt: 0.8, alignItems: 'center' }}>
        <Typography sx={{ fontSize: 10.5, color: neon.muted, mr: 0.3 }}>
          likely to get out:
        </Typography>
        {LIKELY_PORTS.filter((p) => !value.includes(p)).map((p) => (
          <Chip key={p} size="small" label={`+${p}`} clickable
            disabled={disabled}
            onClick={() => onChange([...value, p].sort((a, b) => a - b))}
            sx={{ height: 19, fontSize: 10.5, color: neon.muted,
                  border: `1px solid ${alpha(neon.muted, 0.35)}` }} />
        ))}
      </Stack>
    </Box>
  )
}
