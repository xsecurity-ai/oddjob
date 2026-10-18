import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Chip, MenuItem, Paper, Stack, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type Project } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

/**
 * The rest of the authorisation letter, as config the tool enforces.
 *
 * The scope list has been enforced since the beginning. The dates and
 * the permitted techniques were in the same document and nothing in
 * the system could read them, so an engagement that ended on the 14th
 * went on scanning on the 20th.
 *
 * Shown with the state it is actually in rather than with empty
 * boxes. A project with no window has one — unbounded — and a blank
 * field would read as "not configured" when it means "no limit", and
 * those are not the same thing to anyone asking whether a scan is
 * authorised.
 */

const CEILINGS: { value: string; label: string; detail: string }[] = [
  { value: 'read_only', label: 'Read-only',
    detail: 'Port sweeps, DNS, GET requests, technology fingerprinting. '
          + 'Nothing at the far end is altered. Refuses nmap (its vuln '
          + 'scripts), nuclei, crawling and shell.' },
  { value: 'state_changing', label: 'State-changing',
    detail: 'The above, plus anything that makes something at the far end '
          + 'move: nmap NSE vuln scripts, nuclei payloads, a crawler that '
          + 'follows links and submits forms. Refuses shell.' },
  { value: 'destructive', label: 'Destructive — everything',
    detail: 'No ceiling. Includes an operator shell on the ghost, which is '
          + 'unbounded by definition.' },
]

/** `datetime-local` wants `YYYY-MM-DDTHH:mm`, with no zone and no seconds. */
function toLocalInput(iso: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
       + `T${p(d.getHours())}:${p(d.getMinutes())}`
}

/** How the window reads to somebody who has to decide if a scan is legal. */
function windowState(p: Project): { text: string; colour: string } {
  const now = Date.now()
  const s = p.engagement_starts_at ? Date.parse(p.engagement_starts_at) : null
  const e = p.engagement_ends_at ? Date.parse(p.engagement_ends_at) : null
  if (e !== null && now > e) {
    return { text: 'EXPIRED — nothing will run', colour: neon.red }
  }
  if (s !== null && now < s) {
    return { text: 'NOT STARTED — nothing will run yet', colour: neon.yellow }
  }
  // "Unbounded" and "within the window" are different answers and the
  // card says which. Collapsing them into a green tick would hide the
  // fact that nobody has set a date at all.
  if (s === null && e === null) {
    return { text: 'Unbounded — no dates set', colour: neon.muted }
  }
  return { text: 'Within the authorised window', colour: neon.green }
}

export function RulesOfEngagementCard({ project }: { project: Project }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const writable = canWrite(project.code)

  const [starts, setStarts] = useState('')
  const [ends, setEnds] = useState('')
  const [ceiling, setCeiling] = useState('destructive')
  const [err, setErr] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)

  useEffect(() => {
    setStarts(toLocalInput(project.engagement_starts_at))
    setEnds(toLocalInput(project.engagement_ends_at))
    setCeiling(project.max_impact ?? 'destructive')
    // Keyed on the id, not on the object: a refetch builds a fresh one
    // every time and would overwrite a half-typed date.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id])

  const done = async (what: string) => {
    setErr(null); setOk(what)
    await qc.invalidateQueries({ queryKey: ['project-config', project.code] })
    await qc.invalidateQueries({ queryKey: ['projects'] })
  }

  const save = useMutation({
    mutationFn: () => api.updateProject(project.code, {
      max_impact: ceiling,
      // `datetime-local` gives a local wall-clock string; the server
      // stores UTC. The conversion happens once, here, where the
      // operator can see which value they typed — not per task from a
      // timezone nobody recorded.
      engagement_starts_at: starts ? new Date(starts).toISOString() : null,
      engagement_ends_at: ends ? new Date(ends).toISOString() : null,
    }),
    onSuccess: () => done('Saved.'),
    onError: (e: unknown) =>
      setErr(e instanceof Error ? e.message : String(e)),
  })

  const clear = useMutation({
    mutationFn: () => api.clearEngagementWindow(project.code),
    onSuccess: () => { setStarts(''); setEnds(''); return done('Window cleared.') },
    onError: (e: unknown) =>
      setErr(e instanceof Error ? e.message : String(e)),
  })

  const state = windowState(project)
  const chosen = CEILINGS.find((c) => c.value === ceiling)
  const dirtyDates =
    starts !== toLocalInput(project.engagement_starts_at)
    || ends !== toLocalInput(project.engagement_ends_at)
  // A null in a PATCH means "leave alone" on purpose, so emptying the
  // box and pressing Save does nothing to a date that is already set.
  // Said here rather than discovered.
  const emptied =
    (!starts && !!project.engagement_starts_at)
    || (!ends && !!project.engagement_ends_at)

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2.5,
                                    borderColor: alpha(neon.orange, 0.35) }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1.2 }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                          letterSpacing: '0.14em', textTransform: 'uppercase',
                          color: neon.orange, textShadow: glow(neon.orange, 0.6) }}>
          Rules of engagement
        </Typography>
        <Chip size="small" label={state.text} sx={{
          height: 19, fontSize: 10, bgcolor: alpha(state.colour, 0.15),
          color: state.colour, border: `1px solid ${alpha(state.colour, 0.5)}` }} />
      </Stack>

      <Typography sx={{ fontSize: 11.5, color: alpha(neon.muted, 0.95), mb: 1.5 }}>
        The scope list says which hosts. These say when, and how far.
        Both are enforced when a task is queued and again when it is
        handed to a ghost — an engagement that ends with work still
        queued stops rather than draining.
      </Typography>

      <Stack direction="row" spacing={1.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
        <TextField size="small" type="datetime-local" label="Testing authorised from"
          value={starts} disabled={!writable} sx={{ minWidth: 230 }}
          slotProps={{ inputLabel: { shrink: true } }}
          helperText="Your local time. Stored as UTC. Empty means no start bound."
          onChange={(e) => setStarts(e.target.value)} />
        <TextField size="small" type="datetime-local" label="…until"
          value={ends} disabled={!writable} sx={{ minWidth: 230 }}
          slotProps={{ inputLabel: { shrink: true } }}
          helperText="Past this, every task is refused with the date as the reason."
          onChange={(e) => setEnds(e.target.value)} />
      </Stack>

      <TextField size="small" select label="Most intrusive technique permitted"
        value={ceiling} disabled={!writable} fullWidth sx={{ mt: 1.5 }}
        onChange={(e) => setCeiling(e.target.value)}>
        {CEILINGS.map((c) => (
          <MenuItem key={c.value} value={c.value} sx={{ fontSize: 12.5 }}>
            {c.label}
          </MenuItem>
        ))}
      </TextField>
      {chosen && (
        <Typography sx={{ fontSize: 11, color: alpha(neon.muted, 0.9), mt: 0.8 }}>
          {chosen.detail}
        </Typography>
      )}
      {/* The default is permissive, and a safety control that is off
          by default is only honest if it says so where it is set. */}
      {ceiling === 'destructive' && (
        <Typography sx={{ fontSize: 11, color: alpha(neon.yellow, 0.95), mt: 0.6 }}>
          This is the default for every project, not a decision anybody
          made for this one. If the authorisation says "no intrusive
          testing", set it.
        </Typography>
      )}

      {emptied && (
        <Alert severity="info" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
          Clearing a date box and saving will not remove it. Taking the
          bound off an authorisation is deliberate — use Clear window,
          which records who did it.
        </Alert>
      )}
      {err && <Alert severity="error" variant="outlined"
                     sx={{ mt: 1.5, fontSize: 11.5 }}>{err}</Alert>}
      {ok && !err && <Alert severity="success" variant="outlined"
                            sx={{ mt: 1.5, fontSize: 11.5 }}>{ok}</Alert>}

      <Stack direction="row" spacing={1} sx={{ mt: 1.5, alignItems: 'center' }}>
        <Button size="small" variant="outlined" disabled={!writable || save.isPending}
          onClick={() => save.mutate()}>Save</Button>
        <Tooltip title="Removes both dates. Recorded in the audit log.">
          <Box component="span">
            <Button size="small" variant="outlined" color="warning"
              disabled={!writable || clear.isPending
                        || (!project.engagement_starts_at
                            && !project.engagement_ends_at)}
              onClick={() => clear.mutate()}>Clear window</Button>
          </Box>
        </Tooltip>
        {dirtyDates && !emptied && (
          <Typography sx={{ fontSize: 11, color: neon.yellow }}>
            Unsaved changes.
          </Typography>
        )}
      </Stack>
    </Paper>
  )
}
