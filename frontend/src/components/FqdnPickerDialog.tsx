/**
 * Decide what a finished lookup meant.
 *
 * A reverse lookup on one address can come back with nothing, with one
 * name, or with forty — shared hosting, a CDN and a reverse proxy all
 * serve many unrelated names from a single address. Exactly one name is
 * the only case where the answer is unambiguous, so that one is applied
 * on sight; more than one is a question only a person can answer, and
 * none is a result worth stating rather than hiding.
 *
 * The pending list is derived server-side from completed tasks and the
 * current inventory (see backend/app/routers/enumerate.py). There is no
 * "pending choice" table: applying one makes it stop being returned,
 * which is why nothing here has to mark anything done.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert, Box, Button, Chip, DialogActions, DialogContent, LinearProgress,
  MenuItem, Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import { Caveat, EnumerateDialog, chipSx } from './EnumerateBits'

export type PendingLookup =
  Awaited<ReturnType<typeof api.enumeratePending>>[number]

/** Choices a person still has to make — two or more answers for one
 *  subject. A single answer is applied automatically and is deliberately
 *  not counted here, or the badge would advertise a decision nobody has
 *  to take. */
export function openChoices(rows: PendingLookup[] | undefined): PendingLookup[] {
  return (rows ?? []).filter((r) => r.options.length > 1)
}

/**
 * Lookups that ran and produced nothing.
 *
 * Kept visible and kept separate. "We looked and found nothing" is a
 * coverage fact worth seeing, and folding it in with the open choices
 * would make the badge count things nobody can act on.
 */
export function emptyResults(rows: PendingLookup[] | undefined): PendingLookup[] {
  return (rows ?? []).filter((r) => r.options.length === 0)
}

/**
 * Apply every lookup that came back with exactly one answer.
 *
 * One answer is not a choice, so asking would be ceremony. It runs
 * wherever the pending list is already being watched rather than inside
 * the dialog, because the operator who queued the lookup should not
 * have to go and open something for the obvious half of the result to
 * land.
 *
 * Guarded by a ref of what has been attempted, not by the mutation's
 * own state: the list is recomputed on every cache invalidation, and a
 * row whose apply FAILED would otherwise be retried forever at whatever
 * rate the SSE stream fires. A failure is surfaced, not repeated.
 */
export function useAutoApplySingles(project: string | null,
                                    rows: PendingLookup[] | undefined) {
  const qc = useQueryClient()
  const tried = useRef(new Set<string>())
  const [failed, setFailed] = useState<string | null>(null)

  useEffect(() => {
    if (!project) return
    const single = (rows ?? []).filter(
      (r) => r.options.length === 1 && !tried.current.has(`${r.kind}:${r.subject}`))
    if (!single.length) return
    let live = true
    void (async () => {
      let wrote = false
      for (const r of single) {
        tried.current.add(`${r.kind}:${r.subject}`)
        try {
          await api.enumerateResolve(project, {
            host: r.target_host, field: r.field, value: r.options[0],
          })
          wrote = true
        } catch (e) {
          if (live) {
            setFailed(`${r.subject} → ${r.options[0]}: `
                      + (e instanceof Error ? e.message : String(e)))
          }
        }
      }
      if (wrote && live) await qc.invalidateQueries()
    })()
    return () => { live = false }
  }, [project, rows, qc])

  return failed
}

function Row({ row, project, onBusy }: {
  row: PendingLookup; project: string; onBusy: (b: boolean) => void
}) {
  const qc = useQueryClient()
  const [pick, setPick] = useState(row.options[0] ?? '')
  const [err, setErr] = useState<string | null>(null)

  const apply = useMutation({
    mutationFn: () => api.enumerateResolve(project, {
      host: row.target_host, field: row.field, value: pick,
      // All of them, not just the pick. Choosing one name does not
      // make the others untrue, and they are often the most useful
      // thing a reverse lookup produces.
      also_resolved: row.options,
    }),
    onMutate: () => { setErr(null); onBusy(true) },
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
    onSettled: async () => { onBusy(false); await qc.invalidateQueries() },
  })

  const many = row.options.length > 1
  return (
    <Box sx={{ border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1,
               p: 1.2 }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Box sx={{ fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5,
                   color: neon.cyan }}>{row.subject}</Box>
        <Chip size="small" label={row.kind} sx={chipSx(neon.purple)} />
        <Chip size="small" sx={chipSx(many ? neon.yellow : neon.green)}
          label={`${row.options.length} ${row.field === 'host' ? 'name' : 'address'}${
            many ? 's' : ''}`} />
        {row.partial && (
          <Tooltip title={row.note
            ?? 'A source did not answer, so this is a floor and not a total'}>
            <Chip size="small" label="partial" sx={chipSx(neon.orange)} />
          </Tooltip>
        )}
        <Box sx={{ flex: 1 }} />
        <Typography sx={{ fontSize: 10.5, color: neon.muted }}>
          target {row.target_host}
        </Typography>
      </Stack>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}
             alignItems="flex-start" sx={{ mt: 1 }}>
        <TextField select size="small" value={pick} sx={{ flex: 1, minWidth: 260 }}
          onChange={(e) => setPick(e.target.value)}
          label={row.field === 'host' ? 'Use this name' : 'Use this address'}>
          {row.options.map((o) => (
            <MenuItem key={o} value={o}>{o}</MenuItem>
          ))}
        </TextField>
        <Button variant="outlined" disabled={apply.isPending || !pick}
          onClick={() => apply.mutate()} sx={{ mt: 0.3, color: neon.green,
                                               borderColor: alpha(neon.green, 0.6) }}>
          {apply.isPending ? '…' : 'Apply'}
        </Button>
      </Stack>

      {many && (
        <Caveat>
          More than one name answers for this address, so none of them is
          <i> the</i> name. Only the one picked is recorded; the rest are not
          this target's names just because they share its address.
        </Caveat>
      )}
      {err && <Alert severity="error" variant="outlined"
                     sx={{ mt: 1, fontSize: 11.5 }}>{err}</Alert>}
    </Box>
  )
}

export function FqdnPickerDialog({ project, rows, loading, error, autoError,
                                   onClose }: {
  project: string
  /** The pending list, owned by the view so the badge and the dialog
   *  cannot disagree about how many decisions are outstanding. */
  rows: PendingLookup[] | undefined
  loading: boolean
  error: Error | null
  /** A single-answer lookup that could not be applied automatically. */
  autoError: string | null
  onClose: () => void
}) {
  const [busy, setBusy] = useState(false)
  const open = useMemo(() => openChoices(rows), [rows])
  const empty = useMemo(() => emptyResults(rows), [rows])

  return (
    <EnumerateDialog accent={neon.green} onClose={onClose}
      title={`LOOKUP RESULTS → ${project}`}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {(loading || busy) && (
            <LinearProgress sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                                  '& .MuiLinearProgress-bar': { bgcolor: neon.green } }} />
          )}
          {error && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>
              {error.message}
            </Alert>
          )}
          {autoError && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
              A lookup with a single answer could not be applied: {autoError}
            </Alert>
          )}

          <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
            Built from the output of finished Jaws lookups. A result with
            exactly one answer is applied straight away; one with several is
            a question, and one with none is recorded below as a lookup that
            ran and came back empty — not as an address with no name.
          </Alert>

          {open.map((r) => (
            <Row key={`${r.kind}:${r.subject}`} row={r} project={project}
                 onBusy={setBusy} />
          ))}

          {!loading && !open.length && !empty.length && (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              No finished lookups are waiting on a decision. Queue one from the
              Enumerate menu, or from a row's actions.
            </Typography>
          )}

          {empty.length > 0 && (
            <Box>
              <Typography sx={{ fontSize: 10.5, letterSpacing: '0.12em',
                                textTransform: 'uppercase', color: neon.muted,
                                fontFamily: `'Orbitron', sans-serif`, mb: 0.6 }}>
                Looked up, nothing came back
              </Typography>
              <Stack spacing={0.6}>
                {empty.map((r) => (
                  <Stack key={`${r.kind}:${r.subject}`} direction="row" spacing={1}
                         alignItems="center" flexWrap="wrap" useFlexGap>
                    <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                               fontSize: 12, color: neon.text }}>{r.subject}</Box>
                    <Chip size="small" label={r.kind} sx={chipSx(neon.muted)} />
                    {r.partial && (
                      <Chip size="small" label="a source did not answer"
                            sx={chipSx(neon.orange)} />
                    )}
                    {r.note && (
                      <Typography sx={{ fontSize: 11, color: neon.muted }}>
                        {r.note}
                      </Typography>
                    )}
                  </Stack>
                ))}
              </Stack>
              <Caveat>
                These stay listed because they stay true. A lookup that found
                nothing is a fact about what we tried, and clearing it would
                leave the target looking unexamined.
              </Caveat>
            </Box>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
