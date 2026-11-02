/**
 * Asking for proofs of a group of findings, and saying what that is.
 *
 * `AutoPocButton` sets a FLOOR -- "prove everything this bad or
 * worse, from now on". This is the other half: prove the findings on
 * the row in front of you. The two are deliberately different
 * controls, because raising the floor to cover one host commits the
 * engagement to every finding at that severity across the estate,
 * and lowering it afterwards does not un-send what went out.
 *
 * **The dialog is not politeness.** A proof is a model writing a
 * check and a Ghost firing it at a client's production system with
 * nobody reading it first, and a rollup row that says `412` means
 * four hundred and twelve of those from one click. The count and the
 * target are named before the click, not after.
 *
 * **What comes back is a count, not proofs.** They are written one at
 * a time against a shared model and appear over the following
 * minutes. Saying "queued" rather than "done" is the difference
 * between a button that is honest and one that looks broken when the
 * column does not change.
 */
import { useState } from 'react'
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import ScienceIcon from '@mui/icons-material/Science'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'

/** What to prove, phrased the way the clicked row names it. */
export type Group =
  | { host: string }
  | { title: string; severity: string }
  | { vuln_ids: number[] }

export function describe(g: Group): string {
  if ('host' in g) return g.host
  if ('title' in g) return `${g.title} (${g.severity})`
  return `${g.vuln_ids.length} selected finding(s)`
}

/** Every query a request can change. Listed once: a request alters
 *  the proof counts on both rollups and the state in the secrets
 *  list, and a stale column is how the button reads as a no-op. */
function invalidate(qc: ReturnType<typeof useQueryClient>, project: string) {
  for (const k of ['vulns-by-target', 'vulns-by-title', 'secrets', 'vulns']) {
    void qc.invalidateQueries({ queryKey: [k, project] })
  }
}

export function ProveGroupDialog({ project, group, total, onClose }: {
  project: string
  group: Group | null
  /** How many findings the row reports. Shown so the number in the
   *  dialog is the number in the column, rather than one the server
   *  worked out after the click. */
  total?: number
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [done, setDone] = useState<string | null>(null)

  const ask = useMutation({
    mutationFn: () => api.requestPocs(project, group as Group),
    onSuccess: (r) => { invalidate(qc, project); setDone(r.note) },
  })

  const close = () => { setDone(null); ask.reset(); onClose() }
  if (!group) return null

  return (
    <Dialog open onClose={close} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.yellow, 0.4)}`,
      } } }}>
      <DialogTitle sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
        letterSpacing: '0.12em', color: neon.yellow,
      }}>PROVE THESE → {project}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography sx={{ fontSize: 12.5, color: neon.text }}>
            {describe(group)}
            {total !== undefined && (
              <Box component="span" sx={{ color: neon.muted }}>
                {' '}— {total.toLocaleString()} finding
                {total === 1 ? '' : 's'}
              </Box>
            )}
          </Typography>

          {!done && (
            <>
              <Typography sx={{ fontSize: 11.5, color: neon.muted,
                                lineHeight: 1.7 }}>
                Writes a proof for each finding here that does not have
                one, and queues it to be run. Findings that are already
                proved, or already asked for, are left alone — asking
                twice costs nothing and queues nothing.
              </Typography>
              <Alert severity="warning" variant="outlined"
                sx={{ fontSize: 11.5 }}>
                A model writes each check and a Ghost fires it at the
                client. Nobody reads it first, and this is a whole group
                rather than one finding. The engagement has to have
                authorised that.
              </Alert>
            </>
          )}

          {done && (
            <Alert severity="success" variant="outlined"
              sx={{ fontSize: 11.5 }}>{done}</Alert>
          )}
          {ask.isError && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
              {(ask.error as Error).message || 'could not queue'}
            </Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Box sx={{ flex: 1 }} />
        <Button size="small" onClick={close}
          sx={{ textTransform: 'none', color: neon.muted }}>
          {done ? 'Close' : 'Cancel'}
        </Button>
        {!done && (
          <Button size="small" variant="outlined" disabled={ask.isPending}
            onClick={() => ask.mutate()}
            sx={{ textTransform: 'none', color: neon.yellow,
                  borderColor: alpha(neon.yellow, 0.5) }}>
            {ask.isPending ? 'Queueing…' : 'Prove them'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}

/**
 * The rollup's proof column.
 *
 * Three numbers in one cell, because three states are worth telling
 * apart and a single coverage figure collapses two of them:
 *
 *   proved / total   how much of this row is evidenced
 *   queued           asked for, not yet written. Without this, a row
 *                    clicked a minute ago looks identical to one
 *                    nobody has touched, and gets clicked again.
 *   nothing          no proof and nobody asked.
 */
export function ProofCell({ proofs, requested, total, onProve }: {
  proofs: number
  requested: number
  total: number
  /** Omitted for a read-only account: the cell still REPORTS, it
   *  just cannot ask. A column that vanishes without write access
   *  hides the evidence as well as the button. */
  onProve?: () => void
}) {
  const all = total > 0 && proofs >= total
  const colour = all ? neon.green : proofs > 0 ? neon.cyan : neon.muted
  return (
    <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
      <Tooltip title={`${proofs} of ${total} finding(s) here have a proof`}>
        <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                   fontSize: 11.5, color: colour, cursor: 'help' }}>
          {proofs.toLocaleString()}/{total.toLocaleString()}
        </Box>
      </Tooltip>
      {requested > 0 && (
        <Tooltip title={`${requested} more asked for and not written yet —
                         they are queued behind the model, not lost`}>
          <Box sx={{ fontSize: 10.5, color: neon.yellow, cursor: 'help' }}>
            +{requested.toLocaleString()}
          </Box>
        </Tooltip>
      )}
      {onProve && !all && (
        <Tooltip title="Write and run a proof for each finding here that
                        has not got one">
          <Button size="small" onClick={(e) => { e.stopPropagation(); onProve() }}
            sx={{ minWidth: 0, px: 0.6, py: 0, textTransform: 'none',
                  fontSize: 10.5, color: neon.yellow }}>
            <ScienceIcon sx={{ fontSize: 13, mr: 0.3 }} />Prove
          </Button>
        </Tooltip>
      )}
    </Stack>
  )
}
