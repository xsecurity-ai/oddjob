import { useState } from 'react'
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog,
  DialogActions, DialogContent, DialogTitle, Divider, Stack, TextField,
  Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Target } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * Fold one target into another.
 *
 * The plan is fetched and shown before anything happens, and the
 * confirm button stays off until it has been. Merging moves findings
 * between rows and then deletes one — approving the word "merge" is
 * not the same as approving a specific list of consequences, and the
 * list is the only thing that tells you whether this is the merge you
 * meant.
 */
export function MergeTargetsDialog({ project, source, candidates, onClose }: {
  project: string
  /** The target that will be absorbed and removed. */
  source: Target
  candidates: Target[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [into, setInto] = useState<Target | null>(null)

  const plan = useQuery({
    queryKey: ['merge-plan', project, source.host, into?.host],
    queryFn: () => api.mergePlan(project, source.host, into!.host),
    enabled: !!into,
  })

  const run = useMutation({
    mutationFn: () => api.mergeTargets(project, source.host, into!.host),
    onSuccess: async () => { await qc.invalidateQueries(); onClose() },
  })

  const p = plan.data
  const blocking = (p?.warnings ?? []).filter(
    (w) => w.startsWith('a target cannot') || w.startsWith('these targets are'))
  const advisory = (p?.warnings ?? []).filter((w) => !blocking.includes(w))

  const moved: Array<[number, string]> = p ? [
    [p.services_moved, 'service'], [p.vulns_moved, 'finding'],
    [p.pocs_moved, 'PoC'], [p.web_moved, 'web exchange'],
    [p.implants_moved, 'implant'], [p.events_moved, 'timeline entry'],
  ] : []

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.4) }}>
        Combine {source.host} with another target
      </DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ color: neon.muted, mb: 2 }}>
          Everything <strong>{source.host}</strong> holds moves to the target
          you pick, and {source.host} is removed. The one you pick keeps its
          name.
        </Typography>

        <Autocomplete
          options={candidates.filter((t) => t.host !== source.host)}
          getOptionLabel={(t) => t.host}
          value={into}
          onChange={(_e, v) => setInto(v)}
          renderInput={(params) => (
            <TextField {...params} size="small" label="Merge into" autoFocus
              helperText="This one survives." />
          )}
        />

        {plan.isFetching && (
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 2 }}>
            <CircularProgress size={14} />
            <Typography variant="caption" sx={{ color: neon.muted }}>
              Working out what would move…
            </Typography>
          </Stack>
        )}

        {p && (
          <Box sx={{ mt: 2 }}>
            {blocking.map((w) => (
              <Alert key={w} severity="error" sx={{ mb: 1 }}>{w}</Alert>
            ))}
            {advisory.map((w) => (
              <Alert key={w} severity="warning" sx={{ mb: 1 }}>{w}</Alert>
            ))}

            <Typography variant="overline" sx={{ color: neon.cyan }}>
              What moves
            </Typography>
            <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap
              sx={{ mt: 0.5 }}>
              {moved.filter(([n]) => n > 0).map(([n, what]) => (
                <Chip key={what} size="small"
                  label={`${n} ${what}${n === 1 ? '' : 's'}`}
                  sx={{ height: 20, fontSize: 11, color: neon.green,
                        bgcolor: alpha(neon.green, 0.12) }} />
              ))}
              {moved.every(([n]) => n === 0) && (
                <Typography variant="caption" sx={{ color: neon.muted }}>
                  Nothing — {source.host} holds no records of its own.
                </Typography>
              )}
            </Stack>

            {(p.service_conflicts.length > 0 || p.implant_conflicts.length > 0
              || p.web_duplicates > 0) && (
              <>
                <Divider sx={{ my: 1.5, borderColor: alpha(neon.cyan, 0.15) }} />
                <Typography variant="overline" sx={{ color: neon.yellow }}>
                  Seen on both
                </Typography>
                <Box sx={{ color: neon.muted, fontSize: 12, mt: 0.5 }}>
                  {p.service_conflicts.length > 0 && (
                    <div>
                      Ports {p.service_conflicts.join(', ')} are on both. The
                      two records are combined — anything only one scan saw,
                      like a version or a banner, is kept.
                    </div>
                  )}
                  {p.implant_conflicts.length > 0 && (
                    <div>Implants already present: {p.implant_conflicts.join(', ')}.</div>
                  )}
                  {p.web_duplicates > 0 && (
                    // The only thing a merge actually removes, so it
                    // is stated rather than buried.
                    <div>
                      {p.web_duplicates} web exchange(s) are byte-identical to
                      ones already held and will be dropped as duplicates.
                      This is the only thing a merge deletes.
                    </div>
                  )}
                </Box>
              </>
            )}

            {(p.fields_filled.length > 0 || p.fields_differing.length > 0) && (
              <>
                <Divider sx={{ my: 1.5, borderColor: alpha(neon.cyan, 0.15) }} />
                <Box sx={{ color: neon.muted, fontSize: 12 }}>
                  {p.fields_filled.length > 0 && (
                    <div>Fills in: {p.fields_filled.join('; ')}</div>
                  )}
                  {p.fields_differing.length > 0 && (
                    <div>
                      Differs, {into?.host} keeps its own:{' '}
                      {p.fields_differing.join('; ')} — the other value goes
                      on the timeline.
                    </div>
                  )}
                </Box>
              </>
            )}
          </Box>
        )}

        {run.error ? <Alert severity="error" sx={{ mt: 2 }}>
          {String(run.error)}</Alert> : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button
          // Off until a plan has come back: the whole point is that
          // what is approved is the list, not the verb.
          disabled={!p || blocking.length > 0 || run.isPending || plan.isFetching}
          onClick={() => run.mutate()}
          sx={{ color: neon.red }}>
          {run.isPending ? 'Merging…' : `Merge into ${into?.host ?? '…'}`}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
