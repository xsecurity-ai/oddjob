/**
 * Turning proofs on for an engagement, and saying what that costs.
 *
 * `auto_poc` is a standing order and its value is a FLOOR: "medium"
 * means medium, high and critical. One control carries both "is this
 * on" and "how far down", so the two cannot drift apart the way a
 * checkbox beside a threshold would.
 *
 * The dialog exists rather than a dropdown in a toolbar because of
 * what switching this on does. Every other standing order turns a
 * scanner up and sends that scanner's own traffic; this one has a
 * model write a check for a specific finding and then fires it, at a
 * client's production system, without anybody reading it first. That
 * is worth a sentence and a deliberate click.
 */
import { useState } from 'react'
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  MenuItem, Stack, TextField, Typography, alpha,
} from '@mui/material'
import ScienceIcon from '@mui/icons-material/Science'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'

/** Worst first, and the label says "and worse" rather than naming
 *  the set: the set changes with the floor, so a label listing it is
 *  the one thing on screen that goes stale. */
const FLOORS = [
  { value: 'off', label: 'Off' },
  { value: 'critical', label: 'Critical only' },
  { value: 'high', label: 'High and worse' },
  { value: 'medium', label: 'Medium and worse' },
  { value: 'low', label: 'Low and worse' },
  { value: 'info', label: 'Everything, including info' },
]

export function AutoPocButton({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [floor, setFloor] = useState<string | null>(null)

  const pr = useQuery({
    queryKey: ['project', project],
    queryFn: () => api.project(project as string),
    enabled: !!project && open,
  })
  const current = String(pr.data?.auto_poc ?? 'off')
  const chosen = floor ?? current

  const save = useMutation({
    mutationFn: (v: string) =>
      api.updateProject(project as string, { auto_poc: v }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project', project] })
      void qc.invalidateQueries({ queryKey: ['standing-orders', project] })
      setOpen(false)
      setFloor(null)
    },
  })

  if (!project) return null

  return (
    <>
      <Button size="small" startIcon={<ScienceIcon fontSize="small" />}
        onClick={() => setOpen(true)}
        sx={{ textTransform: 'none', fontSize: 12.5,
              color: current === 'off' ? neon.muted : neon.yellow }}>
        {current === 'off' ? 'Auto PoC' : `Auto PoC: ${current} and worse`}
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.yellow, 0.4)}`,
        } } }}>
        <DialogTitle sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
          letterSpacing: '0.12em', color: neon.yellow,
        }}>PROVE FINDINGS → {project}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField select size="small" label="Lowest severity to prove"
              value={chosen} onChange={(e) => setFloor(e.target.value)}
              helperText="A floor, not a filter: Medium covers medium, high
                          and critical.">
              {FLOORS.map((f) => (
                <MenuItem key={f.value} value={f.value}
                  sx={{ fontSize: 12.5 }}>{f.label}</MenuItem>
              ))}
            </TextField>

            <Typography sx={{ fontSize: 11.5, color: neon.muted,
                              lineHeight: 1.7 }}>
              Writes a proof for every finding at or above that severity,
              runs it, and records whether it reproduced — the backlog as
              well as new findings, because a floor you set today is a
              statement about the engagement rather than about this minute.
              The proof is re-runnable, so the same artefact answers
              “is this real” now and “has it been fixed” later.
            </Typography>

            {/* Said before the click, not after. */}
            {chosen !== 'off' && (
              <Alert severity="warning" variant="outlined"
                sx={{ fontSize: 11.5 }}>
                Unlike every other standing order, this one does not send a
                scanner's own traffic. A model writes a check for each
                finding and a Ghost fires it at the client — so what reaches
                them is composed for the occasion and nobody reads it first.
                The engagement has to have authorised that.
              </Alert>
            )}
            <Typography sx={{ fontSize: 11, color: alpha(neon.muted, 0.85) }}>
              Needs a model configured to write the proofs and a Ghost online
              to run them. Without either, nothing is queued and the Ghosts
              page says so rather than leaving proofs that never validate.
            </Typography>
            {save.isError && (
              <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
                {(save.error as Error).message || 'could not save'}
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Box sx={{ flex: 1 }} />
          <Button size="small" onClick={() => { setOpen(false); setFloor(null) }}
            sx={{ textTransform: 'none', color: neon.muted }}>Cancel</Button>
          <Button size="small" variant="outlined" disabled={save.isPending}
            onClick={() => save.mutate(chosen)}
            sx={{ textTransform: 'none', color: neon.yellow,
                  borderColor: alpha(neon.yellow, 0.5) }}>
            {chosen === 'off' ? 'Turn off' : 'Turn on'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}
