import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, IconButton, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, Tooltip, Typography, alpha,
} from '@mui/material'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * What is waiting to run, and the way to take something back out.
 *
 * The queue is held server-side until an agent reports ready, so work
 * genuinely sits here rather than vanishing into a claim the moment it
 * is submitted. That makes the depth worth looking at — and the moment
 * it is worth looking at, it is worth being able to act on, because
 * the usual reason to open it is that one submission should not have
 * been made.
 *
 * Only queued work can be removed. A task an agent has already taken
 * is running on somebody's network; deleting the row would not stop it
 * and would lose the result when it reports. The server refuses that
 * and says so, and this does not offer it.
 */
export function JawsQueueDialog({ project, onClose }: {
  project: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [err, setErr] = useState<string | null>(null)

  const q = useQuery({
    queryKey: ['jaws-queue', project],
    queryFn: () => api.jawsQueue(project),
    // The queue drains by itself as agents pick work up, so a stale
    // list would offer a Delete for something already running.
    refetchInterval: 4000,
  })

  const cancel = useMutation({
    mutationFn: (id: number) => api.cancelJawsTask(project, id),
    onSuccess: async () => {
      setErr(null)
      await qc.invalidateQueries({ queryKey: ['jaws-queue', project] })
      await qc.invalidateQueries({ queryKey: ['jaws-routing', project] })
      await qc.invalidateQueries({ queryKey: ['agents', project] })
    },
    // Reported rather than swallowed: the common failure is that an
    // agent took the task while the dialog was open, and that is worth
    // reading rather than seeing a row refuse to disappear.
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
  })

  const rows = q.data ?? []

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.yellow, 0.4)}`,
      } } }}>
      <DialogTitle sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 12.5,
        letterSpacing: '0.16em', textTransform: 'uppercase',
        color: neon.yellow, textShadow: glow(neon.yellow, 0.4),
      }}>
        Queue · {project}
      </DialogTitle>

      <DialogContent>
        {err && (
          <Alert severity="error" variant="outlined" sx={{ mb: 1.5, fontSize: 12.5 }}
                 onClose={() => setErr(null)}>
            {err}
          </Alert>
        )}

        <Typography sx={{ fontSize: 11.5, color: neon.muted, mb: 1.5 }}>
          Oddjob holds these until an agent reports it is ready for the next
          one, so nothing is handed to a scanner that is still working.
          Oldest first — that is the order they will run in.
        </Typography>

        {!rows.length ? (
          <Typography sx={{ fontSize: 12.5, color: neon.muted,
                            fontStyle: 'italic', py: 2 }}>
            Nothing waiting. Work an agent has already taken is on its row in
            the table behind this.
          </Typography>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                {['', 'Task', 'On', 'For', 'Asked by', ''].map((h, i) => (
                  <TableCell key={i} sx={{ color: neon.muted, fontSize: 10.5,
                                           letterSpacing: '0.1em',
                                           textTransform: 'uppercase' }}>
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((t, i) => (
                <TableRow key={t.id} hover>
                  <TableCell sx={{ color: neon.muted, fontSize: 11, width: 34 }}>
                    {i + 1}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={t.kind} sx={{
                      height: 19, fontSize: 10.5, color: neon.cyan,
                      bgcolor: alpha(neon.cyan, 0.13) }} />
                  </TableCell>
                  <TableCell sx={{ fontFamily: `'Share Tech Mono', monospace`,
                                   fontSize: 12, color: neon.text,
                                   maxWidth: 300, overflow: 'hidden',
                                   textOverflow: 'ellipsis' }}>
                    <Tooltip title={t.subject}><span>{t.subject}</span></Tooltip>
                  </TableCell>
                  <TableCell sx={{ fontSize: 11.5 }}>
                    {t.agent_name
                      ? <Box sx={{ color: neon.pink }}>{t.agent_name}</Box>
                      : <Tooltip title="Belongs to no agent yet. The routing mode decides who takes it.">
                          <Box sx={{ color: neon.muted }}>pool</Box>
                        </Tooltip>}
                    {t.region && (
                      <Chip size="small" label={t.region} sx={{
                        height: 16, fontSize: 9, ml: 0.6,
                        bgcolor: alpha(neon.purple, 0.15), color: neon.purple }} />
                    )}
                  </TableCell>
                  <TableCell sx={{ fontSize: 11.5, color: neon.muted }}>
                    {t.requested_by ?? '—'}
                  </TableCell>
                  <TableCell align="right" sx={{ width: 48 }}>
                    <Tooltip title={`Take #${t.id} out of the queue. It has not started.`}>
                      <span>
                        <IconButton size="small" disabled={cancel.isPending}
                          onClick={() => cancel.mutate(t.id)}
                          sx={{ color: neon.muted,
                                '&:hover': { color: neon.red } }}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </DialogContent>
      <DialogActions>
        <Stack direction="row" spacing={1} alignItems="center"
               sx={{ mr: 'auto', pl: 2 }}>
          <Typography sx={{ fontSize: 11, color: neon.muted }}>
            {rows.length} waiting
          </Typography>
        </Stack>
        <Button onClick={onClose} sx={{ color: neon.cyan }}>Close</Button>
      </DialogActions>
    </Dialog>
  )
}
