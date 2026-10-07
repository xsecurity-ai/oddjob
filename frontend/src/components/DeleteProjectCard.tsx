import { useState } from 'react'
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Paper, Stack, TextField, Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

/**
 * Deleting an engagement.
 *
 * Shown only to someone who can actually do it, and it asks for the
 * code to be typed. The typing is not ceremony: an engagement is
 * months of work behind one button, and the counts below are what
 * make a person stop — "4,319 targets and 17,736 findings" lands
 * where "this cannot be undone" does not.
 *
 * The server independently requires the code, so this dialog is the
 * courtesy and not the control.
 */
export function DeleteProjectCard({ project }: { project: string }) {
  const { roleOn } = useAuth()
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState('')

  const preview = useQuery({
    queryKey: ['deletion-preview', project],
    queryFn: () => api.deletionPreview(project),
    enabled: open,
  })

  const del = useMutation({
    mutationFn: () => api.deleteProject(project),
    onSuccess: () => {
      // Everything in memory refers to a project that no longer
      // exists, so the cheapest correct thing is to start over at the
      // list rather than invalidate a hundred queries.
      window.location.href = '/projects'
    },
  })

  // Project admins and site admins — a site admin resolves to `admin`
  // on every project, so one check covers both. The server decides
  // for real; this only avoids showing a control that would be
  // refused, and it is placed after the hooks so the hook order does
  // not change with the answer.
  if (roleOn(project) !== 'admin') return null

  const p = preview.data
  const matches = typed.trim() === project

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2.5,
                                    borderColor: alpha(neon.red, 0.4) }}>
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                        letterSpacing: '0.14em', textTransform: 'uppercase',
                        color: neon.red, textShadow: glow(neon.red, 0.5),
                        mb: 1 }}>
        Delete this engagement
      </Typography>
      <Typography variant="body2" sx={{ color: neon.muted, mb: 1.5 }}>
        Removes {project} and every target, service, finding, credential,
        proof-of-concept and agent in it. There is no undo and no copy.
      </Typography>
      <Button size="small" variant="outlined"
        onClick={() => { setTyped(''); setOpen(true) }}
        sx={{ color: neon.red, borderColor: alpha(neon.red, 0.5) }}>
        Delete {project}…
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: neon.red }}>Delete {project}?</DialogTitle>
        <DialogContent>
          {preview.isFetching && (
            <Typography variant="caption" sx={{ color: neon.muted }}>
              Counting what would go…
            </Typography>
          )}
          {p && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ color: neon.text, mb: 1 }}>
                This permanently destroys:
              </Typography>
              <Stack spacing={0.3} sx={{ fontSize: 13, color: neon.text }}>
                {([
                  [p.targets, 'target'], [p.services, 'service'],
                  [p.vulns, 'finding'], [p.pocs, 'proof-of-concept'],
                  [p.credentials, 'credential'], [p.agents, 'Drone agent'],
                ] as Array<[number, string]>)
                  .filter(([n]) => n > 0)
                  .map(([n, what]) => (
                    <Box key={what}>
                      <Box component="span" sx={{ color: neon.red,
                                                  fontWeight: 600 }}>
                        {n.toLocaleString()}
                      </Box>{' '}{what}{n === 1 ? '' : 's'}
                    </Box>
                  ))}
                {p.targets === 0 && p.vulns === 0 && p.agents === 0 && (
                  <Box sx={{ color: neon.muted }}>
                    Nothing — this engagement is empty.
                  </Box>
                )}
              </Stack>
              {p.agent_warning && (
                <Alert severity="warning" sx={{ mt: 1.5, fontSize: 12 }}>
                  {p.agent_warning}
                </Alert>
              )}
            </Box>
          )}

          <TextField size="small" fullWidth value={typed} autoFocus
            label={`Type ${project} to confirm`}
            onChange={(e) => setTyped(e.target.value)}
            helperText="Exact match, including case." />

          {del.error ? <Alert severity="error" sx={{ mt: 1.5 }}>
            {String(del.error)}</Alert> : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} sx={{ color: neon.muted }}>
            Cancel
          </Button>
          <Button disabled={!matches || del.isPending || preview.isFetching}
            onClick={() => del.mutate()} sx={{ color: neon.red }}>
            {del.isPending ? 'Deleting…' : `Delete ${project} permanently`}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  )
}
