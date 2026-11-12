/**
 * One proof: the script, an editor, and a Run button.
 *
 * The script is a **nuclei template**, not a shell script, and that
 * is not an arbitrary choice — the agent image has no interpreter, so
 * a script is a proof that cannot run on a Ghost. It is also
 * declarative, which matters when a model wrote the first draft: YAML
 * with matchers cannot open a socket of its own choosing.
 *
 * Editing and running are deliberately separate, and Run saves first
 * when there are unsaved changes. Running the version on the server
 * while the operator is looking at a different one on screen is the
 * kind of wrong that is very hard to notice.
 *
 * Layout: two panes. The template editor on the left, the run output
 * (verdict, exit code, timestamp) on the right. This is the "Reveal
 * Proof" modal — the operator reads what the last run said while the
 * script is still editable beside it, and can resend with one click.
 */
import { useEffect, useRef, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
import TerminalIcon from '@mui/icons-material/Terminal'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type PocDetail } from '../lib/api'
import { neon, glow } from '../theme'

/** Colour per state. The middle one is deliberately not red: a proof
 *  that needs a credential nobody has is real work, not a failure. */
const STATE_COLOUR: Record<string, string> = {
  'Available, Confirmed': neon.green,
  'Available, Not Confirmed': neon.yellow,
  'Not Available': neon.muted,
}

/** How often an unvalidated proof re-reads itself while a run is out.
 *  The verdict arrives when a Ghost has run it, which is not a
 *  request this page can wait on. */
const POLL_MS = 3000

export function PocModal({ project, pocId, title, onClose }: {
  project: string
  pocId: number
  /** The finding's title, for the header before the proof loads. */
  title?: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<string | null>(null)
  const [said, setSaid] = useState<string | null>(null)
  const [ran, setRan] = useState(false)
  const loaded = useRef<number | null>(null)

  const poc = useQuery({
    queryKey: ['poc', project, pocId],
    queryFn: () => api.poc(project, pocId),
    // Only while a run is outstanding. A confirmed proof cannot
    // change on its own, so polling one asks a question with a
    // known answer.
    refetchInterval: ran ? POLL_MS : false,
  })

  // The server's copy becomes the draft once, not on every refetch:
  // a poll landing mid-edit must not overwrite what is being typed.
  useEffect(() => {
    if (!poc.data || loaded.current === poc.data.id) return
    loaded.current = poc.data.id
    setDraft(poc.data.template ?? '')
  }, [poc.data])

  const save = useMutation({
    mutationFn: (template: string) =>
      api.savePoc(project, pocId, { template }),
    onSuccess: (d) => {
      setSaid(null)
      loaded.current = null       // adopt what the server stored
      void qc.invalidateQueries({ queryKey: ['poc', project, pocId] })
      // The findings table carries the state, and saving a changed
      // script un-confirms it.
      void qc.invalidateQueries({ queryKey: ['vulns'] })
      setDraft(d.template ?? '')
      loaded.current = d.id
    },
    onError: (e) => setSaid((e as Error).message),
  })

  const run = useMutation({
    mutationFn: async () => {
      // Save first if the screen and the server disagree. Running
      // the stored version while a different one is on screen is
      // the kind of wrong that is very hard to notice.
      if (dirty && draft !== null) await api.savePoc(project, pocId,
                                                      { template: draft })
      return api.runPoc(project, pocId)
    },
    onSuccess: (r) => {
      setSaid(r.note)
      setRan(true)
      void qc.invalidateQueries({ queryKey: ['poc', project, pocId] })
    },
    onError: (e) => setSaid((e as Error).message),
  })

  const [confirmOpen, setConfirmOpen] = useState(false)
  const [confirmText, setConfirmText] = useState('')
  const confirm = useMutation({
    mutationFn: () => api.confirmPoc(project, pocId, confirmText),
    onSuccess: () => {
      setConfirmOpen(false)
      setConfirmText('')
      setSaid('Proof confirmed.')
      void qc.invalidateQueries({ queryKey: ['poc', project, pocId] })
      void qc.invalidateQueries({ queryKey: ['vulns'] })
    },
    onError: (e) => setSaid((e as Error).message),
  })

  const d: PocDetail | undefined = poc.data
  const dirty = d !== undefined && draft !== null
    && draft !== (d.template ?? '')
  const runnable = (draft ?? '').trim().length > 0

  return (
    <Dialog open onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle sx={{ color: neon.cyan, pb: 1 }}>
        <Stack direction="row" spacing={1.2} sx={{ alignItems: 'center' }}>
          <Box sx={{ flex: 1, minWidth: 0, overflow: 'hidden',
                     textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {d?.title ?? title ?? 'Proof of concept'}
          </Box>
          {d && (
            <Chip size="small" label={d.state} sx={{
              height: 20, fontSize: 10.5,
              color: STATE_COLOUR[d.state] ?? neon.muted,
              border: `1px solid ${alpha(STATE_COLOUR[d.state]
                                         ?? neon.muted, 0.5)}`,
              textShadow: d.state === 'Available, Confirmed'
                ? glow(neon.green, 0.5) : undefined }} />
          )}
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ p: 0 }}>
        {poc.isLoading && (
          <Box sx={{ p: 3 }}>
            <CircularProgress size={18} sx={{ color: neon.cyan }} />
          </Box>
        )}
        {poc.error && (
          <Alert severity="error" sx={{ m: 2, fontSize: 12 }}>
            {(poc.error as Error).message}
          </Alert>
        )}

        {d && (
          <Stack direction="row" sx={{ minHeight: 420 }}>
            {/* ── Left pane: the template editor ── */}
            <Box sx={{
              flex: 1, minWidth: 0, borderRight: `1px solid ${alpha(neon.muted, 0.2)}`,
              p: 2, display: 'flex', flexDirection: 'column', gap: 1,
            }}>
              <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                <Typography variant="caption" sx={{ color: neon.muted, fontSize: 10.5, letterSpacing: '0.08em' }}>
                  NUCLEI TEMPLATE
                </Typography>
                {dirty && (
                  <Chip size="small" label="unsaved" sx={{
                    height: 16, fontSize: 9, color: neon.yellow,
                    border: `1px solid ${alpha(neon.yellow, 0.5)}` }} />
                )}
              </Stack>

              {d.template === null && (
                <Alert severity="warning" variant="outlined" sx={{ fontSize: 11 }}>
                  No script was written for this finding.
                  {d.verdict ? ` ${d.verdict}` : ''} You can write one below and run it.
                </Alert>
              )}

              <TextField fullWidth multiline minRows={18} maxRows={30}
                value={draft ?? ''}
                onChange={(e) => { setDraft(e.target.value); setSaid(null) }}
                onKeyDown={(e) => {
                  // Ctrl/Cmd+S saves, because this is an editor and
                  // that is what an editor does.
                  if ((e.metaKey || e.ctrlKey) && e.key === 's') {
                    e.preventDefault()
                    if (dirty && draft !== null) save.mutate(draft)
                  }
                }}
                slotProps={{ htmlInput: {
                  spellCheck: false,
                  style: { fontFamily: `'Share Tech Mono', monospace`,
                           fontSize: 12, lineHeight: 1.5 } } }} />

              {d.target_url && (
                <Tooltip title="Where this proof is pointed.">
                  <Box sx={{ fontSize: 10.5, color: neon.muted,
                             fontFamily: `'Share Tech Mono', monospace`,
                             overflow: 'hidden', textOverflow: 'ellipsis',
                             whiteSpace: 'nowrap' }}>
                    → {d.target_url}
                  </Box>
                </Tooltip>
              )}
            </Box>

            {/* ── Right pane: run output ── */}
            <Box sx={{
              width: 340, minWidth: 280, p: 2, display: 'flex',
              flexDirection: 'column', gap: 1.5, bgcolor: alpha(neon.muted, 0.04),
            }}>
              <Typography variant="caption" sx={{ color: neon.muted, fontSize: 10.5, letterSpacing: '0.08em' }}>
                RUN OUTPUT
              </Typography>

              {/* Verdict */}
              {d.verdict ? (
                <Box sx={{
                  p: 1.2, borderRadius: 1,
                  bgcolor: d.state === 'Available, Confirmed'
                    ? alpha(neon.green, 0.08) : alpha(neon.yellow, 0.06),
                  border: `1px solid ${alpha(
                    d.state === 'Available, Confirmed' ? neon.green : neon.yellow, 0.3)}`,
                }}>
                  <Stack direction="row" spacing={0.75} sx={{ alignItems: 'flex-start' }}>
                    <TerminalIcon sx={{ fontSize: 14, mt: '1px',
                      color: d.state === 'Available, Confirmed' ? neon.green : neon.yellow }} />
                    <Box>
                      <Typography sx={{ fontSize: 12, color: neon.text, lineHeight: 1.5 }}>
                        {d.verdict}
                      </Typography>
                      {d.validated_at && (
                        <Typography sx={{ fontSize: 10, color: neon.muted, mt: 0.3 }}>
                          {d.validated_at.slice(0, 16).replace('T', ' ')} UTC
                        </Typography>
                      )}
                    </Box>
                  </Stack>
                </Box>
              ) : (
                <Box sx={{ p: 1.2, borderRadius: 1,
                           border: `1px dashed ${alpha(neon.muted, 0.3)}`,
                           textAlign: 'center' }}>
                  <Typography sx={{ fontSize: 11, color: neon.muted }}>
                    {ran ? 'Waiting for a Ghost to run this…' : 'Not yet run.'}
                  </Typography>
                </Box>
              )}

              {/* Exit code */}
              {d.exit_code !== null && d.exit_code !== undefined && (
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Typography sx={{ fontSize: 10.5, color: neon.muted }}>exit</Typography>
                  <Chip size="small" label={String(d.exit_code)} sx={{
                    height: 18, fontSize: 10, fontFamily: `'Share Tech Mono', monospace`,
                    bgcolor: d.exit_code === 0 ? alpha(neon.green, 0.12) : alpha(neon.red, 0.1),
                    color: d.exit_code === 0 ? neon.green : neon.red,
                    border: `1px solid ${alpha(d.exit_code === 0 ? neon.green : neon.red, 0.4)}`,
                  }} />
                </Stack>
              )}

              {/* Detail (why not confirmed) */}
              {d.detail && d.state !== 'Available, Confirmed' && (
                <Alert severity="info" variant="outlined" sx={{ fontSize: 11 }}>
                  {d.detail}
                </Alert>
              )}

              {/* Updated timestamp */}
              {d.updated_at && (
                <Typography sx={{ fontSize: 10, color: alpha(neon.muted, 0.6), mt: 'auto' }}>
                  last updated {d.updated_at.slice(0, 16).replace('T', ' ')} UTC
                </Typography>
              )}
            </Box>
          </Stack>
        )}

        {said && (
          <Alert severity={save.isError || run.isError ? 'error' : 'info'}
            sx={{ mx: 2, mb: 1, fontSize: 11.5 }} onClose={() => setSaid(null)}>
            {said}
          </Alert>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Typography sx={{ flex: 1, fontSize: 10.5, color: neon.muted,
                          lineHeight: 1.5 }}>
          Runs on a Ghost, never from this server — the agent image has
          nuclei and this host does not, and traffic from here comes
          from the wrong address.
        </Typography>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button disabled={!dirty || save.isPending || draft === null}
          onClick={() => draft !== null && save.mutate(draft)}
          sx={{ color: neon.cyan }}>
          {save.isPending ? 'Saving…' : 'Save'}
        </Button>
        <Button variant="outlined" startIcon={<PlayArrowIcon />}
          disabled={!runnable || run.isPending}
          onClick={() => run.mutate()}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
          {run.isPending ? 'Queueing…' : dirty ? 'Save and run' : 'Run'}
        </Button>
        <Button variant="outlined"
          disabled={!d || d.state === 'Available, Confirmed' || confirm.isPending}
          onClick={() => setConfirmOpen(true)}
          sx={{ color: neon.yellow, borderColor: alpha(neon.yellow, 0.5) }}>
          Confirm manually
        </Button>
      </DialogActions>

      <Dialog open={confirmOpen} onClose={() => !confirm.isPending && setConfirmOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: neon.yellow, pb: 1 }}>
          Confirm proof by hand
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ fontSize: 12, color: neon.muted, mb: 1.5, lineHeight: 1.6 }}>
            You have run this script outside the platform — in a browser,
            against staging, with curl — and it reproduced. Record what you
            saw; it becomes the proof's verdict.
          </Typography>
          <TextField autoFocus fullWidth multiline minRows={3} maxRows={8}
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder="e.g. Reproduced in browser: /admin panel accessible without auth"
            slotProps={{ htmlInput: { spellCheck: false } }} />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setConfirmOpen(false)} disabled={confirm.isPending}
            sx={{ color: neon.muted }}>Cancel</Button>
          <Button variant="contained" disabled={!confirmText.trim() || confirm.isPending}
            onClick={() => confirm.mutate()}
            sx={{ bgcolor: alpha(neon.yellow, 0.9), color: '#111' }}>
            {confirm.isPending ? 'Saving…' : 'Confirm'}
          </Button>
        </DialogActions>
      </Dialog>
    </Dialog>
  )
}
