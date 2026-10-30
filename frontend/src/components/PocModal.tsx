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
 */
import { useEffect, useRef, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
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

  const d: PocDetail | undefined = poc.data
  const dirty = d !== undefined && draft !== null
    && draft !== (d.template ?? '')
  const runnable = (draft ?? '').trim().length > 0

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
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

      <DialogContent>
        {poc.isLoading && <CircularProgress size={18} sx={{ color: neon.cyan }} />}
        {poc.error && (
          <Alert severity="error" sx={{ fontSize: 12 }}>
            {(poc.error as Error).message}
          </Alert>
        )}

        {d && (
          <Stack spacing={1.6}>
            {/* The reason, where there is one. A state word on its
                own is a word the reader has to take on trust. */}
            {d.detail && d.state !== 'Available, Confirmed' && (
              <Alert severity="info" variant="outlined"
                sx={{ fontSize: 11.5 }}>
                {d.detail}
              </Alert>
            )}
            {d.verdict && (
              <Box sx={{ fontSize: 11.5, color: neon.muted,
                         lineHeight: 1.6 }}>
                Last run: {d.verdict}
                {d.validated_at ? ` (${d.validated_at.slice(0, 16)
                  .replace('T', ' ')})` : ''}
              </Box>
            )}

            {d.template === null ? (
              // The row exists to record that a proof was ATTEMPTED
              // and could not be written. Saying "no script" without
              // that is losing the only useful part of the record.
              <Alert severity="warning" sx={{ fontSize: 12 }}>
                No script was written for this finding.
                {d.verdict ? ` ${d.verdict}` : ''} You can write one
                below and run it.
              </Alert>
            ) : null}

            <Box>
              <Stack direction="row" spacing={1}
                sx={{ alignItems: 'center', mb: 0.6 }}>
                <Typography sx={{ fontSize: 11, color: neon.muted }}>
                  nuclei template
                </Typography>
                {dirty && (
                  <Chip size="small" label="unsaved" sx={{
                    height: 17, fontSize: 9.5, color: neon.yellow,
                    border: `1px solid ${alpha(neon.yellow, 0.5)}` }} />
                )}
                <Box sx={{ flex: 1 }} />
                {d.target_url && (
                  <Tooltip title="Where this proof is pointed.">
                    <Box sx={{ fontSize: 10.5, color: neon.muted,
                               fontFamily: `'Share Tech Mono', monospace`,
                               overflow: 'hidden', maxWidth: 280,
                               textOverflow: 'ellipsis',
                               whiteSpace: 'nowrap' }}>
                      {d.target_url}
                    </Box>
                  </Tooltip>
                )}
              </Stack>
              <TextField fullWidth multiline minRows={14} maxRows={26}
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
            </Box>

            {said && (
              <Alert severity={save.isError || run.isError ? 'error' : 'info'}
                sx={{ fontSize: 11.5 }} onClose={() => setSaid(null)}>
                {said}
              </Alert>
            )}
          </Stack>
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
      </DialogActions>
    </Dialog>
  )
}
