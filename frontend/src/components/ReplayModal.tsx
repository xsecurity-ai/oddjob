/** Edit a captured request and send it again.
 *
 * The answer is stored as a NEW row rather than replacing the original.
 * That is the whole point: the original and the edited one sit side by
 * side under the same URL, and the difference between the two
 * responses is usually the finding.
 *
 * **The packet leaves from a ghost, not from the Oddjob server.** That
 * is what makes this dialog a two-step: Send queues a task against a
 * named agent inside the client's estate, and the response appears
 * when that agent reports. Usually seconds — the task jumps the
 * queue — but it is a wait, and the dialog says which ghost has it and
 * why it is waiting rather than spinning silently.
 */
import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, IconButton, Stack, Switch,
  TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import SendIcon from '@mui/icons-material/Send'
import RestartAltIcon from '@mui/icons-material/RestartAlt'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ReplayResult } from '../lib/api'
import { neon, glow } from '../theme'

const mono = { fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5 }

export function ReplayModal({ id, onClose, onCreated }: {
  id: number | null
  onClose: () => void
  /** The new row's id, so the caller can reveal it. */
  onCreated?: (newId: number) => void
}) {
  const qc = useQueryClient()
  const [raw, setRaw] = useState('')
  const [sending, setSending] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [queued, setQueued] = useState<ReplayResult | null>(null)
  const [verify, setVerify] = useState(false)

  const packet = useQuery({
    queryKey: ['packet', id],
    queryFn: () => api.packet(id as number),
    enabled: id != null,
  })

  // The ghost's progress. Polled rather than awaited: the request is
  // sent by an agent on its next heartbeat, and holding an HTTP
  // request open for that is a wait of unbounded length on a
  // connection nothing guarantees survives it.
  const task = useQuery({
    queryKey: ['replay', queued?.task_id],
    queryFn: () => api.replayStatus(queued!.task_id),
    enabled: queued != null,
    // Stop asking once it has finished. `false` is react-query's "do
    // not poll", so this has to be a function rather than a number.
    refetchInterval: (q) => {
      const s = q.state.data?.state
      return s === 'done' || s === 'failed' || s === 'cancelled' ? false : 1500
    },
  })

  // The live answer, whichever half we have. `queued` carries which
  // ghost took it from the moment Send is pressed; `task.data`
  // replaces it as soon as the first poll lands.
  const result: ReplayResult | null = task.data ?? queued

  // Seed the editor from the captured request. Only when it arrives, so
  // typing is never overwritten by a late fetch.
  useEffect(() => {
    if (packet.data) {
      setRaw(packet.data.request || defaultRequest(packet.data.url,
                                                   packet.data.method))
      setQueued(null); setErr(null)
    }
  }, [packet.data])

  // The new row only exists once the ghost has reported, so the
  // caller is told then rather than when Send was pressed.
  const newId = result?.web?.id
  useEffect(() => {
    if (newId != null) {
      onCreated?.(newId)
      void qc.invalidateQueries({ queryKey: ['web'] })
    }
    // `onCreated` is not in the deps on purpose: callers pass an
    // inline arrow, so a new identity every render would re-fire this
    // on every render rather than on every new row.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newId, qc])

  const send = async () => {
    if (id == null) return
    setSending(true); setErr(null); setQueued(null)
    try {
      setQueued(await api.replay(id, raw, { verify_tls: verify }))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setSending(false)
    }
  }

  const waiting = result != null
    && !['done', 'failed', 'cancelled'].includes(result.state)
  const busy = sending || waiting
  const original = packet.data?.request || ''
  const edited = raw !== original

  return (
    <Dialog open={id != null} onClose={busy ? undefined : onClose}
      maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.orange, 0.5)}`,
      } } }}>
      <DialogTitle sx={{ pr: 6 }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 13, fontWeight: 700,
          letterSpacing: '0.12em', color: neon.orange,
          textShadow: glow(neon.orange, 0.4),
        }}>
          REPLAY REQUEST
        </Typography>
        <Typography sx={{ ...mono, color: neon.muted, mt: 0.5,
                          wordBreak: 'break-all' }}>
          {packet.data?.url ?? '…'}
        </Typography>
        <IconButton onClick={onClose} size="small" disabled={busy}
          sx={{ position: 'absolute', top: 10, right: 10, color: neon.muted }}>
          <CloseIcon sx={{ fontSize: 18 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent dividers sx={{ borderColor: alpha(neon.purple, 0.3) }}>
        {packet.isLoading && (
          <Box sx={{ display: 'grid', placeItems: 'center', py: 5 }}>
            <CircularProgress size={22} sx={{ color: neon.orange }} />
          </Box>
        )}

        {packet.data && (
          <Stack spacing={1.5}>
            {packet.data.truncated && (
              <Alert severity="warning" variant="outlined"
                sx={{ fontSize: 11.5, borderColor: alpha(neon.yellow, 0.5),
                      color: neon.text }}>
                This capture was cut at the import cap, so the request below is
                not the whole original. Sending it sends exactly what you see.
              </Alert>
            )}

            <Stack direction="row" spacing={1} sx={{
              alignItems: "center"
            }}>
              <Typography sx={{ fontSize: 10.5, letterSpacing: '0.14em',
                                color: neon.cyan }}>
                REQUEST
              </Typography>
              {edited && (
                <Chip size="small" label="edited" sx={{
                  height: 18, fontSize: 10, bgcolor: alpha(neon.orange, 0.16),
                  color: neon.orange,
                  border: `1px solid ${alpha(neon.orange, 0.5)}` }} />
              )}
              <Box sx={{ flex: 1 }} />
              <Tooltip title="Back to the captured request">
                <span>
                  <IconButton size="small" disabled={!edited || busy}
                    onClick={() => setRaw(original)}
                    sx={{ color: neon.muted }}>
                    <RestartAltIcon sx={{ fontSize: 17 }} />
                  </IconButton>
                </span>
              </Tooltip>
            </Stack>

            <TextField
              multiline minRows={10} maxRows={20} fullWidth value={raw}
              onChange={(e) => setRaw(e.target.value)} disabled={busy}
              slotProps={{ htmlInput: { style: { ...mono, lineHeight: 1.5 },
                                        spellCheck: false } }} />

            <Stack
              direction="row"
              spacing={2}
              sx={{
                alignItems: "center",
                flexWrap: "wrap"
              }}>
              <Tooltip title="An engagement target routinely has a certificate that
                              does not validate; refusing to talk to it is not a
                              useful default for a test tool.">
                <FormControlLabel
                  control={<Switch size="small" checked={verify}
                    onChange={(e) => setVerify(e.target.checked)} />}
                  label={<Typography sx={{ fontSize: 11.5 }}>Verify TLS</Typography>} />
              </Tooltip>
              <Box sx={{ flex: 1 }} />
              {/* Said before Send is pressed, not only after. Where the
                  packet will come FROM is part of the test: a request
                  leaving the wrong egress address can be dropped at the
                  border or, worse, accepted and attributed elsewhere. */}
              <Typography sx={{ fontSize: 10.5, color: neon.muted }}>
                sent from a ghost inside the estate
              </Typography>
            </Stack>

            {err && (
              <Alert severity="error" variant="outlined"
                sx={{ fontSize: 11.5, borderColor: alpha(neon.red, 0.6),
                      color: neon.text }}>
                {err}
              </Alert>
            )}

            {result && (
              <Box>
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{
                    alignItems: "center",
                    mb: 0.75
                  }}>
                  <Typography sx={{ fontSize: 10.5, letterSpacing: '0.14em',
                                    color: neon.cyan }}>
                    RESPONSE
                  </Typography>
                  {result.status_code != null && (
                    <Chip size="small" label={result.status_code} sx={{
                      height: 18, fontSize: 10,
                      bgcolor: alpha(neon.green, 0.15), color: neon.green,
                      border: `1px solid ${alpha(neon.green, 0.5)}` }} />
                  )}
                  {result.elapsed_ms > 0 && (
                    <Typography sx={{ fontSize: 11, color: neon.muted }}>
                      {result.elapsed_ms} ms
                    </Typography>
                  )}
                  <Chip size="small" label={result.agent} sx={{
                    height: 18, fontSize: 10,
                    bgcolor: alpha(neon.purple, 0.16), color: neon.purple,
                    border: `1px solid ${alpha(neon.purple, 0.5)}` }} />
                  <Box sx={{ flex: 1 }} />
                  <Typography sx={{ fontSize: 10.5, color: neon.muted }}>
                    {result.web
                      ? 'saved as a new entry under this URL'
                      : result.note}
                  </Typography>
                </Stack>
                {waiting && (
                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{ alignItems: 'center', mb: 1 }}>
                    <CircularProgress size={13} thickness={6}
                      sx={{ color: neon.orange }} />
                    {/* "Waiting for a ghost" and "sent, waiting for the
                        answer" are different facts, and the note from
                        the server is the one that knows which. */}
                    <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                      {result.note}
                    </Typography>
                  </Stack>
                )}
                {result.error && (
                  <Alert severity="warning" variant="outlined"
                    sx={{ fontSize: 11.5, mb: 1,
                          borderColor: alpha(neon.yellow, 0.5), color: neon.text }}>
                    {/* A failed connection is a result worth keeping:
                        "this host now refuses" is itself a finding. */}
                    {result.error}
                  </Alert>
                )}
                <ResponseBody id={result.web?.id} />
              </Box>
            )}
          </Stack>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={busy} sx={{ color: neon.muted }}>
          Close
        </Button>
        <Button variant="outlined" onClick={send} disabled={busy || !raw.trim()}
          startIcon={busy
            ? <CircularProgress size={13} thickness={6} sx={{ color: neon.orange }} />
            : <SendIcon sx={{ fontSize: 16 }} />}
          sx={{ color: neon.orange, borderColor: alpha(neon.orange, 0.6) }}>
          {busy ? 'Sending…' : 'Send'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** The new row's response, fetched once it exists. */
function ResponseBody({ id }: { id: number | undefined }) {
  const q = useQuery({
    queryKey: ['packet', id],
    queryFn: () => api.packet(id as number),
    enabled: id != null,
  })
  if (!q.data) return null
  return (
    <Box component="pre" sx={{
      ...mono, color: neon.text, m: 0, p: 1.25, maxHeight: 300,
      overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      border: `1px solid ${alpha(neon.purple, 0.3)}`, borderRadius: 1,
      backgroundColor: alpha(neon.bgDeep, 0.5),
    }}>
      {q.data.response || '(no response body was captured)'}
    </Box>
  )
}

/** A request to start from when the original was never captured —
 *  an httpx or nuclei row records the URL and nothing else. */
function defaultRequest(url: string, method: string | null): string {
  let path = '/'
  let host = ''
  try {
    const u = new URL(url)
    path = u.pathname + u.search
    host = u.host
  } catch { /* leave the defaults */ }
  return `${(method || 'GET').toUpperCase()} ${path} HTTP/1.1\r\n`
    + `Host: ${host}\r\n`
    + `User-Agent: Oddjob (authorised security assessment)\r\n`
    + `Accept: */*\r\n\r\n`
}
