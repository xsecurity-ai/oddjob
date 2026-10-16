/** One finding, in full, with every host it was found on.
 *
 * The table has a row per (finding, host) because that is the unit of
 * work. But the text that makes a finding actionable — the detail, the
 * background, the fix — does not fit in a cell, and the first question
 * anyone asks is "where else is this?". Answering that by scrolling a
 * table of thousands of rows is not reasonable, so the server groups
 * them and this shows the group.
 */
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogContent, DialogTitle,
  Divider, Link, MenuItem, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import IconButton from '@mui/material/IconButton'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { SEVERITY_COLOUR } from '../lib/severity'
import { TRIAGE } from '../lib/triage'
import { neon, glow } from '../theme'

/** A long scanner paragraph, shown as written rather than reflowed:
 *  the line breaks in a tool's output usually mean something. */
function Prose({ label, text }: { label: string; text: string | null | undefined }) {
  if (!text?.trim()) return null
  return (
    <Box>
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10.5,
                        letterSpacing: '0.16em', color: neon.cyan, mb: 0.75 }}>
        {label.toUpperCase()}
      </Typography>
      <Typography component="pre" sx={{
        fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5,
        color: neon.text, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
        m: 0, lineHeight: 1.55,
      }}>
        {text.trim()}
      </Typography>
    </Box>
  )
}

/** The credential behind a secret finding: masked until asked for.
 *
 *  Masked by DEFAULT rather than hidden behind a tab, because the
 *  point is that somebody opening a finding should see that there
 *  is a value here without the value being on screen -- in a
 *  screen share, a screenshot, or over a shoulder.
 *
 *  Fetched on click, never with the finding. The modal is opened
 *  constantly while triaging; the credential is wanted rarely, and
 *  each reveal is written to the audit log, so fetching it eagerly
 *  would record a reveal nobody asked for and make the log useless
 *  as evidence of who actually looked.
 */
function SecretField({ vulnId }: { vulnId: number }) {
  const [shown, setShown] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const reveal = async () => {
    setBusy(true); setErr(null)
    try {
      const r = await api.revealSecret(vulnId)
      setShown(r.secret)
    } catch (e) {
      // A 404 here is the ordinary case for older findings, not a
      // fault, so it is said plainly rather than as an error.
      setErr(String(e).includes('404')
        ? 'No credential is stored for this finding.'
        : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box>
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10.5,
                        letterSpacing: '0.16em', color: neon.red, mb: 0.75 }}>
        CREDENTIAL
      </Typography>
      <Stack direction="row" spacing={1} alignItems="center"
        sx={{ flexWrap: 'wrap', gap: 1 }}>
        <Typography component="pre" sx={{
          fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5,
          color: shown ? neon.red : neon.muted, m: 0,
          px: 1, py: 0.5, borderRadius: 0.5,
          background: alpha(shown ? neon.red : neon.muted, 0.1),
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          userSelect: shown ? 'all' : 'none',
        }}>
          {shown ?? '••••••••••••••••'}
        </Typography>
        {!shown && (
          <Button size="small" variant="outlined" disabled={busy}
            onClick={reveal}
            sx={{ color: neon.red, borderColor: alpha(neon.red, 0.5),
                  fontSize: 11.5 }}>
            {busy ? 'Revealing…' : 'Reveal secret'}
          </Button>
        )}
        {shown && (
          <Button size="small" onClick={() => setShown(null)}
            sx={{ color: neon.muted, fontSize: 11.5 }}>
            Hide
          </Button>
        )}
      </Stack>
      <Typography sx={{ fontSize: 11, color: neon.muted, mt: 0.5 }}>
        {err ?? (shown
          ? 'Revealed. This was written to the audit log with your name.'
          : 'Hidden by default. Revealing is recorded in the audit log.')}
      </Typography>
    </Box>
  )
}

export function VulnModal({ id, onClose, onHost }: {
  id: number | null
  onClose: () => void
  /** Jump to a host from the occurrences list. Takes the project too,
   *  because the host modal is keyed on both and the same hostname can
   *  exist in more than one engagement. */
  onHost?: (project: string, host: string) => void
}) {
  const qc = useQueryClient()
  const mark = useMutation({
    mutationFn: (triage: string) => api.setTriage(id as number, triage),
    onSuccess: () => {
      // Both: the modal's own copy and the table behind it, which
      // is showing the same verdict in a column.
      void qc.invalidateQueries({ queryKey: ['vuln', id] })
      void qc.invalidateQueries({ queryKey: ['vulns'] })
    },
  })
  const { data, isLoading, error } = useQuery({
    queryKey: ['vuln', id],
    queryFn: () => api.vuln(id as number),
    enabled: id != null,
  })

  const sev = (s: string) => SEVERITY_COLOUR[s] ?? neon.muted

  return (
    <Dialog open={id != null} onClose={onClose} maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
      } } }}>
      <DialogTitle sx={{ pr: 6 }}>
        <Stack direction="row" spacing={1.25} alignItems="flex-start">
          {data && (
            <Chip size="small" label={data.severity.toUpperCase()} sx={{
              height: 20, fontSize: 10, fontWeight: 700, mt: 0.25,
              bgcolor: alpha(sev(data.severity), 0.18), color: sev(data.severity),
              border: `1px solid ${alpha(sev(data.severity), 0.6)}`,
            }} />
          )}
          <Typography sx={{
            fontFamily: `'Orbitron', sans-serif`, fontSize: 14, fontWeight: 700,
            letterSpacing: '0.06em', color: neon.text,
            textShadow: glow(neon.cyan, 0.3), flex: 1, wordBreak: 'break-word',
          }}>
            {data?.title ?? (isLoading ? 'loading…' : 'finding')}
          </Typography>
        </Stack>
        <IconButton onClick={onClose} size="small"
          sx={{ position: 'absolute', top: 10, right: 10, color: neon.muted }}>
          <CloseIcon sx={{ fontSize: 18 }} />
        </IconButton>
      </DialogTitle>

      <DialogContent dividers sx={{ borderColor: alpha(neon.purple, 0.3) }}>
        {isLoading && (
          <Box sx={{ display: 'grid', placeItems: 'center', py: 6 }}>
            <CircularProgress size={22} sx={{ color: neon.cyan }} />
          </Box>
        )}
        {error && (
          <Typography sx={{ fontSize: 12.5, color: neon.red }}>
            {(error as Error).message}
          </Typography>
        )}

        {data && (
          <Stack spacing={2.5}>
            <Stack direction="row" spacing={2} flexWrap="wrap" rowGap={1}>
              {([
                ['status', data.status],
                ['first seen on', data.host],
                ['port', data.port ? `${data.port}/${data.protocol ?? 'tcp'}` : '—'],
                ['identifier', data.external_id ?? '—'],
                ['engagement', data.project_code],
              ] as const).map(([k, v]) => (
                <Box key={k}>
                  <Typography sx={{ fontSize: 10, letterSpacing: '0.14em',
                                    color: neon.muted, textTransform: 'uppercase' }}>
                    {k}
                  </Typography>
                  <Typography sx={{ fontFamily: `'Share Tech Mono', monospace`,
                                    fontSize: 12.5, color: neon.text }}>
                    {v}
                  </Typography>
                </Box>
              ))}
            </Stack>

            <Divider sx={{ borderColor: alpha(neon.purple, 0.25) }} />

            {/* The same verdict control as the table, so a finding
                opened for a closer look can be marked without going
                back to it -- which is where most of them are
                actually judged. */}
            <Box>
              <Typography sx={{ fontFamily: `'Orbitron', sans-serif`,
                                fontSize: 10.5, letterSpacing: '0.16em',
                                color: neon.cyan, mb: 0.75 }}>
                TRIAGE
              </Typography>
              <TextField select size="small"
                value={data.triage ?? 'needs_investigating'}
                disabled={mark.isPending}
                onChange={(e) => mark.mutate(e.target.value)}
                sx={{ minWidth: 220 }}>
                {TRIAGE.map((t) => (
                  <MenuItem key={t.value} value={t.value}
                    sx={{ fontSize: 12.5, color: t.colour }}>{t.label}</MenuItem>
                ))}
              </TextField>
              <Typography sx={{ fontSize: 11, color: neon.muted, mt: 0.5 }}>
                What a person concluded. Separate from Status, which is
                what has been done about it.
              </Typography>
            </Box>

            <Prose label="Description" text={data.description} />

            {/* Only for findings that carry one. Judged on the
                external_id rather than on a separate request: the
                secret scanners prefix theirs, and asking the server
                "is there a credential" for every finding would be a
                request per row to answer a question the id already
                answers. */}
            {/* Asked of the server, not guessed from the id. Judging
                by the `detect-secrets:` prefix offered Reveal on 92
                findings that predate secrets being kept, where
                pressing it returned an error -- a control that cannot
                do what it offers is worse than no control. */}
            {data.has_secret && <SecretField vulnId={data.id} />}
            <Prose label="Remediation" text={data.remediation} />
            {!data.description?.trim() && !data.remediation?.trim() && (
              <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
                No description was recorded. That is a fact about the import,
                not about the finding — the tool may not have supplied one.
              </Typography>
            )}

            <Divider sx={{ borderColor: alpha(neon.purple, 0.25) }} />

            <Box>
              <Stack direction="row" alignItems="baseline" spacing={1} sx={{ mb: 1 }}>
                <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10.5,
                                  letterSpacing: '0.16em', color: neon.pink }}>
                  AFFECTED SYSTEMS
                </Typography>
                <Typography sx={{ fontSize: 11.5, color: neon.text }}>
                  {data.occurrences.length}
                </Typography>
                <Tooltip title={
                  data.grouped_by === 'title'
                    ? 'This finding carries no identifier, so hosts were matched '
                      + 'on the exact title within this engagement.'
                    : `Hosts were matched on ${data.grouped_by}.`}>
                  <Typography sx={{ fontSize: 10.5, color: neon.muted,
                                    borderBottom: `1px dotted ${alpha(neon.muted, 0.6)}`,
                                    cursor: 'help' }}>
                    grouped by {data.grouped_by.startsWith('external_id')
                      ? 'identifier' : 'title'}
                  </Typography>
                </Tooltip>
              </Stack>

              <Box sx={{ maxHeight: 320, overflow: 'auto',
                         border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      {['Host', 'Port', 'Severity', 'Status'].map((h) => (
                        <TableCell key={h} sx={{
                          fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
                          letterSpacing: '0.12em', color: neon.cyan,
                          backgroundColor: neon.paper,
                          borderBottom: `1px solid ${alpha(neon.cyan, 0.35)}`,
                        }}>{h.toUpperCase()}</TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.occurrences.map((o) => (
                      <TableRow key={o.id} hover>
                        <TableCell sx={{ fontFamily: `'Share Tech Mono', monospace`,
                                         fontSize: 12, color: neon.text,
                                         borderColor: alpha(neon.purple, 0.15) }}>
                          {onHost
                            ? <Link component="button" onClick={() => onHost(o.project_code, o.host)}
                                sx={{ color: neon.cyan, fontSize: 12,
                                      fontFamily: `'Share Tech Mono', monospace`,
                                      textAlign: 'left' }}>
                                {o.host}
                              </Link>
                            : o.host}
                        </TableCell>
                        <TableCell sx={{ fontFamily: `'Share Tech Mono', monospace`,
                                         fontSize: 12, color: neon.muted,
                                         borderColor: alpha(neon.purple, 0.15) }}>
                          {o.port ? `${o.port}/${o.protocol ?? 'tcp'}` : '—'}
                        </TableCell>
                        <TableCell sx={{ fontSize: 11.5, color: sev(o.severity),
                                         borderColor: alpha(neon.purple, 0.15) }}>
                          {o.severity}
                        </TableCell>
                        <TableCell sx={{ fontSize: 11.5,
                                         color: o.status === 'open' ? neon.yellow : neon.muted,
                                         borderColor: alpha(neon.purple, 0.15) }}>
                          {o.status}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            </Box>
          </Stack>
        )}
      </DialogContent>
    </Dialog>
  )
}
