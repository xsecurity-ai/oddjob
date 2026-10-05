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
  Box, Chip, CircularProgress, Dialog, DialogContent, DialogTitle, Divider,
  Link, Stack, Table, TableBody, TableCell, TableHead, TableRow, Tooltip,
  Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import IconButton from '@mui/material/IconButton'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { SEVERITY_COLOUR } from '../lib/severity'
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

export function VulnModal({ id, onClose, onHost }: {
  id: number | null
  onClose: () => void
  /** Jump to a host from the occurrences list. Takes the project too,
   *  because the host modal is keyed on both and the same hostname can
   *  exist in more than one engagement. */
  onHost?: (project: string, host: string) => void
}) {
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

            <Prose label="Description" text={data.description} />
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
