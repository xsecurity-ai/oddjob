import { useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Paper,
  Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import PdfIcon from '@mui/icons-material/PictureAsPdfOutlined'
import DocIcon from '@mui/icons-material/ArticleOutlined'
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Report } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useLive } from '../lib/useLive'
import { neon, glow } from '../theme'

/**
 * Reports: request one, watch it build, download it.
 *
 * The row appears the moment it is requested, in "In Progress". A request
 * that produced nothing visible until it finished would be
 * indistinguishable from one that failed silently.
 */

const STATUS: Record<string, { label: string; colour: string }> = {
  queued: { label: 'In Progress', colour: neon.yellow },
  running: { label: 'In Progress', colour: neon.yellow },
  ready: { label: 'Ready to Download', colour: neon.green },
  failed: { label: 'Failed', colour: neon.red },
}

const SEVERITIES = [
  { value: 'low', label: 'Low and above (excludes informational)' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'high', label: 'High and critical only' },
  { value: 'critical', label: 'Critical only' },
  { value: 'info', label: 'Everything, including informational' },
]

function size(n: number | null): string {
  if (!n) return '—'
  return n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB`
                         : `${Math.max(1, Math.round(n / 1024))} KB`
}

function when(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function ReportsView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const [open, setOpen] = useState(false)

  const reports = useQuery({
    queryKey: ['reports', project],
    queryFn: () => api.reports(project!),
    enabled: !!project,
    // While something is building, poll. The SSE stream also fires, but a
    // report can finish in a second and a missed event would leave the row
    // saying "In Progress" until the next navigation.
    refetchInterval: (q) =>
      (q.state.data ?? []).some((r: Report) =>
        r.status === 'queued' || r.status === 'running') ? 2000 : false,
  })
  useLive(!!project)

  const del = useMutation({
    mutationFn: (id: number) => api.deleteReport(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports', project] }),
  })

  if (!project) {
    return (
      <Box sx={{ p: 4 }}>
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12.5 }}>
          Choose an engagement in the header — a report is written about one
          project.
        </Alert>
      </Box>
    )
  }

  const rows = reports.data ?? []

  return (
    <Box sx={{ flex: 1, overflow: 'auto', p: { xs: 1.5, sm: 2.5 } }}>
      {open && (
        <NewReportDialog project={project} onClose={() => setOpen(false)}
          onCreated={() => {
            setOpen(false)
            qc.invalidateQueries({ queryKey: ['reports', project] })
          }} />
      )}

      <Stack spacing={2} sx={{ maxWidth: 1100, mx: 'auto' }}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Typography sx={{
            fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
            letterSpacing: '0.16em', textTransform: 'uppercase',
            color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
          }}>Reports</Typography>
          <Chip size="small" label={project} sx={{
            height: 19, fontSize: 10, bgcolor: alpha(neon.pink, 0.14),
            color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.45)}` }} />
          <Box sx={{ flex: 1 }} />
          <Button size="small" variant="outlined" startIcon={<AddIcon />}
            onClick={() => setOpen(true)}
            sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
            New report
          </Button>
        </Stack>

        <Paper elevation={0} sx={{
          backgroundColor: alpha(neon.paper, 0.7),
          border: `1px solid ${alpha(neon.purple, 0.3)}`,
        }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {['Report', 'Status', 'Requested', 'Finished', 'Size',
                  'Download', ''].map((h) => (
                  <TableCell key={h} sx={headSx}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.length === 0 && (
                <TableRow><TableCell colSpan={7} sx={{ ...cellSx, py: 3 }}>
                  <Typography sx={{ fontSize: 12.5, color: alpha(neon.muted, 0.8) }}>
                    No reports yet.
                  </Typography>
                </TableCell></TableRow>
              )}
              {rows.map((r) => {
                const st = STATUS[r.status] ?? { label: r.status, colour: neon.muted }
                const busy = r.status === 'queued' || r.status === 'running'
                const ready = r.status === 'ready'
                return (
                  <TableRow key={r.id} hover>
                    <TableCell sx={cellSx}>
                      <Box sx={{ color: neon.text }}>{r.title}</Box>
                      <Stack direction="row" spacing={0.6} sx={{ mt: 0.4 }}
                             flexWrap="wrap" useFlexGap>
                        <Chip size="small" label={r.kind} sx={tag(neon.purple)} />
                        {r.agent_edited && (
                          <Tooltip title={r.agent_note ?? 'Prose revised by the agent'}>
                            <Chip size="small" icon={<AutoAwesomeIcon sx={{ fontSize: 11 }} />}
                              label="agent" sx={tag(neon.pink)} />
                          </Tooltip>
                        )}
                        {r.requested_by_name && (
                          <Chip size="small" label={r.requested_by_name}
                                sx={tag(neon.muted)} />
                        )}
                      </Stack>
                      {r.error && (
                        <Typography sx={{ mt: 0.5, fontSize: 11, color: neon.red }}>
                          {r.error}
                        </Typography>
                      )}
                      {r.agent_note && !r.agent_edited && (
                        <Typography sx={{ mt: 0.5, fontSize: 10.5, color: neon.yellow }}>
                          {r.agent_note}
                        </Typography>
                      )}
                    </TableCell>

                    <TableCell sx={{ ...cellSx, width: 170 }}>
                      <Stack direction="row" spacing={0.8} alignItems="center">
                        {busy && <CircularProgress size={11} sx={{ color: st.colour }} />}
                        <Box sx={{ color: st.colour, textShadow: glow(st.colour, 0.4),
                                   fontSize: 11.5 }}>{st.label}</Box>
                      </Stack>
                      {/* Why no email, said once and kept — "I never got a
                          mail" is otherwise unanswerable. */}
                      {r.emailed_to && (
                        <Typography sx={{ fontSize: 10, color: alpha(neon.green, 0.9) }}>
                          emailed {r.emailed_to}
                        </Typography>
                      )}
                      {ready && r.email_error && (
                        <Tooltip title={r.email_error}>
                          <Typography sx={{ fontSize: 10, color: alpha(neon.muted, 0.85) }}>
                            not emailed
                          </Typography>
                        </Tooltip>
                      )}
                    </TableCell>

                    <TableCell sx={{ ...cellSx, width: 150, color: neon.muted }}>
                      {when(r.created_at)}
                    </TableCell>
                    <TableCell sx={{ ...cellSx, width: 150, color: neon.muted }}>
                      {when(r.finished_at)}
                    </TableCell>
                    <TableCell sx={{ ...cellSx, width: 80, color: neon.muted }}>
                      {size(r.size_bytes)}
                    </TableCell>

                    <TableCell sx={{ ...cellSx, width: 160 }}>
                      <Stack direction="row" spacing={0.8}>
                        {(['pdf', 'docx'] as const).map((fmt) => (
                          <Tooltip key={fmt} title={ready
                            ? `Download ${fmt.toUpperCase()}`
                            : 'Available once the report is ready'}>
                            <span>
                              <Button size="small" variant="outlined" disabled={!ready}
                                href={ready ? api.reportDownloadUrl(r.id, fmt) : undefined}
                                startIcon={fmt === 'pdf'
                                  ? <PdfIcon sx={{ fontSize: 15 }} />
                                  : <DocIcon sx={{ fontSize: 15 }} />}
                                sx={{
                                  fontSize: 10, py: 0.2, minWidth: 0,
                                  color: ready ? neon.cyan : alpha(neon.muted, 0.45),
                                  borderColor: alpha(ready ? neon.cyan : neon.muted, 0.4),
                                }}>
                                {fmt.toUpperCase()}
                              </Button>
                            </span>
                          </Tooltip>
                        ))}
                      </Stack>
                    </TableCell>

                    <TableCell sx={{ ...cellSx, width: 44 }}>
                      {canWrite(project) && (
                        <IconButton size="small" disabled={del.isPending}
                          onClick={() => del.mutate(r.id)}
                          sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                          <DeleteIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </Paper>
      </Stack>
    </Box>
  )
}

function NewReportDialog({ project, onClose, onCreated }: {
  project: string; onClose: () => void; onCreated: () => void
}) {
  const [kind, setKind] = useState('full')
  const [agentic, setAgentic] = useState(false)
  const [minSeverity, setMinSeverity] = useState('low')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const kinds = useQuery({ queryKey: ['report-kinds'], queryFn: api.reportKinds })
  const agent = useQuery({
    queryKey: ['agent-status', project],
    queryFn: () => api.agentStatus(project),
  })
  const chosen = (kinds.data ?? []).find((k) => k.name === kind)
  const agentReady = agent.data?.configured ?? false

  const go = async () => {
    setBusy(true); setErr(null)
    try {
      await api.createReport(project, kind, agentic && agentReady, minSeverity)
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan,
                         textShadow: glow(neon.cyan, 0.5),
                         borderBottom: `1px solid ${alpha(neon.cyan, 0.28)}` }}>
        NEW REPORT → {project}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2.5} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}

          <TextField select size="small" fullWidth label="Report type" value={kind}
            onChange={(e) => setKind(e.target.value)}>
            {(kinds.data ?? []).map((k) => (
              <MenuItem key={k.name} value={k.name} sx={{ fontSize: 13 }}>
                {k.label}
              </MenuItem>
            ))}
          </TextField>
          {chosen && (
            <Box sx={{ mt: -1.4 }}>
              <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
                Sections: {chosen.sections.join(' · ')}
              </Typography>
            </Box>
          )}

          <TextField select size="small" fullWidth label="Findings to include"
            value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}
            helperText="Informational entries are usually coverage records — one
                        per host per task — and including them can run to
                        thousands of pages. Whatever is left out is stated in
                        the report.">
            {SEVERITIES.map((s) => (
              <MenuItem key={s.value} value={s.value} sx={{ fontSize: 13 }}>
                {s.label}
              </MenuItem>
            ))}
          </TextField>

          <Box>
            <FormControlLabel
              control={<Checkbox checked={agentic && agentReady} disabled={!agentReady}
                onChange={(e) => setAgentic(e.target.checked)}
                sx={{ color: neon.muted, '&.Mui-checked': { color: neon.pink } }} />}
              label={
                <Stack direction="row" spacing={0.8} alignItems="center">
                  <AutoAwesomeIcon sx={{ fontSize: 15,
                    color: agentic && agentReady ? neon.pink : alpha(neon.muted, 0.7) }} />
                  <Typography sx={{ fontSize: 13 }}>Use Agentic Support</Typography>
                </Stack>
              } />
            <Typography sx={{ mt: 0.3, fontSize: 10.5, lineHeight: 1.6,
                              color: alpha(neon.muted, 0.9) }}>
              {agentReady
                ? `The agent (${agent.data?.model}) rewrites the narrative and
                   tightens finding wording before the report is marked ready.
                   It cannot change a severity, a host or a number — any edit
                   that alters a figure in the text is rejected, and the report
                   says on its first page that prose was machine-revised.`
                : 'No agent is configured. Set one up in Site Config → Agent.'}
            </Typography>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button variant="outlined" disabled={busy} onClick={go}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
          {busy ? '…' : 'Generate'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

const tag = (c: string) => ({
  height: 17, fontSize: 9.5, bgcolor: alpha(c, 0.14), color: c,
  border: `1px solid ${alpha(c, 0.4)}`,
})
const headSx = {
  fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.12em',
  textTransform: 'uppercase', color: alpha(neon.cyan, 0.8),
  borderBottom: `1px solid ${alpha(neon.cyan, 0.3)}`, py: 0.8,
} as const
const cellSx = {
  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12, color: neon.text,
  borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`, py: 0.9,
  verticalAlign: 'top',
} as const
