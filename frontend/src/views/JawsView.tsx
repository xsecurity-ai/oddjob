import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, IconButton, MenuItem, Stack, Step, StepLabel,
  Stepper, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DownloadIcon from '@mui/icons-material/Download'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew'
import type { GridColDef } from '@mui/x-data-grid'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  api, type AgentEnrolled, type JawsAgent, type JawsRouting,
} from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { neon, glow } from '../theme'

const STATUS_COLOUR: Record<string, string> = {
  online: neon.green, offline: neon.muted, disabled: neon.red,
}

const OS_LABEL: Record<string, string> = {
  linux: 'Linux', darwin: 'macOS', windows: 'Windows',
}

/** "4m ago" — a heartbeat is only useful relative to now. */
function ago(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 0) return 'just now'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <Box component="pre" sx={{
      fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 11.5, m: 0,
      p: 1.2, borderRadius: 1, overflowX: 'auto', whiteSpace: 'pre-wrap',
      wordBreak: 'break-all', bgcolor: alpha('#000', 0.45),
      border: `1px solid ${alpha(neon.cyan, 0.18)}`, color: neon.text,
    }}>{children}</Box>
  )
}

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <Tooltip title={done ? 'Copied' : 'Copy'}>
      <IconButton size="small" onClick={() => {
        navigator.clipboard?.writeText(text)
        setDone(true); setTimeout(() => setDone(false), 1200)
      }}>
        <ContentCopyIcon sx={{ fontSize: 15, color: done ? neon.green : neon.muted }} />
      </IconButton>
    </Tooltip>
  )
}

/** Both architectures for the chosen OS, because the operator knows
 *  which machine they are walking to and we do not. */
function DownloadRow({ os }: { os: string }) {
  const { data } = useQuery({
    queryKey: ['jaws-downloads'],
    queryFn: () => api.jawsDownloads(),
    staleTime: 300000,
  })
  const builds = (data?.builds ?? []).filter((b) => b.os === os)
  if (!data) return null
  if (!builds.some((b) => b.available)) {
    // Said plainly rather than shown as a dead button: an image built
    // without the Go stage genuinely has none, and that is a build
    // problem, not something the operator can click past.
    return (
      <Alert severity="warning" sx={{ mt: 0.5 }}>
        This Oddjob has no {OS_LABEL[os] ?? os} agent binary to hand out.
        They are built into the image; in a development checkout, run
        {' '}<code>make release</code> in <code>jaws/</code>.
      </Alert>
    )
  }
  return (
    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
      {builds.map((b) => (
        <Button key={b.arch} size="small" variant="outlined"
          startIcon={<DownloadIcon />}
          disabled={!b.available}
          href={api.jawsDownloadUrl(b.os, b.arch)}
          download={b.name}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5) }}>
          {b.arch}
          <Box component="span" sx={{ color: neon.muted, ml: 0.8, fontSize: 11 }}>
            {(b.bytes / 1048576).toFixed(1)} MB
          </Box>
        </Button>
      ))}
    </Stack>
  )
}

// ----------------------------------------------------------- the wizard
function DeployWizard({ project, onClose }:
  { project: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [step, setStep] = useState(0)
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'callback' | 'call_in'>('callback')
  const [os, setOs] = useState<'linux' | 'darwin' | 'windows'>('linux')
  const [done, setDone] = useState<AgentEnrolled | null>(null)

  const enrol = useMutation({
    mutationFn: () => api.enrolAgent(project, {
      name: name.trim(), connection_mode: mode, target_os: os,
    }),
    onSuccess: (e) => {
      setDone(e); setStep(3)
      qc.invalidateQueries({ queryKey: ['jaws-agents', project] })
    },
  })

  const origin = window.location.origin
  const win = os === 'windows'
  const bin = win ? 'jaws.exe' : './jaws'
  const cmd = done ? [
    `${bin} run \\`,
    `  --server ${origin} \\`,
    `  --enrol ${done.enrol_token} \\`,
    ...(mode === 'call_in'
      ? [`  --listen 0.0.0.0:7777 \\`, `  --advertise https://this-host:7777 \\`]
      : []),
    `  --name ${done.agent.name}`,
  ].join('\n').replace(/\\\n/g, win ? '`\n' : '\\\n') : ''

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ color: neon.cyan }}>
        Deploy a Jaws on {project}
      </DialogTitle>
      <DialogContent>
        <Stepper activeStep={step} sx={{ mb: 3, mt: 1 }}>
          {['Direction', 'Platform', 'Name', 'Run it'].map((l) => (
            <Step key={l}><StepLabel>{l}</StepLabel></Step>
          ))}
        </Stepper>

        {step === 0 && (
          <Stack spacing={1.5}>
            <Typography variant="body2" sx={{ color: neon.muted }}>
              Which way does the connection go?
            </Typography>
            {([
              ['callback', 'Jaws calls back  (recommended)',
               'The agent dials out and holds the connection open. Works from ' +
               'inside a client network behind NAT, with nothing exposed and no ' +
               'inbound firewall rule to ask for.'],
              ['call_in', 'Oddjob calls in',
               'Oddjob reaches the agent on a port it listens on. Only for a host ' +
               'that cannot dial out but can be reached — it needs an inbound rule, ' +
               'and that port becomes something an attacker can find.'],
            ] as const).map(([v, title, why]) => (
              <Box key={v} onClick={() => setMode(v)}
                sx={{ p: 1.5, borderRadius: 1, cursor: 'pointer',
                      border: `1px solid ${alpha(mode === v ? neon.green : neon.muted, mode === v ? 0.7 : 0.25)}`,
                      bgcolor: mode === v ? alpha(neon.green, 0.07) : 'transparent' }}>
                <Box sx={{ color: mode === v ? neon.green : neon.text, fontWeight: 600,
                           fontSize: 13.5 }}>{title}</Box>
                <Box sx={{ color: neon.muted, fontSize: 12, mt: 0.4 }}>{why}</Box>
              </Box>
            ))}
          </Stack>
        )}

        {step === 1 && (
          <Stack spacing={1.5}>
            <Typography variant="body2" sx={{ color: neon.muted }}>
              What is it being deployed on? This picks the binary and the
              install snippet — the agent reports its own platform once it
              connects, and the two are shown separately so a mismatch is
              visible rather than assumed away.
            </Typography>
            <TextField select size="small" label="Operating system" value={os}
              onChange={(e) => setOs(e.target.value as typeof os)}
              sx={{ maxWidth: 280 }}>
              {Object.entries(OS_LABEL).map(([v, l]) => (
                <MenuItem key={v} value={v}>{l}</MenuItem>
              ))}
            </TextField>
          </Stack>
        )}

        {step === 2 && (
          <Stack spacing={1.5}>
            <Typography variant="body2" sx={{ color: neon.muted }}>
              A name you will recognise in the list — where it sits, not what
              it is. &ldquo;dmz-jump-01&rdquo; beats &ldquo;jaws1&rdquo;.
            </Typography>
            <TextField size="small" label="Name" value={name} autoFocus
              onChange={(e) => setName(e.target.value)} sx={{ maxWidth: 320 }} />
            {enrol.error ? <Alert severity="error">{String(enrol.error)}</Alert> : null}
          </Stack>
        )}

        {step === 3 && done && (
          <Box>
            <Alert severity="warning" sx={{ mb: 2 }}>
              This token is shown <strong>once</strong> and is good for a
              short while. The agent trades it on first run for a keypair it
              generates itself — the private half never leaves that host, and
              Oddjob stores only the public half.
            </Alert>
            <Typography variant="body2" sx={{ color: neon.muted, mb: 1.5 }}>
              It is bound to <strong>{project}</strong>. Everything this agent
              finds imports into {project}, it only ever takes tasking from
              {' '}{project}, and it pins this Oddjob — it will not accept
              instructions from any other.
            </Typography>
            <Typography variant="overline" sx={{ color: neon.cyan,
                                                 display: 'block', mt: 1 }}>
              Get the binary
            </Typography>
            <DownloadRow os={os} />

            <Stack direction="row" alignItems="center" sx={{ mt: 2 }}>
              <Typography variant="overline" sx={{ color: neon.cyan, flex: 1 }}>
                Then, on the {OS_LABEL[os]} host
              </Typography>
              <Copy text={cmd} />
            </Stack>
            <Mono>{cmd}</Mono>
            {mode === 'call_in' && (
              <Alert severity="info" sx={{ mt: 2 }}>
                Set <code>--advertise</code> to a URL this Oddjob can actually
                reach, and open 7777 to it only.
              </Alert>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        {step > 0 && step < 3 && (
          <Button onClick={() => setStep((s) => s - 1)} sx={{ color: neon.muted }}>
            Back
          </Button>
        )}
        {step < 2 && (
          <Button onClick={() => setStep((s) => s + 1)} sx={{ color: neon.cyan }}>
            Next
          </Button>
        )}
        {step === 2 && (
          <Button disabled={!name.trim() || enrol.isPending}
            onClick={() => enrol.mutate()} sx={{ color: neon.green }}>
            {enrol.isPending ? 'Enrolling…' : 'Enrol'}
          </Button>
        )}
        {step === 3 && (
          <Button onClick={onClose} sx={{ color: neon.green }}>
            I have copied it
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}

// ---------------------------------------------------------- the routing
function Routing({ project, routing }:
  { project: string; routing: JawsRouting | undefined }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const set = useMutation({
    mutationFn: (mode: string) => api.setJawsRouting(project, mode),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jaws-routing', project] }),
  })
  if (!routing) return null
  return (
    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }}>
      <TextField select size="small" label="Routing" value={routing.mode}
        disabled={!canWrite(project) || set.isPending}
        onChange={(e) => set.mutate(e.target.value)} sx={{ width: 150 }}>
        <MenuItem value="mesh">Mesh</MenuItem>
        <MenuItem value="primary">Primary</MenuItem>
        <MenuItem value="geo">By region</MenuItem>
      </TextField>
      <Box sx={{ color: neon.muted, fontSize: 12 }}>
        {routing.mode === 'mesh' &&
          'Whichever agent asks first takes the next pooled task.'}
        {routing.mode === 'primary' && (routing.current_primary_name
          ? <>Serving now: <Box component="span" sx={{ color: neon.green }}>
              {routing.current_primary_name}</Box>. If it stops heartbeating
              the next by priority takes over.</>
          : 'No agent is online to be primary.')}
        {routing.mode === 'geo' &&
          'Pooled tasks run on an agent serving their region, or wait.'}
      </Box>
      {routing.unassigned_tasks > 0 && (
        <Chip size="small" label={`${routing.unassigned_tasks} waiting`}
          sx={{ height: 19, fontSize: 10.5, color: neon.yellow,
                bgcolor: alpha(neon.yellow, 0.12) }} />
      )}
    </Stack>
  )
}

// ------------------------------------------------------------- the view
export function JawsView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const [wizard, setWizard] = useState(false)
  const [confirmKill, setConfirmKill] = useState<JawsAgent | null>(null)
  // A killed agent leaves the table, because the table answers "what
  // is deployed" and it no longer is. The record stays — it holds the
  // output of scans that ran — so it is hidden rather than deleted,
  // and can be brought back into view.
  const [showKilled, setShowKilled] = useState(false)

  const { data, isLoading, error } = useQuery({
    queryKey: ['jaws-agents', project],
    queryFn: () => api.agents(project as string),
    enabled: !!project,
    // A heartbeat column is a live thing; a stale one is worse than none.
    refetchInterval: 10000,
  })
  const { data: routing } = useQuery({
    queryKey: ['jaws-routing', project],
    queryFn: () => api.jawsRouting(project as string),
    enabled: !!project,
    refetchInterval: 15000,
  })
  const kill = useMutation({
    mutationFn: (id: number) => api.killAgent(project as string, id),
    onSuccess: () => {
      setConfirmKill(null)
      qc.invalidateQueries({ queryKey: ['jaws-agents', project] })
      qc.invalidateQueries({ queryKey: ['jaws-routing', project] })
    },
  })

  const all = data ?? []
  const killed = all.filter((a) => a.status === 'disabled')
  const rows = showKilled ? all : all.filter((a) => a.status !== 'disabled')

  const columns: GridColDef<JawsAgent>[] = [
    {
      field: 'name', headerName: 'Jaws', flex: 1.1, minWidth: 150,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.9} alignItems="center">
          <Box sx={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
            bgcolor: STATUS_COLOUR[p.row.status] ?? neon.muted,
            boxShadow: glow(STATUS_COLOUR[p.row.status] ?? neon.muted, 0.8) }} />
          <Box sx={{ color: neon.pink, fontWeight: 600 }}>{p.value}</Box>
        </Stack>
      ),
    },
    {
      field: 'hostname', headerName: 'Deployed to', flex: 1.2, minWidth: 160,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => {
        // Nothing is known until it connects. Showing the OS the operator
        // *intended* in this column would be stating a guess as a fact.
        if (!p.value) {
          return (
            <Tooltip title="Known once the agent connects for the first time">
              <Box component="span" sx={{ color: alpha(neon.muted, 0.5) }}>
                {p.row.enrolled_pending ? 'awaiting first contact' : '—'}
              </Box>
            </Tooltip>
          )
        }
        // One line: the grid's row height is fixed, and a second line
        // here is in the DOM but clipped — present to a screen reader
        // and invisible to everyone else.
        const mismatch = p.row.target_os && p.row.platform &&
                         p.row.target_os !== p.row.platform
        return (
          <Stack direction="row" spacing={0.7} alignItems="center"
            sx={{ minWidth: 0 }}>
            <Tooltip title={`${p.row.platform ?? '?'}/${p.row.arch ?? '?'}`}>
              <Box sx={{ color: neon.cyan, overflow: 'hidden',
                         textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {p.value}
              </Box>
            </Tooltip>
            {mismatch ? (
              // Worth surfacing rather than hiding in a tooltip: it
              // usually means the wrong binary went to the wrong host.
              <Tooltip title={`Enrolled for ${OS_LABEL[p.row.target_os!] ?? p.row.target_os}, but it reports ${p.row.platform}`}>
                <Chip size="small" label={p.row.platform ?? '?'} sx={{
                  height: 17, fontSize: 9.5, color: neon.yellow,
                  bgcolor: alpha(neon.yellow, 0.14) }} />
              </Tooltip>
            ) : null}
          </Stack>
        )
      },
    },
    {
      // The agent's own answer, not the source address of its
      // connection. Those differ whenever there is NAT, a proxy or a
      // tunnel in between, and in those cases the observed one is the
      // last hop — 127.0.0.1 through a reverse tunnel — which tells an
      // operator nothing about what the client will see in their logs.
      field: 'outbound_ip', headerName: 'IPv4', width: 150,
      valueGetter: (_v, row) => row.outbound_ip ?? row.last_ip ?? '',
      renderCell: (p) => {
        const own = p.row.outbound_ip
        const seen = p.row.last_ip
        if (!own && !seen) {
          return <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
        }
        const others = (p.row.interfaces ?? []).filter((i) => i !== own)
        const differs = own && seen && own !== seen
        return (
          <Tooltip title={
            (own ? `Reported by the agent: ${own}\n` : '') +
            (seen ? `Connection seen from: ${seen}` +
                    (differs ? '  (NAT, proxy or tunnel in between)' : '') : '') +
            (others.length ? `\nAlso on: ${others.join(', ')}` : '')
          }>
            <Stack direction="row" spacing={0.6} alignItems="center"
              sx={{ minWidth: 0 }}>
              <Box sx={{ fontFamily: 'ui-monospace, monospace', fontSize: 12,
                         color: own ? neon.text : alpha(neon.muted, 0.7),
                         overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {own || seen}
              </Box>
              {others.length > 0 && (
                <Box sx={{ color: neon.muted, fontSize: 10.5 }}>
                  +{others.length}
                </Box>
              )}
            </Stack>
          </Tooltip>
        )
      },
    },
    {
      field: 'last_seen', headerName: 'Last heartbeat', width: 152,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (
        <Tooltip title={p.value ? new Date(String(p.value)).toLocaleString() : ''}>
          <Box sx={{ color: p.row.status === 'online' ? neon.green : neon.muted }}>
            {ago(p.value ? String(p.value) : null)}
          </Box>
        </Tooltip>
      ),
    },
    {
      field: 'running_tasks', headerName: 'In progress', width: 120,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.6} alignItems="center">
          <Box sx={{ color: p.value ? neon.cyan : alpha(neon.muted, 0.45),
                     fontWeight: p.value ? 600 : 400 }}>
            {p.value || '—'}
          </Box>
          {p.row.queued_tasks > 0 && (
            <Tooltip title={`${p.row.queued_tasks} also waiting`}>
              <Box sx={{ color: neon.muted, fontSize: 11 }}>
                +{p.row.queued_tasks}
              </Box>
            </Tooltip>
          )}
        </Stack>
      ),
    },
    {
      field: 'privileged', headerName: 'Raw sockets', width: 118,
      renderCell: (p) => {
        if (!p.row.hostname) {
          return <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
        }
        return p.value
          ? <Chip size="small" label="yes" sx={{ height: 18, fontSize: 10,
              color: neon.green, bgcolor: alpha(neon.green, 0.12) }} />
          : <Tooltip title="masscan will refuse and nmap falls back to connect scans — a different scan from the one asked for">
              <Chip size="small" label="no" sx={{ height: 18, fontSize: 10,
                color: neon.red, bgcolor: alpha(neon.red, 0.12) }} />
            </Tooltip>
      },
    },
    {
      field: 'regions', headerName: 'Regions', width: 120,
      sortable: false,
      valueGetter: (v) => (v as string[] | undefined)?.join(', ') ?? '',
      renderCell: (p) => p.value
        ? <Box sx={{ color: neon.purple, fontSize: 12 }}>{p.value}</Box>
        : <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>,
    },
    {
      field: 'actions', headerName: '', width: 56, sortable: false,
      filterable: false,
      renderCell: (p) => {
        if (!canWrite(project)) return null
        if (p.row.status === 'disabled') {
          return (
            <Tooltip title="Already killed">
              <Box component="span" sx={{ color: alpha(neon.muted, 0.35),
                                          fontSize: 11 }}>killed</Box>
            </Tooltip>
          )
        }
        return (
          <Tooltip title="Kill this Jaws">
            <IconButton size="small" onClick={() => setConfirmKill(p.row)}>
              <PowerSettingsNewIcon sx={{ fontSize: 17, color: neon.red }} />
            </IconButton>
          </Tooltip>
        )
      },
    },
  ]

  if (!project) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">
          A Jaws belongs to exactly one project — its key works only there,
          its tasking comes only from there, and its results import only
          there. Pick a project to see or deploy one.
        </Alert>
      </Box>
    )
  }

  return (
    <Box sx={{ p: 2 }}>
      <Routing project={project} routing={routing} />
      <DataTable
        rows={rows}
        columns={columns}
        loading={isLoading}
        error={error as Error | null}
        tableId="jaws"
        initialSort={{ field: 'name', sort: 'asc' }}
        note={`Each Jaws is sealed to ${project}: it authenticates to this ` +
              `Oddjob alone, takes tasking only from ${project}, and ` +
              `everything it finds imports into ${project}.`}
        extraActions={
          <Stack direction="row" spacing={1} alignItems="center">
            {canWrite(project) && (
              <Button size="small" startIcon={<AddIcon />}
                onClick={() => setWizard(true)}
                sx={{ color: neon.green }}>
                Deploy a Jaws
              </Button>
            )}
            {killed.length > 0 && (
              <Button size="small" onClick={() => setShowKilled((v) => !v)}
                sx={{ color: neon.muted, fontSize: 11 }}>
                {showKilled
                  ? `hide ${killed.length} killed`
                  : `show ${killed.length} killed`}
              </Button>
            )}
          </Stack>
        }
      />

      {wizard && (
        <DeployWizard project={project} onClose={() => setWizard(false)} />
      )}

      <Dialog open={!!confirmKill} onClose={() => setConfirmKill(null)}>
        <DialogTitle sx={{ color: neon.red }}>
          Kill {confirmKill?.name}?
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: neon.text }}>
            Its credential stops working, its queued tasking is cancelled, and
            the next time it checks in it is told to exit.
          </Typography>
          <Divider sx={{ my: 1.5, borderColor: alpha(neon.cyan, 0.15) }} />
          <Typography variant="body2" sx={{ color: neon.muted }}>
            Everything it has already found stays. This does not delete the
            agent or its scan output — killing it is about stopping the
            process, not discarding the evidence.
          </Typography>
          {(confirmKill?.running_tasks ?? 0) > 0 && (
            <Alert severity="warning" sx={{ mt: 1.5 }}>
              {confirmKill?.running_tasks} task(s) are running right now. Work
              already started is left alone so its result is not lost, but if
              the process dies first that scan will not report.
            </Alert>
          )}
          {kill.error ? <Alert severity="error" sx={{ mt: 1.5 }}>
            {String(kill.error)}</Alert> : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmKill(null)} sx={{ color: neon.muted }}>
            Cancel
          </Button>
          <Button disabled={kill.isPending}
            onClick={() => confirmKill && kill.mutate(confirmKill.id)}
            sx={{ color: neon.red }}>
            {kill.isPending ? 'Killing…' : 'Kill it'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}
