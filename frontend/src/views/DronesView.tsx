import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, IconButton, MenuItem, Stack, Step, StepLabel,
  Stepper, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DownloadIcon from '@mui/icons-material/Download'
import EditIcon from '@mui/icons-material/EditOutlined'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew'
import type { GridColDef } from '@mui/x-data-grid'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  api, type AgentEnrolled, type DroneAgent, type DroneRouting,
} from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { DroneQueueDialog } from '../components/DroneQueueDialog'
import { DroneTasksTable } from '../components/DroneTasksTable'
import { neon, glow } from '../theme'

const STATUS_COLOUR: Record<string, string> = {
  // `busy` is its own colour because it is not a degraded state: the
  // agent is working. It stopped heartbeating only because it runs one
  // task at a time, and showing it grey alongside genuinely dead
  // agents was how a healthy long scan looked like a failure.
  online: neon.green, busy: neon.cyan, offline: neon.muted,
  disabled: neon.red,
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
    queryKey: ['drone-downloads'],
    queryFn: () => api.droneDownloads(),
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
        {' '}<code>make release</code> in <code>drone/</code>.
      </Alert>
    )
  }
  return (
    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
      {builds.map((b) => (
        <Button key={b.arch} size="small" variant="outlined"
          startIcon={<DownloadIcon />}
          disabled={!b.available}
          href={api.droneDownloadUrl(b.os, b.arch)}
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

  const enroll = useMutation({
    mutationFn: () => api.enrollAgent(project, {
      name: name.trim(), connection_mode: mode, target_os: os,
    }),
    onSuccess: (e) => {
      setDone(e); setStep(3)
      qc.invalidateQueries({ queryKey: ['drone-agents', project] })
    },
  })

  const origin = window.location.origin
  const win = os === 'windows'
  const bin = win ? 'drone.exe' : './drone'
  const cmd = done ? [
    `${bin} run \\`,
    `  --server ${origin} \\`,
    `  --enroll ${done.enroll_token} \\`,
    ...(mode === 'call_in'
      ? [`  --listen 0.0.0.0:7777 \\`, `  --advertise https://this-host:7777 \\`]
      : []),
    `  --name ${done.agent.name}`,
  ].join('\n').replace(/\\\n/g, win ? '`\n' : '\\\n') : ''

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ color: neon.cyan }}>
        Deploy a Drone on {project}
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
              ['callback', 'Drone calls back  (recommended)',
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
              it is. &ldquo;dmz-jump-01&rdquo; beats &ldquo;drone1&rdquo;.
            </Typography>
            <TextField size="small" label="Name" value={name} autoFocus
              onChange={(e) => setName(e.target.value)} sx={{ maxWidth: 320 }} />
            {enroll.error ? <Alert severity="error">{String(enroll.error)}</Alert> : null}
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
          <Button disabled={!name.trim() || enroll.isPending}
            onClick={() => enroll.mutate()} sx={{ color: neon.green }}>
            {enroll.isPending ? 'Enrolling…' : 'Enroll'}
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
  { project: string; routing: DroneRouting | undefined }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const [queueOpen, setQueueOpen] = useState(false)
  const set = useMutation({
    mutationFn: (b: { mode?: string; max_parallel?: number }) =>
      api.setDroneRouting(project, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['drone-routing', project] }),
  })
  // After the hooks: the early return below is conditional and moving
  // a hook above it would change the order between renders.
  if (!routing) return null
  return (
    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }}>
      <TextField select size="small" label="Routing" value={routing.mode}
        disabled={!canWrite(project) || set.isPending}
        onChange={(e) => set.mutate({ mode: e.target.value })} sx={{ width: 150 }}>
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
      {/* Always shown, including at zero. The queue depth is the
          number an operator checks to know whether a submission landed,
          and a chip that only appears when work is waiting cannot
          answer "did anything queue?" — absence looked identical to
          never having rendered. */}
      <Tooltip title={routing.unassigned_tasks > 0
        ? 'Open the queue: Oddjob holds these until an agent reports it is ready, and anything not yet started can be taken back out.'
        : 'Nothing waiting for the pool. Open it to see work addressed to one agent that has not been picked up.'}>
        <Chip size="small" clickable onClick={() => setQueueOpen(true)}
          label={`${routing.unassigned_tasks} queued`}
          sx={{ height: 21, fontSize: 11, fontWeight: 600,
                color: routing.unassigned_tasks > 0 ? neon.yellow : neon.muted,
                bgcolor: alpha(routing.unassigned_tasks > 0
                               ? neon.yellow : neon.muted, 0.14),
                border: `1px solid ${alpha(routing.unassigned_tasks > 0
                                           ? neon.yellow : neon.muted, 0.45)}`,
                '&:hover': { bgcolor: alpha(neon.yellow, 0.26) } }} />
      </Tooltip>
      <Tooltip title="How many tasks one agent may run at once on this engagement. A ceiling, not a target: each agent also works out what its own host can stand — cores, memory, what masscan managed to emit — and the lower of the two is what runs.">
        <TextField select size="small" label="Parallel" sx={{ width: 110 }}
          value={routing.max_parallel}
          disabled={!canWrite(project) || set.isPending}
          onChange={(e) => set.mutate({ max_parallel: Number(e.target.value) })}>
          {[1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 24, 32].map((n) => (
            <MenuItem key={n} value={n}>{n}</MenuItem>
          ))}
        </TextField>
      </Tooltip>
      {queueOpen && (
        <DroneQueueDialog project={project} onClose={() => setQueueOpen(false)} />
      )}
      {routing.unassigned_tasks > 0 && routing.eligible === 0 && (
        // Waiting work and nobody able to take it is the one case
        // where this number means something is wrong rather than
        // merely in progress.
        <Chip size="small" label="no agent online to take it" sx={{
          height: 21, fontSize: 11, color: neon.red,
          bgcolor: alpha(neon.red, 0.14),
          border: `1px solid ${alpha(neon.red, 0.5)}` }} />
      )}
    </Stack>
  )
}

/** Rename an agent, change where it sits in the running order, or say
 *  which regions it serves.
 *
 *  Both numeric settings only matter in one routing mode each, and the
 *  dialog says which — a priority field on a project running mesh is
 *  a control that does nothing, and leaving the operator to discover
 *  that is how a setting gets blamed for not working. */
function EditAgentDialog({ project, agent, mode, onClose }: {
  project: string; agent: DroneAgent; mode?: string; onClose: () => void
}) {
  const qc = useQueryClient()
  const [name, setName] = useState(agent.name)
  const [priority, setPriority] = useState(String(agent.priority))
  const [regions, setRegions] = useState((agent.regions ?? []).join(', '))
  const [notes, setNotes] = useState('')

  const rotate = useMutation({
    mutationFn: () => api.reenrollAgent(project, agent.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['drone-agents', project] }),
  })

  const save = useMutation({
    mutationFn: () => api.patchAgent(project, agent.id, {
      name: name.trim() || undefined,
      priority: Number.isFinite(Number(priority)) ? Number(priority) : undefined,
      // Sent even when empty: clearing the box is how an agent stops
      // serving a region, so an empty string has to reach the server
      // rather than being treated as "no change".
      regions,
      notes: notes.trim() || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['drone-agents', project] })
      onClose()
    },
  })

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ color: neon.cyan }}>{agent.name}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <TextField size="small" label="Name" value={name} autoFocus
            helperText="What it is called here. Where it sits, not what it is."
            onChange={(e) => setName(e.target.value)} />

          <TextField size="small" label="Priority" value={priority}
            type="number"
            helperText={mode === 'primary'
              ? 'Lower goes first. This project runs primary routing, so this decides who serves.'
              : `Lower goes first — but only in primary routing. This project runs ${mode ?? 'mesh'}, so this has no effect today.`}
            onChange={(e) => setPriority(e.target.value)} />

          <TextField size="small" label="Regions" value={regions}
            placeholder="jp, eu, us-east"
            helperText={mode === 'geo'
              ? 'Comma separated. This project routes by region, so an agent with none set will never be given region-tagged work.'
              : `Comma separated — but only consulted in region routing. This project runs ${mode ?? 'mesh'}, so this agent takes work regardless.`}
            onChange={(e) => setRegions(e.target.value)} />

          <Divider sx={{ borderColor: alpha(neon.cyan, 0.15) }} />
          {!agent.sealed && (
            // The reason most people will press this: an agent
            // enrolled before the channel was encrypted still works,
            // and still reports a client's findings protected only by
            // whatever TLS is in between.
            <Alert severity="warning" sx={{ fontSize: 12 }}>
              This agent is not sealing its traffic. Re-enrolling gives it
              a new keypair and an encrypted channel, and keeps its name,
              history and everything it has found.
            </Alert>
          )}
          <Box>
            <Button size="small" variant="outlined" disabled={rotate.isPending}
              onClick={() => rotate.mutate()}
              sx={{ color: neon.yellow, borderColor: alpha(neon.yellow, 0.5) }}>
              {rotate.isPending ? 'Issuing…' : 'Re-enroll (new keys)'}
            </Button>
            <Box sx={{ color: neon.muted, fontSize: 11, mt: 0.6 }}>
              The key it holds now stops working at once, so it goes
              offline until the new token is redeemed on the host.
            </Box>
          </Box>
          {rotate.data && (
            <Alert severity="success" sx={{ fontSize: 12 }}>
              <Box sx={{ fontFamily: 'ui-monospace, monospace', fontSize: 11.5,
                         wordBreak: 'break-all', mb: 0.8 }}>
                {rotate.data.enroll_token}
              </Box>
              {/* Shown once. The server keeps only a hash. */}
              <Box sx={{ color: neon.muted }}>{rotate.data.instructions}</Box>
            </Alert>
          )}
          {rotate.error ? <Alert severity="error" sx={{ fontSize: 12 }}>
            {String(rotate.error)}</Alert> : null}

          <TextField size="small" label="Add a note" value={notes}
            multiline minRows={2}
            helperText="Why this agent is where it is, for whoever reads this later."
            onChange={(e) => setNotes(e.target.value)} />
        </Stack>
        {save.error ? <Alert severity="error" sx={{ mt: 2 }}>
          {String(save.error)}</Alert> : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => save.mutate()}
          sx={{ color: neon.green }}>
          {save.isPending ? 'Saving…' : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ------------------------------------------------------------- the view
export function DronesView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const [wizard, setWizard] = useState(false)
  const [confirmKill, setConfirmKill] = useState<DroneAgent | null>(null)
  const [editing, setEditing] = useState<DroneAgent | null>(null)
  // A killed agent leaves the table, because the table answers "what
  // is deployed" and it no longer is. The record stays — it holds the
  // output of scans that ran — so it is hidden rather than deleted,
  // and can be brought back into view.
  const [showKilled, setShowKilled] = useState(false)

  const { data, isLoading, error } = useQuery({
    queryKey: ['drone-agents', project],
    queryFn: () => api.agents(project as string),
    enabled: !!project,
    // A heartbeat column is a live thing; a stale one is worse than none.
    refetchInterval: 10000,
  })
  const { data: routing } = useQuery({
    queryKey: ['drone-routing', project],
    queryFn: () => api.droneRouting(project as string),
    enabled: !!project,
    refetchInterval: 15000,
  })
  const kill = useMutation({
    mutationFn: (id: number) => api.killAgent(project as string, id),
    onSuccess: () => {
      setConfirmKill(null)
      qc.invalidateQueries({ queryKey: ['drone-agents', project] })
      qc.invalidateQueries({ queryKey: ['drone-routing', project] })
    },
  })

  const all = data ?? []
  const killed = all.filter((a) => a.status === 'disabled')
  const rows = showKilled ? all : all.filter((a) => a.status !== 'disabled')

  const columns: GridColDef<DroneAgent>[] = [
    {
      field: 'name', headerName: 'Drone', flex: 1.1, minWidth: 150,
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
          <Box sx={{ color: STATUS_COLOUR[p.row.status] ?? neon.muted }}>
            {p.row.status === 'busy'
              // The number would read as neglect; it is the opposite.
              ? 'running a task'
              : ago(p.value ? String(p.value) : null)}
          </Box>
        </Tooltip>
      ),
    },
    {
      // Several can run at once now, so a count alone stopped being an
      // answer: "3 running" does not say which three, and the reason
      // to look at this column is to find the one that is stuck.
      field: 'running_tasks', headerName: 'Working on', width: 260,
      renderCell: (p) => {
        const running = p.value as number
        const queued = p.row.queued_tasks
        const procs = p.row.running ?? []
        if (!running && !queued) {
          return <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>idle</Box>
        }
        if (procs.length) {
          return (
            <Tooltip title={
              <Box component="span">
                {procs.map((r) => (
                  <Box key={r.id} component="span" sx={{ display: 'block' }}>
                    #{r.id} {r.kind} — {r.subject}
                  </Box>
                ))}
                {queued > 0 ? `… and ${queued} queued for this agent` : ''}
              </Box>
            }>
              <Box sx={{ overflow: 'hidden' }}>
                {procs.slice(0, 2).map((r) => (
                  <Box key={r.id} sx={{ fontSize: 11, lineHeight: 1.35,
                                        whiteSpace: 'nowrap',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis' }}>
                    <Box component="span" sx={{ color: neon.cyan }}>
                      {r.kind}
                    </Box>
                    <Box component="span" sx={{ color: neon.muted }}>
                      {' '}{r.subject}
                    </Box>
                  </Box>
                ))}
                {(procs.length > 2 || queued > 0) && (
                  <Box sx={{ fontSize: 10.5, color: neon.muted }}>
                    {procs.length > 2 ? `+${procs.length - 2} more running` : ''}
                    {procs.length > 2 && queued > 0 ? ' · ' : ''}
                    {queued > 0 ? `${queued} queued` : ''}
                  </Box>
                )}
              </Box>
            </Tooltip>
          )
        }
        return (
          <Stack direction="row" spacing={0.8} alignItems="baseline">
            {running > 0 && (
              <Tooltip title={`${running} task(s) this agent has taken and is running`}>
                <Box sx={{ color: neon.cyan, fontWeight: 600 }}>
                  {running} running
                </Box>
              </Tooltip>
            )}
            {queued > 0 && (
              // Spelled out rather than a bare "+N". Work addressed to
              // this agent by name sits here until it finishes what it
              // has; an unlabelled number next to another number is a
              // puzzle, not a status.
              <Tooltip title={`${queued} task(s) addressed to this agent by name, waiting for it`}>
                <Box sx={{ color: neon.yellow, fontSize: 11.5 }}>
                  {running > 0 ? '· ' : ''}{queued} queued
                </Box>
              </Tooltip>
            )}
          </Stack>
        )
      },
    },
    {
      // What this agent decided it can run, and why. Shown because the
      // alternative is an operator raising the project ceiling to 16,
      // seeing nothing change, and having no way to find out that the
      // box had 900 MB free.
      field: 'max_parallel', headerName: 'Parallel', width: 104,
      renderCell: (p) => {
        const eff = (p.value as number) ?? 1
        const own = p.row.capacity
        return (
          <Tooltip title={own == null
            ? 'This agent has not reported an assessment of its host yet, so it is held to one task at a time.'
            : `${own} by its own assessment (${p.row.capacity_reason || 'no reason given'}). `
              + `The project's ceiling and that are combined, and the lower runs.`}>
            <Box sx={{ color: eff > 1 ? neon.green : neon.muted,
                       fontWeight: 600 }}>
              {eff}
              {own != null && own !== eff && (
                <Box component="span" sx={{ color: neon.muted,
                                            fontWeight: 400, fontSize: 11 }}>
                  {' '}of {own}
                </Box>
              )}
            </Box>
          </Tooltip>
        )
      },
    },
    {
      field: 'completed_tasks', headerName: 'Completed', width: 116,
      renderCell: (p) => {
        const done = p.value as number
        const failed = p.row.failed_tasks
        if (!done && !failed) {
          return <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
        }
        return (
          <Stack direction="row" spacing={0.7} alignItems="baseline">
            <Box sx={{ color: done ? neon.green : alpha(neon.muted, 0.5),
                       fontWeight: done ? 600 : 400 }}>
              {done}
            </Box>
            {failed > 0 && (
              // Shown next to the successes, not hidden. An agent with
              // nothing completed and a column of failures reads as
              // idle unless the failures are on screen beside them.
              <Tooltip title={`${failed} task(s) failed on this agent`}>
                <Box sx={{ color: neon.red, fontSize: 11.5 }}>
                  &minus;{failed}
                </Box>
              </Tooltip>
            )}
          </Stack>
        )
      },
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
      // Not a detail. An agent that is not sealing sends a client's
      // findings over the wire protected only by the transport, and
      // nothing else in this table would say so.
      field: 'sealed', headerName: 'Encrypted', width: 112,
      renderCell: (p) => {
        if (!p.row.has_identity) {
          return (
            <Tooltip title="Enrolled before end-to-end encryption existed; it authenticates with a bearer key and its payload is protected only by TLS. Re-enroll to fix.">
              <Chip size="small" label="legacy" sx={{ height: 18, fontSize: 10,
                color: neon.red, bgcolor: alpha(neon.red, 0.12) }} />
            </Tooltip>
          )
        }
        return p.value ? (
          <Tooltip title="Payload sealed end to end under keys exchanged at enrollment — unreadable even to a TLS-terminating proxy in between">
            <Chip size="small" label="sealed" sx={{ height: 18, fontSize: 10,
              color: neon.green, bgcolor: alpha(neon.green, 0.12) }} />
          </Tooltip>
        ) : (
          <Tooltip title="Signed but not sealed: results are protected only by whatever TLS is between this agent and Oddjob. Re-enroll to establish an encrypted channel.">
            <Chip size="small" label="TLS only" sx={{ height: 18, fontSize: 10,
              color: neon.yellow, bgcolor: alpha(neon.yellow, 0.14) }} />
          </Tooltip>
        )
      },
    },
    {
      field: 'regions', headerName: 'Regions', width: 134,
      sortable: false,
      valueGetter: (v) => (v as string[] | undefined)?.join(', ') ?? '',
      renderCell: (p) => {
        const set = (p.row.regions ?? []) as string[]
        if (set.length) {
          return <Box sx={{ color: neon.purple, fontSize: 12 }}>{set.join(', ')}</Box>
        }
        // "all" is true in mesh and primary, where regions are never
        // consulted. It is false in geo, where an agent with none set
        // matches no region-tagged task at all — labelling that "all"
        // would be a lie in precisely the mode the field exists for.
        if (routing?.mode === 'geo') {
          return (
            <Tooltip title="This project routes by region and this agent serves none, so it will never be given region-tagged work. Edit it to set some.">
              <Chip size="small" label="none set" sx={{ height: 18, fontSize: 10,
                color: neon.red, bgcolor: alpha(neon.red, 0.12) }} />
            </Tooltip>
          )
        }
        return (
          <Tooltip title="No regions set, and this project does not route by region — so it is eligible for anything.">
            <Box sx={{ color: neon.muted, fontSize: 12 }}>all</Box>
          </Tooltip>
        )
      },
    },
    {
      field: 'actions', headerName: '', width: 86, sortable: false,
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
          <Stack direction="row" spacing={0.2}>
            <Tooltip title="Edit this Drone">
              <IconButton size="small" onClick={() => setEditing(p.row)}>
                <EditIcon sx={{ fontSize: 16, color: neon.cyan }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Kill this Drone">
              <IconButton size="small" onClick={() => setConfirmKill(p.row)}>
                <PowerSettingsNewIcon sx={{ fontSize: 17, color: neon.red }} />
              </IconButton>
            </Tooltip>
          </Stack>
        )
      },
    },
  ]

  if (!project) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">
          A Drone belongs to exactly one project — its key works only there,
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
        tableId="drones"
        initialSort={{ field: 'name', sort: 'asc' }}
        note={`Each Drone is sealed to ${project}: it authenticates to this ` +
              `Oddjob alone, takes tasking only from ${project}, and ` +
              `everything it finds imports into ${project}.`}
        extraActions={
          <Stack direction="row" spacing={1} alignItems="center">
            {canWrite(project) && (
              <Button size="small" startIcon={<AddIcon />}
                onClick={() => setWizard(true)}
                sx={{ color: neon.green }}>
                Deploy a Drone
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

      {/* Under the fleet, because the question it answers comes second:
          what have I got, then what is it doing. */}
      <Box sx={{ mt: 3 }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                          letterSpacing: '0.14em', textTransform: 'uppercase',
                          color: neon.cyan, textShadow: glow(neon.cyan, 0.4),
                          mb: 1 }}>
          Tasks
        </Typography>
        <DroneTasksTable project={project} />
      </Box>

      {wizard && (
        <DeployWizard project={project} onClose={() => setWizard(false)} />
      )}

      {editing && (
        <EditAgentDialog project={project} agent={editing}
          mode={routing?.mode} onClose={() => setEditing(null)} />
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
