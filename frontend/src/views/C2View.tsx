/**
 * Shell sessions a Ghost caught, and a terminal to use one.
 *
 * **Active by default**, because the question on opening this page is
 * almost always "what can I type at right now". Closed and lost
 * sessions are one tick away and are never deleted: what was done on
 * a host is part of the engagement record, and it is the part that
 * otherwise lives in somebody's terminal scrollback and then is gone.
 *
 * Every keystroke sent and every byte returned is stored against the
 * target. That is the whole reason to run a shell through here rather
 * than through netcat on a laptop.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, IconButton, MenuItem, Stack, Switch, Tab,
  Tabs, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutlined'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  api, type C2Exchange, type C2Listener, type C2Session, type GhostAgent,
} from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { PortPicker } from '../components/PortPicker'
import type { ColumnDef } from '../lib/columns'
import { neon, glow, blink, TAB_SX } from '../theme'
import { key, readingSession, useUnseenSessions } from '../lib/c2unseen'

/** How often an open session re-reads its tail. A shell is
 *  interactive and SSE carries the nudge, but a poll is what makes it
 *  correct when a nudge is missed. */
const POLL_MS = 1500

const STATE_COLOUR: Record<string, string> = {
  open: neon.green,
  lost: neon.yellow,
  closed: neon.muted,
}

/** What a session is called. The label if somebody named one, else
 *  the host, else the address it called from — never a bare id, which
 *  tells an operator nothing about which box they are on. */
function title(s: C2Session): string {
  return s.label || s.host || s.peer || `session ${s.id}`
}

export function C2View({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const [tab, setTab] = useState<'sessions' | 'listeners'>('sessions')
  const [activeOnly, setActiveOnly] = useState(true)
  const [open, setOpen] = useState<number | null>(null)
  const [setup, setSetup] = useState(false)

  const sessions = useQuery({
    queryKey: ['c2-sessions', project, activeOnly],
    queryFn: () => api.c2Sessions(project as string, activeOnly),
    enabled: !!project,
    refetchInterval: POLL_MS * 4,
  })
  const rows = useMemo(() => sessions.data ?? [], [sessions.data])

  // Keep the selection on a session that still exists, and land on
  // the newest when nothing is chosen.
  useEffect(() => {
    if (!rows.length) { setOpen(null); return }
    setOpen((cur) => (cur !== null && rows.some((r) => r.id === cur)
                      ? cur : rows[0].id))
  }, [rows])
  useEffect(() => { setOpen(null) }, [project])

  // Having a session on screen is reading it, so it stops
  // blinking; leaving the page means whatever it says next is
  // unread again and the nav item picks it up. Above the early
  // return below, like every other hook here.
  useEffect(() => {
    if (!project) return
    readingSession(project, open)
    return () => readingSession(project, null)
  }, [project, open])

  if (!project) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12.5 }}>
          Choose an engagement in the header. A shell belongs to one
          project and cannot be borrowed by another.
        </Alert>
      </Box>
    )
  }

  const chosen = rows.find((r) => r.id === open) ?? null

  return (
    <Stack sx={{ flex: 1, minHeight: 0 }}>
      <Stack direction="row" spacing={1.5}
        sx={{ alignItems: 'center', px: 2, py: 1.2,
              borderBottom: `1px solid ${alpha(neon.cyan, 0.22)}` }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                          letterSpacing: '0.16em', color: neon.cyan,
                          textShadow: glow(neon.cyan, 0.5) }}>C2</Typography>
        <Chip size="small" label={project} sx={{
          height: 18, fontSize: 10, bgcolor: alpha(neon.pink, 0.14),
          color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.45)}` }} />
        <Tabs value={tab} onChange={(_e, v) => setTab(v)}
          sx={{ minHeight: 34 }}>
          <Tab value="sessions" label="Sessions" sx={TAB_SX} />
          {/* Its own tab, not a panel beside the terminal: "which
              ghost is listening on which port" is a question asked
              while nothing has called back yet, which is exactly
              when the Sessions list is empty. */}
          <Tab value="listeners" label="Listeners" sx={TAB_SX} />
        </Tabs>
        <Box sx={{ flex: 1 }} />
        {tab === 'sessions' && (
          <Tooltip title="Closed and lost sessions are kept for the record —
                          what was done on a host is part of the engagement.">
            <Stack direction="row" spacing={0.5} sx={{ alignItems: 'center' }}>
              <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                active only
              </Typography>
              <Switch size="small" checked={activeOnly}
                onChange={(e) => setActiveOnly(e.target.checked)} />
            </Stack>
          </Tooltip>
        )}
        {canWrite(project) && (
          <Button size="small" variant="outlined" startIcon={<AddIcon />}
            onClick={() => setSetup(true)}
            sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
            Set up a listener
          </Button>
        )}
      </Stack>

      {tab === 'sessions' ? (
        <Stack direction="row" sx={{ flex: 1, minHeight: 0 }}>
          <SessionList rows={rows} loading={sessions.isLoading}
            error={sessions.error as Error | null} project={project}
            activeOnly={activeOnly} open={open} onOpen={setOpen} />
          {chosen
            ? <Terminal key={chosen.id} project={project} session={chosen}
                onChanged={() => void qc.invalidateQueries(
                  { queryKey: ['c2-sessions', project] })} />
            : (
              <Box sx={{ flex: 1, p: 3 }}>
                <Typography sx={{ fontSize: 12.5, color: neon.muted,
                                  lineHeight: 1.8 }}>
                  No session is open. A Ghost holding a listener files one
                  here the moment something calls back, and goes straight
                  back to listening — so a shell that dies and a payload
                  that retries give you a second session rather than
                  silence.
                </Typography>
              </Box>
            )}
        </Stack>
      ) : (
        <ListenersTab project={project} />
      )}

      {setup && (
        <SetupListenerDialog project={project}
          onClose={() => setSetup(false)} />
      )}
    </Stack>
  )
}

// ------------------------------------------------------------ listeners

const STATE_WORDS: Record<string, string> = {
  bound: 'listening',
  failed: 'did not bind',
  pending: 'waiting for the ghost',
}

/** Which Ghost is holding which port.
 *
 *  The column that matters is `state`, and it has three values
 *  because there are three answers. `pending` is not a quiet failure:
 *  the Ghost has not reported, which happens for a few seconds after
 *  every change and indefinitely while it is offline. Collapsing that
 *  into a red cross would send somebody to debug a port that is fine.
 */
function ListenersTab({ project }: { project: string }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const rows = useQuery({
    queryKey: ['c2-listeners', project],
    queryFn: () => api.c2Listeners(project),
    refetchInterval: 5000,
  })
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['c2-listeners', project] })
  }
  const toggle = useMutation({
    mutationFn: (l: C2Listener) =>
      api.c2PatchListener(project, l.id, { enabled: !l.enabled }),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: (l: C2Listener) => api.c2DeleteListener(project, l.id),
    onSuccess: refresh,
  })

  const columns: ColumnDef<C2Listener>[] = [
    { field: 'agent_name', headerName: 'Ghost', flex: 1, minWidth: 140,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.7} sx={{ alignItems: 'center' }}>
          <Tooltip title={p.row.agent_online
            ? 'This server is holding its shell tunnel.'
            : 'No shell tunnel to this ghost right now. Its ports may '
              + 'well be bound; nothing it catches can reach us until '
              + 'the tunnel is back.'}>
            <Box sx={{ width: 7, height: 7, borderRadius: '50%',
                       flexShrink: 0,
                       bgcolor: p.row.agent_online ? neon.green : neon.muted,
                       boxShadow: p.row.agent_online
                         ? glow(neon.green, 0.8) : undefined }} />
          </Tooltip>
          <Box>{p.row.agent_name ?? '—'}</Box>
        </Stack>
      ) },
    { field: 'protocol', headerName: 'Proto', width: 80,
      type: 'singleSelect', valueOptions: ['tcp', 'udp'] },
    { field: 'port', headerName: 'Port', width: 90, type: 'number' },
    { field: 'state', headerName: 'State', width: 190,
      renderCell: (p) => {
        const colour = p.row.state === 'bound' ? neon.green
          : p.row.state === 'failed' ? neon.red : neon.muted
        return (
          <Tooltip title={p.row.state_detail
            ?? (p.row.state === 'pending'
              ? 'Configured here; the ghost picks it up on its next '
                + 'heartbeat and says whether it bound.'
              : '')}>
            <Box sx={{ color: colour }}>
              {p.row.enabled
                ? STATE_WORDS[p.row.state] ?? p.row.state
                : 'off'}
              {p.row.state === 'failed' && p.row.state_detail
                ? ` — ${p.row.state_detail}` : ''}
            </Box>
          </Tooltip>
        )
      } },
    // Whether the listener has ever done its job. A port bound for a
    // week with nothing on it is worth noticing.
    { field: 'sessions', headerName: 'Shells', width: 90, type: 'number' },
    { field: 'note', headerName: 'Note', flex: 1, minWidth: 120,
      valueGetter: (v) => v ?? '' },
    { field: 'actions', headerName: '', width: 96, sortable: false,
      filterable: false,
      renderCell: (p) => {
        if (!canWrite(project)) return null
        return (
          <Stack direction="row" spacing={0.3}>
            <Tooltip title={p.row.enabled
              ? 'Stop holding this port. The row stays, so it can be '
                + 'switched back on.'
              : 'Hold this port again.'}>
              <Switch size="small" checked={p.row.enabled}
                onChange={() => toggle.mutate(p.row)} />
            </Tooltip>
            <Tooltip title="Remove it. The shells it caught are kept —
                            they are evidence about a host, not about
                            the configuration that caught them.">
              <IconButton size="small" onClick={() => remove.mutate(p.row)}>
                <DeleteIcon sx={{ fontSize: 15, color: neon.muted }} />
              </IconButton>
            </Tooltip>
          </Stack>
        )
      } },
  ]

  return (
    // `display: flex` AND a real height, because DataTable sizes
    // itself with `flex: 1; min-height: 0; overflow: hidden` and all
    // of that needs a flex parent that has one. `minHeight: 0` is
    // not a height -- it is what lets a flex child shrink -- so it
    // is here as well as, not instead of, `height: '100%'`. In a
    // plain block parent the table silently loses its last rows.
    // See test/table.scroll.check.mjs and the DataTable check in
    // test/logic.test.ts.
    <Box sx={{ flex: 1, height: '100%', minHeight: 0, display: 'flex',
               flexDirection: 'column', p: 1.5 }}>
      <DataTable
        rows={rows.data ?? []}
        columns={columns}
        loading={rows.isLoading}
        error={rows.error as Error | null}
        tableId="c2-listeners"
        initialSort={{ field: 'port', sort: 'asc' }}
        note={'A listener is a port a ghost holds open so a payload has '
              + 'somewhere to call back to. The ghost picks changes up on '
              + 'its next heartbeat, so a new one reads “waiting for the '
              + 'ghost” for a few seconds.'} />
    </Box>
  )
}

/** Opening ports on a ghost.
 *
 *  Several at once and both protocols, because an operator setting
 *  up a catch opens the handful of ports a client's egress is likely
 *  to allow rather than one, then another.
 */
function SetupListenerDialog({ project, onClose }: {
  project: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const ghosts = useQuery({
    queryKey: ['ghost-agents', project],
    queryFn: () => api.agents(project),
  })
  const usable = useMemo(
    () => (ghosts.data ?? []).filter((g: GhostAgent) => g.status !== 'disabled'),
    [ghosts.data])
  const [agent, setAgent] = useState<number | ''>('')
  const [tcp, setTcp] = useState<number[]>([])
  const [udp, setUdp] = useState<number[]>([])
  const [note, setNote] = useState('')
  const [said, setSaid] = useState<string[]>([])

  useEffect(() => {
    if (agent === '' && usable.length) setAgent(usable[0].id)
  }, [usable, agent])

  const save = useMutation({
    mutationFn: async () => {
      const refused: string[] = []
      for (const [protocol, ports] of
        [['tcp', tcp], ['udp', udp]] as ['tcp' | 'udp', number[]][]) {
        if (!ports.length) continue
        const r = await api.c2AddListeners(project, {
          agent_id: agent as number, protocol, ports,
          note: note.trim() || undefined,
        })
        refused.push(...r.refused)
      }
      return refused
    },
    onSuccess: (refused) => {
      void qc.invalidateQueries({ queryKey: ['c2-listeners', project] })
      // Closed only when everything landed. A dialog that closes on
      // a partial refusal is a dialog that silently did less than it
      // was asked to.
      if (!refused.length) { onClose(); return }
      setSaid(refused)
    },
  })

  const nothing = !tcp.length && !udp.length

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ color: neon.cyan }}>Set up a listener</DialogTitle>
      <DialogContent>
        <Stack spacing={2.2} sx={{ mt: 0.5 }}>
          <Typography sx={{ fontSize: 12.5, color: neon.muted,
                            lineHeight: 1.7 }}>
            The ghost binds these on its own host and holds them open.
            Anything that calls back lands here as a session, and the
            ghost goes straight back to listening — so a payload that
            retries gives you a second shell rather than silence.
          </Typography>

          {!ghosts.isLoading && !usable.length && (
            <Alert severity="warning" sx={{ fontSize: 12 }}>
              This engagement has no ghost that could hold a port. Deploy
              one from the Ghosts page first — Oddjob itself never
              listens for a callback, because a listener on this server
              is a listener on the thing holding the engagement's data.
            </Alert>
          )}

          <TextField select size="small" label="Ghost" value={agent}
            disabled={!usable.length}
            helperText="Where the port is opened. A ghost is tied to one
                        engagement and cannot be borrowed by another."
            onChange={(e) => setAgent(Number(e.target.value))}>
            {usable.map((g: GhostAgent) => (
              <MenuItem key={g.id} value={g.id}>
                {g.name}{g.status === 'online' ? '' : ` (${g.status})`}
              </MenuItem>
            ))}
          </TextField>

          <PortPicker label="TCP ports" value={tcp} onChange={setTcp}
            help="A client's egress is usually filtered to browser ports,
                  so a callback on 47000 is refused by their firewall and
                  the test then measures the firewall." />
          <PortPicker label="UDP ports" value={udp} onChange={setUdp}
            help="For a payload that can only reach you over UDP." />

          <TextField size="small" label="Note" value={note}
            helperText="Which payload this is for, for whoever reads it later."
            onChange={(e) => setNote(e.target.value)} />

          {said.length > 0 && (
            <Alert severity="warning" sx={{ fontSize: 12 }}
              onClose={() => setSaid([])}>
              {said.map((w) => <Box key={w}>{w}</Box>)}
            </Alert>
          )}
          {save.error ? (
            <Alert severity="error" sx={{ fontSize: 12 }}>
              {String(save.error)}
            </Alert>
          ) : null}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button disabled={save.isPending || nothing || agent === ''}
          onClick={() => save.mutate()} sx={{ color: neon.green }}>
          {save.isPending ? 'Asking the ghost…' : 'Open these ports'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

function SessionList({ rows, loading, error, project, activeOnly, open,
                      onOpen }: {
  rows: C2Session[]
  loading: boolean
  error: Error | null
  project: string
  activeOnly: boolean
  open: number | null
  onOpen: (id: number) => void
}) {
  // One subscription for the list rather than one per row: the set is
  // the same object for every row and a hook inside `rows.map` would
  // not be a hook at a stable position anyway.
  const unseen = useUnseenSessions()
  return (
    <Stack sx={{ width: 320, flexShrink: 0, minHeight: 0, overflowY: 'auto',
                 borderRight: `1px solid ${alpha(neon.cyan, 0.22)}` }}>
      {loading && (
        <Stack sx={{ alignItems: 'center', py: 3 }}>
          <CircularProgress size={16} sx={{ color: neon.cyan }} />
        </Stack>
      )}
      {error && (
        <Alert severity="error" variant="outlined"
          sx={{ m: 1.5, fontSize: 11.5 }}>{error.message}</Alert>
      )}
      {!loading && !error && !rows.length && (
        <Typography sx={{ p: 2, fontSize: 11.5, color: neon.muted,
                          lineHeight: 1.7 }}>
          {activeOnly
            ? 'No live session. Untick “active only” to see ones that have '
              + 'ended — they are kept.'
            : 'Nothing has called back on this engagement yet.'}
        </Typography>
      )}
      {rows.map((s) => {
        const unread = unseen.has(key(project, s.id))
        return (
        <Box key={s.id} onClick={() => onOpen(s.id)}
          sx={{ px: 1.5, py: 1, cursor: 'pointer',
                borderBottom: `1px solid ${alpha(neon.purple, 0.14)}`,
                backgroundColor: s.id === open
                  ? alpha(neon.cyan, 0.1) : 'transparent',
                '&:hover': { backgroundColor: alpha(neon.cyan, 0.06) } }}>
          <Stack direction="row" spacing={0.8} sx={{ alignItems: 'center' }}>
            <Box sx={{ width: 7, height: 7, borderRadius: '50%',
                       flexShrink: 0,
                       bgcolor: STATE_COLOUR[s.state] ?? neon.muted,
                       boxShadow: s.state === 'open'
                         ? glow(neon.green, 0.8) : undefined }} />
            <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                       fontSize: 12, color: neon.text, overflow: 'hidden',
                       textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                       ...(unread ? blink(neon.green) : {}) }}>
              {title(s)}
            </Box>
          </Stack>
          <Stack direction="row" spacing={0.8}
            sx={{ alignItems: 'center', mt: 0.4, pl: 1.6 }}>
            <Box sx={{ fontSize: 10, color: neon.muted }}>
              {s.state}{s.agent_name ? ` · ${s.agent_name}` : ''}
            </Box>
            <Box sx={{ flex: 1 }} />
            {/* Open in the database and unreachable from here is a
                real and different state: the Ghost may have
                reconnected and not re-offered this stream. */}
            {s.state === 'open' && !s.connected && (
              <Tooltip title="Open, but this server is not holding its tunnel
                              right now. It should come back on its own.">
                <Box sx={{ fontSize: 9.5, color: neon.yellow }}>no route</Box>
              </Tooltip>
            )}
            {unread && (
              <Tooltip title="New output you have not read. Open it to
                              clear.">
                <Box sx={{ fontSize: 9.5, ...blink(neon.green) }}>new</Box>
              </Tooltip>
            )}
            <Box sx={{ fontSize: 10, color: alpha(neon.muted, 0.8) }}>
              {s.exchanges}
            </Box>
          </Stack>
        </Box>
        )
      })}
    </Stack>
  )
}

/** One session, as a terminal.
 *
 *  Deliberately not a pty emulator. What is shown is what was stored,
 *  which is what the shell actually sent -- control bytes and all --
 *  because the transcript is an engagement record and a tidied
 *  version of it is not what happened.
 */
function Terminal({ project, session, onChanged }: {
  project: string
  session: C2Session
  onChanged: () => void
}) {
  const [input, setInput] = useState('')
  const [said, setSaid] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement | null>(null)

  const tail = useQuery({
    queryKey: ['c2-transcript', project, session.id],
    queryFn: () => api.c2Transcript(project, session.id),
    // Polled while it is live. A closed session cannot gain lines,
    // so polling one would be asking a question with a known answer.
    refetchInterval: session.state === 'open' ? POLL_MS : false,
  })
  const lines = useMemo(() => tail.data ?? [], [tail.data])

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [lines])

  const send = useMutation({
    mutationFn: (data: string) => api.c2Send(project, session.id, data),
    onSuccess: (r) => {
      setInput('')
      setSaid(r.sent ? null : 'Accepted and recorded, but it could not be '
                            + 'sent — the tunnel is not up. The command is '
                            + 'in the transcript as attempted.')
      void tail.refetch()
      onChanged()
    },
    onError: (e) => setSaid((e as Error).message),
  })

  const live = session.state === 'open' && session.connected

  return (
    <Stack sx={{ flex: 1, minWidth: 0, minHeight: 0 }}>
      <Stack direction="row" spacing={1}
        sx={{ alignItems: 'center', px: 2, py: 1,
              borderBottom: `1px solid ${alpha(neon.purple, 0.2)}` }}>
        <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                   fontSize: 12.5, color: neon.cyan }}>{title(session)}</Box>
        {session.peer && (
          <Chip size="small" label={session.peer} sx={{
            height: 17, fontSize: 9.5, color: neon.muted,
            border: `1px solid ${alpha(neon.muted, 0.35)}` }} />
        )}
        <Chip size="small" label={session.state} sx={{
          height: 17, fontSize: 9.5,
          color: STATE_COLOUR[session.state] ?? neon.muted,
          border: `1px solid ${alpha(STATE_COLOUR[session.state]
                                     ?? neon.muted, 0.45)}` }} />
      </Stack>

      <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', px: 2, py: 1.5,
                 bgcolor: alpha('#000', 0.35),
                 fontFamily: `'Share Tech Mono', monospace`, fontSize: 12,
                 lineHeight: 1.55 }}>
        {tail.isLoading && (
          <CircularProgress size={14} sx={{ color: neon.cyan }} />
        )}
        {lines.map((e) => <Line key={e.id} e={e} />)}
        <div ref={endRef} />
      </Box>

      {said && (
        <Alert severity="warning" variant="outlined"
          sx={{ fontSize: 11.5, mx: 2, mb: 1 }} onClose={() => setSaid(null)}>
          {said}
        </Alert>
      )}

      <Box sx={{ px: 2, py: 1.2,
                 borderTop: `1px solid ${alpha(neon.cyan, 0.22)}` }}>
        <TextField fullWidth size="small" value={input} autoComplete="off"
          disabled={!live || send.isPending}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            // Enter sends. No Shift+Enter newline: a shell takes one
            // line at a time and a multi-line box would pretend
            // otherwise.
            if (e.key === 'Enter' && input.trim()) {
              e.preventDefault()
              send.mutate(input)
            }
          }}
          placeholder={live
            ? 'Type a command and press Enter…'
            : session.state === 'open'
              ? 'Open, but this server is not holding the tunnel right now.'
              : `This session is ${session.state}. The transcript is kept.`}
          slotProps={{ htmlInput: {
            style: { fontFamily: `'Share Tech Mono', monospace`,
                     fontSize: 12.5 } } }} />
      </Box>
    </Stack>
  )
}

function Line({ e }: { e: C2Exchange }) {
  return (
    <Box sx={{ mb: 0.4 }}>
      {e.command !== null && (
        <Box sx={{ color: neon.green, whiteSpace: 'pre-wrap',
                   wordBreak: 'break-all' }}>
          <Box component="span" sx={{ color: neon.pink }}>$ </Box>
          {e.command}
          {e.actor && (
            <Box component="span" sx={{ fontSize: 10,
                                        color: alpha(neon.muted, 0.8) }}>
              {'  '}— {e.actor}
            </Box>
          )}
        </Box>
      )}
      {e.output && (
        <Box sx={{ color: neon.text, whiteSpace: 'pre-wrap',
                   wordBreak: 'break-all' }}>{e.output}</Box>
      )}
    </Box>
  )
}
