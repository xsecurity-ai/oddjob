/**
 * What a site admin needs when something is not working.
 *
 * One screen, because the question is never about one subsystem.
 * "Nobody got the report" is a question about SMTP, the report runner
 * and the scheduler at once, and three screens to check is how the one
 * that matters gets skipped.
 *
 * **Four states, not two.** Working, not-lately, broken, and
 * never-used. A Slack integration nothing has ever sent through is not
 * healthy and is not failing, and colouring it green or red are both
 * lies — one of which gets somebody paged at 3am and the other of which
 * teaches people to stop looking at the page.
 *
 * The audit trail lives here rather than on its own screen for the same
 * reason: "when did this start" is the next question after every single
 * row above it, and it should not be a navigation.
 */
import { useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Collapse, Divider, IconButton,
  LinearProgress, MenuItem, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import RefreshIcon from '@mui/icons-material/Refresh'
import DownloadIcon from '@mui/icons-material/Download'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ExpandLessIcon from '@mui/icons-material/ExpandLess'
import SearchIcon from '@mui/icons-material/Search'
import { useQuery } from '@tanstack/react-query'
import { api, type AuditFilter, type HealthBlock, type HealthState } from '../lib/api'
import { neon, glow } from '../theme'

/** Colour carries the state, but never alone — the chip is always
 *  labelled. A red dot means nothing to someone who cannot see red, and
 *  "failing" means the same thing to everybody. */
const STATE: Record<HealthState, { colour: string; label: string }> = {
  ok: { colour: neon.green, label: 'ok' },
  idle: { colour: neon.yellow, label: 'idle' },
  failing: { colour: neon.red, label: 'failing' },
  // Grey, and worded as a fact rather than a verdict. "never used" is
  // not a degree of healthy.
  unused: { colour: neon.muted, label: 'never used' },
}

function ago(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return 'never'
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

function when(iso?: string | null): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function StateChip({ state }: { state: HealthState }) {
  const s = STATE[state] ?? STATE.unused
  return (
    <Chip size="small" label={s.label}
      sx={{
        height: 20, fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase',
        fontFamily: `'Orbitron', sans-serif`,
        color: s.colour, borderColor: alpha(s.colour, 0.5),
        backgroundColor: alpha(s.colour, 0.12),
      }} variant="outlined" />
  )
}

function Card({ title, state, lines, error, children }: {
  title: string
  state: HealthState
  lines: Array<[string, React.ReactNode]>
  /** Shown even when the state is ok. An error an hour ago that has
   *  since recovered is exactly what someone debugging wants, and
   *  hiding it the moment things recover is how an intermittent fault
   *  stays invisible for a month. */
  error?: string | null
  children?: React.ReactNode
}) {
  return (
    <Paper elevation={0} sx={{
      p: 2, minWidth: 260, flex: '1 1 300px',
      backgroundColor: alpha(neon.paper, 0.75), backdropFilter: 'blur(6px)',
      border: `1px solid ${alpha(STATE[state]?.colour ?? neon.purple, 0.35)}`,
    }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.2 }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.14em',
          textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.4),
        }}>{title}</Typography>
        <StateChip state={state} />
      </Stack>
      <Stack spacing={0.4}>
        {lines.map(([k, v]) => (
          <Stack key={k} direction="row" justifyContent="space-between" spacing={2}>
            <Typography sx={{ fontSize: 12, opacity: 0.65 }}>{k}</Typography>
            <Typography sx={{ fontSize: 12, textAlign: 'right', wordBreak: 'break-word' }}>
              {v}
            </Typography>
          </Stack>
        ))}
      </Stack>
      {error ? (
        <Alert severity="warning" sx={{ mt: 1.2, py: 0, fontSize: 11 }}>
          last error: {error}
        </Alert>
      ) : null}
      {children}
    </Paper>
  )
}

/** A subsystem's three counters, rendered the same way everywhere. */
function counts(b: HealthBlock): Array<[string, React.ReactNode]> {
  return [
    ['last ok', b.last_ok ? when(b.last_ok) : 'never'],
    ['sent / failed', `${b.ok_count ?? 0} / ${b.error_count ?? 0}`],
  ]
}

export function HealthView() {
  const [showAudit, setShowAudit] = useState(false)

  // 15s: fast enough that an admin watching a restart sees it come back,
  // slow enough that leaving the tab open is not a load generator.
  const health = useQuery({
    queryKey: ['site-health'],
    queryFn: api.siteHealth,
    refetchInterval: 15_000,
  })

  if (health.isLoading) {
    return <Box sx={{ p: 4 }}><CircularProgress size={22} /></Box>
  }
  if (health.error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Could not read site health: {(health.error as Error).message}
      </Alert>
    )
  }
  const h = health.data!
  const db = h.database
  const dr = h.drones

  return (
    // Scrolls itself. The app shell sets `overflow: hidden` on body
    // because every other view is a grid that scrolls its own viewport
    // — but this one is a document: cards, then an audit table that is
    // 520px tall the moment it is expanded. Without a scroller of its
    // own, everything past the fold was simply unreachable.
    //
    // `minHeight: 0` as well as the overflow, or the flex parent in
    // App.tsx sizes this to its content and there is nothing to
    // scroll: a flex child's default `min-height: auto` refuses to
    // shrink below its contents, so the overflow never triggers.
    <Box sx={{ p: 2, flex: 1, minHeight: 0, overflowY: 'auto' }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 13, letterSpacing: '0.18em',
          textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
        }}>Site health</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography sx={{ fontSize: 11, opacity: 0.55 }}>
            checked {when(h.generated_at)}
          </Typography>
          <Tooltip title="Check again now">
            <IconButton size="small" onClick={() => health.refetch()}>
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </Stack>
      {health.isFetching ? <LinearProgress sx={{ mb: 1, height: 2 }} /> : null}

      <Stack direction="row" flexWrap="wrap" gap={1.5}>
        <Card title="Database" state={db.state}
          error={db.last_error as string | null}
          lines={[
            ['engine', db.dialect ?? '—'],
            ['latency', db.latency_ms !== undefined ? `${db.latency_ms} ms` : '—'],
            ['size', db.size ?? '—'],
            ['pool in use', db.pool ? `${db.pool.checked_out} of ${db.pool.checked_out + db.pool.in_pool}` : '—'],
            ['targets', db.rows?.targets?.toLocaleString() ?? '—'],
            ['findings', db.rows?.findings?.toLocaleString() ?? '—'],
          ]} />

        <Card title="CVE feed (NVD)" state={h.cve_feed.state}
          error={h.cve_feed.last_error as string | null}
          lines={[
            ['records', h.cve_feed.records?.toLocaleString() ?? '—'],
            ['last updated', h.cve_feed.synced ? when(h.cve_feed.synced) : 'never'],
            ['age', ago(h.cve_feed.age_seconds)],
            ['syncing now', h.cve_feed.running ? 'yes' : 'no'],
          ]}>
          {h.cve_feed.note ? (
            <Typography sx={{ fontSize: 11, opacity: 0.7, mt: 1 }}>{h.cve_feed.note}</Typography>
          ) : null}
        </Card>

        <Card title="Exploits (searchsploit)" state={h.exploit_feed.state}
          error={h.exploit_feed.last_error as string | null}
          lines={[
            ['records', h.exploit_feed.records?.toLocaleString() ?? '—'],
            ['last updated', h.exploit_feed.synced ? when(h.exploit_feed.synced) : 'never'],
            ['age', ago(h.exploit_feed.age_seconds)],
            ['syncing now', h.exploit_feed.running ? 'yes' : 'no'],
          ]}>
          {h.exploit_feed.note ? (
            <Typography sx={{ fontSize: 11, opacity: 0.7, mt: 1 }}>{h.exploit_feed.note}</Typography>
          ) : null}
        </Card>

        <Card title="Slack" state={h.slack.state}
          error={h.slack.last_error as string | null}
          lines={[
            ['configured', h.slack.configured ? 'yes' : 'no'],
            ...counts(h.slack),
            ['last send', h.slack.last_detail ?? '—'],
            ['socket', h.slack_socket.connected ? 'connected' : (h.slack_socket.last ?? 'not connected')],
          ]}>
          {h.slack.note ? (
            <Typography sx={{ fontSize: 11, opacity: 0.7, mt: 1 }}>{h.slack.note}</Typography>
          ) : null}
        </Card>

        <Card title="Email (SMTP)" state={h.smtp.state}
          error={h.smtp.last_error as string | null}
          lines={[
            ['host', h.smtp.host ?? 'not set'],
            ...counts(h.smtp),
            ['last subject', h.smtp.last_detail ?? '—'],
          ]}>
          {h.smtp.note ? (
            <Typography sx={{ fontSize: 11, opacity: 0.7, mt: 1 }}>{h.smtp.note}</Typography>
          ) : null}
        </Card>

        <Card title="Drones" state={dr.state}
          lines={[
            ['online', String((dr.by_state?.online ?? 0) + (dr.by_state?.busy ?? 0))],
            ['offline', String(dr.by_state?.offline ?? 0)],
            ['disabled', String(dr.by_state?.disabled ?? 0)],
            ['running', String(dr.queue?.running ?? 0)],
            ['queued', String(dr.queue?.queued ?? 0)],
            ['failed', String(dr.queue?.failed ?? 0)],
          ]}>
          {dr.queued_over_an_hour ? (
            <Alert severity="warning" sx={{ mt: 1.2, py: 0, fontSize: 11 }}>
              {dr.queued_over_an_hour} task(s) queued over an hour — no drone has
              taken them
            </Alert>
          ) : null}
          {dr.note ? (
            <Typography sx={{ fontSize: 11, opacity: 0.7, mt: 1 }}>{dr.note}</Typography>
          ) : null}
        </Card>

        <Card title="Server" state="ok"
          lines={[
            ['started', when(h.server.started_at)],
            ['uptime', ago(h.server.uptime_seconds)],
            ['live subscribers', String(h.server.sse_subscribers)],
            ['audit newest', h.audit.newest ? ago(h.audit.age_seconds as number) : 'nothing recorded'],
            ['audit retention', `${String(h.audit.retain_days ?? '?')} days`],
          ]} />
      </Stack>

      <Divider sx={{ my: 2, borderColor: alpha(neon.purple, 0.25) }} />

      <Button
        size="small" variant="outlined"
        startIcon={showAudit ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        onClick={() => setShowAudit((v) => !v)}
        sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.1em' }}
      >
        {showAudit ? 'Hide audit log' : 'View audit logs'}
      </Button>

      <Collapse in={showAudit} mountOnEnter>
        <AuditTable />
      </Collapse>
    </Box>
  )
}

/** The log, searchable. Server-side: the table is capped by retention,
 *  not by what fits in a browser, and filtering 200,000 rows in the
 *  client is how a debugging tool becomes the thing that needs
 *  debugging. */
function AuditTable() {
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [action, setAction] = useState('')
  const [username, setUsername] = useState('')
  const [hours, setHours] = useState<number | ''>('')
  const [limit, setLimit] = useState(200)

  const filter: AuditFilter = {
    q: q.trim() || undefined,
    source: source || undefined,
    action: action.trim() || undefined,
    username: username.trim() || undefined,
    hours: hours === '' ? undefined : hours,
    limit,
  }

  const log = useQuery({
    queryKey: ['audit', filter],
    queryFn: () => api.auditLog(filter),
  })

  const SOURCES = ['ui', 'backend', 'middleware', 'drone', 'agent']

  return (
    <Box sx={{ mt: 1.5 }}>
      <Stack direction="row" flexWrap="wrap" gap={1} alignItems="center" sx={{ mb: 1 }}>
        <TextField
          size="small" placeholder="search action, user, detail, path, ip…"
          value={q} onChange={(e) => setQ(e.target.value)}
          InputProps={{ startAdornment: <SearchIcon fontSize="small" sx={{ mr: 0.8, opacity: 0.5 }} /> }}
          sx={{ minWidth: 300, flex: '1 1 300px' }}
        />
        <TextField select size="small" label="source" value={source}
          onChange={(e) => setSource(e.target.value)} sx={{ minWidth: 130 }}>
          <MenuItem value="">any</MenuItem>
          {SOURCES.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
        </TextField>
        <TextField size="small" label="action starts with" value={action}
          onChange={(e) => setAction(e.target.value)} sx={{ minWidth: 150 }} />
        <TextField size="small" label="user" value={username}
          onChange={(e) => setUsername(e.target.value)} sx={{ minWidth: 120 }} />
        <TextField select size="small" label="window" value={hours}
          onChange={(e) => setHours(e.target.value === '' ? '' : Number(e.target.value))}
          sx={{ minWidth: 120 }}>
          <MenuItem value="">all</MenuItem>
          <MenuItem value={1}>last hour</MenuItem>
          <MenuItem value={24}>last day</MenuItem>
          <MenuItem value={168}>last week</MenuItem>
        </TextField>
        <TextField select size="small" label="rows" value={limit}
          onChange={(e) => setLimit(Number(e.target.value))} sx={{ minWidth: 100 }}>
          {[100, 200, 500, 1000, 5000].map((n) => <MenuItem key={n} value={n}>{n}</MenuItem>)}
        </TextField>
        {/* A plain link, not a fetch: it carries the same filters, so the
            file matches the table on screen rather than being a second,
            differently-shaped export of everything. */}
        <Button
          size="small" variant="outlined" startIcon={<DownloadIcon />}
          component="a" href={api.auditCsvUrl(filter)}
          sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11 }}
        >Export CSV</Button>
      </Stack>

      {log.isFetching ? <LinearProgress sx={{ height: 2, mb: 1 }} /> : null}
      {log.error ? (
        <Alert severity="error">{(log.error as Error).message}</Alert>
      ) : null}

      <Typography sx={{ fontSize: 11, opacity: 0.6, mb: 0.8 }}>
        {log.data
          ? `${log.data.entries.length} shown${log.data.next_before ? ' (more available — narrow the search or raise the row count)' : ''}`
          + ` · retained ${log.data.retain_days} days`
          : ''}
      </Typography>

      <TableContainer component={Paper} elevation={0} sx={{
        maxHeight: 520,
        backgroundColor: alpha(neon.paper, 0.6),
        border: `1px solid ${alpha(neon.purple, 0.25)}`,
      }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              {['when', 'source', 'action', 'user', 'ip', 'status', 'detail'].map((c) => (
                <TableCell key={c} sx={{
                  fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
                  letterSpacing: '0.1em', textTransform: 'uppercase',
                  backgroundColor: alpha(neon.paper, 0.95),
                }}>{c}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {(log.data?.entries ?? []).map((e) => (
              <TableRow key={e.id} hover>
                <TableCell sx={{ fontSize: 11, whiteSpace: 'nowrap' }}>{when(e.at)}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{e.source}</TableCell>
                <TableCell sx={{ fontSize: 11, whiteSpace: 'nowrap' }}>{e.action}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{e.username ?? '—'}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{e.ip ?? '—'}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>
                  {e.status ?? '—'}{e.ms !== null ? ` · ${e.ms}ms` : ''}
                </TableCell>
                <TableCell sx={{ fontSize: 11, maxWidth: 420 }}>
                  {e.detail || e.path || '—'}
                </TableCell>
              </TableRow>
            ))}
            {log.data && log.data.entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} sx={{ fontSize: 12, opacity: 0.6, py: 3, textAlign: 'center' }}>
                  Nothing matches. That is a statement about this window and
                  these filters, not about the installation.
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  )
}
