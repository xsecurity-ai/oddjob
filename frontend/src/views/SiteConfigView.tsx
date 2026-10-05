import { useEffect, useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, MenuItem, Paper,
  Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import ScienceIcon from '@mui/icons-material/Science'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type SettingSpec } from '../lib/api'
import { neon, glow } from '../theme'
import { maybeSorted } from '../lib/sortOptions'

/**
 * Site configuration, rendered entirely from the spec the server serves.
 * Adding a setting is one entry in backend/app/settings_spec.py — no form
 * field here, no endpoint, no migration.
 *
 * Secrets are write-only. The server never sends the stored value, so the
 * field shows "stored" / "not set" and an empty box means "leave it alone".
 * Clearing one is an explicit act, because a blank-means-delete field would
 * wipe the Slack token every time somebody saved an unrelated checkbox.
 *
 * SMTP and Google credentials cannot be saved until a Test has passed
 * against the exact values in the form. The server enforces that — the
 * button below only mirrors it — because untested credentials fail at the
 * moment they are needed, which is always the worst moment.
 */

type Gate = 'smtp' | 'google' | 'postgres'
const GATES: Gate[] = ['smtp', 'google', 'postgres']
const GATE_LABEL: Record<Gate, string> = {
  smtp: 'SMTP', google: 'Google SSO', postgres: 'Postgres',
}

/** A pass, and the values it was a pass for. */
interface Pass { token: string; snapshot: string }

export function SiteConfigView() {
  const qc = useQueryClient()
  const { data, isLoading, error } = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const [draft, setDraft] = useState<Record<string, unknown>>({})
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err' | 'warn'; text: string } | null>(null)
  const [testTo, setTestTo] = useState('')
  const [busy, setBusy] = useState(false)
  const [passed, setPassed] = useState<Partial<Record<Gate, Pass>>>({})

  useEffect(() => { if (data) setDraft({ ...data.values }) }, [data])

  // The credential fields each Test covers. Mirrors GATE_KEYS on the server:
  // the on/off switch is excluded, because flipping it does not change what
  // was tested.
  const credKeys = useMemo(() => {
    const out: Record<Gate, string[]> = { smtp: [], google: [], postgres: [] }
    for (const f of data?.spec ?? []) {
      if (f.gate && f.type !== 'bool') out[f.gate].push(f.key)
    }
    return out
  }, [data])

  if (error) return <Box sx={{ p: 3 }}><Alert severity="error" variant="outlined">{(error as Error).message}</Alert></Box>
  if (isLoading || !data) return null

  const set = (k: string, v: unknown) => setDraft((o) => ({ ...o, [k]: v }))

  /** Honour `show_if` against the DRAFT, not the saved values, so picking a
   *  provider swaps the fields immediately rather than after a save. */
  const visible = (f: SettingSpec) =>
    !f.show_if || Object.entries(f.show_if).every(
      ([k, want]) => String(draft[k] ?? '') === String(want))

  /** Stable fingerprint of what a Test would exercise, for comparison only. */
  const snapshot = (g: Gate) =>
    JSON.stringify(credKeys[g].map((k) => [k, draft[k] ?? '']))

  const enableKey = (g: Gate) => (g === 'google' ? 'auth.google_enabled' : null)

  /** Has anything this Test covers been edited since it was loaded? */
  const dirty = (g: Gate) => credKeys[g].some((k) => {
    const spec = data.spec.find((f) => f.key === k)
    // A secret is never sent back, so any text at all is a change.
    if (spec?.type === 'secret') return !!draft[k]
    return (draft[k] ?? '') !== (data.values[k] ?? '')
  })

  const turningOn = (g: Gate) => {
    const k = enableKey(g)
    return !!k && !!draft[k] && !data.values[k]
  }

  /** Configured at all? Blanking the primary field is how you switch it off. */
  const PRIMARY: Record<Gate, string> = {
    smtp: 'smtp.host', google: 'auth.google_client_id', postgres: 'db.external_url',
  }
  const configured = (g: Gate) => !!String(draft[PRIMARY[g]] ?? '').trim()

  const needsTest = (g: Gate) => (dirty(g) || turningOn(g)) && configured(g)
  const satisfied = (g: Gate) =>
    !needsTest(g) || passed[g]?.snapshot === snapshot(g)
  const blocked = GATES.filter((g) => !satisfied(g))

  const runGateTest = async (g: Gate) => {
    setBusy(true); setMsg(null)
    try {
      const r = await api.testProvider(g, draft, g === 'smtp' ? testTo : undefined)
      if (r.ok && r.token) {
        setPassed((p) => ({ ...p, [g]: { token: r.token!, snapshot: snapshot(g) } }))
      } else {
        setPassed((p) => ({ ...p, [g]: undefined }))
      }
      setMsg({ kind: r.ok ? 'ok' : 'warn', text: `${GATE_LABEL[g]}: ${r.detail}` })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    } finally { setBusy(false) }
  }

  const runSlackTest = async () => {
    setBusy(true); setMsg(null)
    try {
      const r = await api.testProvider('slack', draft)
      setMsg({ kind: r.ok ? 'ok' : 'warn', text: `Slack: ${r.detail}` })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    } finally { setBusy(false) }
  }

  const save = async () => {
    setBusy(true); setMsg(null)
    const tokens: Record<string, string> = {}
    for (const g of GATES) if (passed[g]) tokens[g] = passed[g]!.token
    try {
      await api.saveSettings(draft, tokens)
      await qc.invalidateQueries({ queryKey: ['settings'] })
      setPassed({})
      setMsg({ kind: 'ok', text: 'Saved.' })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    } finally { setBusy(false) }
  }

  const clearSecret = async (key: string) => {
    setBusy(true); setMsg(null)
    try {
      await api.clearSetting(key)
      await qc.invalidateQueries({ queryKey: ['settings'] })
      setPassed({})
      setMsg({ kind: 'ok', text: `${key} cleared.` })
    } finally { setBusy(false) }
  }

  const field = (f: SettingSpec) => {
    const v = draft[f.key]
    if (f.type === 'bool') {
      const g = f.gate as Gate | undefined
      const locked = !!g && !!f.gate && !configured(g)
      return (
        <Box key={f.key}>
          <FormControlLabel
            control={<Checkbox checked={!!v} disabled={locked}
              onChange={(e) => set(f.key, e.target.checked)}
              sx={{ color: neon.muted, '&.Mui-checked': { color: neon.pink } }} />}
            label={<Typography sx={{ fontSize: 13, opacity: locked ? 0.5 : 1 }}>{f.label}</Typography>} />
          {f.help && <Help text={f.help} />}
        </Box>
      )
    }
    if (f.type === 'dsn') {
      const stored = !!data.values[f.key]
      const edited = v !== data.values[f.key]
      return (
        <Box key={f.key}>
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField
              size="small" fullWidth label={f.label}
              value={(v as string) ?? ''} onChange={(e) => set(f.key, e.target.value)}
              placeholder="postgresql://user:password@host:5432/dbname"
              autoComplete="off" spellCheck={false}
              slotProps={{ htmlInput: { style: { fontFamily: `'Share Tech Mono', monospace`,
                                                 fontSize: 12 } } }} />
            <Chip size="small" label={stored ? 'stored' : 'not set'} sx={{
              mt: 0.6, height: 20, fontSize: 10,
              bgcolor: alpha(stored ? neon.green : neon.muted, 0.14),
              color: stored ? neon.green : neon.muted,
              border: `1px solid ${alpha(stored ? neon.green : neon.muted, 0.5)}`,
            }} />
            {stored && (
              <Tooltip title="Remove the stored connection string">
                <Button size="small" onClick={() => clearSecret(f.key)} disabled={busy}
                  sx={{ mt: 0.3, color: neon.red, fontSize: 11, minWidth: 0 }}>Clear</Button>
              </Tooltip>
            )}
          </Stack>
          {/* The value arrives with the password already masked by the
              server. Saving it back unchanged is a no-op there, so the
              form can show it without risking storing bullets. */}
          {stored && !edited && (
            <Typography sx={{ mt: 0.5, fontSize: 10.5, color: alpha(neon.green, 0.9) }}>
              Password is masked. Leave it as-is to keep the stored one, or
              paste a whole new connection string to replace it.
            </Typography>
          )}
          {f.help && <Help text={f.help} />}
        </Box>
      )
    }
    if (f.type === 'secret') {
      const stored = data.secrets_set[f.key]
      return (
        <Box key={f.key}>
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField
              size="small" fullWidth type="password" label={f.label}
              value={(v as string) ?? ''} onChange={(e) => set(f.key, e.target.value)}
              placeholder={stored ? 'stored — leave blank to keep' : 'not set'}
              autoComplete="new-password"
            />
            <Chip size="small" label={stored ? 'stored' : 'not set'} sx={{
              mt: 0.6, height: 20, fontSize: 10,
              bgcolor: alpha(stored ? neon.green : neon.muted, 0.14),
              color: stored ? neon.green : neon.muted,
              border: `1px solid ${alpha(stored ? neon.green : neon.muted, 0.5)}`,
            }} />
            {stored && (
              <Tooltip title="Remove the stored value">
                <Button size="small" onClick={() => clearSecret(f.key)} disabled={busy}
                  sx={{ mt: 0.3, color: neon.red, fontSize: 11, minWidth: 0 }}>Clear</Button>
              </Tooltip>
            )}
          </Stack>
          {f.help && <Help text={f.help} />}
        </Box>
      )
    }
    return (
      <Box key={f.key}>
        <TextField
          size="small" fullWidth label={f.label}
          select={f.type === 'select'}
          type={f.type === 'number' ? 'number' : 'text'}
          value={(v as string | number) ?? ''}
          onChange={(e) => set(f.key, f.type === 'number' ? Number(e.target.value) : e.target.value)}>
          {maybeSorted(f.options ?? []).map((o) => (
            <MenuItem key={o} value={o} sx={{ fontSize: 13 }}>{o}</MenuItem>
          ))}
        </TextField>
        {f.help && <Help text={f.help} />}
      </Box>
    )
  }

  const gateBar = (g: Gate, extra?: React.ReactNode) => {
    const ok = !!passed[g] && passed[g]!.snapshot === snapshot(g)
    const must = needsTest(g)
    return (
      <Box sx={{
        mt: 0.5, p: 1.25, borderRadius: 1,
        border: `1px solid ${alpha(ok ? neon.green : must ? neon.yellow : neon.muted, 0.4)}`,
        background: alpha(ok ? neon.green : must ? neon.yellow : neon.muted, 0.06),
      }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          {extra}
          <Button size="small" variant="outlined" disabled={busy || !configured(g)}
            startIcon={ok ? <CheckCircleIcon sx={{ fontSize: 15 }} /> : <ScienceIcon sx={{ fontSize: 15 }} />}
            onClick={() => runGateTest(g)}
            sx={{ color: ok ? neon.green : neon.cyan,
                  borderColor: alpha(ok ? neon.green : neon.cyan, 0.5), whiteSpace: 'nowrap' }}>
            {ok ? 'Tested' : 'Test'}
          </Button>
        </Stack>
        <Typography sx={{ mt: 0.75, fontSize: 10.5, lineHeight: 1.5,
                          color: ok ? neon.green : must ? neon.yellow : alpha(neon.muted, 0.85) }}>
          {ok
            ? `${GATE_LABEL[g]} verified — these values can be saved.`
            : must
              ? `${GATE_LABEL[g]} changed. Test must pass before this can be saved.`
              : `No unsaved ${GATE_LABEL[g]} changes.`}
        </Typography>
      </Box>
    )
  }

  return (
    <Box sx={{ flex: 1, overflow: 'auto', p: { xs: 1.5, sm: 2.5 } }}>
      <Stack spacing={2.5} sx={{ maxWidth: 860, mx: 'auto' }}>
        {msg && (
          <Alert severity={msg.kind === 'ok' ? 'success' : msg.kind === 'warn' ? 'warning' : 'error'}
                 variant="outlined" sx={{ fontSize: 12.5 }} onClose={() => setMsg(null)}>
            {msg.text}
          </Alert>
        )}

        {data.groups.map((g) => (
          <Paper key={g} elevation={0} sx={{
            p: 2.5, backgroundColor: alpha(neon.paper, 0.75), backdropFilter: 'blur(6px)',
            border: `1px solid ${alpha(neon.purple, 0.3)}`,
          }}>
            <Typography sx={{
              fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.16em',
              textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.5), mb: 2,
            }}>{g}</Typography>

            <Stack spacing={2}>
              {data.spec.filter((f) => f.group === g && visible(f)).map(field)}

              {g === 'Email (SMTP)' && gateBar('smtp', (
                <TextField size="small" label="Send a test to" value={testTo}
                           sx={{ flex: 1, minWidth: 200 }}
                           onChange={(e) => setTestTo(e.target.value)}
                           placeholder="your own address" />
              ))}
              {g === 'Agent' && <RemediationPanel />}
              {g === 'Slack' && <SlackBotPanel />}
              {g === 'Identity' && gateBar('google')}
              {g === 'Database' && (
                <>
                  <Alert severity="info" variant="outlined" sx={{ fontSize: 11 }}>
                    Testing and storing a connection string does <b>not</b> switch
                    the app over. The settings table lives inside the database, so
                    the connection string cannot be read until after the connection
                    it describes is already open — the switch is a startup
                    decision. Once Test passes, copy the data across with
                    <code> uv run python pgcopy.py --from-settings</code>, set
                    <code> ODDJOB_DATABASE_URL</code> and restart.
                  </Alert>
                  {gateBar('postgres')}
                </>
              )}
              {g === 'Slack' && (
                <Box>
                  <Button size="small" variant="outlined" disabled={busy}
                    startIcon={<ScienceIcon sx={{ fontSize: 15 }} />}
                    onClick={runSlackTest}
                    sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5) }}>
                    Test token
                  </Button>
                  <Help text="Not required to save: a missing Slack token disables channel
                              creation, it does not lock anyone out." />
                </Box>
              )}
            </Stack>
          </Paper>
        ))}

        <Box sx={{ position: 'sticky', bottom: 0, py: 1.5,
                   background: `linear-gradient(transparent, ${alpha(neon.bgDeep, 0.9)} 40%)` }}>
          <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
            <Button variant="outlined" disabled={busy || blocked.length > 0} onClick={save}
              sx={{ color: neon.pink, borderColor: alpha(neon.pink, 0.6),
                    '&:hover': { borderColor: neon.pink } }}>
              {busy ? '…' : 'Save configuration'}
            </Button>
            {blocked.length > 0 && (
              <Typography sx={{ fontSize: 11, color: neon.yellow }}>
                {blocked.map((g) => GATE_LABEL[g]).join(' and ')} must pass Test first.
              </Typography>
            )}
          </Stack>
        </Box>
      </Stack>
    </Box>
  )
}

/** Whether the Slack bot is listening.
 *
 *  Worth its own panel because a wrong app-level token looks exactly
 *  like a working one: the settings all save, and the only symptom is
 *  that mentions go unanswered. This says connected or not, and why.
 */
function SlackBotPanel() {
  const q = useQuery({
    queryKey: ['slack-bot-status'],
    queryFn: api.slackBotStatus,
    // Polled while it is trying, so a bad token shows up as a reason
    // rather than as silence.
    refetchInterval: (r) =>
      r.state.data?.enabled && !r.state.data?.connected ? 5000 : 30000,
  })
  const s = q.data
  if (!s) return null
  const colour = !s.enabled ? neon.muted
    : s.connected ? neon.green : neon.yellow
  return (
    <Box sx={{
      mt: 0.5, p: 1.5, borderRadius: 1,
      border: `1px solid ${alpha(colour, 0.4)}`,
      background: alpha(colour, 0.06),
    }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography sx={{ fontSize: 11, color: colour, letterSpacing: '0.08em' }}>
          {!s.enabled ? 'ANSWERING IS OFF'
            : !s.configured ? 'NO APP-LEVEL TOKEN'
            : s.connected ? 'LISTENING ON SOCKET MODE' : 'NOT CONNECTED'}
        </Typography>
        <Box sx={{ flex: 1 }} />
        {s.detail && (
          <Typography sx={{ fontSize: 10.5, color: neon.muted }}>{s.detail}</Typography>
        )}
      </Stack>
      <Typography sx={{ fontSize: 10.5, color: neon.muted, mt: 0.5 }}>
        The bot opens the connection outwards, so nothing has to be exposed
        to the internet. It replies only when @-mentioned, only in that
        channel's engagement, and never writes.
      </Typography>
    </Box>
  )
}

/** What automatic remediation is actually doing, and how long it will
 *  take. Without the backlog in front of you the honest answer to
 *  "should I leave this on" is unknowable — a few hundred findings is an
 *  afternoon, six thousand on a local model is a fortnight. */
function RemediationPanel() {
  const q = useQuery({
    queryKey: ['remediation-status'],
    queryFn: api.remediationStatus,
    refetchInterval: (r) => (r.state.data?.pending ?? 0) > 0 ? 5000 : false,
  })
  const s = q.data
  if (!s) return null
  const colour = !s.configured ? neon.muted
    : !s.enabled ? neon.muted : s.pending ? neon.yellow : neon.green
  const order = ['critical', 'high', 'medium', 'low', 'info'] as const
  const SEV: Record<string, string> = {
    critical: neon.red, high: neon.orange, medium: neon.yellow,
    low: neon.cyan, info: neon.muted,
  }
  return (
    <Box sx={{
      mt: 0.5, p: 1.5, borderRadius: 1,
      border: `1px solid ${alpha(colour, 0.4)}`,
      background: alpha(colour, 0.06),
    }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography sx={{ fontSize: 11, color: colour, letterSpacing: '0.08em' }}>
          {!s.configured ? 'NO AGENT CONFIGURED'
            : !s.enabled ? 'AUTOMATIC REMEDIATION OFF'
            : s.pending ? 'WORKING THROUGH THE BACKLOG' : 'UP TO DATE'}
        </Typography>
        <Box sx={{ flex: 1 }} />
        <Chip size="small" label={`${s.written_by_agent} written by the agent`}
          sx={{ height: 19, fontSize: 10, bgcolor: alpha(neon.pink, 0.14),
                color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.4)}` }} />
        <Chip size="small" label={`${s.from_scanner} from scanners`}
          sx={{ height: 19, fontSize: 10, bgcolor: alpha(neon.muted, 0.14),
                color: neon.muted, border: `1px solid ${alpha(neon.muted, 0.4)}` }} />
      </Stack>

      {s.pending > 0 && (
        <>
          <Stack direction="row" spacing={0.6} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
            {order.filter((k) => s.by_severity[k]).map((k) => (
              <Chip key={k} size="small" label={`${s.by_severity[k]} ${k}`}
                sx={{ height: 18, fontSize: 10, bgcolor: alpha(SEV[k], 0.15),
                      color: SEV[k], border: `1px solid ${alpha(SEV[k], 0.45)}` }} />
            ))}
          </Stack>
          <Typography sx={{ mt: 0.9, fontSize: 10.5, lineHeight: 1.6,
                            color: alpha(neon.muted, 0.95) }}>
            {s.pending.toLocaleString()} finding(s) still need remediation
            {s.estimate ? ` — ${s.estimate} at one at a time` : ''}.
            Worst severity first, always: a critical that arrives mid-run is
            picked up before any waiting low.
            {s.gave_up > 0 && ` ${s.gave_up} were given up on after repeated
             failures; their errors are on the findings.`}
          </Typography>
        </>
      )}
      {s.pending === 0 && s.enabled && s.configured && (
        <Typography sx={{ mt: 0.8, fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
          Nothing outstanding at {s.min_severity} severity and above.
        </Typography>
      )}
    </Box>
  )
}

function Help({ text }: { text: string }) {
  return (
    <Typography sx={{ mt: 0.5, fontSize: 10.5, lineHeight: 1.5, color: alpha(neon.muted, 0.85) }}>
      {text}
    </Typography>
  )
}
