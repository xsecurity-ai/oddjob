import { useState, type FormEvent } from 'react'
import {
  Alert, Box, Button, Chip, Divider, FormControlLabel, IconButton, ListSubheader,
  MenuItem, Paper, Stack, Switch, TextField,
  Tooltip, Typography, alpha,
} from '@mui/material'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome'
import { useAuth } from '../lib/auth'
import { useAppearance } from '../lib/appearance'
import { sorted } from '../lib/sortOptions'
import type { ThemeDef } from '../palettes'
import { neon, glow } from '../theme'

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Paper elevation={0} sx={{
      p: 2.5, backgroundColor: alpha(neon.paper, 0.75), backdropFilter: 'blur(6px)',
      border: `1px solid ${alpha(neon.purple, 0.3)}`,
    }}>
      <Typography sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.16em',
        textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.5), mb: 2,
      }}>{title}</Typography>
      {children}
    </Paper>
  )
}

/** Theme and Neon Dreams. Per-device, so it is stored in this browser
 *  rather than on the account — the same person wants the dark theme on a
 *  laptop at night and a light one on a projector. */
function AppearanceCard() {
  const { theme, themes, setTheme, dreams, setDreams, dreamsAvailable } = useAppearance()
  const groups = ['Dark', 'Light', 'Retro'] as const

  return (
    <Stack spacing={2.5}>
      <Box>
        <TextField select size="small" fullWidth label="Theme" value={theme.id}
          onChange={(e) => setTheme(e.target.value)} sx={{ maxWidth: 420 }}>
          {groups.flatMap((g) => [
            <ListSubheader key={g} sx={{
              fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
              letterSpacing: '0.16em', color: neon.cyan,
              backgroundColor: neon.paper, lineHeight: 2.2,
            }}>{g}</ListSubheader>,
            ...sorted(themes.filter((t) => t.group === g), (t) => t.name)
              .map((t) => (
                <MenuItem key={t.id} value={t.id} sx={{ fontSize: 13 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ width: '100%' }}>
                    <Swatch def={t} />
                    <Box sx={{ flex: 1 }}>{t.name}</Box>
                  </Stack>
                </MenuItem>
              )),
          ])}
        </TextField>
        <Typography sx={{ mt: 0.6, fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
          Applies to this browser only. Nobody else's screen changes.
        </Typography>
      </Box>

      <Box>
        <FormControlLabel
          control={<Switch checked={dreams && dreamsAvailable} disabled={!dreamsAvailable}
            onChange={(e) => setDreams(e.target.checked)}
            sx={{ '& .Mui-checked': { color: neon.pink } }} />}
          label={
            <Stack direction="row" spacing={1} alignItems="center">
              <AutoAwesomeIcon sx={{
                fontSize: 16,
                color: dreams && dreamsAvailable ? neon.pink : alpha(neon.muted, 0.7),
                filter: dreams && dreamsAvailable
                  ? `drop-shadow(0 0 6px ${neon.pink})` : undefined,
              }} />
              <Typography sx={{ fontSize: 13 }}>Enable Neon Dreams</Typography>
            </Stack>
          } />
        <Typography sx={{ mt: 0.4, fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
          {dreamsAvailable
            ? 'Adds the Synthwave text bloom. Purely decorative.'
            : `Not available on ${theme.name} — a halo reduces contrast on this
               scheme rather than adding emphasis, so it would make the text
               harder to read, not more striking.`}
        </Typography>
      </Box>
    </Stack>
  )
}

/** Four dots: surface, primary, secondary, and the critical colour. Enough
 *  to recognise a scheme without applying it. */
function Swatch({ def }: { def: ThemeDef }) {
  return (
    <Stack direction="row" spacing={0.3} sx={{
      p: 0.4, borderRadius: 0.5, background: def.palette.bg,
      border: `1px solid ${alpha(neon.muted, 0.4)}`,
    }}>
      {[def.palette.pink, def.palette.cyan, def.palette.green, def.palette.red]
        .map((c, i) => (
          <Box key={i} sx={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
        ))}
    </Stack>
  )
}

export function ProfileView() {
  const { me, refresh } = useAuth()
  const qc = useQueryClient()
  const u = me!.user

  const [fullName, setFullName] = useState(u.full_name ?? '')
  const [email, setEmail] = useState(u.email ?? '')
  // Read structurally: /api/auth/me returns slack_handle, but the User
  // interface in lib/api.ts does not declare it.
  const [slack, setSlack] = useState(
    (u as { slack_handle?: string | null }).slack_handle ?? '')
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [newKey, setNewKey] = useState<string | null>(null)
  const [keyName, setKeyName] = useState('')

  const keys = useQuery({ queryKey: ['api-keys'], queryFn: api.apiKeys })

  const saveDetails = async (e: FormEvent) => {
    e.preventDefault()
    setMsg(null)
    try {
      const saved = await api.updateProfile({
        full_name: fullName || null, email: email || null,
        // Empty clears it, which is the only way to stop it being
        // offered. The server stores it bare, so read the saved value
        // back rather than leaving "@someone" on screen beside a row
        // that now says "someone".
        slack_handle: slack.trim() || null,
      })
      setSlack((saved as { slack_handle?: string | null }).slack_handle ?? '')
      await refresh()
      setMsg({ kind: 'ok', text: 'Details saved.' })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    }
  }

  const savePassword = async (e: FormEvent) => {
    e.preventDefault()
    setMsg(null)
    if (next.length < 8) return setMsg({ kind: 'err', text: 'Password must be at least 8 characters.' })
    if (next !== confirm) return setMsg({ kind: 'err', text: 'Passwords do not match.' })
    try {
      await api.updateProfile({
        new_password: next,
        // Omitted entirely for a Google-only account: there is no current
        // password to prove, and sending an empty string reads as a wrong one.
        ...(u.has_password ? { current_password: current } : {}),
      })
      setCurrent(''); setNext(''); setConfirm('')
      await refresh()
      setMsg({ kind: 'ok', text: 'Password changed.' })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    }
  }

  const mintKey = useMutation({
    mutationFn: () => api.createApiKey(keyName || 'api key'),
    onSuccess: (k) => { setNewKey(k.key); setKeyName(''); void qc.invalidateQueries({ queryKey: ['api-keys'] }) },
  })
  const revoke = useMutation({
    mutationFn: (id: number) => api.revokeApiKey(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const roles = Object.entries(me!.projects)

  return (
    <Box sx={{ flex: 1, overflow: 'auto', p: { xs: 1.5, sm: 2.5 } }}>
      <Stack spacing={2.5} sx={{ maxWidth: 820, mx: 'auto' }}>
        {msg && (
          <Alert severity={msg.kind === 'ok' ? 'success' : 'error'} variant="outlined"
                 sx={{ fontSize: 12.5 }} onClose={() => setMsg(null)}>
            {msg.text}
          </Alert>
        )}

        <Card title="Account">
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2.5 }}>
            {u.avatar_url
              ? <Box component="img" src={u.avatar_url} alt="" referrerPolicy="no-referrer"
                     sx={{ width: 52, height: 52, borderRadius: '50%',
                           border: `1px solid ${alpha(neon.pink, 0.5)}` }} />
              : <Box sx={{ width: 52, height: 52, borderRadius: '50%', display: 'grid',
                           placeItems: 'center', fontSize: 20, color: neon.pink,
                           background: alpha(neon.pink, 0.12),
                           border: `1px solid ${alpha(neon.pink, 0.4)}` }}>
                  {u.username[0]?.toUpperCase()}
                </Box>}
            <Box>
              <Typography sx={{ fontSize: 16, color: neon.pink, textShadow: glow(neon.pink, 0.4) }}>
                {u.username}
              </Typography>
              <Stack direction="row" spacing={0.7} sx={{ mt: 0.6 }} flexWrap="wrap" useFlexGap>
                {u.is_site_admin && (
                  <Chip size="small" label="site admin" sx={{
                    height: 19, fontSize: 10, bgcolor: alpha(neon.red, 0.16), color: neon.red,
                    border: `1px solid ${alpha(neon.red, 0.55)}` }} />
                )}
                <Chip size="small" label={u.has_password ? 'password' : 'no password'} sx={{
                  height: 19, fontSize: 10, bgcolor: alpha(neon.cyan, 0.12), color: neon.cyan,
                  border: `1px solid ${alpha(neon.cyan, 0.4)}` }} />
                {u.has_google && (
                  <Chip size="small" label="google" sx={{
                    height: 19, fontSize: 10, bgcolor: alpha(neon.green, 0.14), color: neon.green,
                    border: `1px solid ${alpha(neon.green, 0.45)}` }} />
                )}
              </Stack>
            </Box>
          </Stack>

          <Stack component="form" onSubmit={saveDetails} spacing={2}>
            <TextField size="small" label="Full name" value={fullName}
                       onChange={(e) => setFullName(e.target.value)} />
            <TextField size="small" label="Email" type="email" value={email}
                       onChange={(e) => setEmail(e.target.value)} />
            <TextField size="small" label="Default Slack handle" value={slack}
                       onChange={(e) => setSlack(e.target.value)} placeholder="@someone"
                       helperText={`Offered as the one-click answer when you open an
                                    engagement that posts to Slack. Each engagement keeps
                                    its own handle — a client's workspace may know you by
                                    another name — so this is only the suggestion. Stored
                                    without the @. Leave it empty and you will be asked
                                    to type one each time.`.replace(/\s+/g, ' ')} />
            <Box>
              <Button type="submit" size="small" variant="outlined"
                sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5) }}>Save</Button>
            </Box>
          </Stack>
        </Card>

        <Card title="Appearance">
          <AppearanceCard />
        </Card>

        <Card title={u.has_password ? 'Change password' : 'Set a password'}>
          {!u.has_password && (
            <Typography sx={{ mb: 2, fontSize: 12, color: neon.muted }}>
              This account signs in with Google. Setting a password adds a second way in;
              it does not remove Google.
            </Typography>
          )}
          <Stack component="form" onSubmit={savePassword} spacing={2}>
            {u.has_password && (
              <TextField size="small" label="Current password" type="password" required
                         autoComplete="current-password" value={current}
                         onChange={(e) => setCurrent(e.target.value)} />
            )}
            <TextField size="small" label="New password" type="password" required
                       autoComplete="new-password" value={next}
                       onChange={(e) => setNext(e.target.value)}
                       helperText="At least 8 characters." />
            <TextField size="small" label="Confirm new password" type="password" required
                       autoComplete="new-password" value={confirm}
                       onChange={(e) => setConfirm(e.target.value)} />
            <Box>
              <Button type="submit" size="small" variant="outlined"
                sx={{ color: neon.pink, borderColor: alpha(neon.pink, 0.5) }}>
                {u.has_password ? 'Change password' : 'Set password'}
              </Button>
            </Box>
          </Stack>
        </Card>

        <Card title="Project access">
          {roles.length === 0 ? (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              You have no project grants yet, so the data views will be empty.
              A site administrator has to grant you access to a project.
            </Typography>
          ) : (
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {roles.map(([code, role]) => {
                const c = role === 'admin' ? neon.pink : role === 'user' ? neon.cyan : neon.muted
                return <Chip key={code} size="small" label={`${code} · ${role}`} sx={{
                  bgcolor: alpha(c, 0.13), color: c, border: `1px solid ${alpha(c, 0.5)}`,
                  fontSize: 11,
                }} />
              })}
            </Stack>
          )}
          {u.groups.length > 0 && (
            <>
              <Divider sx={{ my: 2, borderColor: alpha(neon.purple, 0.2) }} />
              <Typography sx={{ fontSize: 11, color: neon.muted, mb: 1 }}>Groups</Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {u.groups.map((g) => (
                  <Chip key={g.id} size="small" label={g.name} sx={{
                    bgcolor: alpha(neon.purple, 0.13), color: neon.purple,
                    border: `1px solid ${alpha(neon.purple, 0.45)}`, fontSize: 11 }} />
                ))}
              </Stack>
            </>
          )}
        </Card>

        <Card title="API keys">
          <Typography sx={{ mb: 2, fontSize: 12, color: neon.muted }}>
            For scripts and the MCP server. A key carries your access, so it can do
            anything you can.
          </Typography>
          {newKey && (
            <Alert severity="warning" variant="outlined" sx={{ mb: 2, fontSize: 12 }}
                   onClose={() => setNewKey(null)}>
              Copy this now — it is not shown again.
              <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box sx={{ flex: 1, fontFamily: `'Share Tech Mono', monospace`,
                           fontSize: 12, color: neon.yellow, wordBreak: 'break-all' }}>
                  {newKey}
                </Box>
                <IconButton size="small" onClick={() => void navigator.clipboard?.writeText(newKey)}
                  sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
                  <ContentCopyIcon sx={{ fontSize: 15 }} />
                </IconButton>
              </Box>
            </Alert>
          )}
          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
            <TextField size="small" label="Key name" value={keyName} sx={{ flex: 1 }}
                       onChange={(e) => setKeyName(e.target.value)} placeholder="mcp" />
            <Button size="small" variant="outlined" disabled={mintKey.isPending}
              onClick={() => mintKey.mutate()}
              sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
              Create
            </Button>
          </Stack>
          <Stack spacing={0.8}>
            {(keys.data ?? []).map((k) => (
              <Stack key={k.id} direction="row" spacing={1} alignItems="center" sx={{
                px: 1.2, py: 0.7, borderRadius: 0.5,
                background: alpha(neon.bgDeep, 0.5),
                border: `1px solid ${alpha(neon.purple, 0.2)}`,
                opacity: k.revoked ? 0.45 : 1,
              }}>
                <Box sx={{ flex: 1, fontSize: 12.5 }}>{k.name}</Box>
                <Box sx={{ fontSize: 11.5, color: neon.muted }}>{k.prefix}…</Box>
                {k.revoked
                  ? <Chip size="small" label="revoked" sx={{ height: 18, fontSize: 10 }} />
                  : (
                    <Tooltip title="Revoke">
                      <IconButton size="small" onClick={() => revoke.mutate(k.id)}
                        sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                        <DeleteIcon sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                  )}
              </Stack>
            ))}
            {(keys.data ?? []).length === 0 && (
              <Typography sx={{ fontSize: 12, color: alpha(neon.muted, 0.7) }}>No keys yet.</Typography>
            )}
          </Stack>
        </Card>
      </Stack>
    </Box>
  )
}
