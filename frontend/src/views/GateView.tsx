import { useState, type FormEvent } from 'react'
import { Alert, Box, Button, Divider, Paper, Stack, TextField, Typography, alpha } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { consumeNext, pendingNext } from '../lib/route'
import { neon, glow } from '../theme'

/**
 * The sign-in gate, which doubles as first-run setup.
 *
 * There is no seeded admin account anywhere in this app. On a database with
 * zero users this shows "create the site admin" instead of a login form, and
 * the endpoint behind it stops working the moment one account exists.
 */
export function GateView() {
  const { setupRequired, refresh } = useAuth()
  // Set when the gate bounced them here from somewhere specific. Saying
  // so is the difference between "sign in" and "why am I on this page".
  const wanted = pendingNext()
  // Unauthenticated endpoint: the page has to know whether to offer the button.
  const methods = useQuery({ queryKey: ['auth-methods'], queryFn: api.authMethods, retry: false })
  const [magicSent, setMagicSent] = useState<string | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [email, setEmail] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(null)
    if (setupRequired) {
      if (password.length < 8) return setErr('Password must be at least 8 characters.')
      if (password !== confirm) return setErr('Passwords do not match.')
    }
    setBusy(true)
    try {
      if (setupRequired) await api.setup({ username, password, email: email || undefined })
      else await api.login(username, password)
      await refresh()
      // Back to whatever they were trying to reach before the gate sent
      // them here. AuthProvider re-renders into the app on refresh(), and
      // App reads its route from the location, so rewriting the URL first
      // is all it takes.
      consumeNext()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const accent = setupRequired ? neon.cyan : neon.pink

  return (
    <Box sx={{ flex: 1, display: 'grid', placeItems: 'center', p: 2 }}>
      <Paper
        component="form"
        onSubmit={submit}
        elevation={0}
        sx={{
          width: '100%', maxWidth: 420, p: { xs: 3, sm: 4 },
          backgroundColor: alpha(neon.paper, 0.8),
          backdropFilter: 'blur(8px)',
          border: `1px solid ${alpha(accent, 0.45)}`,
          boxShadow: `0 0 36px ${alpha(accent, 0.22)}`,
        }}
      >
        <Typography variant="h6" sx={{ mb: 0.5, color: neon.pink, textShadow: glow(neon.pink, 1.3) }}>
          ODD<Box component="span" sx={{ color: neon.cyan, textShadow: glow(neon.cyan, 1.3) }}>JOB</Box>
        </Typography>
        <Typography sx={{ mb: 3, color: neon.muted, fontSize: 12.5 }}>
          {setupRequired
            ? 'No accounts exist yet. Create the first one — it becomes the site administrator.'
            : wanted ? `Sign in to continue to ${wanted}`
            : 'Sign in to continue.'}
        </Typography>

        {err && (
          <Alert severity="error" variant="outlined"
                 sx={{ mb: 2, borderColor: alpha(neon.red, 0.6), color: neon.text, fontSize: 12.5 }}>
            {err}
          </Alert>
        )}

        <Stack spacing={2}>
          <TextField
            label="Username" value={username} size="small" autoFocus required
            onChange={(e) => setUsername(e.target.value)}
            slotProps={{ htmlInput: { autoCapitalize: 'none', autoCorrect: 'off' } }}
          />
          {setupRequired && (
            <TextField label="Email (optional)" value={email} size="small" type="email"
                       onChange={(e) => setEmail(e.target.value)} />
          )}
          <TextField
            label="Password" value={password} size="small" type="password" required
            autoComplete={setupRequired ? 'new-password' : 'current-password'}
            onChange={(e) => setPassword(e.target.value)}
            helperText={setupRequired ? 'At least 8 characters.' : undefined}
          />
          {setupRequired && (
            <TextField label="Confirm password" value={confirm} size="small" type="password"
                       required autoComplete="new-password"
                       onChange={(e) => setConfirm(e.target.value)} />
          )}
          <Button
            type="submit" variant="outlined" disabled={busy}
            sx={{
              color: accent, borderColor: alpha(accent, 0.6),
              textShadow: glow(accent, 0.5),
              '&:hover': { borderColor: accent, boxShadow: `0 0 14px ${alpha(accent, 0.5)}` },
            }}
          >
            {busy ? '…' : setupRequired ? 'Create site admin' : 'Sign in'}
          </Button>

          {methods.data?.google && (
            <>
              <Divider sx={{ borderColor: alpha(neon.purple, 0.25), fontSize: 11,
                             color: alpha(neon.muted, 0.8) }}>or</Divider>
              <Button
                variant="outlined"
                // A full navigation, not fetch: the OAuth redirect has to
                // happen in the browser's top-level context.
                onClick={() => { window.location.href = '/api/auth/google/start?next=/' }}
                sx={{
                  color: neon.text, borderColor: alpha(neon.muted, 0.5),
                  textTransform: 'none', fontFamily: `'Share Tech Mono', monospace`,
                  letterSpacing: 0,
                  '&:hover': { borderColor: neon.green,
                               boxShadow: `0 0 12px ${alpha(neon.green, 0.35)}` },
                }}
              >
                Continue with Google
              </Button>
              <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.8),
                                textAlign: 'center', lineHeight: 1.5 }}>
                A new Google account can sign in but joins no groups, so it sees
                nothing until an administrator grants it a project.
              </Typography>
            </>
          )}

          {!setupRequired && methods.data?.magic_link && (
            <>
              {!methods.data?.google && (
                <Divider sx={{ borderColor: alpha(neon.purple, 0.25), fontSize: 11,
                               color: alpha(neon.muted, 0.8) }}>or</Divider>
              )}
              {magicSent ? (
                <Alert severity="info" variant="outlined" sx={{ fontSize: 12, lineHeight: 1.55 }}>
                  {magicSent}
                </Alert>
              ) : (
                <Button
                  variant="outlined" disabled={busy || !username}
                  onClick={async () => {
                    setErr(null); setBusy(true)
                    try {
                      const r = await api.requestMagicLink(username)
                      setMagicSent(r.detail)
                    } catch (e) {
                      setErr(e instanceof Error ? e.message : String(e))
                    } finally { setBusy(false) }
                  }}
                  sx={{
                    color: neon.yellow, borderColor: alpha(neon.yellow, 0.5),
                    textTransform: 'none', fontFamily: `'Share Tech Mono', monospace`,
                    letterSpacing: 0,
                    '&:hover': { borderColor: neon.yellow,
                                 boxShadow: `0 0 12px ${alpha(neon.yellow, 0.35)}` },
                  }}>
                  Email me a sign-in link
                </Button>
              )}
              <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.8),
                                textAlign: 'center', lineHeight: 1.5 }}>
                Enter your username or email above first. The link works once and
                expires in 15 minutes.
              </Typography>
            </>
          )}
        </Stack>
      </Paper>
    </Box>
  )
}
