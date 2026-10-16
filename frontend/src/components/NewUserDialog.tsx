import { useState } from 'react'
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, MenuItem, Select, Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/AddCircleOutline'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import { sortedStrings } from '../lib/sortOptions'

/**
 * Creating an account, two ways, decided by whether the site can send mail.
 *
 *  SMTP configured    an email address and nothing else. The account is
 *                     created with NO password and a single-use link is
 *                     mailed; the first secret it has is one its owner
 *                     chose and nobody else ever saw.
 *  SMTP not configured
 *                     the old username/password form, with the reason
 *                     stated. An invitation that cannot be sent is not a
 *                     flow worth pretending to offer.
 *
 * Project grants are part of the same step because the alternative — create
 * the account, then find it in a second list, then grant — is where people
 * stop, and an account that sits ungranted for a week is an account nobody
 * is thinking about.
 *
 * Everything here is a convenience. The server derives its own username,
 * refuses its own collisions, and checks every grant against the caller's
 * own role on that project. See `invite_user` in backend/app/routers/auth.py.
 */

/** Mirrors ROLE_ORDER in backend/app/models.py. Ranked readonly < user <
 *  admin and left in that order deliberately — see lib/sortOptions. */
export const ROLES = ['readonly', 'user', 'admin'] as const

/**
 * Preview of `username_from_email` in backend/app/routers/auth.py.
 *
 * Duplicated on purpose so the admin can see what the account will be
 * called before creating it. It is shown as a placeholder and sent to
 * nobody: the server derives its own and is the one that decides.
 */
export function deriveUsername(email: string): string {
  const local = (email.split('@')[0] ?? '').toLowerCase().split('+')[0]
  const name = local
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '')
    .slice(0, 64)
    .replace(/^[-._]+|[-._]+$/g, '')
  return name || 'user'
}

type Grant = { project: string; role: string }

export function NewUserDialog({ projects, requireGrant, onClose, onDone }: {
  /** Project codes this admin may grant on. The server checks again. */
  projects: string[]
  /** True for a project admin: the server refuses them an account with no
   *  grant at all, so the dialog must not let them submit one. */
  requireGrant: boolean
  onClose: () => void
  onDone: (text: string) => void
}) {
  const methods = useQuery({ queryKey: ['auth-methods'], queryFn: api.authMethods })
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [grants, setGrants] = useState<Grant[]>([])
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)

  // While the answer is still in flight we do not know which form this is.
  // Treating "unknown" as "no mail" would show a password box that vanishes
  // a moment later, so the dialog waits instead.
  const mail = methods.data?.magic_link
  const free = sortedStrings(projects.filter((p) => !grants.some((g) => g.project === p)))

  const addGrant = () => {
    if (free.length) setGrants([...grants, { project: free[0], role: 'readonly' }])
  }
  const setGrant = (i: number, patch: Partial<Grant>) =>
    setGrants(grants.map((g, n) => (n === i ? { ...g, ...patch } : g)))

  const ready = !!email && (mail === true || password.length >= 8)
    && (!requireGrant || grants.length > 0)

  const submit = async () => {
    setBusy(true)
    setProblem(null)
    try {
      const r = await api.inviteUser({
        email,
        full_name: fullName || undefined,
        username: username || undefined,
        // Omitted entirely when mail works: the point of the flow is that
        // no password exists for anyone to intercept or reuse.
        password: mail === true ? undefined : password,
        grants,
      })
      onDone(r.detail)
    } catch (e) {
      // Shown in the dialog rather than behind it: the collision messages
      // carry the fix ("choose a different one, for example alice2") and
      // the username box to apply it is right here. The dialog stays open
      // with the form intact, so nothing typed has to be typed again.
      setProblem(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: { backgroundColor: alpha(neon.paper, 0.97),
        backgroundImage: 'none', border: `1px solid ${alpha(neon.cyan, 0.45)}` } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan }}>NEW USER</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          {problem && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 12 }}
                   onClose={() => setProblem(null)}>{problem}</Alert>
          )}

          <TextField size="small" label="Email" type="email" value={email} required
            onChange={(e) => setEmail(e.target.value)}
            slotProps={{ htmlInput: { autoCapitalize: 'none', spellCheck: false } }}
            helperText={mail === true
              ? 'An invitation goes here. They set their own password; we never see one.'
              : 'Where to reach them.'} />
          <TextField size="small" label="Full name" value={fullName}
            onChange={(e) => setFullName(e.target.value)} />

          {mail === undefined ? (
            <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
              Checking whether email is configured…
            </Typography>
          ) : mail ? (
            <TextField size="small" label="Username (optional)" value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={email ? deriveUsername(email) : 'from the address'}
              slotProps={{ htmlInput: { autoCapitalize: 'none', spellCheck: false },
                           inputLabel: { shrink: true } }}
              helperText="Taken from the address unless you set one. If the name is
                          already in use the account is refused, not merged." />
          ) : (
            <>
              <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
                No SMTP is configured, so no invitation can be sent. Set a first
                password and pass it on yourself, or configure email under Site
                Config and the username and password boxes go away.
              </Alert>
              <TextField size="small" label="Username" value={username} required
                onChange={(e) => setUsername(e.target.value)}
                placeholder={email ? deriveUsername(email) : ''}
                slotProps={{ htmlInput: { autoCapitalize: 'none', spellCheck: false },
                             inputLabel: { shrink: true } }}
                helperText="Blank takes it from the address." />
              <TextField size="small" label="Password" type="password" value={password}
                required onChange={(e) => setPassword(e.target.value)}
                helperText="At least 8 characters. They can change it from their profile." />
            </>
          )}

          {/* ------------------------------- project access --------------- */}
          <Box>
            <Stack direction="row" alignItems="center" sx={{ mb: 0.5 }}>
              <Typography sx={{ flex: 1, fontSize: 11, letterSpacing: '0.1em',
                                textTransform: 'uppercase', color: neon.cyan }}>
                Project access
              </Typography>
              <Tooltip title={free.length ? 'Add a project'
                                          : 'Every project you administer is already listed'}>
                <span>
                  <IconButton size="small" onClick={addGrant} disabled={!free.length}
                    sx={{ color: neon.green }}>
                    <AddIcon sx={{ fontSize: 17 }} />
                  </IconButton>
                </span>
              </Tooltip>
            </Stack>

            {projects.length === 0 ? (
              <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                You administer no projects, so there is nothing to grant here.
              </Typography>
            ) : grants.length === 0 ? (
              <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                {requireGrant
                  ? 'Add at least one project — an account with no access at all is '
                    + 'created by a site administrator.'
                  : 'None. The account is created with no access to anything.'}
              </Typography>
            ) : (
              <Stack spacing={0.8}>
                {grants.map((g, i) => (
                  <Stack key={g.project} direction="row" spacing={1} alignItems="center">
                    <Select size="small" value={g.project} sx={{ flex: 1, fontSize: 12.5 }}
                      onChange={(e) => setGrant(i, { project: e.target.value })}>
                      {sortedStrings([g.project, ...free]).map((p) => (
                        <MenuItem key={p} value={p} sx={{ fontSize: 12.5 }}>{p}</MenuItem>
                      ))}
                    </Select>
                    {/* Ranked, not alphabetical: readonly < user < admin. */}
                    <Select size="small" value={g.role} sx={{ minWidth: 120, fontSize: 12.5 }}
                      onChange={(e) => setGrant(i, { role: e.target.value })}>
                      {ROLES.map((r) => (
                        <MenuItem key={r} value={r} sx={{ fontSize: 12.5 }}>{r}</MenuItem>
                      ))}
                    </Select>
                    <IconButton size="small"
                      onClick={() => setGrants(grants.filter((_, n) => n !== i))}
                      sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                      <DeleteIcon sx={{ fontSize: 16 }} />
                    </IconButton>
                  </Stack>
                ))}
              </Stack>
            )}
          </Box>

          <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.85) }}>
            The account joins no groups. Nothing is created if any of these grants
            is refused.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button onClick={submit} variant="outlined" disabled={busy || !ready}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
          {busy ? '…' : mail ? 'Create and invite' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
