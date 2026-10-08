import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Divider, IconButton, MenuItem, Paper, Select,
  Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import PersonAddIcon from '@mui/icons-material/PersonAddAlt'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'
import { sorted, sortedStrings } from '../lib/sortOptions'
import { NewUserDialog, ROLES } from '../components/NewUserDialog'

/**
 * Two audiences, one screen, scoped by what you actually hold:
 *
 *  Site admins      every account, plus group membership, plus the ACL of
 *                   any project.
 *  Project admins   membership of THEIR projects only. They never see the
 *                   account list, only the picker (username and name), and
 *                   the server enforces both — this component hides what it
 *                   cannot use rather than being the thing that protects it.
 *
 * Both can bring somebody new in, and the same rule applies to the new
 * account's grants as to anyone else's: only on a project you administer.
 * `adminProjects` is what the dialog offers; `invite_user` on the server is
 * what decides.
 */
const ROLE_COLOUR: Record<string, string> = {
  admin: neon.pink, user: neon.cyan, readonly: neon.muted,
}

function Card({ title, action, children }: {
  title: string; action?: React.ReactNode; children: React.ReactNode
}) {
  return (
    <Paper elevation={0} sx={{
      p: 2.5, backgroundColor: alpha(neon.paper, 0.75), backdropFilter: 'blur(6px)',
      border: `1px solid ${alpha(neon.purple, 0.3)}`,
    }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography sx={{
          flex: 1, fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
          letterSpacing: '0.16em', textTransform: 'uppercase',
          color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
        }}>{title}</Typography>
        {action}
      </Stack>
      {children}
    </Paper>
  )
}

export function UsersView() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const isSiteAdmin = !!me?.user.is_site_admin
  const adminProjects = Object.entries(me?.projects ?? {})
    .filter(([, r]) => r === 'admin').map(([c]) => c)

  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [project, setProject] = useState<string>(adminProjects[0] ?? '')
  const [newUser, setNewUser] = useState(false)
  const [grantWho, setGrantWho] = useState('')
  const [grantRole, setGrantRole] = useState<string>('readonly')

  const users = useQuery({ queryKey: ['users'], queryFn: api.users, enabled: isSiteAdmin })
  const picker = useQuery({ queryKey: ['users-selectable'], queryFn: api.selectableUsers })
  const groups = useQuery({ queryKey: ['groups'], queryFn: api.groups })
  const acl = useQuery({
    queryKey: ['acl', project], queryFn: () => api.acl(project), enabled: !!project,
  })

  const fail = (e: unknown) =>
    setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
  const refresh = () => qc.invalidateQueries()

  const grant = useMutation({
    mutationFn: () => api.grant(project, { username: grantWho, role: grantRole }),
    onSuccess: () => { setGrantWho(''); setMsg({ kind: 'ok', text: 'Access granted.' }); refresh() },
    onError: fail,
  })
  const revoke = useMutation({
    mutationFn: (id: number) => api.revoke(project, id),
    onSuccess: refresh, onError: fail,
  })
  const toggleAdminGroup = useMutation({
    // Normalised to void: add returns the Group, remove returns nothing,
    // and the union confuses the mutation's type for no benefit.
    mutationFn: async (v: { username: string; add: boolean }) => {
      if (v.add) await api.addGroupMember('site-admins', v.username)
      else await api.removeGroupMember('site-admins', v.username)
    },
    onSuccess: refresh, onError: fail,
  })
  const setActive = useMutation({
    mutationFn: (v: { username: string; active: boolean }) =>
      api.updateUser(v.username, { is_active: v.active }),
    onSuccess: refresh, onError: fail,
  })
  const sendInvite = useMutation({
    mutationFn: (username: string) => api.invite(username),
    // Reports honestly rather than claiming success: this endpoint is
    // admin-only, so there is no account-existence to protect.
    onSuccess: (r) => setMsg({ kind: r.ok ? 'ok' : 'err', text: r.detail }),
    onError: fail,
  })
  const remove = useMutation({
    mutationFn: (username: string) => api.deleteUser(username),
    onSuccess: refresh, onError: fail,
  })

  return (
    <Box sx={{ flex: 1, overflow: 'auto', p: { xs: 1.5, sm: 2.5 } }}>
      <Stack spacing={2.5} sx={{ maxWidth: 980, mx: 'auto' }}>
        {msg && (
          <Alert severity={msg.kind === 'ok' ? 'success' : 'error'} variant="outlined"
                 sx={{ fontSize: 12.5 }} onClose={() => setMsg(null)}>{msg.text}</Alert>
        )}

        {/* ---------------- accounts: site admins only ---------------- */}
        {isSiteAdmin && (
          <Card title="Accounts" action={
            <Button size="small" variant="outlined" startIcon={<PersonAddIcon />}
              onClick={() => setNewUser(true)}
              sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5), fontSize: 11 }}>
              New user
            </Button>
          }>
            <Stack spacing={0.8}>
              {(users.data ?? []).map((u) => {
                const self = u.id === me?.user.id
                return (
                  <Stack key={u.id} direction="row" spacing={1} alignItems="center" sx={{
                    px: 1.3, py: 0.8, borderRadius: 0.6,
                    background: alpha(neon.bgDeep, 0.5),
                    border: `1px solid ${alpha(neon.purple, 0.2)}`,
                    opacity: u.is_active ? 1 : 0.5,
                  }}>
                    <Box sx={{ minWidth: 140, color: neon.pink, fontSize: 13 }}>{u.username}</Box>
                    <Box sx={{ flex: 1, fontSize: 12, color: neon.muted,
                               overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {u.full_name || u.email || ''}
                    </Box>
                    {u.has_google && <Chip size="small" label="google" sx={chip(neon.green)} />}
                    {!u.has_password && <Chip size="small" label="no password" sx={chip(neon.muted)} />}
                    {!u.is_active && <Chip size="small" label="disabled" sx={chip(neon.red)} />}

                    <Tooltip title={self ? 'You cannot change your own site-admin status'
                                         : u.is_site_admin ? 'Remove from site-admins'
                                                           : 'Add to site-admins'}>
                      <span>
                        <Chip size="small" label="site admin" clickable={!self}
                          disabled={self}
                          onClick={self ? undefined : () => toggleAdminGroup.mutate(
                            { username: u.username, add: !u.is_site_admin })}
                          sx={chip(u.is_site_admin ? neon.red : neon.muted,
                                   u.is_site_admin ? 0.18 : 0.05)} />
                      </span>
                    </Tooltip>

                    <Tooltip title={u.email
                      ? 'Email a sign-in link so they can set a password'
                      : 'No email address on this account'}>
                      <span>
                        <Button size="small" disabled={!u.email || sendInvite.isPending}
                          onClick={() => sendInvite.mutate(u.username)}
                          sx={{ fontSize: 10.5, color: neon.cyan, minWidth: 0 }}>
                          Invite
                        </Button>
                      </span>
                    </Tooltip>
                    <Tooltip title={u.is_active ? 'Disable sign-in' : 'Re-enable'}>
                      <span>
                        <Button size="small" disabled={self}
                          onClick={() => setActive.mutate({ username: u.username, active: !u.is_active })}
                          sx={{ fontSize: 10.5, color: neon.muted, minWidth: 0 }}>
                          {u.is_active ? 'Disable' : 'Enable'}
                        </Button>
                      </span>
                    </Tooltip>
                    <Tooltip title={self ? 'You cannot delete the account you are signed in as' : 'Delete'}>
                      <span>
                        <IconButton size="small" disabled={self}
                          onClick={() => remove.mutate(u.username)}
                          sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                          <DeleteIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </Stack>
                )
              })}
            </Stack>
            {groups.data && groups.data.length > 0 && (
              <>
                <Divider sx={{ my: 2, borderColor: alpha(neon.purple, 0.2) }} />
                <Typography sx={{ fontSize: 11, color: neon.muted, mb: 1 }}>Groups</Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {groups.data.map((g) => (
                    <Chip key={g.id} size="small" label={g.name} sx={chip(neon.purple)} />
                  ))}
                </Stack>
              </>
            )}
          </Card>
        )}

        {/* ---------------- project membership ---------------- */}
        <Card title="Project membership" action={
          <Stack direction="row" spacing={1} alignItems="center">
            {/* A project admin has no Accounts card to hold the button, but
                the server lets them invite someone as long as the new
                account lands on a project they administer. */}
            {!isSiteAdmin && adminProjects.length > 0 && (
              <Button size="small" variant="outlined" startIcon={<PersonAddIcon />}
                onClick={() => setNewUser(true)}
                sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5), fontSize: 11 }}>
                New user
              </Button>
            )}
            <Select size="small" value={project} onChange={(e) => setProject(e.target.value)}
              displayEmpty sx={{ minWidth: 190, height: 30, fontSize: 12, color: neon.cyan,
                '.MuiOutlinedInput-notchedOutline': { borderColor: alpha(neon.cyan, 0.4) } }}>
              {sortedStrings(isSiteAdmin ? Object.keys(me?.projects ?? {}) : adminProjects).map((c) => (
                <MenuItem key={c} value={c} sx={{ fontSize: 12 }}>{c}</MenuItem>
              ))}
              {!isSiteAdmin && adminProjects.length === 0 && (
                <MenuItem value="" sx={{ fontSize: 12 }}>no projects you administer</MenuItem>
              )}
            </Select>
          </Stack>
        }>
          {!project ? (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              You administer no projects, so there is no membership to manage. A site
              administrator grants the admin role on a project.
            </Typography>
          ) : (
            <>
              <Stack direction="row" spacing={1} sx={{ mb: 2 }} flexWrap="wrap" useFlexGap>
                <Select size="small" value={grantWho} displayEmpty sx={{ minWidth: 190, fontSize: 12.5 }}
                  onChange={(e) => setGrantWho(e.target.value)}>
                  <MenuItem value="" sx={{ fontSize: 12.5 }}>choose a person…</MenuItem>
                  {sorted(picker.data ?? [], (u) => u.username).map((u) => (
                    <MenuItem key={u.id} value={u.username} sx={{ fontSize: 12.5 }}>
                      {u.username}{u.full_name ? ` · ${u.full_name}` : ''}
                    </MenuItem>
                  ))}
                </Select>
                <Select size="small" value={grantRole} sx={{ minWidth: 130, fontSize: 12.5 }}
                  onChange={(e) => setGrantRole(e.target.value)}>
                  {ROLES.map((r) => <MenuItem key={r} value={r} sx={{ fontSize: 12.5 }}>{r}</MenuItem>)}
                </Select>
                <Button size="small" variant="outlined" disabled={!grantWho || grant.isPending}
                  onClick={() => grant.mutate()}
                  sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
                  Grant
                </Button>
              </Stack>
              <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.85), mb: 1.5 }}>
                Re-granting an existing member simply changes their role.
              </Typography>

              <Stack spacing={0.8}>
                {(acl.data ?? []).length === 0 && (
                  <Typography sx={{ fontSize: 12.5, color: alpha(neon.muted, 0.7) }}>
                    Nobody is granted access to {project} yet.
                  </Typography>
                )}
                {(acl.data ?? []).map((a) => {
                  const c = ROLE_COLOUR[a.role] ?? neon.muted
                  return (
                    <Stack key={a.id} direction="row" spacing={1} alignItems="center" sx={{
                      px: 1.3, py: 0.7, borderRadius: 0.6,
                      background: alpha(neon.bgDeep, 0.5),
                      border: `1px solid ${alpha(neon.purple, 0.2)}`,
                    }}>
                      <Box sx={{ flex: 1, fontSize: 13,
                                 color: a.group ? neon.purple : neon.pink }}>
                        {a.username ?? `group: ${a.group}`}
                      </Box>
                      <Chip size="small" label={a.role} sx={chip(c)} />
                      <Tooltip title="Revoke">
                        <IconButton size="small" onClick={() => revoke.mutate(a.id)}
                          sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                          <DeleteIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  )
                })}
              </Stack>
            </>
          )}
        </Card>
      </Stack>

      {newUser && (
        <NewUserDialog
          projects={adminProjects}
          // Mirrors the server: a site admin may create a floating account,
          // a project admin may only bring someone onto their own project.
          requireGrant={!isSiteAdmin}
          onClose={() => setNewUser(false)}
          onDone={(text) => {
            setNewUser(false)
            // The server's own sentence, not a cheerful substitute: it says
            // whether the invitation actually went out, and "account created
            // but the mail failed" must not read as a clean success.
            setMsg({ kind: 'ok', text })
            refresh()
          }} />
      )}
    </Box>
  )
}

const chip = (c: string, a = 0.14) => ({
  height: 19, fontSize: 10, bgcolor: alpha(c, a), color: c,
  border: `1px solid ${alpha(c, 0.5)}`,
})
