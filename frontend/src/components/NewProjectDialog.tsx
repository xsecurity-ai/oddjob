import { useState, type FormEvent } from 'react'
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, MenuItem,
  Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'
import { sortedStrings } from '../lib/sortOptions'

/**
 * New engagement. Any signed-in user may create one and becomes its admin.
 *
 * Scope is a single textarea rather than four typed fields: a scope document
 * arrives as a pasted block mixing ranges, addresses and names, and asking
 * someone to classify 400 lines by hand is how a /24 gets filed as a
 * hostname. The server derives the kind and names back anything it could not
 * parse, so a couple of bad lines never cost you the other 398.
 */
const ROLES = [
  { value: 'admin', label: 'Project admin' },
  { value: 'user', label: 'User' },
  // Stored as `readonly`; "Viewer" is just the friendlier name for it.
  { value: 'readonly', label: 'Viewer' },
]

type Delivery = 'site' | 'override' | 'both'
type Privacy = 'default' | 'private' | 'public'

const DELIVERY: { value: Delivery; label: string }[] = [
  { value: 'site', label: 'The site workspace' },
  { value: 'override', label: 'The customer workspace only' },
  { value: 'both', label: 'Both workspaces' },
]
const DELIVERY_HELP: Record<Delivery, string> = {
  site: 'The override token is stored but unused until you switch this.',
  override: 'Nothing is posted to the site workspace for this engagement.',
  both: 'Visible to the customer and kept on the internal record.',
}

/** Mirrors backend/app/slack.py — Slack rejects anything else. */
function normaliseChannel(raw: string): string {
  return raw.trim().replace(/^#/, '').toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-').replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '').slice(0, 80)
}

type Contact = { name: string; email: string; phone: string; title: string; primary_contact: boolean }
type Member = { username: string; role: string }

const blankContact = (): Contact =>
  ({ name: '', email: '', phone: '', title: '', primary_contact: false })

export function NewProjectDialog({ onClose, onCreated }: {
  onClose: () => void
  onCreated: (code: string) => void
}) {
  const qc = useQueryClient()
  const [customer, setCustomer] = useState('')
  const [codename, setCodename] = useState('')
  // The operation's name, separate from the code. ACME's code is ACME
  // and its codename is FALCON; this field used to be labelled
  // "Codename" but was posted as `code`, so the real operation names
  // had nowhere to live and were never recorded.
  const [opname, setOpname] = useState('')
  const [name, setName] = useState('')
  const [scope, setScope] = useState('')
  const [slackToken, setSlackToken] = useState('')
  const [slackChannel, setSlackChannel] = useState('')
  const [delivery, setDelivery] = useState<Delivery>('site')
  const [privacy, setPrivacy] = useState<Privacy>('default')
  const [contacts, setContacts] = useState<Contact[]>([blankContact()])
  const [members, setMembers] = useState<Member[]>([{ username: '', role: 'user' }])
  const [err, setErr] = useState<string | null>(null)
  const [warn, setWarn] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)

  // Only users who already administer a project may list people. A first-time
  // creator cannot, so the field stays free text and the server validates —
  // which is also why the whole directory is not handed to everyone.
  const picker = useQuery({
    queryKey: ['users-selectable'], queryFn: api.selectableUsers, retry: false,
  })
  const options = (picker.data ?? []).map((u) => u.username)

  // Only so the dialog can show what the channel will be called and whether
  // it will be private; the rest of the site config stays admin-only.
  const defaults = useQuery({ queryKey: ['settings-defaults'], queryFn: api.settingsDefaults })
  const prefix = defaults.data?.slack_channel_prefix ?? ''
  const sitePrivate = defaults.data?.slack_default_private ?? true

  const hasToken = !!slackToken.trim()
  // The channel is named after the operation when there is one, which
  // is what the existing channels are actually called.
  const channelFrom = (opname.trim() || codename.trim())
  const defaultChannel = channelFrom ? normaliseChannel(prefix + channelFrom) : ''
  const resolvedChannel = slackChannel.trim()
    ? normaliseChannel(slackChannel)
    : defaultChannel
  const channelPreview = resolvedChannel
    ? `Will be #${resolvedChannel}`
    : 'Defaults to the site prefix plus the codename, or the code.'

  // Selecting a delivery that needs a token and then clearing the token
  // would be refused by the server, so fall back rather than letting the
  // form hold a state it cannot submit.
  const effectiveDelivery: Delivery = hasToken ? delivery : 'site'

  const scopeLines = scope.split('\n').map((l) => l.trim()).filter(Boolean)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(null); setWarn(null); setBusy(true)
    try {
      const r = await api.createProject({
        code: codename,
        codename: opname.trim() || null,
        name: name.trim() || customer.trim() || codename,
        client: customer.trim() || null,
        scope: scopeLines,
        contacts: contacts.filter((c) => c.name.trim()),
        members: members.filter((m) => m.username.trim()),
        slack_token: slackToken.trim() || null,
        slack_channel: slackChannel.trim() || null,
        slack_delivery: effectiveDelivery,
        slack_private: privacy === 'default' ? null : privacy === 'private',
      })
      await qc.invalidateQueries()
      const problems = [...r.scope_errors, ...r.member_errors]
      if (problems.length) {
        // Created, but not everything landed. Say so rather than closing on
        // a half-applied result the person never sees.
        setWarn([
          `Created ${r.project.code} with ${r.scope.length} scope entries, ` +
          `${r.contacts.length} contact(s) and ${r.members.length} member(s).`,
          ...problems,
        ])
        setBusy(false)
        return
      }
      onCreated(r.project.code)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  const section = (title: string, hint?: string) => (
    <Box sx={{ pt: 1 }}>
      <Typography sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 10, letterSpacing: '0.16em',
        textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.45),
      }}>{title}</Typography>
      {hint && <Typography sx={{ mt: 0.4, fontSize: 10.5, color: alpha(neon.muted, 0.85) }}>
        {hint}
      </Typography>}
    </Box>
  )

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth component="form" onSubmit={submit}
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 44px ${alpha(neon.cyan, 0.22)}`,
        width: '92vw', maxWidth: 900,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan,
                         textShadow: glow(neon.cyan, 0.5),
                         borderBottom: `1px solid ${alpha(neon.cyan, 0.28)}` }}>
        NEW ENGAGEMENT
      </DialogTitle>

      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}
          {warn && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 12.5 }}
                   action={<Button size="small" onClick={() => onCreated(codename.toUpperCase())}
                             sx={{ color: neon.cyan }}>Open it</Button>}>
              {warn.map((w, i) => <Box key={i} sx={{ mb: i === 0 ? 1 : 0.3 }}>{w}</Box>)}
            </Alert>
          )}

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField size="small" fullWidth required label="Customer" value={customer}
              onChange={(e) => setCustomer(e.target.value)} placeholder="Acme Corp" />
            <TextField size="small" fullWidth required label="Code" value={codename}
              onChange={(e) => setCodename(e.target.value)} placeholder="ACME"
              helperText="Uppercased. Unique across the site. Goes in the client's deliverables." />
            <TextField size="small" fullWidth label="Codename (optional)" value={opname}
              onChange={(e) => setOpname(e.target.value)} placeholder="FALCON"
              helperText="The operation's internal name. Names the Slack channel." />
          </Stack>
          <TextField size="small" fullWidth label="Engagement name (optional)" value={name}
            onChange={(e) => setName(e.target.value)}
            helperText="Defaults to the customer name." />

          <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
          {section('Scope', 'One per line. CIDR, IPv4, IPv6 and FQDN are detected automatically — '
            + 'prefix a line with ! or - to record it as an exclusion. Anything unparseable is '
            + 'reported back rather than silently dropped.')}
          <TextField
            size="small" fullWidth multiline minRows={5} value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder={'10.0.0.0/24\n2001:db8::/32\nportal.acme.com\n!10.0.0.5'}
            slotProps={{ htmlInput: { style: { fontFamily: `'Share Tech Mono', monospace`,
                                               fontSize: 12.5 } } }} />
          <Typography sx={{ fontSize: 11, color: neon.muted, mt: -1 }}>
            {scopeLines.length} line{scopeLines.length === 1 ? '' : 's'}
          </Typography>

          <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
          {section('Slack', 'The channel this engagement posts to. Supply a bot token to '
            + 'reach a different workspace — write-only, never shown again.')}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField size="small" fullWidth type="password" label="Bot token override (optional)"
              value={slackToken} autoComplete="new-password"
              onChange={(e) => setSlackToken(e.target.value)} placeholder="xoxb-…" />
            <TextField size="small" fullWidth label="Channel name" value={slackChannel}
              onChange={(e) => setSlackChannel(e.target.value)}
              placeholder={defaultChannel || '#acme-falcon'}
              helperText={channelPreview} />
          </Stack>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField select size="small" fullWidth label="Send findings to"
              value={hasToken ? delivery : 'site'} disabled={!hasToken}
              onChange={(e) => setDelivery(e.target.value as Delivery)}
              helperText={hasToken
                ? DELIVERY_HELP[delivery]
                : 'Add a bot token above to post anywhere other than the site workspace.'}>
              {DELIVERY.map((d) => (
                <MenuItem key={d.value} value={d.value} sx={{ fontSize: 13 }}>{d.label}</MenuItem>
              ))}
            </TextField>
            <TextField select size="small" fullWidth label="Channel visibility"
              value={privacy} onChange={(e) => setPrivacy(e.target.value as Privacy)}
              helperText={privacy === 'default'
                ? `Follows the site setting (currently ${sitePrivate ? 'private' : 'public'}).`
                : privacy === 'private'
                  ? 'Only invited members can read it.'
                  : 'Anyone in the workspace can read it — including findings and credentials.'}>
              <MenuItem value="default" sx={{ fontSize: 13 }}>
                Site default ({sitePrivate ? 'private' : 'public'})
              </MenuItem>
              <MenuItem value="private" sx={{ fontSize: 13 }}>Private</MenuItem>
              <MenuItem value="public" sx={{ fontSize: 13 }}>Public</MenuItem>
            </TextField>
          </Stack>

          <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
          {section('Points of contact', 'On the customer side.')}
          {contacts.map((c, i) => (
            <Stack key={i} direction="row" spacing={1} alignItems="flex-start">
              <Stack spacing={1} sx={{ flex: 1 }}>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                  <TextField size="small" fullWidth label="Name" value={c.name}
                    onChange={(e) => setContacts(up(contacts, i, { name: e.target.value }))} />
                  <TextField size="small" fullWidth label="Title" value={c.title}
                    onChange={(e) => setContacts(up(contacts, i, { title: e.target.value }))} />
                </Stack>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems="center">
                  <TextField size="small" fullWidth label="Email" value={c.email}
                    onChange={(e) => setContacts(up(contacts, i, { email: e.target.value }))} />
                  <TextField size="small" fullWidth label="Phone" value={c.phone}
                    onChange={(e) => setContacts(up(contacts, i, { phone: e.target.value }))} />
                  <FormControlLabel sx={{ whiteSpace: 'nowrap' }}
                    control={<Checkbox size="small" checked={c.primary_contact}
                      onChange={(e) => setContacts(up(contacts, i, { primary_contact: e.target.checked }))}
                      sx={{ color: neon.muted, '&.Mui-checked': { color: neon.pink } }} />}
                    label={<Typography sx={{ fontSize: 12 }}>Primary</Typography>} />
                </Stack>
              </Stack>
              <IconButton size="small" onClick={() => setContacts(contacts.filter((_, j) => j !== i))}
                sx={{ mt: 0.5, color: neon.muted, '&:hover': { color: neon.red } }}>
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Stack>
          ))}
          <Box>
            <Button size="small" startIcon={<AddIcon />}
              onClick={() => setContacts([...contacts, blankContact()])}
              sx={{ color: neon.green, fontSize: 11 }}>Add contact</Button>
          </Box>

          <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
          {section('Team', 'You are the project admin. Add anyone else and their role; '
            + 'an unknown username is reported, not fatal.')}
          {members.map((m, i) => (
            <Stack key={i} direction="row" spacing={1} alignItems="center">
              <Autocomplete
                freeSolo size="small" sx={{ flex: 1 }} options={sortedStrings(options)}
                value={m.username}
                onInputChange={(_, v) => setMembers(up(members, i, { username: v }))}
                renderInput={(p) => <TextField {...p} label="Username" />} />
              <TextField select size="small" sx={{ minWidth: 160 }} label="Role" value={m.role}
                onChange={(e) => setMembers(up(members, i, { role: e.target.value }))}>
                {ROLES.map((r) => (
                  <MenuItem key={r.value} value={r.value} sx={{ fontSize: 13 }}>{r.label}</MenuItem>
                ))}
              </TextField>
              <IconButton size="small" onClick={() => setMembers(members.filter((_, j) => j !== i))}
                sx={{ color: neon.muted, '&:hover': { color: neon.red } }}>
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Stack>
          ))}
          <Box>
            <Button size="small" startIcon={<AddIcon />}
              onClick={() => setMembers([...members, { username: '', role: 'user' }])}
              sx={{ color: neon.green, fontSize: 11 }}>Add member</Button>
            {picker.isError && (
              <Tooltip title="You do not administer a project yet, so the directory is not listed. Type usernames directly.">
                <Chip size="small" label="type usernames" sx={{
                  ml: 1, height: 19, fontSize: 10, color: neon.muted,
                  border: `1px solid ${alpha(neon.muted, 0.4)}`,
                }} />
              </Tooltip>
            )}
          </Box>
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button type="submit" variant="outlined" disabled={busy || !customer.trim() || !codename.trim()}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6),
                '&:hover': { borderColor: neon.cyan } }}>
          {busy ? '…' : 'Create engagement'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

function up<T>(arr: T[], i: number, patch: Partial<T>): T[] {
  return arr.map((x, j) => (j === i ? { ...x, ...patch } : x))
}
