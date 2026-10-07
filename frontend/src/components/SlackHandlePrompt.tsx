import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, Snackbar, Stack,
  TextField, Typography, alpha,
} from '@mui/material'
import CheckCircleIcon from '@mui/icons-material/CheckCircleOutline'
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { parse } from '../lib/route'
import { neon, glow } from '../theme'

/* --------------------------------------------------------------------------
   "What are you called in this engagement's Slack?", asked once.

   The server decides whether to ask (GET .../slack/me), because the
   condition is a state and not an event: Slack is on for this project and
   this person has neither given a handle nor refused. Slack is routinely
   turned on after people are already on an engagement, so asking at
   join time only would miss everyone already there.

   There is deliberately no "remind me later". Declining POSTs the refusal
   and the server stops asking for this engagement; a prompt that comes
   back on every page load is one people learn to click past without
   reading. For the same reason the dialog has no backdrop or Escape
   dismissal — the two ways out are an answer and a refusal, and both are
   recorded.

   The invite is reported, not assumed. `invite_result` comes back verbatim
   and an invite fails often enough to matter — usually because the person
   is not in that Slack workspace yet. Rendering that as success would be
   a lie the operator finds out about when nothing arrives in the channel.
   -------------------------------------------------------------------------- */

type SlackMe = Awaited<ReturnType<typeof api.slackMe>>

interface InviteLine { channel: string | null; outcome: string; ok: boolean }

/**
 * Split `invite_result` back into one line per destination.
 *
 * The server joins `"<channel>: <outcome>"` with "; ", where "added" is
 * the only outcome that means it worked — everything else is a Slack
 * error code or a sentence explaining why the lookup failed.
 */
function inviteLines(raw: string | null | undefined): InviteLine[] {
  return (raw ?? '').split('; ').map((s) => s.trim()).filter(Boolean).map((s) => {
    const i = s.indexOf(': ')
    // A line with no channel is a whole-project outcome — "slack is not
    // configured for this project". Do not invent a channel for it.
    if (i < 0) return { channel: null, outcome: s, ok: false }
    const outcome = s.slice(i + 2)
    return { channel: s.slice(0, i), outcome, ok: outcome === 'added' }
  })
}

const chan = (c: string) => `#${c.replace(/^#/, '')}`

export function SlackHandlePrompt({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { refresh } = useAuth()
  const [typed, setTyped] = useState('')
  const [saveDefault, setSaveDefault] = useState(true)
  // Held so the dialog survives its own answer: the invite result is only
  // worth returning if it is shown, and the GET that drove the prompt now
  // says prompt=false.
  const [report, setReport] = useState<SlackMe | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Dismissing the offer below, for this view only. It is not a
  // question, so refusing it is not an answer worth storing.
  const [hideOffer, setHideOffer] = useState(false)

  // The header's project selector keeps an engagement chosen on /profile
  // and /config too, so "a project is selected" is not "a project is
  // open". Covering the Profile page — where the default handle is set —
  // with a modal offering that same default would be absurd. The URL is
  // the app's state (lib/route.ts) and every navigation re-renders this
  // component's parent, so reading it here is current.
  const onProjectPage = parse(window.location.pathname).project !== null

  const key = ['slack-me', project]
  const q = useQuery({
    queryKey: key,
    queryFn: () => api.slackMe(project!),
    enabled: !!project && onProjectPage,
    // Nothing but this dialog changes the answer, and it writes the
    // result straight back into the cache. Without this it is one request
    // per view change for a value that cannot have moved.
    staleTime: Infinity,
  })

  // A different engagement is a different question.
  useEffect(() => {
    setTyped(''); setSaveDefault(true); setReport(null); setError(null)
    setBusy(false); setHideOffer(false)
  }, [project])

  const me = q.data
  const open = !!project && onProjectPage && (report !== null || !!me?.prompt)

  const answer = async (handle: string, saveAsDefault: boolean) => {
    if (!project || busy) return
    setBusy(true); setError(null)
    try {
      const r = await api.slackMe(project, { handle, save_as_default: saveAsDefault })
      qc.setQueryData(key, r)
      setReport(r)
      // The profile default just moved; /auth/me is what Profile reads.
      if (saveAsDefault) await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  // Already known in this workspace, just not in this engagement's
  // channel. Offered rather than done silently: giving a handle is
  // consent to be added to that engagement's channels, and reading it
  // as standing consent for every future one would be deciding
  // something on their behalf. Offered rather than asked, because the
  // question itself has been answered.
  const adopt = async () => {
    if (!project || busy) return
    setBusy(true); setError(null)
    try {
      const r = await api.slackMe(project, 'adopt')
      qc.setQueryData(key, r)
      setReport(r)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const decline = async () => {
    if (!project || busy) return
    setBusy(true); setError(null)
    try {
      // prompt goes false, so the dialog closes and stays closed — on
      // the server, not just in this tab.
      qc.setQueryData(key, await api.slackMe(project, 'decline'))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const handle = typed.trim().replace(/^@/, '')
  const channels = me?.channels ?? []

  // Known here, not in this channel. A banner, not a dialog: the
  // question has been answered and re-opening a modal over an answered
  // question is exactly what this whole change is removing.
  if (!open && me?.can_adopt && !hideOffer && onProjectPage) {
    return (
      <Snackbar open anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        sx={{ maxWidth: 420 }}>
        <Alert severity="info" variant="outlined" icon={false}
          sx={{ bgcolor: alpha(neon.paper, 0.98), fontSize: 12.5,
                borderColor: alpha(neon.cyan, 0.5) }}
          action={
            <Stack direction="row" spacing={0.5}>
              <Button size="small" disabled={busy} onClick={() => void adopt()}
                sx={{ color: neon.green, fontSize: 11.5 }}>
                {busy ? 'Adding…' : 'Add me'}
              </Button>
              <Button size="small" onClick={() => setHideOffer(true)}
                sx={{ color: neon.muted, fontSize: 11.5 }}>
                Not now
              </Button>
            </Stack>
          }>
          {error ? error : <>
            You are <b>@{me.handle}</b> in this Slack. Add you to{' '}
            {channels.map(chan).join(', ') || 'this engagement’s channels'}?
          </>}
        </Alert>
      </Snackbar>
    )
  }

  return (
    // No onClose and no Escape: see the note at the top of the file. The
    // only exits write an answer or a refusal.
    <Dialog open={open} disableEscapeKeyDown maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.4)}`,
      } } }}>
      <DialogTitle sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 12.5, letterSpacing: '0.16em',
        textTransform: 'uppercase', color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
        borderBottom: `1px solid ${alpha(neon.cyan, 0.22)}`, py: 1.4,
      }}>
        Slack · {project}
      </DialogTitle>

      <DialogContent sx={{ pt: 2.5 }}>
        {error && (
          <Alert severity="error" variant="outlined" sx={{ mb: 2, fontSize: 12 }}
                 onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {report
          ? <InviteReport me={report} />
          : (
            <Stack spacing={2}>
              <Box>
                <Typography sx={{ fontSize: 12.5, color: neon.text, lineHeight: 1.7 }}>
                  This engagement posts to Slack. Tell us what you are called in
                  that workspace and you will be added to its channel
                  {channels.length === 1 ? '' : 's'}.
                </Typography>
                <Stack direction="row" spacing={0.7} flexWrap="wrap" useFlexGap sx={{ mt: 1.2 }}>
                  {channels.map((c) => (
                    <Chip key={c} size="small" label={chan(c)} sx={{
                      height: 20, fontSize: 11, fontFamily: `'Share Tech Mono', monospace`,
                      bgcolor: alpha(neon.pink, 0.13), color: neon.pink,
                      border: `1px solid ${alpha(neon.pink, 0.45)}`,
                    }} />
                  ))}
                </Stack>
              </Box>

              {me?.default_handle && (
                <Box>
                  <Button fullWidth variant="outlined" disabled={busy}
                    onClick={() => void answer(me.default_handle!, false)}
                    sx={{ color: neon.green, borderColor: alpha(neon.green, 0.55),
                          fontSize: 13, textTransform: 'none',
                          '&:hover': { borderColor: neon.green } }}>
                    Use @{me.default_handle}
                  </Button>
                  <Typography sx={{ mt: 0.6, fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
                    Your profile default.
                  </Typography>
                </Box>
              )}

              {me?.default_handle && (
                <Divider sx={{ borderColor: alpha(neon.purple, 0.25) }}>
                  <Typography sx={{ fontSize: 10, letterSpacing: '0.14em', color: neon.muted }}>
                    OR
                  </Typography>
                </Divider>
              )}

              <Box>
                <TextField size="small" fullWidth autoFocus value={typed}
                  disabled={busy} onChange={(e) => setTyped(e.target.value)}
                  label="Handle in this workspace" placeholder="@someone"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && handle) { e.preventDefault(); void answer(handle, saveDefault && !me?.default_handle) }
                  }} />
                <Typography sx={{ mt: 0.6, fontSize: 10.5, color: alpha(neon.muted, 0.9),
                                  lineHeight: 1.6 }}>
                  Kept for {project} only. A consultant is often in the client's
                  workspace under a different name from the one on their profile,
                  which is why this is asked per engagement.
                </Typography>
                {/* Only worth offering when there is nothing to overwrite.
                    With a default already set, a per-project handle is by
                    definition the exception, not the new rule. */}
                {!me?.default_handle && !!handle && (
                  <FormControlLabel sx={{ mt: 0.5 }}
                    control={<Checkbox size="small" checked={saveDefault} disabled={busy}
                      onChange={(e) => setSaveDefault(e.target.checked)}
                      sx={{ color: alpha(neon.muted, 0.7), '&.Mui-checked': { color: neon.cyan } }} />}
                    label={<Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                      Save this as my default for future engagements
                    </Typography>} />
                )}
              </Box>

              <Alert severity="info" variant="outlined" icon={false}
                     sx={{ fontSize: 11.5, lineHeight: 1.6,
                           borderColor: alpha(neon.muted, 0.35), color: neon.muted }}>
                Declining records a refusal for {project}: you will not be asked
                again for this engagement, and nothing will add you to the
                channel{channels.length === 1 ? '' : 's'} above. Other engagements
                still ask.
              </Alert>
            </Stack>
          )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, borderTop: `1px solid ${alpha(neon.purple, 0.2)}` }}>
        {report ? (
          <Button size="small" variant="outlined" onClick={() => setReport(null)}
            sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5), textTransform: 'none' }}>
            Close
          </Button>
        ) : (
          <>
            <Button size="small" disabled={busy} onClick={() => void decline()}
              sx={{ color: neon.muted, textTransform: 'none',
                    '&:hover': { color: neon.red } }}>
              Don't add me to this engagement's channels
            </Button>
            <Box sx={{ flex: 1 }} />
            {busy && <CircularProgress size={14} sx={{ color: neon.cyan, mr: 1 }} />}
            <Button size="small" variant="outlined" disabled={busy || !handle}
              onClick={() => void answer(handle, saveDefault && !me?.default_handle)}
              sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5),
                    textTransform: 'none',
                    '&.Mui-disabled': { borderColor: alpha(neon.muted, 0.25) } }}>
              Use this handle
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  )
}

/** What the invite actually did, per channel. */
function InviteReport({ me }: { me: SlackMe }) {
  const lines = inviteLines(me.invite_result)
  const failed = lines.filter((l) => !l.ok)

  return (
    <Stack spacing={1.6}>
      {/* Not "success": the handle is stored whatever the invite does, so
          saying so is a separate statement from how the invite went. */}
      <Alert severity={failed.length === 0 && lines.length > 0 ? 'success' : 'info'}
             variant="outlined" sx={{ fontSize: 12 }}>
        {me.handle
          ? <>This engagement will use <b>@{me.handle}</b>.</>
          : 'Your answer is recorded.'}
      </Alert>

      <Box>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 10, letterSpacing: '0.16em',
          textTransform: 'uppercase', color: alpha(neon.cyan, 0.8), mb: 1,
        }}>Channel invites</Typography>

        {lines.length === 0 ? (
          <Typography sx={{ fontSize: 12, color: neon.muted }}>
            The server reported nothing about the invite. That is not the same
            as it having worked — check the channel.
          </Typography>
        ) : (
          <Stack spacing={0.7}>
            {lines.map((l, i) => (
              <Stack key={i} direction="row" spacing={1} alignItems="flex-start" sx={{
                px: 1.2, py: 0.8, borderRadius: 0.5,
                background: alpha(neon.bgDeep, 0.5),
                border: `1px solid ${alpha(l.ok ? neon.green : neon.red, 0.35)}`,
              }}>
                {l.ok
                  ? <CheckCircleIcon sx={{ fontSize: 15, color: neon.green, mt: 0.2 }} />
                  : <ErrorOutlineIcon sx={{ fontSize: 15, color: neon.red, mt: 0.2 }} />}
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  {l.channel && (
                    <Box sx={{ fontFamily: `'Share Tech Mono', monospace`, fontSize: 12,
                               color: l.ok ? neon.green : neon.red }}>
                      {chan(l.channel)}
                    </Box>
                  )}
                  {/* Verbatim. A Slack error code is the thing to search for,
                      so paraphrasing it would cost the only useful detail. */}
                  <Box sx={{ fontSize: 11.5, color: neon.text, wordBreak: 'break-word' }}>
                    {l.ok ? 'added' : l.outcome}
                  </Box>
                </Box>
              </Stack>
            ))}
          </Stack>
        )}
      </Box>

      {failed.length > 0 && (
        <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5, lineHeight: 1.6 }}>
          Your handle is saved regardless — the invite is a separate step and
          failing it does not lose your answer. The usual cause is not being a
          member of that Slack workspace yet, which someone with access to it
          has to fix; adding you to a channel cannot.
        </Alert>
      )}
    </Stack>
  )
}
