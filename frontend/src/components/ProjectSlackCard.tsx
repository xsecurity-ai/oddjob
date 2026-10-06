import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Chip, MenuItem, Paper, Stack, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

/**
 * Where this engagement posts to Slack, and whether it posts at all.
 *
 * Shows the resolved state rather than the stored fields. A project
 * with no channel set still has one — derived from its codename and
 * the site prefix — and a page showing an empty box would imply
 * nothing is configured when in fact findings are already going
 * somewhere. Whether anything is sent depends on a bot token, not on
 * the channel, so the two are reported separately.
 */
export function ProjectSlackCard({ project }: { project: string }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const writable = canWrite(project)

  const { data, isLoading } = useQuery({
    queryKey: ['project-slack', project],
    queryFn: () => api.projectSlack(project),
  })

  const [channel, setChannel] = useState('')
  const [delivery, setDelivery] = useState('site')
  const [token, setToken] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)

  useEffect(() => {
    if (!data) return
    // Only prefill an explicitly chosen channel. Putting the derived
    // name in the box would turn "we worked this out for you" into a
    // stored value the first time anyone pressed Save, which is a
    // different thing and harder to undo.
    setChannel(data.channel_is_explicit ? data.channel : '')
    setDelivery(data.delivery)
  }, [data])

  const save = useMutation({
    mutationFn: (create: boolean) => api.setProjectSlack(project, {
      channel, delivery, token: token.trim() || undefined, create,
    }),
    onMutate: () => { setErr(null); setOk(null) },
    onSuccess: (r, create) => {
      setToken('')
      setOk(create ? `#${r.channel} exists and settings are saved`
                   : 'Saved.')
      void qc.invalidateQueries({ queryKey: ['project-slack', project] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
  })

  if (isLoading || !data) return null

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2.5,
                                    borderColor: alpha(neon.cyan, 0.3) }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                          letterSpacing: '0.14em', textTransform: 'uppercase',
                          color: neon.cyan, textShadow: glow(neon.cyan, 0.5) }}>
          Slack
        </Typography>
        {data.active
          ? <Chip size="small" label={`posting to #${data.channel}`} sx={{
              height: 19, fontSize: 10.5, color: neon.green,
              bgcolor: alpha(neon.green, 0.12) }} />
          : <Chip size="small" label="nothing is sent" sx={{
              height: 19, fontSize: 10.5, color: neon.muted,
              bgcolor: alpha(neon.muted, 0.12) }} />}
        {!data.channel_is_explicit && (
          <Tooltip title="No channel was chosen for this engagement, so this name is derived from its codename and the site-wide prefix. It is a real channel name and is what gets posted to.">
            <Chip size="small" label="derived" sx={{ height: 19, fontSize: 10.5,
              color: neon.purple, bgcolor: alpha(neon.purple, 0.14) }} />
          </Tooltip>
        )}
      </Stack>

      {!data.active && (
        // The reason, not just the fact. "Off" with no explanation
        // sends people to the wrong settings page.
        <Alert severity="info" variant="outlined" sx={{ mb: 1.5 }}>
          {data.inactive_reason || 'No destination resolves.'}
          {!data.site_token_set && !data.project_token_set
            && ' A bot token is set either site-wide in Site Config, or '
             + 'here for this engagement alone.'}
        </Alert>
      )}

      <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
        <TextField size="small" label="Channel" value={channel}
          disabled={!writable} sx={{ minWidth: 230 }}
          placeholder={data.channel}
          helperText={data.channel_is_explicit
            ? 'Chosen for this engagement.'
            : `Empty uses #${data.channel}, derived from the codename.`}
          onChange={(e) => setChannel(e.target.value)} />

        <TextField size="small" select label="Send via" value={delivery}
          disabled={!writable} sx={{ minWidth: 200 }}
          helperText="Which workspace receives it"
          onChange={(e) => setDelivery(e.target.value)}>
          <MenuItem value="site" sx={{ fontSize: 12.5 }}>
            The site-wide bot
          </MenuItem>
          <MenuItem value="override" sx={{ fontSize: 12.5 }}>
            This engagement&rsquo;s own token
          </MenuItem>
          <MenuItem value="both" sx={{ fontSize: 12.5 }}>
            Both
          </MenuItem>
        </TextField>

        <TextField size="small" label="Workspace token" value={token}
          type="password" disabled={!writable} sx={{ minWidth: 230 }}
          placeholder={data.project_token_set ? 'set — leave blank to keep'
                                              : 'none'}
          helperText="For an engagement run in the customer's workspace"
          onChange={(e) => setToken(e.target.value)} />
      </Stack>

      {delivery !== 'site' && !data.project_token_set && !token.trim() && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 1.5 }}>
          This is set to use the engagement&rsquo;s own token and there is
          none. Nothing will be sent through it.
        </Alert>
      )}
      {err && <Alert severity="error" variant="outlined" sx={{ mt: 1.5 }}>{err}</Alert>}
      {ok && <Alert severity="success" variant="outlined" sx={{ mt: 1.5 }}>{ok}</Alert>}

      {writable && (
        <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
          <Button size="small" variant="outlined" disabled={save.isPending}
            onClick={() => save.mutate(false)}>Save</Button>
          <Tooltip title={data.site_token_set || data.project_token_set
            ? 'Creates the channel in Slack if it is not already there. An existing channel is left alone.'
            : 'No bot token, so there is nothing to create it with.'}>
            <span>
              <Button size="small" variant="outlined" disabled={
                save.isPending || (!data.site_token_set && !data.project_token_set)}
                onClick={() => save.mutate(true)}
                sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5) }}>
                Save and create the channel
              </Button>
            </span>
          </Tooltip>
        </Stack>
      )}

      <Box sx={{ mt: 1.2, color: neon.muted, fontSize: 11.5 }}>
        Who gets added to the channel is asked of each person when they
        open this engagement, using the Slack handle on their profile.
      </Box>
    </Paper>
  )
}
