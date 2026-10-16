import { useMemo, useState } from 'react'
import {
  Alert, Box, Chip, CircularProgress, FormControlLabel, IconButton, Stack,
  Switch, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import ClearIcon from '@mui/icons-material/Clear'
import RefreshIcon from '@mui/icons-material/Refresh'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type GhostAgent } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon } from '../theme'

/**
 * What the ghosts are saying about themselves.
 *
 * This page exists because diagnosing a ghost meant having an account
 * on the box it runs on, and this fleet is a GCP VM behind an IAP
 * tunnel, a Windows host whose docker lives inside WSL2, and a
 * droplet — three different procedures to answer one question. When
 * the GCP host lost its network route there was no procedure at all:
 * the only channel still working was the one the agent dials out on.
 *
 * Off by default, per agent. A ghost's log names the hosts it is
 * scanning, so it is not less sensitive than the findings and is not
 * left running once the question has been answered — switching it off
 * discards what was collected.
 */

/** Colour a line by what it appears to be. Cheap and only cosmetic:
 *  these are the agent's own words, not a structured level. */
function tint(line: string): string {
  const l = line.toLowerCase()
  if (l.includes('warning') || l.includes('dropped') || l.includes('retry'))
    return neon.yellow
  if (l.includes('error') || l.includes('failed') || l.includes('refus'))
    return neon.red
  if (l.startsWith('debug:')) return neon.purple
  return neon.text
}

function stamp(at: string | null): string {
  if (!at) return '—'
  const d = new Date(at)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString()
}

export function GhostDebugView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite, isAdmin } = useAuth()
  const [pick, setPick] = useState<number | 'all'>('all')
  const [find, setFind] = useState('')

  const fleet = useQuery({
    queryKey: ['ghosts', project],
    queryFn: () => api.agents(project!),
    enabled: !!project,
    refetchInterval: 15000,
  })

  const logs = useQuery({
    queryKey: ['ghost-debug', project, pick, find],
    queryFn: () => api.ghostDebug(project!, {
      ...(pick === 'all' ? {} : { agent_id: pick }),
      ...(find.trim() ? { contains: find.trim() } : {}),
      limit: 1000,
    }),
    enabled: !!project,
    // The point of the page is watching a ghost misbehave as it
    // happens, so it follows rather than waiting to be asked.
    refetchInterval: 5000,
  })

  const toggle = useMutation({
    mutationFn: ({ id, on }: { id: number; on: boolean }) =>
      api.patchAgent(project!, id, { debug: on }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['ghosts', project] })
      void qc.invalidateQueries({ queryKey: ['ghost-debug', project] })
    },
  })

  const agents: GhostAgent[] = useMemo(
    () => (fleet.data ?? []).filter((a) => a.status !== 'disabled'),
    [fleet.data])
  const anyOn = agents.some((a) => a.debug)
  const writable = canWrite(project)

  if (!project) {
    return (
      <Alert severity="info" variant="outlined" sx={{ fontSize: 12.5 }}>
        Pick an engagement to see what its ghosts are logging. Debug is a
        per-agent switch, so there is nothing to show across all of them.
      </Alert>
    )
  }

  // The sidebar already leaves this out for anyone who is not an
  // administrator of the engagement, and that is a convenience, not
  // the control: the route still resolves from a typed URL or an old
  // bookmark. The server refuses the read regardless -- this exists so
  // the refusal reads as a rule rather than as the page being broken.
  if (!isAdmin(project)) {
    return (
      <Alert severity="warning" variant="outlined" sx={{ fontSize: 12.5 }}>
        Ghost debug is limited to administrators of this engagement. The
        log is an agent's unedited running commentary — which hosts it is
        probing right now, in what order, and what came back — so it is
        read by the same people who can switch it on.
      </Alert>
    )
  }

  return (
    <Stack spacing={1.5}>
      <Box>
        <Typography sx={{ fontSize: 13, color: neon.cyan, mb: 0.3 }}>
          Ghost debug
        </Typography>
        <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
          Turn a ghost's own log on and it is sent here on every heartbeat,
          so a failing agent can be read without an account on the host it
          runs on. Its lines name the hosts it is scanning — switch it off
          when you are done, which also discards what was collected.
        </Typography>
      </Box>

      {/* The switches. One per live agent, because this is a property
          of a single ghost and a fleet-wide toggle would collect far
          more than any one question needs. */}
      <Stack direction="row" spacing={1.4} flexWrap="wrap" useFlexGap
        sx={{
          p: 1.2, border: `1px solid ${alpha(neon.cyan, 0.2)}`,
          borderRadius: 0.5, bgcolor: alpha(neon.cyan, 0.03),
        }}>
        {fleet.isLoading ? (
          <CircularProgress size={18} sx={{ color: neon.cyan }} />
        ) : agents.length === 0 ? (
          <Typography sx={{ fontSize: 12, color: neon.muted }}>
            No ghosts on this engagement.
          </Typography>
        ) : agents.map((a) => (
          <FormControlLabel key={a.id}
            control={
              <Switch size="small" checked={!!a.debug}
                disabled={!writable || toggle.isPending}
                onChange={(e) =>
                  toggle.mutate({ id: a.id, on: e.target.checked })} />
            }
            label={
              <Stack direction="row" spacing={0.6} alignItems="center">
                <Typography sx={{ fontSize: 12, color: neon.text }}>
                  {a.name}
                </Typography>
                <Chip size="small" label={a.status} sx={{
                  height: 16, fontSize: 9.5, borderRadius: 0.5,
                  color: a.status === 'lost' ? neon.orange : neon.muted,
                  border: `1px solid ${alpha(
                    a.status === 'lost' ? neon.orange : neon.muted, 0.4)}`,
                }} />
              </Stack>
            } />
        ))}
      </Stack>

      {/* A lost ghost cannot send anything, and its log stops at the
          moment it stopped. Saying so beats an empty list. */}
      {agents.some((a) => a.debug && a.status === 'lost') && (
        <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
          A ghost with debug on is <b>lost</b>. Its log ends at its last
          heartbeat — nothing after that was ever sent, so the final line
          here is the last thing it managed to report, not the last thing
          it did.
        </Alert>
      )}

      <Stack direction="row" spacing={1} alignItems="center">
        <TextField select size="small" label="Ghost" value={pick}
          onChange={(e) => setPick(
            e.target.value === 'all' ? 'all' : Number(e.target.value))}
          SelectProps={{ native: true }}
          sx={{ minWidth: 150 }}
          InputLabelProps={{ shrink: true }}>
          <option value="all">All</option>
          {agents.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </TextField>
        <TextField size="small" label="Containing" value={find}
          onChange={(e) => setFind(e.target.value)}
          placeholder="text in the line"
          sx={{ minWidth: 220 }}
          InputProps={{
            endAdornment: find ? (
              <IconButton size="small" onClick={() => setFind('')}>
                <ClearIcon sx={{ fontSize: 15 }} />
              </IconButton>
            ) : undefined,
          }} />
        <Tooltip title="Fetch now">
          <IconButton size="small" onClick={() => void logs.refetch()}
            sx={{ color: neon.cyan }}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        {!!logs.data && (
          <Typography sx={{ fontSize: 11, color: neon.muted }}>
            {logs.data.lines.length} line
            {logs.data.lines.length === 1 ? '' : 's'}
            {logs.data.keep ? ` · keeps the last ${logs.data.keep} per ghost` : ''}
          </Typography>
        )}
      </Stack>

      {logs.error ? (
        <Alert severity="error" variant="outlined" sx={{ fontSize: 12 }}>
          {(logs.error as Error).message}
        </Alert>
      ) : logs.isLoading ? (
        <Stack alignItems="center" sx={{ py: 3 }}>
          <CircularProgress size={20} sx={{ color: neon.cyan }} />
        </Stack>
      ) : (logs.data?.lines.length ?? 0) === 0 ? (
        // "Nothing collected" and "nothing to collect" are different
        // facts, and only the first one is a thing to go and fix.
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
          {anyOn
            ? 'Debug is on and nothing has arrived yet. Lines are sent on '
              + 'the heartbeat, so give it a few seconds — and if it stays '
              + 'empty, the ghost is not beating.'
            : 'No ghost has debug switched on, so nothing is being '
              + 'collected. This is not the same as a quiet fleet.'}
        </Alert>
      ) : (
        <Box sx={{
          border: `1px solid ${alpha(neon.purple, 0.3)}`,
          bgcolor: alpha('#000', 0.35), maxHeight: '62vh', overflow: 'auto',
          fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
        }}>
          {logs.data!.lines.map((l) => (
            <Box key={l.id} sx={{
              display: 'flex', gap: 1, px: 1.2, py: 0.25,
              borderBottom: `1px solid ${alpha(neon.muted, 0.08)}`,
              '&:hover': { bgcolor: alpha(neon.cyan, 0.05) },
            }}>
              <Box sx={{ color: neon.muted, flexShrink: 0, width: 66 }}>
                {stamp(l.at)}
              </Box>
              {pick === 'all' && (
                <Box sx={{ color: neon.cyan, flexShrink: 0, width: 150,
                  overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {l.agent}
                </Box>
              )}
              <Box sx={{ color: tint(l.line), wordBreak: 'break-all' }}>
                {l.line}
              </Box>
            </Box>
          ))}
        </Box>
      )}
    </Stack>
  )
}
