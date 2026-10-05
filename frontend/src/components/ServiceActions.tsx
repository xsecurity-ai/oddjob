import { CircularProgress, IconButton, Stack, Tooltip, alpha } from '@mui/material'
import TravelExploreIcon from '@mui/icons-material/SettingsEthernet'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * Per-row actions. Currently one: grab banner.
 *
 * The action is a server-side job, so this shows the latest job's state
 * rather than the outcome of this click — which is also what makes the
 * result appear when somebody else, or a script, runs it.
 *
 * `unavailable` is shown distinctly from `failed`: it means no probe backend
 * is configured, which is a fact about the deployment, not about the host.
 */
const COLOUR: Record<string, string> = {
  pending: neon.yellow, running: neon.yellow,
  done: neon.green, failed: neon.red, unavailable: neon.muted,
}

export function ServiceActions({ serviceId, canWrite }: { serviceId: number; canWrite: boolean }) {
  const qc = useQueryClient()
  // Jobs for this row only. Cheap, and the SSE invalidation refreshes it when
  // the job settles, so there is no polling.
  const { data } = useQuery({
    queryKey: ['actions', serviceId],
    queryFn: () => api.actions(serviceId),
    staleTime: 10_000,
  })
  const latest = data?.items?.find((a) => a.kind === 'grab_banner')
  const busy = latest?.status === 'pending' || latest?.status === 'running'

  const run = useMutation({
    mutationFn: () => api.runAction(serviceId, 'grab_banner'),
    onSettled: () => void qc.invalidateQueries({ queryKey: ['actions', serviceId] }),
  })

  const tip = !canWrite
    ? 'Read-only on this project'
    : busy
      ? 'Running…'
      : latest
        ? `Grab banner — last run: ${latest.status}${latest.error ? ` · ${latest.error}` : ''}`
        : 'Grab banner'

  const colour = latest ? COLOUR[latest.status] ?? neon.muted : neon.muted

  return (
    <Stack direction="row" spacing={0.3}>
      <Tooltip title={tip}>
        <span>
          <IconButton size="small" disabled={!canWrite || busy || run.isPending}
            onClick={() => run.mutate()}
            sx={{ color: colour,
                  '&:hover': { color: neon.cyan, textShadow: glow(neon.cyan, 0.6) },
                  '&.Mui-disabled': { color: alpha(neon.muted, 0.3) } }}>
            {busy || run.isPending
              ? <CircularProgress size={15} sx={{ color: neon.yellow }} />
              : <TravelExploreIcon sx={{ fontSize: 17 }} />}
          </IconButton>
        </span>
      </Tooltip>
    </Stack>
  )
}
