/** Four policies a project can leave running, above the Targets table.
 *
 *  Each one queues scans against a client's estate with nobody
 *  watching, so the bar is written to make that obvious rather than to
 *  be tidy:
 *
 *   - **Admin only.** The server refuses a plain user with a 403; a
 *     control that is offered and then rejected teaches people the app
 *     is broken, so it is not offered. A non-admin sees the state,
 *     disabled, because knowing that the estate is being scanned
 *     matters to anyone working on it.
 *   - **No optimistic update.** A toggle that flips and then flips back
 *     on a refetch is how somebody walks away believing scanning is on.
 *     It moves when the server says it moved.
 *   - **nmap is a choice, not a switch.** The hundred commonest ports
 *     and all 65,535 are hours apart in traffic at the far end.
 *
 *  Only with a single project in view: these are per-engagement
 *  settings and there is no sensible "all projects" meaning for them.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box, Chip, CircularProgress, FormControlLabel, MenuItem, Select, Stack,
  Switch, Tooltip, Typography, alpha,
} from '@mui/material'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon } from '../theme'

/** What each switch is for, in the words the operator needs rather than
 *  the column name. The description is the tooltip and says what will
 *  actually happen — "queues", not "enables". */
const SWITCHES = [
  {
    field: 'auto_amass' as const,
    label: 'Amass new domains',
    help: 'Hands every in-scope zone to amass once, as it appears. '
      + 'A zone that has already been enumerated is not sent again.',
  },
  {
    field: 'auto_resolve_ips' as const,
    label: 'Resolve missing IPs',
    help: 'Runs a forward lookup on any hostname with no address '
      + 'recorded. Tried once per name — a lookup that comes back '
      + 'empty is not retried on a loop.',
  },
  {
    field: 'auto_reverse_dns' as const,
    label: 'Name address-only hosts',
    help: 'Runs a reverse lookup on any host named by its address. '
      + 'Several names at one address still comes to you to decide.',
  },
]

const NMAP = [
  { value: 'off', label: 'Off' },
  { value: 'top100', label: 'Top 100 ports' },
  { value: 'full', label: 'Full TCP' },
]

export function StandingOrders({ project }: { project: string }) {
  const qc = useQueryClient()
  const { roleOn } = useAuth()
  const admin = roleOn(project) === 'admin'

  const pr = useQuery({
    queryKey: ['project', project],
    queryFn: () => api.project(project),
    enabled: !!project,
  })

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.updateProject(project, body),
    // Refetched rather than written into the cache: the server is what
    // decides, and a value this component invented would look identical
    // to one it was told.
    onSettled: () => qc.invalidateQueries({ queryKey: ['project', project] }),
  })

  const on = (f: string) => Boolean((pr.data as Record<string, unknown> | undefined)?.[f])
  const nmap = String((pr.data as { auto_nmap?: string } | undefined)?.auto_nmap ?? 'off')
  const busy = pr.isLoading || save.isPending
  const live = SWITCHES.filter((s) => on(s.field)).length + (nmap !== 'off' ? 1 : 0)

  return (
    <Stack direction="row" spacing={1.4} alignItems="center" useFlexGap
      sx={{ flexWrap: 'wrap', px: 1.2, py: 0.7, mb: 1,
            border: `1px solid ${alpha(live ? neon.yellow : neon.muted, 0.28)}`,
            borderRadius: 1,
            bgcolor: alpha(live ? neon.yellow : neon.muted, 0.05) }}>
      <Tooltip title={admin
        ? 'Work the project does on its own as hosts arrive. Every '
          + 'candidate is checked against the scope list before anything '
          + 'is queued.'
        : 'Only a project admin can change these.'}>
        <Typography sx={{ fontSize: 11, letterSpacing: 0.6, color: neon.muted,
                          textTransform: 'uppercase' }}>
          Standing orders
        </Typography>
      </Tooltip>

      {/* Said out loud. Someone opening this view should not have to
          read four controls to learn the estate is being scanned. */}
      {live > 0 && (
        <Chip size="small" label={`${live} running`} sx={{
          height: 18, fontSize: 10, color: neon.yellow,
          bgcolor: alpha(neon.yellow, 0.14) }} />
      )}

      {SWITCHES.map((s) => (
        <Tooltip key={s.field} title={s.help}>
          <FormControlLabel
            sx={{ m: 0 }}
            control={
              <Switch size="small" checked={on(s.field)} disabled={!admin || busy}
                onChange={(e) => save.mutate({ [s.field]: e.target.checked })} />
            }
            label={<Box sx={{ fontSize: 11.5, color: neon.text }}>{s.label}</Box>}
          />
        </Tooltip>
      ))}

      {/* The tooltip is on the LABEL, not around the whole control.
          Wrapping the Select meant the balloon was still open when the
          menu dropped, and it covered the options you were trying to
          pick — the explanation obscuring the thing it explains. */}
      <Stack direction="row" spacing={0.7} alignItems="center">
        <Tooltip title={'Scans hosts that have never been scanned. Top 100 is '
          + "nmap's own fast list; Full TCP is all 65,535 ports and is hours "
          + 'of traffic at the far end.'}>
          <Box sx={{ fontSize: 11.5, color: neon.text, cursor: 'help' }}>
            nmap new hosts
          </Box>
        </Tooltip>
        <Select size="small" value={nmap} disabled={!admin || busy}
          onChange={(e) => save.mutate({ auto_nmap: e.target.value })}
          sx={{ fontSize: 11.5, height: 26,
                color: nmap === 'off' ? neon.muted : neon.yellow }}>
          {NMAP.map((o) => (
            <MenuItem key={o.value} value={o.value} sx={{ fontSize: 11.5 }}>
              {o.label}
            </MenuItem>
          ))}
        </Select>
      </Stack>

      {busy && <CircularProgress size={13} sx={{ color: neon.muted }} />}
      {save.isError && (
        <Box sx={{ fontSize: 11, color: neon.pink }}>
          {(save.error as Error).message || 'could not save'}
        </Box>
      )}
    </Stack>
  )
}
