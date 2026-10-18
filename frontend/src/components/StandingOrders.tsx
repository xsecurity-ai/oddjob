/** Four policies a project can leave running, and the button that opens them.
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
 *  These used to be a strip of controls wedged above the Targets
 *  table: seven switches and selects on one wrapping row, each with
 *  its explanation hidden in a tooltip, and the whole thing eating the
 *  height the table needed. A dialog gives every policy room for the
 *  sentence that says what it will actually do, and it moves the
 *  controls next to the project they belong to rather than onto one
 *  view that happens to show hosts.
 *
 *  What does NOT change is that the state stays visible without
 *  opening anything — the trigger carries the running count, because
 *  "the estate is being scanned right now" must not be a fact you have
 *  to click to learn.
 *
 *  Only with a single project in view: these are per-engagement
 *  settings and there is no sensible "all projects" meaning for them.
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogContent, DialogTitle,
  FormControlLabel, IconButton, MenuItem, Select, Stack, Switch, Tooltip,
  Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import PolicyIcon from '@mui/icons-material/Policy'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { neon } from '../theme'

/** What each switch is for, in the words the operator needs rather than
 *  the column name. The description says what will actually happen —
 *  "queues", not "enables". */
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

// Labelled by what the mode DOES, not by the tool that happens to do
// it. The values stay `gobuster` and `both`: they are the wire
// contract with `auto_web` and the name of a task kind, and renaming
// those to match a label would be a migration, not a rename.
const WEB = [
  { value: 'off', label: 'off' },
  // Different questions, which is why `both` exists: a crawl follows
  // what the application links to, brute force asks for paths
  // nothing links to.
  { value: 'crawl', label: 'crawl only' },
  { value: 'gobuster', label: 'brute force only' },
  { value: 'both', label: 'crawl + brute force' },
]

// Two runs, not one. Every technology-detection template is `info`
// severity, so the `-severity critical,high` the vulnerability run
// uses would discard all 1,228 of them — they cannot share a task.
const NUCLEI = [
  { value: 'off', label: 'Off' },
  { value: 'vuln', label: 'CVE templates' },
  { value: 'tech', label: 'Fingerprint only' },
  { value: 'both', label: 'CVEs + fingerprint' },
]

const NMAP = [
  { value: 'off', label: 'Off' },
  { value: 'top100', label: 'Top 100 ports' },
  { value: 'full', label: 'Full TCP' },
]

/** Everything the project does on its own, and what it costs the
 *  client when it does. */
function useStandingOrders(project: string) {
  const qc = useQueryClient()
  const { roleOn } = useAuth()

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

  const on = (f: string) =>
    Boolean((pr.data as Record<string, unknown> | undefined)?.[f])
  const nmap = String(
    (pr.data as { auto_nmap?: string } | undefined)?.auto_nmap ?? 'off')
  // Read off the typed Project, not through a cast. The cast that was
  // here is why nothing caught `auto_web` being missing from the API
  // response for as long as it was: asserting a shape the type did not
  // have told the compiler to stop checking exactly the field that was
  // never arriving, so the control silently fell back to 'off' on every
  // refetch while the database held the operator's choice.
  const web = String(pr.data?.auto_web ?? 'off')
  const nuclei = String(pr.data?.auto_nuclei ?? 'off')
  const live = SWITCHES.filter((s) => on(s.field)).length
    + (nmap !== 'off' ? 1 : 0) + (web !== 'off' ? 1 : 0)
    + (nuclei !== 'off' ? 1 : 0)

  return {
    admin: roleOn(project) === 'admin',
    busy: pr.isLoading || save.isPending,
    save, on, nmap, web, nuclei, live,
  }
}

/** One policy: its name, the sentence that says what it will do, and
 *  the control. The explanation is on the row rather than in a
 *  tooltip — in a dialog there is room for it, and a policy that
 *  queues traffic at a client should not have to be hovered to be
 *  understood. */
function Row({ label, help, children }: {
  label: string; help: string; children: React.ReactNode
}) {
  return (
    <Stack direction="row" spacing={2}
      sx={{ alignItems: 'flex-start', py: 1.1,
            borderBottom: `1px solid ${alpha(neon.purple, 0.14)}` }}>
      <Stack spacing={0.3} sx={{ flex: 1, minWidth: 0 }}>
        <Box sx={{ fontSize: 12.5, color: neon.text }}>{label}</Box>
        <Box sx={{ fontSize: 11, color: alpha(neon.muted, 0.95),
                   lineHeight: 1.45 }}>
          {help}
        </Box>
      </Stack>
      <Box sx={{ pt: 0.2, flexShrink: 0 }}>{children}</Box>
    </Stack>
  )
}

/** The controls themselves. Separate from the dialog so the shape can
 *  be read without the chrome around it. */
export function StandingOrdersControls({ project }: { project: string }) {
  const { admin, busy, save, on, nmap, web, nuclei } =
    useStandingOrders(project)

  const pick = (value: string, options: { value: string; label: string }[],
                onChange: (v: string) => void) => (
    <Select size="small" value={value} disabled={!admin || busy}
      onChange={(e) => onChange(e.target.value)}
      sx={{ fontSize: 11.5, height: 28, minWidth: 170,
            color: value === 'off' ? neon.muted : neon.yellow }}>
      {options.map((o) => (
        <MenuItem key={o.value} value={o.value} sx={{ fontSize: 11.5 }}>
          {o.label}
        </MenuItem>
      ))}
    </Select>
  )

  return (
    <Stack>
      {!admin && (
        <Box sx={{ fontSize: 11.5, color: neon.yellow, pb: 1 }}>
          Only a project admin can change these. Shown because knowing
          the estate is being scanned matters to anyone working on it.
        </Box>
      )}

      {SWITCHES.map((s) => (
        <Row key={s.field} label={s.label} help={s.help}>
          <FormControlLabel
            sx={{ m: 0 }}
            control={
              <Switch size="small" checked={on(s.field)}
                disabled={!admin || busy}
                onChange={(e) => save.mutate({ [s.field]: e.target.checked })} />
            }
            label="" />
        </Row>
      ))}

      <Row label="nmap new hosts"
        help={'Scans hosts that have never been scanned. Top 100 is '
          + "nmap's own fast list; Full TCP is all 65,535 ports and is "
          + 'hours of traffic at the far end.'}>
        {pick(nmap, NMAP, (v) => save.mutate({ auto_nmap: v }))}
      </Row>

      <Row label="Web discovery"
        help={'Crawls each web address this project knows, asks for paths '
          + 'nothing links to, or both. A crawl follows the application’s '
          + 'own links; brute forcing asks for 4,751 paths it does not. '
          + 'Both against a large estate is a great deal of traffic at '
          + 'the far end.'}>
        {pick(web, WEB, (v) => save.mutate({ auto_web: v }))}
      </Row>

      <Row label="nuclei"
        help={'Runs nuclei against every web address this project knows. '
          + 'CVE templates are critical and high only, and exclude anything '
          + 'needing a login. Fingerprinting records what the service IS '
          + 'against the service itself rather than filing hundreds of '
          + 'informational findings. CVE templates send a known exploit’s '
          + 'request at a production system — the engagement has to have '
          + 'authorised that.'}>
        {pick(nuclei, NUCLEI, (v) => save.mutate({ auto_nuclei: v }))}
      </Row>

      <Stack direction="row" spacing={1}
        sx={{ alignItems: 'center', pt: 1.2, minHeight: 24 }}>
        {busy && <CircularProgress size={13} sx={{ color: neon.muted }} />}
        {save.isError && (
          <Box sx={{ fontSize: 11.5, color: neon.pink }}>
            {(save.error as Error).message || 'could not save'}
          </Box>
        )}
      </Stack>
    </Stack>
  )
}

/** The trigger, for the header beside the project's own configuration.
 *
 *  It carries the running count rather than hiding it behind the
 *  click: these policies scan a client's estate unattended, and
 *  "three running" is the one thing about them that has to be true on
 *  screen without being asked for.
 */
export function StandingOrdersButton({ project }: { project: string }) {
  const [open, setOpen] = useState(false)
  const { live, admin } = useStandingOrders(project)

  return (
    <>
      <Tooltip title={admin
        ? 'Work this project does on its own as hosts arrive. Every '
          + 'candidate is checked against the scope list before anything '
          + 'is queued.'
        : 'Work this project does on its own. Only a project admin can '
          + 'change it.'}>
        <Button size="small" startIcon={<PolicyIcon fontSize="small" />}
          onClick={() => setOpen(true)}
          sx={{
            textTransform: 'none', fontSize: 12.5, minWidth: 0,
            py: 0.25, px: 1,
            color: live ? neon.yellow : neon.muted,
            '&:hover': { color: live ? neon.yellow : neon.cyan,
                         background: alpha(live ? neon.yellow : neon.cyan, 0.08) },
          }}>
          <Box component="span" sx={{ display: { xs: 'none', md: 'inline' } }}>
            Standing orders
          </Box>
          {live > 0 && (
            <Chip size="small" label={live} sx={{
              ml: 0.7, height: 17, fontSize: 10, color: neon.yellow,
              bgcolor: alpha(neon.yellow, 0.16),
              '& .MuiChip-label': { px: 0.7 } }} />
          )}
        </Button>
      </Tooltip>

      <Dialog open={open} onClose={() => setOpen(false)}
        maxWidth="sm" fullWidth>
        <DialogTitle sx={{ pb: 0.5 }}>
          <Stack direction="row" sx={{ alignItems: 'center' }}>
            <Stack spacing={0.3} sx={{ flex: 1 }}>
              <Typography sx={{ fontSize: 14, letterSpacing: 0.6,
                                textTransform: 'uppercase', color: neon.cyan }}>
                Standing orders · {project}
              </Typography>
              <Box sx={{ fontSize: 11, color: neon.muted }}>
                What this engagement does on its own, with nobody watching.
                Every candidate is checked against the scope list before
                anything is queued.
              </Box>
            </Stack>
            <IconButton size="small" onClick={() => setOpen(false)}>
              <CloseIcon fontSize="small" sx={{ color: neon.muted }} />
            </IconButton>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <StandingOrdersControls project={project} />
        </DialogContent>
      </Dialog>
    </>
  )
}
