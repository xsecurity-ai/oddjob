import { useEffect, useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, MenuItem,
  Paper, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import GppBadIcon from '@mui/icons-material/GppBadOutlined'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ScopeApplyResult } from '../lib/api'
import { DeleteProjectCard } from '../components/DeleteProjectCard'
import { PillInput } from '../components/PillInput'
import { ProjectSlackCard } from '../components/ProjectSlackCard'
import { makeScopePills } from '../components/scopePills'
import { neon, glow } from '../theme'

/**
 * Project configuration: what the engagement is called, and what it is
 * allowed to touch.
 *
 * The scope half is not documentation. It is enforced on every path that
 * creates a target or queues an agent — see backend/app/scopegate.py for
 * the list — so an entry added here changes what the rest of the app will
 * do, immediately and without an apply step.
 *
 * Three things the screen has to keep straight, because getting any of
 * them wrong would be worse than not having the feature:
 *
 *  - OUT beats IN. A host on both lists is barred. Said on the page, not
 *    only in the code, because the operator is the one composing the two
 *    lists.
 *  - The lists govern what is NEW. Adding an entry deletes nothing. What
 *    is already here is dealt with under "Already in this project", with
 *    every host named — a count is not something anyone can decide from.
 *  - A country is DECLARED here, never looked up. Resolving an address to
 *    a country means sending the client's target list to a third party,
 *    which is a disclosure of the engagement itself. So the operator tags
 *    the ranges they know, and a host no tagged entry covers has an
 *    undetermined country — which the server treats as a third answer,
 *    not as "not barred".
 *  - "Include subdomains" is asked WHERE THE NAME IS TYPED, which is the
 *    whole point of it. `*.acme.example` does not cover `acme.example` —
 *    that is how DNS and certificates read a wildcard and the server is
 *    right to refuse it — but an operator who has pasted a scope document
 *    meets that rule later, as a refusal on a host they believed they had
 *    authorisation for. Asking at the point of entry is the difference
 *    between expressing an intent and debugging a rule.
 */

type Config = Awaited<ReturnType<typeof api.projectConfig>>
type Entry = Config['scope'][number]

const KIND_COLOUR: Record<string, string> = {
  cidr: neon.cyan, ipv4: neon.cyan, ipv6: neon.cyan,
  fqdn: neon.green, wildcard: neon.yellow, country: neon.purple,
}

function KindChip({ kind }: { kind: string }) {
  const c = KIND_COLOUR[kind] ?? neon.muted
  return <Chip size="small" label={kind} sx={{
    height: 19, fontSize: 10, letterSpacing: '0.08em',
    bgcolor: alpha(c, 0.14), color: c, border: `1px solid ${alpha(c, 0.5)}` }} />
}

export function ProjectConfigView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [details, setDetails] = useState({ name: '', client: '', codename: '',
                                           description: '', status: 'active' })
  const [lines, setLines] = useState('')
  const [addTo, setAddTo] = useState<'in' | 'out'>('in')
  const [addCountry, setAddCountry] = useState('')
  const [addSubs, setAddSubs] = useState(false)
  const [countries, setCountries] = useState('')
  const [confirm, setConfirm] = useState<ScopeApplyResult | null>(null)
  // Ticking the box changes what every fqdn line in the box MEANS,
  // so the pills are built from it and not from a fixed `false`.
  // Above the early returns below, because it is a hook; rebuilt
  // only when the checkbox moves, because `Analyse` has to stay
  // referentially stable or its memo rebuilds on every keystroke.
  const scopeAnalyse = useMemo(() => makeScopePills(addSubs), [addSubs])

  const cfg = useQuery({
    queryKey: ['project-config', project],
    queryFn: () => api.projectConfig(project as string),
    enabled: !!project,
  })
  const viol = useQuery({
    queryKey: ['scope-violations', project],
    queryFn: () => api.scopeViolations(project as string),
    enabled: !!project,
  })

  // Seeded from the server once it answers, and only then: typing into a
  // field that a refetch overwrites mid-edit is how people lose a
  // sentence they were half way through.
  const loaded = cfg.data?.project
  useEffect(() => {
    if (!loaded) return
    setDetails({
      name: loaded.name ?? '', client: loaded.client ?? '',
      codename: loaded.codename ?? '', description: loaded.description ?? '',
      status: loaded.status ?? 'active',
    })
    // Keyed on the id and not on `loaded` itself, which is a fresh object
    // on every refetch. Depending on the whole thing is what would
    // overwrite the half-typed sentence described above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded?.id])

  if (!project) {
    return <Box sx={{ p: 3 }}>
      <Alert severity="info" variant="outlined">
        Choose an engagement. Configuration and scope belong to one project,
        and there is no site-wide answer to either.
      </Alert>
    </Box>
  }
  if (cfg.isLoading) {
    return <Box sx={{ flex: 1, display: 'grid', placeItems: 'center', p: 6 }}>
      <CircularProgress sx={{ color: neon.cyan }} />
    </Box>
  }
  if (cfg.error) {
    return <Box sx={{ p: 3 }}>
      <Alert severity="error" variant="outlined">{(cfg.error as Error).message}</Alert>
    </Box>
  }

  const data = cfg.data as Config
  const inList = data.scope.filter((e) => e.included)
  const outList = data.scope.filter((e) => !e.included)

  const run = async (what: string, fn: () => Promise<unknown>) => {
    setBusy(true); setMsg(null)
    try {
      await fn()
      await qc.invalidateQueries({ queryKey: ['project-config', project] })
      await qc.invalidateQueries({ queryKey: ['scope-violations', project] })
      await qc.invalidateQueries({ queryKey: ['projects'] })
      setMsg({ kind: 'ok', text: what })
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) })
    } finally { setBusy(false) }
  }

  const saveDetails = () => run('Saved.', () => api.updateProject(project, {
    name: details.name.trim(),
    client: details.client.trim() || null,
    codename: details.codename.trim() || null,
    description: details.description.trim() || null,
    status: details.status,
  }))

  const addEntries = () => {
    const ls = lines.split('\n').map((l) => l.trim()).filter(Boolean)
    const cs = countries.split(/[\s,]+/).map((c) => c.trim()).filter(Boolean)
    if (!ls.length && !cs.length) return
    run('Added.', async () => {
      const r = await api.addProjectScope(project, {
        lines: ls, countries: cs, included: addTo === 'in',
        country: addCountry.trim() || null,
        include_subdomains: addSubs,
      })
      setLines(''); setCountries(''); setAddCountry(''); setAddSubs(false)
      // Named individually rather than counted: a line that did not load
      // is a rule that is not being enforced, and "3 errors" does not say
      // which rule.
      if (r.scope_errors?.length) {
        throw new Error(`Added, except: ${r.scope_errors.join(' · ')}`)
      }
    })
  }

  const entryRow = (e: Entry) => (
    <TableRow key={e.id} hover>
      <TableCell sx={{ py: 0.4 }}><KindChip kind={e.kind} /></TableCell>
      <TableCell sx={{ py: 0.4, fontFamily: `'Share Tech Mono', monospace`,
                       fontSize: 12.5 }}>
        {e.kind === 'country' ? e.value.toUpperCase() : e.value}
        {/* Written into the value, not only shown as the switch below.
            A row covering a whole zone has to read as one at a glance,
            the same way the server writes it into a refusal and the
            report prints it. */}
        {e.include_subdomains && (
          <Box component="span" sx={{ color: neon.yellow, ml: 0.6 }}>
            +subdomains
          </Box>
        )}
      </TableCell>
      {/* Only an FQDN can answer this. A wildcard already covers its
          subdomains and a range has none, so the control is absent
          rather than present-and-inert: a switch that does nothing on
          a security list is one somebody will read as a guarantee. */}
      <TableCell sx={{ py: 0.4, width: 96 }}>
        {e.kind !== 'fqdn' ? (
          <Box component="span" sx={{ color: alpha(neon.muted, 0.5) }}>—</Box>
        ) : (
          <Tooltip title={e.include_subdomains
            ? `Covers ${e.value} and everything under it. Turn off to cover only ${e.value}.`
            : `Covers only ${e.value}. Turn on to cover everything under it too.`}>
            <Switch size="small" checked={e.include_subdomains} disabled={busy}
              onChange={() => run(
                e.include_subdomains
                  ? `${e.value} now covers only itself.`
                  : `${e.value} now covers its subdomains too.`,
                () => api.patchProjectScope(project, e.id,
                  { include_subdomains: !e.include_subdomains }))} />
          </Tooltip>
        )}
      </TableCell>
      <TableCell sx={{ py: 0.4, width: 120 }}>
        {e.kind === 'country' ? (
          <Box component="span" sx={{ color: alpha(neon.muted, 0.5) }}>—</Box>
        ) : (
          <TextField
            size="small" variant="standard" placeholder="--"
            defaultValue={e.country ?? ''}
            slotProps={{ htmlInput: { maxLength: 2, size: 4,
                                      style: { fontSize: 12 } } }}
            onBlur={(ev) => {
              const v = ev.target.value.trim().toLowerCase()
              if (v === (e.country ?? '')) return
              run(v ? `Declared ${e.value} to be in ${v.toUpperCase()}.`
                    : `Cleared the country on ${e.value}.`,
                  () => api.patchProjectScope(project, e.id, { country: v }))
            }} />
        )}
      </TableCell>
      <TableCell sx={{ py: 0.4, width: 90 }}>
        <Tooltip title={e.included
          ? 'Move to the out-of-scope list'
          : 'Move to the in-scope list'}>
          <Switch size="small" checked={e.included} disabled={busy}
            onChange={() => run(
              `${e.value} moved to the ${e.included ? 'out' : 'in'} list.`,
              () => api.patchProjectScope(project, e.id,
                                          { included: !e.included }))} />
        </Tooltip>
      </TableCell>
      <TableCell sx={{ py: 0.4, width: 48 }}>
        <IconButton size="small" disabled={busy}
          onClick={() => run(`Removed ${e.value}.`,
                             () => api.deleteProjectScope(project, e.id))}
          sx={{ color: alpha(neon.muted, 0.8), '&:hover': { color: neon.red } }}>
          <DeleteIcon fontSize="small" />
        </IconButton>
      </TableCell>
    </TableRow>
  )

  const list = (title: string, rows: Entry[], colour: string, note: string) => (
    <Paper variant="outlined" sx={{ flex: 1, minWidth: 320,
                                    borderColor: alpha(colour, 0.4) }}>
      <Box sx={{ px: 1.6, py: 1 }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11.5,
                          letterSpacing: '0.14em', textTransform: 'uppercase',
                          color: colour, textShadow: glow(colour, 0.5) }}>
          {title} ({rows.length})
        </Typography>
        <Typography sx={{ fontSize: 11.5, color: neon.muted, mt: 0.4 }}>
          {note}
        </Typography>
      </Box>
      <Divider sx={{ borderColor: alpha(colour, 0.25) }} />
      {rows.length === 0
        ? <Typography sx={{ p: 1.6, fontSize: 12, color: alpha(neon.muted, 0.8) }}>
            Empty.
          </Typography>
        : <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontSize: 10.5 }}>Kind</TableCell>
                <TableCell sx={{ fontSize: 10.5 }}>Value</TableCell>
                <TableCell sx={{ fontSize: 10.5 }}>Subdomains</TableCell>
                <TableCell sx={{ fontSize: 10.5 }}>Country</TableCell>
                <TableCell sx={{ fontSize: 10.5 }}>In</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>{rows.map(entryRow)}</TableBody>
          </Table>}
    </Paper>
  )

  const v = viol.data
  return (
    <Box sx={{ p: 2.5, overflowY: 'auto', flex: 1 }}>
      {msg && (
        <Alert severity={msg.kind === 'ok' ? 'success' : 'error'} variant="outlined"
          sx={{ mb: 2 }} onClose={() => setMsg(null)}>{msg.text}</Alert>
      )}

      {/* ---------------------------------------------------- details */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2.5,
                                      borderColor: alpha(neon.pink, 0.35) }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                          letterSpacing: '0.14em', textTransform: 'uppercase',
                          color: neon.pink, textShadow: glow(neon.pink, 0.6),
                          mb: 1.5 }}>
          {data.project.code}
        </Typography>
        <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
          <TextField size="small" label="Name" value={details.name}
            sx={{ minWidth: 240 }}
            onChange={(e) => setDetails((d) => ({ ...d, name: e.target.value }))} />
          <TextField size="small" label="Client" value={details.client}
            sx={{ minWidth: 200 }}
            onChange={(e) => setDetails((d) => ({ ...d, client: e.target.value }))} />
          <TextField size="small" label="Codename" value={details.codename}
            sx={{ minWidth: 160 }}
            helperText="Internal. Names the channels and the scan directories."
            onChange={(e) => setDetails((d) => ({ ...d, codename: e.target.value }))} />
          <TextField size="small" select label="Status" value={details.status}
            sx={{ minWidth: 140 }}
            onChange={(e) => setDetails((d) => ({ ...d, status: e.target.value }))}>
            {['active', 'paused', 'complete', 'archived'].map((s) => (
              <MenuItem key={s} value={s} sx={{ fontSize: 12.5 }}>{s}</MenuItem>
            ))}
          </TextField>
        </Stack>
        <TextField size="small" label="Description" value={details.description}
          fullWidth multiline minRows={2} sx={{ mt: 1.5 }}
          onChange={(e) => setDetails((d) => ({ ...d, description: e.target.value }))} />
        <Button size="small" variant="outlined" disabled={busy} sx={{ mt: 1.5 }}
          onClick={saveDetails}>Save</Button>
        {/* The code is the join key for every target, finding and report
            in the engagement, so it is shown and not edited. */}
        <Typography sx={{ fontSize: 11, color: alpha(neon.muted, 0.85), mt: 1 }}>
          The project code cannot be changed here: it is the key every
          target, finding and report hangs off.
        </Typography>
      </Paper>

      <ProjectSlackCard project={data.project.code} />

      {/* ------------------------------------------------------ scope */}
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                        letterSpacing: '0.14em', textTransform: 'uppercase',
                        color: neon.cyan, textShadow: glow(neon.cyan, 0.6),
                        mb: 1 }}>
        Scope
      </Typography>
      <Alert severity={data.scope_defined ? 'warning' : 'info'} variant="outlined"
        sx={{ mb: 2, fontSize: 12.5 }}>
        {data.scope_defined ? (
          <>
            <strong>These lists are enforced.</strong> Out-of-scope beats
            in-scope: a host on both is barred, and nothing in this project
            may touch it — including tasking sent to a Drone agent.
            {data.allowlist_active
              ? ' An in-scope list exists, so the project may not acquire'
                + ' any host outside it. Hosts it already has are untouched.'
              : ' No in-scope list yet, so nothing is restricted to a list —'
                + ' only the out-of-scope entries bar anything.'}
          </>
        ) : (
          <>This project has no scope lists, so nothing is enforced. Adding
            one takes effect immediately for anything NEW, and deletes
            nothing that is already here.</>
        )}
      </Alert>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap
               alignItems="flex-start">
          {/* The kind on each pill is derived by src/lib/scopeEntry.ts,
              which is a port of the server's `classify` kept honest by a
              shared fixture — so the chip says what the row below will
              say once it is added, and not a second opinion about it.
              That includes the subdomains box beside it: a name under a
              tick renders through the same `entry_label` the table row,
              the report and Slack use, so the chip and the row that
              replaces it read identically. */}
          <PillInput
            label="Addresses, ranges, names, wildcards"
            value={lines} onChange={setLines} analyse={scopeAnalyse}
            accent={neon.cyan} sx={{ flex: 2, minWidth: 300 }}
            placeholder="203.0.113.0/24, 2001:db8::/32, portal.acme.example, *.acme.example"
            helperText="One per line. The kind is derived. A leading ! puts that line on the other list." />
          <Stack spacing={1.5} sx={{ minWidth: 230 }}>
            <TextField size="small" select label="Add to" value={addTo}
              onChange={(e) => setAddTo(e.target.value as 'in' | 'out')}>
              <MenuItem value="in" sx={{ fontSize: 12.5 }}>In scope</MenuItem>
              <MenuItem value="out" sx={{ fontSize: 12.5 }}>Out of scope</MenuItem>
            </TextField>
            {/* Beside the box the names are typed into, because the
                question it answers is one the operator has in mind at
                exactly that moment and never again until a scan is
                refused. */}
            <Box>
              <FormControlLabel
                control={<Checkbox size="small" checked={addSubs}
                           onChange={(e) => setAddSubs(e.target.checked)} />}
                label="Include subdomains"
                slotProps={{ typography: { sx: { fontSize: 12.5 } } }} />
              <Typography sx={{ fontSize: 11, color: neon.muted, mt: -0.3 }}>
                {addSubs
                  ? 'portal.acme.example also covers a.portal.acme.example.'
                  : 'Names cover themselves only. Ranges, addresses and'
                    + ' wildcards ignore this — a wildcard already says it.'}
              </Typography>
            </Box>
            <TextField size="small" label="Countries" value={countries}
              placeholder="jp, de"
              helperText="ISO 3166-1 alpha-2. Goes on the list chosen above."
              onChange={(e) => setCountries(e.target.value)} />
            <TextField size="small" label="Declare these ranges to be in"
              value={addCountry} placeholder="jp"
              slotProps={{ htmlInput: { maxLength: 2 } }}
              helperText="Optional. Nothing is looked up — this is your statement about where they are."
              onChange={(e) => setAddCountry(e.target.value)} />
            <Button size="small" variant="outlined" disabled={busy}
              onClick={addEntries}>Add</Button>
          </Stack>
        </Stack>
      </Paper>

      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ mb: 2.5 }}>
        {list('In scope', inList, neon.green,
              'What the project may acquire. Empty means no allowlist.')}
        {list('Out of scope', outList, neon.red,
              'Barred outright. Always wins over the in-scope list.')}
      </Stack>

      {/* ------------------------------------------------------ apply */}
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 12,
                        letterSpacing: '0.14em', textTransform: 'uppercase',
                        color: neon.yellow, textShadow: glow(neon.yellow, 0.6),
                        mb: 1 }}>
        Already in this project
      </Typography>
      <Paper variant="outlined" sx={{ p: 2, borderColor: alpha(neon.yellow, 0.3) }}>
        {viol.isLoading && <CircularProgress size={18} sx={{ color: neon.cyan }} />}
        {viol.error && (
          <Alert severity="error" variant="outlined">
            {(viol.error as Error).message}
          </Alert>
        )}
        {v && (
          <>
            <Typography sx={{ fontSize: 12.5, color: neon.text, mb: 1 }}>
              {v.violations.length} host(s) currently violate these lists.
            </Typography>
            {v.violations.length > 0 && (
              <>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontSize: 10.5 }}>Host</TableCell>
                      <TableCell sx={{ fontSize: 10.5 }}>Address</TableCell>
                      <TableCell sx={{ fontSize: 10.5 }}>Verdict</TableCell>
                      <TableCell sx={{ fontSize: 10.5 }}>Why</TableCell>
                      <TableCell sx={{ fontSize: 10.5 }}>Goes with it</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {v.violations.map((row) => (
                      <TableRow key={row.id} hover>
                        <TableCell sx={{ py: 0.4,
                                         fontFamily: `'Share Tech Mono', monospace`,
                                         fontSize: 12.5 }}>{row.host}</TableCell>
                        <TableCell sx={{ py: 0.4, fontSize: 12, color: neon.muted }}>
                          {row.ip_address ?? '—'}
                        </TableCell>
                        <TableCell sx={{ py: 0.4 }}>
                          <Chip size="small" label={row.verdict} sx={{
                            height: 19, fontSize: 10,
                            color: row.verdict === 'barred' ? neon.red : neon.yellow,
                            bgcolor: alpha(row.verdict === 'barred'
                              ? neon.red : neon.yellow, 0.14),
                            border: `1px solid ${alpha(row.verdict === 'barred'
                              ? neon.red : neon.yellow, 0.5)}` }} />
                        </TableCell>
                        <TableCell sx={{ py: 0.4, fontSize: 11.5,
                                         color: neon.muted }}>{row.reason}</TableCell>
                        <TableCell sx={{ py: 0.4, fontSize: 11.5,
                                         color: neon.muted }}>
                          {row.services} services · {row.vulns} findings · {row.pocs} PoCs
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <Stack direction="row" spacing={1.5} sx={{ mt: 1.5 }}>
                  <Button size="small" variant="outlined" startIcon={<GppBadIcon />}
                    disabled={busy} onClick={() => setConfirm(v)}
                    sx={{ color: neon.red, borderColor: alpha(neon.red, 0.5) }}>
                    Remove these {v.violations.length} host(s)
                  </Button>
                  <Button size="small" variant="outlined" disabled={busy}
                    onClick={() => run(
                      'Left in place. Nothing was recorded, so they will be '
                      + 'reported again.',
                      () => api.applyProjectScope(project, 'ignore'))}>
                    Ignore
                  </Button>
                </Stack>
                <Typography sx={{ fontSize: 11, color: alpha(neon.muted, 0.9),
                                  mt: 1 }}>
                  Ignoring records nothing: these hosts will be listed again
                  next time. A remembered "ignore" is a way for an
                  out-of-scope host to become invisible, which is what this
                  page exists to prevent.
                </Typography>
              </>
            )}
          </>
        )}
      </Paper>

      {/* Deletion is irreversible and cascades, so the hosts are named
          again at the moment of confirming — not just counted. */}
      <Dialog open={!!confirm} onClose={() => setConfirm(null)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontSize: 15, color: neon.red }}>
          Remove {confirm?.violations.length} host(s) from {project}?
        </DialogTitle>
        <DialogContent dividers>
          <Typography sx={{ fontSize: 12.5, mb: 1.5 }}>
            This deletes the targets below and everything recorded against
            them — services, findings, PoCs, captured traffic and timeline.
            It cannot be undone.
          </Typography>
          <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
            {confirm?.violations.map((row) => (
              <li key={row.id}>
                <Typography component="span" sx={{
                  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5 }}>
                  {row.host}
                </Typography>
                <Typography component="span" sx={{ fontSize: 11.5,
                                                   color: neon.muted }}>
                  {' '}— {row.services} services, {row.vulns} findings,
                  {' '}{row.pocs} PoCs
                </Typography>
              </li>
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button size="small" onClick={() => setConfirm(null)}>Cancel</Button>
          <Button size="small" disabled={busy} sx={{ color: neon.red }}
            onClick={() => {
              const hosts = (confirm?.violations ?? []).map((row) => row.host)
              setConfirm(null)
              run(`Removed ${hosts.length} host(s).`,
                  () => api.applyProjectScope(project, 'remove', hosts))
            }}>
            Remove them
          </Button>
        </DialogActions>
      </Dialog>

      <DeleteProjectCard project={data.project.code} />
    </Box>
  )
}
