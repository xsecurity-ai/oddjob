/**
 * Discovery over ranges, selected targets, or anything typed in.
 *
 * Three sources, because "scan new ranges" turned out to be one of
 * three things an operator means by it. The uncovered-scope list is
 * the one this started as. But a selection already made in the grid is
 * the commonest intent — you tick six hosts and want those scanned,
 * and being shown a list of scope ranges instead is the dialog
 * ignoring what you just told it. And neither covers "scan this one
 * CIDR I was handed in an email", which is why there is a box.
 *
 * They combine. What runs is the union of everything ticked, and the
 * count says so before anything is queued.
 *
 * "Not covered" here means the project holds no target with an address
 * inside the range. That is a statement about our coverage and not
 * about the client's network: a range with no targets has not been
 * looked at, which is a different claim from a range that is empty.
 * The column is labelled accordingly.
 *
 * Only included scope entries are offered. A scope document is almost
 * always "this /16 except these hosts", and putting the exclusions on a
 * list of things to scan is how the exclusions get scanned.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, DialogActions, DialogContent,
  LinearProgress, Stack, Table, TableBody, TableCell,
  TableHead, TableRow, TextField, Typography, alpha,
} from '@mui/material'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import {
  AgentChooser, Argv, Caveat, EnumerateDialog, FleetNotice, chipSx,
} from './EnumerateBits'
import {
  needsRegion, queueEach, rawSockets, useFleet, type AgentChoice,
} from './droneTasking'

/** Above this, a discovery sweep is a decision rather than a click. */
const LARGE = 4096

/** Mirrors the server's own parsing: one per line, or comma separated. */
export function parseSubjects(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const piece of (raw || '').split(/[\s,;]+/)) {
    const v = piece.trim().toLowerCase().replace(/\.$/, '')
    if (v && !seen.has(v)) { seen.add(v); out.push(v) }
  }
  return out
}

export function ScanRangesDialog({ project, selected = [], onClose,
                                  onQueued }: {
  project: string
  /** Rows ticked in the grid behind this. When there are any, they are
   *  what the operator meant, so they lead and start checked. */
  selected?: Array<{ host: string; ip_address?: string | null }>
  onClose: () => void
  /** Called with the confirmation once work is queued; the parent
   *  closes this and reports it outside the modal. */
  onQueued?: (summary: string) => void
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [tool, setTool] = useState<'masscan' | 'nmap'>('masscan')
  const [ports, setPorts] = useState('80,443,8080,8443')
  const [picked, setPicked] = useState<Set<string>>(new Set())
  // Pre-checked: the selection is a statement of intent already made,
  // and making it again in here would be asking twice.
  const [useSelected, setUseSelected] = useState(selected.length > 0)
  const [manual, setManual] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)
  /** Ranges the queue refused because the scope does not cover them.
   *  Held so they can be offered, rather than reported and lost. */
  const [outOfScope, setOutOfScope] = useState<string[]>([])

  const q = useQuery({
    queryKey: ['enumerate-ranges', project],
    queryFn: () => api.enumerateRanges(project),
  })
  const uncovered = useMemo(
    () => (q.data ?? []).filter((r) => r.targets === 0), [q.data])
  const covered = useMemo(
    () => (q.data ?? []).filter((r) => r.targets > 0), [q.data])

  const chosen = useMemo(
    () => uncovered.filter((r) => picked.has(r.value)), [uncovered, picked])

  // An address where there is one: a scan wants the host it can reach,
  // and a name that has already been resolved resolves again for
  // nothing. Where there is no address the name is used and the agent
  // resolves it.
  const fromSelected = useMemo(
    () => (useSelected ? selected.map((t) => t.ip_address || t.host) : []),
    [useSelected, selected])
  const fromManual = useMemo(() => parseSubjects(manual), [manual])

  const subjects = useMemo(() => {
    const seen = new Set<string>()
    const out: string[] = []
    for (const v of [...fromSelected, ...fromManual,
                     ...chosen.map((r) => r.value)]) {
      if (v && !seen.has(v)) { seen.add(v); out.push(v) }
    }
    return out
  }, [fromSelected, fromManual, chosen])

  // Only the scope ranges carry a known address count; a typed CIDR is
  // not expanded here. Reported as "at least", because claiming an
  // exact figure that excludes two of the three sources would be worse
  // than admitting the number is a floor.
  const addresses = chosen.reduce((n, r) => n + r.addresses, 0)

  const priv = rawSockets(fleet, agent)
  // masscan does not degrade. Without raw sockets it refuses outright
  // rather than falling back, so offering it against an unprivileged
  // agent queues a task that can only fail.
  const masscanImpossible = tool === 'masscan' && priv === false
  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = !subjects.length || !!fleet.blocked || regionMissing
               || masscanImpossible

  const toggle = (v: string) => setPicked((p) => {
    const n = new Set(p)
    if (n.has(v)) n.delete(v); else n.add(v)
    return n
  })

  // One target, because one task per target is what gets queued; the
  // count is said separately rather than crammed onto a command line
  // that will never be run in that form.
  const head = subjects[0] ?? '<nothing selected>'
  const more = ''
  const argv = tool === 'masscan'
    ? `masscan -oX <task output> -p ${ports || '80,443,8080,8443'} --rate 1000 `
      + head + more
    : `nmap -oX <task output>${ports ? ` -p ${ports}` : ''} -sV`
      + (priv === true ? ' -sS' : priv === null
         ? ' [-sS if the agent has raw sockets]' : '')
      + ` ${head}${more}`

  const run = async () => {
    setBusy(true); setErr(null)
    try {
      // One task per range, not one task holding all of them: forty
      // ranges in a single task is forty ranges on one agent while the
      // rest of the fleet is idle, and one failure takes the lot.
      const extra: Record<string, unknown> = {}
      if (ports.trim()) extra.ports = ports.trim()
      const { ids, failed } = await queueEach(project, agent, tool, subjects,
                                              extra, region)
      if (!ids.length) {
        setErr(`Nothing was queued. ${failed[0]?.why ?? ''}`)
        return
      }
      const parts = [
        fromSelected.length && `${fromSelected.length} selected target(s)`,
        fromManual.length && `${fromManual.length} typed in`,
        chosen.length && `${chosen.length} scope range(s), `
                         + `${addresses.toLocaleString()} addresses`,
      ].filter(Boolean)
      const msg = `Queued ${ids.length} task${ids.length === 1 ? '' : 's'}, one `
                  + `per target, over ${parts.join(' + ')}`
                  + (failed.length
                     ? `. ${failed.length} refused: ${failed[0].subject} — `
                       + `${failed[0].why}`
                     : `. Results import into ${project} as each reports back.`)
      await qc.invalidateQueries({ queryKey: ['agents'] })

      // Anything refused for scope is offered rather than just
      // reported. Typing a range the scope does not cover is the
      // normal way an engagement grows, and "refused: out of scope"
      // with no way to act on it sends the operator to another screen
      // to retype what they just typed here.
      const oos = failed.filter((f) => /scope/i.test(f.why))
      if (oos.length) {
        setOutOfScope(oos.map((f) => f.subject))
        setDone(msg)
        return
      }

      if (onQueued) onQueued(msg); else setDone(msg)
      // Closed on success, because the answer arrives on the Drones
      // page and there is nothing further to do here. Left open when
      // something was refused — that is the case worth reading.
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  /** Add the refused ranges to the scope, then queue them.
   *
   *  Deliberately two steps the operator asked for rather than one
   *  they did not: widening a client's scope is a decision, so it is
   *  a button and not something the queue does on their behalf. */
  const addScopeAndQueue = async () => {
    if (!outOfScope.length) return
    setBusy(true); setErr(null)
    try {
      await api.addProjectScope(project, { lines: outOfScope, included: true })
      const extra: Record<string, unknown> = {}
      if (ports.trim()) extra.ports = ports.trim()
      const { ids, failed } = await queueEach(project, agent, tool, outOfScope,
                                              extra, region)
      const msg = `Added ${outOfScope.length} range`
                + `${outOfScope.length === 1 ? '' : 's'} to scope and queued `
                + `${ids.length} task${ids.length === 1 ? '' : 's'}`
                + (failed.length ? `; ${failed.length} still refused` : '')
      setOutOfScope([])
      await qc.invalidateQueries()
      if (onQueued) onQueued(msg); else setDone(msg)
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <EnumerateDialog accent={neon.purple} onClose={onClose}
      title={`SCAN NEW RANGES → ${project}`}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}
          {done && <Alert severity="success" variant="outlined" sx={{ fontSize: 12.5 }}>{done}</Alert>}
          <FleetNotice fleet={fleet} />
          {q.isLoading && (
            <LinearProgress sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                                  '& .MuiLinearProgress-bar': { bgcolor: neon.purple } }} />
          )}
          {q.error && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>
              {(q.error as Error).message}
            </Alert>
          )}

          {/* The selection leads when there is one. Being shown a list
              of scope ranges after ticking six hosts is the dialog
              ignoring what was just said to it. */}
          {selected.length > 0 && (
            <Box sx={{ border: `1px solid ${alpha(neon.cyan, 0.4)}`,
                       borderRadius: 1, p: 1.2 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Checkbox size="small" checked={useSelected}
                  onChange={(e) => setUseSelected(e.target.checked)} />
                <Box sx={{ flex: 1 }}>
                  <Typography sx={{ fontSize: 12.5, color: neon.cyan }}>
                    Scan the {selected.length} target
                    {selected.length === 1 ? '' : 's'} selected behind this
                  </Typography>
                  <Typography sx={{ fontSize: 11, color: neon.muted,
                                    fontFamily: `'Share Tech Mono', monospace`,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap' }}>
                    {selected.slice(0, 6).map((t) => t.ip_address || t.host)
                            .join(', ')}
                    {selected.length > 6 ? ` …+${selected.length - 6}` : ''}
                  </Typography>
                </Box>
              </Stack>
            </Box>
          )}

          <TextField size="small" fullWidth multiline minRows={2} maxRows={6}
            label="Or scan these" value={manual}
            onChange={(e) => setManual(e.target.value)}
            placeholder={'198.51.100.0/24\n203.0.113.10\nportal.acme.example'}
            helperText={fromManual.length
              ? `${fromManual.length} entr${fromManual.length === 1 ? 'y' : 'ies'}`
                + ' — addresses, CIDRs and names all work. Scope still decides.'
              : 'Addresses, CIDRs or names. One per line or comma separated. '
                + 'Anything out of scope is refused when it is queued.'}
            slotProps={{ htmlInput: { style: {
              fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5 } } }} />

          <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
            A range is listed as uncovered when this project holds no target
            with an address inside it. That says nothing has been scanned
            there — not that there is nothing there.
          </Alert>

          {!q.isLoading && !uncovered.length && (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              Every included range in this project's scope already has at least
              one target in it. {covered.length
                ? `${covered.length} range(s) checked.`
                : 'There are no CIDR entries in the scope to check.'}
            </Typography>
          )}

          {uncovered.length > 0 && (
            <Box sx={{ maxHeight: '34vh', overflow: 'auto',
                       border: `1px solid ${alpha(neon.purple, 0.25)}`,
                       borderRadius: 1 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ ...headSx, width: 44 }} />
                    <TableCell sx={headSx}>Range</TableCell>
                    <TableCell sx={headSx}>Addresses</TableCell>
                    <TableCell sx={headSx}>Coverage</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {uncovered.map((r) => (
                    <TableRow key={r.value} hover selected={picked.has(r.value)}
                      onClick={() => toggle(r.value)} sx={{ cursor: 'pointer' }}>
                      <TableCell sx={cellSx}>
                        <Checkbox size="small" checked={picked.has(r.value)}
                          sx={{ p: 0.4, color: neon.muted,
                                '&.Mui-checked': { color: neon.purple } }} />
                      </TableCell>
                      <TableCell sx={{ ...cellSx, color: neon.cyan }}>{r.value}</TableCell>
                      <TableCell sx={cellSx}>
                        {r.addresses.toLocaleString()}
                        {r.addresses > LARGE && (
                          <Chip size="small" label="large" sx={{ ...chipSx(neon.yellow), ml: 1 }} />
                        )}
                      </TableCell>
                      <TableCell sx={{ ...cellSx, color: neon.muted }}>
                        not scanned
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}

          {addresses > LARGE && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
              {addresses.toLocaleString()} addresses selected. That is a lot of
              packets into someone else's network — check it is what the rules
              of engagement allow before queueing it.
            </Alert>
          )}

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <TextField select size="small" label="Tool" value={tool}
              sx={{ minWidth: 200 }}
              slotProps={{ select: { native: true } }}
              onChange={(e) => setTool(e.target.value as 'masscan' | 'nmap')}>
              <option value="masscan">masscan — fast sweep</option>
              <option value="nmap">nmap — slower, identifies services</option>
            </TextField>
            <TextField size="small" label="Ports" value={ports} sx={{ flex: 1 }}
              onChange={(e) => setPorts(e.target.value)}
              helperText={tool === 'masscan'
                ? 'masscan needs ports; the agent defaults to 80,443,8080,8443.'
                : 'Empty lets the agent choose. Naming ports also stops it adding -F.'} />
          </Stack>

          {masscanImpossible && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
              masscan builds its own packets and refuses to run without raw
              sockets — it does not fall back the way nmap does. This agent has
              none, so the task would fail rather than scan. Use nmap, or pick
              an agent with raw sockets.
            </Alert>
          )}

          <AgentChooser fleet={fleet} value={agent} onChange={setAgent}
            region={region} onRegion={setRegion} />

          <Box>
            <Typography sx={{ fontSize: 10.5, color: neon.muted, mb: 0.5 }}>
              What the agent will run
            </Typography>
            <Argv text={argv} repeat={subjects.length} />
          </Box>

          <Caveat>
            Results import in strict mode, as every agent result does: hosts
            this project has never seen are surveyed and nothing is written
            until someone answers for them.
          </Caveat>
        </Stack>
      </DialogContent>
      {outOfScope.length > 0 && (
        <Alert severity="warning" variant="outlined"
               sx={{ mx: 3, mb: 1, fontSize: 12 }}
               action={
                 <Button size="small" disabled={busy} onClick={addScopeAndQueue}
                   sx={{ color: neon.green, whiteSpace: 'nowrap' }}>
                   Add to scope &amp; queue
                 </Button>
               }>
          {outOfScope.length} range{outOfScope.length === 1 ? ' is' : 's are'} not
          in {project}&apos;s scope and {outOfScope.length === 1 ? 'was' : 'were'}
          {' '}refused: {outOfScope.slice(0, 4).join(', ')}
          {outOfScope.length > 4 ? ` and ${outOfScope.length - 4} more` : ''}.
        </Alert>
      )}

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Typography sx={{ fontSize: 11, color: neon.muted, mr: 'auto' }}>
          {chosen.length ? `${chosen.length} range(s), ${addresses.toLocaleString()} addresses` : ''}
        </Typography>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="outlined" disabled={busy || stop} onClick={run}
          sx={{ color: neon.purple, borderColor: alpha(neon.purple, 0.6) }}>
          {busy ? '…' : 'Queue discovery scan'}
        </Button>
      </DialogActions>
    </EnumerateDialog>
  )
}

const headSx = {
  fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.12em',
  textTransform: 'uppercase', color: alpha(neon.purple, 0.85),
  backgroundColor: alpha(neon.bgDeep, 0.95),
  borderBottom: `1px solid ${alpha(neon.purple, 0.3)}`, py: 0.6,
} as const
const cellSx = {
  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12, color: neon.text,
  borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`, py: 0.5,
} as const
