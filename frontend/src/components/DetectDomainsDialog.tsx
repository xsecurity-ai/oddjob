import { useMemo, useState } from 'react'
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, LinearProgress, Stack,
  Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isLive } from './droneTasking'
import { api, type DomainCandidate, type DetectResult } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * Suggest hostnames worth trying, from what the project already knows.
 *
 * Nothing here resolves or probes anything — candidates are extrapolated
 * from names already recorded, and every one carries the reason it was
 * suggested. They stay hypotheses until promoted, because a guessed name
 * is a guess and an inventory row is a claim.
 */

const SOURCE_COLOUR: Record<string, string> = {
  sequence: neon.green, environment: neon.cyan, label: neon.purple,
  sibling: neon.yellow, certificate: neon.pink, reference: neon.muted,
}

/** Mirrors `EnumerateRequest.wanted` in backend/app/routers/domains.py.
 *
 *  Operators paste from spreadsheets, scope documents and chat
 *  messages. Making them reformat first is the friction that sends
 *  people back to a terminal, so schemes, paths, wildcards, commas and
 *  newlines are all accepted here and normalised the same way the
 *  server does it. */
export function parseDomains(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const piece of (raw || '').split(/[\s,;]+/)) {
    const v = piece.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '')
                   .replace(/^[a-z]+:\/\//, '').split('/')[0].split('?')[0]
    if (v && !seen.has(v)) { seen.add(v); out.push(v) }
  }
  return out
}

export function DetectDomainsDialog({ project, onClose, seed = [],
                                      allHosts = [], onQueued }: {
  project: string
  /** Hosts ticked in the grid behind this. Picking an action after
   *  making a selection should start from the selection, not from an
   *  empty box. */
  seed?: string[]
  /** Every host on the project, for "all hosts" below. */
  allHosts?: string[]
  /** Called once work is handed to an agent; the parent closes this
   *  and reports it outside the modal. Detection itself does not use
   *  it — it produces candidates to look at, so closing on it would
   *  throw away the thing the operator asked for. */
  onQueued?: (summary: string) => void
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [domain, setDomain] = useState(seed.join('\n'))
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [result, setResult] = useState<DetectResult | null>(null)
  // What was actually submitted, so a re-run after promoting asks for
  // the same domains rather than for the summary string.
  const agents = useQuery({
    queryKey: ['agents', project],
    queryFn: () => api.agents(project),
  })
  const [ran, setRan] = useState<string[]>([])
  const [autoAdd, setAutoAdd] = useState(false)
  //: Progress through a batched sweep, so a long run is visibly
  //: running rather than apparently hung.
  const [sweep, setSweep] = useState<{ done: number; total: number } | null>(null)
  const [picked, setPicked] = useState<Set<number>>(new Set())

  const roots = useQuery({
    queryKey: ['domain-roots', project],
    queryFn: () => api.domainRoots(project),
  })
  const searched = useQuery({
    queryKey: ['domain-searches', project],
    queryFn: () => api.domainSearches(project),
  })

  const alreadySearched = useMemo(
    () => new Set((searched.data ?? []).map((s) => s.domain)),
    [searched.data])


  // Every hostname on the project, not just the registrable roots.
  // Searching under `web01.corp.com` finds names the root sweep never
  // proposes, and detection sends nothing, so the only cost is the
  // list getting long.
  //
  // Ones already searched are left out rather than re-run: that is the
  // whole point of the memory, and a sweep that re-asked every host
  // every time would report "nothing new" four hundred times.
  const hostCandidates = useMemo(() => {
    const out: string[] = []
    const seen = new Set<string>()
    for (const h of allHosts) {
      const v = (h || '').trim().toLowerCase().replace(/\.$/, '')
      // An address has no zone under it; the server refuses these
      // individually, and filtering here keeps the count honest.
      if (!v || !v.includes('.') || /^[0-9.]+$/.test(v) || v.includes(':')) continue
      if (seen.has(v) || alreadySearched.has(v)) continue
      seen.add(v)
      out.push(v)
    }
    return out
  }, [allHosts, alreadySearched])

  /** Everything worth sweeping, once. The roots and the hostnames
   *  were two buttons; they are one list. Already-searched names stay
   *  out — that is what the memory is for, and a sweep that re-asked
   *  every host would report "nothing new" four hundred times. */
  const sweepAll = useMemo(() => {
    const out: string[] = []
    const seen = new Set<string>()
    for (const v of [...(roots.data ?? []).map((r) => r.domain), ...hostCandidates]) {
      const k = (v || '').trim().toLowerCase().replace(/\.$/, '')
      if (!k || seen.has(k) || alreadySearched.has(k)) continue
      seen.add(k)
      out.push(k)
    }
    return out
  }, [roots.data, hostCandidates, alreadySearched])

  /** Detect against one domain, several, or every root.
   *
   *  One request, not one per domain: the endpoint takes a list and
   *  reports per-domain, so a typo in the fourth of eight no longer
   *  costs the other seven and the sweep is a single round trip. */
  const run = async (force = false, which?: string[]) => {
    const list = (which ?? parseDomains(domain)).filter(Boolean)
    if (!list.length) return
    setBusy(true); setErr(null)
    try {
      const r = await api.detectDomains(
        project, list, force, autoAdd,
        // A sweep over four hundred hostnames goes out in batches of
        // fifty, and without this the dialog looks frozen for the
        // length of all of them.
        list.length > 50
          ? (done, total) => setSweep({ done, total })
          : undefined)
      setResult(r)
      setRan(list)
      setPicked(new Set())
      if (r.errors.length) {
        setErr(`${r.errors.length} did not run: `
               + r.errors.slice(0, 3).join('; ')
               + (r.errors.length > 3 ? ' …' : ''))
      }
      await qc.invalidateQueries({ queryKey: ['domain-searches', project] })
      await qc.invalidateQueries({ queryKey: ['domain-roots', project] })
      if (r.promoted.length) await qc.invalidateQueries({ queryKey: ['targets'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false); setSweep(null) }
  }


  /** Promote, hand to a Drone, and get out of the way.
   *
   *  Adding a name as a target and then enumerating it were two
   *  buttons, and nobody wanted the first without the second: a
   *  candidate is a guess, and the only way it becomes worth anything
   *  is an agent going and looking. So promotion queues the lookup
   *  too, and the dialog closes, because the answer arrives on the
   *  Drones page rather than here.
   *
   *  Promotion is what must not fail. If no agent is online the names
   *  are still added — reported, not silently dropped — and the sweep
   *  can be run again later from the Targets page. */
  const act = async (what: 'promote' | 'reject') => {
    const ids = [...picked]
    if (!ids.length) return
    setBusy(true); setErr(null)
    try {
      if (what !== 'promote') {
        await api.rejectDomains(project, ids)
        // `ran`, not `result.domain` — after a sweep that string is
        // "7 domain(s)", which is not a domain and came back 422.
        setResult(await api.detectDomains(project, ran, false))
        setPicked(new Set())
        await qc.invalidateQueries()
        return
      }

      const names = (result?.candidates ?? [])
        .filter((c) => picked.has(c.id)).map((c) => c.name)
      await api.promoteDomains(project, ids)

      let note = `Added ${ids.length} target${ids.length === 1 ? '' : 's'}`
      if (!noAgents && names.length) {
        try {
          const q = await api.enumerateDomains(project, names.join('\n'), 'passive')
          const refused = Object.keys(q.refused).length
          note += `. Queued ${q.queued.length} enumeration`
                + `${q.queued.length === 1 ? '' : 's'} across `
                + `${q.agents_online} online agent`
                + `${q.agents_online === 1 ? '' : 's'}`
                + (refused ? `; ${refused} refused` : '')
        } catch (e) {
          // The targets are already in. Say what did not happen
          // rather than failing the whole action over it.
          note += `, but enumeration could not be queued: `
                + (e instanceof Error ? e.message : String(e))
        }
      } else if (noAgents) {
        note += `, not enumerated: ${noAgents}`
      }
      await qc.invalidateQueries()
      onQueued?.(note)
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  const toggle = (id: number) => setPicked((p) => {
    const n = new Set(p)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })

  const typed = parseDomains(domain)
  const live = (agents.data ?? []).filter(isLive).length
  const noAgents = live
    ? ''
    : (agents.data ?? []).length
      ? 'Every Drone agent on this project is offline, so there is nothing '
        + 'to run the enumeration.'
      : 'No Drone agent is enrolled on this project. Add one under Drone.'
  const candidates = result?.candidates ?? []
  const allPicked = candidates.length > 0 && picked.size === candidates.length

  return (
    <Dialog open onClose={onClose} maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 44px ${alpha(neon.cyan, 0.22)}`,
        width: '94vw', maxWidth: 1100,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan,
                         textShadow: glow(neon.cyan, 0.5),
                         borderBottom: `1px solid ${alpha(neon.cyan, 0.28)}` }}>
        DETECT NEW DOMAINS → {project}
      </DialogTitle>

      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}

          <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
            Candidates are extrapolated from hostnames this project already
            knows — naming patterns, environment pairs, numbering. <b>Nothing
            is resolved and no packets are sent</b>, so every suggestion is a
            hypothesis until you promote it.
          </Alert>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems="flex-start">
            <Autocomplete
              freeSolo size="small" sx={{ flex: 1 }}
              options={(roots.data ?? []).map((r) => r.domain)}
              value={domain}
              onInputChange={(_, v) => setDomain(v)}
              renderOption={(props, option) => {
                const r = (roots.data ?? []).find((x) => x.domain === option)
                return (
                  <Box component="li" {...props} key={option}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ width: '100%' }}>
                      <Box sx={{ flex: 1, fontSize: 13 }}>{option}</Box>
                      <Typography sx={{ fontSize: 10.5, color: neon.muted }}>
                        {r?.known_hosts} known
                      </Typography>
                      {r?.searched && (
                        <Chip size="small" label="searched" sx={{
                          height: 16, fontSize: 9, bgcolor: alpha(neon.muted, 0.15),
                          color: neon.muted }} />
                      )}
                    </Stack>
                  </Box>
                )
              }}
              renderInput={(p) => (
                <TextField {...p} label="Domains" multiline maxRows={4}
                  placeholder="corp.com, other.example&#10;one-per-line also fine"
                  helperText={typed.length > 1
                    ? `${typed.length} domains — ${typed.slice(0, 3).join(', ')}`
                      + (typed.length > 3 ? '…' : '')
                    : 'One, several, or a pasted list. Commas, spaces and '
                      + 'newlines all work; URLs and *. are trimmed.'} />
              )}
            />
            {/* One sweep, not two. "All" and "All hosts" differed only
                in which list they walked — registrable roots versus
                every hostname — and nobody picking between them was
                choosing on that basis. The union is what both were
                reaching for. */}
            <Tooltip title={sweepAll.length
              ? `Search under every domain and hostname this project `
                + `touches that has not been searched yet `
                + `(${sweepAll.length}). Offline — it extrapolates from `
                + `names already held and sends nothing.`
              : 'Nothing left to sweep: everything this project knows about '
                + 'has been searched. Type a domain above instead.'}>
              <span>
                <Button variant="outlined"
                  disabled={busy || !sweepAll.length}
                  onClick={() => run(false, sweepAll)}
                  sx={{ mt: 0.3, color: neon.green,
                        borderColor: alpha(neon.green, 0.6) }}>
                  {busy ? '…' : `All${sweepAll.length ? ` (${sweepAll.length})` : ''}`}
                </Button>
              </span>
            </Tooltip>
            {alreadySearched.has(domain.trim().toLowerCase()) && (
              <Tooltip title="Searched before — run again to look for names that new data has made possible">
                <Button variant="text" disabled={busy} onClick={() => run(true)}
                  sx={{ mt: 0.3, color: neon.yellow, fontSize: 11 }}>
                  Search again
                </Button>
              </Tooltip>
            )}
          </Stack>

          <Stack direction="row" spacing={1} alignItems="center">
            <FormControlLabel
              control={<Checkbox size="small" checked={autoAdd}
                         onChange={(e) => setAutoAdd(e.target.checked)} />}
              label={
                <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
                  Add detected names as targets without asking
                </Typography>
              } />
            {autoAdd && (
              // Said before it happens, not after. These are guesses,
              // and a guess filed as inventory is a host somebody will
              // later try to scan.
              <Typography sx={{ fontSize: 11, color: neon.yellow }}>
                extrapolated names are unverified — out-of-scope ones are
                still refused
              </Typography>
            )}
          </Stack>

          {result?.promoted?.length ? (
            <Alert severity="success" variant="outlined" sx={{ fontSize: 12 }}>
              Added {result.promoted.length} target
              {result.promoted.length === 1 ? '' : 's'}:{' '}
              {result.promoted.slice(0, 6).join(', ')}
              {result.promoted.length > 6
                ? ` and ${result.promoted.length - 6} more` : ''}
            </Alert>
          ) : null}

          {sweep && sweep.total > 0 && (
            <Box>
              <LinearProgress variant="determinate"
                value={(sweep.done / sweep.total) * 100}
                sx={{ height: 3, bgcolor: alpha(neon.purple, 0.2),
                      '& .MuiLinearProgress-bar': { bgcolor: neon.purple } }} />
              <Typography sx={{ fontSize: 11, color: neon.muted, mt: 0.4 }}>
                {sweep.done} of {sweep.total} searched
              </Typography>
            </Box>
          )}
          {busy && !sweep && <LinearProgress sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                                         '& .MuiLinearProgress-bar': { bgcolor: neon.cyan } }} />}

          {result && (
            <>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
                <Chip size="small" label={`${result.new_candidates} new`} sx={chip(neon.green)} />
                <Chip size="small" label={`${result.already_known} already in the estate`}
                      sx={chip(neon.muted)} />
                <Chip size="small" label={`run ${result.runs}`} sx={chip(neon.purple)} />
              </Stack>
              {result.note && (
                <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
                  {result.note}
                </Alert>
              )}
            </>
          )}

          {candidates.length > 0 && (
            <Box sx={{ maxHeight: '46vh', overflow: 'auto',
                       border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ ...headSx, width: 40 }}>
                      <Checkbox size="small" checked={allPicked}
                        indeterminate={picked.size > 0 && !allPicked}
                        onChange={() => setPicked(allPicked ? new Set()
                          : new Set(candidates.map((c) => c.id)))}
                        sx={{ p: 0.4, color: neon.muted,
                              '&.Mui-checked': { color: neon.cyan } }} />
                    </TableCell>
                    {['Hostname', 'Score', 'Why', 'Source', 'Seen'].map((h) => (
                      <TableCell key={h} sx={headSx}>{h}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {candidates.map((c: DomainCandidate) => {
                    const sc = SOURCE_COLOUR[c.source] ?? neon.muted
                    return (
                      <TableRow key={c.id} hover selected={picked.has(c.id)}
                        onClick={() => toggle(c.id)} sx={{ cursor: 'pointer' }}>
                        <TableCell sx={cellSx}>
                          <Checkbox size="small" checked={picked.has(c.id)}
                            sx={{ p: 0.4, color: neon.muted,
                                  '&.Mui-checked': { color: neon.cyan } }} />
                        </TableCell>
                        <TableCell sx={{ ...cellSx, color: neon.cyan }}>{c.name}</TableCell>
                        <TableCell sx={{ ...cellSx, width: 70 }}>
                          <Box sx={{ color: c.score >= 75 ? neon.green
                                      : c.score >= 45 ? neon.yellow : neon.muted,
                                     fontWeight: 700 }}>{c.score}</Box>
                        </TableCell>
                        <TableCell sx={{ ...cellSx, color: alpha(neon.text, 0.85),
                                         fontFamily: 'inherit', fontSize: 11.5 }}>
                          {c.reason}
                        </TableCell>
                        <TableCell sx={{ ...cellSx, width: 120 }}>
                          <Chip size="small" label={c.source} sx={chip(sc)} />
                        </TableCell>
                        <TableCell sx={{ ...cellSx, width: 60, color: neon.muted }}>
                          {c.times_seen > 1 ? `×${c.times_seen}` : ''}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </Box>
          )}

          {result && candidates.length === 0 && (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              No candidates. Either everything this project's patterns suggest
              already exists, or there is not yet enough recorded under other
              domains to extrapolate from.
            </Typography>
          )}
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Typography sx={{ fontSize: 11, color: neon.muted, mr: 'auto' }}>
          {picked.size > 0 ? `${picked.size} selected` : ''}
        </Typography>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button disabled={busy || !picked.size} onClick={() => act('reject')}
          sx={{ color: neon.red }}>Reject</Button>
        <Button variant="outlined" disabled={busy || !picked.size}
          onClick={() => act('promote')}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.6) }}>
          Add {picked.size || ''} as target{picked.size === 1 ? '' : 's'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

const chip = (c: string) => ({
  height: 18, fontSize: 10, bgcolor: alpha(c, 0.15), color: c,
  border: `1px solid ${alpha(c, 0.45)}`,
})
const headSx = {
  fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.12em',
  textTransform: 'uppercase', color: alpha(neon.cyan, 0.8),
  backgroundColor: alpha(neon.bgDeep, 0.95),
  borderBottom: `1px solid ${alpha(neon.cyan, 0.3)}`, py: 0.6,
} as const
const cellSx = {
  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12, color: neon.text,
  borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`, py: 0.5,
} as const
