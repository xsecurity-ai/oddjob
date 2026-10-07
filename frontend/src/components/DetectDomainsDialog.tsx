import { useMemo, useState } from 'react'
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, LinearProgress, Stack,
  Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isLive } from './jawsTasking'
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

export function DetectDomainsDialog({ project, onClose }: {
  project: string; onClose: () => void
}) {
  const qc = useQueryClient()
  const [domain, setDomain] = useState('')
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
  const [queued, setQueued] =
    useState<Awaited<ReturnType<typeof api.enumerateDomains>> | null>(null)
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

  /** Detect across every root this project touches.
   *
   *  Generation is offline — it extrapolates from names already held
   *  and performs no lookups — so running it for every root costs
   *  nothing on the wire and is the obvious thing to want. Doing them
   *  one at a time was busywork.
   *
   *  Results accumulate rather than replace, because the point is one
   *  list to triage. Roots already searched are included: the whole
   *  reason to re-run is that new data has since made new names
   *  derivable. */
  const runAll = () => run(true, (roots.data ?? []).map((r) => r.domain))

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
      const r = await api.detectDomains(project, list, force, autoAdd)
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
    } finally { setBusy(false) }
  }

  /** Hand the list to an agent and let the results file themselves.
   *
   *  The other button guesses names from patterns; this one has a
   *  scanner go and look. Nothing to triage afterwards — a name a tool
   *  resolved is a finding, so it becomes a target when the task
   *  reports back. */
  const sendToJaws = async () => {
    const list = parseDomains(domain)
    if (!list.length) return
    setBusy(true); setErr(null); setQueued(null)
    try {
      const r = await api.enumerateDomains(project, domain, 'passive')
      setQueued(r)
      const bad = Object.keys(r.refused)
      if (bad.length) {
        setErr(`${bad.length} not queued — `
               + bad.slice(0, 3).map((d) => `${d}: ${r.refused[d]}`).join('; ')
               + (bad.length > 3 ? ' …' : ''))
      }
      await qc.invalidateQueries({ queryKey: ['agents', project] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  const act = async (what: 'promote' | 'reject') => {
    const ids = [...picked]
    if (!ids.length) return
    setBusy(true); setErr(null)
    try {
      if (what === 'promote') await api.promoteDomains(project, ids)
      else await api.rejectDomains(project, ids)
      // `ran`, not `result.domain` — after a sweep that string is
      // "7 domain(s)", which is not a domain and came back 422.
      setResult(await api.detectDomains(project, ran, false))
      setPicked(new Set())
      await qc.invalidateQueries()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
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
      ? 'Every Jaws agent on this project is offline, so there is nothing '
        + 'to run the enumeration.'
      : 'No Jaws agent is enrolled on this project. Add one under Jaws.'
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
            <Button variant="outlined" disabled={busy || !typed.length}
              onClick={() => run(false)}
              sx={{ mt: 0.3, color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
              {busy ? '…' : `Detect${typed.length > 1 ? ` (${typed.length})` : ''}`}
            </Button>
            {/* The other half of the dialog's job: stop guessing and
                have an agent actually look. */}
            <Tooltip title={noAgents
              ? noAgents
              : 'Hand these to a Jaws agent to enumerate for real. Names '
                + 'that come back are resolved, so they are filed as '
                + 'targets automatically — nothing to triage.'}>
              <span>
                <Button variant="contained" disableElevation
                  disabled={busy || !typed.length || !!noAgents}
                  onClick={sendToJaws}
                  sx={{ mt: 0.3, bgcolor: alpha(neon.pink, 0.22),
                        color: neon.pink,
                        border: `1px solid ${alpha(neon.pink, 0.6)}`,
                        '&:hover': { bgcolor: alpha(neon.pink, 0.3) } }}>
                  Send to Jaws
                </Button>
              </span>
            </Tooltip>
            <Tooltip title={(roots.data ?? []).length
              ? `Run it for every domain this project covers (${(roots.data ?? []).length}) — from its targets, its scope, and anything searched before. Generation is offline, so this costs nothing on the wire.`
              : 'Nothing to sweep: this project has no targets, no FQDNs in scope and nothing searched before. Type a domain above instead.'}>
              <span>
                <Button variant="outlined"
                  disabled={busy || !(roots.data ?? []).length}
                  onClick={runAll}
                  sx={{ mt: 0.3, color: neon.green,
                        borderColor: alpha(neon.green, 0.6) }}>
                  All {(roots.data ?? []).length
                    ? `(${(roots.data ?? []).length})` : ''}
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

          {queued && (
            <Alert severity={queued.queued.length ? 'success' : 'warning'}
                   variant="outlined" sx={{ fontSize: 12 }}>
              {queued.queued.length
                ? <>Queued {queued.queued.length} enumeration
                    {queued.queued.length === 1 ? '' : 's'} across{' '}
                    {queued.agents_online} online agent
                    {queued.agents_online === 1 ? '' : 's'}. Names found are
                    added as targets when each task reports — you can close
                    this.</>
                : <>Nothing was queued.</>}
            </Alert>
          )}

          {result?.promoted?.length ? (
            <Alert severity="success" variant="outlined" sx={{ fontSize: 12 }}>
              Added {result.promoted.length} target
              {result.promoted.length === 1 ? '' : 's'}:{' '}
              {result.promoted.slice(0, 6).join(', ')}
              {result.promoted.length > 6
                ? ` and ${result.promoted.length - 6} more` : ''}
            </Alert>
          ) : null}

          {busy && <LinearProgress sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
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
