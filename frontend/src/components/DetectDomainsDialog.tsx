/**
 * Hand domains to a Drone and have amass go and look.
 *
 * This used to guess. It extrapolated hostnames from patterns already
 * in the project — `admin.` under one zone because `admin.` existed
 * under another — and handed back a few thousand hypotheses to triage.
 * The triage WAS the product: a list of names nobody had checked,
 * ranked by how plausible the guess looked.
 *
 * That has been pulled. A name no tool resolved is not a finding, and
 * sorting a pile of them is not enumeration. `amass enum -d <domain>`
 * asks the internet instead, and everything it returns resolved — so
 * there is nothing to triage afterwards. Results file themselves as
 * targets when each task reports.
 *
 * One task per domain, because amass enumerates one zone at a time and
 * one-per-domain is what lets the fleet share the work and keeps a
 * single failure to a single domain.
 *
 * **Kitchen Sink Lookup** is the other way of saying what to enumerate.
 * Instead of naming domains, it says "everything this project knows
 * about": every hostname on record, addresses thrown away, each
 * remaining name walked back to its registrable domain — so a project
 * holding `a.b.c.example` also asks about `b.c.example` and
 * `c.example`. The walk stops at the registrable domain and every name
 * it produces is scope-checked on its own, so a parent nobody
 * authorised is refused like anything else; the server does both, and
 * this dialog reports what came back.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, DialogActions, DialogContent,
  FormControlLabel, Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { isIpLiteral, validateHost } from '../lib/scopeEntry'
import { neon, glow } from '../theme'
import { Caveat, EnumerateDialog, FleetNotice } from './EnumerateBits'
import { BY_ANY, PillInput, type Analyse } from './PillInput'
import { useFleet } from './droneTasking'

/** Commas, spaces, newlines. Operators paste from spreadsheets, scope
 *  documents and chat messages, and making them reformat it first is
 *  the kind of friction that gets a tool abandoned for a terminal. */
export function parseDomains(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const piece of (raw || '').split(/[\s,;]+/)) {
    const v = piece.trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '')
      .replace(/^\*\./, '').replace(/\.$/, '')
    if (!v || !v.includes('.') || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}

/** `MAX_TASKS` in backend/app/routers/domains.py.
 *
 *  It means two different things on the two lists and only one of them
 *  belongs in a warning here. A TYPED list over the cap is refused
 *  outright, in both modes — the check runs on `body.wanted()` before
 *  Kitchen Sink is even consulted — so it is worth saying before the
 *  button is pressed rather than after a 422. The list the Kitchen Sink
 *  WALK produces is not refused for being long: the overflow comes back
 *  as `deferred` and the next run drains it. Warning about that would be
 *  telling the operator to split something they did not write. */
const MAX_PER_SUBMISSION = 200

/** What the SERVER makes of one pasted piece — `EnumerateRequest.wanted`
 *  in backend/app/routers/domains.py, not `parseDomains` above.
 *
 *  The two differ in corners (the server's `lstrip("*.")` eats a run of
 *  leading stars and dots, this box's regex takes one `*.`), and it is
 *  the server's reading that decides what gets queued: what travels is
 *  the raw text, and `parseDomains` only ever counted it for the button.
 *  A pill claiming a line is malformed when the server would enumerate
 *  it happily is the client overruling the authority, so the pill uses
 *  the authority's own normalisation. */
function asServerReadsIt(raw: string): string {
  const v = raw.trim().replace(/\.+$/, '').toLowerCase()
    .replace(/^[*.]+/, '')
  return v.replace(/^[a-z]+:\/\//, '').split('/')[0].split('?')[0]
}

/** Only the two refusals `enumerate_domains` actually issues are red.
 *  Everything else it will at least attempt, so the pill says its piece
 *  in muted text and gets out of the way. */
const domainPills: Analyse = (lines) => {
  const seen = new Set<string>()
  return lines.map((raw) => {
    const v = asServerReadsIt(raw)
    if (!v) return { raw, problem: 'there is no domain here' }
    if (isIpLiteral(v)) {
      return { raw, problem: 'an address has no zone to enumerate' }
    }
    if (!validateHost(v)) return { raw, problem: 'not a well-formed hostname' }
    if (seen.has(v)) return { raw, duplicate: true }
    seen.add(v)
    // A single label is a legal host and the server will queue it, so it
    // is not a problem — but amass enumerates a zone, and `localhost` is
    // not one. Worth a word, not a refusal.
    if (!v.includes('.')) {
      return { raw, kind: 'label',
               note: 'a single label, not a zone — amass needs something '
                     + 'like acme.example' }
    }
    return { raw, kind: 'zone',
             note: v !== raw.trim() ? `enumerated as ${v}` : undefined }
  })
}

export function DetectDomainsDialog({ project, onClose, seed = [], onQueued }: {
  project: string
  onClose: () => void
  /** Whatever was ticked in the grid, so acting after a selection
   *  starts from the selection rather than an empty box. */
  seed?: string[]
  /** Accepted and deliberately unused. Kitchen Sink Lookup asks the
   *  server for the project's hostnames rather than taking the grid's
   *  loaded rows: a page of the table is not the estate, and walking
   *  only what happens to be rendered would enumerate a slice while
   *  reporting it as everything. */
  allHosts?: string[]
  onQueued?: (summary: string) => void
}) {
  const qc = useQueryClient()
  const [domain, setDomain] = useState(seed.join('\n'))
  const [mode, setMode] = useState<'passive' | 'active'>('passive')
  const [kitchenSink, setKitchenSink] = useState(false)
  const [rescan, setRescan] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const typed = useMemo(() => parseDomains(domain), [domain])
  const fleet = useFleet(project)
  // Kitchen Sink takes its hosts from the server, not from whatever
  // page of the grid happens to be loaded — a 30-row page is not "all
  // hosts", and sending the visible ones would silently enumerate a
  // third of the estate. The box still contributes: typed names are
  // walked alongside the recorded ones.
  const canRun = kitchenSink || typed.length > 0

  // Roots the project already touches — from its targets AND its
  // scope, so a fresh engagement with nothing resolved yet still has
  // something to pick from.
  const roots = useQuery({
    queryKey: ['domain-roots', project],
    queryFn: () => api.domainRoots(project),
    enabled: !!project,
  })

  // Roots not already in the box. Compared on the parsed form, so a root
  // typed with a trailing dot or a scheme still counts as present and is
  // not offered a second time.
  const suggestions = useMemo(() => {
    const have = new Set(typed)
    return (roots.data ?? []).map((r) => r.domain)
      .filter((d) => d && !have.has(d.toLowerCase())).slice(0, 10)
  }, [roots.data, typed])

  const run = useMutation({
    mutationFn: () => api.enumerateDomains(project, domain, mode,
                                           { kitchenSink, rescan }),
    onSuccess: async (r) => {
      await qc.invalidateQueries({ queryKey: ['agents', project] })
      const refused = Object.keys(r.refused)
      // Every outcome is named, in both branches. A skipped domain is
      // not a queued one and is not a refused one, and rolling it into
      // either makes a run that did almost nothing look like a run that
      // did everything.
      const also = [
        r.skipped.length ? `${r.skipped.length} already scanned` : '',
        refused.length ? `${refused.length} refused` : '',
        r.deferred.length ? `${r.deferred.length} left for the next run` : '',
      ].filter(Boolean)
      if (!r.queued.length) {
        // Nothing went out, so stay open: the reasons are the only
        // useful thing on the screen.
        const why = r.skipped.length && !refused.length
          ? `All ${r.skipped.length} ${r.skipped.length === 1 ? 'domain has' : 'domains have'}`
            + ' already been enumerated. Tick "Rescan already scanned'
            + ' domains" to run them again.'
          : refused.slice(0, 3).map((d) => `${d}: ${r.refused[d]}`).join('; ')
            + (refused.length > 3 ? ` …and ${refused.length - 3} more` : '')
        setErr(`Nothing was queued. ${why}`)
        return
      }
      onQueued?.(`Queued ${r.queued.length} amass enumeration`
                 + `${r.queued.length === 1 ? '' : 's'} across `
                 + `${r.agents_online} online drone`
                 + `${r.agents_online === 1 ? '' : 's'}`
                 + (kitchenSink ? ` from ${r.considered} domain`
                                  + `${r.considered === 1 ? '' : 's'} walked`
                                : '')
                 + (also.length ? `; ${also.join(', ')}` : '')
                 + '. Names that resolve are added as targets when each '
                 + 'task reports.')
      onClose()
    },
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
  })

  return (
    <EnumerateDialog accent={neon.cyan} onClose={onClose}
      title={`FIND SUBDOMAINS → ${project}`}>
      <DialogContent sx={{ pt: 1 }}>
        <Stack spacing={2}>
          <Caveat>
            Runs <code>amass enum</code> on a Drone, one task per domain.
            Everything it returns resolved, so the names are filed as
            targets when each task reports — there is nothing to triage.
          </Caveat>

          {/* The count that used to be built into this helper line is
              the pill summary now. What stays is the guidance the count
              was carrying alongside it, including the Kitchen Sink
              wording — with the walk on, this box stops being the whole
              input and says so.

              Deliberately NOT shown per pill: which registrable domain a
              typed name walks back to. That needs a public-suffix list,
              the server has one and the browser does not, and a chip
              guessing `c.example` from `a.b.c.example` would be the
              client inventing scope. The sentence says the walk happens;
              the server says what it produced. */}
          <PillInput
            label="Domains" value={domain} onChange={setDomain}
            analyse={domainPills} separator={BY_ANY} accent={neon.cyan}
            placeholder="corp.com, other.example — one per line also fine"
            helperText={kitchenSink
              ? (typed.length
                  ? 'Walked back to their registrable domains, alongside the '
                    + 'hosts already on record.'
                  : 'Optional with Kitchen Sink on — anything typed here is '
                    + 'walked alongside the hosts already on record.')
              : 'Commas, spaces and newlines all work; URLs and *. are trimmed.'} />

          {/* The roots the project already touches. This was the options
              list on an Autocomplete, which a chip input has nowhere to
              put — and which only ever offered one completion at a time
              anyway. As chips they can be added in any order and the
              ones already in the box are not offered again.

              Hidden under Kitchen Sink, because that is the same list.
              The walk takes every host on record back to its registrable
              domain, which is where these came from, so offering them is
              offering to type out by hand the thing the checkbox was
              just ticked to do. */}
          {!kitchenSink && suggestions.length > 0 && (
            <Stack direction="row" spacing={0.6} useFlexGap flexWrap="wrap"
                   alignItems="center">
              <Typography sx={{ fontSize: 10.5, color: neon.muted,
                                letterSpacing: '0.08em' }}>
                ALREADY IN THIS PROJECT
              </Typography>
              {suggestions.map((d) => (
                <Chip key={d} size="small" clickable label={d}
                  onClick={() => setDomain(domain.trim()
                    ? `${domain.replace(/\s+$/, '')}\n${d}` : d)}
                  sx={{ height: 20, fontSize: 10.5,
                        fontFamily: `'Share Tech Mono', monospace`,
                        color: neon.green,
                        bgcolor: alpha(neon.green, 0.1),
                        border: `1px solid ${alpha(neon.green, 0.4)}` }} />
              ))}
            </Stack>
          )}

          {typed.length > MAX_PER_SUBMISSION && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
              {typed.length} domains typed. The server refuses a typed list
              over {MAX_PER_SUBMISSION} outright — each becomes a task, and
              a queue that long buries everything else this project needs
              to run. Split it.
              {kitchenSink
                ? ' Kitchen Sink does not change that: the cap is lifted'
                  + ' for the domains the walk finds, which overflow into'
                  + ' the next run, but a list typed by hand is still'
                  + ' refused because splitting it is something you can do'
                  + ' and the walk cannot.'
                : ''}
            </Alert>
          )}

          <Stack direction="row" spacing={1} alignItems="center">
            <Typography sx={{ fontSize: 12, color: neon.muted }}>Mode</Typography>
            {/* Passive is the default and stays the default. Active
                sends traffic to the client's own infrastructure, which
                is a scope decision rather than a speed one. */}
            <Tooltip title="Asks public sources. Sends nothing to the client.">
              <Chip label="passive" size="small" clickable
                onClick={() => setMode('passive')}
                variant={mode === 'passive' ? 'filled' : 'outlined'}
                sx={{ height: 22, fontSize: 11,
                      color: mode === 'passive' ? neon.bg : neon.green,
                      bgcolor: mode === 'passive' ? neon.green : 'transparent',
                      borderColor: alpha(neon.green, 0.6) }} />
            </Tooltip>
            <Tooltip title="Resolves and probes the client's infrastructure directly.">
              <Chip label="active" size="small" clickable
                onClick={() => setMode('active')}
                variant={mode === 'active' ? 'filled' : 'outlined'}
                sx={{ height: 22, fontSize: 11,
                      color: mode === 'active' ? neon.bg : neon.yellow,
                      bgcolor: mode === 'active' ? neon.yellow : 'transparent',
                      borderColor: alpha(neon.yellow, 0.6) }} />
            </Tooltip>
            <Box sx={{ flex: 1 }} />
          </Stack>

          {mode === 'active' && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
              Active enumeration sends traffic to the client&apos;s own
              infrastructure. Only if the engagement covers it.
            </Alert>
          )}

          <Stack>
            <Tooltip title={'Every hostname this project has on record — '
                            + 'targets, their DNS and certificate names, and '
                            + 'the hosts of web addresses.'}>
              <FormControlLabel
                control={<Checkbox size="small" checked={kitchenSink}
                  onChange={(e) => setKitchenSink(e.target.checked)} />}
                label={
                  <Typography sx={{ fontSize: 12.5 }}>
                    Kitchen Sink Lookup — take every host on record, ignore
                    the addresses, walk each name back to its domain
                  </Typography>} />
            </Tooltip>
            {/* Only shown with Kitchen Sink on, because it only does
                anything there. A domain somebody typed is an explicit
                instruction and is always run: refusing to re-enumerate
                a zone the operator just asked for by name would be the
                tool overruling them. */}
            {kitchenSink && (
              <FormControlLabel sx={{ ml: 2 }}
                control={<Checkbox size="small" checked={rescan}
                  onChange={(e) => setRescan(e.target.checked)} />}
                label={
                  <Typography sx={{ fontSize: 12.5 }}>
                    Rescan already scanned domains
                  </Typography>} />
            )}
          </Stack>

          {kitchenSink && (
            <Caveat>
              <code>a.b.c.d.e.f.com</code> becomes six domains —{' '}
              <code>a.b.c.d.e.f.com</code> down to <code>f.com</code> — and
              stops there: <code>com</code> is not a domain anybody owns, and
              neither is <code>co.uk</code> for a name under it. Parents are
              scope-checked one at a time and are not approved by having an
              approved child, so expect some to come back refused. Domains
              already handed to amass are skipped unless you tick the box.
            </Caveat>
          )}

          <FleetNotice fleet={fleet} />

          {err && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 12 }}>
              {err}
            </Alert>
          )}
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Typography sx={{ fontSize: 11, color: neon.muted, mr: 'auto' }}>
          {/* Not a task count with Kitchen Sink on. How many tasks it
              becomes depends on the walk, the scope list and what has
              already been run, all of which the server decides — and a
              confident wrong number here is worse than none. */}
          {kitchenSink
            ? 'Task count decided by the walk, scope and what has already run'
            : typed.length
              ? `${typed.length} task${typed.length === 1 ? '' : 's'}` : ''}
        </Typography>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="contained" disableElevation
          disabled={run.isPending || !canRun || !!fleet.blocked}
          onClick={() => { setErr(null); run.mutate() }}
          sx={{ bgcolor: alpha(neon.cyan, 0.22), color: neon.cyan,
                border: `1px solid ${alpha(neon.cyan, 0.6)}`,
                textShadow: glow(neon.cyan, 0.4),
                '&:hover': { bgcolor: alpha(neon.cyan, 0.3) } }}>
          {run.isPending ? 'Queueing…'
            : kitchenSink ? 'Run kitchen sink'
              : `Run amass${typed.length > 1 ? ` (${typed.length})` : ''}`}
        </Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
