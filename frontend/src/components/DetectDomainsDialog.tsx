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
  Alert, Autocomplete, Box, Button, Checkbox, Chip, DialogActions,
  DialogContent, FormControlLabel, Stack, TextField, Tooltip, Typography,
  alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'
import { Caveat, EnumerateDialog, FleetNotice } from './EnumerateBits'
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

          <Autocomplete
            freeSolo options={(roots.data ?? []).map((r) => r.domain)}
            inputValue={domain} onInputChange={(_, v) => setDomain(v)}
            renderInput={(p) => (
              <TextField {...p} label="Domains" multiline minRows={2} maxRows={6}
                placeholder="corp.com, other.example&#10;one per line also fine"
                helperText={typed.length
                  ? `${typed.length} domain${typed.length === 1 ? '' : 's'} — `
                    + typed.slice(0, 4).join(', ') + (typed.length > 4 ? '…' : '')
                    + (kitchenSink ? ', walked back to their registrable domains'
                                   : '')
                  : kitchenSink
                    ? 'Optional with Kitchen Sink on — anything typed here is '
                      + 'walked alongside the hosts already on record.'
                    : 'Commas, spaces and newlines all work; URLs and *. are trimmed.'} />
            )}
          />

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
