/**
 * Crawling and content discovery, aimed at the URLs that still owe it.
 *
 * Pointed at a URL rather than a host, because that is the unit both
 * tools take: one host can serve several sites and neither katana nor
 * gobuster can be given a bare hostname.
 *
 * The list is the server's, not a filter over whatever the grid has
 * loaded — a page of the table is not the estate. It is built from
 * two sources: URLs already recorded on the project, and URLs derived
 * from open web services. The second is the one that matters, because
 * a host with 443 open and nothing recorded against it is precisely
 * the one nobody has looked at yet.
 *
 * **"Scanned" is not a flag here.** katana follows what the
 * application links to; gobuster asks for the paths nothing links to.
 * Neither answers the other's question, so a URL that has been
 * crawled still owes a content-discovery run, and what is shown is
 * the owed SET per URL.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, DialogActions, DialogContent,
  FormControlLabel, MenuItem, Stack, TextField, Typography, alpha,
} from '@mui/material'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import {
  AgentChooser, Caveat, EnumerateDialog, FleetNotice, chipSx,
} from './EnumerateBits'
import {
  detach, needsRegion, queueEach, useFleet,
  type AgentChoice, type Report,
} from './ghostTasking'

/** Matches WEB_KINDS in backend/app/automation.py. Asserted there. */
const MODES = [
  { value: 'crawl', label: 'Web crawl only (katana)',
    hint: 'Follows what the application links to.' },
  { value: 'gobuster', label: 'Brute force only (gobuster)',
    hint: 'Asks for paths nothing links to.' },
  { value: 'both', label: 'Both',
    hint: 'Two different questions, so neither covers the other.' },
] as const

type Mode = (typeof MODES)[number]['value']

/** How many URLs to list before it becomes a count. */
const SHOWN = 25

export function WebDiscoveryDialog({ project, onClose, onQueued }: {
  project: string
  onClose: () => void
  /** Reports once the work finishes; this has already closed. */
  onQueued?: Report
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [mode, setMode] = useState<Mode>('both')
  const [kitchenSink, setKitchenSink] = useState(false)
  const [fetchAssets, setFetchAssets] = useState(false)
  // Off: a re-crawl pulls back only the bundles the project does not
  // already hold. Off is the default because the saving is traffic at
  // the client and their CDNs, and a re-download is only worth it when
  // something has been deployed since the last run.
  const [refetchAssets, setRefetchAssets] = useState(false)
  // Authenticated discovery. Empty leaves the agent's defaults alone,
  // so an unauthenticated run is the no-extra-input case.
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [cookies, setCookies] = useState('')

  const pending = useQuery({
    queryKey: ['web-pending', project, mode, kitchenSink],
    queryFn: () => api.webPending(project, mode, kitchenSink),
    enabled: !!project,
  })

  const rows = useMemo(() => pending.data?.urls ?? [], [pending.data])
  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = !rows.length || !!fleet.blocked || regionMissing

  const authArgs = () => {
    const a: Record<string, unknown> = {}
    if (fetchAssets) {
      a.fetch_assets = true
      // Only ever sent with the flag it qualifies. On its own it
      // would read as "re-download" to an agent that was not asked to
      // download anything.
      if (refetchAssets) a.refetch_assets = true
      // First party only, always, from here. Widening it is an
      // `assets_scope` the agent accepts but this dialog does not
      // offer: fetching from four hundred CDNs is a scope decision
      // and should not be one click away from a routine crawl.
      a.assets_scope = 'first-party'
    }
    if (username.trim()) a.username = username.trim()
    if (password) a.password = password
    if (cookies.trim()) a.cookies = cookies.trim()
    return a
  }

  const run = () => {
    // Snapshotted before closing: `rows` comes from a query this
    // dialog owns, and the work must run against what was on screen
    // when Queue was pressed rather than whatever a refetch produces
    // after it has gone.
    const planned = rows.map((r) => ({ url: r.url, owes: [...r.owes] }))
    const auth = authArgs()
    const tasks = planned.reduce((n, r) => n + r.owes.length, 0)

    detach(async () => {
      // Grouped by kind, because one task carries one kind. A URL
      // owing both produces two tasks, which is what the button says.
      const byKind = new Map<string, string[]>()
      for (const r of planned) {
        for (const k of r.owes) {
          byKind.set(k, [...(byKind.get(k) ?? []), r.url])
        }
      }
      const ids: number[] = []
      const failed: Array<{ subject: string; why: string }> = []
      const done: string[] = []
      for (const [kind, urls] of byKind) {
        // Sequential rather than parallel: each call is one request
        // creating up to a few thousand rows, and firing them at once
        // only makes the server do the same work with more contention.
        // `kitchenSink` is the re-run. The listing already filtered
        // on it, but the server enforces it independently and the
        // two must agree — otherwise ticking the box produces a list
        // the queue then silently declines.
        const r = await queueEach(project, agent, kind, urls, auth, region,
                                  false, kitchenSink)
        ids.push(...r.ids)
        failed.push(...r.failed)
        done.push(...r.alreadyDone)
      }
      if (!ids.length) {
        throw new Error(
          done.length
            ? `Nothing was queued: all ${done.length} had already been `
              + 'done. Tick Kitchen Sink to run them again.'
            : `Nothing was queued. ${failed[0]?.why ?? ''}`)
      }
      await qc.invalidateQueries({ queryKey: ['agents'] })
      await qc.invalidateQueries({ queryKey: ['web-pending', project] })
      const kinds = [...byKind.keys()].sort().join(' + ')
      return `Queued ${ids.length} task${ids.length === 1 ? '' : 's'} `
           + `(${kinds}) over ${planned.length} URL`
           + `${planned.length === 1 ? '' : 's'}`
           + (kitchenSink ? ', including ones already done' : '')
           + `. Results import into ${project} as each reports back.`
           + (done.length
              ? ` ${done.length} skipped as already done — tick Kitchen `
                + 'Sink to repeat them.'
              : '')
           + (failed.length
              ? ` ${failed.length} refused: ${failed[0].subject} — `
                + `${failed[0].why}`
              : '')
    }, onQueued, onClose,
       `Queueing ${tasks} web discovery task${tasks === 1 ? '' : 's'}…`)
  }

  const byKind = pending.data?.by_kind ?? {}
  // Tasks this run would repeat. Zero unless Kitchen Sink is on —
  // the server only counts it when the flag is set, because without
  // the flag nothing already done is offered in the first place.
  const repeats = pending.data?.repeats ?? 0
  const tasksOffered = pending.data?.tasks ?? 0

  return (
    <EnumerateDialog accent={neon.pink} onClose={onClose}
      title={`WEB DISCOVERY → ${project}`}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <FleetNotice fleet={fleet} />

          <TextField
            select size="small" label="What to run" value={mode}
            onChange={(e) => setMode(e.target.value as Mode)}
            helperText={MODES.find((m) => m.value === mode)?.hint}>
            {MODES.map((m) => (
              <MenuItem key={m.value} value={m.value}>{m.label}</MenuItem>
            ))}
          </TextField>

          <FormControlLabel
            control={<Checkbox size="small" checked={kitchenSink}
              onChange={(e) => setKitchenSink(e.target.checked)} />}
            label={<Box sx={{ fontSize: 13 }}>
              Kitchen Sink — every web URL, including ones already done
            </Box>} />
          <Caveat>
            Off, only URLs that still owe this work are queued: a site
            already crawled is not crawled again, though it may still owe a
            content-discovery run, because the two ask different questions.
            On, everything is re-run — worth it when paths have been added
            since, and wasted traffic at a client when they have not.
          </Caveat>
          {/* Stated, not merely counted. One project queued this four
              times in 45 hours, ~1,230 crawls each, every one of them
              a repeat. */}
          {!!repeats && (
            <Alert severity="warning" variant="outlined"
              sx={{ fontSize: 12, mt: -0.5 }}>
              {repeats === tasksOffered
                ? `All ${repeats} of these have been run before. This `
                  + 'repeats every one of them against the client.'
                : `${repeats} of ${tasksOffered} have been run before and `
                  + 'will be run again against the client.'}
            </Alert>
          )}

          {/* Only meaningful when something is crawling: gobuster
              asks for paths and never reads a page's markup, so
              there are no assets to pull back. */}
          {mode !== 'gobuster' && (
            <>
              <FormControlLabel
                control={<Checkbox size="small" checked={fetchAssets}
                  onChange={(e) => {
                    setFetchAssets(e.target.checked)
                    // Cleared with its parent rather than left ticked
                    // and greyed. A box that still shows a choice it
                    // can no longer act on is a lie about what the
                    // next run will do.
                    if (!e.target.checked) setRefetchAssets(false)
                  }} />}
                label={<Box sx={{ fontSize: 13 }}>
                  Download the bundles the pages load
                </Box>} />
              <Caveat>
                Stores the JavaScript itself, so it can be searched for
                endpoints, function names and hardcoded keys — Web →
                Assets → Inside the code. The client's own hosts only:
                a page's CDN is somebody else's infrastructure and is
                recorded but never fetched. The files are kept in the
                database, and a bundle with a key in it puts that key in
                the database too.
                {' '}Only bundles this project does not already hold are
                requested, unless the box below is ticked.
              </Caveat>
              {/* Under the checkbox it qualifies, and dead until that
                  one is on: "re-download" means nothing when nothing
                  is being downloaded, and an enabled control that
                  does nothing is worse than a greyed one that
                  explains itself. */}
              <FormControlLabel
                disabled={!fetchAssets}
                control={<Checkbox size="small" checked={refetchAssets}
                  disabled={!fetchAssets}
                  onChange={(e) => setRefetchAssets(e.target.checked)} />}
                label={<Box sx={{ fontSize: 13 }}>
                  Re-download bundles already stored
                </Box>}
                sx={{ ml: 2, mt: -0.5 }} />
              {fetchAssets && (
                <Caveat>
                  Off, a second crawl asks only for what is new — the
                  usual case, and it is the client's servers and their
                  CDNs that are spared the repeat. On, every bundle is
                  fetched again, which is what a deploy since the last
                  run calls for: a fingerprinted bundle changes its URL
                  and is picked up either way, but <code>app.js</code>
                  {' '}does not.
                </Caveat>
              )}
            </>
          )}

          <AgentChooser fleet={fleet} value={agent} onChange={setAgent}
            region={region} onRegion={setRegion} />

          <Box>
            <Typography sx={{ fontSize: 11, letterSpacing: '0.12em',
                              textTransform: 'uppercase', color: neon.pink,
                              fontFamily: `'Orbitron', sans-serif`, mb: 0.5 }}>
              Authenticated discovery (optional)
            </Typography>
            <Stack spacing={1.2}>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.2}>
                <TextField size="small" label="Username" value={username}
                  onChange={(e) => setUsername(e.target.value)} sx={{ flex: 1 }} />
                <TextField size="small" label="Password" type="password"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  sx={{ flex: 1 }} />
              </Stack>
              <TextField size="small" label="Cookies" value={cookies}
                onChange={(e) => setCookies(e.target.value)}
                placeholder="session=abc123; csrf=def456"
                helperText="Sent with every request. Left empty, the run is
                            unauthenticated and sees only what a stranger sees." />
            </Stack>
          </Box>

          {pending.isLoading ? (
            <Typography sx={{ fontSize: 12, color: neon.muted }}>
              Working out what still owes discovery…
            </Typography>
          ) : !rows.length ? (
            <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
              {pending.data?.considered
                ? 'Every web URL on this project has already had this work '
                  + 'done. Tick Kitchen Sink to run it again.'
                : 'No web services and no recorded URLs on this project yet. '
                  + 'Port-scan something first — an open 80 or 443 is what '
                  + 'makes a URL to crawl.'}
            </Alert>
          ) : (
            <>
              <Stack
                direction="row"
                spacing={1}
                useFlexGap
                sx={{
                  alignItems: "center",
                  flexWrap: "wrap"
                }}>
                <Chip size="small" sx={chipSx(neon.pink)}
                  label={`${rows.length} URL${rows.length === 1 ? '' : 's'}`} />
                {Object.entries(byKind).map(([k, n]) => (
                  <Chip key={k} size="small" sx={chipSx(neon.cyan)}
                    label={`${n} × ${k}`} />
                ))}
                {!!pending.data?.out_of_scope && (
                  <Chip size="small" sx={chipSx(neon.yellow)}
                    label={`${pending.data.out_of_scope} out of scope`} />
                )}
                {/* The cost of the tick, in the same row as the
                    counts. Without it the chips read identically
                    whether or not Kitchen Sink is on, which makes a
                    repeat of every crawl in the project look exactly
                    like doing the outstanding work. */}
                {!!repeats && (
                  <Chip size="small" sx={chipSx(neon.yellow)}
                    label={`${repeats} already done — will run again`} />
                )}
              </Stack>

              <Box sx={{
                maxHeight: '28vh', overflow: 'auto', px: 1.2, py: 0.8,
                fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
                color: neon.text, bgcolor: alpha(neon.bgDeep, 0.6),
                border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1,
              }}>
                {rows.slice(0, SHOWN).map((r) => (
                  <Box key={r.url} sx={{ display: 'flex', gap: 1,
                                         justifyContent: 'space-between' }}>
                    <Box sx={{ overflow: 'hidden', textOverflow: 'ellipsis',
                               whiteSpace: 'nowrap' }}>{r.url}</Box>
                    <Box sx={{ color: neon.muted, flexShrink: 0 }}>
                      {r.owes.join(' + ')}
                    </Box>
                  </Box>
                ))}
                {rows.length > SHOWN
                  && <Box sx={{ color: neon.muted }}>
                       …and {rows.length - SHOWN} more
                     </Box>}
              </Box>
            </>
          )}

          <Caveat>
            One task per URL per tool, so a slow site holds up its own
            result rather than everything behind it. A URL is only offered
            when its host passes the scope gate; anything barred is counted
            above and not queued.
          </Caveat>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="outlined" disabled={stop} onClick={run}
          sx={{ color: neon.pink, borderColor: alpha(neon.pink, 0.6) }}>
          {`Queue ${pending.data?.tasks ?? 0} task`
           + `${pending.data?.tasks === 1 ? '' : 's'}`}
        </Button>
      </DialogActions>
    </EnumerateDialog>
  );
}
