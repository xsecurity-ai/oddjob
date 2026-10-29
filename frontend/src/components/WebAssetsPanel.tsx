/**
 * What the client's pages pull in, and which version of it.
 *
 * Dependencies, not addresses. The host serving jQuery is usually a
 * CDN — somebody else's infrastructure, barred as a target — so
 * these are recorded against the project and never become things to
 * scan. "Our page loads this" is a fact about our page.
 *
 * The engagement question this answers is the third-party one: what
 * does the client's application depend on that the client does not
 * control, and is any of it old. An abandoned CDN, a library three
 * majors behind, an analytics script nobody remembers adding — all
 * of it is in the markup and none of it was being written down.
 *
 * **A missing version is UNKNOWN, not current.** It is rendered as
 * such, because the two read the same in a table and mean opposite
 * things: one is a gap to fill, the other is a reassurance. The
 * fingerprinted bundles — `app.a1b2c3.js` — are exactly the ones
 * where the filename cannot say and the answer matters most.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Chip, IconButton, InputAdornment, Stack, TextField,
  ToggleButton, ToggleButtonGroup, Tooltip, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import SearchIcon from '@mui/icons-material/Search'
import { useQuery } from '@tanstack/react-query'
import { api, type WebAsset } from '../lib/api'
import { SEVERITY_COLOUR as SEV } from '../lib/severity'
import type { ColumnDef } from '../lib/columns'
import { AssetModal } from './AssetModal'
import { DataTable } from './DataTable'
import { neon, glow } from '../theme'

/** Colour by what the thing is, so the shape of a page's dependency
 *  list is readable without reading every row. */
const KIND: Record<string, string> = {
  script: neon.cyan,
  stylesheet: neon.purple,
  font: neon.yellow,
  iframe: neon.pink,
}

export function WebAssetsPanel({ project }: { project: string | null }) {
  const [filter, setFilter] = useState<'all' | 'third' | 'unversioned'>('all')
  // The same data read from either end. By library answers "what
  // are we on and is it old"; by page answers "which page is
  // still loading the old one", and that is the one you act on.
  const [by, setBy] = useState<'library' | 'page' | 'inside'>('library')
  // Searching the FILE, which is not the same as the table's own
  // search box: that one matches the columns on screen, this one
  // matches bytes that are deliberately not on screen. Separate
  // controls because they answer different questions, and folding
  // them together would make a term that matched nothing visible
  // look like a bug.
  const [contains, setContains] = useState('')
  const [term, setTerm] = useState('')      // what has been submitted
  const [open, setOpen] = useState<number | null>(null)

  const q = useQuery({
    queryKey: ['web-assets', project, term],
    queryFn: () => api.webAssets(project ?? '', undefined, term || undefined),
    enabled: !!project,
    placeholderData: (prev) => prev,
  })

  const libraries = useMemo(() => {
    const all = q.data?.items ?? []
    if (filter === 'third') return all.filter((a) => a.third_party)
    if (filter === 'unversioned') return all.filter((a) => !a.version)
    return all
  }, [q.data, filter])

  // One row per (page, asset). Built from the same payload rather
  // than a second request: by-library and by-page are the same facts
  // read from either end, and fetching them separately would let the
  // two disagree about what the estate loads.
  const perPage = useMemo(() => {
    const byId = new Map((q.data?.items ?? []).map((a) => [a.id, a]))
    const keep = new Set(libraries.map((a) => a.id))
    return (q.data?.refs ?? [])
      .filter((r) => keep.has(r.asset_id))
      .map((r) => {
        const a = byId.get(r.asset_id)
        return {
          id: `${r.asset_id}:${r.page}`,
          page: r.page,
          name: a?.name ?? null, version: a?.version ?? null,
          kind: a?.kind ?? '', host: a?.host ?? null,
          third_party: a?.third_party ?? false,
          bytes: a?.bytes ?? null, fetched: a?.fetched ?? false,
          // Carried across, and this is the bug that made the By page
          // table show a dash in Findings and Secrets on every row
          // whatever the data said: the columns read them off the row
          // and these rows were built by hand without them.
          scanned: a?.scanned ?? false,
          vulns: a?.vulns ?? 0, criticals: a?.criticals ?? 0,
          highs: a?.highs ?? 0, secrets: a?.secrets ?? 0,
          url: a?.url ?? '',
        }
      })
  }, [q.data, libraries])

  const columns: ColumnDef[] = useMemo(() => [
    {
      field: 'name', headerName: 'Library', flex: 1, minWidth: 160,
      valueGetter: (v) => v ?? '',
      // The way in to the file. A cell rather than a row click: the
      // row is also how you select, sort and copy, and making the
      // whole of it open a dialog takes those away.
      renderCell: (p) => (
        <Box onClick={() => setOpen((p.row as WebAsset).id)}
          title="Open the file"
          sx={{ fontFamily: `'Share Tech Mono', monospace`,
                color: neon.cyan, overflow: 'hidden', cursor: 'pointer',
                textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                '&:hover': { textDecoration: 'underline' } }}>
          {p.value || (p.row as WebAsset).url?.split('/').pop() || '—'}
        </Box>
      ),
    },
    {
      field: 'version', headerName: 'Version', width: 120,
      valueGetter: (v) => v ?? '',
      // Unknown and current are different answers and must not read
      // the same. A blank cell would say "fine".
      renderCell: (p) => p.value
        ? <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                     color: neon.green, textShadow: glow(neon.green, 0.4) }}>
            {p.value}
          </Box>
        : <Tooltip title="The URL does not state a version — a
                          fingerprinted bundle. Unknown, not current.">
            <Box sx={{ color: alpha(neon.yellow, 0.8), fontSize: 11 }}>
              unknown
            </Box>
          </Tooltip>,
    },
    {
      field: 'third_party', headerName: 'Party', width: 104, type: 'boolean',
      renderCell: (p) => p.value
        ? <Tooltip title="Served from a domain the client does not own">
            <Chip size="small" label="third party" sx={{
              height: 17, fontSize: 9.5, bgcolor: alpha(neon.orange, 0.15),
              color: neon.orange,
              border: `1px solid ${alpha(neon.orange, 0.45)}` }} />
          </Tooltip>
        : <Box sx={{ fontSize: 11, color: neon.muted }}>own</Box>,
    },
    {
      field: 'kind', headerName: 'Kind', width: 108,
      renderCell: (p) => (
        <Chip size="small" label={p.value} sx={{
          height: 17, fontSize: 9.5,
          bgcolor: alpha(KIND[p.value] ?? neon.muted, 0.14),
          color: KIND[p.value] ?? neon.muted,
          border: `1px solid ${alpha(KIND[p.value] ?? neon.muted, 0.4)}` }} />
      ),
    },
    { field: 'host', headerName: 'Served by', flex: 1, minWidth: 180,
      valueGetter: (v) => v ?? '' },
    {
      field: 'seen_on', headerName: 'Pages', width: 86, type: 'number',
      // One forgotten page loading an old library is a different
      // problem from every page loading it.
      renderCell: (p) => (
        <Box sx={{ color: (p.value ?? 0) > 1 ? neon.pink : neon.muted }}>
          {p.value}
        </Box>
      ),
    },
    {
      // What this asset is CARRYING, not what is wrong with the host
      // that serves it. A CDN bundle's host is somebody else's
      // infrastructure; the bundle is ours to answer for.
      field: 'vulns', headerName: 'Findings', width: 128, type: 'number',
      renderCell: (p) => {
        const r = p.row as WebAsset
        if (!r.vulns) {
          // Three answers, not two. "Nothing has looked at this file"
          // and "this file is clean" are different, and collapsing
          // the first into the second is how a finding gets missed --
          // the sweep covers a tenth of a large estate at any moment,
          // so most dashes mean the first.
          if (!r.fetched) {
            return (
              <Tooltip title="Nothing has retrieved this file, so nothing
                              has read it. Run a crawl with asset fetching on.">
                <Box sx={{ color: alpha(neon.muted, 0.3) }}>—</Box>
              </Tooltip>
            )
          }
          if (!r.scanned) {
            return (
              <Tooltip title="Fetched, but the scanners have not reached it
                              yet. This is not a clean result.">
                <Box sx={{ color: alpha(neon.yellow, 0.75), fontSize: 10.5 }}>
                  unscanned
                </Box>
              </Tooltip>
            )
          }
          return (
            <Tooltip title="Read by the scanners, nothing found.">
              <Box sx={{ color: alpha(neon.green, 0.75) }}>0</Box>
            </Tooltip>
          )
        }
        return (
          // Clickable: the count was a number you then had to go and
          // find in Vulns. The modal lists them, and a finding with a
          // line scrolls the file to it.
          <Stack direction="row" spacing={0.6}
            onClick={() => setOpen(r.id)}
            sx={{ alignItems: 'center', cursor: 'pointer',
                  '&:hover': { textDecoration: 'underline' } }}>
            <Box sx={{ color: neon.text }}>{r.vulns}</Box>
            {/* Severity beside the total rather than instead of it.
                "14 findings" and "14 findings, 3 of them critical"
                are different sentences and only the second says
                where to start. */}
            {r.criticals > 0 && (
              <Box sx={{ fontSize: 10.5, color: SEV.critical,
                         fontWeight: 700 }}>{r.criticals}C</Box>
            )}
            {r.highs > 0 && (
              <Box sx={{ fontSize: 10.5, color: SEV.high }}>{r.highs}H</Box>
            )}
          </Stack>
        )
      },
    },
    {
      field: 'secrets', headerName: 'Secrets', width: 96, type: 'number',
      renderCell: (p) => (p.value ?? 0) > 0 ? (
        <Box onClick={() => setOpen((p.row as WebAsset).id)}
          sx={{ color: neon.yellow, fontWeight: 700, cursor: 'pointer',
                textShadow: glow(neon.yellow, 0.5),
                '&:hover': { textDecoration: 'underline' } }}>{p.value}</Box>
      ) : !(p.row as WebAsset).scanned ? (
        // Same three answers as Findings. A blank Secrets column on a
        // file nothing has read is not "no secrets".
        <Tooltip title={(p.row as WebAsset).fetched
          ? 'Fetched, but not scanned yet. This is not a clean result.'
          : 'Never retrieved, so never read.'}>
          <Box sx={{ color: alpha(neon.yellow, 0.6), fontSize: 10.5 }}>?</Box>
        </Tooltip>
      ) : (
        // No underline and no pointer on a dash: there is nothing to
        // open, and a cell that looks clickable and is not is worse
        // than one that plainly is not.
        <Tooltip title="Read by the scanners, no credential in it.">
          <Box sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
        </Tooltip>
      ),
    },
    {
      field: 'fetched', headerName: 'Bytes', width: 110, type: 'boolean',
      // The size is the evidence it was pulled back; a tick beside
      // it would say the same thing twice.
      renderCell: (p) => p.row.fetched
        ? <Box sx={{ fontSize: 11, color: neon.muted }}>
            {((p.row.bytes ?? 0) / 1024).toFixed(1)} KB
          </Box>
        : <Tooltip title="Known by reference only. Nothing has retrieved it — run a crawl with asset fetching on.">
            <Box sx={{ fontSize: 11, color: alpha(neon.muted, 0.5) }}>—</Box>
          </Tooltip>,
    },
    { field: 'url', headerName: 'URL', flex: 2, minWidth: 280 },
    { field: 'content_type', headerName: 'Content type', width: 170,
      valueGetter: (v) => v ?? '' },
    { field: 'sha256', headerName: 'SHA-256', width: 160,
      valueGetter: (v) => v ?? '' },
    { field: 'first_page', headerName: 'First seen on', flex: 1, minWidth: 200,
      valueGetter: (v) => v ?? '' },
  ], [])

  const pageColumns: ColumnDef[] = useMemo(() => [
    { field: 'page', headerName: 'Page', flex: 2, minWidth: 260 },
    ...columns.filter((c) => c.field !== 'seen_on'
                          && c.field !== 'first_page'),
  ], [columns])

  const d = q.data
  return (
    <Box sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Stack
        direction="row"
        spacing={1}
        useFlexGap
        sx={{
          alignItems: "center",
          flexWrap: "wrap",
          mb: 1.5
        }}>
        <ToggleButtonGroup exclusive size="small" value={filter}
          onChange={(_, v) => v && setFilter(v)}>
          <ToggleButton value="all" sx={{ fontSize: 11, py: 0.2 }}>
            All {d ? `(${d.total})` : ''}
          </ToggleButton>
          <ToggleButton value="third" sx={{ fontSize: 11, py: 0.2 }}>
            Third party {d ? `(${d.third_party})` : ''}
          </ToggleButton>
          {/* The ones worth chasing: a bundle whose filename says
              nothing is the case where "what version is this" cannot
              be answered from the inventory at all. */}
          <ToggleButton value="unversioned" sx={{ fontSize: 11, py: 0.2 }}>
            No version {d ? `(${d.total - d.versioned})` : ''}
          </ToggleButton>
        </ToggleButtonGroup>
        <ToggleButtonGroup exclusive size="small" value={by}
          onChange={(_, v) => v && setBy(v)}>
          <ToggleButton value="library" sx={{ fontSize: 11, py: 0.2 }}>
            By library
          </ToggleButton>
          <ToggleButton value="page" sx={{ fontSize: 11, py: 0.2 }}>
            By page {d ? `(${d.pages})` : ''}
          </ToggleButton>
          {/* Only the bundles whose bytes came back can be read, and
              fetching is opt-in per crawl, so this is frequently a
              view of nothing. It says which kind of nothing. */}
          <ToggleButton value="inside" sx={{ fontSize: 11, py: 0.2 }}>
            Inside the code
          </ToggleButton>
        </ToggleButtonGroup>
        {!!d?.hosts && (
          <Box sx={{ fontSize: 11, color: neon.muted }}>
            from {d.hosts} host{d.hosts === 1 ? '' : 's'}
          </Box>
        )}

        {/* Narrows the table by what is INSIDE the files, which the
            table does not show and should not: the bodies are the
            largest text the database holds. Matched in SQL, so this
            searches every stored byte rather than the page of rows
            that happens to be loaded.

            Submitted on Enter rather than as you type. Each keystroke
            would otherwise be an ILIKE over every bundle in the
            project. */}
        {by !== 'inside' && (
          <TextField
            size="small" value={contains} placeholder="search file contents…"
            onChange={(e) => setContains(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') setTerm(contains) }}
            onBlur={() => setTerm(contains)}
            sx={{ minWidth: 230,
                  '& .MuiInputBase-input': { fontSize: 11.5, py: 0.5 } }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ fontSize: 15, color: neon.muted }} />
                  </InputAdornment>
                ),
                endAdornment: term ? (
                  <InputAdornment position="end">
                    <IconButton size="small" title="Clear"
                      onClick={() => { setContains(''); setTerm('') }}>
                      <CloseIcon sx={{ fontSize: 14, color: neon.muted }} />
                    </IconButton>
                  </InputAdornment>
                ) : undefined,
              }
            }} />
        )}
        {!!term && (
          <Box sx={{ fontSize: 11, color: neon.cyan }}>
            {d?.total ?? 0} file{(d?.total ?? 0) === 1 ? '' : 's'} contain
            {(d?.total ?? 0) === 1 ? 's' : ''} “{term}”
          </Box>
        )}
      </Stack>

      {by === 'inside' ? (
        <AssetSearch project={project} />
      ) : by === 'library' ? (
        <DataTable
          tableId="web-assets"
          rows={libraries as unknown as Record<string, unknown>[]}
          columns={columns}
          loading={q.isLoading}
          error={q.error as Error | null}
          initialSort={{ field: 'seen_on', sort: 'desc' }}
          hiddenColumns={{ sha256: false, first_page: false,
                           content_type: false }}
        />
      ) : (
        <DataTable
          // Its own id, so the two groupings remember their own
          // columns and sort rather than fighting over one set.
          tableId="web-assets-by-page"
          rows={perPage as unknown as Record<string, unknown>[]}
          columns={pageColumns}
          loading={q.isLoading}
          error={q.error as Error | null}
          initialSort={{ field: 'page', sort: 'asc' }}
          hiddenColumns={{ sha256: false, content_type: false }}
        />
      )}

      {open !== null && (
        <AssetModal id={open} onClose={() => setOpen(null)} />
      )}
    </Box>
  );
}

/**
 * Grep the bundles.
 *
 * A minified bundle is where an application keeps the endpoints
 * nothing links to, the role names, the feature flags, and — often
 * enough to be worth a button — a key somebody meant to keep on the
 * server.
 *
 * **Snippets, never the file.** A bundle is megabytes and a finding
 * is forty characters. The offset is shown rather than a line
 * number because minified code is routinely one line.
 *
 * Nothing is searchable until a crawl has been asked to pull the
 * bytes back, which is off by default and deliberately so — most
 * asset URLs are on hosts the engagement does not have. So the
 * empty state here has to distinguish "nothing matched" from "we
 * have never looked", and it does.
 */
function AssetSearch({ project }: { project: string | null }) {
  const [term, setTerm] = useState('')
  const [mode, setMode] = useState<'text' | 'secrets'>('secrets')
  // Submitted rather than live: each search reads every stored
  // bundle, and running one per keystroke would be a scan of the
  // corpus per character.
  const [run, setRun] = useState<{ q: string; mode: string } | null>(
    { q: '', mode: 'secrets' })

  const s = useQuery({
    queryKey: ['asset-search', project, run?.q, run?.mode],
    queryFn: () => api.searchAssets(project!, run!.q,
                                    run!.mode as 'text' | 'secrets'),
    enabled: !!project && !!run && (run.mode === 'secrets' || !!run.q),
  })

  const d = s.data
  const submit = () => setRun({ q: term, mode })

  return (
    <Box sx={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
      <Stack
        direction="row"
        spacing={1}
        useFlexGap
        sx={{
          alignItems: "center",
          flexWrap: "wrap",
          mb: 1.5
        }}>
        <ToggleButtonGroup exclusive size="small" value={mode}
          onChange={(_, v) => v && setMode(v)}>
          <ToggleButton value="secrets" sx={{ fontSize: 11, py: 0.2 }}>
            Secrets
          </ToggleButton>
          <ToggleButton value="text" sx={{ fontSize: 11, py: 0.2 }}>
            Text
          </ToggleButton>
        </ToggleButtonGroup>
        {mode !== 'secrets' && (
          <TextField size="small" value={term}
            placeholder="loadUserProfile"
            helperText="Matched literally — there is no regex mode, on
                        purpose. See assetsearch.py."
            onChange={(e) => setTerm(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') submit() }}
            sx={{ minWidth: 260, '& input': {
              fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5 } }} />
        )}
        <Button size="small" variant="outlined" onClick={submit}
          disabled={mode !== 'secrets' && !term.trim()}>
          Search
        </Button>
        {d && (
          <Box sx={{ fontSize: 11, color: neon.muted }}>
            {d.matches} match{d.matches === 1 ? '' : 'es'} in{' '}
            {d.searched} fetched bundle{d.searched === 1 ? '' : 's'}
          </Box>
        )}
      </Stack>

      {s.isLoading ? (
        <Box sx={{ fontSize: 12, color: neon.muted }}>Reading the bundles…</Box>
      ) : s.error ? (
        <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
          {(s.error as Error).message}
        </Alert>
      ) : d && d.searched === 0 ? (
        /* The distinction that matters on a fresh install. Saying
           "no results" here would read as "there are no secrets"
           when it means "we have never looked". */
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
          {d.stored
            ? `${d.stored} asset${d.stored === 1 ? ' is' : 's are'} recorded `
              + 'but none has been downloaded, so there is nothing to search. '
              + 'Tick “Download the bundles” on a web crawl to pull them back.'
            : 'No assets recorded yet. Crawl something first — these come '
              + 'from the markup of pages that were walked.'}
        </Alert>
      ) : !d?.assets.length ? (
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
          Nothing matched in {d?.searched ?? 0} bundle
          {d?.searched === 1 ? '' : 's'}.
        </Alert>
      ) : (
        <Stack spacing={1.5}>
          {d.assets.map((a) => (
            <Box key={a.asset_id} sx={{
              border: `1px solid ${alpha(neon.purple, 0.3)}`,
              borderRadius: 1, p: 1.2,
            }}>
              <Stack
                direction="row"
                spacing={1}
                useFlexGap
                sx={{
                  alignItems: "center",
                  flexWrap: "wrap",
                  mb: 0.8
                }}>
                <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                           fontSize: 12, color: neon.cyan, wordBreak: 'break-all' }}>
                  {a.url}
                </Box>
                {a.third_party && (
                  <Chip size="small" label="third party"
                    sx={{ height: 18, fontSize: 10 }} />
                )}
                {a.capped && (
                  <Chip size="small" label="more hits not shown"
                    sx={{ height: 18, fontSize: 10 }} />
                )}
              </Stack>
              <Stack spacing={0.6}>
                {a.hits.map((h, i) => (
                  <Box key={`${h.offset}-${i}`}>
                    <Stack direction="row" spacing={1} sx={{
                      alignItems: "baseline"
                    }}>
                      {h.rule && (
                        <Box sx={{ fontSize: 10, letterSpacing: '0.06em',
                          textTransform: 'uppercase',
                          /* Firm and loose look different, because a
                             reader has to know which list they are
                             reading before they act on a row. */
                          color: h.confidence === 'firm'
                            ? neon.pink : neon.muted }}>
                          {h.rule}{h.confidence === 'loose' ? ' (guess)' : ''}
                        </Box>
                      )}
                      <Box sx={{ fontSize: 10, color: neon.muted }}>
                        @{h.offset.toLocaleString()}
                      </Box>
                    </Stack>
                    <Box sx={{
                      fontFamily: `'Share Tech Mono', monospace`,
                      fontSize: 11.5, color: neon.text, whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      background: alpha(neon.bgDeep, 0.6), p: 0.6,
                      borderRadius: 0.5,
                    }}>{h.snippet}</Box>
                  </Box>
                ))}
              </Stack>
            </Box>
          ))}
        </Stack>
      )}
    </Box>
  );
}
