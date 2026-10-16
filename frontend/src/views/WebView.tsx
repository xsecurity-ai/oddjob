import { useEffect, useMemo, useState } from 'react'
import {
  Box, Chip, Menu, MenuItem, Stack, Tab, Tabs, ToggleButton, ToggleButtonGroup,
  Tooltip, Typography, alpha,
} from '@mui/material'
import LaunchIcon from '@mui/icons-material/Launch'
import { WebAssetsPanel } from '../components/WebAssetsPanel'
import ArticleIcon from '@mui/icons-material/ArticleOutlined'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import ReplayIcon from '@mui/icons-material/Replay'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import CircularProgress from '@mui/material/CircularProgress'
import IconButton from '@mui/material/IconButton'
import type { ColumnDef } from '../lib/columns'
import { useQuery } from '@tanstack/react-query'
import { useServerTable } from '../lib/useServerTable'
import { api, type WebAddress, type WebGroup } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { PacketModal } from '../components/PacketModal'
import { ReplayModal } from '../components/ReplayModal'
import { neon, glow, TAB_SX } from '../theme'

/**
 * Every URL found on an http(s) service.
 *
 * Sits beside Services rather than inside it because a web server is not
 * one thing: a single :443 routinely carries a login page, an admin
 * console, an API and a forgotten status endpoint, and "what is reachable"
 * is the question an operator actually has. A banner cannot answer it.
 */

function statusColour(code: number | null): string {
  if (code === null) return neon.muted
  if (code >= 500) return neon.red
  if (code >= 400) return code === 401 || code === 403 ? neon.orange : neon.muted
  if (code >= 300) return neon.yellow
  return neon.green
}

/** POST and friends change state; GET does not. Worth seeing at a glance. */
const VERB_COLOUR: Record<string, string> = {
  GET: neon.cyan, HEAD: neon.muted, OPTIONS: neon.muted,
  POST: neon.orange, PUT: neon.orange, PATCH: neon.orange,
  DELETE: neon.red,
}

/** A grid row: either a URL group, or one exchange under it. */
type WebRow = (WebGroup | WebAddress) & { __child?: boolean; hits?: number
                                          methods?: string[]; statuses?: number[]
                                          __seq?: number }

/** Groups are keyed on (target, url) — the same path on two hosts is
 *  two URLs, and ids are not stable across pages. */
const rowKey = (r: { target_id: number; url: string }) => `${r.target_id}|${r.url}`

export function WebView({ project }: { project: string | null }) {
  const { open } = useHostModal()
  // Anchored on the POINTER, not on the element clicked.
  //
  // Holding `e.currentTarget` put the menu in the top-left corner.
  // The element is a cell rendered by `renderCell`; setting this
  // state re-renders the table, `renderCell` runs again and replaces
  // that node, and MUI is left measuring something detached from the
  // document — `getBoundingClientRect()` on it is all zeroes, which
  // is the origin. Coordinates cannot go stale.
  const [menu, setMenu] = useState<
    { x: number; y: number; row: WebAddress } | null>(null)
  const [packet, setPacket] = useState<number | null>(null)
  // Reaching a URL is the thing a reader most often wants and the thing
  // the table cannot do for them, so it is a link rather than a cell.
  const [filter, setFilter] = useState<'all' | 'crawled' | 'interesting'>('all')
  // Who found the URL. Separate state from `filter` because the two
  // are independent questions and an operator routinely wants both at
  // once -- "the 401s nothing links to" is Discovery-only crossed
  // with 200/401/403/500, and folding them into one control would
  // make that combination unaskable.
  const [foundBy, setFoundBy] = useState<'any' | 'crawl' | 'discovery'>('any')
  const [tab, setTab] = useState<'urls' | 'assets'>('urls')
  // Which URLs are open, and what their exchanges are once fetched.
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [children, setChildren] = useState<Record<string, WebAddress[]>>({})
  const [loadingKey, setLoadingKey] = useState<string | null>(null)
  const [replay, setReplay] = useState<number | null>(null)

  const toggle = async (g: WebGroup) => {
    const key = rowKey(g)
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
    if (!children[key]) {
      setLoadingKey(key)
      try {
        const r = await api.webByUrl(g.target_id, g.url)
        setChildren((c) => ({ ...c, [key]: r.items }))
      } catch {
        // Leave it unexpanded rather than showing an empty group that
        // claims the URL has no exchanges.
        setExpanded((prev) => { const n = new Set(prev); n.delete(key); return n })
      } finally {
        setLoadingKey(null)
      }
    }
  }

  // Paged, sorted and searched in the database. One engagement holds
  // 211,012 addresses; the previous version asked for 5,000 and showed
  // those, so anything past the first 5,000 was invisible and the
  // search box only ever searched the part that happened to be loaded.
  const table = useServerTable('web', {
    sort: 'url', order: 'asc', pageSize: 100,
    // Must match FILTERABLE on /api/web. A column left out here is
    // shown but not offered in the filter panel, which is better than
    // offering a filter the server rejects.
    filterable: ['url', 'path', 'port', 'status_code', 'title', 'scheme',
                 'webserver', 'crawled', 'host', 'method', 'project_code',
                 'content_type', 'notes', 'sources'],
  })

  const { data, isLoading, error } = useQuery({
    queryKey: ['web', project, filter, foundBy, table.query],
    queryFn: () => api.webGrouped({
      project: project ?? undefined,
      crawled: filter === 'crawled' ? true : undefined,
      found_by: foundBy === 'any' ? undefined : foundBy,
      // In SQL, not after the fact: filtering a page would leave the
      // total and the page count describing something else.
      status_in: filter === 'interesting' ? '200,401,403,500' : undefined,
      q: table.query.q || undefined,
      sort: table.query.sort,
      order: table.query.order,
      filters: table.query.filters || undefined,
      logic: table.query.logic,
      limit: table.query.pageSize,
      offset: table.query.page * table.query.pageSize,
    }),
    placeholderData: (prev) => prev,
  })

  // The three numbers behind the chooser. Deliberately NOT given
  // `found_by` -- it returns all three counts at once -- but given
  // every other filter in force, so the numbers describe the table
  // the operator is actually looking at rather than the whole estate.
  const counts = useQuery({
    queryKey: ['web-source-counts', project, filter, table.query.q,
               table.query.filters, table.query.logic],
    queryFn: () => api.webSourceCounts({
      project: project ?? undefined,
      crawled: filter === 'crawled' ? true : undefined,
      status_in: filter === 'interesting' ? '200,401,403,500' : undefined,
      q: table.query.q || undefined,
      filters: table.query.filters || undefined,
      logic: table.query.logic,
    }),
    placeholderData: (prev) => prev,
  })

  // Taken off `table` rather than called through it. useServerTable
  // builds a new object on every render, so depending on `table` would
  // re-run both of these every render; these two in particular are raw
  // useState setters underneath and so are stable for the life of the
  // component, which makes them honest dependencies.
  const { setTotal, setPage } = table
  useEffect(() => { setTotal(data?.total ?? 0) }, [setTotal, data?.total])
  // Changing the crawled/interesting shortcut changes the result set,
  // so page 7 of the old one is meaningless.
  useEffect(() => { setPage(0) }, [setPage, filter, foundBy, project])

  // One row per URL, with the exchanges recorded against it spliced in
  // underneath when it is expanded. The grid is given the finished
  // array, which is how in-place expansion is possible at all: the MIT
  // DataGrid has no master-detail.
  //
  // `data?.items ?? []` is read inside the callback rather than above it.
  // Hoisted into a `const groups`, the `?? []` minted a new empty array
  // on every render that had no data yet, so this memo's dependency
  // changed identity every render and the memo never held anything —
  // which is the whole point of it.
  const rows = useMemo(() => {
    const out: WebRow[] = []
    // Numbered from the start of the LISTING, not of the page, so
    // entry 101 is the first row of page two rather than a second
    // row 1. The expanded exchanges under a URL are deliberately
    // unnumbered: they are one entry seen several ways, and giving
    // them numbers would make the column stop counting entries.
    let seq = table.query.page * table.query.pageSize
    for (const g of data?.items ?? []) {
      out.push({ ...g, __seq: ++seq })
      const kids = children[rowKey(g)]
      if (expanded.has(rowKey(g)) && kids) {
        for (const k of kids) out.push({ ...k, __child: true })
      }
    }
    return out
  }, [data?.items, expanded, children,
      table.query.page, table.query.pageSize])

  const columns: ColumnDef<WebAddress>[] = [
    {
      // A handle to refer to a row by. Position in the listing as it
      // is currently sorted and filtered — with the default sort and
      // no filter that is 1, 2, 3 … through the project. It follows
      // the view rather than being a stored per-row ordinal, because
      // a stored one would disagree with the order on screen the
      // moment anything was sorted differently.
      field: '__seq', headerName: '#', width: 64, sortable: false,
      renderCell: (p) => {
        const r = p.row as WebRow
        return (
          <Box sx={{
            fontFamily: `'Share Tech Mono', monospace`, fontSize: 11,
            color: neon.muted,
          }}>{r.__seq ?? ''}</Box>
        )
      },
    },
    {
      field: 'url', headerName: 'URL', flex: 3, minWidth: 320,
      // Clicking offers the choice rather than assuming one: sometimes
      // you want the live page, sometimes what was actually exchanged.
      renderCell: (p) => {
        const r = p.row as WebRow
        const key = rowKey(r)
        const open = expanded.has(key)
        const many = !r.__child && (r.hits ?? 1) > 1
        return (
          <Stack
            direction="row"
            spacing={0.5}
            sx={{
              alignItems: "center",
              pl: r.__child ? 3 : 0,
              minWidth: 0
            }}>
            {many ? (
              <IconButton size="small" onClick={(e) => { e.stopPropagation(); toggle(r as WebGroup) }}
                sx={{ p: 0.1, color: neon.pink }}>
                {loadingKey === key
                  ? <CircularProgress size={12} thickness={6} sx={{ color: neon.pink }} />
                  : open ? <ExpandMoreIcon sx={{ fontSize: 17 }} />
                         : <ChevronRightIcon sx={{ fontSize: 17 }} />}
              </IconButton>
            ) : <Box sx={{ width: r.__child ? 0 : 20 }} />}
            <Box
              onClick={(e) => {
                e.stopPropagation()
                setMenu({ x: e.clientX, y: e.clientY, row: p.row })
              }}
              sx={{
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                color: r.__child ? alpha(neon.cyan, 0.75) : neon.cyan,
                fontFamily: `'Share Tech Mono', monospace`,
                cursor: 'pointer', '&:hover': { textShadow: glow(neon.cyan, 0.8) },
              }}>
              {r.__child ? '↳ ' : ''}{p.value}
            </Box>
            {many && (
              <Chip size="small" label={`${r.hits} hits`} onClick={(e) => {
                e.stopPropagation(); toggle(r as WebGroup)
              }} sx={{
                height: 17, fontSize: 9.5, ml: 0.5, cursor: 'pointer',
                bgcolor: alpha(neon.pink, 0.15), color: neon.pink,
                border: `1px solid ${alpha(neon.pink, 0.45)}` }} />
            )}
          </Stack>
        );
      },
    },
    {
      field: 'method', headerName: 'Verb', width: 86,
      // A group stands for several exchanges, which may not share a
      // verb. Showing one of them would be a lie about the others.
      renderCell: (p) => {
        const r = p.row as WebRow
        if (!r.__child && (r.methods?.length ?? 0) > 1) {
          return (
            <Tooltip title={r.methods!.join(', ')}>
              <Box sx={{ color: neon.purple, fontSize: 11 }}>
                {r.methods!.length} verbs
              </Box>
            </Tooltip>
          )
        }
        return p.value
          ? <Box sx={{ color: VERB_COLOUR[p.value] ?? neon.purple, fontWeight: 700,
                       fontSize: 11, letterSpacing: '0.06em' }}>{p.value}</Box>
          : <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
      },
    },
    {
      field: 'host', headerName: 'Host', flex: 1, minWidth: 160,
      renderCell: (p) => (
        <Box onClick={() => open(p.row.project_code, p.value)}
          sx={{ color: neon.pink, cursor: 'pointer',
                '&:hover': { textShadow: glow(neon.pink, 0.8) } }}>{p.value}</Box>
      ),
    },
    {
      field: 'status_code', headerName: 'Status', width: 90, type: 'number',
      renderCell: (p) => {
        const c = statusColour(p.value ?? null)
        return <Box sx={{ color: c, textShadow: glow(c, 0.4), fontWeight: 700 }}>
          {p.value ?? '—'}
        </Box>
      },
    },
    { field: 'title', headerName: 'Title', flex: 2, minWidth: 180,
      valueGetter: (v) => v ?? '' },
    { field: 'port', headerName: 'Port', width: 78, type: 'number' },
    { field: 'scheme', headerName: 'Scheme', width: 86 },
    // No `webserver` column. The header is still collected by every
    // importer that sees one and `q` still searches it -- it is just
    // not worth a column of its own, which on this data was blank on
    // every row.
    //
    // katana fingerprints what a page is built on and the agent has
    // always reported it; the column is the only thing that was
    // missing. Rendered as chips because it is a list, and a list
    // flattened into a cell reads as one long name.
    {
      field: 'tech', headerName: 'Tech', flex: 1, minWidth: 150,
      sortable: false,
      valueGetter: (v) => (Array.isArray(v) ? v.join(', ') : (v ?? '')),
      renderCell: (p) => {
        const list: string[] = Array.isArray(p.row.tech) ? p.row.tech : []
        if (!list.length) return null
        return (
          <Stack direction="row" spacing={0.4} sx={{ overflow: 'hidden' }}>
            {list.slice(0, 4).map((t) => (
              <Chip key={t} size="small" label={t} sx={{
                height: 16, fontSize: 9.5, bgcolor: alpha(neon.purple, 0.15),
                color: neon.purple,
                border: `1px solid ${alpha(neon.purple, 0.4)}` }} />
            ))}
            {list.length > 4 && (
              <Box sx={{ fontSize: 9.5, color: neon.muted, alignSelf: 'center' }}>
                +{list.length - 4}
              </Box>
            )}
          </Stack>
        )
      },
    },
    // No `crawled` column. A status code is the evidence that
    // something fetched the address, so a tick beside it says the
    // same thing twice — and when the status is blank the tick is
    // the only thing on the row claiming anything, which is how 24,937
    // rows came to show a column of dashes. The field is still stored
    // and still drives the "Fetched" filter in the toolbar.
    {
      field: 'sources', headerName: 'Found by', flex: 1, minWidth: 130,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.4} useFlexGap sx={{
          flexWrap: "wrap"
        }}>
          {String(p.value || '').split(',').filter(Boolean).map((s) => (
            <Chip key={s} size="small" label={s} sx={{
              height: 17, fontSize: 9.5, bgcolor: alpha(neon.purple, 0.16),
              color: neon.purple, border: `1px solid ${alpha(neon.purple, 0.4)}` }} />
          ))}
        </Stack>
      ),
    },
    // Hidden by default, and present so that `filterable` below is not a
    // promise the table cannot keep: the API accepts a condition on each
    // of these, and until they had columns there was no way to express
    // one. Path in particular is how you ask for every /admin on the
    // engagement without also matching the hostname.
    { field: 'path', headerName: 'Path', flex: 1, minWidth: 160,
      valueGetter: (v) => v ?? '' },
    { field: 'content_type', headerName: 'Content type', width: 170,
      valueGetter: (v) => v ?? '' },
    { field: 'notes', headerName: 'Notes', flex: 1, minWidth: 160,
      valueGetter: (v) => v ?? '' },
    { field: 'project_code', headerName: 'Project', width: 120 },
  ]

  if (tab === 'assets') {
    return (
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)}
          sx={{ minHeight: 34, px: 2, pt: 1,
                borderBottom: `1px solid ${alpha(neon.purple, 0.25)}` }}>
          <Tab value="urls" label="URLs" sx={TAB_SX} />
          <Tab value="assets" label="Assets" sx={TAB_SX} />
        </Tabs>
        <Box sx={{ flex: 1, minHeight: 0 }}>
          <WebAssetsPanel project={project} />
        </Box>
      </Box>
    )
  }

  return (
    <>
      {/* Two readings of the same estate: what addresses exist, and
          what those pages pull in to render themselves. They are
          different questions with different answers, which is why
          they are tabs rather than one table with more columns. */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        sx={{ minHeight: 34, px: 2, pt: 1,
              borderBottom: `1px solid ${alpha(neon.purple, 0.25)}` }}>
        <Tab value="urls" label="URLs" sx={TAB_SX} />
        <Tab value="assets" label="Assets" sx={TAB_SX} />
      </Tabs>
      {/* The packet view hands straight to the editor. It closes as the
          editor opens, so the two are never stacked: they show the same
          exchange, and two dialogs of one exchange is a guess about
          which is live. */}
      {packet !== null && (
        <PacketModal id={packet} onClose={() => setPacket(null)}
          onReplay={(pid) => { setPacket(null); setReplay(pid) }} />
      )}
      <Menu open={!!menu} onClose={() => setMenu(null)}
        anchorReference="anchorPosition"
        anchorPosition={menu ? { top: menu.y, left: menu.x } : undefined}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.4)}`,
        } } }}>
        <MenuItem
          onClick={() => { setPacket(menu!.row.id); setMenu(null) }}
          sx={{ fontSize: 12.5, color: neon.cyan }}>
          <ArticleIcon sx={{ fontSize: 16, mr: 1 }} />
          View packet
        </MenuItem>
        <MenuItem
          onClick={() => { setReplay(menu!.row.id); setMenu(null) }}
          sx={{ fontSize: 12.5, color: neon.orange }}>
          <ReplayIcon sx={{ fontSize: 16, mr: 1 }} />
          Edit and resend
        </MenuItem>
        {/* `href` is kept so middle-click and "copy link address" still
            work, but the navigation is done explicitly rather than left
            to the anchor's default. Closing the menu in the same handler
            unmounts that anchor, and an <a> removed during its own click
            never navigates — which is why this did nothing at all. */}
        <MenuItem
          component="a" href={menu?.row.url ?? '#'}
          target="_blank" rel="noopener noreferrer"
          onClick={(e) => {
            e.preventDefault()
            const u = menu?.row.url
            setMenu(null)
            if (u) window.open(u, '_blank', 'noopener,noreferrer')
          }}
          sx={{ fontSize: 12.5, color: neon.text }}>
          <LaunchIcon sx={{ fontSize: 16, mr: 1 }} />
          Open in browser
        </MenuItem>
        <MenuItem
          onClick={() => { navigator.clipboard?.writeText(menu!.row.url); setMenu(null) }}
          sx={{ fontSize: 12.5, color: neon.muted }}>
          <ContentCopyIcon sx={{ fontSize: 16, mr: 1 }} />
          Copy URL
        </MenuItem>
      </Menu>

      <ReplayModal
        id={replay} onClose={() => setReplay(null)}
        onCreated={() => {
          // The new exchange belongs under the same URL, so drop the
          // cached children: leaving them would show a group whose hit
          // count and contents disagree.
          setChildren({})
        }} />
      <DataTable
        tableId="web"
        rows={rows}
        columns={columns as ColumnDef[]}
        loading={isLoading}
        error={error as Error | null}
        initialSort={{ field: 'url', sort: 'asc' }}
        hiddenColumns={{
          path: false, content_type: false, notes: false,
          ...(project ? { project_code: false } : {}),
        }}
        server={table}
        // A group row and the exchange it stands for share an id — the
        // group IS that exchange. The grid keys rows by id, so without a
        // distinct key the parent vanishes the moment it is expanded.
        // Verified: expanding produced three indented rows and no parent,
        // with a duplicate key in the DOM.
        getRowId={(r) => {
          const w = r as unknown as WebRow
          return w.__child ? `c${w.id}` : `g${rowKey(w)}`
        }}
        extraActions={
          <Stack direction="row" spacing={1} sx={{
            alignItems: "center"
          }}>
            <ToggleButtonGroup size="small" exclusive value={filter}
              onChange={(_, v) => v && setFilter(v)}>
              <ToggleButton value="all" sx={tbSx}>All</ToggleButton>
              <ToggleButton value="crawled" sx={tbSx}>Fetched</ToggleButton>
              <ToggleButton value="interesting" sx={tbSx}>200/401/403/500</ToggleButton>
            </ToggleButtonGroup>

            {/* A SECOND, independent filter, and the wording works hard
                to keep it apart from "Fetched" above. "Fetched" is
                whether we retrieved the URL; this is who found it in
                the first place. A path gobuster guessed and we then
                retrieved is Fetched AND Discovery-only. */}
            <SourceFilter value={foundBy} onChange={setFoundBy}
              counts={counts.data} />

            <Typography sx={{ fontSize: 11, color: neon.muted, whiteSpace: 'nowrap' }}>
              {rows.length} of {data?.total ?? 0}
            </Typography>
          </Stack>
        }
      />
    </>
  );
}

const tbSx = {
  fontSize: 10.5, py: 0.25, px: 1, color: neon.muted,
  borderColor: alpha(neon.purple, 0.4),
  '&.Mui-selected': { color: neon.cyan, bgcolor: alpha(neon.cyan, 0.12) },
} as const

type FoundBy = 'any' | 'crawl' | 'discovery'

const FOUND_BY: { value: FoundBy; label: string; hint: string }[] = [
  { value: 'any', label: 'Any source',
    hint: 'Every address, however it was found.' },
  { value: 'crawl', label: 'Crawl-confirmed',
    hint: 'A crawler reached it by following a link, so something in '
        + 'the application points at it.' },
  { value: 'discovery', label: 'Brute force only',
    hint: 'Brute forcing guessed it and no crawler ever reached it — '
        + 'nothing links here. Mostly 401s and 403s: paths that exist '
        + 'and are protected, which no amount of crawling finds.' },
]

/**
 * Filter by what found the URL.
 *
 * This exists instead of a cleanup job. The obvious idea — once a
 * crawl has run, delete the content-discovery rows as clutter —
 * turns out to delete the findings and none of the clutter, because
 * there is no clutter to delete: the importer merges a URL found by
 * two tools into ONE row listing both, so the crawl rows and the
 * discovery-only rows never overlap by construction. On the live
 * estate the rule would have removed 45,163 addresses no crawl ever
 * saw, 29,032 of them answering 401 or 403.
 *
 * So the rows stay and the view narrows. Reversible, costs nothing,
 * and the counts are on the options so the size of each slice is
 * visible before choosing.
 */
function SourceFilter({ value, onChange, counts }: {
  value: FoundBy
  onChange: (v: FoundBy) => void
  counts?: { all: number; crawl: number; discovery: number }
}) {
  const [at, setAt] = useState<HTMLElement | null>(null)
  const current = FOUND_BY.find((o) => o.value === value) ?? FOUND_BY[0]
  const countOf = (v: FoundBy) =>
    counts ? counts[v === 'any' ? 'all' : v] : undefined

  return (
    <>
      <Chip size="small" clickable onClick={(e) => setAt(e.currentTarget)}
        label={`${current.label}${
          countOf(value) === undefined ? '' : ` · ${countOf(value)!.toLocaleString()}`}`}
        sx={{
          fontSize: 10.5, height: 22, borderRadius: 0.5,
          border: `1px solid ${alpha(neon.purple, 0.4)}`,
          bgcolor: value === 'any' ? 'transparent' : alpha(neon.cyan, 0.12),
          color: value === 'any' ? neon.muted : neon.cyan,
        }} />
      <Menu anchorEl={at} open={!!at} onClose={() => setAt(null)}>
        {FOUND_BY.map((o) => (
          <MenuItem key={o.value} selected={o.value === value}
            onClick={() => { onChange(o.value); setAt(null) }}
            sx={{ fontSize: 12, alignItems: 'flex-start', maxWidth: 330 }}>
            <Box>
              <Stack direction="row" spacing={1} sx={{
                alignItems: "baseline"
              }}>
                <Box sx={{ color: neon.cyan }}>{o.label}</Box>
                {countOf(o.value) !== undefined && (
                  <Box sx={{ fontSize: 10.5, color: neon.muted }}>
                    {countOf(o.value)!.toLocaleString()}
                  </Box>
                )}
              </Stack>
              <Box sx={{ fontSize: 10.5, color: neon.muted, whiteSpace: 'normal' }}>
                {o.hint}
              </Box>
            </Box>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}
