import { useEffect, useMemo, useState } from 'react'
import {
  Box, Chip, Menu, MenuItem, Stack, ToggleButton, ToggleButtonGroup,
  Tooltip, Typography, alpha,
} from '@mui/material'
import LaunchIcon from '@mui/icons-material/Launch'
import ArticleIcon from '@mui/icons-material/ArticleOutlined'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import ReplayIcon from '@mui/icons-material/Replay'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import CircularProgress from '@mui/material/CircularProgress'
import IconButton from '@mui/material/IconButton'
import type { GridColDef } from '@mui/x-data-grid'
import { useQuery } from '@tanstack/react-query'
import { useServerTable } from '../lib/useServerTable'
import { api, type WebAddress, type WebGroup } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { PacketModal } from '../components/PacketModal'
import { ReplayModal } from '../components/ReplayModal'
import { neon, glow } from '../theme'

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
                                          methods?: string[]; statuses?: number[] }

/** Groups are keyed on (target, url) — the same path on two hosts is
 *  two URLs, and ids are not stable across pages. */
const rowKey = (r: { target_id: number; url: string }) => `${r.target_id}|${r.url}`

export function WebView({ project }: { project: string | null }) {
  const { open } = useHostModal()
  const [menu, setMenu] = useState<{ el: HTMLElement; row: WebAddress } | null>(null)
  const [packet, setPacket] = useState<number | null>(null)
  // Reaching a URL is the thing a reader most often wants and the thing
  // the table cannot do for them, so it is a link rather than a cell.
  const [filter, setFilter] = useState<'all' | 'crawled' | 'interesting'>('all')
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
    queryKey: ['web', project, filter, table.query],
    queryFn: () => api.webGrouped({
      project: project ?? undefined,
      crawled: filter === 'crawled' ? true : undefined,
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

  // Taken off `table` rather than called through it. useServerTable
  // builds a new object on every render, so depending on `table` would
  // re-run both of these every render; these two in particular are raw
  // useState setters underneath and so are stable for the life of the
  // component, which makes them honest dependencies.
  const { setTotal, setPage } = table
  useEffect(() => { setTotal(data?.total ?? 0) }, [setTotal, data?.total])
  // Changing the crawled/interesting shortcut changes the result set,
  // so page 7 of the old one is meaningless.
  useEffect(() => { setPage(0) }, [setPage, filter, project])

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
    for (const g of data?.items ?? []) {
      out.push(g)
      const kids = children[rowKey(g)]
      if (expanded.has(rowKey(g)) && kids) {
        for (const k of kids) out.push({ ...k, __child: true })
      }
    }
    return out
  }, [data?.items, expanded, children])

  const columns: GridColDef<WebAddress>[] = [
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
          <Stack direction="row" alignItems="center" spacing={0.5}
            sx={{ pl: r.__child ? 3 : 0, minWidth: 0 }}>
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
              onClick={(e) => { e.stopPropagation(); setMenu({ el: e.currentTarget, row: p.row }) }}
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
        )
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
    { field: 'webserver', headerName: 'Server', flex: 1, minWidth: 130,
      valueGetter: (v) => v ?? '' },
    {
      field: 'crawled', headerName: 'Fetched', width: 96, type: 'boolean',
      // The distinction the column exists for: something actually
      // retrieved this, as opposed to merely referencing it.
      renderCell: (p) => p.value
        ? <Tooltip title="A tool actually fetched this address">
            <Box sx={{ color: neon.green, textShadow: glow(neon.green, 0.5) }}>✓</Box>
          </Tooltip>
        : <Tooltip title="Referenced but never fetched">
            <Box sx={{ color: alpha(neon.muted, 0.45) }}>—</Box>
          </Tooltip>,
    },
    {
      field: 'sources', headerName: 'Found by', flex: 1, minWidth: 130,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.4} flexWrap="wrap" useFlexGap>
          {String(p.value || '').split(',').filter(Boolean).map((s) => (
            <Chip key={s} size="small" label={s} sx={{
              height: 17, fontSize: 9.5, bgcolor: alpha(neon.purple, 0.16),
              color: neon.purple, border: `1px solid ${alpha(neon.purple, 0.4)}` }} />
          ))}
        </Stack>
      ),
    },
    { field: 'project_code', headerName: 'Project', width: 120 },
  ]

  return (
    <>
    {packet !== null && (
      <PacketModal id={packet} onClose={() => setPacket(null)} />
    )}
    <Menu open={!!menu} anchorEl={menu?.el} onClose={() => setMenu(null)}
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
      <MenuItem
        component="a" href={menu?.row.url} target="_blank" rel="noopener noreferrer"
        onClick={() => setMenu(null)}
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
      columns={columns as GridColDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'url', sort: 'asc' }}
      hiddenColumns={project ? { project_code: false } : undefined}
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
        <Stack direction="row" spacing={1} alignItems="center">
          <ToggleButtonGroup size="small" exclusive value={filter}
            onChange={(_, v) => v && setFilter(v)}>
            <ToggleButton value="all" sx={tbSx}>All</ToggleButton>
            <ToggleButton value="crawled" sx={tbSx}>Fetched</ToggleButton>
            <ToggleButton value="interesting" sx={tbSx}>200/401/403/500</ToggleButton>
          </ToggleButtonGroup>
          <Typography sx={{ fontSize: 11, color: neon.muted, whiteSpace: 'nowrap' }}>
            {rows.length} of {data?.total ?? 0}
          </Typography>
        </Stack>
      }
    />
    </>
  )
}

const tbSx = {
  fontSize: 10.5, py: 0.25, px: 1, color: neon.muted,
  borderColor: alpha(neon.purple, 0.4),
  '&.Mui-selected': { color: neon.cyan, bgcolor: alpha(neon.cyan, 0.12) },
} as const
