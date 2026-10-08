import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Paper, Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import EditIcon from '@mui/icons-material/EditOutlined'
import RestartAltIcon from '@mui/icons-material/RestartAlt'
import type { RowSelectionState } from '@tanstack/react-table'
import { useQueryClient } from '@tanstack/react-query'
import { api, type EntityKind } from '../lib/api'
import { LABELS } from '../lib/entities'
import { useTableState } from '../lib/useTableState'
import { cellValue, filterRows, pageOf, sortRows } from '../lib/tableOps'
import {
  armedItems, nextSort,
  type ColumnDef, type FilterModel, type RowIdGetter,
} from '../lib/columns'
import { TableFooter } from './TableFooter'
import { TableToolbar } from './TableToolbar'
import { EmptyRows, TableGrid } from './TableGrid'
import type { ServerTable } from '../lib/useServerTable'
import { EntityDialog } from './EntityDialog'
import { neon, glow } from '../theme'

/** A stable empty list, so a table with nothing ticked does not hand its
 *  view a new array on every render and restart whatever that triggers. */
const NO_IDS: number[] = []

/** One field, escaped for CSV — and defused.
 *
 *  A cell beginning `=`, `+`, `-` or `@` is a formula to Excel and to
 *  Sheets, and these tables carry attacker-controlled text: a page title,
 *  a banner, a URL scraped off a host under test. Exporting one unquoted
 *  turns "download the findings" into running whatever the target wrote. */
function csvCell(v: unknown): string {
  const s = v == null ? '' : String(v)
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
  return `"${safe.replace(/"/g, '""')}"`
}

export function DataTable({
  rows, columns, loading, error, initialSort, hiddenColumns, note,
  kind, project, canWrite = false, extraActions, tableId, server, getRowId,
  onSelectionChange,
}: {
  /** `any` because a row is whatever the view's query returned; this is
   *  what `GridRowsProp` defaulted to and the views rely on it. */
  rows: readonly any[]
  columns: ColumnDef[]
  loading?: boolean
  error?: Error | null
  initialSort?: { field: string; sort: 'asc' | 'desc' }
  hiddenColumns?: Record<string, boolean>
  note?: string
  /** Enables add / bulk-edit / delete when given alongside a project. */
  kind?: EntityKind
  project?: string | null
  canWrite?: boolean
  extraActions?: ReactNode
  /** Identity for remembering sort/filter/columns. Defaults to `kind`;
   *  a view without a kind (Web, Projects) must pass its own. Changing
   *  one orphans every user's saved state for that table. */
  tableId?: string
  /** How to key a row, when `id` is not unique across the rows given.
   *  The Web table shows a URL group and then its exchanges beneath it;
   *  the group's id IS one of those exchanges, so without this the table
   *  sees a duplicate key and the parent row disappears. */
  getRowId?: RowIdGetter
  /** Supplied when the database does the paging, sorting and searching.
   *  `rows` is then ONE PAGE, not the whole table. Needed for Web,
   *  where one engagement holds 211,012 rows: loading them to filter in
   *  the browser is both slow and wrong, because a search would only
   *  ever see whatever subset had been fetched. */
  server?: ServerTable
  /** Mirror of the selection, for a view that acts on it. */
  onSelectionChange?: (ids: number[]) => void
}) {
  const qc = useQueryClient()

  // Sort, filters, the search box, column visibility, page size and
  // density survive a reload. See lib/useTableState.
  const view = useTableState(tableId ?? kind ?? 'table', columns, {
    sort: initialSort ? [initialSort] : [],
    columns: hiddenColumns,
  })

  // Selection is a map of row key to ticked, owned here so that it
  // survives paging and so that the clears which follow a delete or a
  // bulk edit are seen by the view watching it. The keys are whatever
  // `getRowId` produces; the ids handed out are the entity's own `id`,
  // resolved against the rows we hold.
  const [selection, setSelection] = useState<RowSelectionState>({})

  // A column the API cannot filter on must not be offered in the panel;
  // the alternative is a filter that comes back as a 400 and looks like
  // the table is broken. Marking it unfilterable also keeps it out of
  // the search box, which is how Credentials keeps secrets out of it.
  const shownColumns = useMemo(() => {
    const ok = server?.filterable
    if (!ok) return columns
    const allow = new Set(ok)
    return columns.map((c) =>
      allow.has(c.field) ? c : { ...c, filterable: false })
  }, [columns, server?.filterable])

  const [clientPage, setClientPage] = useState(0)
  const [clientSize, setClientSize] = useState(view.pagination.pageSize || 100)
  // The search box in client mode. The model holds the terms split
  // apart, which cannot round-trip what was typed — "acme " would come
  // back as "acme" and eat the space as it was typed — so the string
  // lives here and the terms are derived from it.
  const [clientSearch, setClientSearch] = useState(
    () => (view.filter.quickFilterValues ?? []).join(' '))

  // Paging is ours in both modes. In server mode the database has
  // already filtered, ordered and sliced; in client mode `tableOps` does
  // all three over the WHOLE row set, because ordering a page is not
  // ordering the table and filtering one would leave the footer counting
  // something else.
  const shown = useMemo(() => {
    if (server) return { rows, page: server.query.page, total: server.total }
    const matched = filterRows(rows as Record<string, unknown>[], view.filter, columns)
    const ordered = sortRows(matched, view.sort, columns)
    const cut = pageOf(ordered, clientPage, clientSize)
    return { rows: cut.rows as readonly any[], page: cut.page, total: ordered.length }
    // `server.query.page` and `server.total` used to be listed here too.
    // They are already covered by `server`, which useServerTable rebuilds
    // on every render, so naming the fields as well said nothing extra.
  }, [server, rows, columns, view.filter, view.sort, clientPage, clientSize])

  const [dialog, setDialog] = useState<'create' | 'bulk' | null>(null)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [opErr, setOpErr] = useState<string | null>(null)

  const keyOf = useCallback(
    (row: any) => String(getRowId ? getRowId(row) : (row as { id?: unknown })?.id),
    [getRowId])

  const ids = useMemo(() => {
    const picked = Object.keys(selection).filter((k) => selection[k])
    if (!picked.length) return NO_IDS
    const want = new Set(picked)
    // Resolved against the rows we hold rather than carried as keys:
    // every caller wants a concrete list of entity ids to delete or
    // edit, and a key is not one. Rows that have since gone drop out,
    // which is the right answer — they cannot be edited either.
    return rows
      .filter((r) => want.has(keyOf(r)))
      .map((r) => Number((r as { id?: unknown }).id))
      .filter((n) => Number.isFinite(n))
  }, [selection, rows, keyOf])

  useEffect(() => { onSelectionChange?.(ids) }, [ids, onSelectionChange])

  // Which model is actually in force. Reading the client one while the
  // server is doing the filtering is how the Web table ended up unable
  // to say it was filtered: `view.filter` is never written in server
  // mode, so the chip could not fire however many conditions were on.
  const filterModel: FilterModel = server ? server.filterModel : view.filter
  const filtering = server ? server.dirty : view.hiding

  const setFilterModel = (next: FilterModel) => {
    if (server) { server.setFilterModel(next); return }
    view.setFilter(next)
    setClientPage(0)      // a different result set has a different page 7
  }

  const setSearch = (next: string) => {
    if (server) { server.setTyped(next); return }
    setClientSearch(next)
    view.setFilter({
      ...view.filter,
      quickFilterValues: next.trim() ? next.trim().split(/\s+/) : [],
    })
    setClientPage(0)
  }

  const onSort = (field: string, additive: boolean) => {
    if (server) {
      // The API orders on one column, so a shift-click cannot mean a
      // second one here. See useServerTable.setSortModel.
      server.setSortModel(nextSort(server.sortModel, field, false))
      return
    }
    view.setSort(nextSort(view.sort, field, additive))
  }

  const resetView = () => {
    view.reset()
    setClientSearch('')
    setClientPage(0)
    // In server mode the conditions and the search live on the query,
    // not in the view state, so clearing only the latter would leave a
    // table insisting it was unfiltered while the database filtered it.
    server?.reset()
  }

  const exportCsv = () => {
    const cols = shownColumns.filter((c) => view.columns[c.field] !== false)
    const lines = [
      cols.map((c) => csvCell(c.headerName || c.field)).join(','),
      ...shown.rows.map((r) => cols
        .map((c) => csvCell(cellValue(r as Record<string, unknown>, c, c.field)))
        .join(',')),
    ]
    const url = URL.createObjectURL(
      new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${tableId ?? kind ?? 'table'}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Creating needs a single project to create *into*; "All projects" is
  // ambiguous, so the button is offered only when one is selected.
  const editable = !!kind && canWrite
  const canCreate = editable && !!project && kind !== 'pocs'

  const doDelete = async () => {
    if (!kind) return
    setBusy(true); setOpErr(null)
    try {
      const r = await api.bulkDelete(kind, ids)
      if (r.errors.length) setOpErr(`${r.changed} deleted, ${r.skipped} skipped — ${r.errors.join('; ')}`)
      else setConfirm(false)
      setSelection({})
      await qc.invalidateQueries()
    } catch (e) {
      setOpErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <Alert severity="error" variant="outlined"
        sx={{ m: 2, fontFamily: `'Share Tech Mono', monospace`,
              borderColor: alpha(neon.red, 0.6), color: neon.text }}>
        {error.message}
      </Alert>
    )
  }

  const btn = (c: string) => ({
    color: c, borderColor: alpha(c, 0.5), fontSize: 11, py: 0.3,
    '&:hover': { borderColor: c, boxShadow: `0 0 10px ${alpha(c, 0.35)}` },
  })

  // What the server side has on, in the same words the client side uses.
  // `view.summary` covers nothing in this mode, because none of it is
  // written there.
  const serverConditions = server ? armedItems(server.filterModel).length : 0
  const serverSummary = server
    ? [server.query.q ? `search “${server.query.q}”` : '',
       serverConditions
         ? `${serverConditions} filter${serverConditions > 1 ? 's' : ''}` : '']
      .filter(Boolean).join(' · ')
    : ''
  const summary = [view.summary, serverSummary].filter(Boolean).join(' · ')
  const dirty = view.dirty || filtering

  return (
    <Paper elevation={0} sx={{
      flex: 1, minHeight: 0, m: { xs: 1, sm: 1.5 }, overflow: 'hidden',
      display: 'flex', flexDirection: 'column',
      backgroundColor: alpha(neon.paper, 0.72), backdropFilter: 'blur(6px)',
      border: `1px solid ${alpha(neon.pink, 0.34)}`,
      boxShadow: `0 0 26px ${alpha(neon.pink, 0.12)}, inset 0 0 50px ${alpha(neon.purple, 0.07)}`,
      position: 'relative',
    }}>
      <TableToolbar
        columns={shownColumns}
        filter={filterModel}
        onFilter={setFilterModel}
        search={server ? server.typed : clientSearch}
        onSearch={setSearch}
        searchNote={server
          ? 'Searched and filtered in the database, over every row — not '
            + 'over the page on screen.'
          : undefined}
        columnVisibility={view.columns}
        onColumnVisibility={view.setColumns}
        density={view.density}
        onDensity={view.setDensity}
        onExport={exportCsv}
        serverSide={!!server}
        actions={
          <>
            {canCreate && (
              <Button size="small" variant="outlined" startIcon={<AddIcon />}
                onClick={() => setDialog('create')} sx={btn(neon.green)}>
                Add
              </Button>
            )}
            {editable && (
              <>
                <Button size="small" variant="outlined" startIcon={<EditIcon />}
                  disabled={!ids.length} onClick={() => setDialog('bulk')} sx={btn(neon.cyan)}>
                  Edit{ids.length ? ` (${ids.length})` : ''}
                </Button>
                <Button size="small" variant="outlined" startIcon={<DeleteIcon />}
                  disabled={!ids.length} onClick={() => { setOpErr(null); setConfirm(true) }}
                  sx={btn(neon.red)}>
                  Delete{ids.length ? ` (${ids.length})` : ''}
                </Button>
              </>
            )}
            {extraActions}
          </>
        }
        status={
          <>
            {/* A remembered filter that hides rows must announce itself.
                Without this, someone returns to a table they filtered
                last week, sees four rows, and concludes the import
                broke. The conditions themselves are chipped below. */}
            {dirty && (
              <Tooltip title={`Remembered from last time: ${summary}. Click to clear.`}>
                <Chip size="small" clickable onDelete={resetView}
                  deleteIcon={<RestartAltIcon sx={{ fontSize: 15 }} />}
                  onClick={resetView}
                  label={filtering
                    ? `filtered · ${shown.total.toLocaleString()} of these`
                    : 'view saved'}
                  sx={{
                    height: 21, fontSize: 10, letterSpacing: '0.06em',
                    bgcolor: alpha(filtering ? neon.yellow : neon.muted, 0.16),
                    color: filtering ? neon.yellow : neon.muted,
                    border: `1px solid ${alpha(filtering ? neon.yellow : neon.muted, 0.5)}`,
                    '& .MuiChip-deleteIcon': {
                      color: 'inherit', '&:hover': { color: neon.pink } },
                  }} />
              </Tooltip>
            )}
            {note && (
              <Typography sx={{
                fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase',
                fontFamily: `'Orbitron', sans-serif`, color: neon.yellow,
                textShadow: glow(neon.yellow, 0.5),
              }}>{note}</Typography>
            )}
          </>
        }
      />

      {loading && (
        <Box sx={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
                   zIndex: 5, background: alpha(neon.bgDeep, 0.45) }}>
          <CircularProgress sx={{ color: neon.cyan }} />
        </Box>
      )}

      <Box sx={{ flex: 1, minHeight: 0 }}>
        <TableGrid
          rows={shown.rows}
          columns={shownColumns}
          columnVisibility={view.columns}
          sort={server ? server.sortModel : view.sort}
          onSort={onSort}
          density={view.density}
          getRowId={getRowId}
          selectable={editable}
          rowSelection={selection}
          onRowSelectionChange={setSelection}
          empty={filtering
            ? (
              <Stack spacing={1} alignItems="center">
                <Typography sx={{ fontSize: 12.5, color: neon.yellow }}>
                  No rows match the {armedItems(filterModel).length || 'current'} filter
                  {armedItems(filterModel).length === 1 ? '' : 's'} on this table.
                </Typography>
                <Button size="small" onClick={resetView}
                  sx={{ color: neon.cyan, fontSize: 11 }}>
                  Clear them
                </Button>
              </Stack>
            )
            : <EmptyRows />} />
      </Box>

      <TableFooter
        page={server ? server.query.page : shown.page}
        pageSize={server ? server.query.pageSize : clientSize}
        total={shown.total}
        loading={loading}
        note={server ? 'paged in the database' : undefined}
        onPage={server ? server.setPage : setClientPage}
        onPageSize={(n) => {
          if (server) server.setPageSize(n)
          else { setClientSize(n); setClientPage(0) }
        }} />

      {dialog && kind && (
        <EntityDialog kind={kind} project={project ?? ''} mode={dialog}
          ids={ids} onClose={() => { setDialog(null); setSelection({}) }} />
      )}

      <Dialog open={confirm} onClose={() => setConfirm(false)} maxWidth="xs" fullWidth
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.red, 0.5)}`,
        } } }}>
        <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                           letterSpacing: '0.14em', color: neon.red }}>
          DELETE {ids.length} {kind ? LABELS[kind].toUpperCase() : ''}{ids.length > 1 ? 'S' : ''}
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ fontSize: 13, color: neon.text }}>
            This cannot be undone.
            {kind === 'targets' && ' Deleting a target also deletes its services, vulnerabilities and PoCs.'}
          </Typography>
          {opErr && <Alert severity="warning" variant="outlined"
                           sx={{ mt: 2, fontSize: 12.5 }}>{opErr}</Alert>}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setConfirm(false)} sx={{ color: neon.muted }}>Cancel</Button>
          <Button onClick={doDelete} disabled={busy} variant="outlined" sx={btn(neon.red)}>
            {busy ? '…' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  )
}
