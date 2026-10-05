import { useMemo, useState, type ReactNode } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Paper, Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import EditIcon from '@mui/icons-material/EditOutlined'
import RestartAltIcon from '@mui/icons-material/RestartAlt'
import {
  DataGrid, type GridColDef, type GridRowSelectionModel, type GridRowsProp,
} from '@mui/x-data-grid'
import { useQueryClient } from '@tanstack/react-query'
import { api, type EntityKind } from '../lib/api'
import { LABELS } from '../lib/entities'
import { hidesRows, useTableState } from '../lib/useTableState'
import { filterRows, pageOf, sortRows } from '../lib/tableOps'
import { TableFooter } from './TableFooter'
import type { ServerTable } from '../lib/useServerTable'
import { EntityDialog } from './EntityDialog'
import { neon, glow } from '../theme'

/** MUI X v8 hands back {type:'include'|'exclude', ids:Set}. An 'exclude'
 *  model means "everything except these", which we cannot turn into a
 *  concrete id list without the full row set, so resolve it against it. */
function selectedIds(model: GridRowSelectionModel | undefined, rows: GridRowsProp): number[] {
  if (!model) return []
  const anyModel = model as unknown as { type?: string; ids?: Set<unknown> }
  if (anyModel?.ids instanceof Set) {
    const ids = [...anyModel.ids].map(Number)
    if (anyModel.type === 'exclude') {
      const ex = new Set(ids)
      return rows.map((r) => Number((r as { id: number }).id)).filter((i) => !ex.has(i))
    }
    return ids
  }
  return Array.isArray(model) ? (model as unknown[]).map(Number) : []
}

export function DataTable({
  rows, columns, loading, error, initialSort, hiddenColumns, note,
  kind, project, canWrite = false, extraActions, tableId, server,
}: {
  rows: GridRowsProp
  columns: GridColDef[]
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
   *  a view without a kind (Web, Projects) must pass its own. */
  tableId?: string
  /** Supplied when the database does the paging, sorting and searching.
   *  `rows` is then ONE PAGE, not the whole table. Needed for Web,
   *  where one engagement holds 211,012 rows: loading them to filter in
   *  the browser is both slow and wrong, because a search would only
   *  ever see whatever subset had been fetched. */
  server?: ServerTable
}) {
  const qc = useQueryClient()

  // Sort, filters, the search box, column visibility, page size and
  // density survive a reload. See lib/useTableState.
  const view = useTableState(tableId ?? kind ?? 'table', columns, {
    sort: initialSort ? [initialSort] : [],
    columns: hiddenColumns,
  })
  // Selection is left UNCONTROLLED in the grid; we only mirror the ids out
  // for the toolbar. Driving rowSelectionModel from React state fought MUI's
  // own model handling and nothing ever appeared ticked. `gen` bumps the
  // grid's key to clear the selection after an operation.
  const [ids, setIds] = useState<number[]>([])

  // Paging is ours in both modes, because the MIT DataGrid throws above
  // 100 rows a page. The grid is handed one page and `pageSize: -1`,
  // its "all results" sentinel, which is the only value over 100 it
  // accepts. Client mode therefore has to sort and filter out here too
  // — sorting one page is not sorting the table.
  // A column the API cannot filter on must not be offered in the
  // panel; the alternative is a filter that comes back as a 400 and
  // looks like the table is broken.
  const gridColumns = useMemo(() => {
    const ok = server?.filterable
    if (!ok) return columns
    const allow = new Set(ok)
    return columns.map((c) =>
      allow.has(c.field) ? c : { ...c, filterable: false })
  }, [columns, server?.filterable])

  const [clientPage, setClientPage] = useState(0)
  const [clientSize, setClientSize] = useState(view.pagination.pageSize || 100)
  const shown = useMemo(() => {
    if (server) return { rows, page: server.query.page, total: server.total }
    const matched = filterRows(rows as Record<string, unknown>[], view.filter, columns)
    const ordered = sortRows(matched, view.sort, columns)
    const cut = pageOf(ordered, clientPage, clientSize)
    return { rows: cut.rows as GridRowsProp, page: cut.page, total: ordered.length }
  }, [server, rows, columns, view.filter, view.sort, clientPage, clientSize,
      server?.query.page, server?.total])
  const [gen, setGen] = useState(0)
  const [dialog, setDialog] = useState<'create' | 'bulk' | null>(null)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [opErr, setOpErr] = useState<string | null>(null)

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
      setIds([]); setGen((g) => g + 1)
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

  return (
    <Paper elevation={0} sx={{
      flex: 1, minHeight: 0, m: { xs: 1, sm: 1.5 }, overflow: 'hidden',
      display: 'flex', flexDirection: 'column',
      backgroundColor: alpha(neon.paper, 0.72), backdropFilter: 'blur(6px)',
      border: `1px solid ${alpha(neon.pink, 0.34)}`,
      boxShadow: `0 0 26px ${alpha(neon.pink, 0.12)}, inset 0 0 50px ${alpha(neon.purple, 0.07)}`,
      position: 'relative',
    }}>
      {(editable || extraActions || note) && (
        <Stack direction="row" spacing={1} alignItems="center" sx={{
          px: 1.5, py: 0.9, borderBottom: `1px solid ${alpha(neon.pink, 0.22)}`,
          backgroundColor: alpha(neon.bgDeep, 0.45), flexWrap: 'wrap',
        }}>
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
          <Box sx={{ flex: 1 }} />
          {/* A remembered filter that hides rows must announce itself.
              Without this, someone returns to a grid they filtered last
              week, sees four rows, and concludes the import broke. */}
          {view.dirty && (
            <Tooltip title={`Remembered from last time: ${view.summary}. `
                          + `Click to clear.`}>
              <Chip size="small" clickable onDelete={view.reset}
                deleteIcon={<RestartAltIcon sx={{ fontSize: 15 }} />}
                onClick={view.reset}
                label={hidesRows(view) ? `filtered · ${rows.length} shown` : 'view saved'}
                sx={{
                  height: 21, fontSize: 10, letterSpacing: '0.06em',
                  bgcolor: alpha(hidesRows(view) ? neon.yellow : neon.muted, 0.16),
                  color: hidesRows(view) ? neon.yellow : neon.muted,
                  border: `1px solid ${alpha(hidesRows(view) ? neon.yellow : neon.muted, 0.5)}`,
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
        </Stack>
      )}

      {loading && (
        <Box sx={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
                   zIndex: 5, background: alpha(neon.bgDeep, 0.45) }}>
          <CircularProgress sx={{ color: neon.cyan }} />
        </Box>
      )}

      <Box sx={{ flex: 1, minHeight: 0 }}>
        <DataGrid
          rows={shown.rows} columns={gridColumns} showToolbar
          disableRowSelectionOnClick
          key={gen}
          checkboxSelection={editable}
          onRowSelectionModelChange={(m) => setIds(selectedIds(m, rows))}
          // -1 is the grid's "all results" value and the only one above
          // 100 it will accept; everything it is given is one page
          // already. Our own footer does the paging.
          pageSizeOptions={[-1]}
          paginationModel={{ page: 0, pageSize: -1 }}
          hideFooterPagination
          // In server mode the grid must not re-sort or re-filter: it
          // holds one page, and ordering a page is not ordering the
          // table. In client mode we sort and filter in tableOps, for
          // the same reason.
          sortingMode="server"
          filterMode="server"
          // The filter panel stays available in server mode: the API
          // takes chained column filters and combines them with AND or
          // OR, so the panel means what it appears to mean. Columns the
          // API will not filter on are marked unfilterable below rather
          // than offered and then rejected.
          // Every model is controlled rather than initialState: that is
          // read once at mount, so it can neither reflect the project
          // chosen a tick later nor be written back when the user sorts.
          columnVisibilityModel={view.columns}
          onColumnVisibilityModelChange={view.setColumns}
          sortModel={server ? server.sortModel : view.sort}
          onSortModelChange={server ? server.setSortModel : view.setSort}
          filterModel={server
            ? { ...server.filterModel,
                quickFilterValues: server.typed ? server.typed.split(/\s+/) : [] }
            : view.filter}
          onFilterModelChange={server
            ? (m) => {
                // The panel carries both: the chained column filters go
                // to SQL, the quick-filter words become the `q` search.
                server.setTyped((m.quickFilterValues ?? []).join(' '))
                server.setFilterModel({
                  items: m.items ?? [],
                  logicOperator: m.logicOperator,
                })
              }
            : view.setFilter}
          density={view.density}
          onDensityChange={view.setDensity}
          sx={{
            border: 0, color: neon.text, fontFamily: `'Share Tech Mono', monospace`,
            '--DataGrid-containerBackground': 'transparent',
            '--DataGrid-rowBorderColor': alpha(neon.purple, 0.16),
            '& .MuiDataGrid-columnHeaders': { borderBottom: `1px solid ${alpha(neon.cyan, 0.45)}` },
            '& .MuiDataGrid-columnHeaderTitle': {
              fontFamily: `'Orbitron', sans-serif`, fontSize: 11, fontWeight: 700,
              letterSpacing: '0.14em', textTransform: 'uppercase',
              color: neon.cyan, textShadow: glow(neon.cyan, 0.55),
            },
            '& .MuiDataGrid-columnSeparator': { color: alpha(neon.purple, 0.3) },
            '& .MuiDataGrid-cell': { borderBottom: `1px solid ${alpha(neon.purple, 0.12)}` },
            '& .MuiDataGrid-row:hover': { backgroundColor: alpha(neon.pink, 0.09) },
            '& .MuiDataGrid-row.Mui-selected, & .MuiDataGrid-row.Mui-selected:hover': {
              backgroundColor: alpha(neon.cyan, 0.12),
            },
            '& .MuiCheckbox-root': { color: alpha(neon.muted, 0.7),
                                     '&.Mui-checked': { color: neon.cyan } },
            '& .MuiDataGrid-toolbarContainer, & .MuiDataGrid-toolbar': {
              padding: '8px 10px', gap: 8,
              borderBottom: `1px solid ${alpha(neon.pink, 0.22)}`,
              backgroundColor: alpha(neon.bgDeep, 0.5),
            },
            '& .MuiDataGrid-footerContainer': {
              borderTop: `1px solid ${alpha(neon.pink, 0.28)}`,
              backgroundColor: alpha(neon.bgDeep, 0.5),
            },
            '& .MuiTablePagination-root, & .MuiDataGrid-selectedRowCount': { color: neon.muted },
            '& .MuiDataGrid-overlay': { backgroundColor: 'transparent', color: neon.muted },
          }}
        />
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
          ids={ids} onClose={() => { setDialog(null); setIds([]); setGen((g) => g + 1) }} />
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
