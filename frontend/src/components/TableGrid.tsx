/**
 * The table itself: headers, rows, cells.
 *
 * TanStack Table does the bookkeeping — which columns are showing, which
 * rows are ticked, how a row is keyed, how a cell's value is derived — and
 * nothing else. Sorting, filtering and paging are deliberately `manual`
 * here, because this component is only ever handed ONE PAGE: in server
 * mode the database has already done all three, and in client mode
 * `lib/tableOps.ts` has, over the whole row set. A table that re-sorted
 * its own page would be ordering a slice and calling it an order.
 *
 * The markup is CSS grid rather than `<table>`, which is what makes a
 * column's `flex`, `width` and `minWidth` mean what they say: a flexing
 * column becomes `minmax(minWidth, flex fr)` and a fixed one a pixel
 * track, so the row stops shrinking at the sum of the minimums and the
 * container scrolls sideways instead of crushing the text.
 */
import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react'
import { Box, Checkbox, Tooltip, Typography, alpha } from '@mui/material'
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward'
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward'
import {
  flexRender, getCoreRowModel, useReactTable,
  type ColumnDef as TanstackColumn, type OnChangeFn,
  type RowSelectionState, type VisibilityState,
} from '@tanstack/react-table'
import { cellValue } from '../lib/tableOps'
import type { ColumnDef, Density, RowIdGetter, SortModel } from '../lib/columns'
import { MAX_WIDTH, MIN_WIDTH } from '../lib/useTableState'
import { neon, glow } from '../theme'

/** Row height per density, and the padding that goes with it. */
const ROW: Record<Density, { h: number; py: number }> = {
  compact: { h: 34, py: 0.15 },
  standard: { h: 44, py: 0.5 },
  comfortable: { h: 56, py: 0.9 },
}

/** The track a column occupies, and the width below which we scroll.
 *
 *  A dragged width wins over everything, INCLUDING `flex`. A flexing
 *  column that has been given a size is no longer flexing: the whole
 *  point of dragging it was to say how wide it should be, and leaving
 *  it as a fraction would have it spring back the moment a sibling
 *  changed. */
function track(c: ColumnDef, dragged?: number): { css: string; min: number } {
  if (dragged != null) return { css: `${dragged}px`, min: dragged }
  if (c.flex) {
    const min = c.minWidth ?? 80
    return { css: `minmax(${min}px, ${c.flex}fr)`, min }
  }
  const w = c.width ?? c.minWidth ?? 110
  return { css: `${w}px`, min: w }
}

const JUSTIFY = { left: 'flex-start', center: 'center', right: 'flex-end' } as const

/** The checkbox gutter, when there is one. */
const TICK = 42

export function TableGrid({
  rows, columns, columnVisibility, sort, onSort, density, getRowId,
  selectable, rowSelection, onRowSelectionChange, empty,
  widths = {}, onWidth,
}: {
  /** One page of rows. `any` for the same reason MUI's own row type was
   *  `any`: a row is whatever the view's query returned. */
  rows: readonly any[]
  columns: ColumnDef[]
  columnVisibility: VisibilityState
  sort: SortModel
  /** Shift-click asks for an additional sort rather than a replacement. */
  onSort: (field: string, additive: boolean) => void
  density: Density
  getRowId?: RowIdGetter
  selectable: boolean
  rowSelection: RowSelectionState
  onRowSelectionChange: OnChangeFn<RowSelectionState>
  /** Shown in place of the rows when there are none. */
  empty: ReactNode
  /** Widths the operator dragged, by field. */
  widths?: Record<string, number>
  /** Commit one. `null` restores the column's own default. Called on
   *  release, not during the drag -- the drag is tracked locally so a
   *  pointermove does not write to storage sixty times a second. */
  onWidth?: (field: string, px: number | null) => void
}) {
  const byField = useMemo(
    () => new Map(columns.map((c) => [c.field, c])), [columns])

  const tanstackColumns = useMemo<TanstackColumn<any>[]>(
    () => columns.map((c) => ({
      id: c.field,
      // The column's own `valueGetter` decides the value, so sorting,
      // filtering, the search box and the cell all read the same thing.
      accessorFn: (row: any) => cellValue(row as Record<string, unknown>, c, c.field),
      header: c.headerName ?? c.field,
      enableSorting: false,      // ordering happens outside; see the header
      cell: (ctx) => {
        const value = ctx.getValue()
        if (c.renderCell) {
          return c.renderCell({
            value, row: ctx.row.original, field: c.field, id: ctx.row.id,
          })
        }
        return value == null ? '' : String(value)
      },
    })),
    [columns])

  // `incompatible-library` is React Compiler's warning that this hook
  // returns functions it cannot memoize, so it would skip optimising the
  // component. There is no React Compiler in this build — vite.config.ts
  // runs plain @vitejs/plugin-react — so the warning describes a cost
  // nothing here is paying, and it is advice rather than a defect either
  // way: the hook is doing bookkeeping over one page of rows.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    // Cast only to drop `readonly`; the rows are never written to.
    data: rows as any[],
    columns: tanstackColumns,
    state: { columnVisibility, rowSelection },
    onRowSelectionChange,
    enableRowSelection: selectable,
    // The Web table shows a URL group and then its exchanges beneath it,
    // and the group's id IS one of those exchanges. Without a key of the
    // view's choosing the two collide and the parent row disappears.
    getRowId: getRowId
      ? (row: any, index: number) => String(getRowId(row) ?? index)
      : (row: any, index: number) => String((row as { id?: unknown }).id ?? index),
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
    manualFiltering: true,
    manualPagination: true,
  })

  // Derived from the visibility model rather than from
  // `table.getVisibleLeafColumns()`, and that is not a style choice:
  // `useReactTable` hands back the SAME instance object on every render,
  // so a memo keyed on `table` would never recompute and the column
  // tracks would keep describing whichever columns were showing when the
  // component first mounted. The rule matches TanStack's — a field with
  // no entry is visible — so this and `row.getVisibleCells()` agree.
  const shownColumns = useMemo(
    () => columns.filter((c) => columnVisibility[c.field] !== false),
    [columns, columnVisibility])

  // The column being dragged right now, and how wide it is at this
  // instant. Held here rather than pushed up on every pointermove:
  // the state above persists to localStorage on change, and a drag
  // would otherwise write it continuously for the length of the
  // gesture. The committed value goes up once, on release.
  const [live, setLive] = useState<{ field: string; w: number } | null>(null)
  const drag = useRef<{ field: string; startX: number; startW: number } | null>(null)

  const widthOf = useCallback((field: string) => (
    live && live.field === field ? live.w : widths[field]
  ), [live, widths])

  const onHandleDown = useCallback((e: React.PointerEvent, field: string) => {
    // The handle sits inside a header that sorts on click. Without
    // this, every resize also re-sorts the table.
    e.preventDefault()
    e.stopPropagation()
    const cell = (e.currentTarget as HTMLElement).closest('[role=columnheader]')
    const startW = (cell as HTMLElement | null)?.offsetWidth ?? 110
    drag.current = { field, startX: e.clientX, startW }
    setLive({ field, w: startW })
    // Capture, so the drag survives the pointer leaving the 6px
    // handle -- which it does immediately, every time.
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }, [])

  const onHandleMove = useCallback((e: React.PointerEvent) => {
    const d = drag.current
    if (!d) return
    const w = Math.max(MIN_WIDTH,
                       Math.min(MAX_WIDTH, d.startW + (e.clientX - d.startX)))
    setLive({ field: d.field, w })
  }, [])

  const onHandleUp = useCallback((e: React.PointerEvent) => {
    const d = drag.current
    if (!d) return
    const w = Math.max(MIN_WIDTH,
                       Math.min(MAX_WIDTH, d.startW + (e.clientX - d.startX)))
    drag.current = null
    setLive(null)
    onWidth?.(d.field, w)
  }, [onWidth])

  const layout = useMemo(() => {
    const parts = shownColumns.map((c) => track(c, widthOf(c.field)))
    return {
      template: (selectable ? `${TICK}px ` : '')
        + (parts.map((p) => p.css).join(' ') || '1fr'),
      min: (selectable ? TICK : 0) + parts.reduce((n, p) => n + p.min, 0),
    }
  }, [shownColumns, selectable, widthOf])

  const sortIndex = useMemo(() => {
    const m = new Map<string, { dir: 'asc' | 'desc'; place: number }>()
    sort.forEach((s, i) => {
      if (s.sort) m.set(s.field, { dir: s.sort, place: i })
    })
    return m
  }, [sort])

  const { h, py } = ROW[density] ?? ROW.compact
  const bodyRows = table.getRowModel().rows
  const allTicked = selectable && bodyRows.length > 0
    && bodyRows.every((r) => r.getIsSelected())
  const someTicked = selectable && !allTicked && bodyRows.some((r) => r.getIsSelected())

  // Every row and cell rule lives on the one container, and the rows and
  // cells themselves are plain divs. With a page size of 1000 and ten
  // columns there are ten thousand cells on screen, and giving each one
  // its own `sx` means ten thousand style objects for Emotion to
  // serialise on every render. The MUI grid this replaces virtualised
  // its rows and so never rendered that many; this one does not, so the
  // per-element cost is the thing that has to be small.
  const sheet = {
    height: '100%', overflow: 'auto', position: 'relative',
    fontFamily: `'Share Tech Mono', monospace`, color: neon.text,

    '& [role="row"]': {
      display: 'grid', gridTemplateColumns: layout.template,
    },
    '& [role="cell"], & [role="columnheader"]': {
      display: 'flex', alignItems: 'center', minWidth: 0, overflow: 'hidden',
      px: 1.25, py, fontSize: 12.5,
    },
    '& .tick': { display: 'flex', alignItems: 'center', justifyContent: 'center' },

    '& .thead': {
      position: 'sticky', top: 0, zIndex: 3,
      backgroundColor: neon.bgDeep,
      borderBottom: `1px solid ${alpha(neon.cyan, 0.45)}`,
    },
    '& [role="columnheader"]': { minHeight: 36, userSelect: 'none' },
    '& [role="columnheader"].sortable': { cursor: 'pointer' },
    '& [role="columnheader"].sortable:hover': {
      backgroundColor: alpha(neon.cyan, 0.07),
    },
    '& .head-label': {
      fontFamily: `'Orbitron', sans-serif`, fontSize: 11, fontWeight: 700,
      letterSpacing: '0.14em', textTransform: 'uppercase',
      color: neon.cyan, textShadow: glow(neon.cyan, 0.55),
      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
    },

    '& .tbody [role="row"]': {
      minHeight: h,
      borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`,
    },
    '& .tbody [role="row"]:hover': { backgroundColor: alpha(neon.pink, 0.09) },
    '& .tbody [role="row"].ticked': { backgroundColor: alpha(neon.cyan, 0.12) },
    '& .tbody [role="row"].ticked:hover': { backgroundColor: alpha(neon.cyan, 0.12) },

    // A view's own markup gets a flex box with `minWidth: 0` around it so
    // that whatever ellipsis it set up actually has somewhere to clip.
    '& .custom': {
      display: 'flex', alignItems: 'center', minWidth: 0,
      maxWidth: '100%', overflow: 'hidden',
    },
    '& .plain': {
      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
    },
  } as const

  return (
    <Box sx={sheet}>
      <Box role="table" sx={{ minWidth: layout.min, display: 'flex',
                              flexDirection: 'column' }}>
        {table.getHeaderGroups().map((group) => (
          <div key={group.id} role="row" className="thead">
            {selectable && (
              <div className="tick">
                <Checkbox size="small" checked={allTicked} indeterminate={someTicked}
                  onChange={table.getToggleAllRowsSelectedHandler()}
                  sx={tickSx} />
              </div>
            )}
            {group.headers.map((header) => {
              const col = byField.get(header.column.id)
              if (!col) return null
              const sorted = sortIndex.get(col.field)
              const sortable = col.sortable !== false
              return (
                <div key={header.id} role="columnheader"
                  className={sortable ? 'sortable' : undefined}
                  onClick={sortable ? (e) => onSort(col.field, e.shiftKey) : undefined}
                  title={sortable
                    ? 'Click to sort. Shift-click to sort by this as well as '
                      + 'the column already sorted.'
                    : undefined}
                  style={{ position: 'relative',
                           justifyContent: JUSTIFY[col.headerAlign ?? col.align ?? 'left'] }}>
                  <span className="head-label">
                    {header.isPlaceholder ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </span>
                  {/* The grab strip. Six pixels, on the boundary, and
                      it stops the click reaching the header or every
                      resize would also re-sort. Double-click puts the
                      column back to the width its definition asks for,
                      which is the way out of having dragged one to a
                      sliver. */}
                  {onWidth && (
                    <span
                      onPointerDown={(e) => onHandleDown(e, col.field)}
                      onPointerMove={onHandleMove}
                      onPointerUp={onHandleUp}
                      onClick={(e) => e.stopPropagation()}
                      onDoubleClick={(e) => {
                        e.stopPropagation()
                        onWidth(col.field, null)
                      }}
                      title="Drag to resize. Double-click to reset."
                      style={{
                        position: 'absolute', top: 0, right: 0, bottom: 0,
                        width: 6, cursor: 'col-resize', zIndex: 2,
                        touchAction: 'none',
                        background: live?.field === col.field
                          ? alpha(neon.pink, 0.8) : 'transparent',
                      }} />
                  )}
                  {sorted && (
                    <span className="sort-mark" style={{ display: 'flex',
                                                         alignItems: 'center',
                                                         marginLeft: 3, flexShrink: 0 }}>
                      {sorted.dir === 'asc'
                        ? <ArrowUpwardIcon sx={arrowSx} />
                        : <ArrowDownwardIcon sx={arrowSx} />}
                      {/* Which column leads, when more than one is sorted. */}
                      {sortIndex.size > 1 && (
                        <span style={{ fontSize: 9, color: neon.pink }}>
                          {sorted.place + 1}
                        </span>
                      )}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        ))}

        <div className="tbody">
          {bodyRows.map((row) => {
            const ticked = row.getIsSelected()
            return (
              <div key={row.id} role="row" className={ticked ? 'ticked' : undefined}>
                {selectable && (
                  <div className="tick">
                    <Checkbox size="small" checked={ticked}
                      onChange={row.getToggleSelectedHandler()} sx={tickSx} />
                  </div>
                )}
                {row.getVisibleCells().map((cell) => {
                  const col = byField.get(cell.column.id)
                  if (!col) return null
                  const rendered = flexRender(cell.column.columnDef.cell, cell.getContext())
                  return (
                    <div key={cell.id} role="cell"
                      style={{ justifyContent: JUSTIFY[col.align ?? 'left'] }}>
                      {col.renderCell
                        ? <div className="custom">{rendered}</div>
                        : <span className="plain">{rendered}</span>}
                    </div>
                  )
                })}
              </div>
            )
          })}
        </div>
      </Box>

      {bodyRows.length === 0 && (
        <Box sx={{ position: 'absolute', inset: 0, top: 36, display: 'grid',
                   placeItems: 'center', pointerEvents: 'none' }}>
          <Box sx={{ pointerEvents: 'auto', textAlign: 'center', px: 3 }}>{empty}</Box>
        </Box>
      )}
    </Box>
  )
}

const tickSx = {
  p: 0.3, color: alpha(neon.muted, 0.7),
  '&.Mui-checked, &.MuiCheckbox-indeterminate': { color: neon.cyan },
} as const

const arrowSx = { fontSize: 13, color: neon.pink } as const

/** The plain "nothing here" message, for a table with no filter on it. */
export function EmptyRows({ note }: { note?: string }) {
  return (
    <Tooltip title={note ?? ''} disableHoverListener={!note}>
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
                        letterSpacing: '0.18em', textTransform: 'uppercase',
                        color: alpha(neon.muted, 0.8) }}>
        no rows
      </Typography>
    </Tooltip>
  )
}
