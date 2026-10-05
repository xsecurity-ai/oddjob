import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type {
  GridColDef, GridDensity, GridFilterModel, GridPaginationModel, GridSortModel,
} from '@mui/x-data-grid'

/**
 * Remembers how each table was left: sort, filters, the search box, which
 * columns are showing, page size and density.
 *
 * Per table and per browser. A pentester lives in these grids for days and
 * re-sorting Vulns by severity every time the page reloads is the kind of
 * small friction that makes a tool feel hostile.
 *
 * Two things this has to get right, both of which are about not stranding
 * the user:
 *
 * **Stale state must never hide data silently.** A filter restored from
 * last week, on a column that no longer exists or a value nothing matches,
 * produces an empty grid with no explanation — and the user's conclusion
 * is "the import failed", not "there is a filter on". So restored state is
 * pruned against the columns that actually exist now, and the caller is
 * told whether anything non-default is active so it can say so and offer a
 * reset.
 *
 * **Storage is best-effort.** localStorage throws in a private window and
 * comes back empty after a data clear, so every read and write is wrapped
 * and the table works normally without it.
 */

export interface TableState {
  sort: GridSortModel
  filter: GridFilterModel
  columns: Record<string, boolean>
  pagination: GridPaginationModel
  density: GridDensity
}

const VERSION = 1
const KEY = (id: string) => `oddjob.table.v${VERSION}.${id}`

const EMPTY_FILTER: GridFilterModel = { items: [] }

export function load(id: string): Partial<TableState> | null {
  try {
    const raw = window.localStorage.getItem(KEY(id))
    return raw ? (JSON.parse(raw) as Partial<TableState>) : null
  } catch {
    return null
  }
}

function save(id: string, state: Partial<TableState>): void {
  try {
    window.localStorage.setItem(KEY(id), JSON.stringify(state))
  } catch {
    /* private window or blocked storage — the table still works */
  }
}

function clear(id: string): void {
  try {
    window.localStorage.removeItem(KEY(id))
  } catch { /* nothing to do */ }
}

/** Drop anything referring to a column this table no longer has.
 *
 *  Views gain and lose columns between releases, and a filter item whose
 *  `field` is gone matches nothing — which looks exactly like a table with
 *  no data in it. */
export function prune(state: Partial<TableState>, fields: Set<string>): Partial<TableState> {
  const out: Partial<TableState> = {}
  if (state.sort) out.sort = state.sort.filter((s) => fields.has(s.field))
  if (state.filter) {
    out.filter = {
      ...state.filter,
      items: (state.filter.items ?? []).filter((i) => fields.has(String(i.field))),
    }
  }
  if (state.columns) {
    out.columns = Object.fromEntries(
      Object.entries(state.columns).filter(([f]) => fields.has(f)))
  }
  if (state.pagination) out.pagination = state.pagination
  if (state.density) out.density = state.density
  return out
}

/** What the toolbar chip says, and whether to show it at all. Pulled out
 *  of the hook so it can be tested without rendering anything. */
export function describe(
  sort: GridSortModel, filter: GridFilterModel,
  touched: Record<string, boolean>, defaultSort: GridSortModel,
): { dirty: boolean; summary: string; hiding: boolean } {
  const activeFilters = (filter.items ?? []).filter(
    (i) => i.value !== undefined && i.value !== '' && i.value !== null).length
  const quick = (filter.quickFilterValues ?? []).filter(Boolean)
  const hidden = Object.values(touched).filter((v) => v === false).length
  const sortChanged = JSON.stringify(sort) !== JSON.stringify(defaultSort ?? [])

  const parts: string[] = []
  if (quick.length) parts.push(`search “${quick.join(' ')}”`)
  if (activeFilters) parts.push(`${activeFilters} filter${activeFilters > 1 ? 's' : ''}`)
  if (hidden) parts.push(`${hidden} column${hidden > 1 ? 's' : ''} hidden`)
  if (sortChanged && sort.length) {
    parts.push(`sorted by ${sort[0].field} ${sort[0].sort ?? ''}`.trim())
  }
  return {
    dirty: activeFilters > 0 || quick.length > 0 || hidden > 0 || sortChanged,
    summary: parts.join(' · '),
    hiding: activeFilters > 0 || quick.length > 0,
  }
}

/** Only persist visibility that differs from what the view asked for, so a
 *  view-driven default (hide Project when one is selected) is never frozen
 *  into storage as if the user had chosen it. */
export function visibilityDiff(
  model: Record<string, boolean>, base: Record<string, boolean>,
): Record<string, boolean> {
  const diff: Record<string, boolean> = {}
  for (const [f, visible] of Object.entries(model)) {
    if ((base[f] ?? true) !== visible) diff[f] = visible
  }
  return diff
}

export interface UseTableState {
  sort: GridSortModel
  setSort: (m: GridSortModel) => void
  filter: GridFilterModel
  setFilter: (m: GridFilterModel) => void
  columns: Record<string, boolean>
  setColumns: (m: Record<string, boolean>) => void
  pagination: GridPaginationModel
  setPagination: (m: GridPaginationModel) => void
  density: GridDensity
  setDensity: (d: GridDensity) => void
  /** Is anything restored or changed from the default? */
  dirty: boolean
  /** A short description of what is active, for the toolbar. */
  summary: string
  reset: () => void
}

export function useTableState(
  id: string,
  columnDefs: GridColDef[],
  defaults: {
    sort?: GridSortModel
    /** Visibility the VIEW wants, e.g. hiding Project when one is chosen. */
    columns?: Record<string, boolean>
    pageSize?: number
  } = {},
): UseTableState {
  const fields = useMemo(
    () => new Set(columnDefs.map((c) => c.field)), [columnDefs])

  // Read once per table id. Re-reading on every column change would stomp
  // the user's in-session edits the moment a view adds a column.
  const initial = useMemo(() => prune(load(id) ?? {}, fields), [id])
  // eslint-disable-next-line react-hooks/exhaustive-deps -- see above

  const [sort, setSortState] = useState<GridSortModel>(
    initial.sort ?? defaults.sort ?? [])
  const [filter, setFilterState] = useState<GridFilterModel>(
    initial.filter ?? EMPTY_FILTER)
  const [pagination, setPaginationState] = useState<GridPaginationModel>(
    initial.pagination ?? { page: 0, pageSize: defaults.pageSize ?? 50 })
  const [density, setDensityState] = useState<GridDensity>(
    initial.density ?? 'compact')

  // Column visibility is the one that needs merging rather than replacing.
  // The view hides Project when a single project is selected; that is a
  // default, not a user decision, so it must not be frozen into storage —
  // but a column the user explicitly toggled has to win over it.
  const [touched, setTouched] = useState<Record<string, boolean>>(
    initial.columns ?? {})
  const columns = useMemo(
    () => ({ ...(defaults.columns ?? {}), ...touched }),
    [defaults.columns, touched])

  const first = useRef(true)
  useEffect(() => {
    // Skip the write caused by mounting, so merely visiting a view does
    // not create a storage entry that then looks like saved state.
    if (first.current) { first.current = false; return }
    save(id, { sort, filter, columns: touched, pagination, density })
  }, [id, sort, filter, touched, pagination, density])

  const setColumns = useCallback((m: Record<string, boolean>) => {
    // Store only what differs from what the view asked for.
    setTouched(visibilityDiff(m, defaults.columns ?? {}))
  }, [defaults.columns])

  const reset = useCallback(() => {
    clear(id)
    setSortState(defaults.sort ?? [])
    setFilterState(EMPTY_FILTER)
    setTouched({})
    setPaginationState({ page: 0, pageSize: defaults.pageSize ?? 50 })
    setDensityState('compact')
  }, [id, defaults.sort, defaults.pageSize])

  const described = describe(sort, filter, touched, defaults.sort ?? [])

  return {
    sort, setSort: setSortState,
    filter, setFilter: setFilterState,
    columns, setColumns,
    pagination, setPagination: setPaginationState,
    density, setDensity: setDensityState,
    // Hiding rows is the only state worth warning about. A remembered sort
    // or page size is helpful and invisible; a remembered filter is the one
    // that makes someone think their data is missing.
    dirty: described.dirty,
    summary: described.summary,
    reset,
  }
}

/** True when state is actively hiding rows, as opposed to merely reordering. */
export function hidesRows(s: UseTableState): boolean {
  return describe(s.sort, s.filter, {}, s.sort).hiding
}
