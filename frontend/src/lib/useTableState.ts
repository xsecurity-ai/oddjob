import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  EMPTY_FILTER, armedItems, filtersActive, findOperator, quickTerms,
  type ColumnDef, type Density, type FilterModel, type PaginationModel,
  type SortModel,
} from './columns'

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
  sort: SortModel
  filter: FilterModel
  columns: Record<string, boolean>
  pagination: PaginationModel
  density: Density
}

// Still v1 after the move off MUI X. The stored shape is unchanged —
// `lib/columns.ts` keeps the same field names deliberately — so bumping
// it would throw away every saved sort and filter in every browser to no
// purpose, which reads to the user as the tool forgetting.
const VERSION = 1
const KEY = (id: string) => `oddjob.table.v${VERSION}.${id}`

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

/** Drop anything the table can no longer honour.
 *
 *  Two kinds of stale. A condition on a column that has since been
 *  removed matches nothing, which looks exactly like a table with no data
 *  in it. A condition whose *operator* the column no longer offers — a
 *  `contains` left over on a field that is now a number — is worse: in
 *  client mode `matches()` does not recognise it and keeps every row, so
 *  the chip says filtered and nothing is filtered; in server mode
 *  `filtering.py` answers 400 and the table looks broken.
 *
 *  Pass `columns` to get the second check. Without them only fields are
 *  pruned, which is what the storage layer could do before it knew what
 *  operators each column allowed. */
export function prune(
  state: Partial<TableState>, fields: Set<string>, columns?: ColumnDef[],
): Partial<TableState> {
  const out: Partial<TableState> = {}
  const byField = new Map((columns ?? []).map((c) => [c.field, c]))
  const keep = (i: { field?: unknown; operator?: unknown }) => {
    const f = String(i.field)
    if (!fields.has(f)) return false
    if (!columns) return true
    return !!findOperator(byField.get(f), String(i.operator))
  }
  if (state.sort) out.sort = state.sort.filter((s) => fields.has(s.field))
  if (state.filter) {
    out.filter = {
      ...state.filter,
      items: (state.filter.items ?? []).filter(keep),
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
  sort: SortModel, filter: FilterModel,
  touched: Record<string, boolean>, defaultSort: SortModel,
): { dirty: boolean; summary: string; hiding: boolean } {
  // Shared with the filter itself, so "the chip says filtered" and "rows
  // are being dropped" cannot come apart. The old count tested the value
  // directly and so missed `isEmpty` and `isNotEmpty`, which hide rows
  // while having nothing typed in them — exactly the case the chip is for.
  const activeFilters = armedItems(filter).length
  const quick = quickTerms(filter)
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
    // Hiding rows is the only state worth warning about. A remembered
    // sort or page size is helpful and invisible; a remembered filter is
    // the one that makes someone think their data is missing.
    hiding: filtersActive(filter),
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
  sort: SortModel
  setSort: (m: SortModel) => void
  filter: FilterModel
  setFilter: (m: FilterModel) => void
  columns: Record<string, boolean>
  setColumns: (m: Record<string, boolean>) => void
  pagination: PaginationModel
  setPagination: (m: PaginationModel) => void
  density: Density
  setDensity: (d: Density) => void
  /** Is anything restored or changed from the default? */
  dirty: boolean
  /** Is anything actively hiding rows, as opposed to merely reordering
   *  them? What the toolbar's chip turns yellow for. */
  hiding: boolean
  /** A short description of what is active, for the toolbar. */
  summary: string
  reset: () => void
}

export function useTableState(
  id: string,
  columnDefs: ColumnDef[],
  defaults: {
    sort?: SortModel
    /** Visibility the VIEW wants, e.g. hiding Project when one is chosen. */
    columns?: Record<string, boolean>
    pageSize?: number
  } = {},
): UseTableState {
  const fields = useMemo(
    () => new Set(columnDefs.map((c) => c.field)), [columnDefs])

  // Read once per table id. Re-reading on every column change would stomp
  // the user's in-session edits the moment a view adds a column — so
  // `fields` is read here and deliberately left out of the dependencies.
  //
  // The suppression has to be the line immediately above the call. It was
  // written underneath for a long time, where ESLint applied it to the
  // blank line after it and it silenced nothing. Nobody noticed because
  // there was no linter in the repository to notice with.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const initial = useMemo(() => prune(load(id) ?? {}, fields, columnDefs), [id])

  const [sort, setSortState] = useState<SortModel>(
    initial.sort ?? defaults.sort ?? [])
  const [filter, setFilterState] = useState<FilterModel>(
    initial.filter ?? EMPTY_FILTER)
  const [pagination, setPaginationState] = useState<PaginationModel>(
    initial.pagination ?? { page: 0, pageSize: defaults.pageSize ?? 50 })
  const [density, setDensityState] = useState<Density>(
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
    dirty: described.dirty,
    hiding: described.hiding,
    summary: described.summary,
    reset,
  }
}
