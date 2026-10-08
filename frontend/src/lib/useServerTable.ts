/** Paging, sorting and searching that happen in the database.
 *
 * The Web table holds 211,012 rows for one engagement. Fetching them
 * and working on them in the browser does not scale, and it was already
 * failing quietly: the view asked for `limit: 5000`, so it showed the
 * first 5,000 and the search box searched only those. A URL that was
 * not in that window simply did not exist as far as the UI was
 * concerned — on a security tool, that is a missed finding, not a
 * cosmetic limit.
 *
 * So the query lives here and the server answers it. `page`, `pageSize`,
 * `sort`, `order` and `q` go out as parameters; `total` comes back and
 * drives the footer. The search covers the whole table because it is a
 * SQL `ILIKE`, not a filter over whatever happened to be loaded.
 *
 * The state is persisted per table, like the client-side view state, so
 * a reload does not throw away a sort. Page is deliberately NOT
 * persisted: coming back to a table on page 47 with no memory of why is
 * disorienting, and the row it was showing has usually moved.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ALL_OPERATORS, EMPTY_FILTER, isArmed,
  type FilterModel, type SortModel,
} from './columns'

export interface ServerQuery {
  page: number
  pageSize: number
  sort: string
  order: 'asc' | 'desc'
  /** The search box. Debounced before it reaches this. */
  q: string
  /** Chained column filters, as the API's JSON, or '' for none. */
  filters: string
  /** How they combine. */
  logic: 'and' | 'or'
}

export interface ServerTable {
  /** What the view should send to the API. */
  query: ServerQuery
  /** What the search box shows — updates immediately, unlike `query.q`. */
  typed: string
  total: number
  setTotal: (n: number) => void
  setPage: (n: number) => void
  setPageSize: (n: number) => void
  setSortModel: (m: SortModel) => void
  setTyped: (s: string) => void
  sortModel: SortModel
  filterModel: FilterModel
  setFilterModel: (m: FilterModel) => void
  /** Columns the API will accept a filter on. Anything else is marked
   *  unfilterable in the table, so the panel cannot offer a filter that
   *  comes back as a 400. */
  filterable?: string[]
  /** Back to how the table ships, and forget what was stored. The
   *  toolbar's "clear" has to reach this: in server mode the conditions
   *  and the search live here, not in `useTableState`, and clearing only
   *  the latter left a table that said it was unfiltered and was not. */
  reset: () => void
  /** Is anything here hiding rows? Asked by the toolbar, which otherwise
   *  has no way to know — the client-side view state is empty in this
   *  mode and would report a filtered table as clean. */
  dirty: boolean
}

const KEY = (id: string) => `oddjob.server-table.${id}`

interface Stored {
  pageSize?: number
  sort?: string
  order?: 'asc' | 'desc'
  /** Chained conditions, as the model rather than the serialised query,
   *  so the panel can reopen on them. Added when multi-condition
   *  filtering arrived: a Web filter used to be thrown away on reload
   *  while the other seven tables remembered theirs. */
  filterModel?: FilterModel
}

function load(id: string): Stored {
  try {
    const raw = window.localStorage.getItem(KEY(id))
    return raw ? JSON.parse(raw) as Stored : {}
  } catch {
    // Private windows and blocked site data both throw here. A table
    // that forgets its sort is fine; one that fails to render is not.
    return {}
  }
}

/** Restore only conditions this endpoint will still accept.
 *
 *  `filterable` is the endpoint's contract and it moves between releases.
 *  A stored condition on a field the API has dropped comes back as an
 *  HTTP 400 on first load, which reads as a broken page rather than as
 *  stale state — so it is discarded here instead. */
function restoreFilters(stored: FilterModel | undefined,
                        filterable: string[] | undefined): FilterModel {
  const items = (stored?.items ?? []).filter((i) =>
    isArmed(i)
    && ALL_OPERATORS.has(String(i.operator))
    && (!filterable || filterable.includes(String(i.field))))
  if (!items.length) return EMPTY_FILTER
  return { items, logicOperator: stored?.logicOperator === 'or' ? 'or' : 'and' }
}

function save(id: string, q: ServerQuery, filterModel: FilterModel) {
  try {
    const { pageSize, sort, order } = q
    const items = (filterModel.items ?? []).filter(isArmed)
    window.localStorage.setItem(KEY(id), JSON.stringify({
      pageSize, sort, order,
      filterModel: { items, logicOperator: filterModel.logicOperator ?? 'and' },
    } satisfies Stored))
  } catch { /* best effort */ }
}

function clear(id: string) {
  try { window.localStorage.removeItem(KEY(id)) } catch { /* nothing to do */ }
}

//: Offered in the footer, in both modes. The table renders one page and
//: `TableFooter` decides which, so nothing here is capped by the renderer.
export const PAGE_SIZES = [25, 50, 100, 250, 500, 1000]

/** Milliseconds to wait before a keystroke becomes a query. */
const DEBOUNCE = 300

export function useServerTable(
  id: string,
  defaults: { sort: string; order?: 'asc' | 'desc'; pageSize?: number
              filterable?: string[] },
): ServerTable {
  const saved = useMemo(() => load(id), [id])
  const [page, setPageRaw] = useState(0)
  const [pageSize, setPageSizeRaw] = useState(
    saved.pageSize && PAGE_SIZES.includes(saved.pageSize)
      ? saved.pageSize : (defaults.pageSize ?? 100))
  const [sort, setSort] = useState(saved.sort ?? defaults.sort)
  const [order, setOrder] = useState<'asc' | 'desc'>(
    saved.order ?? defaults.order ?? 'asc')
  const [typed, setTyped] = useState('')
  const [filterModel, setFilterModelRaw] = useState<FilterModel>(
    () => restoreFilters(saved.filterModel, defaults.filterable))
  const [q, setQ] = useState('')
  const [total, setTotal] = useState(0)

  // Debounce the search box. Without this every keystroke is a query
  // against a 211,000-row table.
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => {
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => {
      setQ(typed.trim())
      setPageRaw(0)      // a new search starts at the beginning
    }, DEBOUNCE)
    return () => window.clearTimeout(timer.current)
  }, [typed])

  // Only armed conditions travel. The panel adds an empty row the moment
  // it opens, and sending that would filter on "" and empty the table
  // while the user is still choosing a column.
  //
  // The shape below is the wire contract with `backend/app/filtering.py`
  // and is not ours to change casually: it reads `field`, `op` and
  // `value`, and raises 400 on a field or operator it does not know
  // rather than returning unfiltered rows. Any number of conditions may
  // go, combined by `logic`.
  const filters = useMemo(() => {
    const armed = (filterModel.items ?? []).filter(isArmed)
    if (!armed.length) return ''
    return JSON.stringify(armed.map((i) => ({
      field: i.field, op: i.operator, value: i.value,
    })))
  }, [filterModel])

  const logic = (filterModel.logicOperator === 'or' ? 'or' : 'and') as 'and' | 'or'

  const query = useMemo<ServerQuery>(
    () => ({ page, pageSize, sort, order, q, filters, logic }),
    [page, pageSize, sort, order, q, filters, logic])

  useEffect(() => { save(id, query, filterModel) }, [id, query, filterModel])

  const setPageSize = useCallback((n: number) => {
    setPageSizeRaw(n)
    setPageRaw(0)        // page 3 of 25 is not page 3 of 500
  }, [])

  const setSortModel = useCallback((m: SortModel) => {
    const s = m[0]
    // The API sorts on one column. Clearing the sort returns to the
    // table's default rather than to no order at all, because an
    // unordered paged query can repeat and skip rows between pages.
    setSort(s?.field ?? defaults.sort)
    setOrder((s?.sort as 'asc' | 'desc') ?? defaults.order ?? 'asc')
    setPageRaw(0)
  }, [defaults.sort, defaults.order])

  const sortModel = useMemo<SortModel>(
    () => [{ field: sort, sort: order }], [sort, order])

  const setFilterModel = useCallback((m: FilterModel) => {
    setFilterModelRaw(m)
    setPageRaw(0)      // a different result set has a different page 7
  }, [])

  const reset = useCallback(() => {
    clear(id)
    setSort(defaults.sort)
    setOrder(defaults.order ?? 'asc')
    setFilterModelRaw(EMPTY_FILTER)
    setTyped('')
    setQ('')
    setPageRaw(0)
  }, [id, defaults.sort, defaults.order])

  return {
    filterable: defaults.filterable,
    query, typed, total, sortModel, filterModel,
    setTotal, setPage: setPageRaw, setPageSize, setSortModel, setTyped,
    setFilterModel, reset,
    // `q` rather than `typed`: the debounce means the box can hold a
    // word that is not filtering anything yet, and claiming otherwise
    // would make the chip flicker on every keystroke.
    dirty: filters !== '' || q !== '',
  }
}
