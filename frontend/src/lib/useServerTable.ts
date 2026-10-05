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
import type { GridFilterModel, GridSortModel } from '@mui/x-data-grid'

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
  setSortModel: (m: GridSortModel) => void
  setTyped: (s: string) => void
  sortModel: GridSortModel
  filterModel: GridFilterModel
  setFilterModel: (m: GridFilterModel) => void
  /** Columns the API will accept a filter on. Anything else is marked
   *  unfilterable in the grid, so the panel cannot offer a filter that
   *  comes back as a 400. */
  filterable?: string[]
}

const KEY = (id: string) => `oddjob.server-table.${id}`

function load(id: string): Partial<ServerQuery> {
  try {
    const raw = window.localStorage.getItem(KEY(id))
    return raw ? JSON.parse(raw) : {}
  } catch {
    // Private windows and blocked site data both throw here. A table
    // that forgets its sort is fine; one that fails to render is not.
    return {}
  }
}

function save(id: string, q: ServerQuery) {
  try {
    const { pageSize, sort, order } = q
    window.localStorage.setItem(KEY(id), JSON.stringify({ pageSize, sort, order }))
  } catch { /* best effort */ }
}

//: Offered in the footer. 250 and 500 are the point of the exercise —
//: the MIT DataGrid refuses any page size above 100, so the grid is not
//: the thing paginating any more.
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
  const [filterModel, setFilterModelRaw] = useState<GridFilterModel>({ items: [] })
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

  // Only armed rows travel. The grid adds an empty row the moment the
  // panel opens, and sending that would filter on "" and empty the
  // table while the user is still choosing a column.
  const filters = useMemo(() => {
    const armed = (filterModel.items ?? []).filter((i) => {
      const op = String(i.operator ?? '')
      if (op === 'isEmpty' || op === 'isNotEmpty') return !!i.field
      if (Array.isArray(i.value)) return i.value.length > 0
      return !!i.field && i.value !== undefined && i.value !== null && i.value !== ''
    })
    if (!armed.length) return ''
    return JSON.stringify(armed.map((i) => ({
      field: i.field, op: i.operator, value: i.value,
    })))
  }, [filterModel])

  const logic = (filterModel.logicOperator === 'or' ? 'or' : 'and') as 'and' | 'or'

  const query = useMemo<ServerQuery>(
    () => ({ page, pageSize, sort, order, q, filters, logic }),
    [page, pageSize, sort, order, q, filters, logic])

  useEffect(() => { save(id, query) }, [id, query])

  const setPageSize = useCallback((n: number) => {
    setPageSizeRaw(n)
    setPageRaw(0)        // page 3 of 25 is not page 3 of 500
  }, [])

  const setSortModel = useCallback((m: GridSortModel) => {
    const s = m[0]
    // The API sorts on one column. Clearing the sort returns to the
    // table's default rather than to no order at all, because an
    // unordered paged query can repeat and skip rows between pages.
    setSort(s?.field ?? defaults.sort)
    setOrder((s?.sort as 'asc' | 'desc') ?? defaults.order ?? 'asc')
    setPageRaw(0)
  }, [defaults.sort, defaults.order])

  const sortModel = useMemo<GridSortModel>(
    () => [{ field: sort, sort: order }], [sort, order])

  const setFilterModel = useCallback((m: GridFilterModel) => {
    setFilterModelRaw(m)
    setPageRaw(0)      // a different result set has a different page 7
  }, [])

  return {
    filterable: defaults.filterable,
    query, typed, total, sortModel, filterModel,
    setTotal, setPage: setPageRaw, setPageSize, setSortModel, setTyped,
    setFilterModel,
  }
}
