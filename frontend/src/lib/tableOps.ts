/** Filtering and sorting rows ourselves, so page size is not capped at 100.
 *
 * The MIT DataGrid refuses a page size above 100:
 *
 *     MAX_PAGE_SIZE = 100
 *     'MUI X: `pageSize` cannot exceed 100 in the MIT version of the
 *      DataGrid. You need to upgrade to DataGridPro...'
 *
 * and it throws from `getDerivedPaginationModel`, so it happens whatever
 * the pagination mode is. Offering 250 and 500 in `pageSizeOptions` was
 * therefore a promise the grid could not keep — picking one threw.
 *
 * The one page size it accepts above 100 is `-1`, its "all results"
 * sentinel. So the grid is given `-1` and exactly one page of rows, and
 * the paging happens here. That in turn means the grid must not sort or
 * filter either: it only ever sees one page, and sorting a page is not
 * sorting the table. Both are done here instead, over the whole set,
 * before the slice.
 *
 * The operators implemented are the ones the grid's own filter panel
 * offers for string, number, boolean and single-select columns. An
 * operator that is not recognised keeps the row rather than dropping
 * it: a filter we failed to understand must not silently hide findings.
 */
import type { GridColDef, GridFilterModel, GridSortModel } from '@mui/x-data-grid'

type Row = Record<string, unknown>

/** The value a column shows for a row, honouring `valueGetter`. */
export function cellValue(row: Row, col: GridColDef | undefined, field: string): unknown {
  const raw = row[field]
  const get = col?.valueGetter as
    | ((value: unknown, row: Row, column: GridColDef, apiRef: unknown) => unknown)
    | undefined
  if (typeof get !== 'function') return raw
  try {
    return get(raw, row, col as GridColDef, undefined)
  } catch {
    // A valueGetter that needs the grid's apiRef cannot run out here.
    // Falling back to the raw field is better than losing the column.
    return raw
  }
}

const str = (v: unknown) => (v == null ? '' : String(v))
const lower = (v: unknown) => str(v).toLowerCase()
const empty = (v: unknown) => v == null || v === ''
const num = (v: unknown) => (typeof v === 'number' ? v : Number(str(v)))

function matches(value: unknown, op: string, target: unknown): boolean {
  switch (op) {
    case 'contains': return lower(value).includes(lower(target))
    case 'doesNotContain': return !lower(value).includes(lower(target))
    case 'equals': return lower(value) === lower(target)
    case 'doesNotEqual': return lower(value) !== lower(target)
    case 'startsWith': return lower(value).startsWith(lower(target))
    case 'endsWith': return lower(value).endsWith(lower(target))
    case 'isEmpty': return empty(value)
    case 'isNotEmpty': return !empty(value)
    case 'isAnyOf':
      return Array.isArray(target)
        ? target.length === 0 || target.some((t) => lower(value) === lower(t))
        : true
    case 'is':
      if (typeof value === 'boolean' || target === 'true' || target === 'false') {
        return empty(target) ? true : Boolean(value) === (str(target) === 'true')
      }
      return lower(value) === lower(target)
    case 'not': return lower(value) !== lower(target)
    case 'after': return str(value) > str(target)
    case 'onOrAfter': return str(value) >= str(target)
    case 'before': return str(value) < str(target)
    case 'onOrBefore': return str(value) <= str(target)
    case '=': return num(value) === num(target)
    case '!=': return num(value) !== num(target)
    case '>': return num(value) > num(target)
    case '>=': return num(value) >= num(target)
    case '<': return num(value) < num(target)
    case '<=': return num(value) <= num(target)
    default:
      // Unknown operator: keep the row. Hiding data because we did not
      // recognise a filter is the one outcome worth ruling out.
      return true
  }
}

/** Whether a filter item is armed. An empty value means "not set yet". */
function armed(op: string, value: unknown): boolean {
  if (op === 'isEmpty' || op === 'isNotEmpty') return true
  if (Array.isArray(value)) return value.length > 0
  return !empty(value)
}

export function filterRows<T extends Row>(
  rows: readonly T[], model: GridFilterModel | undefined, columns: GridColDef[],
): readonly T[] {
  if (!model) return rows
  const byField = new Map(columns.map((c) => [c.field, c]))
  const items = (model.items ?? []).filter((i) => armed(String(i.operator), i.value))
  const quick = (model.quickFilterValues ?? []).filter(Boolean).map((q) => lower(q))

  if (!items.length && !quick.length) return rows

  const linkOr = model.logicOperator === 'or'
  // The grid's quick filter defaults to requiring every term, across
  // any column. Mirroring that matters: "acme 500" should mean both.
  const quickAll = (model.quickFilterLogicOperator ?? 'and') !== 'or'

  return rows.filter((row) => {
    if (items.length) {
      const results = items.map((i) => {
        const f = String(i.field)
        return matches(cellValue(row, byField.get(f), f), String(i.operator), i.value)
      })
      const pass = linkOr ? results.some(Boolean) : results.every(Boolean)
      if (!pass) return false
    }
    if (quick.length) {
      const haystack = columns
        .map((c) => lower(cellValue(row, c, c.field)))
        .join('\u0000')
      const hits = quick.map((q) => haystack.includes(q))
      if (!(quickAll ? hits.every(Boolean) : hits.some(Boolean))) return false
    }
    return true
  })
}

/** Compare two cell values the way the grid would. */
function compare(a: unknown, b: unknown): number {
  if (a == null && b == null) return 0
  if (a == null) return -1
  if (b == null) return 1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b)
  const na = Number(a), nb = Number(b)
  if (!Number.isNaN(na) && !Number.isNaN(nb) && str(a).trim() !== '' && str(b).trim() !== '') {
    return na - nb
  }
  // localeCompare with numeric so host9 sorts before host10.
  return str(a).localeCompare(str(b), undefined, { numeric: true, sensitivity: 'base' })
}

export function sortRows<T extends Row>(
  rows: readonly T[], model: GridSortModel | undefined, columns: GridColDef[],
): readonly T[] {
  const active = (model ?? []).filter((s) => s.sort)
  if (!active.length) return rows
  const byField = new Map(columns.map((c) => [c.field, c]))
  // Copy: Array.prototype.sort mutates, and `rows` belongs to the query
  // cache — sorting it in place would reorder the cached response.
  return [...rows].sort((x, y) => {
    for (const s of active) {
      const col = byField.get(s.field)
      const a = cellValue(x, col, s.field)
      const b = cellValue(y, col, s.field)
      // A column may define its own order, and some depend on it being
      // honoured: severity is a string, so the generic comparator sorts
      // it critical, high, info, low, medium — putting "info" third,
      // which is actively misleading on a findings table.
      let c: number
      const cmp = col?.sortComparator as
        | ((a: unknown, b: unknown) => number) | undefined
      if (typeof cmp === 'function') {
        try { c = cmp(a, b) } catch { c = compare(a, b) }
      } else {
        c = compare(a, b)
      }
      if (c !== 0) return s.sort === 'desc' ? -c : c
    }
    return 0
  })
}

/** One page, clamped so a shrinking result set cannot strand the view
 *  on a page that no longer exists. */
export function pageOf<T>(rows: readonly T[], page: number, size: number): {
  rows: readonly T[]; page: number; pages: number
} {
  if (size <= 0) return { rows, page: 0, pages: 1 }
  const pages = Math.max(1, Math.ceil(rows.length / size))
  const p = Math.min(Math.max(0, page), pages - 1)
  return { rows: rows.slice(p * size, p * size + size), page: p, pages }
}
