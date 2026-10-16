/**
 * The table's own vocabulary: columns, sort, filters, density.
 *
 * These types were `GridColDef`, `GridSortModel` and `GridFilterModel` from
 * `@mui/x-data-grid`. The grid is gone — the free tier hardcodes
 * `disableMultipleColumnsFiltering: true`, so a second condition is a paid
 * feature — but the *shapes* are deliberately kept, for three reasons:
 *
 *  - `backend/app/filtering.py` speaks this wire format already, operator
 *    names and all, and it is not worth a migration on both sides to rename
 *    `startsWith` to something of our own.
 *  - The view state in localStorage was written in this shape. Changing it
 *    would silently discard every saved sort and filter in every browser,
 *    which looks to the user like the tool forgetting.
 *  - The eight views each describe their columns in it, so keeping it means
 *    they change by one import line rather than being rewritten.
 *
 * `any` appears in three places and each one is on purpose: a cell value is
 * whatever the column says it is, and typing it as `unknown` would make
 * every view annotate its way back out again. This mirrors what
 * `GridValidRowModel` did.
 */
import type { ReactNode } from 'react'

export type RowId = string | number

/** How a row is keyed, when `id` will not do. */
export type RowIdGetter<R = any> = (row: R) => RowId

export type ColumnType =
  | 'string' | 'number' | 'boolean' | 'singleSelect' | 'date' | 'dateTime'

export type Align = 'left' | 'center' | 'right'

/** Row height. The names are the ones already in saved view state. */
export type Density = 'compact' | 'standard' | 'comfortable'

/** What a column hands its `renderCell`. */
export interface CellParams<R = any> {
  /** What the column shows, after `valueGetter` has had it. */
  value: any
  row: R
  field: string
  id: RowId
}

export interface ValueOption { value: unknown; label: string }

export interface ColumnDef<R = any> {
  field: string
  headerName?: string
  /** A fixed width in pixels. Mutually exclusive with `flex`. */
  width?: number
  /** A share of whatever space is left over, after the fixed columns. */
  flex?: number
  /** The floor for a flexing column, below which the table scrolls. */
  minWidth?: number
  /** Decides the operators offered and how values compare. */
  type?: ColumnType
  /** For `singleSelect`: the values the filter panel offers. */
  valueOptions?: (string | number | ValueOption)[]
  /** Derive the cell's value from the row. Receives the raw field first,
   *  so `(v) => v ?? ''` and `(_v, row) => …` both read naturally. */
  valueGetter?: (value: any, row: R) => any
  renderCell?: (params: CellParams<R>) => ReactNode
  /** Order two cell values. Needed where the generic comparator is wrong:
   *  severity is a string, so alphabetical puts "info" third. */
  sortComparator?: (a: any, b: any) => number
  /** Default true. */
  sortable?: boolean
  /** Default true. A column that is not filterable is also left out of the
   *  quick search, which is how Credentials keeps secrets out of it. */
  filterable?: boolean
  align?: Align
  headerAlign?: Align
}

export interface SortItem {
  field: string
  sort?: 'asc' | 'desc' | null
}
export type SortModel = SortItem[]

export interface FilterItem {
  /** Identity for the panel's rows, so editing one does not remount the
   *  others and steal focus. Not sent to the server. */
  id?: number | string
  field: string
  operator: string
  value?: unknown
}

/** Several conditions, combined. This is the whole point of the migration:
 *  `items` may hold more than one entry and `logicOperator` says how they
 *  join. The free DataGrid refused the second one. */
export interface FilterModel {
  items: FilterItem[]
  logicOperator?: 'and' | 'or'
  /** The search box: whole-row substring matching, independent of `items`. */
  quickFilterValues?: string[]
  quickFilterLogicOperator?: 'and' | 'or'
}

export interface PaginationModel { page: number; pageSize: number }

export const EMPTY_FILTER: FilterModel = { items: [] }

// ------------------------------------------------------------ operators
//
// Three places have to agree on what a condition means, and when they
// drift the symptom is silent:
//
//   - `backend/app/filtering.py` turns conditions into SQL. It raises 400
//     on a field or operator it does not know, deliberately, so a table
//     never looks filtered while showing unfiltered rows.
//   - `lib/tableOps.ts` evaluates the same conditions in the browser, for
//     the seven tables that are not paged in the database.
//   - the panel below offers the operators to pick from.
//
// Offer one the backend rejects and the user gets a 400 and reasonably
// concludes the table is broken. Offer one the backend accepts but
// `tableOps` does not implement and the same filter means two different
// things depending on which table it is on — and `tableOps` keeps the row
// when it does not recognise an operator, so that failure is a condition
// that quietly does nothing.
//
// So these catalogues are the INTERSECTION of what all three support.
// Adding an operator means adding it to `_TEXT_OPS`/`_NUM_OPS` in
// filtering.py and to `matches()` in tableOps.ts in the same change.

export interface Operator {
  value: string
  label: string
  /** False for `isEmpty` / `isNotEmpty`, which are armed on their own. */
  needsValue?: boolean
  /** The value is a list, entered comma-separated. */
  list?: boolean
}

const PRESENCE: Operator[] = [
  { value: 'isEmpty', label: 'is empty' },
  { value: 'isNotEmpty', label: 'is not empty' },
]

export const TEXT_OPERATORS: Operator[] = [
  { value: 'contains', label: 'contains', needsValue: true },
  { value: 'doesNotContain', label: 'does not contain', needsValue: true },
  { value: 'equals', label: 'equals', needsValue: true },
  { value: 'doesNotEqual', label: 'does not equal', needsValue: true },
  { value: 'startsWith', label: 'starts with', needsValue: true },
  { value: 'endsWith', label: 'ends with', needsValue: true },
  ...PRESENCE,
  // Known divergence: `filtering.py` emits a plain SQL `IN`, which is
  // case-SENSITIVE, while `matches()` lowercases both sides. So the same
  // "is any of" means subtly different things on Web (paged in the
  // database) and on the seven tables filtered in the browser. Offered
  // anyway because it is the only way to ask for a set, and the fix
  // belongs in SQL, not in narrowing the UI.
  { value: 'isAnyOf', label: 'is any of', needsValue: true, list: true },
]

export const NUMBER_OPERATORS: Operator[] = [
  { value: '=', label: '=', needsValue: true },
  { value: '!=', label: '≠', needsValue: true },
  { value: '>', label: '>', needsValue: true },
  { value: '>=', label: '≥', needsValue: true },
  { value: '<', label: '<', needsValue: true },
  { value: '<=', label: '≤', needsValue: true },
  ...PRESENCE,
  { value: 'isAnyOf', label: 'is any of', needsValue: true, list: true },
]

/**
 * A boolean column gets `is` and `not` and nothing else, and the
 * narrowness is load-bearing rather than tidy.
 *
 * `filtering.py`'s boolean branch is `col.is_(truthy) if op in
 * ("is","equals","=") else col.isnot(truthy)` — so ANY other operator
 * that reaches it, `contains` included, compiles to the NEGATION and
 * returns HTTP 200 with inverted rows. There is no worse failure for a
 * filter than a confident wrong answer, so the operator never gets
 * offered. (The backend should reject it too; that fix is separate.)
 *
 * `isEmpty` is kept because it is NULL, and on a tri-state column like
 * `alive` — up, down, never probed — that is a genuinely different
 * answer from `false`.
 */
export const BOOLEAN_OPERATORS: Operator[] = [
  { value: 'is', label: 'is', needsValue: true },
  { value: 'not', label: 'is not', needsValue: true },
  ...PRESENCE,
]

export const SELECT_OPERATORS: Operator[] = [
  { value: 'is', label: 'is', needsValue: true },
  { value: 'not', label: 'is not', needsValue: true },
  ...PRESENCE,
  { value: 'isAnyOf', label: 'is any of', needsValue: true, list: true },
]

/** Every operator name the UI will ever emit, for callers that have to
 *  vet a stored condition without knowing the column's type. */
export const ALL_OPERATORS: ReadonlySet<string> = new Set(
  [...TEXT_OPERATORS, ...NUMBER_OPERATORS, ...BOOLEAN_OPERATORS,
   ...SELECT_OPERATORS].map((o) => o.value))

/**
 * The columns a condition may name, and the columns the search box reads.
 *
 * One function because the two must be the same set. `filterable: false`
 * on Credentials' secret column is a security control — "a secret should
 * not be discoverable by typing fragments of it into a filter box" — and
 * it was only half honoured before: the panel left the column out, and
 * then the quick search went over every column anyway and matched it.
 *
 * In server mode the caller has already marked everything outside the
 * endpoint's `filterable` list, so a condition the API would answer with
 * a 400 never gets offered either.
 */
export function filterableColumns(columns: ColumnDef[]): ColumnDef[] {
  return columns.filter((c) => c.filterable !== false)
}

export function operatorsFor(col: ColumnDef | undefined): Operator[] {
  switch (col?.type) {
    case 'number': return NUMBER_OPERATORS
    case 'boolean': return BOOLEAN_OPERATORS
    case 'singleSelect': return SELECT_OPERATORS
    default: return TEXT_OPERATORS
  }
}

export function defaultOperator(col: ColumnDef | undefined): string {
  return operatorsFor(col)[0].value
}

export function findOperator(col: ColumnDef | undefined, op: string): Operator | undefined {
  return operatorsFor(col).find((o) => o.value === op)
}

/** Operators that mean something with no value typed in. */
const NO_VALUE = new Set(['isEmpty', 'isNotEmpty'])

/**
 * Is this condition actually doing anything yet?
 *
 * The panel adds an empty row the moment it is opened, and a half-filled
 * one while someone is still choosing a column. Treating either as live
 * would empty the table underneath them, and — worse — send `value: ""` to
 * the server, which is a real filter that matches almost nothing.
 *
 * One definition, used by the client-side filter, the server-side query
 * builder and the "filters are on" chip alike, so the three cannot
 * disagree about whether a table is filtered.
 */
export function isArmed(item: FilterItem | undefined): boolean {
  if (!item?.field) return false
  if (NO_VALUE.has(String(item.operator))) return true
  const v = item.value
  if (Array.isArray(v)) return v.length > 0
  return v !== undefined && v !== null && v !== ''
}

export function armedItems(model: FilterModel | undefined): FilterItem[] {
  return (model?.items ?? []).filter(isArmed)
}

/** The search terms that are actually searching for something. */
export function quickTerms(model: FilterModel | undefined): string[] {
  return (model?.quickFilterValues ?? []).filter(Boolean).map(String)
}

/** Is anything about this model hiding rows? */
export function filtersActive(model: FilterModel | undefined): boolean {
  return armedItems(model).length > 0 || quickTerms(model).length > 0
}

/**
 * What clicking a column header does: ascending, then descending, then
 * off again. Shift-clicking adds the column to the order rather than
 * replacing it, which is the only way to express "worst first, then by
 * host" — and the reason sorting is a list and not a single field.
 *
 * Returning to *no* sort rather than back to ascending matters on the
 * server-paged tables: `useServerTable` reads an empty model as "use the
 * table's default", and an unordered paged query can repeat and skip rows
 * between pages.
 */
export function nextSort(
  model: SortModel, field: string, additive = false,
): SortModel {
  const current = model.find((s) => s.field === field)
  const dir: 'asc' | 'desc' | null =
    !current?.sort ? 'asc' : current.sort === 'asc' ? 'desc' : null
  if (!additive) return dir ? [{ field, sort: dir }] : []
  const rest = model.filter((s) => s.field !== field)
  return dir ? [...rest, { field, sort: dir }] : rest
}

/** One condition in words, for a chip or a tooltip. */
export function describeItem(item: FilterItem, col?: ColumnDef): string {
  const name = col?.headerName || item.field
  const op = findOperator(col, String(item.operator))
  const label = op?.label ?? String(item.operator)
  if (!op?.needsValue) return `${name} ${label}`
  const v = Array.isArray(item.value)
    ? item.value.map(String).join(', ')
    : String(item.value ?? '')
  return `${name} ${label} ${v}`
}
