/**
 * The table, actually rendered.
 *
 *     npm run test:logic
 *
 * `logic.test.ts` next door covers pure functions, and `tsc` covers
 * types, but neither of them would notice if the table rendered no rows
 * at all — which is the shape of every mistake available while moving a
 * grid from one library to another. So this one renders to a string and
 * reads the markup back.
 *
 * It is deliberately a small number of load-bearing questions:
 *
 *   - do rows appear, and only the columns that are showing
 *   - does a view's own `renderCell` reach the page
 *   - does a custom row key keep two rows that share an `id` (the Web
 *     table's parent row vanished exactly this way)
 *   - are the armed conditions chipped where they cannot be missed, and
 *     is a half-typed one correctly left alone
 *
 * react-dom/server, not a DOM: there is no jsdom in this project and
 * adding one to answer these would cost more than it returns. Nothing
 * here clicks anything — the pure half of that lives in logic.test.ts.
 */
import { renderToString } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TableGrid, EmptyRows } from '../src/components/TableGrid'
import { TableToolbar } from '../src/components/TableToolbar'
import { AgentPanel } from '../src/components/AgentPanel'
import { AuthProvider } from '../src/lib/auth'
import type { AgentSession, AgentSessionBrief } from '../src/lib/api'
import type { ColumnDef, FilterModel } from '../src/lib/columns'

let pass = 0, fail = 0
const check = (label: string, cond: boolean, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${label} ${extra}`) }
  else { fail++; console.log(`  FAIL  ${label} ${extra}`) }
}
// `<div role="row"`, not `role="row"`: the row and cell rules live in one
// stylesheet on the container, so the bare attribute selector also
// appears in the CSS that Emotion emits alongside the markup.
const rowCount = (html: string) => (html.match(/<div role="row"/g) ?? []).length

const rows = [
  { id: 1, host: 'a.acme.example', port: 443, status_code: 500, sev: 'low', secret: 'hunter2' },
  { id: 2, host: 'b.acme.example', port: 80, status_code: 404, sev: 'critical', secret: 'hunter2' },
  { id: 3, host: 'c.corp.com', port: 8080, status_code: 503, sev: 'high', secret: 'hunter2' },
]

const columns: ColumnDef[] = [
  { field: 'host', headerName: 'Host', flex: 2, minWidth: 180 },
  { field: 'port', headerName: 'Port', width: 90, type: 'number' },
  { field: 'status_code', headerName: 'Status', width: 90, type: 'number' },
  {
    field: 'sev', headerName: 'Severity', width: 110, type: 'singleSelect',
    valueOptions: ['critical', 'high', 'low'],
    renderCell: (p) => <span>sev:{String(p.value)}</span>,
  },
  // Credentials marks its secret column this way on purpose.
  { field: 'secret', headerName: 'Secret', width: 120, filterable: false, sortable: false },
]

console.log('== the table renders ==')
const html = renderToString(
  <TableGrid rows={rows} columns={columns} columnVisibility={{ port: false }}
    sort={[{ field: 'host', sort: 'asc' }]} onSort={() => {}} density="compact"
    selectable rowSelection={{ '2': true }} onRowSelectionChange={() => {}}
    empty={<EmptyRows />} />)

check('every row is rendered, plus the header row',
      rowCount(html) === 4, String(rowCount(html)))
check('a visible column is there', html.includes('Host') && html.includes('Severity'))
check('a hidden column is not — this is the one that silently shows '
      + 'everything if the visibility model is dropped',
      !html.includes('>Port<'))
// `sev:` and the value are two text nodes, and the server renderer puts
// a comment between them, so this looks for both rather than the pair.
check('the view’s own renderCell reaches the page',
      html.includes('sev:') && html.includes('critical'))
check('a ticked row is ticked', html.includes('Mui-checked'))

console.log('\n== a row key the view chose ==')
// The Web table shows a URL group and then its exchanges beneath it, and
// the group's id IS one of those exchanges. Keyed on `id`, the parent
// disappears; this is that case, reduced.
const collide = [{ id: 7, host: 'group' }, { id: 7, host: 'child' }]
const plain = renderToString(
  <TableGrid rows={collide} columns={[{ field: 'host', headerName: 'Host', flex: 1 }]}
    columnVisibility={{}} sort={[]} onSort={() => {}} density="compact"
    selectable={false} rowSelection={{}} onRowSelectionChange={() => {}}
    empty={<EmptyRows />} />)
const keyed = renderToString(
  <TableGrid rows={collide} columns={[{ field: 'host', headerName: 'Host', flex: 1 }]}
    columnVisibility={{}} sort={[]} onSort={() => {}} density="compact"
    getRowId={(r) => `${r.id}-${r.host}`}
    selectable={false} rowSelection={{}} onRowSelectionChange={() => {}}
    empty={<EmptyRows />} />)
check('getRowId keeps both rows that share an id',
      rowCount(keyed) === 3, String(rowCount(keyed)))
check('and both are distinguishable',
      keyed.includes('group') && keyed.includes('child'))
check('without it they still render, so the key is about identity and '
      + 'not about whether anything appears',
      rowCount(plain) === 3, String(rowCount(plain)))

console.log('\n== the empty state ==')
const none = renderToString(
  <TableGrid rows={[]} columns={columns} columnVisibility={{}} sort={[]}
    onSort={() => {}} density="standard" selectable={false} rowSelection={{}}
    onRowSelectionChange={() => {}} empty={<EmptyRows />} />)
check('says so rather than rendering a blank box', none.includes('no rows'))
check('and still draws the headers', none.includes('Host'))

console.log('\n== several conditions, and saying so ==')
const model: FilterModel = {
  items: [{ id: 1, field: 'status_code', operator: '>=', value: '500' },
          { id: 2, field: 'host', operator: 'contains', value: 'acme' }],
  logicOperator: 'and',
}
const bar = renderToString(
  <TableToolbar columns={columns} filter={model} onFilter={() => {}} search=""
    onSearch={() => {}} columnVisibility={{}} onColumnVisibility={() => {}}
    density="compact" onDensity={() => {}} onExport={() => {}} />)
check('both conditions are chipped — a filtered table that looks '
      + 'unfiltered is the failure this exists to prevent',
      bar.includes('Status ≥ 500') && bar.includes('Host contains acme'))
check('the connective is shown, not assumed', bar.includes('showing rows where'))

const half: FilterModel = {
  items: [{ id: 1, field: 'host', operator: 'contains', value: 'acme' },
          { id: 2, field: 'port', operator: '=', value: '' }],
}
const halfBar = renderToString(
  <TableToolbar columns={columns} filter={half} onFilter={() => {}} search=""
    onSearch={() => {}} columnVisibility={{}} onColumnVisibility={() => {}}
    density="compact" onDensity={() => {}} onExport={() => {}} />)
check('a half-typed condition is not chipped, because it is not filtering',
      halfBar.includes('Host contains acme') && !halfBar.includes('Port ='))

// The panel itself is a MUI Popover, which renders through a portal and
// so produces nothing at all under renderToString — an assertion about
// its markup here would pass for the wrong reason whatever it claimed.
// What the panel offers is decided by `filterableColumns`, which is a
// pure function and is tested as one in logic.test.ts.

console.log('\n== the agent panel keeps every open thread mounted ==')
// The claim being tested is the one that makes a tab switch free: an
// inactive thread is HIDDEN, not unmounted, so the draft in it, its
// scroll position and a question still in flight all survive. Unmount
// the inactive ones and all three are silently thrown away, which
// looks identical until someone loses a half-written question.
const brief = (id: number, title: string): AgentSessionBrief => ({
  id, project_code: 'ACME', title, opened_by: 'tester', closed: false,
  at: null, turn_count: 2,
})
const thread = (id: number, text: string): AgentSession => ({
  id, project_code: 'ACME', title: text, opened_by: 'tester', closed: false,
  at: null,
  turns: [{ id, seq: 0, role: 'user', text, steps: [], author: 'tester',
            at: null }],
})

/** A client primed with what the panel would have fetched. `useQuery`
 *  reads the cache synchronously, so a server render sees the data
 *  without a request. */
function primed() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } } })
  qc.setQueryData(['agent-sessions', 'ACME'],
                  [brief(1, 'the crawl'), brief(2, 'the credential')])
  qc.setQueryData(['agent-session', 'ACME', 1], thread(1, 'what did the crawl find'))
  qc.setQueryData(['agent-session', 'ACME', 2], thread(2, 'is this credential worth anything'))
  return qc
}

/** The panel under the two providers it reads from. `AuthProvider`
 *  is there for `SlackHandlePrompt`, which the panel renders because
 *  it is the one component every signed-in view mounts with the open
 *  engagement in hand. */
const mount = (qc: QueryClient) => renderToString(
  <QueryClientProvider client={qc}>
    <AuthProvider>
      <AgentPanel project="ACME" open onClose={() => {}} />
    </AuthProvider>
  </QueryClientProvider>)

// Two components under here read `window.localStorage` while
// rendering — the handle prompt and the panel's docked/popped-out
// preference — and node has no window at all. The shim is the
// smallest thing that lets a server render reach them, and doubling
// as the preference store is what makes the popped-out shape
// testable below.
const store: Record<string, string> = {}
;(globalThis as { window?: unknown }).window = {
  // The handle prompt asks the URL whether it is on a project page.
  location: { pathname: '/p/ACME' },
  localStorage: {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => { store[k] = v },
    removeItem: (k: string) => { delete store[k] },
  },
}

const panel = mount(primed())

// The transcript itself is filled by an effect, and effects do not
// run under renderToString, so the question here is how many threads
// are MOUNTED rather than what is written in them. Each one marks
// itself with `data-thread`.
const threads = (html: string) => (html.match(/data-thread="/g) ?? []).length
const closers = (html: string) =>
  (html.match(/aria-label="Close thread"/g) ?? []).length

check('a tab per open thread on the engagement',
      panel.includes('the crawl') && panel.includes('the credential'))
check('each tab can be closed', closers(panel) === 2, String(closers(panel)))
check('every thread is mounted, not only the one in front of you — '
      + 'this is what makes a tab switch keep the draft in the other',
      threads(panel) === 2, String(threads(panel)))
check('and the one not in front of you is hidden rather than dropped',
      panel.includes('display:none'))

// One thread needs no strip: a tab bar with a single tab in it is
// chrome that explains nothing.
const solo = new QueryClient({ defaultOptions: { queries: { retry: false } } })
solo.setQueryData(['agent-sessions', 'ACME'], [brief(1, 'the crawl')])
solo.setQueryData(['agent-session', 'ACME', 1], thread(1, 'what did the crawl find'))
const one = mount(solo)
check('a single thread is shown without a tab strip',
      closers(one) === 0 && threads(one) === 1,
      `${closers(one)} close buttons, ${threads(one)} threads`)

// Popping out is the same drawer at the width of the window. It is a
// width swap rather than a different component for a reason: a Dialog
// would remount everything under it and discard exactly the drafts
// and in-flight questions the hidden threads above exist to keep.
store['oddjob.agent.fullscreen'] = '1'
const popped = mount(primed())
check('popped out, the panel is the whole window and not a side column',
      popped.includes('width:100vw') && !popped.includes('width:480px'))
check('docked, it is the side column it has always been',
      panel.includes('width:480px'))
check('and popping out changes the width, not the threads under it',
      threads(popped) === 2, String(threads(popped)))

console.log(`\n${'='.repeat(56)}\n  ${pass} passed, ${fail} failed\n${'='.repeat(56)}`)
process.exit(fail ? 1 : 0)
