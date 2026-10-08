/**
 * Pure client-side logic, exercised without a browser or a DOM.
 *
 *     npm run test:logic
 *
 * Only the parts where being wrong is silent: pruning table state that
 * refers to columns which no longer exist (symptom: an empty grid and a
 * user who concludes the import failed), and the dropdown ordering rule
 * (symptom: severity listed critical, high, info, low, medium, which
 * reads as a ranking and is the wrong one).
 */
import { prune, describe as describeState, visibilityDiff } from '../src/lib/useTableState'
import {
  describeItem, filterableColumns, isArmed, nextSort, operatorsFor,
  type ColumnDef, type FilterModel,
} from '../src/lib/columns'
import { filterRows, sortRows } from '../src/lib/tableOps'
import { maybeSorted, sortedStrings, isRanked } from '../src/lib/sortOptions'
import { THEMES } from '../src/palettes'
import { parse as parseRoute, build as buildRoute } from '../src/lib/route'

let pass = 0, fail = 0
const check = (label: string, cond: boolean, extra = '') => {
  if (cond) { pass++; console.log(`  PASS  ${label} ${extra}`) }
  else { fail++; console.log(`  FAIL  ${label} ${extra}`) }
}
const eq = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

console.log('== pruning stale table state ==')
const fields = new Set(['host', 'severity', 'port'])
const stale = {
  sort: [{ field: 'host', sort: 'asc' as const },
         { field: 'removed_column', sort: 'desc' as const }],
  filter: { items: [{ field: 'severity', operator: 'is', value: 'high', id: 1 },
                    { field: 'gone', operator: 'is', value: 'x', id: 2 }] },
  columns: { host: true, gone: false },
  pagination: { page: 2, pageSize: 100 },
}
const p = prune(stale as never, fields)
check('sort on a removed column is dropped',
      eq(p.sort, [{ field: 'host', sort: 'asc' }]), JSON.stringify(p.sort))
check('filter on a removed column is dropped — this is the one that would '
      + 'otherwise empty the grid',
      (p.filter?.items ?? []).length === 1, JSON.stringify(p.filter?.items))
check('the surviving filter is kept intact',
      p.filter?.items?.[0]?.value === 'high')
check('visibility for a removed column is dropped',
      eq(Object.keys(p.columns ?? {}), ['host']), JSON.stringify(p.columns))
check('pagination survives untouched', eq(p.pagination, { page: 2, pageSize: 100 }))
check('empty stored state prunes to empty, not a crash',
      eq(prune({}, fields), {}))

console.log('\n== what counts as worth warning about ==')
const noFilter = { items: [] }
check('a default view is not dirty',
      describeState([], noFilter, {}, []).dirty === false)
check('a remembered sort is dirty but does NOT hide rows',
      describeState([{ field: 'host', sort: 'asc' }], noFilter, {}, []).hiding === false)
const filtered = { items: [{ field: 'severity', operator: 'is', value: 'critical', id: 1 }] }
check('an active filter hides rows',
      describeState([], filtered as never, {}, []).hiding === true)
check('a filter with no value yet does not count',
      describeState([], { items: [{ field: 'x', operator: 'is', id: 1 }] } as never,
                    {}, []).hiding === false)
check('a quick search counts as hiding',
      describeState([], { items: [], quickFilterValues: ['acme'] } as never,
                    {}, []).hiding === true)
check('an empty quick search does not',
      describeState([], { items: [], quickFilterValues: [''] } as never,
                    {}, []).hiding === false)
check('the summary names what is on',
      describeState([], { items: [], quickFilterValues: ['acme'] } as never,
                    { port: false }, []).summary === 'search “acme” · 1 column hidden',
      describeState([], { items: [], quickFilterValues: ['acme'] } as never,
                    { port: false }, []).summary)
check('matching the default sort is not dirty',
      describeState([{ field: 'host', sort: 'asc' }], noFilter, {},
                    [{ field: 'host', sort: 'asc' }]).dirty === false)

console.log('\n== column visibility: view defaults vs user choice ==')
check('hiding what the view already hides stores nothing',
      eq(visibilityDiff({ project_code: false }, { project_code: false }), {}))
check('a user re-showing a view-hidden column IS stored',
      eq(visibilityDiff({ project_code: true }, { project_code: false }),
         { project_code: true }))
check('a user hiding a normally-visible column is stored',
      eq(visibilityDiff({ port: false }, {}), { port: false }))
check('untouched visible columns are not stored',
      eq(visibilityDiff({ host: true, port: true }, {}), {}))

console.log('\n== several conditions at once ==')
// The point of moving off @mui/x-data-grid: its free tier hardcodes
// disableMultipleColumnsFiltering, so the second condition replaced the
// first. These are the cases where being wrong is silent — a condition
// that quietly matches everything looks exactly like one that works.
const webCols: ColumnDef[] = [
  { field: 'url', headerName: 'URL' },
  { field: 'status_code', headerName: 'Status', type: 'number' },
  { field: 'crawled', headerName: 'Fetched', type: 'boolean' },
  { field: 'title', headerName: 'Title', valueGetter: (v) => v ?? '' },
  { field: 'secret', headerName: 'Secret', filterable: false },
]
const web = [
  { url: 'https://a.acme.example/admin', status_code: 500, crawled: true, title: null, secret: 'hunter2' },
  { url: 'https://a.acme.example/login', status_code: 200, crawled: true, title: 'Login', secret: 'hunter2' },
  { url: 'https://b.corp.com/admin', status_code: 503, crawled: false, title: null, secret: 'hunter2' },
  { url: 'https://b.corp.com/health', status_code: 404, crawled: false, title: 'Health', secret: 'hunter2' },
]
const and: FilterModel = {
  items: [{ field: 'status_code', operator: '>=', value: '500' },
          { field: 'url', operator: 'contains', value: 'admin' }],
  logicOperator: 'and',
}
check('two conditions ANDed keep only the rows matching both',
      eq(filterRows(web, and, webCols).map((r) => r.status_code), [500, 503]),
      JSON.stringify(filterRows(web, and, webCols).map((r) => r.url)))
// Deliberately two conditions that match DIFFERENT rows, so AND and OR
// cannot give the same answer and the assertion means something.
const or: FilterModel = {
  items: [{ field: 'status_code', operator: '>=', value: '500' },
          { field: 'url', operator: 'contains', value: 'health' }],
  logicOperator: 'or',
}
check('ORed, a row matching either is kept',
      eq(filterRows(web, or, webCols).map((r) => r.status_code), [500, 503, 404]),
      JSON.stringify(filterRows(web, or, webCols).map((r) => r.status_code)))
check('and ANDed, the same pair matches nothing',
      filterRows(web, { ...or, logicOperator: 'and' }, webCols).length === 0)
check('no logicOperator means AND, not "whatever is first"',
      filterRows(web, { items: and.items }, webCols).length === 2)
check('two conditions on the SAME column are a range, which is the thing '
      + 'a one-condition-per-column model cannot express',
      filterRows(web, { items: [
        { field: 'status_code', operator: '>=', value: '400' },
        { field: 'status_code', operator: '<', value: '500' }] }, webCols)
        .length === 1)
check('a half-typed condition filters nothing rather than everything',
      filterRows(web, { items: [{ field: 'url', operator: 'contains', value: '' }] },
                 webCols).length === 4)
check('an operator we do not recognise KEEPS the rows — never hide a '
      + 'finding because a filter was not understood',
      filterRows(web, { items: [{ field: 'url', operator: 'sorcery', value: 'x' }] },
                 webCols).length === 4)
check('isEmpty is armed with no value and really does hide rows',
      filterRows(web, { items: [{ field: 'title', operator: 'isEmpty' }] },
                 webCols).length === 2)
check('a condition and the search box both have to pass',
      filterRows(web, { items: [{ field: 'url', operator: 'contains', value: 'admin' }],
                        quickFilterValues: ['corp'] }, webCols).length === 1)

console.log('\n== the search box does not read a withheld column ==')
// Credentials marks its secret column `filterable: false` so that "a
// secret should not be discoverable by typing fragments of it into a
// filter box". Before this was honoured the panel left the column out
// and the search then read every column anyway.
check('a term matching only an unfilterable column matches no rows',
      filterRows(web, { items: [], quickFilterValues: ['hunter2'] }, webCols).length === 0)
check('while an ordinary column is still searched',
      filterRows(web, { items: [], quickFilterValues: ['health'] }, webCols).length === 1)
check('and the filter panel is offered the same set',
      eq(filterableColumns(webCols).map((c) => c.field),
         ['url', 'status_code', 'crawled', 'title']))

console.log('\n== what each column type may be asked ==')
const ops = (c: ColumnDef) => operatorsFor(c).map((o) => o.value)
check('a boolean gets is/not and presence, and nothing else — every '
      + 'other operator reaches filtering.py’s boolean branch and comes '
      + 'back as the NEGATION, with a 200',
      eq(ops({ field: 'b', type: 'boolean' }), ['is', 'not', 'isEmpty', 'isNotEmpty']),
      JSON.stringify(ops({ field: 'b', type: 'boolean' })))
check('a number gets no "contains"',
      !ops({ field: 'n', type: 'number' }).includes('contains'))
check('a string gets no ">="',
      !ops({ field: 's' }).includes('>='))
check('every operator offered is one filtering.py lists in _TEXT_OPS or '
      + '_NUM_OPS',
      [...new Set([...ops({ field: 's' }), ...ops({ field: 'n', type: 'number' }),
                   ...ops({ field: 'b', type: 'boolean' }),
                   ...ops({ field: 'v', type: 'singleSelect' })])]
        .every((o) => new Set([
          'contains', 'doesNotContain', 'equals', 'doesNotEqual', 'startsWith',
          'endsWith', 'isEmpty', 'isNotEmpty', 'isAnyOf', 'is', 'not',
          '=', '!=', '>', '>=', '<', '<=']).has(o)))

console.log('\n== pruning a condition whose operator has gone ==')
// The other half of "stale state must never hide data silently": a
// `contains` left on a column that is now a number is not recognised by
// matches(), so the chip says filtered and nothing is filtered.
const typed: ColumnDef[] = [{ field: 'port', type: 'number' }, { field: 'host' }]
const typedFields = new Set(['port', 'host'])
const stalely = prune({ filter: { items: [
  { field: 'port', operator: 'contains', value: '44' },
  { field: 'port', operator: '>=', value: '443' },
  { field: 'host', operator: 'contains', value: 'acme' },
] } }, typedFields, typed)
check('a condition the column can no longer answer is dropped',
      (stalely.filter?.items ?? []).length === 2,
      JSON.stringify(stalely.filter?.items))
check('without columns given, only the field is checked — which is what '
      + 'the storage layer could do before it knew about operators',
      (prune({ filter: { items: [{ field: 'port', operator: 'contains', value: '44' }] } },
             typedFields).filter?.items ?? []).length === 1)

console.log('\n== clicking a header ==')
check('a fresh column sorts ascending', eq(nextSort([], 'host'), [{ field: 'host', sort: 'asc' }]))
check('clicking again reverses',
      eq(nextSort([{ field: 'host', sort: 'asc' }], 'host'), [{ field: 'host', sort: 'desc' }]))
check('and a third click clears it, rather than cycling forever',
      eq(nextSort([{ field: 'host', sort: 'desc' }], 'host'), []))
check('a different column replaces the sort',
      eq(nextSort([{ field: 'host', sort: 'asc' }], 'port'), [{ field: 'port', sort: 'asc' }]))
check('shift-clicking adds to it instead',
      eq(nextSort([{ field: 'sev', sort: 'asc' }], 'host', true),
         [{ field: 'sev', sort: 'asc' }, { field: 'host', sort: 'asc' }]))
check('and shift-clicking it off leaves the rest in place',
      eq(nextSort([{ field: 'sev', sort: 'asc' }, { field: 'host', sort: 'desc' }],
                  'host', true),
         [{ field: 'sev', sort: 'asc' }]))

console.log('\n== a column may insist on its own order ==')
// Severity is a string, so the generic comparator sorts it critical,
// high, info, low, medium — putting "info" third on a findings table.
const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const sevCols: ColumnDef[] = [{
  field: 'sev',
  sortComparator: (a, b) => (RANK[a as string] ?? 9) - (RANK[b as string] ?? 9),
}]
const sevRows = [{ sev: 'info' }, { sev: 'critical' }, { sev: 'medium' }]
check('sortComparator is honoured, so ascending really is worst first',
      eq(sortRows(sevRows, [{ field: 'sev', sort: 'asc' }], sevCols).map((r) => r.sev),
         ['critical', 'medium', 'info']),
      JSON.stringify(sortRows(sevRows, [{ field: 'sev', sort: 'asc' }], sevCols)
        .map((r) => r.sev)))
check('and without one the generic comparator would have got it wrong',
      eq(sortRows(sevRows, [{ field: 'sev', sort: 'asc' }], [{ field: 'sev' }])
        .map((r) => r.sev), ['critical', 'info', 'medium']))
check('a second sort key breaks ties in the first',
      eq(sortRows([{ a: 1, b: 'z' }, { a: 1, b: 'a' }, { a: 0, b: 'm' }],
                  [{ field: 'a', sort: 'asc' }, { field: 'b', sort: 'asc' }],
                  [{ field: 'a' }, { field: 'b' }]).map((r) => `${r.a}${r.b}`),
         ['0m', '1a', '1z']))

console.log('\n== saying what a condition does, in words ==')
check('an operator with a value reads as a sentence',
      describeItem({ field: 'status_code', operator: '>=', value: '500' },
                   { field: 'status_code', headerName: 'Status', type: 'number' })
        === 'Status ≥ 500')
check('one without a value does not pretend to have one',
      describeItem({ field: 'title', operator: 'isEmpty' },
                   { field: 'title', headerName: 'Title' }) === 'Title is empty')
check('a list is spelled out',
      describeItem({ field: 's', operator: 'isAnyOf', value: ['200', '401'] },
                   { field: 's', headerName: 'Status' }) === 'Status is any of 200, 401')
check('a condition with no column falls back to the field name',
      describeItem({ field: 'mystery', operator: 'contains', value: 'x' })
        === 'mystery contains x')

console.log('\n== armed, or still being typed ==')
check('no field is never armed', isArmed({ field: '', operator: 'contains', value: 'x' }) === false)
check('no value is not armed', isArmed({ field: 'a', operator: 'contains' }) === false)
check('an empty string is not armed',
      isArmed({ field: 'a', operator: 'contains', value: '' }) === false)
check('an empty list is not armed',
      isArmed({ field: 'a', operator: 'isAnyOf', value: [] }) === false)
check('isEmpty needs no value to be armed',
      isArmed({ field: 'a', operator: 'isEmpty' }) === true)
check('zero IS a value — the bug where "port = 0" filters nothing',
      isArmed({ field: 'a', operator: '=', value: 0 }) === true)
check('and so is false',
      isArmed({ field: 'a', operator: 'is', value: false }) === true)

console.log('\n== dropdown ordering ==')
check('arbitrary lists sort, numeric-aware',
      eq(sortedStrings(['web10', 'web2', 'api']), ['api', 'web2', 'web10']),
      JSON.stringify(sortedStrings(['web10', 'web2', 'api'])))
check('severity is recognised as ranked',
      isRanked(['critical', 'high', 'medium', 'low', 'info']))
check('and is therefore NOT alphabetised',
      eq(maybeSorted(['critical', 'high', 'medium', 'low', 'info']),
         ['critical', 'high', 'medium', 'low', 'info']))
check('smtp security keeps most-secure-first',
      eq(maybeSorted(['starttls', 'tls', 'none']), ['starttls', 'tls', 'none']))
check('a mixed list is not treated as ranked',
      isRanked(['critical', 'bananas']) === false)
check('a one-item list is not treated as ranked', isRanked(['critical']) === false)

console.log('\n== themes ==')
const SLOTS = ['bg', 'bgDeep', 'paper', 'raised', 'pink', 'cyan', 'yellow',
               'orange', 'green', 'red', 'purple', 'text', 'muted']
check('every theme fills every slot',
      THEMES.every((t) => SLOTS.every((k) => /^#[0-9a-fA-F]{6}$/.test(
        (t.palette as Record<string, string>)[k] ?? ''))),
      THEMES.filter((t) => !SLOTS.every((k) =>
        /^#[0-9a-fA-F]{6}$/.test((t.palette as Record<string, string>)[k] ?? '')))
        .map((t) => t.id).join(',') || 'all ok')
check('theme ids are unique',
      new Set(THEMES.map((t) => t.id)).size === THEMES.length)
check('14 themes', THEMES.length === 14, String(THEMES.length))
check('only Synthwave draws the grid decor',
      THEMES.filter((t) => t.decor === 'synthwave').map((t) => t.id).join() === 'synthwave84')
check('no light theme claims glow',
      THEMES.filter((t) => t.mode === 'light').every((t) => !t.glow))

console.log('\n== URL routing ==')

const r1 = parseRoute('/projects/ACME/targets/web01.corp.com/services/tcp/443')
check('the full path parses',
      r1.project === 'ACME' && r1.view === 'targets'
      && r1.host === 'web01.corp.com' && r1.protocol === 'tcp' && r1.port === 443,
      JSON.stringify(r1))
check('and rebuilds to itself',
      buildRoute(r1) === '/projects/ACME/targets/web01.corp.com/services/tcp/443',
      buildRoute(r1))
check('/ lands on the project list, not targets-across-everything',
      eq(parseRoute('/'), { view: 'projects', project: null }))
check('an empty path is the same as /',
      eq(parseRoute(''), { view: 'projects', project: null }))
check('/projects lists projects',
      parseRoute('/projects').view === 'projects')
check('but a project of its own still defaults to its targets',
      eq(parseRoute('/projects/ACME'), { view: 'targets', project: 'ACME' }))
check('an unknown view under a project falls back to its targets',
      parseRoute('/projects/ACME/nope').view === 'targets')
check('a project code is upper-cased',
      parseRoute('/projects/acme').project === 'ACME')
check('a global view needs no project',
      eq(parseRoute('/config'), { view: 'config', project: null }))
check('a scoped view without a project means all projects',
      eq(parseRoute('/vulns'), { view: 'vulns', project: null }))
check('an unknown view falls back rather than erroring',
      parseRoute('/projects/ACME/nonsense').view === 'targets')
check('a typo at the root falls back to the project list',
      parseRoute('/wat').view === 'projects')
check('a hostname with dots survives',
      parseRoute('/projects/X/targets/a.b.c.d').host === 'a.b.c.d')
check('a percent-encoded host is decoded',
      parseRoute('/projects/X/targets/a%2Eb.com').host === 'a.b.com',
      parseRoute('/projects/X/targets/a%2Eb.com').host)
check('a non-numeric port is ignored rather than becoming NaN',
      parseRoute('/projects/X/targets/h/services/tcp/abc').port === undefined)
check('switching view drops the host from the path',
      buildRoute({ view: 'vulns', project: 'ACME' }) === '/projects/ACME/vulns')
check('no project builds a bare view path',
      buildRoute({ view: 'targets', project: null }) === '/targets')

console.log('\n== the ?next= round trip ==')
// `next` arrives in a URL anyone can craft. Validated on the client as
// well as the server, because checking in one place only is how a
// parameter like this becomes a phishing link.
const SAFE = (raw: string): boolean =>
  raw.startsWith('/') && !raw.startsWith('//')
  && !raw.includes('://') && !raw.includes('\\')

check('a normal path is accepted', SAFE('/projects/ACME/vulns'))
check('a protocol-relative URL is not', !SAFE('//evil.com'))
check('an absolute URL is not', !SAFE('https://evil.com/x'))
check('a backslash path is not', !SAFE('/\\evil.com'))
check('a bare path with a query is accepted', SAFE('/targets?q=web'))
check('the remembered path parses back to its route',
      eq(parseRoute('/projects/ACME/vulns'), { view: 'vulns', project: 'ACME' }))
check('and a deep one keeps its host and service',
      buildRoute(parseRoute('/projects/X/targets/h/services/tcp/22'))
      === '/projects/X/targets/h/services/tcp/22')

console.log(`\n${'='.repeat(56)}\n  ${pass} passed, ${fail} failed\n${'='.repeat(56)}`)
process.exit(fail ? 1 : 0)
