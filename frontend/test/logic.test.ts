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
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { prune, describe as describeState, visibilityDiff } from '../src/lib/useTableState'
import {
  describeItem, filterableColumns, isArmed, nextSort, operatorsFor,
  type ColumnDef, type FilterModel,
} from '../src/lib/columns'
import { filterRows, sortRows } from '../src/lib/tableOps'
import { maybeSorted, sortedStrings, isRanked } from '../src/lib/sortOptions'
import { THEMES } from '../src/palettes'
import { parse as parseRoute, build as buildRoute } from '../src/lib/route'
import { classifyScopeEntry, entryLabel } from '../src/lib/scopeEntry'
import { makeScopePills, scopePills } from '../src/components/scopePills'
import { cap, windowSlice } from '../src/lib/pillLayout'
import { extraAddresses, splitVersion } from '../src/lib/cellFacts'
import { parseDomains } from '../src/lib/domainInput'
import scopeCases from './scope-cases.json'
import domainCases from './domain-cases.json'

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

console.log('\n== scope classification agrees with the server ==')
// The gate that makes client-side classification safe at all.
//
// scope-cases.json is GENERATED from backend/app/scope.py: each entry is
// a line and the Entry that `classify()` produced for it. Both sides are
// held to it — this file checks the TypeScript port, and
// backend/tests/scopetest.py checks that `classify()` still answers the
// way the fixture records. Either implementation drifting turns one of
// the two gates red, which is the only thing standing between a pill
// that says `fqdn` and a server that files `cidr`.
//
// Regenerate (and read the diff — a change here is a change to what the
// scope lists mean) with:
//     cd backend && uv run python -c "..."   see the suite for the snippet
//
// Error TEXT is deliberately not compared. Matching prose across two
// languages buys nothing and breaks on every reword; what matters is
// that both sides agree a line parses, and agree on what it became.
const cases: Array<{ raw: string; subs?: boolean; ok: boolean; kind?: string
                     value?: string; included?: boolean
                     include_subdomains?: boolean }> = scopeCases
const disagree: string[] = []
for (const c of cases) {
  const r = classifyScopeEntry(c.raw, !!c.subs)
  const same = r.ok === c.ok && (!c.ok || (r.ok && r.kind === c.kind
                                 && r.value === c.value
                                 && r.included === c.included
                                 && r.includeSubdomains === c.include_subdomains))
  if (!same) {
    disagree.push(`${JSON.stringify(c.raw)} subs=${!!c.subs}: server ${
      c.ok ? `${c.kind} ${c.value} in=${c.included} sub=${c.include_subdomains}`
           : 'rejected'
    }, browser ${r.ok
      ? `${r.kind} ${r.value} in=${r.included} sub=${r.includeSubdomains}`
      : 'rejected'}`)
  }
}
check(`all ${cases.length} recorded server verdicts reproduced in the browser`,
      disagree.length === 0, disagree.slice(0, 3).join(' | '))
check('the fixture is not empty, which would make the check above vacuous',
      cases.length > 50, `${cases.length} cases`)
check('and it covers every kind the server can return',
      ['cidr', 'ipv4', 'ipv6', 'fqdn', 'wildcard']
        .every((k) => cases.some((c) => c.kind === k)))
check('and it covers lines the server rejects', cases.some((c) => !c.ok))
// The flag arrived after this gate did. A fixture that only ever called
// classify() one way would have kept passing while the port covered half
// of it, which is the exact failure the gate exists to prevent.
check('and it exercises the subdomains flag in both positions',
      cases.some((c) => c.subs) && cases.some((c) => !c.subs))
check('and pins that only an fqdn carries it',
      cases.some((c) => c.include_subdomains)
      && cases.filter((c) => c.include_subdomains)
              .every((c) => c.kind === 'fqdn'))

console.log('\n== an entry that covers a whole zone says so ==')
// entry_label exists on the server so a row covering a zone never prints
// as the bare apex in something the client reads. A pill is read while
// the operator is deciding whether the box is ticked right, so it is the
// last place that should show `acme.example` for a rule that is
// `acme.example (+subdomains)`.
check('the label matches the server for an fqdn with the flag',
      entryLabel('fqdn', 'acme.example', true) === 'acme.example (+subdomains)')
check('a wildcard already covers its zone, so it is unchanged',
      entryLabel('wildcard', '*.acme.example', true) === '*.acme.example')
check('and a range is unchanged', entryLabel('cidr', '203.0.113.0/24', true)
      === '203.0.113.0/24')

const subPills = makeScopePills(true)
check('the chip for a zone entry does not render as the bare name',
      subPills(['acme.example'])[0].label === 'acme.example (+subdomains)')
check('but the typed text is still what the pill carries, for searching '
      + 'and for deleting the right line',
      subPills(['acme.example'])[0].raw === 'acme.example')
check('a cidr under the same tick is not relabelled',
      subPills(['203.0.113.0/24'])[0].label === '203.0.113.0/24')
check('and is told the box did nothing to it, rather than left silent',
      (subPills(['203.0.113.0/24'])[0].note ?? '').includes('do not apply'))
check('a wildcard is told the same, in its own words',
      (subPills(['*.acme.example'])[0].note ?? '').includes('already covers'))
check('with the box clear, a name is just a name',
      scopePills(['acme.example'])[0].label === 'acme.example'
      && !scopePills(['acme.example'])[0].note)

console.log('\n== scope pills ==')
// One pill per line, in order: the index is what a delete button acts
// on, so a dropped or reordered pill deletes the wrong entry.
const pasted = ['203.0.113.0/24', '', 'portal.acme.example', 'not a host!!']
check('one pill per line is returned, blanks included',
      scopePills(pasted).length === pasted.length)
check('an unparseable line is marked as a problem',
      !!scopePills(pasted)[3].problem, scopePills(pasted)[3].problem)
check('a good line is not', !scopePills(pasted)[2].problem)
check('the pill keeps the text that was typed, not the stored form',
      scopePills(['PORTAL.Acme.Example'])[0].raw === 'PORTAL.Acme.Example')
check('and says so when the two differ',
      !!scopePills(['PORTAL.Acme.Example'])[0].note)

// Duplicates are keyed on what the server STORES, which is the whole
// point: these two lines are one entry to classify_many, and a pill list
// that called them two would have the operator hunting for a line the
// server never dropped.
const dupes = scopePills(['203.0.113.0/24', '203.0.113.5/24'])
check('two lines that mask to the same range are marked as duplicates',
      dupes[1].duplicate === true)
check('the first of them is not', !dupes[0].duplicate)
check('unrelated ranges are not',
      !scopePills(['203.0.113.0/24', '198.51.100.0/24'])[1].duplicate)
// Surprising, faithful: classify_many holds one `seen` set of values and
// does not key it on which list the line was for.
check('an exclusion of a line already included is a duplicate, as the '
      + 'server treats it',
      scopePills(['203.0.113.5', '!203.0.113.5'])[1].duplicate === true)
check('an exclusion says which list it lands on',
      (scopePills(['!203.0.113.5'])[0].kind ?? '').includes('out'))

console.log('\n== a pasted scope document ==')
// The size this input is actually for. Correctness at 400 lines, and a
// bound on how long deriving them may take, because the version of this
// component that re-derives on every keystroke is the one that drops
// input.
const doc: string[] = []
for (let i = 0; i < 400; i++) doc.push(`203.0.113.${i % 256}`)
for (let i = 0; i < 400; i++) doc.push(`host${i}.acme.example`)
for (let i = 0; i < 200; i++) doc.push(`10.${i}.0.0/16`)
for (let i = 0; i < 100; i++) doc.push(`*.site${i}.example`)
const big = scopePills(doc)
check('1,100 lines produce 1,100 pills', big.length === 1100)
check('none of the well-formed ones is called a problem',
      big.every((p) => !p.problem))
check('the 144 repeated addresses are marked as duplicates, not dropped',
      big.filter((p) => p.duplicate).length === 400 - 256,
      `${big.filter((p) => p.duplicate).length}`)
const t0 = Date.now()
for (let i = 0; i < 20; i++) scopePills(doc)
const per = (Date.now() - t0) / 20
check('deriving them stays well inside a frame', per < 16, `${per.toFixed(1)}ms`)

console.log('\n== how much of a 1,100-entry list reaches the DOM ==')
// The regression this component exists to avoid is a pill list that is
// lovely at five entries and unusable at four hundred, so the bound on
// rendered elements is asserted rather than assumed.
const many = scopePills(doc)
const capped = cap(many, 60)
check('the inline cloud is capped however long the list is',
      capped.length === 60, `${capped.length} of ${many.length}`)
check('and stays in document order',
      capped.every((x, n) => n === 0 || x.i > capped[n - 1].i))

// The entry worth seeing is the one that is wrong, and in a pasted
// document it is never in the first sixty lines.
const withBad = scopePills([...doc.slice(0, 300), '10.0.0.0/33',
                            ...doc.slice(300)])
const cappedBad = cap(withBad, 60)
check('a malformed line at 301 survives the cap, which a head-slice '
      + 'would have hidden',
      cappedBad.some(({ p }) => !!p.problem))
check('a short list is never reordered or trimmed',
      cap(scopePills(['203.0.113.1', 'bad!!', '203.0.113.2']), 60).length === 3)

check('the virtual window renders a few dozen rows, not 1,100', (() => {
  const w = windowSlice(1100, 0, 300, 30, 5)
  return w.last - w.first <= 30
})(), JSON.stringify(windowSlice(1100, 0, 300, 30, 5)))
check('scrolled to the middle it still renders a window, not a prefix',
      windowSlice(1100, 9000, 300, 30, 5).first === 295)
check('scrolled to the end it clamps to the last row',
      windowSlice(1100, 99999, 300, 30, 5).last === 1100)
check('an elastic overscroll past the end does not invert the slice', (() => {
  const w = windowSlice(1100, -400, 300, 30, 5)
  return w.first === 0 && w.last >= w.first
})())
check('an empty list windows to nothing rather than to NaN',
      JSON.stringify(windowSlice(0, 0, 300, 30, 5)) === '{"first":0,"last":0}')

console.log('\n== a host holds several addresses ==')
check('one address needs no chip', extraAddresses(['10.0.0.1']) === 0)
check('three addresses count the two the cell does not lead with',
      extraAddresses(['10.0.0.1', '10.0.0.2', '::1']) === 2)
// A host with no addresses must give 0. `length - 1` on an empty array
// is -1, which would render as a "+-1" chip.
check('no addresses is zero, not minus one', extraAddresses([]) === 0)
// A response cached from before the field existed. A cell that throws
// takes the whole table down with it.
check('an absent array does not throw', extraAddresses(undefined) === 0)
check('...nor a null one', extraAddresses(null) === 0)

console.log('\n== a ghost version says which build it is ==')
check('a release shows as itself', splitVersion('0.1.0').label === '0.1.0')
check('a release is not marked dev', splitVersion('0.1.0').dev === false)
const dv = splitVersion('0.1.0-dev-20261008T174500Z')
check('a dev build shows the triple', dv.label === '0.1.0')
check('a dev build is marked', dv.dev === true)
// "Has not reported" is a different statement from "is on an old one",
// and the cell renders them differently -- so neither may come back as
// an empty label that prints beside real versions.
check('null is not a version', splitVersion(null).label === null)
check('empty is not a version', splitVersion('').label === null)
check('whitespace is not a version either', splitVersion('   ').label === null)
// A value that is nothing but the suffix is malformed; showing an empty
// string for it would be worse than showing it whole.
check('a version that is only the suffix is left intact',
      splitVersion('-dev-20261008').label === '-dev-20261008')

console.log('\n== the enumerate box reads a paste the way the server will ==')
// domain-cases.json is GENERATED from `EnumerateRequest.wanted` in
// backend/app/routers/domains.py. The backend suite asserts the server
// still answers this; here the port has to agree with the same table.
// What travels to the server is the raw text, so every disagreement is
// the box telling the operator something untrue about what will happen.
{
  const drift: string[] = []
  for (const c of domainCases as { raw: string; wanted: string[] }[]) {
    const got = parseDomains(c.raw)
    if (JSON.stringify(got) !== JSON.stringify(c.wanted)) {
      drift.push(`${JSON.stringify(c.raw)}: port ${JSON.stringify(got)} vs server ${JSON.stringify(c.wanted)}`)
    }
  }
  check(`the port agrees with the server on all ${domainCases.length} cases`,
        drift.length === 0, drift.slice(0, 3).join(' | '))
}
// The specific disagreement this replaced, kept as its own line so a
// regression names itself rather than showing up as "case 7 differs".
check('a single-label name counts, because the server queues it',
      parseDomains('localhost').length === 1)
check('a wildcard run is eaten whole, not one star',
      parseDomains('**..acme.example')[0] === 'acme.example')
check('a port stays attached, because the server keeps it',
      parseDomains('acme.example:8443')[0] === 'acme.example:8443')
check('the first spelling of a duplicate wins',
      JSON.stringify(parseDomains('dup.example DUP.EXAMPLE')) === '["dup.example"]')

// ---------------------------------------------------------------------
// DataTable needs a parent that gives it a height
// ---------------------------------------------------------------------
//
// It sizes itself with `flex: 1; min-height: 0; overflow: hidden`,
// which only resolves inside a flex container that has a height. In a
// plain block `flex` is ignored, `overflow: hidden` then clips, and
// the grid inside asks for `height: 100%` of a parent that has none —
// a table cut off with no way to scroll to the rest of the rows. That
// is what GhostsView did.
//
// No type can express that contract, so it is checked against the
// source: a view either hands DataTable straight to the app shell
// (fragment root) or puts something with a height in between.
const viewDir = new URL('../src/views', import.meta.url).pathname
for (const f of readdirSync(viewDir).filter((x) => x.endsWith('.tsx'))) {
  const src = readFileSync(join(viewDir, f), 'utf8')
  const at = src.indexOf('<DataTable')
  if (at < 0) continue
  const head = src.slice(src.lastIndexOf('return (', at), at)
  const fragmentRoot = /return \(\s*(\/\/[^\n]*\n\s*)*<>/.test(head)
  const directChild = /return \(\s*(\/\/[^\n]*\n\s*)*$/.test(head)
  // A real height, not `minHeight: 0`. That one is the OPPOSITE of
  // giving a height -- it is what lets a flex child shrink -- and an
  // earlier version of this check accepted it, which made the whole
  // assertion pass against the very bug it was written for.
  const givesHeight = /height:\s*'[^']*(vh|px|%)'|minHeight:\s*[1-9]/.test(head)
  check(`${f} gives DataTable a height to fill`,
        fragmentRoot || directChild || givesHeight)
}

console.log(`\n${'='.repeat(56)}\n  ${pass} passed, ${fail} failed\n${'='.repeat(56)}`)
process.exit(fail ? 1 : 0)
