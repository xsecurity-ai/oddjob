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
