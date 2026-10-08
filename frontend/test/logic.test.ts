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
import { classifyScopeEntry, entryLabel } from '../src/lib/scopeEntry'
import { makeScopePills, scopePills } from '../src/components/scopePills'
import { cap, windowSlice } from '../src/lib/pillLayout'
import scopeCases from './scope-cases.json'

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

console.log(`\n${'='.repeat(56)}\n  ${pass} passed, ${fail} failed\n${'='.repeat(56)}`)
process.exit(fail ? 1 : 0)
