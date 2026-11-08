/**
 * The application is split into chunks, and stays split.
 *
 * It shipped as ONE 1,581 KB file (445 KB gzipped): sixteen views,
 * a terminal emulator and every dialog, downloaded before the
 * sign-in page could render, by a user about to look at one of them.
 *
 * This asserts the shape rather than a number. A size budget on a
 * growing application is a line somebody raises until it means
 * nothing; what matters is that the views are still separate files
 * and the entry has not quietly swallowed them again — which is what
 * one stray eager `import` of a view does.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { join } from 'node:path'

const DIST = 'dist/assets'
let fail = 0
const check = (label, ok, extra = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? '  ' + extra : ''}`)
  if (!ok) fail++
}

if (!existsSync(DIST)) {
  console.log('  SKIP  no dist/ — run `npm run build` first')
  process.exit(0)
}

const files = readdirSync(DIST).filter((f) => f.endsWith('.js'))
check('the build produced many chunks, not one', files.length > 10,
      `${files.length} chunks`)

// Walk the static import graph from the entry: that, and only that,
// is what a cold visitor downloads before anything renders.
const entry = files.find((f) => /^index-.*\.js$/.test(f))
check('there is an entry chunk', !!entry, entry ?? '')
const eager = new Set()
const walk = (name) => {
  if (!name || eager.has(name) || !existsSync(join(DIST, name))) return
  eager.add(name)
  const body = readFileSync(join(DIST, name), 'utf8')
  for (const m of body.matchAll(/(?:from|import)"\.\/([A-Za-z0-9_\-.]+\.js)"/g)) {
    walk(m[1])
  }
}
walk(entry)

const gz = [...eager].reduce(
  (n, f) => n + gzipSync(readFileSync(join(DIST, f))).length, 0)
console.log(`\n  first load: ${eager.size} chunks, ${(gz / 1024).toFixed(0)} KB gzipped`)
console.log(`  (was one 1,581 KB chunk, 445 KB gzipped)\n`)

// Comfortably under what it was, with room to grow before anyone has
// to think about it again. A failure here means a view or something
// as large as one has been pulled back into the entry.
check('the first load is well under the 445 KB it used to be',
      gz / 1024 < 330, `${(gz / 1024).toFixed(0)} KB`)

// The heaviest single dependency, and the one least often needed:
// only a live shell uses it.
const term = files.find((f) => f.startsWith('LiveTerminal-'))
check('the terminal emulator is its own chunk', !!term, term ?? 'not split')
check('and it is NOT loaded before anything renders',
      !!term && !eager.has(term))

// The views that cost the most. Each must be reachable only by
// opening it.
for (const view of ['TargetsView', 'GhostsView', 'VulnsView', 'WebView',
                    'C2View', 'HealthView']) {
  const f = files.find((x) => x.startsWith(view + '-'))
  check(`${view} is a chunk of its own`, !!f, f ? '' : 'not split out')
  if (f) check(`  …and is not in the first load`, !eager.has(f))
}

process.exit(fail ? 1 : 0)
