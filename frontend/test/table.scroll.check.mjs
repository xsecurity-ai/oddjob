/**
 * Catch a table that cannot reach its own last row.
 *
 * `DataTable` is built to be a flex child: `flex: 1; min-height: 0;
 * overflow: hidden`, with the scrolling done by the grid inside it.
 * Put one in a plain block parent and every part of that stops
 * working at once -- `flex` is ignored outside a flex container, the
 * Paper sizes to its content instead, and `overflow: hidden` on it or
 * on an ancestor then clips the rows away with no scrollbar to reach
 * them. The table looks fine and is simply missing its tail.
 *
 * That has now shipped twice: once on the Ghosts page and once on the
 * Subdomain Takeovers tab. It is invisible in review, invisible in
 * typecheck, and only shows up when a list happens to be longer than
 * the viewport -- which on an engagement it always eventually is.
 *
 * Two checks, both deliberately cheap and textual:
 *
 *   1. `DataTable` itself still carries the `height: '100%'` fallback
 *      that makes it survive a block parent at all.
 *   2. No caller wraps one in the exact broken shape -- an element
 *      sized with `flex: 1` that never says `display: 'flex'`.
 *
 * The second is a lint, not a proof: it cannot see through a styled
 * component or a parent three files away. It catches the mistake that
 * was actually made, twice, which is the bar the hooks check is held
 * to as well.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Relative to the working directory, like hooks.check.mjs: both are
// run from `frontend/`, and `URL` is not in the eslint env this repo
// lints test scripts under.
const SRC = 'src'
const problems = []

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.tsx?$/.test(p)) out.push(p)
  }
  return out
}

// ---- 1. the component keeps its fallback -------------------------
const dt = readFileSync(join(SRC, 'components', 'DataTable.tsx'), 'utf8')
for (const want of ["flex: 1", "minHeight: 0", "height: '100%'",
                    "flexDirection: 'column'"]) {
  if (!dt.includes(want)) {
    problems.push(`DataTable.tsx no longer sets ${want} on its root. `
      + 'Without all four it cannot scroll in a block parent.')
  }
}

// ---- 2. no caller wraps one in a block box -----------------------
// Walk backwards from each `<DataTable` to the element that opens the
// block it sits in, and complain if that element is sized with `flex`
// but never declares itself a flex container.
for (const file of walk(SRC)) {
  const text = readFileSync(file, 'utf8')
  if (!text.includes('<DataTable')) continue
  const lines = text.split('\n')
  lines.forEach((line, i) => {
    if (!line.includes('<DataTable')) return
    // The nearest opening tag above that carries an `sx`.
    for (let j = i - 1; j >= 0 && j > i - 12; j--) {
      const l = lines[j]
      if (!/<(Box|Stack|Paper|div)\b/.test(l)) continue
      // Gather the sx block, which may wrap over a few lines.
      const chunk = lines.slice(j, j + 6).join(' ')
      if (!/sx=\{\{/.test(chunk)) break
      const sized = /flex:\s*1/.test(chunk)
      const isFlex = /display:\s*['"]flex['"]/.test(chunk)
                  || /<Stack\b/.test(l)
      if (sized && !isFlex) {
        problems.push(
          `${file}:${j + 1} wraps a <DataTable> in a `
          + 'box sized with `flex: 1` that is not a flex container. '
          + "Add `display: 'flex', flexDirection: 'column'` or the "
          + 'table will clip instead of scrolling.')
      }
      break
    }
  })
}

if (problems.length) {
  console.error('table scroll check failed:\n')
  for (const p of problems) console.error('  - ' + p)
  process.exit(1)
}
console.log('table scroll check: ok')
