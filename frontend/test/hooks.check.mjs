/**
 * Catch React hooks called after an early return.
 *
 * A component that calls 15 hooks on one render and 17 on the next is a
 * hard React error, and it renders as a blank page with the reason only
 * in the console. That is exactly what happened here: a `useQuery` added
 * below `if (!authed) return <GateView/>` booted fine for a signed-out
 * visitor and crashed the moment they signed in.
 *
 * Depth is tracked with a brace counter rather than by indentation. The
 * first version of this matched `/^\s{2}return/` and therefore missed
 * every early return written as `if (x) {\n    return …\n  }` — which is
 * all of them, including the one it was written to catch.
 *
 * Narrower than eslint-plugin-react-hooks, which is the real tool for
 * this, but zero dependencies and it catches the failure that occurred.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const COMPONENT = /^(?:export\s+)?(?:default\s+)?function\s+([A-Z]\w*)\s*\(/
const HOOK = /\b(use[A-Z]\w*)\s*\(/
const RETURN = /\breturn\b/
const FUNC_OPEN = /=>|\bfunction\b/

/** Strip strings and comments so braces inside them are not counted. */
function sanitise(line) {
  return line
    .replace(/\/\/.*$/, '')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``')
}

function walk(dir) {
  const out = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else if (/\.tsx$/.test(name)) out.push(p)
  }
  return out
}

export function check(files) {
  const problems = []
  let components = 0

  for (const file of files) {
    const lines = readFileSync(file, 'utf8').split('\n')
    let depth = 0, inComponent = false, name = '', earlyReturn = 0, inBlockComment = false
    /** What each open brace belongs to: 'fn' or 'block'. */
    let frames = []

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i]
      if (inBlockComment) {
        if (line.includes('*/')) { inBlockComment = false; line = line.split('*/')[1] ?? '' }
        else continue
      }
      if (line.includes('/*') && !line.includes('*/')) { inBlockComment = true; line = line.split('/*')[0] }
      const code = sanitise(line)

      if (!inComponent) {
        const m = COMPONENT.exec(code)
        if (m) { inComponent = true; name = m[1]; depth = 0; earlyReturn = 0; frames = [] }
        else continue
      }

      const before = depth
      // Is anything between here and the component body a function? A
      // `return` inside `useMemo(() => { … })` is that callback's value,
      // not an early exit from the component — which is what the first
      // two versions of this check got wrong, in opposite directions.
      // frames[0] is the component's own body — skipping it was the
      // third thing this check got wrong: counting it made every line
      // look like it was inside a callback, so nothing was ever flagged.
      const insideCallback = frames.slice(1).some((f) => f === 'fn')

      if (before >= 1 && !insideCallback && RETURN.test(code)) {
        earlyReturn = earlyReturn || i + 1
      }
      // A hook at depth 1, outside any callback, is a top-level call.
      if (before === 1 && !insideCallback && earlyReturn) {
        const h = HOOK.exec(code)
        if (h) {
          problems.push(`${file}:${i + 1} — ${name}() calls ${h[1]}() after `
                        + `the early return on line ${earlyReturn}`)
        }
      }

      // Classify each brace this line opens, so the stack knows what it
      // is inside. A line opening a function is one with => or `function`
      // before the brace.
      for (const ch of code) {
        if (ch === '{') {
          frames.push(FUNC_OPEN.test(code) ? 'fn' : 'block')
          depth++
        } else if (ch === '}') {
          frames.pop()
          depth--
        }
      }
      if (inComponent && depth <= 0 && before > 0) {
        inComponent = false
        components++
      }
    }
  }
  return { problems, components }
}

const { problems, components } = check(walk('src'))
for (const p of problems) console.log(`  FAIL  ${p}`)
if (!problems.length) {
  console.log(`  PASS  no hooks after an early return (${components} components)`)
}
process.exit(problems.length ? 1 : 0)
