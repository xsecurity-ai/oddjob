/** How the enumerate box reads what was pasted into it.
 *
 *  A port of `EnumerateRequest.wanted` in backend/app/routers/domains.py,
 *  and the server is the authority: what travels to it is the RAW text,
 *  so whatever this says is only ever a prediction of what will be
 *  queued. A prediction that disagrees with the thing it predicts is
 *  worse than no prediction, because the operator believes it.
 *
 *  It disagreed. This box used to parse the text twice — once to count
 *  for the Run button and once to analyse for the pills — and the two
 *  did not agree with each other, let alone with the server. The count
 *  required a dot, so a single-label name like `localhost` counted as
 *  zero: the pill showed it as perfectly good, the Run button stayed
 *  disabled, and the server would have enumerated it happily. There is
 *  one normalisation here now and both callers use it.
 *
 *  `frontend/test/domain-cases.json` is generated from the server's own
 *  function and both sides assert against it, the same arrangement
 *  scope.py and scopeEntry.ts have. Change `wanted` and the backend
 *  suite goes red, which is the reminder to regenerate and read the
 *  diff — it is a diff of what a pasted list MEANS.
 */

/** One pasted piece, as the server will read it.
 *
 *  The order matters and is the server's: strip, drop trailing dots,
 *  lowercase, drop leading stars and dots, then the scheme, then
 *  everything from the first `/` or `?`. Lowercasing before the scheme
 *  is why `HTTPS://` is handled and a case-sensitive port would not be.
 *
 *  Note what it does NOT do: a port is left attached, because `wanted`
 *  leaves it attached. Stripping it here would be this file deciding
 *  something the authority did not.
 */
export function asServerReadsIt(raw: string): string {
  const v = raw.trim().replace(/\.+$/, '').toLowerCase().replace(/^[*.]+/, '')
  return v.replace(/^[a-z]+:\/\//, '').split('/')[0].split('?')[0]
}

/** The whole box, split and de-duplicated exactly as `wanted` does it.
 *
 *  Commas, spaces, semicolons, newlines. Operators paste from
 *  spreadsheets, scope documents and chat messages, and making them
 *  reformat it first is the kind of friction that gets a tool abandoned
 *  for a terminal.
 *
 *  First occurrence wins on a duplicate, which is what the server keeps.
 */
export function parseDomains(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const piece of (raw || '').split(/[\s,;]+/)) {
    const v = asServerReadsIt(piece)
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}
