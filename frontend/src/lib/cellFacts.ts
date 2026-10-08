/** Small decisions two table cells make, kept out of the cells.
 *
 *  Both of these are one line inside a `renderCell`, which is exactly
 *  where a wrong one is hardest to see: the cell renders, it just says
 *  something untrue. Pulled out here so `logic.test.ts` can ask them
 *  directly, because the alternative is a test that re-implements the
 *  line it is checking and agrees with itself.
 */

/** How many addresses a host holds beyond the one the cell leads with.
 *
 *  Defensive about the array: a client holding a response cached from
 *  before `ip_addresses` existed has the field undefined, and a cell
 *  that throws takes the whole table with it.
 *
 *  Counts from the array, not from `length - 1` on a possibly-empty
 *  one: a host with no addresses at all must give 0, not -1.
 */
export function extraAddresses(all: string[] | null | undefined): number {
  return Math.max(0, (all?.length ?? 0) - 1)
}

/** Split a ghost version into what to show and whether it is a dev build.
 *
 *  `scripts/version.sh` appends `-dev-<commit time>` to a build that is
 *  not a release, and the suffix is long enough to push the useful part
 *  out of a 110px column. So the column shows the triple and marks it,
 *  rather than truncating and leaving a dev build looking like 0.1.0.
 *
 *  Null and empty are NOT a version. "Has not reported" is a different
 *  statement from "is on an old one", and the caller renders them
 *  differently -- so this returns a null label rather than an empty
 *  string that a cell could print beside real versions.
 */
export function splitVersion(v: string | null | undefined):
    { label: string | null; dev: boolean } {
  const s = (v ?? '').trim()
  if (!s) return { label: null, dev: false }
  const at = s.indexOf('-dev-')
  if (at <= 0) return { label: s, dev: false }
  return { label: s.slice(0, at), dev: true }
}
