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

/** What the Country cell should say about a target. */
export type CountryCell =
  /** A mobile app: no address, so nowhere to be. */
  | { state: 'na' }
  /** No address on record at all — nothing to locate, and saying
   *  "unknown" would blame MaxMind for our own empty inventory. */
  | { state: 'none' }
  /** Addresses exist and have never been looked up. OUR gap. */
  | { state: 'unasked'; pending: number }
  /** Looked up; the databases hold no country. A fact about the data,
   *  and ordinary for a private range. */
  | { state: 'unknown' }
  | { state: 'known'; code: string; name: string | null; all: string[] }

/** Decide the Country cell. Three kinds of blank, kept apart.
 *
 *  The whole reason this is a function: "no country" has three
 *  different causes and they are not interchangeable. Nobody asked is
 *  a gap in our coverage; asked-and-no-data is a fact about MaxMind;
 *  no addresses at all is a fact about the inventory. A cell that
 *  rendered one blank for all three would turn our own missing work
 *  into an assertion about the client's estate — which is the exact
 *  mistake the engagement notes call out as "a failed lookup is not
 *  evidence about the target".
 *
 *  `geo_pending` is read before `geo_country` is trusted to be absent,
 *  and defensively: a response cached from before these fields existed
 *  has them undefined, and a cell that throws takes the table with it.
 */
export function countryCell(t: {
  kind?: string | null
  ip_addresses?: string[] | null
  geo_country?: string | null
  geo_country_name?: string | null
  geo_countries?: string[] | null
  geo_pending?: number | null
}): CountryCell {
  if (t.kind === 'mobile') return { state: 'na' }
  if (!(t.ip_addresses?.length)) return { state: 'none' }
  if (t.geo_country) {
    const all = t.geo_countries?.length ? t.geo_countries : [t.geo_country]
    return { state: 'known', code: t.geo_country,
             name: t.geo_country_name ?? null, all }
  }
  // An ABSENT `geo_pending` is not a zero. A response cached from
  // before the field existed cannot tell us whether anything was
  // looked up, and "asked, no data" is the flattering reading of a
  // thing we do not know — so an undefined count falls to `unasked`,
  // which claims nothing, rather than to `unknown`, which claims we
  // tried. `pending: 0` there means "cannot say how many", and the
  // cell words its tooltip accordingly.
  const pending = t.geo_pending
  if (pending === null || pending === undefined) {
    return { state: 'unasked', pending: 0 }
  }
  return pending > 0 ? { state: 'unasked', pending } : { state: 'unknown' }
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
