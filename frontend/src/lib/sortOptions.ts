/**
 * Ordering for dropdown contents.
 *
 * Sorted by default, because a list whose order nobody chose is a list the
 * reader has to scan linearly — and the format picker, the project list and
 * the user list had all grown past the point where that was reasonable.
 *
 * But NOT everything. Some option lists are *ranked*, and alphabetising
 * them is actively misleading: severity sorted by name gives
 * critical, high, info, low, medium — putting `info` third and `low`
 * fourth, which reads as an ordering and is the wrong one. The same goes
 * for role hierarchies and for a small set of options whose author chose
 * the order deliberately (`starttls, tls, none` runs most-secure first).
 *
 * So: `sorted()` for arbitrary lists, and ranked lists keep their order
 * and say why at the call site.
 */

/** Alphabetical, case-insensitive, numeric-aware ("web2" before "web10"). */
export function sorted<T>(items: T[], key: (x: T) => string): T[] {
  return [...items].sort((a, b) =>
    key(a).localeCompare(key(b), undefined, { numeric: true, sensitivity: 'base' }))
}

export const sortedStrings = (items: string[]): string[] => sorted(items, (x) => x)

/** Option lists whose order carries meaning and must survive untouched. */
export const RANKED = new Set([
  'critical', 'high', 'medium', 'low', 'info',   // severity
  'admin', 'user', 'readonly', 'viewer',         // role hierarchy
  'starttls', 'tls', 'none',                     // most-secure first
  'site', 'override', 'both',                    // escalating Slack reach
])

/** True when every option is part of a ranked set, so leave it alone. */
export function isRanked(options: string[]): boolean {
  return options.length > 1 && options.every((o) => RANKED.has(String(o).toLowerCase()))
}

/** Sort unless the list is ranked. */
export function maybeSorted(options: string[]): string[] {
  return isRanked(options) ? options : sortedStrings(options)
}

/** Same, for `{value, label}` options. Ranked-ness is judged on the value,
 *  since that is what carries the meaning — a severity relabelled
 *  "Critical" is still a severity. */
export function maybeSortedBy<T>(options: T[], value: (x: T) => unknown,
                                 label: (x: T) => string): T[] {
  const vals = options.map((o) => String(value(o) ?? ''))
  return isRanked(vals) ? options : sorted(options, label)
}
