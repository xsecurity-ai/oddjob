/**
 * How many pills to put in the DOM, and which ones.
 *
 * Separated from the component because this is the part that has to be
 * right at 1,100 entries and the part that is cheapest to get subtly
 * wrong — an off-by-one in the window shows a band of blank rows on a
 * fast scroll, and a naive `.slice()` in the cap hides exactly the entry
 * the operator opened the box to find. Neither failure is visible in a
 * screenshot of five pills, which is how both survive a review.
 *
 * No React in here, so test/logic.test.ts can exercise it in node.
 */

/** Anything with an index, which is all `cap` and `windowSlice` need. */
export interface Indexed<T> { p: T; i: number }

/**
 * Choose at most `cap` entries to render inline, keeping document order.
 *
 * `flagged` gets first refusal on the budget. The entire argument for
 * pills over a textarea is that a malformed line announces itself, and a
 * plain head-slice of a 400-line scope document shows lines 1-60 — which
 * are almost always the fine ones, because an operator pastes a document
 * that was mostly right. The one line with a typo'd range is at 217 and
 * would never be on screen.
 *
 * The result is re-sorted into document order afterwards. A list that
 * jumps the bad entries to the front reads as a different list from the
 * one that was pasted, and the operator is reconciling against a
 * spreadsheet in the same order.
 */
export function cap<T extends { problem?: string; duplicate?: boolean }>(
  pills: T[], limit: number,
): Array<Indexed<T>> {
  const all = pills.map((p, i) => ({ p, i }))
  if (all.length <= limit) return all
  const flagged = all.filter(({ p }) => p.problem || p.duplicate)
  const plain = all.filter(({ p }) => !p.problem && !p.duplicate)
  return [...flagged, ...plain].slice(0, limit).sort((a, b) => a.i - b.i)
}

/** The half-open row range to render for a scrolled viewport.
 *
 *  `overscan` rows are drawn beyond each edge so that a flick of the
 *  wheel does not outrun the scroll event and show blank.
 *
 *  BOTH ends are clamped to `total`, and that is not belt-and-braces. An
 *  elastic overscroll on macOS reports a `scrollTop` outside the content,
 *  and the list also shrinks under a standing scroll position every time
 *  the filter box is typed into or an entry is deleted. Clamping only
 *  `last` leaves `first` past the end of the array, and `Math.max` then
 *  pushes `last` out to meet it — a slice that is empty when it should
 *  have been the final rows. The first version of this did exactly that
 *  and the test below is the one that caught it. */
export function windowSlice(
  total: number, scrollTop: number, viewport: number, row: number,
  overscan: number,
): { first: number; last: number } {
  if (total <= 0 || row <= 0) return { first: 0, last: 0 }
  const first = Math.min(total,
                         Math.max(0, Math.floor(scrollTop / row) - overscan))
  const last = Math.min(total,
                        Math.max(first,
                                 Math.ceil((scrollTop + viewport) / row) + overscan))
  return { first, last }
}
