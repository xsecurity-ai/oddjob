import { neon } from '../theme'

/**
 * What the most recent scan said about a finding.
 *
 * Four words, not three. The report vocabulary everyone asks for is
 * new / still present / resolved, and the fourth is the one that
 * keeps the other three honest: a finding nothing has looked for
 * since it was last seen is neither resolved nor confirmed present,
 * and rolling it into either would be the tool making something up.
 */
export const LIFECYCLE = ['new', 'present', 'resolved', 'unconfirmed'] as const

export const LIFECYCLE_LABEL: Record<string, string> = {
  new: 'New',
  present: 'Still there',
  resolved: 'Resolved',
  unconfirmed: 'Not checked',
}

/** `unconfirmed` is deliberately NOT grey-on-grey. It is the state
 *  that should prompt somebody to go and scan, and a colour that
 *  reads as "nothing to see" would defeat the whole point of having
 *  a fourth answer at all. */
export const LIFECYCLE_COLOUR: Record<string, string> = {
  new: neon.orange,
  present: neon.yellow,
  resolved: neon.green,
  unconfirmed: neon.cyan,
}

/** Sort order for the column: what needs attention first. */
export const LIFECYCLE_RANK: Record<string, number> = {
  new: 0, present: 1, unconfirmed: 2, resolved: 3,
}
