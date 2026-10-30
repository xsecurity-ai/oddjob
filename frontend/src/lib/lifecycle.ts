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

// --------------------------------------------------------- proofs
//
// What the PoC column says, and in what order it sorts. The words
// come from the server (`app/pocwork.py`) -- they are not derived
// here, because two places deciding what a state is called is how
// the two come to disagree.

export const POC_STATES = [
  'Available, Confirmed',
  'Available, Not Confirmed',
  'Not Available',
] as const

/** Shorter, for a 168px column. The full words are in the modal's
 *  header and in the tooltip, so nothing is lost. */
export const POC_LABEL: Record<string, string> = {
  'Available, Confirmed': 'confirmed',
  'Available, Not Confirmed': 'not confirmed',
  'Not Available': 'none',
}

/** The middle state is YELLOW and not red. A proof that needs a
 *  credential nobody has is real work that cannot be run from here,
 *  not a failure -- and colouring it like one would say the opposite
 *  of what it means. */
export const POC_COLOUR: Record<string, string> = {
  'Available, Confirmed': neon.green,
  'Available, Not Confirmed': neon.yellow,
  'Not Available': neon.muted,
}

/** Sort order: proven first, then written, then nothing. Severity
 *  sorts worst-first and this sorts most-evidence-first, which is
 *  the same instinct -- the rows that need reading are at the top. */
export const POC_RANK: Record<string, number> = {
  'Available, Confirmed': 0,
  'Available, Not Confirmed': 1,
  'Not Available': 2,
}
