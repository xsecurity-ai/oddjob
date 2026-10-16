/**
 * What a person concluded about a finding.
 *
 * Separate from `status`, which is what has been DONE about it: a
 * confirmed issue can be open and a false positive can be closed,
 * and one field could not say both.
 *
 * Here rather than in a view because three places render it — the
 * table column, the row control and the modal — and three copies
 * of a vocabulary is how they stop agreeing.
 */
export type Triage = 'needs_investigating' | 'true_positive' | 'false_positive'

export const TRIAGE: Array<{ value: Triage; label: string; colour: string }> = [
  // `needs_investigating` first: it is the default, and the one a
  // scanner produces. The other two are somebody's judgement.
  { value: 'needs_investigating', label: 'Needs investigating', colour: '#f5c518' },
  { value: 'true_positive', label: 'True positive', colour: '#ff4d6d' },
  { value: 'false_positive', label: 'False positive', colour: '#7a8699' },
]

export const TRIAGE_LABEL: Record<string, string> =
  Object.fromEntries(TRIAGE.map((t) => [t.value, t.label]))

export const TRIAGE_COLOUR: Record<string, string> =
  Object.fromEntries(TRIAGE.map((t) => [t.value, t.colour]))
