/**
 * The scope box's pill analyser, shared by the two screens that have one:
 * ProjectConfigView (adding to a live engagement's in/out lists) and
 * NewProjectDialog (the scope pasted when the engagement is created).
 *
 * Both post to `classify_many`, so both must describe a pasted line the
 * same way. One copy, because two would drift and the drift would be
 * invisible — the screens are rarely open at the same time.
 *
 * Lives beside the component rather than in lib/ because a Pill is a
 * presentation concept; src/lib/scopeEntry.ts is the part with no opinion
 * about chips, and it is the part that has to agree with the server.
 */
import { classifyScopeEntry, entryLabel } from '../lib/scopeEntry'
import type { Analyse, Pill } from './PillInput'

/**
 * Build the analyser for a given state of the "include subdomains" box.
 *
 * A factory rather than a plain function because the flag is part of how
 * a line is read: with it ticked, `acme.example` is the whole zone and
 * not one name. `Analyse` has to stay referentially stable, so callers
 * memoise this on the flag — it changes when the checkbox does and not
 * on every keystroke.
 *
 * Duplicates are keyed on the value the server would STORE, not on the
 * text that was typed. `203.0.113.0/24` and `203.0.113.5/24` are one
 * entry to `classify_many` — it masks host bits and then deduplicates on
 * the result — so a pill list that keyed on raw text would show 400
 * entries for a document the server files as 398, and the operator
 * counting them against the client's spreadsheet would be the one who
 * had to work out why.
 *
 * Note that the dedup key ignores whether a line was an exclusion, and
 * ignores the subdomains flag too. That looks wrong and is faithful:
 * `classify_many` holds a single `seen` set of values, so `!acme.example`
 * after `acme.example` is dropped rather than moved to the other list.
 * Worth flagging to the operator precisely BECAUSE it is surprising — a
 * line they wrote to exclude something silently does nothing.
 */
export function makeScopePills(includeSubdomains: boolean): Analyse {
  return (lines) => {
    const seen = new Set<string>()
    return lines.map((raw): Pill => {
      const r = classifyScopeEntry(raw, includeSubdomains)
      if (!r.ok) return { raw, problem: r.reason }

      // `entry_label` is the one place that decides how an entry reads
      // back, and it exists because a row covering a whole zone printing
      // as the bare apex tells the client a narrower scope than the one
      // being enforced. A pill is read at exactly the moment the
      // operator is deciding whether the box is ticked right, so it is
      // the last place that should render `acme.example` when the stored
      // rule is `acme.example (+subdomains)`.
      const label = entryLabel(r.kind, r.value, r.includeSubdomains)
      // The `!`/`-` prefix flips which list the line lands on, which is a
      // bigger deal than the kind and is one character wide in the raw
      // text. Said out loud on the chip.
      const kind = r.included ? r.kind : `${r.kind} · out`

      if (seen.has(r.value)) return { raw, label, kind, duplicate: true }
      seen.add(r.value)

      // Where the stored value differs from what was typed — a host bit
      // masked off, a scheme stripped, a name lowercased — say so,
      // because the row that appears in the list below will not be the
      // text they pasted and that reads as the wrong entry having been
      // added. The flag on a kind that cannot carry it is worth a word
      // for the same reason: ticking the box does nothing to a CIDR, and
      // silence there reads as it having worked.
      let note: string | undefined
      if (label !== raw.trim()) note = `stored as ${label}`
      else if (includeSubdomains && r.kind !== 'fqdn') {
        note = r.kind === 'wildcard'
          ? 'already covers its subdomains, so the box adds nothing here'
          : `subdomains do not apply to a ${r.kind}, so the box is ignored `
            + 'for this line'
      }
      return { raw, label, kind, note }
    })
  }
}

/** The common case: no zone coverage asked for. Kept as a value so the
 *  call sites that have no checkbox, and the tests, do not each have to
 *  memoise a factory call. */
export const scopePills: Analyse = makeScopePills(false)
