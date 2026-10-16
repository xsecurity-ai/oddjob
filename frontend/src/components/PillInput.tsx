/**
 * A pill/chip editor for the places an operator pastes a list of hosts.
 *
 * ── What it is a replacement for, and what it must not break ───────────
 *
 * Four screens took a multiline TextField holding one entry per line: the
 * amass domain list, the "or scan these" box, the project scope box and
 * the scope box on the new-engagement dialog. Each of those posts its
 * text to an endpoint that has its own opinion about how to split it, so
 * the single most important property of this component is that it is a
 * PRESENTATION LAYER OVER THE SAME STRING. It is controlled on `value:
 * string` exactly as the TextField was, it hands back a string through
 * `onChange`, and every call site still builds its payload the way it
 * always did. Nothing about the wire changed, and nothing should.
 *
 * That choice also answers the question an operator always asks of a chip
 * input — "where did my text go?". It did not go anywhere. The raw text
 * IS the state, the "Raw text" toggle shows the very same string in the
 * very same kind of textarea, and Copy puts it on the clipboard so it can
 * be reconciled against the client's spreadsheet.
 *
 * ── Hundreds of entries is the normal case ─────────────────────────────
 *
 * A scope document is pasted whole. The scope suite exercises a 400-line
 * re-paste and real engagements run past a thousand entries, so "renders
 * 400 chips" is the design centre and not an edge case. Two things follow:
 *
 *  1. The DOM is capped. Past `collapseAfter` the inline cloud shows a
 *     bounded slice and a "+N more" chip; the full list opens in a panel
 *     that renders only the rows in view. A thousand entries is a few
 *     dozen elements on screen either way.
 *
 *  2. Typing must not re-analyse the list. The half-typed entry lives in
 *     local `draft` state and the committed `value` does not change until
 *     the entry is finished, so a keystroke re-renders the input and
 *     nothing else. Deriving pills from `value + draft` on every
 *     keystroke is the version of this component that drops input at 400
 *     entries, which is worse than the textarea it replaced.
 *
 * The capped slice is chosen rather than truncated: anything flagged goes
 * in first, then the earliest clean entries fill the remainder, and the
 * result is put back in document order. The whole point of pills over a
 * textarea is that a bad line is visible without hunting for it, and a
 * plain `.slice(0, 60)` hides exactly the line you need when the bad one
 * is number 217.
 *
 * ── On verdicts ────────────────────────────────────────────────────────
 *
 * Pills show what `analyse` says and nothing here acts on it. No entry is
 * withheld from a payload and no submit button consults a verdict reached
 * in this file — `scope.py` and `hosts.py` decide what is valid, and a
 * browser that silently drops a line the server would have accepted is a
 * scope rule that never got enforced. See src/lib/scopeEntry.ts for why
 * the client is allowed to have an opinion at all.
 */
import { useCallback, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Box, Chip, FormControl, FormHelperText, InputLabel,
  OutlinedInput, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import { cap, windowSlice } from '../lib/pillLayout'
import { neon } from '../theme'

const MONO = `'Share Tech Mono', monospace`

/** One entry, as `analyse` sees it. */
export interface Pill {
  /** Exactly what the operator wrote, never normalised. They are
   *  reconciling against a document that says `203.0.113.0/24`, and
   *  showing them the server's canonicalisation of it instead means
   *  comparing two spellings of the same thing by eye. */
  raw: string
  /** What the chip shows, when that is not the typed text. Used where
   *  the stored rule reads differently from the line — a scope entry
   *  covering a whole zone must not render as the bare apex, which is
   *  the same rule `entry_label` enforces in the report and in Slack.
   *  The typed text stays in the tooltip, and search still matches it. */
  label?: string
  /** A short derived label — `cidr`, `fqdn`, `wildcard`. Leave it unset
   *  to make no claim; a wrong label is worse than no label. */
  kind?: string
  /** Why this entry will not do, in a sentence that reads under a
   *  cursor. Advisory: it colours a pill, it does not block a submit.
   *
   *  Only set this where the SERVER would refuse the entry. Colouring a
   *  pill red for something the endpoint behind it accepts happily is
   *  the client overruling the authority in the only way it can — by
   *  lying to the operator — and the scan queue in particular validates
   *  nothing but scope, so almost nothing typed there earns a red. */
  problem?: string
  /** Something worth saying that is not a refusal: an entry this screen
   *  does not recognise but will submit anyway, or a value the server
   *  will store in a different form than it was typed. Renders muted. */
  note?: string
  /** Set on the second and later occurrence of the same entry. The
   *  server deduplicates silently, which is the right thing for it to do
   *  and the wrong thing for a person checking that all 400 lines of a
   *  scope document arrived. */
  duplicate?: boolean
}

/** Turns the committed lines into pills. MUST return exactly one pill per
 *  line, in order — the index is the identity used to delete an entry —
 *  and MUST be referentially stable (declare it at module scope, or wrap
 *  it in useCallback), or the memo it feeds rebuilds on every render and
 *  the performance argument above evaporates. */
export type Analyse = (lines: string[]) => Pill[]

/** One entry per line: what the scope endpoints parse. A leading `!` and
 *  a space after it belong to the entry, so whitespace cannot split. */
export const BY_LINE = /\n/
/** Newlines, commas, semicolons or spaces: what the enumerate endpoints
 *  parse, and what a list pasted out of a chat message looks like. */
export const BY_ANY = /[\s,;]+/

/** Rows past this and the inline cloud collapses. Sized so the common
 *  case — a handful of ranges typed by hand — never collapses at all. */
const DEFAULT_CAP = 60
/** Fixed row height in the expanded panel. Uniform rows are what make
 *  the windowing a subtraction instead of a measurement pass. */
const ROW = 30
const PANEL = 300
/** Rows rendered above and below the viewport, so a flick of the wheel
 *  does not show a band of blank. */
const OVERSCAN = 5

export interface PillInputProps {
  label: string
  /** The raw text. Unchanged in meaning from the TextField this replaces. */
  value: string
  onChange: (next: string) => void
  analyse: Analyse
  /** How a paste becomes entries. BY_LINE unless the endpoint behind
   *  this box splits on more than newlines. */
  separator?: RegExp
  placeholder?: string
  /** Shown when there is nothing to report about the list itself. */
  helperText?: ReactNode
  accent?: string
  collapseAfter?: number
  /** Rows for the raw-text view. */
  minRows?: number
  disabled?: boolean
  /** Extra sx for the outer control, for call sites that size it. */
  sx?: Record<string, unknown>
}

export function PillInput({
  label, value, onChange, analyse, separator = BY_LINE, placeholder,
  helperText, accent = neon.cyan, collapseAfter = DEFAULT_CAP, minRows = 4,
  disabled = false, sx,
}: PillInputProps) {
  const id = useId()
  const [draft, setDraft] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [rawMode, setRawMode] = useState(false)
  const [query, setQuery] = useState('')
  const [onlyProblems, setOnlyProblems] = useState(false)
  const [scrollTop, setScrollTop] = useState(0)
  const [armClear, setArmClear] = useState(false)
  const [copied, setCopied] = useState(false)
  const inputRef = useRef<HTMLInputElement | null>(null)

  const lines = useMemo(
    () => value.split(separator).map((l) => l.trim()).filter(Boolean),
    [value, separator])
  const pills = useMemo(() => analyse(lines), [lines, analyse])

  const commit = useCallback((text: string) => {
    const add = text.split(separator).map((l) => l.trim()).filter(Boolean)
    if (add.length) onChange([...lines, ...add].join('\n'))
  }, [lines, onChange, separator])

  const removeAt = useCallback((i: number) => {
    onChange(lines.filter((_, j) => j !== i).join('\n'))
  }, [lines, onChange])

  // A paste is a finished act, so all of it commits — including the last
  // entry when the blob has no trailing newline. Left to the keystroke
  // path a 400-line paste would strand line 400 in the draft box.
  const onPaste = useCallback((e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text')
    if (!text) return
    e.preventDefault()
    commit(draft + text)
    setDraft('')
  }, [commit, draft])

  const onType = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const parts = e.target.value.split(separator)
    // Everything before the final separator is a finished entry; what
    // follows it is still being typed.
    if (parts.length > 1) {
      commit(parts.slice(0, -1).join('\n'))
      setDraft(parts[parts.length - 1])
    } else {
      setDraft(e.target.value)
    }
  }, [commit, separator])

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      commit(draft)
      setDraft('')
    } else if (e.key === 'Backspace' && !draft && lines.length) {
      e.preventDefault()
      removeAt(lines.length - 1)
    }
  }, [commit, draft, lines.length, removeAt])

  const counts = useMemo(() => {
    const kinds = new Map<string, number>()
    let bad = 0, dup = 0
    for (const p of pills) {
      if (p.problem) bad += 1
      else if (p.duplicate) dup += 1
      else if (p.kind) kinds.set(p.kind, (kinds.get(p.kind) ?? 0) + 1)
    }
    return { kinds: [...kinds].sort((a, b) => b[1] - a[1]), bad, dup }
  }, [pills])

  // Flagged entries first, then the earliest clean ones, then back into
  // document order — so the cap never hides the line worth looking at.
  const shown = useMemo(() => cap(pills, collapseAfter),
                        [pills, collapseAfter])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return pills.map((p, i) => ({ p, i })).filter(({ p }) => {
      if (onlyProblems && !p.problem && !p.duplicate) return false
      return !q || p.raw.toLowerCase().includes(q)
    })
  }, [pills, query, onlyProblems])

  const hidden = pills.length - shown.length
  const { first, last } = windowSlice(filtered.length, scrollTop, PANEL,
                                      ROW, OVERSCAN)
  const windowed = filtered.slice(first, last)

  const copy = () => {
    navigator.clipboard?.writeText(value).then(
      () => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) },
      // A clipboard the browser refuses is not worth an error dialog; the
      // raw-text view is right there and can be selected by hand.
      () => setRawMode(true))
  }

  const summary: string[] = []
  if (pills.length) {
    summary.push(`${pills.length} entr${pills.length === 1 ? 'y' : 'ies'}`)
    for (const [k, n] of counts.kinds) summary.push(`${n} ${k}`)
    if (counts.dup) summary.push(`${counts.dup} duplicate`)
    if (counts.bad) {
      summary.push(`${counts.bad} the server will not accept`)
    }
  }

  return (
    <FormControl fullWidth size="small" disabled={disabled} sx={sx}>
      {/* The label belongs to whichever control is actually mounted. A
          FormControl's own InputLabel is positioned over its input, so
          leaving it up while the raw TextField renders its own puts two
          labels on top of the first line of the textarea. */}
      {!rawMode && (
        <InputLabel shrink htmlFor={id} sx={{ color: alpha(accent, 0.9) }}>
          {label}
        </InputLabel>
      )}

      {rawMode ? (
        <TextField
          id={id} label={label} size="small" fullWidth multiline
          minRows={minRows} value={value} disabled={disabled}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          slotProps={{ inputLabel: { shrink: true },
                       htmlInput: { style: { fontFamily: MONO, fontSize: 12.5 } } }} />
      ) : (
        <OutlinedInput
          id={id} notched label={label} disabled={disabled}
          value={draft} onChange={onType} onKeyDown={onKeyDown}
          onPaste={onPaste} onBlur={() => { commit(draft); setDraft('') }}
          inputRef={inputRef}
          placeholder={pills.length ? '' : placeholder}
          sx={{
            display: 'flex', flexWrap: 'wrap', alignItems: 'center',
            gap: 0.5, py: 0.9, minHeight: 56, alignContent: 'flex-start',
          }}
          startAdornment={
            <>
              {shown.map(({ p, i }) => (
                <PillChip key={`${i}:${p.raw}`} pill={p} accent={accent}
                  onDelete={disabled ? undefined : () => removeAt(i)} />
              ))}
              {hidden > 0 && (
                <Chip size="small" clickable label={`+${hidden} more`}
                  onClick={() => setExpanded(true)}
                  sx={{ height: 20, fontSize: 10.5, letterSpacing: '0.06em',
                        color: neon.muted,
                        bgcolor: alpha(neon.muted, 0.12),
                        border: `1px solid ${alpha(neon.muted, 0.45)}` }} />
              )}
            </>
          }
          slotProps={{ input: { style: {
            flex: '1 1 150px', minWidth: 150, padding: 0,
            fontFamily: MONO, fontSize: 12.5,
          } } }} />
      )}

      <FormHelperText component="div" sx={{ mx: 0 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center',
                   gap: 1, rowGap: 0.3 }}>
          {/* The count and the standing guidance both stay. The
              TextField this replaces folded a short form of the guidance
              into its count line for the same reason: "anything out of
              scope is refused when it is queued" stops being true the
              moment it is needed least, which is before anything has
              been typed. */}
          <Box component="span" sx={{ fontSize: 11, color: neon.muted }}>
            {summary.length ? summary.join(' · ') : null}
            {summary.length && helperText ? ' — ' : null}
            {helperText}
          </Box>
          <Box sx={{ flex: 1 }} />
          {/* `|| rawMode` is not redundant: clearing the box while in raw
              mode would otherwise take the toggle away with the pills and
              strand the operator in a textarea with no way back. */}
          {(pills.length > 0 || rawMode) && (
            <>
              {pills.length > shown.length && !rawMode && (
                <Act onClick={() => setExpanded(true)} colour={accent}>
                  show all {pills.length}
                </Act>
              )}
              <Act onClick={() => setRawMode((r) => !r)} colour={neon.muted}>
                {rawMode ? 'pills' : 'raw text'}
              </Act>
              <Act onClick={copy} colour={neon.muted}>
                {copied ? 'copied' : 'copy'}
              </Act>
              {/* Two clicks, because one misplaced click should not cost
                  somebody the scope document they just pasted. */}
              <Act onClick={() => {
                if (!armClear) { setArmClear(true); return }
                onChange(''); setDraft(''); setArmClear(false); setExpanded(false)
              }} colour={armClear ? neon.red : neon.muted}>
                {armClear ? `clear all ${pills.length}?` : 'clear'}
              </Act>
            </>
          )}
        </Box>
      </FormHelperText>

      {/* The panel is a view of the pills, so it goes away with them when
          the raw text is showing — two editors over one string, open at
          once, is a race nobody needs to reason about. */}
      {expanded && !rawMode && (
        <Box sx={{ mt: 1, border: `1px solid ${alpha(accent, 0.35)}`,
                   borderRadius: 1, overflow: 'hidden' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 0.8,
                     borderBottom: `1px solid ${alpha(accent, 0.2)}` }}>
            <TextField size="small" variant="standard" placeholder="filter…"
              value={query} onChange={(e) => { setQuery(e.target.value); setScrollTop(0) }}
              sx={{ flex: 1, maxWidth: 240 }}
              slotProps={{ htmlInput: { style: { fontFamily: MONO, fontSize: 12 } } }} />
            <Chip size="small" clickable label="only problems"
              onClick={() => { setOnlyProblems((o) => !o); setScrollTop(0) }}
              sx={{ height: 20, fontSize: 10.5,
                    color: onlyProblems ? neon.bg : neon.yellow,
                    bgcolor: onlyProblems ? neon.yellow : alpha(neon.yellow, 0.12),
                    border: `1px solid ${alpha(neon.yellow, 0.5)}` }} />
            <Typography sx={{ fontSize: 11, color: neon.muted }}>
              {filtered.length} of {pills.length}
            </Typography>
            <Box sx={{ flex: 1 }} />
            <Act onClick={() => setExpanded(false)} colour={neon.muted}>close</Act>
          </Box>

          {/* Only the rows in view exist. The spacer carries the full
              height so the scrollbar still describes the whole list. */}
          <Box onScroll={(e) => setScrollTop((e.target as HTMLElement).scrollTop)}
            sx={{ height: PANEL, overflowY: 'auto' }}>
            <Box sx={{ height: filtered.length * ROW, position: 'relative' }}>
              {windowed.map(({ p, i }, n) => (
                <Box key={`${i}:${p.raw}`}
                  sx={{ position: 'absolute', left: 0, right: 0,
                        top: (first + n) * ROW, height: ROW, px: 1,
                        display: 'flex', alignItems: 'center', gap: 1,
                        borderBottom: `1px solid ${alpha(neon.muted, 0.12)}` }}>
                  <Box component="span" sx={{ width: 46, flexShrink: 0,
                                              fontSize: 10, color: alpha(neon.muted, 0.7),
                                              textAlign: 'right' }}>
                    {i + 1}
                  </Box>
                  <PillChip pill={p} accent={accent}
                    onDelete={disabled ? undefined : () => removeAt(i)} />
                  <Box component="span" sx={{ fontSize: 11, color: neon.muted,
                                              overflow: 'hidden',
                                              textOverflow: 'ellipsis',
                                              whiteSpace: 'nowrap' }}>
                    {p.problem
                      ?? (p.duplicate ? 'already in the list above' : p.note ?? '')}
                  </Box>
                </Box>
              ))}
            </Box>
          </Box>
        </Box>
      )}
    </FormControl>
  )
}

/** A flat text button. MUI's Button carries ripple, focus and elevation
 *  machinery that a four-character control in a helper line does not
 *  need, and these sit next to a list that may hold a thousand rows. */
function Act({ onClick, colour, children }: {
  onClick: () => void; colour: string; children: ReactNode
}) {
  return (
    <Box component="span" role="button" tabIndex={0} onClick={onClick}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onClick() }}
      sx={{ fontSize: 10.5, letterSpacing: '0.07em', color: colour,
            cursor: 'pointer', userSelect: 'none',
            borderBottom: `1px dotted ${alpha(colour, 0.5)}`,
            '&:hover': { color: neon.text } }}>
      {children}
    </Box>
  )
}

function PillChip({ pill, accent, onDelete }: {
  pill: Pill; accent: string; onDelete?: () => void
}) {
  const colour = pill.problem ? neon.red
    : pill.duplicate ? neon.yellow : accent
  // When the chip is showing a label rather than the typed line, the
  // typed line goes in the tooltip — an operator reconciling against a
  // client's spreadsheet still needs to find the text they pasted.
  const typed = pill.label && pill.label !== pill.raw
    ? `typed as ${pill.raw}` : ''
  const say = [pill.problem ?? (pill.duplicate
    ? 'The same entry appears earlier in this list. The server keeps the '
      + 'first one and drops this, so the list is shorter than it looks.'
    : pill.note), typed].filter(Boolean).join(' · ')
  const chip = (
    <Chip size="small" onDelete={onDelete}
      deleteIcon={<CloseIcon sx={{ fontSize: 13 }} />}
      label={
        <Box component="span" sx={{ display: 'inline-flex', gap: 0.7,
                                    alignItems: 'baseline' }}>
          <Box component="span" sx={{ fontFamily: MONO, fontSize: 11.5 }}>
            {pill.label ?? pill.raw}
          </Box>
          {pill.kind && (
            <Box component="span" sx={{ fontSize: 9, letterSpacing: '0.08em',
                                        opacity: 0.7 }}>
              {pill.kind}
            </Box>
          )}
        </Box>
      }
      sx={{ height: 22, maxWidth: 360, bgcolor: alpha(colour, 0.14),
            color: colour,
            // Dashed for a note: it reads as "there is something to read
            // here" without the alarm of a red chip, which is the whole
            // distinction between a note and a problem.
            border: `1px ${pill.note && !pill.problem && !pill.duplicate
              ? 'dashed' : 'solid'} ${alpha(colour, 0.5)}`,
            '& .MuiChip-deleteIcon': { color: alpha(colour, 0.7),
                                       '&:hover': { color: colour } } }} />
  )
  // A tooltip costs a wrapper component per pill, so only the entries
  // with something to say get one. The rest already show their kind.
  if (!say) return chip
  return <Tooltip placement="top" title={say}>{chip}</Tooltip>
}

/** Marks the second and later occurrence of an entry.
 *
 *  `identity` is what the server would store, not what was typed, because
 *  that is what it deduplicates on: `203.0.113.5/24` and `203.0.113.0/24`
 *  are one entry to `classify_many` and look like two here. Where an
 *  analyser has no canonical form to offer, the raw text is the identity
 *  and near-duplicates simply go unmarked — under-reporting a duplicate
 *  is a missing hint, over-reporting one is a lie about what will be
 *  stored.
 */
export function markDuplicates(pills: Pill[], identity: (p: Pill, i: number) => string): Pill[] {
  const seen = new Set<string>()
  return pills.map((p, i) => {
    const key = identity(p, i)
    if (seen.has(key)) return { ...p, duplicate: true }
    seen.add(key)
    return p
  })
}
