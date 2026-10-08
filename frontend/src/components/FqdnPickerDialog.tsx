/**
 * Decide what a finished lookup meant — and show the ones that need no
 * deciding separately from the ones that do.
 *
 * Most of this used to be a question because the schema could only hold
 * one answer: `Target.ip_address` was a single column, so a forward
 * lookup returning four addresses was four candidates for one slot.
 * Addresses are many-to-many now, and a host with four addresses simply
 * has four addresses.
 *
 * So the server classifies every result as `auto`, `choice` or
 * `blocked` (the rule, and the argument for where the line falls, is in
 * backend/app/lookups.py) and this dialog follows that classification
 * rather than counting options itself. It had the count rule wired in —
 * "one answer applies on sight, two or more is a question" — and that
 * rule is now wrong in both directions: a partial reverse answer with
 * one name is NOT safe to apply, and several names with one of them
 * already a target IS.
 *
 * The pending list is derived server-side from completed tasks and the
 * current inventory (see backend/app/routers/enumerate.py). There is no
 * "pending choice" table: applying one makes it stop being returned,
 * which is why nothing here has to mark anything done.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog,
  DialogActions, DialogContent, DialogTitle, LinearProgress, MenuItem,
  Stack, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import { Caveat, EnumerateDialog, chipSx } from './EnumerateBits'

/** Add or remove one entry, returning a new Set — the state is held
 *  as a Set and React needs a different object to re-render. */
function toggle(set: Set<string>, v: string, on: boolean): Set<string> {
  const n = new Set(set)
  if (on) n.add(v); else n.delete(v)
  return n
}

export type PendingLookup =
  Awaited<ReturnType<typeof api.enumeratePending>>[number]

/** Choices a person still has to make.
 *
 *  The server's word, not a count of options. Counting was the old
 *  rule and it is wrong at both ends now: a partial reverse answer
 *  naming one host is not safe to apply automatically, and several
 *  names of which one is already a target is. The badge counts these,
 *  so it must never advertise a decision nobody has to take. */
export function openChoices(rows: PendingLookup[] | undefined): PendingLookup[] {
  return (rows ?? []).filter((r) => r.decision === 'choice')
}

/**
 * Results there is nothing to pick from: the lookup found nothing, the
 * scope list refused every name it did find, or somebody already
 * refused them.
 *
 * Kept visible and kept separate. "We looked and found nothing" is a
 * coverage fact worth seeing, and a scope refusal is the operator's cue
 * to edit the scope list — but neither is a question, so folding them
 * in with the open choices would make the badge count things nobody can
 * answer here.
 */
export function emptyResults(rows: PendingLookup[] | undefined): PendingLookup[] {
  return (rows ?? []).filter((r) => r.decision === 'blocked')
}

/** Results the server will apply by itself. Shown, not asked about. */
export function autoResults(rows: PendingLookup[] | undefined): PendingLookup[] {
  return (rows ?? []).filter((r) => r.decision === 'auto')
}

/**
 * Ask the server to apply every lookup result whose answer is not in
 * doubt, and report what it did.
 *
 * The decision no longer lives here. It used to: this hook picked the
 * rows with exactly one option and POSTed each one, which was the best
 * rule available when `ip_address` was a single column. The rule is
 * wrong now in both directions — a partial reverse answer with one name
 * must NOT be applied, and several names with one already a target
 * must — and more to the point it was being made by a browser tab,
 * which is not where a scope decision belongs. The server classifies,
 * the server applies, and one call does the lot.
 *
 * The NAME is kept deliberately. `TargetsView` imports it and is being
 * migrated to TanStack Table by another session; changing the symbol
 * would collide with that work for no benefit the operator can see.
 *
 * Still guarded by a ref. The pending list is recomputed on every cache
 * invalidation and the call itself invalidates, so an unguarded effect
 * is a loop. The guard key is the set of auto-able subjects: when a new
 * lookup finishes the key changes and it runs again.
 */
export function useAutoApplySingles(project: string | null,
                                    rows: PendingLookup[] | undefined) {
  const qc = useQueryClient()
  const tried = useRef<string>('')
  const [failed, setFailed] = useState<string | null>(null)
  //: Kept in the returned shape although the server now merges these
  //: itself. An address-named row taking a name we already hold is no
  //: longer a collision to offer a dialog about — it is the merge the
  //: operator ruled automatic. What can still collide is an FQDN
  //: renaming onto another FQDN, which the server refuses, and this is
  //: where that offer surfaces.
  const [collision, setCollision] = useState<
    { source: string; into: string } | null>(null)

  const auto = useMemo(
    () => autoResults(rows).map((r) => `${r.kind}:${r.subject}`).sort().join(','),
    [rows])

  useEffect(() => {
    if (!project || !auto || tried.current === auto) return
    tried.current = auto
    let live = true
    void (async () => {
      try {
        const r = await api.enumerateAuto(project)
        if (!live) return
        // A refusal is not a failure of the call, and it is the half
        // most worth reading: a name the scope gate turned down is the
        // cue to edit the scope list. Named, never counted.
        const bad = Object.entries(r.refused ?? {})
        if (bad.length) {
          setFailed(`${bad.length} not added — ${bad[0][0]}: ${bad[0][1]}`
                    + (bad.length > 1 ? ` (+${bad.length - 1} more)` : ''))
        }
        await qc.invalidateQueries()
      } catch (e) {
        if (!live) return
        setFailed(e instanceof Error ? e.message : String(e))
      }
    })()
    return () => { live = false }
  }, [project, auto, qc])

  return { failed, collision,
           clear: () => { setFailed(null); setCollision(null) } }
}

function Row({ row, project, onBusy }: {
  row: PendingLookup; project: string; onBusy: (b: boolean) => void
}) {
  const qc = useQueryClient()
  const [pick, setPick] = useState(row.options[0] ?? '')
  //: What to do with the names NOT picked. Unticked on both sides is
  //: the old behaviour — recorded on the timeline and nothing more —
  //: which stays the default because silence is not a decision.
  const [add, setAdd] = useState<Set<string>>(new Set())
  const [deny, setDeny] = useState<Set<string>>(new Set())
  const [err, setErr] = useState<string | null>(null)
  //: What became of the extras, when it is not simply "what you asked".
  const [outcome, setOutcome] = useState<string | null>(null)
  //: The name we tried to apply, when it turned out to belong to a
  //: target that already exists.
  const [merge, setMerge] = useState<string | null>(null)

  const apply = useMutation({
    mutationFn: () => api.enumerateResolve(project, {
      host: row.target_host, field: row.field, value: pick,
      // All of them, not just the pick. Choosing one name does not
      // make the others untrue, and they are often the most useful
      // thing a reverse lookup produces.
      also_resolved: row.options,
      // The pick cannot also be an extra; the server enforces that
      // too, but sending it would be asking for something incoherent.
      add: [...add].filter((n) => n !== pick),
      deny: [...deny].filter((n) => n !== pick),
    }),
    onMutate: () => { setErr(null); setOutcome(null); onBusy(true) },
    onSuccess: (r) => {
      // Scope can refuse an extra while the rename itself succeeds, so
      // a silent success would be a lie about half the request.
      const bad = Object.entries(r.out_of_scope ?? {})
      if (bad.length) {
        setOutcome(`${bad.length} not added — ${bad[0][0]}: ${bad[0][1]}`
                   + (bad.length > 1 ? ` (+${bad.length - 1} more)` : ''))
      }
    },
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
    onSettled: async () => { onBusy(false); await qc.invalidateQueries() },
  })

  const many = row.options.length > 1
  return (
    <Box sx={{ border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1,
               p: 1.2 }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Box sx={{ fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5,
                   color: neon.cyan }}>{row.subject}</Box>
        <Chip size="small" label={row.kind} sx={chipSx(neon.purple)} />
        <Chip size="small" sx={chipSx(many ? neon.yellow : neon.green)}
          label={`${row.options.length} ${row.field === 'host' ? 'name' : 'address'}${
            many ? 's' : ''}`} />
        {row.partial && (
          <Tooltip title={row.note
            ?? 'A source did not answer, so this is a floor and not a total'}>
            <Chip size="small" label="partial" sx={chipSx(neon.orange)} />
          </Tooltip>
        )}
        <Box sx={{ flex: 1 }} />
        <Typography sx={{ fontSize: 10.5, color: neon.muted }}>
          target {row.target_host}
        </Typography>
      </Stack>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}
             alignItems="flex-start" sx={{ mt: 1 }}>
        <TextField select size="small" value={pick} sx={{ flex: 1, minWidth: 260 }}
          onChange={(e) => setPick(e.target.value)}
          label={row.field === 'host' ? 'Use this name' : 'Use this address'}>
          {row.options.map((o) => (
            <MenuItem key={o} value={o}>{o}</MenuItem>
          ))}
        </TextField>
        <Button variant="outlined" disabled={apply.isPending || !pick}
          onClick={() => apply.mutate()} sx={{ mt: 0.3, color: neon.green,
                                               borderColor: alpha(neon.green, 0.6) }}>
          {apply.isPending ? '…' : 'Apply'}
        </Button>
      </Stack>

      {many && (
        <>
          <Caveat>
            More than one name answers for this address, so none of them is
            <i> the</i> name. The one picked becomes this target's; the rest
            are not its names just because they share its address — but each
            is a lead, so say what should happen to them.
          </Caveat>
          <Box sx={{ mt: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
              <Typography sx={{ fontSize: 11, color: neon.muted }}>
                The other {row.options.length - 1}:
              </Typography>
              <Button size="small" sx={{ fontSize: 10.5, color: neon.green,
                                         minWidth: 0 }}
                onClick={() => { setAdd(new Set(row.options)); setDeny(new Set()) }}>
                add all
              </Button>
              <Button size="small" sx={{ fontSize: 10.5, color: neon.red,
                                         minWidth: 0 }}
                onClick={() => { setDeny(new Set(row.options)); setAdd(new Set()) }}>
                deny all
              </Button>
              <Button size="small" sx={{ fontSize: 10.5, color: neon.muted,
                                         minWidth: 0 }}
                onClick={() => { setAdd(new Set()); setDeny(new Set()) }}>
                clear
              </Button>
            </Stack>
            <Stack spacing={0.3}>
              {row.options.filter((o) => o !== pick).map((o) => (
                <Stack key={o} direction="row" spacing={0.5} alignItems="center">
                  <Tooltip title={`Add ${o} to the inventory as its own target. Scope still decides.`}>
                    <Checkbox size="small" checked={add.has(o)}
                      onChange={(e) => {
                        setAdd((p2) => toggle(p2, o, e.target.checked))
                        if (e.target.checked) setDeny((p2) => toggle(p2, o, false))
                      }}
                      sx={{ p: 0.3, color: alpha(neon.green, 0.6),
                            '&.Mui-checked': { color: neon.green } }} />
                  </Tooltip>
                  <Tooltip title={`Refuse ${o}. Remembered, so domain detection does not propose it again.`}>
                    <Checkbox size="small" checked={deny.has(o)}
                      onChange={(e) => {
                        setDeny((p2) => toggle(p2, o, e.target.checked))
                        if (e.target.checked) setAdd((p2) => toggle(p2, o, false))
                      }}
                      sx={{ p: 0.3, color: alpha(neon.red, 0.5),
                            '&.Mui-checked': { color: neon.red } }} />
                  </Tooltip>
                  <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                             fontSize: 12,
                             color: deny.has(o) ? alpha(neon.muted, 0.6)
                                    : add.has(o) ? neon.green : neon.text,
                             textDecoration: deny.has(o) ? 'line-through' : 'none' }}>
                    {o}
                  </Box>
                </Stack>
              ))}
            </Stack>
            <Typography sx={{ fontSize: 10.5, color: neon.muted, mt: 0.5 }}>
              green adds it as a target · red refuses it for good ·
              neither leaves it on the timeline as a lead
            </Typography>
          </Box>
        </>
      )}
      {outcome && (
        <Alert severity="warning" variant="outlined"
          sx={{ mt: 1, fontSize: 11.5 }} onClose={() => setOutcome(null)}>
          {outcome}
        </Alert>
      )}
      {err && (
        <Alert severity="error" variant="outlined"
          sx={{ mt: 1, fontSize: 11.5 }}
          // The collision is not a dead end, it is the answer. The
          // name already exists because this address and that name
          // are the same host, which is precisely when combining them
          // is the right move — so the way forward is offered here
          // rather than leaving the operator to find it on the row.
          action={/already has a target/.test(err) ? (
            <Button size="small" onClick={() => setMerge(pick)}
              sx={{ color: neon.pink, fontSize: 11 }}>
              Combine them
            </Button>
          ) : undefined}>
          {err}
          {/already has a target/.test(err) && (
            <Box sx={{ mt: 0.5, color: neon.muted }}>
              That is usually because they are the same machine, found
              once by address and once by name.
            </Box>
          )}
        </Alert>
      )}
      {merge && (
        <MergeConfirm project={project} source={row.target_host} into={merge}
          onClose={(done) => {
            setMerge(null)
            if (done) { setErr(null); void qc.invalidateQueries() }
          }} />
      )}
    </Box>
  )
}

/** Merging straight out of a name collision.
 *
 *  Narrower than the full dialog on purpose: both ends are already
 *  known — the target being renamed, and the one whose name it wanted
 *  — so there is nothing to choose, only a plan to read and approve. */
function MergeConfirm({ project, source, into, onClose }: {
  project: string; source: string; into: string
  onClose: (done: boolean) => void
}) {
  const plan = useQuery({
    queryKey: ['merge-plan', project, source, into],
    queryFn: () => api.mergePlan(project, source, into),
  })
  const run = useMutation({
    mutationFn: () => api.mergeTargets(project, source, into),
    onSuccess: () => onClose(true),
  })
  const p = plan.data
  const moved = p ? (p.services_moved + p.vulns_moved + p.pocs_moved
                     + p.web_moved + p.implants_moved) : 0
  return (
    <Dialog open onClose={() => onClose(false)} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ color: neon.pink, fontSize: 15 }}>
        Combine {source} into {into}?
      </DialogTitle>
      <DialogContent>
        {plan.isFetching && <CircularProgress size={16} />}
        {p && (
          <Box sx={{ fontSize: 12.5, color: neon.text }}>
            <div>
              {moved === 0
                ? `${source} holds no records of its own.`
                : `${moved} record(s) move to ${into}, and ${source} is removed.`}
            </div>
            {p.service_conflicts.length > 0 && (
              <Box sx={{ mt: 0.8, color: neon.muted }}>
                Ports on both ({p.service_conflicts.join(', ')}) have their
                records combined — nothing a scan saw is dropped.
              </Box>
            )}
            {p.web_duplicates > 0 && (
              <Box sx={{ mt: 0.8, color: neon.muted }}>
                {p.web_duplicates} identical web capture(s) dropped as
                duplicates. That is the only thing removed.
              </Box>
            )}
            {p.warnings.map((w: string) => (
              <Alert key={w} severity="warning" sx={{ mt: 1, fontSize: 11.5 }}>
                {w}
              </Alert>
            ))}
          </Box>
        )}
        {run.error ? <Alert severity="error" sx={{ mt: 1, fontSize: 11.5 }}>
          {String(run.error)}</Alert> : null}
      </DialogContent>
      <DialogActions>
        <Button size="small" onClick={() => onClose(false)}
          sx={{ color: neon.muted }}>Cancel</Button>
        <Button size="small" disabled={!p || run.isPending}
          onClick={() => run.mutate()} sx={{ color: neon.pink }}>
          {run.isPending ? 'Combining…' : 'Combine'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

/**
 * Take every name and address these results offer, in one go.
 *
 * At the very top, because it is the answer most of the time: the
 * operator queued these lookups against their own estate and the
 * results are their own estate. Making them tick through twelve rows to
 * say so is how the twelfth gets skipped.
 *
 * It is not a bypass. Only `applicable` entries are sent — the ones the
 * scope gate already allowed, per name, with the refusals listed beside
 * them — and the server gates again on the way in. What this skips is
 * the clicking, not the checking.
 *
 * The automatic half goes first and separately: it may rename or merge
 * an address-named row, and the choices below are expressed in terms of
 * rows that would then no longer exist.
 */
function AddAllBar({ project, choices, autos, onBusy }: {
  project: string
  choices: PendingLookup[]
  autos: PendingLookup[]
  onBusy: (b: boolean) => void
}) {
  const qc = useQueryClient()
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  const names = useMemo(
    () => choices.reduce((n, r) => n + r.applicable.length, 0), [choices])

  const run = useMutation({
    mutationFn: async () => {
      await api.enumerateAuto(project)
      let taken = 0
      const refused: string[] = []
      for (const r of choices) {
        if (!r.applicable.length) continue
        // The first applicable entry takes the row and the rest are
        // added alongside it. Which one takes it is exactly the
        // question this button is declining to ask — see
        // backend/app/lookups.py — so it is stated in the result
        // rather than hidden, and a row where that matters can still
        // be answered individually below.
        const res = await api.enumerateResolve(project, {
          host: r.target_host, field: r.field, value: r.applicable[0],
          also_resolved: r.options,
          add: r.applicable.slice(1),
        })
        taken += 1 + (res.added?.length ?? 0)
        for (const [n, why] of Object.entries(res.out_of_scope ?? {})) {
          refused.push(`${n}: ${why}`)
        }
      }
      return { taken, refused }
    },
    onMutate: () => { setErr(null); setDone(null); onBusy(true) },
    onSuccess: (r) => setDone(
      `${r.taken} applied`
      + (r.refused.length ? ` · ${r.refused.length} refused — ${r.refused[0]}` : '')),
    onError: (e) => setErr(e instanceof Error ? e.message : String(e)),
    onSettled: async () => { onBusy(false); await qc.invalidateQueries() },
  })

  return (
    <Box sx={{ border: `1px solid ${alpha(neon.green, 0.4)}`, borderRadius: 1,
               p: 1.2 }}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}
             alignItems={{ sm: 'center' }}>
        <Button variant="outlined" disabled={run.isPending || !choices.length}
          onClick={() => run.mutate()}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.6),
                whiteSpace: 'nowrap' }}>
          {run.isPending ? 'Applying…' : 'Add all'}
        </Button>
        <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
          {names} name{names === 1 ? '' : 's'} across {choices.length}{' '}
          outstanding result{choices.length === 1 ? '' : 's'}
          {autos.length > 0 && `, plus ${autos.length} the server applies by itself`}.
          Scope still decides each one on its own.
        </Typography>
      </Stack>
      {done && (
        <Alert severity="success" variant="outlined"
               sx={{ mt: 1, fontSize: 11.5 }}>{done}</Alert>
      )}
      {err && (
        <Alert severity="error" variant="outlined"
               sx={{ mt: 1, fontSize: 11.5 }}>{err}</Alert>
      )}
    </Box>
  )
}

export function FqdnPickerDialog({ project, rows, loading, error, auto,
                                   onClose }: {
  project: string
  /** The pending list, owned by the view so the badge and the dialog
   *  cannot disagree about how many decisions are outstanding. */
  rows: PendingLookup[] | undefined
  loading: boolean
  error: Error | null
  /** A single-answer lookup that could not be applied automatically. */
  auto: {
    failed: string | null
    /** Both ends of a name clash, when the single answer could not be
     *  applied because another target already carries it. */
    collision: { source: string; into: string } | null
    clear: () => void
  }
  onClose: () => void
}) {
  const [busy, setBusy] = useState(false)
  //: A collision the auto-apply hit, once the operator asks to resolve
  //: it by combining the two rows.
  const [autoMerge, setAutoMerge] = useState<
    { source: string; into: string } | null>(null)
  const open = useMemo(() => openChoices(rows), [rows])
  const empty = useMemo(() => emptyResults(rows), [rows])
  const autos = useMemo(() => autoResults(rows), [rows])

  return (
    <EnumerateDialog accent={neon.green} onClose={onClose}
      title={`LOOKUP RESULTS → ${project}`}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {(loading || busy) && (
            <LinearProgress sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                                  '& .MuiLinearProgress-bar': { bgcolor: neon.green } }} />
          )}
          {error && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>
              {error.message}
            </Alert>
          )}
          {auto.failed && (
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}
              action={auto.collision ? (
                <Button size="small" onClick={() => setAutoMerge(auto.collision)}
                  sx={{ color: neon.pink, fontSize: 11 }}>
                  Combine them
                </Button>
              ) : undefined}>
              A lookup with a single answer could not be applied: {auto.failed}
              {auto.collision && (
                <Box sx={{ mt: 0.5, color: neon.muted }}>
                  That usually means {auto.collision.source} and{' '}
                  {auto.collision.into} are the same machine, found once by
                  address and once by name.
                </Box>
              )}
            </Alert>
          )}
          {autoMerge && (
            <MergeConfirm project={project} source={autoMerge.source}
              into={autoMerge.into}
              onClose={(done) => {
                setAutoMerge(null)
                if (done) auto.clear()
              }} />
          )}

          {open.length > 0 && (
            <AddAllBar project={project} choices={open} autos={autos}
                       onBusy={setBusy} />
          )}

          <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
            Built from the output of finished Drone lookups. A host having
            several addresses is not a question, so those are recorded
            without asking. What is left here turns on an address being
            SHARED — several names answer at it and nothing in the data says
            which one owns the row — or on an answer the resolver could not
            finish. Anything with nothing left to pick is listed at the
            bottom, including a name the scope list refused: that is a cue to
            edit the scope list, not a decision to take here.
          </Alert>

          {open.map((r) => (
            <Row key={`${r.kind}:${r.subject}`} row={r} project={project}
                 onBusy={setBusy} />
          ))}

          {!loading && !open.length && !empty.length && (
            <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
              No finished lookups are waiting on a decision. Queue one from the
              Enumerate menu, or from a row's actions.
            </Typography>
          )}

          {empty.length > 0 && (
            <Box>
              <Typography sx={{ fontSize: 10.5, letterSpacing: '0.12em',
                                textTransform: 'uppercase', color: neon.muted,
                                fontFamily: `'Orbitron', sans-serif`, mb: 0.6 }}>
                Reported, with nothing to pick
              </Typography>
              <Stack spacing={0.6}>
                {empty.map((r) => (
                  <Stack key={`${r.kind}:${r.subject}`} direction="row" spacing={1}
                         alignItems="center" flexWrap="wrap" useFlexGap>
                    <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                               fontSize: 12, color: neon.text }}>{r.subject}</Box>
                    <Chip size="small" label={r.kind} sx={chipSx(neon.muted)} />
                    {r.partial && (
                      <Chip size="small" label="a source did not answer"
                            sx={chipSx(neon.orange)} />
                    )}
                    {r.note && (
                      <Typography sx={{ fontSize: 11, color: neon.muted }}>
                        {r.note}
                      </Typography>
                    )}
                    <Box sx={{ flexBasis: '100%' }} />
                    <Typography sx={{ fontSize: 11, color: neon.muted }}>
                      {r.plan}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
              <Caveat>
                These stay listed because they stay true. A lookup that found
                nothing is a fact about what we tried, and clearing it would
                leave the target looking unexamined. A name the scope list
                refused stays for the same reason: it was found, and the
                record should say so even though nothing was done with it.
              </Caveat>
            </Box>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
