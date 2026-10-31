import { useEffect, useMemo, useState } from 'react'
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog,
  DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel,
  Radio, RadioGroup, Stack, TextField, Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Target } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * Fold one target into another.
 *
 * The plan is fetched and shown before anything happens, and the
 * confirm button stays off until it has been. Merging moves findings
 * between rows and then deletes one — approving the word "merge" is
 * not the same as approving a specific list of consequences, and the
 * list is the only thing that tells you whether this is the merge you
 * meant.
 */
export function MergeTargetsDialog({ project, source, candidates, onClose,
                                    onMerged }: {
  project: string
  /** The target that will be absorbed and removed. */
  source: Target
  /** Every target that could be merged into, when the caller already
   *  holds the list. Omitted, the dialog fetches it on the same query
   *  key the targets view uses, so opening this from somewhere with no
   *  list -- the target window -- costs nothing where there is one and
   *  one fetch where there is not. */
  candidates?: Target[]
  onClose: () => void
  /** The merge happened. The source row is GONE, so a caller showing
   *  it has to do something about that -- the target window closes
   *  rather than sitting on a 404. */
  onMerged?: (survivingHost: string) => void
}) {
  const qc = useQueryClient()

  // Type-ahead against the database, not a copy of the project.
  //
  // The first version of this fetched every target so the Autocomplete
  // could filter them in the browser. On a real engagement that is
  // 10,105 rows and 8.5 MB, and the box sat on "Loading..." until it
  // arrived -- which read as a hang, because for the several seconds
  // it took that is exactly what it was.
  //
  // Searching in SQL also means the match is against every target
  // rather than against whichever ones were loaded, which is the same
  // correctness point the web listing's own comment makes.
  const [typed, setTyped] = useState('')
  const [term, setTerm] = useState('')
  useEffect(() => {
    const t = window.setTimeout(() => setTerm(typed.trim()), 250)
    return () => window.clearTimeout(t)
  }, [typed])

  const found = useQuery({
    queryKey: ['target-search', project, term],
    queryFn: () => api.searchTargets(project, term),
    // Nothing typed is not a reason to fetch the whole project. Two
    // characters is where a search starts being a search.
    enabled: !candidates && term.length >= 2,
    placeholderData: (prev) => prev,
  })

  // A caller that already holds the list keeps filtering in the
  // browser: the grid has the rows in hand and a second round trip
  // would be slower than the work it saves.
  const options = useMemo(
    () => candidates ?? found.data?.items ?? [],
    [candidates, found.data])
  const [into, setInto] = useState<Target | null>(null)
  // Which name the surviving row carries. Defaults to the
  // destination's, which is what a merge did before the choice
  // existed, so the quick path is unchanged for anyone not
  // interested in it.
  const [keep, setKeep] = useState<string | null>(null)
  const keeping = keep ?? into?.host ?? null

  const plan = useQuery({
    queryKey: ['merge-plan', project, source.host, into?.host],
    queryFn: () => api.mergePlan(project, source.host, into!.host),
    enabled: !!into,
  })

  const run = useMutation({
    mutationFn: () => api.mergeTargets(project, source.host, into!.host,
                                       keeping ?? undefined),
    onSuccess: async (res) => {
      // The SERVER's answer for what the row ended up called, not a
      // recomputation of it here. The rename happens after the source
      // row is deleted and the route reports the name the survivor
      // actually carries; deriving it a second time in the client is
      // the two-readings mistake this codebase keeps paying for.
      const survivor = res?.surviving ?? keeping ?? into!.host
      await qc.invalidateQueries()
      onMerged?.(survivor)
      onClose()
    },
  })

  const p = plan.data
  const blocking = (p?.warnings ?? []).filter(
    (w) => w.startsWith('a target cannot') || w.startsWith('these targets are'))
  const advisory = (p?.warnings ?? []).filter((w) => !blocking.includes(w))

  const moved: Array<[number, string]> = p ? [
    [p.services_moved, 'service'], [p.vulns_moved, 'finding'],
    [p.pocs_moved, 'PoC'], [p.web_moved, 'web exchange'],
    [p.implants_moved, 'implant'], [p.events_moved, 'timeline entry'],
  ] : []

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.4) }}>
        Combine {source.host} with another target
      </DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ color: neon.muted, mb: 2 }}>
          Everything <strong>{source.host}</strong> holds moves to the target
          you pick, and the {source.host} row is removed. You choose which of
          the two names the surviving row carries — the other is kept on it as
          an alternate name, so nothing stops answering to what it answered to.
        </Typography>

        <Autocomplete
          loading={found.isFetching}
          options={options.filter((t) => t.host !== source.host)}
          // The server already matched; filtering again here would
          // hide rows it deliberately returned.
          filterOptions={candidates ? undefined : (x) => x}
          noOptionsText={
            candidates ? 'No match'
              : term.length < 2 ? 'Type at least two characters'
              : found.isFetching ? 'Searching...' : 'No match'}
          getOptionLabel={(t) => t.host}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          value={into}
          onChange={(_e, v) => setInto(v)}
          onInputChange={(_e, v, reason) => {
            if (reason === 'input') setTyped(v)
            // A new destination makes the old name choice meaningless.
            // Clearing it rather than carrying it over: a stale
            // `keep` pointing at a row no longer in the merge is the
            // kind of thing that silently renames the wrong host.
            if (reason !== 'reset') setKeep(null)
          }}
          renderInput={(params) => (
            <TextField {...params} size="small" label="Merge into" autoFocus
              helperText="This row survives and absorbs the other." />
          )}
        />

        {into && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="overline" sx={{ color: neon.cyan }}>
              What the surviving row is called
            </Typography>
            <RadioGroup value={keeping ?? ''}
              onChange={(e) => setKeep(e.target.value)}>
              {[into.host, source.host].map((h) => (
                <FormControlLabel key={h} value={h}
                  control={<Radio size="small" sx={{ color: neon.muted,
                                 '&.Mui-checked': { color: neon.green } }} />}
                  label={
                    <Typography sx={{ fontSize: 12.5,
                                      fontFamily: `'Share Tech Mono', monospace`,
                                      color: keeping === h ? neon.green
                                                           : neon.muted }}>
                      {h}
                      <Box component="span" sx={{ fontSize: 10.5,
                                                  color: neon.muted,
                                                  ml: 1,
                                                  fontFamily: 'inherit' }}>
                        {h === into.host
                          ? "the row that survives — its own name"
                          : "the absorbed row's name, moved onto the survivor"}
                      </Box>
                    </Typography>
                  } />
              ))}
            </RadioGroup>
          </Box>
        )}

        {plan.isFetching && (
          <Stack
            direction="row"
            spacing={1}
            sx={{
              alignItems: "center",
              mt: 2
            }}>
            <CircularProgress size={14} />
            <Typography variant="caption" sx={{ color: neon.muted }}>
              Working out what would move…
            </Typography>
          </Stack>
        )}

        {p && (
          <Box sx={{ mt: 2 }}>
            {blocking.map((w) => (
              <Alert key={w} severity="error" sx={{ mb: 1 }}>{w}</Alert>
            ))}
            {advisory.map((w) => (
              <Alert key={w} severity="warning" sx={{ mb: 1 }}>{w}</Alert>
            ))}

            <Typography variant="overline" sx={{ color: neon.cyan }}>
              What moves
            </Typography>
            <Stack
              direction="row"
              spacing={0.8}
              useFlexGap
              sx={{
                flexWrap: "wrap",
                mt: 0.5
              }}>
              {moved.filter(([n]) => n > 0).map(([n, what]) => (
                <Chip key={what} size="small"
                  label={`${n} ${what}${n === 1 ? '' : 's'}`}
                  sx={{ height: 20, fontSize: 11, color: neon.green,
                        bgcolor: alpha(neon.green, 0.12) }} />
              ))}
              {moved.every(([n]) => n === 0) && (
                <Typography variant="caption" sx={{ color: neon.muted }}>
                  Nothing — {source.host} holds no records of its own.
                </Typography>
              )}
            </Stack>

            {(p.service_conflicts.length > 0 || p.implant_conflicts.length > 0
              || p.web_duplicates > 0) && (
              <>
                <Divider sx={{ my: 1.5, borderColor: alpha(neon.cyan, 0.15) }} />
                <Typography variant="overline" sx={{ color: neon.yellow }}>
                  Seen on both
                </Typography>
                <Box sx={{ color: neon.muted, fontSize: 12, mt: 0.5 }}>
                  {p.service_conflicts.length > 0 && (
                    <div>
                      Ports {p.service_conflicts.join(', ')} are on both. The
                      two records are combined — anything only one scan saw,
                      like a version or a banner, is kept.
                    </div>
                  )}
                  {p.implant_conflicts.length > 0 && (
                    <div>Implants already present: {p.implant_conflicts.join(', ')}.</div>
                  )}
                  {p.web_duplicates > 0 && (
                    // The only thing a merge actually removes, so it
                    // is stated rather than buried.
                    <div>
                      {p.web_duplicates} web exchange(s) are byte-identical to
                      ones already held and will be dropped as duplicates.
                      This is the only thing a merge deletes.
                    </div>
                  )}
                </Box>
              </>
            )}

            {(p.fields_filled.length > 0 || p.fields_differing.length > 0) && (
              <>
                <Divider sx={{ my: 1.5, borderColor: alpha(neon.cyan, 0.15) }} />
                <Box sx={{ color: neon.muted, fontSize: 12 }}>
                  {p.fields_filled.length > 0 && (
                    <div>Fills in: {p.fields_filled.join('; ')}</div>
                  )}
                  {p.fields_differing.length > 0 && (
                    <div>
                      Differs, the surviving row keeps its own:{' '}
                      {p.fields_differing.join('; ')} — the other value goes
                      on the timeline.
                    </div>
                  )}
                </Box>
              </>
            )}
          </Box>
        )}

        {run.error ? <Alert severity="error" sx={{ mt: 2 }}>
          {String(run.error)}</Alert> : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button
          // Off until a plan has come back: the whole point is that
          // what is approved is the list, not the verb.
          disabled={!p || blocking.length > 0 || run.isPending || plan.isFetching}
          onClick={() => run.mutate()}
          sx={{ color: neon.red }}>
          {run.isPending ? 'Merging…'
            : keeping ? `Merge, keeping ${keeping}` : 'Merge'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
