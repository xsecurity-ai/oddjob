/**
 * Queue a DNS lookup on a Ghost agent — address to name, or name to
 * address — and say where the answer will come from.
 *
 * Reverse lookup is not just PTR. The agent asks a third-party reverse-IP
 * service as well, because PTR gives only the name the address owner
 * chose and shared hosting or a CDN serves many unrelated names from one
 * address. That means the addresses being looked up leave the agent's
 * host, which is the operator's decision to make knowingly.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, DialogActions, DialogContent,
  FormControlLabel, Stack, Typography, alpha,
} from '@mui/material'
import { useQueryClient } from '@tanstack/react-query'
import { neon } from '../theme'
import { AgentChooser, Caveat, EnumerateDialog, FleetNotice } from './EnumerateBits'
import {
  detach, needsRegion, queueEach, useFleet,
  type AgentChoice, type Report,
} from './ghostTasking'

export type LookupKind = 'reverse_ip' | 'nslookup'

/** How many subjects to show before the list becomes a count. */
const SHOWN = 40

/**
 * "address"/"addresses", "name"/"names".
 *
 * Was built inline as `noun + (n === 1 ? '' : 'es')`, which is right
 * for "address" and gives "namees" for anything else. It reached the
 * operator-facing summary, so the sweep that queued 101 names reported
 * "over 101 namees".
 */
function subjectWord(reverse: boolean, n: number) {
  const one = reverse ? 'address' : 'name'
  return n === 1 ? one : (reverse ? 'addresses' : 'names')
}

export function LookupQueueDialog({ project, kind, subjects, onClose,
                                   onQueued }: {
  project: string
  kind: LookupKind
  /** Addresses for reverse_ip, hostnames for nslookup. */
  subjects: string[]
  onClose: () => void
  /** Reports on the work once it finishes. Called after this has
   *  already closed — see `detach`. Refusals come through here too,
   *  because a closed dialog cannot show them. */
  onQueued?: Report
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [rescan, setRescan] = useState(false)

  // Deduplicated here rather than relying on the agent: one task that
  // looks a thing up twice is two outbound requests about a client's
  // estate for one answer.
  const list = useMemo(
    () => [...new Set(subjects.map((s) => s.trim()).filter(Boolean))], [subjects])

  const reverse = kind === 'reverse_ip'
  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = !list.length || !!fleet.blocked || regionMissing

  const run = () => {
    // Closes now; the answer arrives as a toast. One task per subject
    // over 1,738 addresses is one request that creates 1,738 rows,
    // and holding the modal open for it looks exactly like a hang.
    detach(async () => {
      const { ids, failed, skipped } = await queueEach(
        project, agent, kind, list, {}, region, rescan)
      if (!ids.length) {
        // Everything already answered is a different outcome from
        // everything refused, and the operator needs to know which —
        // one is a scope problem, the other is this declining to
        // repeat itself and telling them how to override it.
        throw new Error(skipped.length && !failed.length
          ? `Nothing was queued. All ${skipped.length} `
            + `${subjectWord(reverse, skipped.length)} have been looked up `
            + `before and came back with nothing. Tick "Rescan `
            + `${reverse ? 'addresses' : 'hosts'} that did not respond" to `
            + `ask again.`
          : `Nothing was queued. ${failed[0]?.why ?? ''}`)
      }
      await qc.invalidateQueries({ queryKey: ['agents'] })
      return `Queued ${ids.length} task${ids.length === 1 ? '' : 's'}, one `
           + `per ${reverse ? 'address' : 'name'}, over ${ids.length} `
           + `${subjectWord(reverse, ids.length)}. `
           + `Results are applied as each Ghost reports back wherever the `
           + `answer is not in doubt; what is genuinely ambiguous waits `
           + `for you on this page. Scope decides every name and address `
           + `on its own either way.`
           + (skipped.length
              ? ` ${skipped.length} skipped as already answered with nothing.`
              : '')
           + (failed.length
              ? ` ${failed.length} refused: ${failed[0].subject} — `
                + `${failed[0].why}`
              : '')
    }, onQueued, onClose,
       `Queueing ${list.length} lookup${list.length === 1 ? '' : 's'}…`)
  }

  return (
    <EnumerateDialog accent={neon.green} onClose={onClose}
      title={reverse ? 'FIND FQDNS FOR ADDRESSES' : 'FIND ADDRESSES FOR NAMES'}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <FleetNotice fleet={fleet} />

          {!list.length ? (
            <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
              {reverse
                ? 'Every target in this selection already carries a name, or has '
                  + 'no address to look up. Nothing to do.'
                : 'Every target in this selection already has an address, or is '
                  + 'not the kind of thing that resolves. Nothing to do.'}
            </Alert>
          ) : (
            <>
              <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
                {reverse
                  ? 'PTR first, then a third-party reverse-IP service — PTR gives '
                    + 'only the name the address owner chose, and one address can '
                    + 'serve many unrelated names. The addresses therefore leave '
                    + 'the agent host. A source that does not answer is reported '
                    + 'as partial rather than as "no names".'
                  : 'A and AAAA records from the agent\'s own resolver. A lookup '
                    + 'that fails is reported as a failure, not as "no address" — '
                    + 'they are different answers.'}
              </Alert>

              <Box>
                <Typography sx={{ fontSize: 10.5, color: neon.muted, mb: 0.5 }}>
                  {list.length} {subjectWord(reverse, list.length)} to look up
                </Typography>
                <Box sx={{
                  maxHeight: '30vh', overflow: 'auto', px: 1.2, py: 0.8,
                  fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
                  color: neon.text, bgcolor: alpha(neon.bgDeep, 0.6),
                  border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1,
                }}>
                  {list.slice(0, SHOWN).join('  ')}
                  {list.length > SHOWN && `  …and ${list.length - SHOWN} more`}
                </Box>
              </Box>

              <AgentChooser fleet={fleet} value={agent} onChange={setAgent}
                region={region} onRegion={setRegion} />

              <FormControlLabel
                control={<Checkbox size="small" checked={rescan}
                  onChange={(e) => setRescan(e.target.checked)} />}
                label={<Box sx={{ fontSize: 13 }}>
                  Rescan {reverse ? 'addresses' : 'hosts'} that did not respond
                </Box>} />
              <Caveat>
                Off, a subject a previous run answered with <i>nothing</i> is
                skipped rather than asked again — the answer is already known
                and asking costs another outbound request about the client's
                estate. On, every subject is queued regardless.
                <br />
                This never hides a lookup that <b>failed</b>. An error, a
                timeout, or a reverse result flagged partial means the
                question was not answered, so it is always asked again
                without needing this box. Only a resolver positively saying
                "no records" counts as answered.
              </Caveat>

              <Caveat>
                One task per subject, so a slow source holds up one answer
                rather than all of them. Results come back as they finish and
                most are applied without asking: a host having several
                addresses is not a decision. What is left for you turns on an
                address being shared between names, or on a resolver that did
                not finish.
              </Caveat>
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="outlined" disabled={stop} onClick={run}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.6) }}>
          Queue lookup
        </Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
