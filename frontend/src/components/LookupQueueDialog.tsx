/**
 * Queue a DNS lookup on a Jaws agent — address to name, or name to
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
  Alert, Box, Button, DialogActions, DialogContent, Stack, Typography, alpha,
} from '@mui/material'
import { useQueryClient } from '@tanstack/react-query'
import { neon } from '../theme'
import { AgentChooser, Caveat, EnumerateDialog, FleetNotice } from './EnumerateBits'
import { needsRegion, queue, useFleet, type AgentChoice } from './jawsTasking'

export type LookupKind = 'reverse_ip' | 'nslookup'

/** How many subjects to show before the list becomes a count. */
const SHOWN = 40

export function LookupQueueDialog({ project, kind, subjects, onClose }: {
  project: string
  kind: LookupKind
  /** Addresses for reverse_ip, hostnames for nslookup. */
  subjects: string[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  // Deduplicated here rather than relying on the agent: one task that
  // looks a thing up twice is two outbound requests about a client's
  // estate for one answer.
  const list = useMemo(
    () => [...new Set(subjects.map((s) => s.trim()).filter(Boolean))], [subjects])

  const reverse = kind === 'reverse_ip'
  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = !list.length || !!fleet.blocked || regionMissing

  const run = async () => {
    setBusy(true); setErr(null)
    try {
      const t = await queue(project, agent, kind, { targets: list }, region)
      setDone(`Queued as task ${t.id} over ${list.length} `
              + `${reverse ? 'address' : 'name'}${list.length === 1 ? '' : 'es'}. `
              + `Results appear on this page as "choices waiting" once the `
              + `agent reports back — nothing is written to the inventory `
              + `until you pick.`)
      await qc.invalidateQueries({ queryKey: ['agents'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <EnumerateDialog accent={neon.green} onClose={onClose}
      title={reverse ? 'FIND FQDNS FOR ADDRESSES' : 'FIND ADDRESSES FOR NAMES'}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}
          {done && <Alert severity="success" variant="outlined" sx={{ fontSize: 12.5 }}>{done}</Alert>}
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
                  {list.length} {reverse ? 'address' : 'name'}
                  {list.length === 1 ? '' : 'es'} to look up
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

              <Caveat>
                One task, not one per subject. The agent works through them in
                order and reports the lot, so a slow source delays the answer
                rather than losing it.
              </Caveat>
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="outlined" disabled={busy || stop} onClick={run}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.6) }}>
          {busy ? '…' : 'Queue lookup'}
        </Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
