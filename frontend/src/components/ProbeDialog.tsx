/**
 * httpx and nuclei, which have never run.
 *
 * Both have been runnable by the agent, importable by the server and
 * storable in the schema since long before this file. Neither had
 * ever run on any install, on a project carrying 122,542 web
 * addresses, because the only place they were named in the frontend
 * was a `GHOST_KINDS` constant that no component read. The runners,
 * the task kinds and the importers were all already correct; there
 * was simply no way to press go.
 *
 * **They take different subjects and that is not cosmetic.** httpx
 * probes a HOST — finding out whether anything answers on the web
 * ports, what it is and what certificate it presents is the whole
 * job — so pointing it at a URL throws away the discovery. nuclei
 * runs templates against a URL that is already known to be there,
 * and a bare hostname gives it nothing to request. The server
 * decides which is which (`webtargets.PROBE_KINDS`); this dialog
 * reports it rather than having its own opinion.
 */
import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Checkbox, FormControlLabel, Stack, Typography,
} from '@mui/material'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon } from '../theme'
import {
  AgentChooser, Caveat, EnumerateDialog, FleetNotice, chipSx,
} from './EnumerateBits'
import {
  detach, needsRegion, queueEach, useFleet,
  type AgentChoice, type Report,
} from './ghostTasking'

/** How many subjects to list before it becomes a count. */
const SHOWN = 25

const BLURB: Record<'httpx' | 'nuclei', { title: string; hint: string }> = {
  httpx: {
    title: 'PROBE FOR WEB SERVICES',
    hint: 'One request per host. Reports what answered, what it is '
        + 'built on, and the certificate — whose subject alternative '
        + 'names are the richest source of hostnames in the estate.',
  },
  nuclei: {
    title: 'TEMPLATE SCAN',
    hint: 'Runs the template set against URLs already known to be '
        + 'there. This is the one tool here that is looking for '
        + 'findings rather than inventory, and it is the loudest.',
  },
}

export function ProbeDialog({ project, tool, onClose, onQueued }: {
  project: string
  tool: 'httpx' | 'nuclei'
  onClose: () => void
  onQueued?: Report
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [kitchenSink, setKitchenSink] = useState(false)

  const pending = useQuery({
    queryKey: ['probe-pending', project, tool, kitchenSink],
    queryFn: () => api.probePending(project, tool, kitchenSink),
    enabled: !!project,
  })

  const d = pending.data
  const subjects = d?.subjects ?? []
  const repeats = d?.repeats ?? 0
  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = !subjects.length || !!fleet.blocked || regionMissing

  const run = () => {
    // Snapshotted before closing, like every other queue here: the
    // work must run against what was on screen when Queue was
    // pressed, not whatever a refetch produces after it has gone.
    const planned = [...subjects]
    detach(async () => {
      const r = await queueEach(project, agent, tool, planned, {}, region,
                                false, kitchenSink)
      if (!r.ids.length) {
        throw new Error(
          r.alreadyDone.length
            ? `Nothing was queued: all ${r.alreadyDone.length} had already `
              + 'been done.'
            : `Nothing was queued. ${r.failed[0]?.why ?? ''}`)
      }
      await qc.invalidateQueries({ queryKey: ['agents'] })
      await qc.invalidateQueries({ queryKey: ['probe-pending', project] })
      return `Queued ${r.ids.length} ${tool} task`
           + `${r.ids.length === 1 ? '' : 's'}. Results import into `
           + `${project} as each reports back.`
           + (r.failed.length
              ? ` ${r.failed.length} refused: ${r.failed[0].subject} — `
                + `${r.failed[0].why}`
              : '')
    }, onQueued, onClose,
       `Queueing ${planned.length} ${tool} task`
       + `${planned.length === 1 ? '' : 's'}…`)
  }

  return (
    <EnumerateDialog accent={neon.green} onClose={onClose}
      title={`${BLURB[tool].title} → ${project}`}>
      <Stack spacing={1.6}>
        <Caveat>{BLURB[tool].hint}</Caveat>

        {/* Called what it does. "Kitchen Sink" was the same switch
            under a name that sounded like a scope setting, so the
            dialog appeared to offer a choice about WHICH subjects --
            and the only thing the flag changes is whether ones
            already done are included.
            `probe_owed` computes the subject list identically either
            way; off, it subtracts what has been run. So the default
            IS incremental, and this is the opt-in to repeat it. */}
        <FormControlLabel
          control={<Checkbox size="small" checked={kitchenSink}
            onChange={(e) => setKitchenSink(e.target.checked)} />}
          label={<Box sx={{ fontSize: 13 }}>
            Rescan targets — run {tool} again on subjects it has already
            been pointed at
          </Box>} />
        {/* The cost of the tick, stated. The count alone reads the
            same with it on and off, which is how a project came to
            re-run every crawl it had four times in 45 hours. */}
        {!!repeats && (
          <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
            {repeats === subjects.length
              ? `All ${repeats} of these have been run before. This repeats `
                + 'every one of them against the client.'
              : `${repeats} of ${subjects.length} have been run before and `
                + 'will be run again against the client.'}
          </Alert>
        )}

        <AgentChooser fleet={fleet} value={agent} onChange={setAgent}
          region={region} onRegion={setRegion} />

        {pending.isLoading ? (
          <Typography sx={{ fontSize: 12, color: neon.muted }}>
            Working out what is left…
          </Typography>
        ) : !subjects.length ? (
          <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
            {d?.considered
              ? `Every ${d.takes} on this project has already been through `
                + `${tool}. Tick Rescan targets to run it again.`
              : `Nothing to point ${tool} at yet. `
                + (tool === 'nuclei'
                   ? 'It needs URLs — port-scan or crawl something first.'
                   : 'Add some targets first.')}
          </Alert>
        ) : (
          <>
            <Stack
              direction="row"
              spacing={1}
              useFlexGap
              sx={{
                alignItems: "center",
                flexWrap: "wrap"
              }}>
              <Chip size="small" sx={chipSx(neon.green)}
                label={`${subjects.length} ${d?.takes ?? 'subject'}${
                  subjects.length === 1 ? '' : 's'}`} />
              {!!d?.out_of_scope && (
                <Chip size="small" sx={chipSx(neon.yellow)}
                  label={`${d.out_of_scope} out of scope`} />
              )}
            </Stack>
            <Box sx={{
              fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
              color: neon.muted, maxHeight: 180, overflowY: 'auto',
            }}>
              {subjects.slice(0, SHOWN).map((s) => <div key={s}>{s}</div>)}
              {subjects.length > SHOWN && (
                <div>…and {subjects.length - SHOWN} more</div>
              )}
            </Box>
          </>
        )}

        <FleetNotice fleet={fleet} />
        <Button variant="outlined" disabled={stop} onClick={run}>
          Queue {subjects.length || ''} {tool} task
          {subjects.length === 1 ? '' : 's'}
        </Button>
      </Stack>
    </EnumerateDialog>
  );
}
