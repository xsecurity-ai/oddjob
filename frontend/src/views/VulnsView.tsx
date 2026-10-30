import { useState } from 'react'
import { Box, Chip, MenuItem, Select, Stack, Tab, Tabs, TextField, alpha } from '@mui/material'
import type { ColumnDef } from '../lib/columns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, SEVERITY_RANK, type Vuln } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { ImportReportButton } from '../components/ImportReportButton'
import { useHostModal } from '../components/HostModal'
import { VulnModal } from '../components/VulnModal'
import { PocModal } from '../components/PocModal'
import { SEVERITY_COLOUR as SEV_COLOUR } from '../lib/severity'
import { TRIAGE, TRIAGE_COLOUR } from '../lib/triage'
import {
  LIFECYCLE, LIFECYCLE_COLOUR, LIFECYCLE_LABEL, LIFECYCLE_RANK,
  POC_COLOUR, POC_LABEL, POC_RANK, POC_STATES,
} from '../lib/lifecycle'
import { useAuth } from '../lib/auth'
import { useStoredChoice } from '../lib/useStoredChoice'
import { AutoPocButton } from '../components/AutoPocButton'
import { SecretsPanel } from '../components/SecretsPanel'
import { VulnsByTarget, VulnsByTitle } from '../components/VulnRollupPanel'
import { LifecycleStrip } from '../components/LifecycleStrip'
import { neon, glow, TAB_SX } from '../theme'

/** Module-level so the stored-choice hook gets a stable reference,
 *  and so the validated set and the rendered tabs cannot drift. */
const VULN_TABS = ['all', 'by-target', 'by-vuln', 'secrets'] as const


export function VulnsView({ project }: { project: string | null }) {
  const { open } = useHostModal()
  // Which tab you were on survives a reload. Refreshing on Secrets
  // and landing back on All means re-finding your place every time
  // the page reloads, which on a long triage is most of the session.
  const [tab, setTab] = useStoredChoice('vulns.tab', VULN_TABS, 'all')
  const [detail, setDetail] = useState<number | null>(null)
  // The proof being read, separate from the finding being read: the
  // PoC chip opens the script without opening the finding behind it.
  const [poc, setPoc] = useState<{ id: number; title: string } | null>(null)
  const [selected, setSelected] = useState<number[]>([])
  // Named back by the server rather than silently skipped.
  const [refused, setRefused] = useState(0)
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const { data, isLoading, error } = useQuery({
    queryKey: ['vulns', project],
    queryFn: () => api.vulns(project ?? undefined),
  })

  const columns: ColumnDef<Vuln>[] = [
    {
      field: 'severity', headerName: 'Severity', width: 112,
      type: 'singleSelect',
      valueOptions: ['critical', 'high', 'medium', 'low', 'info'],
      // Severity is a string, so the default comparator sorts it
      // alphabetically: critical, high, info, low, medium. That puts "info"
      // third and is actively misleading, so rank explicitly.
      sortComparator: (a, b) =>
        (SEVERITY_RANK[a as string] ?? 9) - (SEVERITY_RANK[b as string] ?? 9),
      renderCell: (p) => {
        const c = SEV_COLOUR[p.value] ?? neon.muted
        return (
          <Chip size="small" label={p.value} sx={{
            height: 20, fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase',
            bgcolor: alpha(c, 0.16), color: c,
            border: `1px solid ${alpha(c, 0.6)}`, textShadow: glow(c, 0.45),
          }} />
        )
      },
    },
    {
      field: 'host', headerName: 'Host', flex: 1, minWidth: 210,
      renderCell: (p) => (
        <Box
          onClick={() => open(p.row.project_code, p.row.host)}
          sx={{
            color: neon.pink, textShadow: glow(neon.pink, 0.35), fontWeight: 600,
            cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) },
          }}
        >{p.value}</Box>
      ),
    },
    {
      field: 'title', headerName: 'Title', flex: 3, minWidth: 320,
      // The detail, the fix and the list of affected hosts do not fit
      // in a cell, and "where else is this?" is the first question
      // anyone has in front of a finding.
      renderCell: (p) => (
        <Box
          onClick={(e) => { e.stopPropagation(); setDetail(p.row.id) }}
          sx={{
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            cursor: 'pointer', color: neon.text,
            '&:hover': { color: neon.cyan, textShadow: glow(neon.cyan, 0.5) },
          }}
          title="Show the full finding">
          {p.value}
        </Box>
      ),
    },
    {
      // What the last scan SAW, as distinct from Status (what has
      // been done about it) and Triage (what a person concluded).
      // Three different questions, and this is the one nothing could
      // answer before: a finding from March sat at `open` for ever
      // through re-scans that no longer saw it.
      field: 'lifecycle', headerName: 'Last scan', width: 128,
      type: 'singleSelect',
      valueOptions: [...LIFECYCLE],
      sortComparator: (a, b) =>
        (LIFECYCLE_RANK[a as string] ?? 9) - (LIFECYCLE_RANK[b as string] ?? 9),
      renderCell: (p) => {
        const c = LIFECYCLE_COLOUR[p.value] ?? neon.muted
        return (
          // The sentence behind the word, on hover. `Resolved` is a
          // claim about a client's estate and a reader is entitled
          // to see what it rests on without opening the finding.
          <Chip size="small" label={LIFECYCLE_LABEL[p.value] ?? p.value}
            title={p.row.lifecycle_why ?? ''} sx={{
              height: 20, fontSize: 10, letterSpacing: '0.06em',
              bgcolor: alpha(c, 0.14), color: c,
              border: `1px solid ${alpha(c, 0.55)}`, cursor: 'help',
            }} />
        )
      },
    },
    {
      // Three states, because there are three answers. Available
      // means a script EXISTS; Confirmed means it ran here and
      // worked. The middle one is the one worth having: a proof
      // that needs a credential nobody has, or a person to click a
      // link, is real work that cannot be run from here -- neither
      // "no proof" nor "proven".
      field: 'poc_state', headerName: 'PoC', width: 168,
      type: 'singleSelect',
      valueOptions: [...POC_STATES],
      sortComparator: (a, b) =>
        (POC_RANK[a as string] ?? 9) - (POC_RANK[b as string] ?? 9),
      renderCell: (p) => {
        const c = POC_COLOUR[p.value] ?? neon.muted
        const has = p.row.poc_id !== null && p.row.poc_id !== undefined
        return (
          <Chip size="small" label={POC_LABEL[p.value] ?? p.value}
            onClick={has ? (e) => {
              // The row's own click opens the finding; this opens
              // the proof. Without this the modal would open behind
              // the finding drawer.
              e.stopPropagation()
              setPoc({ id: p.row.poc_id as number, title: p.row.title })
            } : undefined}
            title={p.row.poc_detail
              ?? (has ? 'Open the script' : 'No proof has been written')}
            sx={{
              height: 20, fontSize: 10, letterSpacing: '0.06em',
              bgcolor: alpha(c, 0.14), color: c,
              border: `1px solid ${alpha(c, 0.55)}`,
              cursor: has ? 'pointer' : 'help',
              '&:hover': has ? { bgcolor: alpha(c, 0.26) } : undefined,
            }} />
        )
      },
    },
    {
      field: 'status', headerName: 'Status', width: 104,
      renderCell: (p) => (
        <Box sx={{ color: p.value === 'open' ? neon.yellow : neon.muted }}>{p.value}</Box>
      ),
    },
    {
      // What a PERSON concluded. Next to Status on purpose: they are
      // adjacent questions and reading them together is the point.
      field: 'triage', headerName: 'Triage', width: 178,
      renderCell: (p) => (
        <Select size="small" variant="standard" disableUnderline
          value={String(p.value ?? 'needs_investigating')}
          disabled={!canWrite(project) || mark.isPending}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => mark.mutate({
            ids: [Number((p.row as { id: number }).id)],
            triage: e.target.value,
          })}
          sx={{
            fontSize: 11.5,
            color: TRIAGE_COLOUR[String(p.value ?? 'needs_investigating')],
            '& .MuiSelect-select': { py: 0 },
          }}>
          {TRIAGE.map((t) => (
            <MenuItem key={t.value} value={t.value}
              sx={{ fontSize: 12, color: t.colour }}>{t.label}</MenuItem>
          ))}
        </Select>
      ),
    },
    { field: 'port', headerName: 'Port', width: 82, type: 'number',
      valueGetter: (v) => v ?? null,
      renderCell: (p) => p.value == null
        ? <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
        : <Box sx={{ color: neon.cyan }}>{p.value}</Box> },
    { field: 'external_id', headerName: 'Source ID', width: 150,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (
        <Box sx={{ color: alpha(neon.muted, 0.85), fontSize: 11.5 }}>{p.value}</Box>
      ) },
    { field: 'project_code', headerName: 'Project', width: 130,
      renderCell: (p) => (
        <Box sx={{ color: neon.purple, fontSize: 11.5, letterSpacing: '0.06em' }}>{p.value}</Box>
      ) },
  ]

  // Bulk triage. The selection can span projects when no project is
  // chosen, so the server checks permission per finding and names
  // back anything it refused -- a bulk action that silently skipped
  // rows would look like it had worked.
  const mark = useMutation({
    mutationFn: ({ ids, triage }: { ids: number[]; triage: string }) =>
      ids.length === 1
        ? api.setTriage(ids[0], triage)
        : api.setTriageBulk(ids, triage),
    onSuccess: (r) => {
      setRefused(r.refused?.length ?? 0)
      void qc.invalidateQueries({ queryKey: ['vulns'] })
    },
  })

  /* Two readings of the same findings. Secrets are not a severity
     or a filter on the grid above: the question there is "what is
     wrong with this estate", and the question here is "which of
     these several hundred candidate values is a real credential,
     and do any of them come from the same file" -- which needs the
     value and its origin side by side, and neither belongs in a
     column of the main table. */
  const strip = (
    <Tabs value={tab} onChange={(_, v) => setTab(v)}
      sx={{ minHeight: 34, px: 2, pt: 1,
            borderBottom: `1px solid ${alpha(neon.purple, 0.25)}` }}>
      <Tab value="all" label="All" sx={TAB_SX} />
      {/* The same findings asked two other ways, right after All
          because they are readings of it rather than a different
          dataset -- Secrets is the one that is a different question. */}
      <Tab value="by-target" label="By Target" sx={TAB_SX} />
      <Tab value="by-vuln" label="By Vuln" sx={TAB_SX} />
      <Tab value="secrets" label="Secrets" sx={TAB_SX} />
    </Tabs>
  )

  // Both panels are returned as siblings of the strip in a FRAGMENT,
  // not inside a wrapper, and that is load-bearing rather than tidy.
  // `DataTable`'s own root is `flex: 1; min-height: 0`, so it sizes
  // itself only when its parent is a flex column -- here, the one App
  // puts every view in. Wrapping it in a plain `<Box flex={1}>` gave
  // it an auto height instead, the grid grew to its full content, and
  // the Secrets table could not be scrolled at all.
  // Siblings of the strip in a fragment, for the reason spelled out
  // below: these panels size themselves against the view's flex
  // column and a wrapper would give them an auto height.
  if (tab === 'by-target' || tab === 'by-vuln') {
    return (
      <>
      {strip}
      {tab === 'by-target'
        ? <VulnsByTarget project={project} onFinding={setDetail} />
        : <VulnsByTitle project={project} onFinding={setDetail} />}
      <VulnModal id={detail} onClose={() => setDetail(null)}
        onHost={(proj, h) => { setDetail(null); open(proj, h) }} />
      </>
    )
  }

  if (tab === 'secrets') {
    return (
      <>
      {strip}
      <SecretsPanel project={project} onFinding={setDetail} />
      <VulnModal id={detail} onClose={() => setDetail(null)}
        onHost={(proj, h) => { setDetail(null); open(proj, h) }} />
      </>
    )
  }

  return (
    <>
      {strip}
      {/* Inside a plain Box with its own padding, NOT a flex child:
          the DataTable below has to stay the only thing that grows,
          or it sizes to its content and the table stops scrolling. */}
      <Box sx={{ px: 2, pt: 1 }}>
        <LifecycleStrip project={project} />
      </Box>
      <DataTable
        rows={data?.items ?? []}
        columns={columns as ColumnDef[]}
        loading={isLoading}
        error={error as Error | null}
        initialSort={{ field: 'severity', sort: 'asc' }}   // asc on rank = worst first
        hiddenColumns={project ? { project_code: false } : undefined}
        kind="vulns"
        project={project}
        canWrite={canWrite(project)}
        note={canWrite(project) ? undefined : 'read-only'}
        onSelectionChange={setSelected}
        extraActions={canWrite(project) ? (
          <Stack direction="row" spacing={1} sx={{
            alignItems: "center"
          }}>
            {selected.length > 0 && (
              <TextField select size="small" value=""
                disabled={mark.isPending}
                onChange={(e) => mark.mutate({
                  ids: selected, triage: e.target.value,
                })}
                sx={{ minWidth: 210 }}
                slotProps={{ inputLabel: { shrink: true } }}
                label={`Mark ${selected.length} selected`}>
                {TRIAGE.map((t) => (
                  <MenuItem key={t.value} value={t.value}
                    sx={{ fontSize: 12.5, color: t.colour }}>{t.label}</MenuItem>
                ))}
              </TextField>
            )}
            {refused > 0 && (
              <Box sx={{ fontSize: 11.5, color: neon.red }}>
                {refused} could not be changed — no write access on that
                engagement.
              </Box>
            )}
            {/* Beside the import button: both are "do something to
                this engagement's findings", and this is the one that
                sends traffic. */}
            <AutoPocButton project={project} />
            <ImportReportButton project={project} />
          </Stack>
        ) : undefined}
      />
      <VulnModal id={detail} onClose={() => setDetail(null)}
        onHost={(proj, h) => { setDetail(null); open(proj, h) }} />
      {/* Only on this tab: the PoC column lives in the findings
          table, and the rollup tabs show a collapsed row that no
          single proof belongs to. */}
      {poc && project && (
        <PocModal project={project} pocId={poc.id} title={poc.title}
          onClose={() => setPoc(null)} />
      )}
    </>
  );
}
