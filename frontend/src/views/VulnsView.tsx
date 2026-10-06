import { useState } from 'react'
import { Box, Chip, alpha } from '@mui/material'
import type { GridColDef } from '@mui/x-data-grid'
import { useQuery } from '@tanstack/react-query'
import { api, SEVERITY_RANK, type Vuln } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { ImportReportButton } from '../components/ImportReportButton'
import { useHostModal } from '../components/HostModal'
import { VulnModal } from '../components/VulnModal'
import { SEVERITY_COLOUR as SEV_COLOUR } from '../lib/severity'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'



export function VulnsView({ project }: { project: string | null }) {
  const { open } = useHostModal()
  const [detail, setDetail] = useState<number | null>(null)
  const { canWrite } = useAuth()
  const { data, isLoading, error } = useQuery({
    queryKey: ['vulns', project],
    queryFn: () => api.vulns(project ?? undefined),
  })

  const columns: GridColDef<Vuln>[] = [
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
      field: 'status', headerName: 'Status', width: 104,
      renderCell: (p) => (
        <Box sx={{ color: p.value === 'open' ? neon.yellow : neon.muted }}>{p.value}</Box>
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

  return (
    <>
    <DataTable
      rows={data?.items ?? []}
      columns={columns as GridColDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'severity', sort: 'asc' }}   // asc on rank = worst first
      hiddenColumns={project ? { project_code: false } : undefined}
      kind="vulns"
      project={project}
      canWrite={canWrite(project)}
      note={canWrite(project) ? undefined : 'read-only'}
      extraActions={canWrite(project)
        ? <ImportReportButton project={project} /> : undefined}
    />
    <VulnModal id={detail} onClose={() => setDetail(null)}
      onHost={(proj, h) => { setDetail(null); open(proj, h) }} />
    </>
  )
}
