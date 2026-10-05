import { Box, Button, Chip, alpha } from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import type { GridColDef } from '@mui/x-data-grid'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type Project } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { NewProjectDialog } from '../components/NewProjectDialog'
import { neon, glow } from '../theme'

const ROLE_COLOUR: Record<string, string> = {
  admin: neon.pink, user: neon.cyan, readonly: neon.muted,
}

export function ProjectsView({ onOpen }: { onOpen: (code: string) => void }) {
  const { roleOn } = useAuth()
  const [creating, setCreating] = useState(false)
  const { data, isLoading, error } = useQuery({ queryKey: ['projects'], queryFn: api.projects })

  const columns: GridColDef<Project>[] = [
    {
      field: 'code', headerName: 'Code', width: 170,
      renderCell: (p) => (
        <Box
          onClick={() => onOpen(p.value)}
          sx={{
            color: neon.pink, textShadow: glow(neon.pink, 0.4), fontWeight: 700,
            cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) },
          }}
        >{p.value}</Box>
      ),
    },
    {
      // The operation's internal name — a client code is ACME, its operation name FALCON.
      // The code is the client's and goes in their deliverables; the
      // codename is what the scan directories, the Slack channels and
      // the operators are all named after, so it belongs on this list.
      field: 'codename', headerName: 'Codename', width: 130,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (p.value
        ? <Box sx={{ color: neon.cyan, letterSpacing: '0.1em', fontWeight: 600 }}>
            {p.value}
          </Box>
        : <Box sx={{ color: alpha(neon.muted, 0.6) }}>—</Box>),
    },
    { field: 'name', headerName: 'Name', flex: 2, minWidth: 200 },
    { field: 'client', headerName: 'Client', flex: 1, minWidth: 130,
      valueGetter: (v) => v ?? '' },
    {
      // Shows the caller's own effective role, which is what makes the
      // ACL legible without opening a separate admin screen.
      field: 'myrole', headerName: 'Your role', width: 120, sortable: false,
      valueGetter: (_v, row) => roleOn(row.code) ?? '',
      renderCell: (p) => {
        const r = String(p.value || '')
        if (!r) return <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
        const c = ROLE_COLOUR[r] ?? neon.muted
        return <Chip size="small" label={r} sx={{
          height: 20, fontSize: 10, letterSpacing: '0.08em',
          bgcolor: alpha(c, 0.14), color: c, border: `1px solid ${alpha(c, 0.55)}`,
        }} />
      },
    },
    {
      field: 'status', headerName: 'Status', width: 110,
      renderCell: (p) => {
        const c = p.value === 'active' ? neon.green
          : p.value === 'archived' ? neon.muted : neon.yellow
        return <Box sx={{ color: c, textShadow: glow(c, 0.3) }}>{p.value}</Box>
      },
    },
    { field: 'total_targets', headerName: 'Targets', width: 96, type: 'number',
      renderCell: (p) => <Box sx={{ color: neon.cyan, fontWeight: 700 }}>{p.value}</Box> },
    { field: 'total_services', headerName: 'Services', width: 100, type: 'number' },
    { field: 'total_vulns', headerName: 'Vulns', width: 92, type: 'number',
      renderCell: (p) => <Box sx={{ color: neon.yellow, fontWeight: 700 }}>{p.value}</Box> },
    { field: 'total_pocs', headerName: 'PoCs', width: 86, type: 'number' },
    {
      field: 'slack_token_set', headerName: 'Slack', width: 92, type: 'boolean',
      renderCell: (p) => p.value
        ? <Chip size="small" label="override" sx={{
            height: 19, fontSize: 10, bgcolor: alpha(neon.green, 0.14),
            color: neon.green, border: `1px solid ${alpha(neon.green, 0.5)}` }} />
        : <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>,
    },
  ]

  return (
    <>
    {creating && (
      <NewProjectDialog onClose={() => setCreating(false)}
        onCreated={(code) => { setCreating(false); onOpen(code) }} />
    )}
    <DataTable
      tableId="projects"
      rows={data?.items ?? []}
      columns={columns as GridColDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'code', sort: 'asc' }}
      extraActions={
        // Any signed-in user may start an engagement; they become its admin.
        <Button size="small" variant="outlined" startIcon={<AddIcon />}
          onClick={() => setCreating(true)}
          sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5), fontSize: 11, py: 0.3 }}>
          New engagement
        </Button>
      }
    />
    </>
  )
}
