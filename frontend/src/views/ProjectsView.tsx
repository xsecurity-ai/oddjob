import { Box, Button, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import CheckCircleIcon from '@mui/icons-material/CheckCircleOutline'
import CancelIcon from '@mui/icons-material/HighlightOff'
import TuneIcon from '@mui/icons-material/TuneOutlined'
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

export function ProjectsView({ onOpen, onConfigure }: {
  onOpen: (code: string) => void
  onConfigure: (code: string) => void
}) {
  const { roleOn } = useAuth()
  const [creating, setCreating] = useState(false)
  const { data, isLoading, error } = useQuery({ queryKey: ['projects'], queryFn: api.projects })

  const columns: GridColDef<Project>[] = [
    {
      // One identity column, not two. An engagement has a client code
      // (ACME) and an operation name (FALCON), and operators use
      // whichever one exists — the scan directories, the Slack channel
      // and the report are all named after it.
      //
      // The code stays the join key underneath: it is what the URL
      // carries and what `onOpen` needs, so the click uses `row.code`
      // whatever the cell happens to be showing. The tooltip surfaces
      // it when it differs, because someone reading a filename or a
      // channel name still has to be able to find the row.
      field: 'codename', headerName: 'Project', width: 190,
      valueGetter: (_v, row) => row.codename || row.name || row.code,
      renderCell: (p) => {
        const label = String(p.value ?? '')
        const code = p.row.code
        const cell = (
          <Box
            onClick={() => onOpen(code)}
            sx={{
              color: neon.pink, textShadow: glow(neon.pink, 0.4), fontWeight: 700,
              cursor: 'pointer', overflow: 'hidden', textOverflow: 'ellipsis',
              '&:hover': { textShadow: glow(neon.pink, 1) },
            }}
          >{label}</Box>
        )
        return label === code ? cell
          : <Tooltip title={`Code: ${code}`} placement="right">{cell}</Tooltip>
      },
    },
    { field: 'name', headerName: 'Name', flex: 2, minWidth: 200 },
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
      // Whether a notification would actually arrive — not whether this
      // engagement overrides the token. Those are different questions,
      // and the column used to answer the second while looking like it
      // answered the first: an engagement on the site-wide bot showed a
      // dash with Slack working perfectly.
      field: 'slack_active', headerName: 'Slack', width: 80, type: 'boolean',
      align: 'center', headerAlign: 'center',
      renderCell: (p) => {
        const on = !!p.value
        const why = on
          ? (p.row.slack_delivery === 'both'
              ? 'Posting to the site-wide bot and this engagement’s own workspace'
              : p.row.slack_delivery === 'override'
                ? 'Posting through this engagement’s own workspace token'
                : 'Posting through the site-wide bot')
          : (p.row.slack_delivery === 'override'
              ? 'Set to use its own workspace token, and none is set — nothing is posted'
              : 'No bot token is configured, so nothing is posted')
        return (
          <Tooltip title={why}>
            {on ? <CheckCircleIcon sx={{ fontSize: 18, color: neon.green }} />
                : <CancelIcon sx={{ fontSize: 18, color: alpha(neon.red, 0.75) }} />}
          </Tooltip>
        )
      },
    },
    {
      field: 'actions', headerName: '', width: 56, sortable: false,
      filterable: false, align: 'center', headerAlign: 'center',
      renderCell: (p) => (
        <Tooltip title={`Configure ${p.row.codename || p.row.code}`}>
          <IconButton size="small"
            onClick={(e) => { e.stopPropagation(); onConfigure(p.row.code) }}
            sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
            <TuneIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      ),
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
      initialSort={{ field: 'codename', sort: 'asc' }}
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
