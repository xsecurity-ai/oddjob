import { Box, Button, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import CheckCircleIcon from '@mui/icons-material/CheckCircleOutline'
import CancelIcon from '@mui/icons-material/HighlightOff'
import HelpIcon from '@mui/icons-material/HelpOutline'
import SyncIcon from '@mui/icons-material/SyncOutlined'
import TuneIcon from '@mui/icons-material/TuneOutlined'
import type { ColumnDef } from '../lib/columns'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
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
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const { data, isLoading, error } = useQuery({ queryKey: ['projects'], queryFn: api.projects })

  // Asking Slack which channels exist is one listing call per distinct
  // bot token however many engagements share it — cheap enough to be a
  // button, far too expensive to do per row while rendering.
  const recheck = useMutation({
    mutationFn: () => api.refreshSlackChannels(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['projects'] }),
  })

  const columns: ColumnDef<Project>[] = [
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
      field: 'codename', headerName: 'Project', flex: 1, minWidth: 220,
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
      // Whether a notification would actually arrive. Two things have
      // to be true — a token resolves AND the channel exists — and the
      // column has answered only the first of them twice now. A token
      // on its own posts into a channel_not_found, which looks exactly
      // like working Slack from in here.
      //
      // Three icons, not two. "We could not ask Slack" is a real third
      // answer and rendering it as a red cross would have an operator
      // recreating a channel that was there all along.
      field: 'slack_active', headerName: 'Slack', width: 80, type: 'boolean',
      align: 'center', headerAlign: 'center',
      valueGetter: (_v, row) => row.slack_active,
      renderCell: (p) => {
        const via = p.row.slack_delivery === 'both'
          ? 'the site-wide bot and this engagement’s own workspace'
          : p.row.slack_delivery === 'override'
            ? 'this engagement’s own workspace token'
            : 'the site-wide bot'
        if (p.row.slack_active) {
          return (
            <Tooltip title={`Posting to #${p.row.slack_channel ?? '…'} through ${via}`}>
              <CheckCircleIcon sx={{ fontSize: 18, color: neon.green }} />
            </Tooltip>
          )
        }
        if (p.row.slack_channel_state === 'unknown') {
          return (
            <Tooltip title={p.row.slack_channel_error
              ? `Could not check with Slack: ${p.row.slack_channel_error}`
              : 'Not checked yet — use Check Slack to find out'}>
              <HelpIcon sx={{ fontSize: 18, color: alpha(neon.yellow, 0.8) }} />
            </Tooltip>
          )
        }
        const why = p.row.slack_channel_state === 'missing'
          ? `A token resolves, but #${p.row.slack_channel ?? ''} is not in the `
            + `workspace — nothing posted here arrives`
          : p.row.slack_delivery === 'override'
            ? 'Set to use its own workspace token, and none is set'
            : 'No bot token is configured, so nothing is posted'
        return (
          <Tooltip title={why}>
            <CancelIcon sx={{ fontSize: 18, color: alpha(neon.red, 0.75) }} />
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
      columns={columns as ColumnDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'codename', sort: 'asc' }}
      extraActions={
        <>
          <Tooltip title="Ask Slack which engagement channels actually exist">
            <span>
              <Button size="small" variant="outlined" disabled={recheck.isPending}
                startIcon={<SyncIcon sx={{ fontSize: 16 }} />}
                onClick={() => recheck.mutate()}
                sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5),
                      fontSize: 11, py: 0.3, mr: 1 }}>
                {recheck.isPending ? 'Checking…' : 'Check Slack'}
              </Button>
            </span>
          </Tooltip>
          {/* Any signed-in user may start an engagement; they become its admin. */}
          <Button size="small" variant="outlined" startIcon={<AddIcon />}
            onClick={() => setCreating(true)}
            sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5), fontSize: 11, py: 0.3 }}>
            New engagement
          </Button>
        </>
      }
    />
    </>
  )
}
