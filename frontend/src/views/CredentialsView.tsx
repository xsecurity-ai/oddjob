import { useState } from 'react'
import { Box, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import VisibilityIcon from '@mui/icons-material/VisibilityOutlined'
import VisibilityOffIcon from '@mui/icons-material/VisibilityOffOutlined'
import type { ColumnDef } from '../lib/columns'
import { useQuery } from '@tanstack/react-query'
import { api, type Credential } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { neon, glow } from '../theme'

const VALID_COLOUR: Record<string, string> = {
  works: neon.green, failed: neon.red, none: neon.muted,
}

export function CredentialsView({ project }: { project: string | null }) {
  const { canWrite } = useAuth()
  const { open } = useHostModal()
  // Reveal is per row and resets on reload. Secrets are not rendered by
  // default so a shared screen or a screenshot does not leak the lot.
  const [shown, setShown] = useState<Record<number, boolean>>({})
  const { data, isLoading, error } = useQuery({
    queryKey: ['credentials', project],
    queryFn: () => api.credentials(project ?? undefined),
  })

  const columns: ColumnDef<Credential>[] = [
    {
      field: 'host', headerName: 'Host', flex: 1.4, minWidth: 190,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => p.value ? (
        <Box onClick={() => open(p.row.project_code, String(p.value))}
          sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.35), fontWeight: 600,
                cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) } }}>
          {p.value}
        </Box>
      ) : <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>,
    },
    { field: 'username', headerName: 'Username', flex: 1, minWidth: 150,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => <Box sx={{ color: neon.cyan }}>{p.value || '—'}</Box> },
    {
      field: 'secret', headerName: 'Secret', flex: 1.3, minWidth: 190,
      sortable: false,
      // Excluded from quick-search by design: a secret should not be
      // discoverable by typing fragments of it into a filter box.
      filterable: false,
      renderCell: (p) => {
        if (!p.row.secret_set) {
          return <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
        }
        if (p.row.secret === null) {
          return (
            <Tooltip title="You are read-only on this project, so the secret is withheld">
              <Chip size="small" label="withheld" sx={{
                height: 19, fontSize: 10, bgcolor: alpha(neon.muted, 0.12),
                color: neon.muted, border: `1px solid ${alpha(neon.muted, 0.4)}`,
              }} />
            </Tooltip>
          )
        }
        const on = !!shown[p.row.id]
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, width: '100%' }}>
            <Box sx={{ flex: 1, color: on ? neon.yellow : neon.muted,
                       fontFamily: `'Share Tech Mono', monospace`,
                       whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {on ? p.row.secret : '••••••••••'}
            </Box>
            <IconButton size="small" onClick={() => setShown((o) => ({ ...o, [p.row.id]: !on }))}
              sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
              {on ? <VisibilityOffIcon sx={{ fontSize: 15 }} />
                  : <VisibilityIcon sx={{ fontSize: 15 }} />}
            </IconButton>
          </Box>
        )
      },
    },
    { field: 'kind', headerName: 'Kind', width: 104,
      renderCell: (p) => (
        <Chip size="small" label={p.value} sx={{
          height: 19, fontSize: 10, bgcolor: alpha(neon.purple, 0.15),
          color: neon.purple, border: `1px solid ${alpha(neon.purple, 0.5)}`,
        }} />
      ) },
    { field: 'validated', headerName: 'Validated', width: 112,
      renderCell: (p) => {
        const c = VALID_COLOUR[p.value] ?? neon.muted
        const label = p.value === 'none' ? 'not tried' : p.value
        return <Box sx={{ color: c, textShadow: p.value === 'none' ? undefined : glow(c, 0.4) }}>
          {label}
        </Box>
      } },
    { field: 'service', headerName: 'Service', width: 130, valueGetter: (v) => v ?? '' },
    { field: 'port', headerName: 'Port', width: 82, type: 'number',
      valueGetter: (v) => v ?? null },
    { field: 'source', headerName: 'Source', flex: 1, minWidth: 150, valueGetter: (v) => v ?? '' },
    { field: 'project_code', headerName: 'Project', width: 128,
      renderCell: (p) => (
        <Box sx={{ color: neon.purple, fontSize: 11.5, letterSpacing: '0.06em' }}>{p.value}</Box>
      ) },
  ]

  return (
    <DataTable
      rows={data?.items ?? []}
      columns={columns as ColumnDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'host', sort: 'asc' }}
      hiddenColumns={project ? { project_code: false } : undefined}
      kind="credentials"
      project={project}
      canWrite={canWrite(project)}
      note={canWrite(project) ? undefined : 'read-only'}
    />
  )
}
