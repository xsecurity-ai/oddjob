import { useState } from 'react'
import { Box, Button, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import BoltIcon from '@mui/icons-material/Bolt'
import ScanIcon from '@mui/icons-material/RadarOutlined'
import TravelExploreIcon from '@mui/icons-material/TravelExplore'
import type { GridColDef } from '@mui/x-data-grid'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Target } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { ImportScanDialog } from '../components/ImportScanDialog'
import { DetectDomainsDialog } from '../components/DetectDomainsDialog'
import { neon, glow } from '../theme'

/** Zero is muted so the eye lands on the non-zero numbers. */
function Count({ n, color }: { n: number; color?: string }) {
  if (!n) return <Box component="span" sx={{ color: alpha(neon.muted, 0.45) }}>0</Box>
  return (
    <Box component="span" sx={{
      color: color ?? neon.text, fontWeight: 700,
      textShadow: color ? glow(color, 0.5) : undefined,
    }}>{n}</Box>
  )
}

export function TargetsView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const { open } = useHostModal()
  const writable = canWrite(project)
  const [importing, setImporting] = useState(false)
  const [detecting, setDetecting] = useState(false)
  const { data, isLoading, error } = useQuery({
    queryKey: ['targets', project],
    queryFn: () => api.targets(project ?? undefined),
  })

  const patch = useMutation({
    mutationFn: (v: { project: string; host: string; body: Partial<Target> }) =>
      api.patchTarget(v.project, v.host, v.body),
    // No optimistic update: the server publishes an SSE change and the grid
    // refetches. That is the same path an external API or MCP client takes,
    // so the UI exercises live-refresh rather than faking it locally.
    onSettled: () => void qc.invalidateQueries({ queryKey: ['targets'] }),
  })

  const columns: GridColDef<Target>[] = [
    {
      field: 'host', headerName: 'Host', flex: 2, minWidth: 230,
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
      field: 'kind', headerName: 'Type', width: 110,
      type: 'singleSelect', valueOptions: ['host', 'mobile', 'cloud'],
      renderCell: (p) => {
        const c = p.value === 'mobile' ? neon.purple
          : p.value === 'cloud' ? neon.cyan : neon.muted
        // The provider is the useful half of "cloud" — knowing it is a
        // bucket somewhere is less use than knowing whose.
        const label = p.value === 'cloud' && p.row.provider
          ? p.row.provider : (p.value ?? 'host')
        return (
          <Chip size="small" label={label} sx={{
            height: 19, fontSize: 10, letterSpacing: '0.06em',
            bgcolor: alpha(c, 0.15), color: c, border: `1px solid ${alpha(c, 0.5)}`,
          }} />
        )
      },
    },
    { field: 'provider', headerName: 'Provider', width: 110,
      valueGetter: (v) => v ?? '' },
    { field: 'ip_address', headerName: 'IP Address', flex: 1, minWidth: 130,
      valueGetter: (v) => v ?? '',
      // A mobile app has no address. "N/A" says that; a blank cell would
      // read as "not resolved yet", which is a claim about our coverage
      // rather than about the asset.
      renderCell: (p) => (
        // A mobile app has no address at all. A cloud resource may or
        // may not resolve, so a blank one there is still "unknown",
        // not "not applicable".
        p.row.kind === 'mobile'
          ? <Box sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic' }}>N/A</Box>
          : <>{p.value || ''}</>
      ) },
    {
      // Tri-state. "Not probed" is shown as a dash, deliberately distinct from
      // a red DOWN: absence of a probe is not evidence the host is dead.
      field: 'alive', headerName: 'Alive', width: 104,
      type: 'singleSelect', valueOptions: [
        { value: true, label: 'Up' }, { value: false, label: 'Down' },
      ],
      renderCell: (p) => {
        // Liveness is meaningless for an application — there is nothing
        // to probe — so it is not left looking like an unscanned host.
        if (p.row.kind === 'mobile') {
          return <Box sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic' }}>N/A</Box>
        }
        if (p.value === null || p.value === undefined) {
          return (
            <Tooltip title="Not probed yet">
              <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
            </Tooltip>
          )
        }
        const up = p.value === true
        const c = up ? neon.green : neon.red
        return (
          <Tooltip title={up ? 'Responding' : 'Probed — no response'}>
            <Chip size="small" label={up ? 'UP' : 'DOWN'} sx={{
              height: 20, fontSize: 10, letterSpacing: '0.1em',
              bgcolor: alpha(c, 0.16), color: c,
              border: `1px solid ${alpha(c, 0.65)}`, textShadow: glow(c, 0.5),
            }} />
          </Tooltip>
        )
      },
    },
    {
      // Click to toggle: a lamp that lights red when the host is owned and
      // sits dark when it is not. This is the flag an operator flips most
      // often during an engagement, and making them open a dialog for it
      // was the wrong trade.
      field: 'hacked', headerName: 'Hacked', width: 116, type: 'boolean',
      renderCell: (p) => {
        const on = !!p.value
        const allowed = canWrite(p.row.project_code)
        return (
          <Tooltip title={allowed
            ? (on ? 'Pwned — click to clear' : 'Click to mark pwned')
            : 'Read-only on this project'}>
            <Box
              component="span"
              onClick={(e) => {
                e.stopPropagation()      // the row click opens the host modal
                if (allowed && !patch.isPending) {
                  patch.mutate({ project: p.row.project_code, host: p.row.host,
                                 body: { hacked: !on } })
                }
              }}
              sx={{
                display: 'inline-flex', alignItems: 'center', gap: 0.7,
                cursor: allowed ? 'pointer' : 'default',
                opacity: patch.isPending ? 0.5 : 1,
                userSelect: 'none',
                '&:hover .lamp': allowed
                  ? { boxShadow: `0 0 10px ${alpha(on ? neon.red : neon.muted, 0.9)}` }
                  : undefined,
              }}>
              <Box className="lamp" sx={{
                width: 11, height: 11, borderRadius: '50%',
                flex: '0 0 auto',
                background: on ? neon.red : 'transparent',
                border: `1px solid ${alpha(on ? neon.red : neon.muted, on ? 1 : 0.55)}`,
                boxShadow: on ? `0 0 9px ${alpha(neon.red, 0.85)}` : 'none',
                transition: 'all .14s',
              }} />
              {/* Nothing when it is off. An unlit lamp already says so,
                  and a column of the word "off" is noise in a grid whose
                  job is to make the few pwned hosts findable. */}
              {on && (
                <Box component="span" sx={{
                  fontSize: 11, letterSpacing: '0.08em',
                  color: neon.red, textShadow: glow(neon.red, 0.5),
                }}>PWNED</Box>
              )}
            </Box>
          </Tooltip>
        )
      },
    },
    { field: 'total_vulns', headerName: 'Vulns', width: 88, type: 'number',
      renderCell: (p) => <Count n={p.value} /> },
    { field: 'total_criticals', headerName: 'Crit', width: 80, type: 'number',
      renderCell: (p) => <Count n={p.value} color={neon.red} /> },
    { field: 'total_highs', headerName: 'High', width: 80, type: 'number',
      renderCell: (p) => <Count n={p.value} color={neon.orange} /> },
    { field: 'total_pocs', headerName: 'PoCs', width: 82, type: 'number',
      renderCell: (p) => <Count n={p.value} color={neon.green} /> },
    { field: 'total_ports', headerName: 'Open', width: 80, type: 'number',
      renderCell: (p) => <Count n={p.value} color={neon.cyan} /> },
    { field: 'project_code', headerName: 'Project', width: 130,
      renderCell: (p) => (
        <Box sx={{ color: neon.purple, fontSize: 11.5, letterSpacing: '0.06em' }}>{p.value}</Box>
      ) },
    {
      field: 'actions', headerName: 'Action', width: 100, sortable: false, filterable: false,
      renderCell: (p) => {
        // Placeholder column, wired with the one action that is safe and
        // reversible. Disabled for readonly so the UI matches what the API
        // will actually permit, rather than offering a button that 403s.
        const allowed = canWrite(p.row.project_code)
        return (
          <Tooltip title={allowed
            ? (p.row.hacked ? 'Mark not pwned' : 'Mark pwned')
            : 'Read-only on this project'}>
            <span>
              <IconButton size="small" disabled={!allowed}
                onClick={() => patch.mutate({
                  project: p.row.project_code, host: p.row.host,
                  body: { hacked: !p.row.hacked },
                })}
                sx={{
                  color: p.row.hacked ? neon.red : neon.muted,
                  '&:hover': { color: neon.yellow, textShadow: glow(neon.yellow) },
                }}>
                <BoltIcon fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
        )
      },
    },
  ]

  return (
    <>
      {importing && project && (
        <ImportScanDialog project={project} onClose={() => setImporting(false)} />
      )}
      {detecting && project && (
        <DetectDomainsDialog project={project} onClose={() => setDetecting(false)} />
      )}
      <DataTable
        rows={data?.items ?? []}
        columns={columns as GridColDef[]}
        loading={isLoading}
        error={error as Error | null}
        initialSort={{ field: 'host', sort: 'asc' }}
        hiddenColumns={project ? { project_code: false } : undefined}
        kind="targets"
        project={project}
        canWrite={writable}
        note={writable ? undefined : 'read-only'}
        extraActions={writable && project ? (
          <>
            <Button size="small" variant="outlined" startIcon={<TravelExploreIcon sx={{ fontSize: 16 }} />}
              onClick={() => setDetecting(true)}
              sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5), fontSize: 11, py: 0.3 }}>
              Detect New Domains
            </Button>
            <Button size="small" variant="outlined" startIcon={<ScanIcon sx={{ fontSize: 16 }} />}
              onClick={() => setImporting(true)}
              sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5), fontSize: 11, py: 0.3 }}>
              Import report
            </Button>
          </>
        ) : undefined}
      />
    </>
  )
}
