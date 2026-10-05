import { Box, Chip, alpha } from '@mui/material'
import type { GridColDef } from '@mui/x-data-grid'
import { useQuery } from '@tanstack/react-query'
import { api, type Service } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { useExplore } from '../components/ExploreModal'
import { ServiceActions } from '../components/ServiceActions'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

const makeHostCol = (open: (p: string, h: string) => void): GridColDef<Service> => ({
  field: 'host',
  headerName: 'Host',
  flex: 2,
  minWidth: 230,
  renderCell: (p) => (
    <Box
      onClick={() => open(p.row.project_code, p.row.host)}
      sx={{
        color: neon.pink, textShadow: glow(neon.pink, 0.35), fontWeight: 600,
        cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) },
      }}
    >{p.value}</Box>
  ),
})

const makePortCol = (
  openMenu: ReturnType<typeof useExplore>['openMenu'], project: string | null,
): GridColDef<Service> => ({
  field: 'port',
  headerName: 'Port',
  width: 96,
  type: 'number',
  renderCell: (p) => (
    <Box
      onClick={(e) => openMenu(e, {
        dimension: 'port', value: String(p.row.port),
        protocol: p.row.protocol, project,
      })}
      sx={{
        color: neon.cyan, textShadow: glow(neon.cyan, 0.4), fontWeight: 700,
        cursor: 'pointer', '&:hover': { textShadow: glow(neon.cyan, 1) },
      }}
    >{p.value}</Box>
  ),
})

const protoCol: GridColDef<Service> = {
  field: 'protocol',
  headerName: 'Proto',
  width: 92,
  renderCell: (p) => (
    <Chip
      size="small"
      label={String(p.value).toUpperCase()}
      sx={{
        height: 20, fontSize: 10, letterSpacing: '0.1em',
        bgcolor: alpha(p.value === 'udp' ? neon.yellow : neon.purple, 0.16),
        color: p.value === 'udp' ? neon.yellow : neon.purple,
        border: `1px solid ${alpha(p.value === 'udp' ? neon.yellow : neon.purple, 0.55)}`,
      }}
    />
  ),
}

/** What a person recorded about the service, as distinct from what the
 *  service said about itself. Hidden by default: most have none, and an
 *  empty column in a 6,000-row grid costs more than one click to show. */
const notesCol: GridColDef<Service> = {
  field: 'notes',
  headerName: 'Notes',
  flex: 2,
  minWidth: 180,
  valueGetter: (v) => v ?? '',
}

/** Version strings are long and frequently empty; keep them last and let
 *  them flex. The field is `banner` — what nmap and Faraday both call it. */
const bannerCol: GridColDef<Service> = {
  field: 'banner',
  headerName: 'Version',
  flex: 3,
  minWidth: 240,
  valueGetter: (v) => v ?? '',
  renderCell: (p) =>
    p.value ? (
      <Box sx={{ color: neon.muted, whiteSpace: 'nowrap', overflow: 'hidden',
                 textOverflow: 'ellipsis' }} title={String(p.value)}>
        {p.value}
      </Box>
    ) : (
      <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
    ),
}

const projectCol: GridColDef<Service> = {
  field: 'project_code', headerName: 'Project', width: 130,
  renderCell: (p) => (
    <Box sx={{ color: neon.purple, fontSize: 11.5, letterSpacing: '0.06em' }}>{p.value}</Box>
  ),
}

export function ServicesView({ project }: { project: string | null }) {
  const { open } = useHostModal()
  const { openMenu } = useExplore()
  const { canWrite } = useAuth()
  const writable = canWrite(project)
  const { data, isLoading, error } = useQuery({
    queryKey: ['services', project],
    queryFn: () => api.services(project ?? undefined),
  })
  const serviceCol: GridColDef<Service> = {
    field: 'name',
    headerName: 'Service',
    flex: 1,
    minWidth: 140,
    valueGetter: (v) => v ?? '',
    renderCell: (p) =>
      p.value ? (
        <Box
          onClick={(e) => openMenu(e, { dimension: 'service', value: String(p.value), project })}
          sx={{
            color: neon.green, textShadow: glow(neon.green, 0.3),
            cursor: 'pointer', '&:hover': { textShadow: glow(neon.green, 1) },
          }}
        >{p.value}</Box>
      ) : (
        // "unknown" is the absence of a service name, not a name — there is
        // nothing to explore, so it stays inert.
        <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>unknown</Box>
      ),
  }
  const stateCol: GridColDef<Service> = {
    field: 'state',
    headerName: 'State',
    width: 100,
    renderCell: (p) => {
      const c = p.value === 'open' ? neon.green : p.value === 'closed' ? neon.red : neon.yellow
      return <Box sx={{ color: c, textShadow: glow(c, 0.35) }}>{p.value}</Box>
    },
  }
  const actionsCol: GridColDef<Service> = {
    field: 'actions', headerName: 'Actions', width: 112,
    sortable: false, filterable: false,
    renderCell: (p) => <ServiceActions serviceId={p.row.id} canWrite={writable} />,
  }
  const columns = [makeHostCol(open), serviceCol, makePortCol(openMenu, project),
                   protoCol, stateCol, bannerCol, notesCol, projectCol, actionsCol]
  return (
    <DataTable
      rows={data?.items ?? []}
      columns={columns as GridColDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'host', sort: 'asc' }}
      hiddenColumns={{ notes: false, ...(project ? { project_code: false } : {}) }}
      kind="services"
      project={project}
      canWrite={writable}
      note={writable ? undefined : 'read-only'}
    />
  )
}
