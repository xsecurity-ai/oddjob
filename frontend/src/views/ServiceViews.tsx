import { Box, Chip, alpha } from '@mui/material'
import type { ColumnDef } from '../lib/columns'
import { useQuery } from '@tanstack/react-query'
import { api, type Service } from '../lib/api'
import { DataTable } from '../components/DataTable'
import { ImportReportButton } from '../components/ImportReportButton'
import { useHostModal } from '../components/HostModal'
import { useExplore } from '../components/ExploreModal'
import { ServiceActions } from '../components/ServiceActions'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

const makeHostCol = (open: (p: string, h: string) => void): ColumnDef<Service> => ({
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
): ColumnDef<Service> => ({
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

const protoCol: ColumnDef<Service> = {
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
const notesCol: ColumnDef<Service> = {
  field: 'notes',
  headerName: 'Notes',
  flex: 2,
  minWidth: 180,
  valueGetter: (v) => v ?? '',
}

/** What is running here, from whichever field actually has it.
 *
 *  This column read `banner` alone, and on a real estate the banner
 *  is set on 1,061 services out of 919,752 — so it was empty on
 *  99.9% of rows while `product` was populated on 999 of them and
 *  `version` on 36, in columns it never looked at. The column was
 *  not broken so much as reading one field out of four.
 *
 *  Composed in nmap's own order — product, version, extrainfo — and
 *  falling back to the banner, which is the raw thing a service
 *  said about itself when nothing parsed it.
 */
function identified(s: Service): string {
  const parts = [s.product, s.version].filter(Boolean) as string[]
  const extra = s.extrainfo ? `(${s.extrainfo})` : ''
  const composed = [...parts, extra].filter(Boolean).join(' ').trim()
  return composed || (s.banner ?? '').trim()
}

/** Why there is nothing to show, which is not one answer but three.
 *
 *  A blank cell reads as "fine" and these are not the same fact:
 *  nothing looked, something looked and could not tell, and the port
 *  accepted a connection and then hung up without saying a word.
 *  The third is `tcpwrapped`, and on this estate it is 917,402 rows
 *  across 53 hosts — a device answering every port, not services.
 */
function whyBlank(s: Service): string {
  if (s.name === 'tcpwrapped') {
    return 'accepted the connection and closed it without responding'
  }
  if (!s.method) return 'not probed for a version'
  if (s.name === 'UNKNOWN') return 'probed; nothing recognised it'
  return 'probed; no version offered'
}

const bannerCol: ColumnDef<Service> = {
  field: 'banner',
  headerName: 'Version',
  flex: 3,
  minWidth: 240,
  // Sorts and filters on what is DISPLAYED. Sorting a column by a
  // field it does not show is the kind of thing nobody reports and
  // everybody distrusts.
  valueGetter: (_v, row) => identified(row as Service),
  renderCell: (p) => {
    const s = p.row as Service
    const got = identified(s)
    return got ? (
      <Box sx={{ color: neon.text, whiteSpace: 'nowrap', overflow: 'hidden',
                 textOverflow: 'ellipsis' }} title={got}>
        {got}
      </Box>
    ) : (
      <Box component="span" title={whyBlank(s)}
        sx={{ color: alpha(neon.muted, 0.5), fontSize: 11, cursor: 'help' }}>
        {s.name === 'tcpwrapped' ? 'no reply' : '—'}
      </Box>
    )
  },
}

const projectCol: ColumnDef<Service> = {
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
  const serviceCol: ColumnDef<Service> = {
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
  const stateCol: ColumnDef<Service> = {
    field: 'state',
    headerName: 'State',
    width: 100,
    renderCell: (p) => {
      const c = p.value === 'open' ? neon.green : p.value === 'closed' ? neon.red : neon.yellow
      return <Box sx={{ color: c, textShadow: glow(c, 0.35) }}>{p.value}</Box>
    },
  }
  const actionsCol: ColumnDef<Service> = {
    field: 'actions', headerName: 'Actions', width: 112,
    sortable: false, filterable: false,
    renderCell: (p) => <ServiceActions serviceId={p.row.id} canWrite={writable} />,
  }
  const columns = [makeHostCol(open), serviceCol, makePortCol(openMenu, project),
                   protoCol, stateCol, bannerCol, notesCol, projectCol, actionsCol]
  return (
    <DataTable
      rows={data?.items ?? []}
      columns={columns as ColumnDef[]}
      loading={isLoading}
      error={error as Error | null}
      initialSort={{ field: 'host', sort: 'asc' }}
      hiddenColumns={{ notes: false, ...(project ? { project_code: false } : {}) }}
      kind="services"
      project={project}
      canWrite={writable}
      note={writable ? undefined : 'read-only'}
      extraActions={writable ? <ImportReportButton project={project} /> : undefined}
    />
  )
}
