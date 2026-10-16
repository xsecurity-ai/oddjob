import { createContext, useContext, useMemo, useState, type MouseEvent, type ReactNode } from 'react'
import {
  Box, Chip, CircularProgress, Dialog, DialogContent, DialogTitle, Divider,
  IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Stack, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import DnsIcon from '@mui/icons-material/Dns'
import TravelExploreIcon from '@mui/icons-material/TravelExplore'
import { useQuery } from '@tanstack/react-query'
import { api, type ExploreHost, type NameCount } from '../lib/api'
import type { ColumnDef } from '../lib/columns'
import { DataTable } from './DataTable'
import { useHostModal } from './HostModal'
import { neon, glow } from '../theme'

/* --------------------------------------------------------------------------
   Clicking a port or a service name offers two readings of the same value:

     "All hosts"  — the flat list: who exposes this.
     "Explore"    — the aggregate: what is actually listening on it, which
                    products and banners appear, what has been found on it.

   They answer different questions, which is why this is a menu rather than
   one modal: the list is for pivoting to a host, the aggregate is for
   deciding whether the port is worth pivoting to at all.
   -------------------------------------------------------------------------- */

type Subject = {
  dimension: 'port' | 'service'
  value: string
  protocol?: string
  project: string | null
}
type Ctx = { openMenu: (e: MouseEvent<HTMLElement>, s: Subject) => void }
const ExploreCtx = createContext<Ctx | null>(null)

export function useExplore(): Ctx {
  const c = useContext(ExploreCtx)
  if (!c) throw new Error('useExplore outside ExploreProvider')
  return c
}

const SEV_COLOUR: Record<string, string> = {
  critical: neon.red, high: neon.orange, medium: neon.yellow,
  low: neon.cyan, info: neon.muted,
}

function Label({ children }: { children: ReactNode }) {
  return <Typography sx={{
    fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.16em',
    textTransform: 'uppercase', color: alpha(neon.cyan, 0.75), mb: 0.6,
  }}>{children}</Typography>
}

function Distribution({ title, rows, colour }: { title: string; rows: NameCount[]; colour: string }) {
  if (!rows.length) return null
  const max = Math.max(...rows.map((r) => r.count))
  return (
    <Box sx={{ minWidth: 230, flex: 1 }}>
      <Label>{title}</Label>
      <Stack spacing={0.5}>
        {rows.slice(0, 8).map((r) => (
          <Box key={r.name} sx={{ position: 'relative', px: 1, py: 0.35, borderRadius: 0.5,
                                  overflow: 'hidden', background: alpha(neon.bgDeep, 0.5) }}>
            {/* Bar is a background fill, so long banner strings stay readable
                on top of it rather than being pushed out of the row. */}
            <Box sx={{
              position: 'absolute', inset: 0, width: `${(r.count / max) * 100}%`,
              background: alpha(colour, 0.18), borderRight: `1px solid ${alpha(colour, 0.5)}`,
            }} />
            <Stack direction="row" spacing={1} sx={{ position: 'relative' }}>
              <Box sx={{ flex: 1, fontSize: 12, color: neon.text, whiteSpace: 'nowrap',
                         overflow: 'hidden', textOverflow: 'ellipsis' }} title={r.name}>
                {r.name}
              </Box>
              <Box sx={{ fontSize: 12, fontWeight: 700, color: colour }}>{r.count}</Box>
            </Stack>
          </Box>
        ))}
      </Stack>
      {rows.length > 8 && (
        <Typography sx={{ mt: 0.5, fontSize: 11, color: alpha(neon.muted, 0.7) }}>
          +{rows.length - 8} more
        </Typography>
      )}
    </Box>
  )
}

/** "All hosts with this port/service" — the flat list. */
function HostsBody({ subject }: { subject: Subject }) {
  const { open } = useHostModal()
  const { data, isLoading, error } = useQuery({
    queryKey: ['services-where', subject],
    queryFn: () => api.servicesWhere({
      project: subject.project ?? undefined,
      port: subject.dimension === 'port' ? Number(subject.value) : undefined,
      name: subject.dimension === 'service' ? subject.value : undefined,
    }),
  })

  const columns: ColumnDef[] = [
    {
      field: 'host', headerName: 'Host', flex: 2, minWidth: 230,
      renderCell: (p) => (
        <Box onClick={() => open(p.row.project_code, p.row.host)}
          sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.35), fontWeight: 600,
                cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) } }}>
          {p.value}
        </Box>
      ),
    },
    { field: 'port', headerName: 'Port', width: 90, type: 'number',
      renderCell: (p) => <Box sx={{ color: neon.cyan, fontWeight: 700 }}>{p.value}</Box> },
    { field: 'protocol', headerName: 'Proto', width: 84 },
    { field: 'state', headerName: 'State', width: 96,
      renderCell: (p) => {
        const c = p.value === 'open' ? neon.green : p.value === 'closed' ? neon.red : neon.yellow
        return <Box sx={{ color: c }}>{p.value}</Box>
      } },
    { field: 'name', headerName: 'Service', width: 140, valueGetter: (v) => v ?? '',
      renderCell: (p) => <Box sx={{ color: neon.green }}>{p.value || 'unknown'}</Box> },
    { field: 'banner', headerName: 'Version', flex: 2, minWidth: 200, valueGetter: (v) => v ?? '' },
    { field: 'project_code', headerName: 'Project', width: 125,
      renderCell: (p) => <Box sx={{ color: neon.purple, fontSize: 11.5 }}>{p.value}</Box> },
  ]

  return (
    <Box sx={{ height: '100%', minHeight: 420, display: 'flex' }}>
      {/* The same table as everywhere else, rather than a second one with
          its own rules: it brings the search box, the multi-condition
          filter and the column control with it, which is exactly what
          "show me every host on this port" wants next. */}
      <DataTable
        tableId="explore-hosts"
        rows={data?.items ?? []}
        columns={columns}
        loading={isLoading}
        error={error as Error | null}
        initialSort={{ field: 'host', sort: 'asc' }}
        hiddenColumns={subject.project ? { project_code: false } : undefined}
      />
    </Box>
  )
}

/** "Explore" — the aggregate picture. */
function ExploreBody({ subject }: { subject: Subject }) {
  const { open } = useHostModal()
  const { data, isLoading, error } = useQuery({
    queryKey: ['explore', subject],
    queryFn: () => api.explore({
      dimension: subject.dimension, value: subject.value,
      project: subject.project ?? undefined, protocol: subject.protocol,
    }),
  })

  if (isLoading) {
    return <Box sx={{ display: 'grid', placeItems: 'center', py: 10 }}>
      <CircularProgress sx={{ color: neon.cyan }} />
    </Box>
  }
  if (error) return <Typography sx={{ color: neon.red, py: 4 }}>{(error as Error).message}</Typography>
  if (!data) return null

  const stat = (label: string, v: number | string, c: string) => (
    <Box key={label} sx={{
      px: 1.6, py: 1, borderRadius: 1, minWidth: 104,
      background: alpha(neon.bgDeep, 0.55), border: `1px solid ${alpha(c, 0.4)}`,
    }}>
      <Label>{label}</Label>
      <Box sx={{ fontSize: 20, fontWeight: 700, color: c, textShadow: glow(c, 0.5),
                 lineHeight: 1.1 }}>{v}</Box>
    </Box>
  )

  const hostCols: ColumnDef<ExploreHost>[] = [
    { field: 'host', headerName: 'Host', flex: 2, minWidth: 230,
      renderCell: (p) => (
        <Box onClick={() => open(p.row.project_code, p.row.host)}
          sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.35), fontWeight: 600,
                cursor: 'pointer', '&:hover': { textShadow: glow(neon.pink, 1) } }}>
          {p.value}
        </Box>
      ) },
    { field: 'port', headerName: 'Port', width: 86, type: 'number',
      renderCell: (p) => <Box sx={{ color: neon.cyan, fontWeight: 700 }}>{p.value}</Box> },
    { field: 'protocol', headerName: 'Proto', width: 80 },
    { field: 'state', headerName: 'State', width: 92,
      renderCell: (p) => {
        const c = p.value === 'open' ? neon.green : p.value === 'closed' ? neon.red : neon.yellow
        return <Box sx={{ color: c }}>{p.value}</Box>
      } },
    { field: 'name', headerName: 'Service', width: 130, valueGetter: (v) => v ?? '' },
    { field: 'banner', headerName: 'Version', flex: 2, minWidth: 180, valueGetter: (v) => v ?? '' },
    { field: 'criticals', headerName: 'Crit', width: 76, type: 'number',
      renderCell: (p) => p.value
        ? <Box sx={{ color: neon.red, fontWeight: 700, textShadow: glow(neon.red, 0.5) }}>{p.value}</Box>
        : <Box sx={{ color: alpha(neon.muted, 0.4) }}>0</Box> },
    { field: 'vulns', headerName: 'Vulns', width: 82, type: 'number' },
  ]

  return (
    <Stack spacing={2.5} sx={{ height: '100%' }}>
      <Stack direction="row" spacing={1.2} flexWrap="wrap" useFlexGap>
        {stat('Hosts', data.total_hosts, neon.pink)}
        {stat('Records', data.total_services, neon.purple)}
        {stat('Open', data.by_state.open ?? 0, neon.green)}
        {stat('Closed', data.by_state.closed ?? 0, neon.red)}
        {stat('Filtered', data.by_state.filtered ?? 0, neon.yellow)}
        {stat('Findings', data.vulns_total, neon.cyan)}
      </Stack>

      <Box>
        <Label>Findings on this {data.dimension}</Label>
        <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => {
            const n = data.vulns_by_severity[k] ?? 0
            const c = SEV_COLOUR[k]
            return <Chip key={k} size="small" label={`${k} ${n}`} sx={{
              height: 21, fontSize: 10.5, letterSpacing: '0.06em',
              bgcolor: alpha(c, n ? 0.18 : 0.05), color: n ? c : alpha(neon.muted, 0.5),
              border: `1px solid ${alpha(c, n ? 0.6 : 0.2)}`,
            }} />
          })}
        </Stack>
      </Box>

      <Stack direction="row" spacing={2.5} flexWrap="wrap" useFlexGap>
        {data.dimension === 'port'
          ? <Distribution title="What is listening" rows={data.service_names} colour={neon.green} />
          : <Distribution title="Ports in use" rows={data.ports} colour={neon.cyan} />}
        <Distribution title="Products" rows={data.products} colour={neon.purple} />
        <Distribution title="Banners" rows={data.banners} colour={neon.yellow} />
      </Stack>

      <Box sx={{ flex: 1, minHeight: 320, display: 'flex', flexDirection: 'column' }}>
        <Label>Hosts — worst first{data.truncated ? ' (truncated)' : ''}</Label>
        <DataTable
          tableId="explore-detail"
          // The server returns these already ordered worst-first and the
          // list is truncated, so the index IS the ranking — and the only
          // id these rows have.
          rows={data.hosts.map((h, i) => ({ id: i, ...h }))}
          columns={hostCols as ColumnDef[]}
          hiddenColumns={subject.project ? { project_code: false } : undefined}
        />
      </Box>
    </Stack>
  )
}

export function ExploreProvider({ children }: { children: ReactNode }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const [subject, setSubject] = useState<Subject | null>(null)
  const [mode, setMode] = useState<'hosts' | 'explore' | null>(null)

  const ctx = useMemo<Ctx>(() => ({
    openMenu: (e, s) => { setAnchor(e.currentTarget); setSubject(s) },
  }), [])

  const noun = subject?.dimension === 'port' ? 'port' : 'service'
  const title = subject
    ? `${noun} ${subject.value}${subject.protocol ? '/' + subject.protocol : ''}`
    : ''

  return (
    <ExploreCtx.Provider value={ctx}>
      {children}

      <Menu
        open={!!anchor} anchorEl={anchor} onClose={() => setAnchor(null)}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.bgDeep, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.45)}`,
          boxShadow: `0 0 20px ${alpha(neon.cyan, 0.25)}`,
        } } }}
      >
        <MenuItem onClick={() => { setMode('hosts'); setAnchor(null) }} sx={{ fontSize: 12.5 }}>
          <ListItemIcon><DnsIcon fontSize="small" sx={{ color: neon.pink }} /></ListItemIcon>
          <ListItemText primaryTypographyProps={{ fontSize: 12.5 }}>
            Show all hosts with {title}
          </ListItemText>
        </MenuItem>
        <MenuItem onClick={() => { setMode('explore'); setAnchor(null) }} sx={{ fontSize: 12.5 }}>
          <ListItemIcon><TravelExploreIcon fontSize="small" sx={{ color: neon.cyan }} /></ListItemIcon>
          <ListItemText primaryTypographyProps={{ fontSize: 12.5 }}>
            Explore this {noun}
          </ListItemText>
        </MenuItem>
      </Menu>

      <Dialog
        open={!!mode} onClose={() => setMode(null)} maxWidth="xl" fullWidth scroll="paper"
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.45)}`,
          boxShadow: `0 0 50px ${alpha(neon.cyan, 0.22)}`,
          width: '96vw', maxWidth: '1700px', height: '92vh',
        } } }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.2, py: 1.4,
                           borderBottom: `1px solid ${alpha(neon.cyan, 0.3)}` }}>
          <Typography sx={{
            fontFamily: `'Orbitron', sans-serif`, fontSize: 13, letterSpacing: '0.14em',
            color: neon.cyan, textShadow: glow(neon.cyan, 0.6),
          }}>
            {mode === 'hosts' ? 'HOSTS' : 'EXPLORE'}
          </Typography>
          <Typography sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.4), fontSize: 13 }}>
            {title}
          </Typography>
          <Box sx={{ flex: 1 }} />
          <IconButton size="small" onClick={() => setMode(null)}
            sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
            <CloseIcon fontSize="small" />
          </IconButton>
        </DialogTitle>
        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
        <DialogContent sx={{ display: 'flex', flexDirection: 'column' }}>
          {mode === 'hosts' && subject && <HostsBody subject={subject} />}
          {mode === 'explore' && subject && <ExploreBody subject={subject} />}
        </DialogContent>
      </Dialog>
    </ExploreCtx.Provider>
  )
}
