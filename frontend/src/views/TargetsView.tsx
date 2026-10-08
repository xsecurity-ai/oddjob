import { useMemo, useState } from 'react'
import {
  Alert, Badge, Box, Button, Chip, Snackbar, Stack, Tooltip, alpha,
} from '@mui/material'
import ScanIcon from '@mui/icons-material/RadarOutlined'
import type { ColumnDef } from '../lib/columns'
import { extraAddresses } from '../lib/cellFacts'
import { StandingOrders } from '../components/StandingOrders'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Target } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { useHostModal } from '../components/HostModal'
import { ImportScanDialog } from '../components/ImportScanDialog'
import { MergeTargetsDialog } from '../components/MergeTargetsDialog'
import { DetectDomainsDialog } from '../components/DetectDomainsDialog'
import {
  EnumerateMenu, TargetRowActions, type EnumerateAction, type RowAction,
} from '../components/EnumerateMenu'
import { isLive } from '../components/ghostTasking'
import {
  FqdnPickerDialog, openChoices, useAutoApplySingles,
} from '../components/FqdnPickerDialog'
import { LookupQueueDialog, type LookupKind } from '../components/LookupQueueDialog'
import { NmapScanDialog } from '../components/NmapScanDialog'
import { ScanRangesDialog } from '../components/ScanRangesDialog'
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

/** Is this string an address rather than a name? */
function isAddress(v: string | null | undefined): boolean {
  const s = (v ?? '').trim()
  if (!s) return false
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    return s.split('.').every((o) => Number(o) <= 255)
  }
  // IPv6 is matched loosely on purpose: hex, colons and an optional
  // zone. Anything with a colon in it is not a hostname, so a loose
  // match here cannot mistake a name for an address.
  return /^[0-9a-f:]+(%[0-9a-z]+)?$/i.test(s) && s.includes(':')
}

/** The address to look a target up by, or '' when it has none. */
function addressOf(t: Target): string {
  const ip = (t.ip_address ?? '').trim()
  if (ip) return ip
  return isAddress(t.host) ? t.host.trim() : ''
}

/** A target named by something other than its own address. */
function hasName(t: Target): boolean {
  return !isAddress(t.host)
}

/** An address on record and no name to go with it — what the two
 *  "find FQDNs" actions are for. A mobile app is excluded: it has no
 *  address, so it is not a gap in our coverage. */
function needsName(t: Target): boolean {
  return t.kind !== 'mobile' && !!addressOf(t) && !hasName(t)
}

/** A name on record and no address to go with it — the mirror of
 *  `needsName`, and what the two "find IPs" actions are for.
 *
 *  A mobile app is excluded for the opposite reason to the other
 *  direction: it has no address because there is nothing to resolve,
 *  so it is not a gap. Listing it would turn a correct N/A into a
 *  permanent outstanding task. */
function needsAddress(t: Target): boolean {
  return t.kind !== 'mobile' && hasName(t) && !(t.ip_address ?? '').trim()
}

// ----------------------------------------------------------- widths
// Widths are computed from the rows rather than measured, because the
// grid lives inside DataTable and MUI's autosize measures what is
// rendered — and DataTable hands the grid ONE page at a time, so an
// autosize would fit whichever page happened to be on screen first and
// then jump. Deriving from the whole row set is stable across paging.
//
// The constants are the two fonts the grid actually uses: cells are
// 'Share Tech Mono' at 12px, headers 'Orbitron' at 11px uppercase with
// 0.14em tracking. Chips carry their own padding and a smaller face.
const CELL_CH = 7.3
const HEAD_CH = 8.2
const CELL_PAD = 22
/** Room for the sort arrow and the column menu button. */
const HEAD_FURNITURE = 30

function fit(header: string, widest: number, min = 60, max = 300): number {
  const head = header.length * HEAD_CH + CELL_PAD + HEAD_FURNITURE
  return Math.ceil(Math.min(max, Math.max(min, widest + CELL_PAD, head)))
}

const textWidth = (s: string) => s.length * CELL_CH
/** A MUI chip at fontSize 10 with the padding this grid gives it. */
const chipWidth = (s: string) => s.length * 6.4 + 20

export function TargetsView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()
  const { open } = useHostModal()
  const writable = canWrite(project)
  const [importing, setImporting] = useState(false)
  // The target that would be absorbed and removed.
  const [merging, setMerging] = useState<Target | null>(null)
  const [detecting, setDetecting] = useState(false)
  const [picking, setPicking] = useState(false)
  const [scanningRanges, setScanningRanges] = useState(false)
  const [nmapOn, setNmapOn] = useState<string[] | null>(null)
  const [lookup, setLookup] = useState<{ kind: LookupKind; subjects: string[] } | null>(null)
  //: The confirmation a closed modal would otherwise have taken with it.
  const [toast, setToast] = useState<string | null>(null)
  const [selected, setSelected] = useState<number[]>([])

  const { data, isLoading, error } = useQuery({
    queryKey: ['targets', project],
    queryFn: () => api.targets(project ?? undefined),
  })

  // Lookup results that have come home. The SSE stream invalidates
  // everything when an agent reports, so this refreshes by itself —
  // no polling, and no window where the grid is newer than the badge.
  const pending = useQuery({
    queryKey: ['enumerate-pending', project],
    queryFn: () => api.enumeratePending(project as string),
    enabled: !!project && writable,
  })
  // Every Enumerate action is work for an agent to do. With none
  // connected the task is queued against nothing: it sits there
  // looking submitted and never runs, which reads as a broken scan
  // rather than as a missing scanner. The menu says so instead.
  const agents = useQuery({
    queryKey: ['agents', project],
    queryFn: () => api.agents(project as string),
    enabled: !!project && writable,
  })
  // `isLive`, not `status === 'online'`: an agent part-way through a
  // scan reports `busy`, and treating that as "not there" made this
  // page say no agents while the Ghost page showed two working.
  const live = (agents.data ?? []).filter(isLive)
  const enrolled = (agents.data ?? []).length

  const auto = useAutoApplySingles(writable ? project : null, pending.data)
  const choices = useMemo(() => openChoices(pending.data), [pending.data])

  const rows = useMemo(() => data?.items ?? [], [data])
  const selectedRows = useMemo(() => {
    const want = new Set(selected)
    return rows.filter((t) => want.has(t.id))
  }, [rows, selected])

  const unnamed = useMemo(() => rows.filter(needsName), [rows])
  const unnamedSelected = useMemo(() => selectedRows.filter(needsName), [selectedRows])
  const unaddressed = useMemo(() => rows.filter(needsAddress), [rows])
  const unaddressedSelected = useMemo(
    () => selectedRows.filter(needsAddress), [selectedRows])

  const patch = useMutation({
    mutationFn: (v: { project: string; host: string; body: Partial<Target> }) =>
      api.patchTarget(v.project, v.host, v.body),
    // No optimistic update: the server publishes an SSE change and the grid
    // refetches. That is the same path an external API or MCP client takes,
    // so the UI exercises live-refresh rather than faking it locally.
    onSettled: () => void qc.invalidateQueries({ queryKey: ['targets'] }),
  })

  // Closing the modal and saying so outside it. A dialog that stays
  // open on success has to be dismissed before the operator can get
  // back to the table, which is the next thing they want; the
  // confirmation still matters, so it is not simply dropped.
  const queued = (summary: string) => {
    setDetecting(false); setScanningRanges(false); setNmapOn(null)
    setLookup(null)
    setToast(summary)
  }

  const onEnumerate = (a: EnumerateAction) => {
    if (a === 'detect-domains') setDetecting(true)
    else if (a === 'scan-ranges') setScanningRanges(true)
    else if (a === 'ip-all' || a === 'ip-selected') {
      // Forward: a name we hold, resolved to the address it points at.
      const src = a === 'ip-all' ? unaddressed : unaddressedSelected
      setLookup({ kind: 'nslookup', subjects: src.map((t) => t.host) })
    } else {
      // Reverse: an address we hold, asked what it is called.
      const src = a === 'fqdn-all' ? unnamed : unnamedSelected
      setLookup({ kind: 'reverse_ip', subjects: src.map(addressOf) })
    }
  }

  const onRowAction = (t: Target, a: RowAction) => {
    if (a === 'merge') setMerging(t)
    else if (a === 'nmap') setNmapOn([t.host])
    else if (a === 'find-hostname') {
      setLookup({ kind: 'reverse_ip', subjects: [addressOf(t)] })
    } else {
      setLookup({ kind: 'nslookup', subjects: [t.host] })
    }
  }

  const widths = useMemo(() => {
    const kindLabel = (t: Target) =>
      (t.kind === 'cloud' && t.provider ? t.provider : (t.kind ?? 'host'))
    const widest = (f: (t: Target) => number) =>
      rows.reduce((n, t) => Math.max(n, f(t)), 0)
    return {
      // "N/A" stands in for a mobile app in three of these columns, so
      // it is part of the content even when no row is wide.
      kind: fit('Type', Math.max(widest((t) => chipWidth(kindLabel(t))),
                                 chipWidth('host'))),
      // A host can hold several addresses. The column shows the first and
      // a `+N` for the rest, so the width has to allow for that chip on
      // the widest address rather than on the widest row overall — those
      // are not usually the same row.
      ip: fit('IP Addresses', Math.max(
        widest((t) => (t.kind === 'mobile'
          ? textWidth('N/A')
          : textWidth(t.ip_address ?? '') +
            (extraAddresses(t.ip_addresses)
              ? chipWidth(`+${extraAddresses(t.ip_addresses)}`) + 6 : 0))),
        textWidth('255.255.255.255'))),
      alive: fit('Alive', Math.max(chipWidth('DOWN'), textWidth('N/A'))),
      hacked: fit('Hacked', chipWidth('PWNED') + 18),   // + the lamp and its gap
      // An icon button, or the italic N/A a mobile row shows instead.
      actions: fit('Action', Math.max(34, textWidth('N/A'))),
    }
  }, [rows])

  const columns: ColumnDef<Target>[] = [
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
      field: 'kind', headerName: 'Type', width: widths.kind,
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
    { field: 'ip_address', headerName: 'IP Addresses', width: widths.ip,
      // Sorted and filtered on the first address, which is what the cell
      // leads with. `ip_addresses` is the whole truth and the tooltip
      // shows all of it, but sorting a row by an address the reader
      // cannot see in it is worse than sorting by the one they can.
      valueGetter: (v) => v ?? '',
      // A mobile app has no address. "N/A" says that; a blank cell would
      // read as "not resolved yet", which is a claim about our coverage
      // rather than about the asset.
      renderCell: (p) => {
        // A mobile app has no address at all. A cloud resource may or
        // may not resolve, so a blank one there is still "unknown",
        // not "not applicable".
        if (p.row.kind === 'mobile') {
          return <Box sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic' }}>N/A</Box>
        }
        const all = p.row.ip_addresses ?? []
        const extra = extraAddresses(all)
        return (
          <Stack direction="row" spacing={0.6} alignItems="center" sx={{ minWidth: 0 }}>
            <Box sx={{ overflow: 'hidden', textOverflow: 'ellipsis',
                       whiteSpace: 'nowrap' }}>{p.value || ''}</Box>
            {extra > 0 ? (
              // The count, not the addresses: a host behind a load
              // balancer can hold a dozen, and spelling them into a
              // fixed-height cell would clip them into a half-address
              // that reads like a whole one.
              <Tooltip title={<Box sx={{ whiteSpace: 'pre-line' }}>{all.join('\n')}</Box>}>
                <Chip size="small" label={`+${extra}`} sx={{
                  height: 17, fontSize: 9.5, color: neon.cyan,
                  bgcolor: alpha(neon.cyan, 0.12) }} />
              </Tooltip>
            ) : null}
          </Stack>
        )
      } },
    {
      // Tri-state. "Not probed" is shown as a dash, deliberately distinct from
      // a red DOWN: absence of a probe is not evidence the host is dead.
      field: 'alive', headerName: 'Alive', width: widths.alive,
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
      // was the wrong trade. It is also the ONLY way to set it now — the
      // row action that duplicated it has gone.
      field: 'hacked', headerName: 'Hacked', width: widths.hacked, type: 'boolean',
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
      field: 'actions', headerName: 'Action', width: widths.actions,
      sortable: false, filterable: false,
      renderCell: (p) => (
        <TargetRowActions
          kind={p.row.kind}
          hasIp={!!addressOf(p.row)}
          hasName={hasName(p.row)}
          allowed={canWrite(p.row.project_code)}
          liveAgents={live.length}
          enrolledAgents={enrolled}
          onPick={(a) => onRowAction(p.row, a)} />
      ),
    },
  ]

  return (
    <>
      {importing && project && (
        <ImportScanDialog project={project} onClose={() => setImporting(false)} />
      )}
      {merging && project && (
        <MergeTargetsDialog project={project} source={merging}
          candidates={rows} onClose={() => setMerging(null)} />
      )}
      {detecting && project && (
        <DetectDomainsDialog project={project}
          // Whatever was ticked in the grid, so picking an action after
          // making a selection starts from the selection rather than
          // from an empty box.
          seed={selectedRows.map((t) => t.host)}
          allHosts={rows.map((t) => t.host)}
          onQueued={queued}
          onClose={() => setDetecting(false)} />
      )}
      {scanningRanges && project && (
        <ScanRangesDialog project={project} selected={selectedRows}
          onQueued={queued}
          onClose={() => setScanningRanges(false)} />
      )}
      {nmapOn && project && (
        <NmapScanDialog project={project} targets={nmapOn}
          onQueued={queued}
          onClose={() => setNmapOn(null)} />
      )}
      {toast && (
        <Snackbar open autoHideDuration={9000}
          onClose={() => setToast(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
          <Alert severity="success" variant="outlined"
            onClose={() => setToast(null)}
            sx={{ bgcolor: alpha(neon.paper, 0.98), fontSize: 12.5,
                  maxWidth: 560 }}>
            {toast}
          </Alert>
        </Snackbar>
      )}
      {lookup && project && (
        <LookupQueueDialog project={project} kind={lookup.kind} onQueued={queued}
          subjects={lookup.subjects} onClose={() => setLookup(null)} />
      )}
      {picking && project && (
        <FqdnPickerDialog project={project} rows={pending.data}
          loading={pending.isLoading} error={pending.error as Error | null}
          auto={auto} onClose={() => setPicking(false)} />
      )}
      {/* Only with one engagement in view: these are per-project
          settings and "all projects" has no sensible meaning for
          them. Above the table rather than behind a menu, because
          something that scans a client on its own should be visible
          from the screen that shows what it scanned. */}
      {project && <StandingOrders project={project} />}
      <DataTable
        rows={rows}
        columns={columns as ColumnDef[]}
        loading={isLoading}
        error={error as Error | null}
        initialSort={{ field: 'host', sort: 'asc' }}
        hiddenColumns={project ? { project_code: false } : undefined}
        kind="targets"
        project={project}
        canWrite={writable}
        onSelectionChange={setSelected}
        note={writable ? undefined : 'read-only'}
        extraActions={writable && project ? (
          <>
            <EnumerateMenu onPick={onEnumerate}
              liveAgents={live.length}
              enrolledAgents={enrolled}
              selectedCount={selected.length}
              unnamedCount={unnamed.length}
              unnamedSelectedCount={unnamedSelected.length}
              unaddressedCount={unaddressed.length}
              unaddressedSelectedCount={unaddressedSelected.length} />
            {/* Shown whenever a lookup has come home with anything to
                report, not only when there is a decision to take: a
                lookup that found nothing, and one whose single answer
                could not be applied, both need saying. The badge counts
                only the decisions. */}
            {(!!pending.data?.length || auto.failed) && (
              <Tooltip title={choices.length
                ? 'A reverse lookup returned more than one name for the same '
                  + 'address. Only a person can say which is the right one.'
                : 'Finished lookups, including ones that came back empty.'}>
                <Badge badgeContent={choices.length} color="warning">
                  <Button size="small" variant="outlined" onClick={() => setPicking(true)}
                    sx={{ color: choices.length || auto.failed ? neon.yellow : neon.muted,
                          borderColor: alpha(choices.length || auto.failed
                            ? neon.yellow : neon.muted, 0.5),
                          fontSize: 11, py: 0.3 }}>
                    Lookup results
                  </Button>
                </Badge>
              </Tooltip>
            )}
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
