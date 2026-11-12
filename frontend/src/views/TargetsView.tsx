import { useEffect, useMemo, useState } from 'react'
import {
  Alert, Badge, Box, Button, Checkbox, Chip, Dialog, DialogContent,
  DialogTitle, Divider, ListItemButton, Snackbar, Stack, Tab, Tabs, Tooltip,
  Typography, alpha,
} from '@mui/material'
import ScanIcon from '@mui/icons-material/RadarOutlined'
import KeyIcon from '@mui/icons-material/Key'
import type { ColumnDef } from '../lib/columns'
import { countryCell, extraAddresses } from '../lib/cellFacts'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Target } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from '../components/DataTable'
import { useServerTable } from '../lib/useServerTable'
import { CloudTargetsPanel } from '../components/CloudTargetsPanel'
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
import { WebDiscoveryDialog } from '../components/WebDiscoveryDialog'
import { ProbeDialog } from '../components/ProbeDialog'
import { neon, glow, TAB_SX } from '../theme'
import { useRouteParam, useTab } from '../lib/route'

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
  return /^[0-9a-f:]+(%[0-9a-z]+)?$/i.test(s) && s.includes(':');
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
 *  permanent outstanding task.
 *
 *  A cloud resource is excluded for the same reason and was not: its
 *  identifier is an ARN, a bucket name or a resource path, not a
 *  hostname, so there is no name here to look up. Queueing one sent
 *  the client's resource names to a resolver to be told, correctly,
 *  that no such name exists. The backend applies the same rule — see
 *  `dns_subject` in `app/hosts.py` — so a sweep queued any other way
 *  drops them too.
 *
 *  A provider-assigned name (`cloud_ephemeral`) is excluded for a
 *  third reason: the provider derives it FROM the address, so looking
 *  it up tells us what we would already know if the row had been
 *  filed with its address, and on a cloud estate these outnumber the
 *  real gaps several to one. The list exists to show what is still
 *  missing; burying three of those under 5,000 PTR names is the same
 *  as not having it. A name chosen inside a cloud is a real gap and
 *  stays. */
function needsAddress(t: Target): boolean {
  return t.kind !== 'mobile' && t.kind !== 'cloud' && !t.cloud_ephemeral
    && hasName(t) && !(t.ip_address ?? '').trim()
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
  const [tab, setTab] = useTab(['scope', 'cloud'], 'scope',
                                useRouteParam('tab'))
  const [importing, setImporting] = useState(false)
  // The target that would be absorbed and removed.
  const [merging, setMerging] = useState<Target | null>(null)
  const [detecting, setDetecting] = useState(false)
  const [picking, setPicking] = useState(false)
  const [scanningRanges, setScanningRanges] = useState(false)
  const [webDiscovery, setWebDiscovery] = useState(false)
  // httpx or nuclei, or neither. One dialog: they differ in
  // what they are pointed at, and the server decides that.
  const [probe, setProbe] = useState<'httpx' | 'nuclei' | null>(null)
  // Ranges the queue refused for scope, carried back so Scan New
  // Ranges can re-open with them. Every other refusal is just news;
  // this one has something to do about it, and the dialog now closes
  // the moment Queue is pressed, so it cannot hold on to them itself.
  const [refusedScope, setRefusedScope] = useState<string[]>([])
  const [nmapOn, setNmapOn] = useState<string[] | null>(null)
  const [lookup, setLookup] = useState<{ kind: LookupKind; subjects: string[] } | null>(null)
  //: The confirmation a closed modal would otherwise have taken with it.
  // `severity` because a dialog that closes the instant you press
  // Queue can no longer show you why nothing was queued. The reason
  // has to arrive here instead, and a refusal must not be dressed as
  // a success.
  const [toast, setToast] = useState<
    { message: string; severity: 'success' | 'error' | 'info' } | null>(null)
  const [selected, setSelected] = useState<number[]>([])
  const [assignCredsOpen, setAssignCredsOpen] = useState(false)

  // Paged in the database. This fetched every target in the project
  // -- 10,338 rows and 8.2 MB on this engagement -- to render a
  // screenful, and half that payload was the JSON key names repeated
  // once per row. The browser then split it into two tabs and
  // counted two gaps out of it; both of those are the server's job
  // now, which is what made paging possible at all.
  const table = useServerTable('targets', {
    sort: 'host', order: 'asc', pageSize: 100,
    filterable: ['host', 'kind', 'geo_country', 'ip_address', 'alive', 'hacked'],
  })
  const { data, isLoading, error } = useQuery({
    queryKey: ['targets', project, tab, table.query],
    queryFn: () => api.targetPage({
      project: project ?? undefined,
      q: table.query.q || undefined,
      sort: table.query.sort,
      order: table.query.order,
      // The tab IS the filter. `cloud_family` is computed from the
      // host rather than stored, so this cannot be a plain column
      // filter -- see `_cloud_ids`, which applies the same
      // classifier the API exposes.
      cloud: tab === 'cloud',
      limit: table.query.pageSize,
      offset: table.query.page * table.query.pageSize,
      filters: table.query.filters || undefined,
      logic: table.query.logic,
    }),
    enabled: !!project,
    placeholderData: (prev) => prev,
  })
  const { setTotal, setPage } = table
  useEffect(() => { setTotal(data?.total ?? 0) }, [setTotal, data?.total])
  // A different project, or the other tab, is a different result
  // set: page 7 of the old one means nothing.
  useEffect(() => { setPage(0) }, [setPage, project, tab])

  // The two tab counts, and the two Enumerate gap counts. Four
  // integers that used to be derived from every row in the project.
  const counts = useQuery({
    queryKey: ['target-counts', project],
    queryFn: async () => {
      const [cloud, scope, gaps] = await Promise.all([
        api.targetPage({ project: project as string, cloud: true, limit: 1 }),
        api.targetPage({ project: project as string, cloud: false, limit: 1 }),
        api.targetGaps(project as string),
      ])
      return { cloud: cloud.total ?? 0, scope: scope.total ?? 0, ...gaps }
    },
    enabled: !!project,
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

  // Whether locating addresses is possible here, and whether there is
  // anything left to locate. Cheap — one count — and it writes
  // nothing, so the menu can ask it without that being an action.
  const geo = useQuery({
    queryKey: ['enumerate-geolocation', project],
    queryFn: () => api.enumerateGeolocation(project as string),
    enabled: !!project && writable,
  })

  const geolocate = useMutation({
    mutationFn: () => api.enumerateGeolocate(project as string),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ['targets'] })
      void qc.invalidateQueries({ queryKey: ['enumerate-geolocation'] })
      const n = Object.keys(r.located).length
      if (!r.usable) { setToast({ message: r.note, severity: 'info' }); return }
      // Each of the three outcomes gets said. "41 located" on its own
      // would let the addresses MaxMind knows nothing about, and the
      // ones the batch limit never reached, both read as located.
      const parts = [`${n} address${n === 1 ? '' : 'es'} located`]
      if (r.unknown.length) parts.push(`${r.unknown.length} with no data`)
      if (r.remaining) parts.push(`${r.remaining} still to do — run it again`)
      setToast({ message: parts.join(', '),
                 severity: n ? 'success' : 'info' })
    },
    onError: (e: Error) =>
      setToast({ message: e.message, severity: 'error' }),
  })

  const auto = useAutoApplySingles(writable ? project : null, pending.data)
  const choices = useMemo(() => openChoices(pending.data), [pending.data])

  const rows = useMemo(() => data?.items ?? [], [data])

  // Two tabs over one fetch. A name a provider assigned per address
  // is the provider's naming, not the client's estate -- on this
  // engagement that is the large majority of the list, and mixing
  // the two is what makes the real estate hard to see.
  //
  // `rows` itself is deliberately NOT narrowed: selection, the
  // enumerate counts and the merge candidates all read it, and a
  // cloud-named host is still a host you can look up or scan. Only
  // what each tab DISPLAYS is split.
  // The server already filtered to this tab, so the page IS the
  // rows. The split used to happen here because the fetch carried
  // both kinds.
  const scopeRows = rows
  const selectedRows = useMemo(() => {
    const want = new Set(selected)
    return rows.filter((t) => want.has(t.id))
  }, [rows, selected])

  // Project-wide, from the server. These drive the Enumerate menu's
  // "N targets need a name" and the actions behind it, so they have
  // to describe the ESTATE and not the page -- which is exactly what
  // they would describe if they were still counted from `rows`.
  const unnamedCount = counts.data?.needs_name ?? 0
  const unaddressedCount = counts.data?.needs_address ?? 0
  // The selected ones stay client-side and are still correct: you
  // can only select rows you can see.
  const unnamedSelected = useMemo(
    () => selectedRows.filter(needsName), [selectedRows])
  const unaddressedSelected = useMemo(
    () => selectedRows.filter(needsAddress), [selectedRows])

  // Closing the modal and saying so outside it. A dialog that stays
  // open on success has to be dismissed before the operator can get
  // back to the table, which is the next thing they want; the
  // confirmation still matters, so it is not simply dropped.
  const closeAll = () => {
    setDetecting(false); setScanningRanges(false); setNmapOn(null)
    setWebDiscovery(false)
    setProbe(null)
    setLookup(null)
  }

  /** Re-open Scan New Ranges holding what scope refused. Deferred a
   *  tick because `queued` closes everything first, and the two
   *  firing in the same batch would close what this just opened. */
  const reopenForScope = (ranges: string[]) => {
    setRefusedScope(ranges)
    setTimeout(() => setScanningRanges(true), 0)
  }

  /** A dialog reporting on work it started. Called AFTER it closed.
   *
   *  Queueing a sweep is one request that creates thousands of rows,
   *  and the dialog used to sit there until it returned — which on a
   *  large estate reads as a hung window. The dialog now hands the
   *  work over and closes; this is where the answer lands. */
  const queued = (message: string,
                  severity: 'success' | 'error' | 'info' = 'success') => {
    closeAll()
    setToast({ message, severity })
  }

  const onEnumerate = (a: EnumerateAction) => {
    if (a === 'detect-domains') setDetecting(true)
    else if (a === 'geolocate') geolocate.mutate()
    else if (a === 'scan-ranges') setScanningRanges(true)
    else if (a === 'web-discovery') setWebDiscovery(true)
    else if (a === 'probe-web') setProbe('httpx')
    else if (a === 'template-scan') setProbe('nuclei')
    else if (a === 'ip-all' || a === 'ip-selected') {
      // Forward: a name we hold, resolved to the address it points at.
      if (a === 'ip-selected') {
        setLookup({ kind: 'nslookup',
                    subjects: unaddressedSelected.map((t) => t.host) })
      } else {
        // "All" is the whole ESTATE, which the browser no longer
        // holds. Asked for when the action is taken rather than
        // carried on every page load — it is thousands of names.
        void api.targetGapSubjects(project as string, 'address')
          .then((r) => setLookup({ kind: 'nslookup', subjects: r.subjects }))
      }
    } else if (a === 'fqdn-selected') {
      setLookup({ kind: 'reverse_ip',
                  subjects: unnamedSelected.map(addressOf) })
    } else {
      // Reverse: an address we hold, asked what it is called. The
      // server returns the addresses themselves, so `addressOf` is
      // not re-applied — for these rows the host IS the address,
      // which is the condition that put them in the list.
      void api.targetGapSubjects(project as string, 'name')
        .then((r) => setLookup({ kind: 'reverse_ip', subjects: r.subjects }))
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
      // A two-letter code, or the word the cell shows when there is
      // no code to show — "unknown" is wider than any country code
      // and is part of the content, not an edge case.
      country: fit('Country', Math.max(
        widest((t) => chipWidth(t.geo_country ?? '')
                    + ((t.geo_countries?.length ?? 0) > 1
                        ? chipWidth(`+${(t.geo_countries?.length ?? 1) - 1}`) + 6 : 0)),
        textWidth('unknown'))),
      alive: fit('Alive', Math.max(chipWidth('DOWN'), textWidth('N/A'))),
      // An icon button, or the italic N/A a mobile row shows instead.
      actions: fit('Action', Math.max(34, textWidth('N/A'))),
    }
  }, [rows])

  // Memoised. A fresh array every render makes every memo inside
  // TableGrid that is keyed on `columns` recompute, and TanStack
  // rebuild its column model from them — on every keystroke in the
  // search box and every unrelated state change in this view.
  const columns: ColumnDef<Target>[] = useMemo(() => [
    {
      field: 'status_icons', headerName: '', width: 60, minWidth: 60, sortable: false,
      renderCell: (p) => {
        const r = p.row as Target & { total_ports?: number; web_count?: number; total_criticals?: number }
        return (
          <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
            {(r.total_ports ?? 0) > 0 && (
              <Tooltip title="Has been port-scanned">
                <span style={{ fontSize: 12, opacity: 0.9 }}>🔍</span>
              </Tooltip>
            )}
            {(r.web_count ?? 0) > 0 && (
              <Tooltip title="Has been web-enumerated">
                <span style={{ fontSize: 12, opacity: 0.9 }}>🌐</span>
              </Tooltip>
            )}
            {(r.total_criticals ?? 0) > 0 && (
              <Tooltip title="Has critical findings">
                <span style={{ fontSize: 12, opacity: 0.9 }}>🔴</span>
              </Tooltip>
            )}
          </Box>
        )
      },
    },
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
      type: 'singleSelect', valueOptions: ['host', 'mobile', 'cloud', 'repo'],
      renderCell: (p) => {
        const c = p.value === 'mobile' ? neon.purple
          : p.value === 'cloud' ? neon.cyan
          : p.value === 'repo' ? '#a78bfa' : neon.muted
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
    // Where the host's addresses are, in place of the Provider column
    // that used to sit here. Provider was null on every row but the
    // cloud ones, and for those the Type chip beside it already shows
    // it — so the column cost a column's width to repeat one chip and
    // be empty the rest of the time.
    //
    // Three states, kept apart on purpose. A country is an answer; a
    // looked-up address MaxMind knows nothing about is a different
    // answer; and an address nobody has looked up yet is not an answer
    // at all, it is a gap in our coverage. A single blank cell for the
    // last two would read as "no geolocation for this host", which is
    // a claim about the host made out of a claim about us.
    { field: 'geo_country', headerName: 'Country', width: widths.country,
      type: 'singleSelect',
      valueOptions: [
        'US', 'GB', 'DE', 'FR', 'JP', 'NL', 'SG', 'AU', 'CA', 'BR',
        'IN', 'KR', 'SE', 'CH', 'AT', 'BE', 'IT', 'ES', 'PL', 'DK',
      ],
      valueGetter: (v) => v ?? '',
      renderCell: (p) => {
        const c = countryCell(p.row)
        if (c.state === 'na') {
          return <Box sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic' }}>N/A</Box>
        }
        if (c.state === 'none') return null
        if (c.state === 'unasked') {
          return (
            <Tooltip title={(c.pending
                      ? `${c.pending} address${c.pending === 1 ? '' : 'es'} not `
                      : 'Not ')
                      + 'looked up yet — Enumerate → Locate addresses'}>
              <Box sx={{ color: alpha(neon.muted, 0.7) }}>—</Box>
            </Tooltip>
          )
        }
        if (c.state === 'unknown') {
          return (
            <Tooltip title="Looked up; the GeoLite2 databases hold no country for it. Normal for a private range.">
              <Box sx={{ color: alpha(neon.muted, 0.7), fontSize: 11 }}>unknown</Box>
            </Tooltip>
          )
        }
        if (c.state === 'internal') {
          return (
            <Tooltip title={`Private / link-local address${c.addresses.length > 1 ? 'es' : ''}: ${c.addresses.join(', ')}`}>
              <Chip size="small" label="Internal" sx={{
                height: 19, fontSize: 10, letterSpacing: '0.06em',
                bgcolor: alpha(neon.green, 0.15), color: neon.green,
                border: `1px solid ${alpha(neon.green, 0.5)}`,
              }} />
            </Tooltip>
          )
        }
        const extra = Math.max(0, c.all.length - 1)
        return (
          <Stack
            direction="row"
            spacing={0.6}
            sx={{
              alignItems: "center",
              minWidth: 0
            }}>
            <Tooltip title={c.name ?? c.code}>
              <Chip size="small" label={c.code} sx={{
                height: 19, fontSize: 10, letterSpacing: '0.06em',
                bgcolor: alpha(neon.cyan, 0.15), color: neon.cyan,
                border: `1px solid ${alpha(neon.cyan, 0.5)}`,
              }} />
            </Tooltip>
            {extra > 0 ? (
              // A host answering in several countries is a CDN or an
              // anycast front, and that is worth seeing rather than
              // flattening to whichever address was observed first.
              <Tooltip title={`Answers in ${c.all.join(', ')} — addresses in `
                            + `more than one country, usually a CDN or anycast`}>
                <Chip size="small" label={`+${extra}`} sx={{
                  height: 17, fontSize: 9.5,
                  bgcolor: alpha(neon.purple, 0.15), color: neon.purple,
                  border: `1px solid ${alpha(neon.purple, 0.4)}`,
                }} />
              </Tooltip>
            ) : null}
          </Stack>
        );
      } },
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
          <Stack
            direction="row"
            spacing={0.6}
            sx={{
              alignItems: "center",
              minWidth: 0
            }}>
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
        );
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
  // Values, not objects: `widths.*` are numbers and `live.length`
  // and `enrolled` are counts, so the memo compares equal between
  // renders. `canWrite` and `open` come from contexts that memoise
  // their value — the memo is worthless if a dependency is rebuilt
  // every render, which is the trap when copying this pattern.
  ], [canWrite, enrolled, live.length, open, widths.actions, widths.alive,
      widths.country, widths.ip, widths.kind])

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
          refusedScope={refusedScope}
          onRefusedScope={reopenForScope}
          onClose={() => { setScanningRanges(false); setRefusedScope([]) }} />
      )}
      {webDiscovery && project && (
        <WebDiscoveryDialog project={project}
          onQueued={queued}
          onClose={() => setWebDiscovery(false)} />
      )}
      {probe && project && (
        <ProbeDialog project={project} tool={probe}
          onQueued={queued}
          onClose={() => setProbe(null)} />
      )}
      {nmapOn && project && (
        <NmapScanDialog project={project} targets={nmapOn}
          onQueued={queued}
          onClose={() => setNmapOn(null)} />
      )}
      {toast && (
        <Snackbar open
          // The "queueing…" notice must not time out from under the
          // work it describes; the result replaces it when it lands.
          autoHideDuration={toast.severity === 'info' ? null : 9000}
          onClose={() => setToast(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
          <Alert severity={toast.severity} variant="outlined"
            onClose={() => setToast(null)}
            sx={{ bgcolor: alpha(neon.paper, 0.98), fontSize: 12.5,
                  maxWidth: 560 }}>
            {toast.message}
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
      {assignCredsOpen && project && (
        <AssignCredsDialog project={project} rows={rows} selectedIds={selected}
          onClose={() => setAssignCredsOpen(false)} />
      )}
      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        sx={{ minHeight: 34, px: 2, pt: 0.5,
              borderBottom: `1px solid ${alpha(neon.purple, 0.25)}` }}>
        {/* Counted by the server, so the label describes the project
            rather than the page. It used to read the length of a
            browser-side filter over every row in the estate. */}
        <Tab value="scope" sx={TAB_SX}
          label={`In Scope${counts.data?.scope
            ? ` (${counts.data.scope.toLocaleString()})` : ''}`} />
        <Tab value="cloud" sx={TAB_SX}
          label={`Cloud${counts.data?.cloud
            ? ` (${counts.data.cloud.toLocaleString()})` : ''}`} />
      </Tabs>
      {tab === 'cloud' ? (
        <Box sx={{ flex: 1, minHeight: 0, height: '100%',
                   display: 'flex', flexDirection: 'column' }}>
          {/* The same paged fetch: `cloud: tab === 'cloud'` above
              means `rows` already IS the cloud page here. */}
          <CloudTargetsPanel rows={rows} project={project}
            onOpen={(t) => open(t.project_code, t.host)} />
        </Box>
      ) : (
      <DataTable
        rows={scopeRows}
        columns={columns as ColumnDef[]}
        loading={isLoading}
        error={error as Error | null}
        server={table}
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
              unnamedCount={unnamedCount}
              unnamedSelectedCount={unnamedSelected.length}
              unaddressedCount={unaddressedCount}
              unaddressedSelectedCount={unaddressedSelected.length}
              geoUsable={geo.data?.usable ?? false}
              geoPending={geo.data?.remaining ?? 0} />
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
            <Button size="small" variant="outlined" startIcon={<KeyIcon sx={{ fontSize: 16 }} />}
              onClick={() => setAssignCredsOpen(true)}
              sx={{ color: neon.pink, borderColor: alpha(neon.pink, 0.5), fontSize: 11, py: 0.3 }}>
              Assign credentials
            </Button>
          </>
        ) : undefined}
      />
      )}
    </>
  )
}

/* --------------------------------------------------------------------------
   Bulk credential assignment: pick the targets (the selected rows, or every
   target in scope) and the credentials they should carry. The endpoint is
   per-host — it REPLACES a target's assignment set — so each chosen host gets
   its own PUT with the full list. A named-to-credential still applies after
   the call; this only adds rows on top of what the importers recorded.
-------------------------------------------------------------------------- */

function AssignCredsDialog({ project, rows, selectedIds, onClose }: {
  project: string
  rows: Target[]
  /** Target ids already selected in the grid when the dialog opened. */
  selectedIds: number[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [hosts, setHosts] = useState<Set<string>>(
    new Set(rows.filter((t) => selectedIds.includes(t.id)).map((t) => t.host)))
  const [allTargets, setAllTargets] = useState(selectedIds.length === 0)
  const [credSel, setCredSel] = useState<Set<number>>(new Set())

  const creds = useQuery({
    queryKey: ['credentials', project],
    queryFn: () => api.credentials(project),
  })

  // "All targets" needs the full list; the grid only holds one page.
  const allRows = useQuery({
    queryKey: ['targets-all-assign', project],
    queryFn: () => api.targetPage({ project, limit: 100000, offset: 0 }),
    enabled: allTargets,
  })

  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<string | null>(null)

  const toggleHost = (h: string) => {
    setAllTargets(false)
    setHosts((prev) => {
      const next = new Set(prev)
      if (next.has(h)) next.delete(h); else next.add(h)
      return next
    })
  }

  const toggleCred = (id: number) => {
    setCredSel((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const targetList = allTargets
    ? (allRows.data?.items ?? []).map((t) => t.host)
    : Array.from(hosts)

  const save = async () => {
    if (targetList.length === 0 || credSel.size === 0) return
    setBusy(true)
    let ok = 0, failed = 0
    for (const h of targetList) {
      try {
        await api.assignTargetCredentials(project, h, Array.from(credSel))
        ok++
      } catch { failed++ }
    }
    setBusy(false)
    setDone(`Assigned ${credSel.size} credential${credSel.size === 1 ? '' : 's'} to ${ok} target${ok === 1 ? '' : 's'}${failed ? ` (${failed} failed)` : ''}`)
    qc.invalidateQueries({ queryKey: ['target-detail'] })
  }

  return (
    <Dialog open onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                          letterSpacing: '0.1em', color: neon.pink }}>
        Assign credentials to targets
      </DialogTitle>
      <Divider />
      <DialogContent dividers sx={{ minHeight: 320 }}>
        {done ? (
          <Stack spacing={1.5} sx={{ py: 3, alignItems: 'center' }}>
            <Typography sx={{ color: neon.green, fontSize: 13 }}>{done}</Typography>
            <Button size="small" variant="outlined" onClick={onClose}
              sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.4) }}>Done</Button>
          </Stack>
        ) : (
          <Stack spacing={2}>
            {/* Targets */}
            <Box>
              <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
                                  letterSpacing: '0.14em', textTransform: 'uppercase',
                                  color: alpha(neon.cyan, 0.75), mb: 0.8 }}>
                Targets ({targetList.length})
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
                <Button size="small" variant="outlined" onClick={() => setAllTargets(true)}
                  sx={{ fontSize: 11, color: allTargets ? neon.cyan : neon.muted,
                        borderColor: alpha(allTargets ? neon.cyan : neon.muted, 0.4) }}>
                  All targets in project
                </Button>
                <Button size="small" variant="outlined" onClick={() => setAllTargets(false)}
                  sx={{ fontSize: 11, color: !allTargets ? neon.cyan : neon.muted,
                        borderColor: alpha(!allTargets ? neon.cyan : neon.muted, 0.4) }}>
                  Selected rows ({hosts.size})
                </Button>
              </Stack>
              {!allTargets && (
                <Box sx={{ maxHeight: 160, overflowY: 'auto', border: `1px solid ${alpha(neon.cyan, 0.2)}`, p: 1 }}>
                  {rows.length === 0
                    ? <Typography sx={{ color: neon.muted, fontSize: 12 }}>No rows on this page.</Typography>
                    : rows.map((t) => (
                      <ListItemButton key={t.id} onClick={() => toggleHost(t.host)}
                        selected={hosts.has(t.host)}
                        sx={{ px: 0.5, py: 0.25, minHeight: 30 }}>
                        <Checkbox size="small" checked={hosts.has(t.host)}
                          sx={{ color: neon.cyan, mr: 0.5 }} />
                        <Typography sx={{ fontSize: 12 }}>{t.host}</Typography>
                      </ListItemButton>
                    ))}
                </Box>
              )}
              {allTargets && (
                <Typography sx={{ color: neon.muted, fontSize: 12 }}>
                  {allRows.isLoading ? 'Loading…' : `${targetList.length} targets in ${project}`}
                </Typography>
              )}
            </Box>
            {/* Credentials */}
            <Box>
              <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
                                  letterSpacing: '0.14em', textTransform: 'uppercase',
                                  color: alpha(neon.pink, 0.75), mb: 0.8 }}>
                Credentials ({credSel.size} selected)
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
                <Button size="small" variant="outlined"
                  onClick={() => setCredSel(new Set((creds.data?.items ?? []).map((c) => c.id)))}
                  sx={{ fontSize: 11, color: neon.cyan, borderColor: alpha(neon.cyan, 0.4) }}>
                  Select all
                </Button>
                <Button size="small" variant="outlined" onClick={() => setCredSel(new Set())}
                  sx={{ fontSize: 11, color: neon.muted, borderColor: alpha(neon.muted, 0.3) }}>
                  Clear
                </Button>
              </Stack>
              <Box sx={{ maxHeight: 200, overflowY: 'auto', border: `1px solid ${alpha(neon.pink, 0.25)}`, p: 1 }}>
                {creds.isLoading
                  ? <Typography sx={{ color: neon.muted, fontSize: 12 }}>Loading…</Typography>
                  : (creds.data?.items ?? []).length === 0
                    ? <Typography sx={{ color: neon.muted, fontSize: 12 }}>No credentials in this project yet.</Typography>
                    : (creds.data?.items ?? []).map((c) => (
                      <ListItemButton key={c.id} onClick={() => toggleCred(c.id)}
                        selected={credSel.has(c.id)}
                        sx={{ px: 0.5, py: 0.25, minHeight: 30 }}>
                        <Checkbox size="small" checked={credSel.has(c.id)}
                          sx={{ color: neon.pink, mr: 0.5 }} />
                        <Typography sx={{ fontSize: 12 }}>
                          {c.host || '(no host)'} — {c.kind}{c.username ? ` / ${c.username}` : ''}
                        </Typography>
                      </ListItemButton>
                    ))}
              </Box>
            </Box>
          </Stack>
        )}
      </DialogContent>
      {!done && (
        <Box sx={{ px: 2, py: 1.5 }}>
          <Button size="small" variant="contained" disabled={busy || targetList.length === 0 || credSel.size === 0}
            onClick={() => void save()}
            sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.08em' }}>
            {busy ? 'Assigning…' : `Assign to ${targetList.length} target${targetList.length === 1 ? '' : 's'}`}
          </Button>
        </Box>
      )}
    </Dialog>
  )
}
