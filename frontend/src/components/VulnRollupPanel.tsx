/**
 * The findings, rolled up two ways.
 *
 * "This host has 400 things wrong" and "this one thing is wrong on
 * 400 hosts" are different questions and neither answers the other.
 * The flat All tab answers a third — "what is wrong with this
 * estate" — and on a project with 23,000 findings it answers none of
 * them well.
 *
 * **Aggregated on the server.** Both tabs are a GROUP BY; the
 * findings behind a row are fetched only when it is expanded.
 * Grouping in the browser would mean shipping every finding first,
 * which is the thing this exists to avoid.
 *
 * **Real `DataTable`s.** They sort, filter, resize and export like
 * every other table here, and they expand — see `renderDetail`.
 * Expansion used to be impossible in the grid and the panels were
 * hand-rolled lists; that made them the only tables in the app that
 * looked different and did less.
 */
import { useMemo, useState } from 'react'
import { Box, Chip, CircularProgress, Stack, Tooltip, alpha } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '../lib/columns'
import { api, type Vuln, type VulnsByTargetRow, type VulnsByTitleRow } from '../lib/api'
import { SEVERITY_COLOUR as SEV } from '../lib/severity'
import { DataTable } from './DataTable'
import { neon, glow } from '../theme'

/** Worst first, and the order the server rolls up in. */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

/** A count cell. Zero is shown as a dash and not left blank: "no
 *  criticals" is an answer, and an empty cell reads as "not counted". */
function Count({ n, colour }: { n: number; colour?: string }) {
  if (!n) return <Box sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>
  return (
    <Box sx={{ color: colour ?? neon.text, fontWeight: 700,
               textShadow: colour === neon.red ? glow(neon.red, 0.4) : 'none' }}>
      {n.toLocaleString()}
    </Box>
  )
}

function Severity({ value }: { value: string }) {
  return (
    <Box sx={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '0.08em',
               textTransform: 'uppercase', color: SEV[value] ?? neon.muted,
               textShadow: value === 'critical' ? glow(neon.red, 0.45) : 'none' }}>
      {value}
    </Box>
  )
}

/** The findings behind one expanded row. */
/** Worst first, then everything settled pushed to the bottom.
 *
 *  Three keys, in the order somebody reading an expanded host
 *  actually works:
 *
 *    severity   critical before info. Alphabetical would put
 *               `critical` before `high` by luck and `info` before
 *               `low` by accident, which is why this is a table and
 *               not a string compare.
 *    last scan  what the most recent scan said. `resolved` means the
 *               scan looked and it was gone, so it goes last -- it
 *               is the one row in the list nobody has to do anything
 *               about. `unconfirmed` does NOT go last: nothing that
 *               reports this finding has run since, so its absence
 *               is unmeasured rather than fixed.
 *    status     what somebody DID about it. Closed last, for the
 *               same reason: it is finished.
 *
 *  Then newest sighting, then title, so the order is stable between
 *  renders rather than whatever the server's `Vuln.id` happened to be.
 */
const SEV_RANK: Record<string, number> =
  Object.fromEntries(SEVERITIES.map((s, i) => [s, i]))

export function byWorstFirst(a: Vuln, b: Vuln): number {
  const sev = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99)
  if (sev) return sev
  const gone = Number(a.lifecycle === 'resolved') - Number(b.lifecycle === 'resolved')
  if (gone) return gone
  const shut = Number(a.status === 'closed') - Number(b.status === 'closed')
  if (shut) return shut
  const seen = (b.last_seen_at ?? '').localeCompare(a.last_seen_at ?? '')
  if (seen) return seen
  return (a.title ?? '').localeCompare(b.title ?? '')
}

export type Dup = Vuln & { dupes: number }

/** One entry per distinct thing, carrying how many rows said it.
 *
 *  A rollup's expansion is "what is this row made of", and listing
 *  the same host twice under one vulnerability answers a question
 *  nobody asked while contradicting the count beside it -- the `hosts`
 *  column already counts DISTINCT hosts, so two rows for one host made
 *  the table disagree with itself on screen.
 *
 *  Duplicates are real and routine: an importer that ran twice, or a
 *  source that recorded the same finding twice with different ids.
 *  Collapsing is a display decision and nothing is deleted.
 *
 *  **Port is part of the identity.** The same title on 443 and on
 *  8443 is two instances, not one row seen twice, and merging those
 *  would hide a genuine second exposure. Only rows that match on
 *  everything the view distinguishes are folded.
 *
 *  The survivor is the worst one, so collapsing can never lower what
 *  the row reports: an open critical and a closed duplicate of it
 *  collapse to the open critical.
 */
export function collapse(rows: Vuln[], sameAs: (v: Vuln) => string): Dup[] {
  const by = new Map<string, Dup>()
  for (const v of rows) {
    const k = sameAs(v)
    const had = by.get(k)
    if (!had) {
      by.set(k, { ...v, dupes: 1 })
      continue
    }
    const keep = byWorstFirst(v, had) < 0 ? v : had
    by.set(k, { ...keep, dupes: had.dupes + 1 })
  }
  return [...by.values()]
}

function Detail({ rows, loading, onFinding, show, sameAs }: {
  rows: Vuln[]
  loading: boolean
  onFinding: (id: number) => void
  show: (v: Vuln) => React.ReactNode
  /** What makes two rows the same thing in THIS view. By Vuln is
   *  already filtered to one title, so a host is the identity; By
   *  Target is filtered to one host, so the title is. */
  sameAs: (v: Vuln) => string
}) {
  // Deduplicated and sorted here rather than at each call site: both
  // rollups expand into this, and two copies of either is two of
  // whatever they disagree about.
  const ordered = useMemo(
    () => collapse(rows, sameAs).sort(byWorstFirst), [rows, sameAs])
  if (loading) {
    return <Stack sx={{ alignItems: 'center', py: 1 }}>
      <CircularProgress size={15} sx={{ color: neon.cyan }} />
    </Stack>
  }
  if (!ordered.length) {
    return <Box sx={{ fontSize: 11.5, color: neon.muted }}>
      Nothing came back for this row.
    </Box>
  }
  return (
    <Stack spacing={0.2}>
      {ordered.map((v) => (
        <Box key={v.id} onClick={() => onFinding(v.id)}
          sx={{ display: 'flex', alignItems: 'center', gap: 1,
                px: 0.6, py: 0.4, fontSize: 11.5, borderRadius: 0.5,
                cursor: 'pointer',
                '&:hover': { backgroundColor: alpha(neon.cyan, 0.1) } }}>
          {show(v)}
          {!!v.port && (
            <Chip size="small" label={`:${v.port}`} variant="outlined"
              sx={{ height: 16, fontSize: 10, color: neon.muted,
                    borderColor: alpha(neon.muted, 0.35) }} />
          )}
          {/* Collapsed, not hidden. Several rows for one thing is a
              fact about the data -- usually an importer that ran
              twice, or a source that recorded it twice -- and an
              operator reconciling against that source needs to know
              the rows are there. */}
          {(v as Dup).dupes > 1 && (
            <Tooltip title={`${(v as Dup).dupes} finding rows say this. They
                             are the same thing here, so they are shown once;
                             open it to see the one this links to.`}>
              <Chip size="small" label={`×${(v as Dup).dupes}`}
                variant="outlined"
                sx={{ height: 16, fontSize: 10, color: neon.yellow,
                      borderColor: alpha(neon.yellow, 0.45) }} />
            </Tooltip>
          )}
        </Box>
      ))}
    </Stack>
  )
}

// ---------------------------------------------------------- by target
export function VulnsByTarget({ project, onFinding }: {
  project: string | null
  onFinding: (id: number) => void
}) {
  const [open, setOpen] = useState<string | null>(null)
  const q = useQuery({
    queryKey: ['vulns-by-target', project],
    queryFn: () => api.vulnsByTarget(project as string),
    enabled: !!project,
  })
  const detail = useQuery({
    queryKey: ['vulns-of-host', project, open],
    queryFn: () => api.vulnsForHost(project as string, open as string),
    enabled: !!open && !!project,
  })

  const columns: ColumnDef<VulnsByTargetRow>[] = [
    { field: 'host', headerName: 'Host', flex: 2, minWidth: 220,
      renderCell: (p) => (
        <Box sx={{ fontFamily: `'Share Tech Mono', monospace`,
                   color: neon.cyan }}>{p.value}</Box>
      ) },
    { field: 'total', headerName: 'Vulns', width: 92, type: 'number',
      renderCell: (p) => <Count n={p.value as number} /> },
    ...SEVERITIES.map((s): ColumnDef<VulnsByTargetRow> => ({
      field: s,
      headerName: s === 'critical' ? 'Crit' : s[0].toUpperCase() + s.slice(1),
      width: s === 'critical' ? 80 : 76,
      type: 'number',
      renderCell: (p) => <Count n={p.value as number} colour={SEV[s]} />,
    })),
  ]

  return (
    <DataTable
      rows={q.data?.items ?? []}
      columns={columns as ColumnDef[]}
      loading={q.isLoading}
      error={q.error as Error | null}
      tableId="vulns-by-target"
      // The host IS the identity here; the rollup has one row each.
      getRowId={(r) => (r as VulnsByTargetRow).host}
      initialSort={{ field: 'total', sort: 'desc' }}
      expanded={open}
      onExpand={setOpen}
      renderDetail={() => (
        <Detail rows={detail.data?.items ?? []} loading={detail.isLoading}
          onFinding={onFinding}
          // One host's findings, so two rows are the same thing when
          // the title, severity and port match.
          sameAs={(v) => `${v.title}\u0000${v.severity}\u0000${v.port ?? ''}`
                         + `\u0000${v.protocol ?? ''}`}
          show={(v) => (
            <>
              <Box sx={{ width: 62, flex: '0 0 auto' }}>
                <Severity value={v.severity} />
              </Box>
              <Box sx={{ flex: 1, minWidth: 0, color: neon.text,
                         overflow: 'hidden', textOverflow: 'ellipsis',
                         whiteSpace: 'nowrap' }}>{v.title}</Box>
            </>
          )} />
      )}
      note={'One row per host, worst first. Expand a host to see what '
            + 'was found on it; the findings are fetched only when you do.'
            + (q.data?.truncated
               ? ' THIS LIST IS CUT SHORT — there are more hosts than the '
                 + 'rollup returns, so the totals below are not the whole '
                 + 'project.' : '')}
    />
  )
}

// ------------------------------------------------------------ by vuln
export function VulnsByTitle({ project, onFinding }: {
  project: string | null
  onFinding: (id: number) => void
}) {
  const [open, setOpen] = useState<string | null>(null)
  const q = useQuery({
    queryKey: ['vulns-by-title', project],
    queryFn: () => api.vulnsByTitle(project as string),
    enabled: !!project,
  })
  // The row id carries BOTH halves of the key, because the rollup is
  // unique on (title, severity) and the same title at two severities
  // is two rows with two different host lists.
  const [title, severity] = (open ?? '\u0000').split('\u0000')
  const detail = useQuery({
    queryKey: ['vulns-of-title', project, title, severity],
    queryFn: () => api.vulnsForTitle(project as string, title, severity),
    enabled: !!open && !!project,
  })

  const columns: ColumnDef<VulnsByTitleRow>[] = [
    { field: 'severity', headerName: 'Severity', width: 104,
      renderCell: (p) => <Severity value={String(p.value)} /> },
    { field: 'title', headerName: 'Finding', flex: 3, minWidth: 260 },
    { field: 'hosts', headerName: 'Hosts', width: 96, type: 'number',
      renderCell: (p) => (
        <Tooltip title="Distinct hosts carrying this finding at this severity">
          <Box sx={{ color: neon.cyan, fontWeight: 700, cursor: 'help' }}>
            {(p.value as number).toLocaleString()}
          </Box>
        </Tooltip>
      ) },
    { field: 'total', headerName: 'Findings', width: 100, type: 'number',
      renderCell: (p) => <Count n={p.value as number} /> },
  ]

  return (
    <DataTable
      rows={q.data?.items ?? []}
      columns={columns as ColumnDef[]}
      loading={q.isLoading}
      error={q.error as Error | null}
      tableId="vulns-by-title"
      getRowId={(r) => {
        const v = r as VulnsByTitleRow
        // NUL as the separator: a finding title can contain anything
        // a scanner put in it, including the punctuation an obvious
        // separator would use.
        return `${v.title}\u0000${v.severity}`
      }}
      initialSort={{ field: 'hosts', sort: 'desc' }}
      expanded={open}
      onExpand={setOpen}
      renderDetail={() => (
        <Detail rows={detail.data?.items ?? []} loading={detail.isLoading}
          onFinding={onFinding}
          // Already filtered to one title and severity, so the HOST
          // is the identity — which is also what the `hosts` column
          // counts, and the two must agree.
          sameAs={(v) => `${v.host}\u0000${v.port ?? ''}\u0000${v.protocol ?? ''}`}
          show={(v) => (
            <Box sx={{ flex: 1, minWidth: 0,
                       fontFamily: `'Share Tech Mono', monospace`,
                       color: neon.cyan, overflow: 'hidden',
                       textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {v.host}
            </Box>
          )} />
      )}
      note={'One row per finding AT a severity — two scanners that '
            + 'disagree about the same thing are two rows, each with its '
            + 'own host count. Expand one to see which hosts carry it.'
            + (q.data?.truncated
               ? ' THIS LIST IS CUT SHORT — there are more findings than '
                 + 'the rollup returns.' : '')}
    />
  )
}
