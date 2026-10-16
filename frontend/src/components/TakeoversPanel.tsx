import { Box, Button, MenuItem, Select, Stack, Tooltip, alpha } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '../lib/columns'
import { api, type Takeover } from '../lib/api'
import { DataTable } from './DataTable'
import { TRIAGE, TRIAGE_COLOUR } from '../lib/triage'
import { neon, glow } from '../theme'

/** How sure we are, and what each word actually claims.
 *
 *  Deliberately not a severity scale. `dangling` and `fingerprint`
 *  are two different kinds of evidence, and `candidate` is the
 *  absence of either — it is the "could not determine" of the three,
 *  and colouring it like a finding is exactly how a tester spends a
 *  morning proving a live Shopify store belongs to the client. */
const VERDICT: Record<string, { label: string; colour: string; why: string }> = {
  dangling: {
    label: 'Dangling', colour: neon.pink,
    why: 'The chain reached a name that does not resolve. The record points at nothing.',
  },
  fingerprint: {
    label: 'Fingerprint', colour: '#ff9f43',
    why: "The provider served its own “nothing is here” page.",
  },
  candidate: {
    label: 'Candidate', colour: neon.muted,
    why: 'Points at a provider that hands out subdomains, and neither check could '
       + 'be run. This is not a finding yet — it is a thing to go and look at.',
  },
}

/** Names in this engagement pointing at a service that hands out
 *  subdomains to whoever asks first.
 *
 *  Read-only with respect to the network: every row here was decided
 *  from CNAMEs the agent already collected and responses already
 *  captured. Refresh re-derives from what is on record and resolves
 *  nothing itself, which is why it is safe to press during an
 *  engagement without putting traffic anywhere.
 */
export function TakeoversPanel({ project }: { project: string | null }) {
  const qc = useQueryClient()

  const { data, isLoading, error } = useQuery({
    queryKey: ['takeovers', project],
    queryFn: () => api.takeovers({ project: project ?? undefined }),
    enabled: true,
  })

  const refresh = useMutation({
    mutationFn: () => api.refreshTakeovers(project ?? ''),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['takeovers', project] }) },
  })

  const triage = useMutation({
    mutationFn: ({ id, state }: { id: number; state: string }) =>
      api.updateTakeover(id, project ?? '', { state }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['takeovers', project] }) },
  })

  const rows = data?.items ?? []
  const counts = rows.reduce<Record<string, number>>((a, r) => {
    a[r.verdict] = (a[r.verdict] ?? 0) + 1
    return a
  }, {})

  const columns: ColumnDef<Takeover>[] = [
    {
      field: 'hostname', headerName: 'Hostname', flex: 2, minWidth: 220,
      renderCell: (p) => (
        <Box sx={{ color: neon.pink, fontWeight: 600, fontSize: 11.5,
                   overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {String(p.value ?? '')}
        </Box>
      ),
    },
    {
      field: 'cname', headerName: 'Points at', flex: 2, minWidth: 240,
      renderCell: (p) => {
        const row = p.row as Takeover
        // The hop that matched on top, the rest of the chain under
        // it. An intermediate hop is frequently the interesting one
        // and showing only the last would hide it.
        const rest = row.cname_chain.filter((c) => c !== row.cname)
        return (
          <Stack spacing={0} sx={{ py: 0.5, minWidth: 0 }}>
            <Box sx={{ fontFamily: 'ui-monospace, Menlo, monospace',
                       fontSize: 11.5, color: neon.cyan,
                       overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {row.cname}
            </Box>
            {rest.length > 0 && (
              <Box sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.8),
                         overflow: 'hidden', textOverflow: 'ellipsis' }}>
                via {rest.join(' → ')}
              </Box>
            )}
          </Stack>
        )
      },
    },
    {
      field: 'provider', headerName: 'Provider', width: 170,
      renderCell: (p) => {
        const row = p.row as Takeover
        return (
          <Stack spacing={0} sx={{ py: 0.5, minWidth: 0 }}>
            <Box sx={{ fontSize: 11.5, color: neon.text }}>{String(p.value ?? '')}</Box>
            {/* The distinction that stops a report overstating itself:
                a beanstalk or CloudFront record dangles but is not
                freely re-registerable. */}
            {!row.claimable && (
              <Tooltip title="This record dangles, but the name is not freely
                              re-registerable — treat it as hygiene, not an
                              exploitable takeover.">
                <Box sx={{ fontSize: 10, color: alpha(neon.muted, 0.9),
                           letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                  not claimable
                </Box>
              </Tooltip>
            )}
          </Stack>
        )
      },
    },
    {
      field: 'verdict', headerName: 'Verdict', width: 130,
      renderCell: (p) => {
        const v = VERDICT[String(p.value)] ?? VERDICT.candidate
        return (
          <Tooltip title={v.why} enterDelay={300}>
            <Box sx={{ color: v.colour, fontSize: 10.5, letterSpacing: '0.08em',
                       textTransform: 'uppercase', cursor: 'help' }}>
              {v.label}
            </Box>
          </Tooltip>
        )
      },
    },
    {
      field: 'evidence', headerName: 'Evidence', flex: 2, minWidth: 220,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => {
        const row = p.row as Takeover
        if (!row.evidence) {
          // Saying "nothing was found" and "nothing was checked" the
          // same way is how the third answer gets lost.
          return (
            <Tooltip title="Neither check could be run against this host. Not a
                            statement that it is safe.">
              <Box sx={{ fontSize: 11, color: alpha(neon.muted, 0.6),
                         fontStyle: 'italic', cursor: 'help' }}>
                not determined
              </Box>
            </Tooltip>
          )
        }
        return (
          <Box sx={{ fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 11,
                     color: alpha(neon.text, 0.85), overflow: 'hidden',
                     textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {row.evidence}
          </Box>
        )
      },
    },
    {
      field: 'state', headerName: 'Triage', width: 190,
      renderCell: (p) => {
        const row = p.row as Takeover
        return (
          <Select
            size="small" variant="standard" disableUnderline
            value={row.state}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => triage.mutate({ id: row.id, state: e.target.value })}
            sx={{
              fontSize: 11, color: TRIAGE_COLOUR[row.state] ?? neon.muted,
              '& .MuiSelect-select': { py: 0.25 },
            }}>
            {TRIAGE.map((t) => (
              <MenuItem key={t.value} value={t.value}
                sx={{ fontSize: 11.5, color: t.colour }}>
                {t.label}
              </MenuItem>
            ))}
          </Select>
        )
      },
    },
  ]

  return (
    <Stack sx={{ height: '100%', minHeight: 0 }}>
      <Stack direction="row" spacing={1.5}
        sx={{ alignItems: 'center', px: 2, py: 1 }}>
        {/* The counts, strongest first, so the shape of the list is
            readable before anything is clicked. */}
        {(['dangling', 'fingerprint', 'candidate'] as const).map((v) => (
          <Tooltip key={v} title={VERDICT[v].why} enterDelay={300}>
            <Box sx={{ fontSize: 11, letterSpacing: '0.07em',
                       textTransform: 'uppercase', cursor: 'help',
                       color: counts[v] ? VERDICT[v].colour : alpha(neon.muted, 0.5) }}>
              {counts[v] ?? 0} {VERDICT[v].label}
            </Box>
          </Tooltip>
        ))}
        <Box sx={{ flex: 1 }} />
        <Tooltip title="Re-derive from the CNAMEs already on record. Sends no
                        traffic to the client — nothing is resolved or fetched.">
          <span>
            <Button
              size="small" variant="outlined"
              disabled={!project || refresh.isPending}
              onClick={() => refresh.mutate()}
              sx={{ fontSize: 10.5, letterSpacing: '0.1em',
                    color: neon.cyan, borderColor: alpha(neon.cyan, 0.4),
                    '&:hover': { borderColor: neon.cyan,
                                 textShadow: glow(neon.cyan, 0.5) } }}>
              {refresh.isPending ? 'Re-deriving…' : 'Refresh'}
            </Button>
          </span>
        </Tooltip>
      </Stack>
      <Box sx={{ flex: 1, minHeight: 0 }}>
        <DataTable
          rows={rows}
          columns={columns as ColumnDef[]}
          loading={isLoading}
          error={(error ?? refresh.error ?? triage.error) as Error | null}
          getRowId={(r) => (r as Takeover).id}
          // No `kind`: these rows are re-derived from DNS on every
          // refresh, so adding or deleting one here would be undone
          // by the next pass. Triage is the only thing that persists,
          // and it has its own column.
          tableId="takeovers"
          project={project}
          canWrite={false}
          note={!project
            ? 'Pick an engagement to see its takeover candidates'
            : `${rows.length} name(s) pointing at a provider that hands out subdomains`}
        />
      </Box>
    </Stack>
  )
}
