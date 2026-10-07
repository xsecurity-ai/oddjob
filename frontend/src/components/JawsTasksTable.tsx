import { Box, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import ReplayIcon from '@mui/icons-material/ReplayOutlined'
import type { GridColDef } from '@mui/x-data-grid'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type JawsTaskRow } from '../lib/api'
import { useAuth } from '../lib/auth'
import { DataTable } from './DataTable'
import { neon } from '../theme'

/**
 * Every task on the engagement, under the fleet it runs on.
 *
 * The agents table answers "what have I got"; this answers "what is
 * happening", which is the question with a queue in it. It shows
 * pooled work too — tasks no agent owns yet — which the per-agent
 * view by definition cannot.
 *
 * Sorted by task id descending, which is both "newest first" and the
 * reverse of the order they run in: ids are assigned on receipt and
 * that is the dispatch order, so the bottom of a run of queued rows
 * is the next thing to go out.
 */

const STATE_COLOUR: Record<string, string> = {
  'complete': neon.green,
  'in progress': neon.cyan,
  'awaiting': neon.yellow,
  'failed': neon.red,
}

function when(v: unknown): string {
  if (!v) return ''
  const d = new Date(String(v))
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString()
}

/** Just the clock part, since every row is from the same engagement
 *  and the date is the same noise on all of them. The full stamp is
 *  in the tooltip. */
function clock(v: unknown): string {
  if (!v) return ''
  const d = new Date(String(v))
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleTimeString()
}

function Stamp({ value }: { value: unknown }) {
  if (!value) return <Box component="span" sx={{ color: alpha(neon.muted, 0.35) }}>—</Box>
  return (
    <Tooltip title={when(value)}>
      <Box component="span" sx={{ color: neon.muted, fontSize: 11.5 }}>
        {clock(value)}
      </Box>
    </Tooltip>
  )
}

export function JawsTasksTable({ project }: { project: string }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()

  const q = useQuery({
    queryKey: ['jaws-tasks', project],
    queryFn: () => api.jawsTasks(project),
    // Tasks move between states on their own as agents pick them up
    // and report back, so a table that only refreshed on navigation
    // would be describing a fleet that had moved on.
    refetchInterval: 5000,
  })

  const retry = useMutation({
    mutationFn: (id: number) => api.retryJawsTask(project, id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['jaws-tasks', project] })
      await qc.invalidateQueries({ queryKey: ['jaws-routing', project] })
      await qc.invalidateQueries({ queryKey: ['agents', project] })
    },
  })

  const columns: GridColDef<JawsTaskRow>[] = [
    {
      field: 'id', headerName: 'Task', width: 86, type: 'number',
      renderCell: (p) => (
        <Box sx={{ color: neon.pink, fontWeight: 700 }}>#{p.value}</Box>
      ),
    },
    {
      field: 'kind', headerName: 'Kind', width: 110,
      renderCell: (p) => (
        <Chip size="small" label={p.value} sx={{
          height: 19, fontSize: 10.5, color: neon.cyan,
          bgcolor: alpha(neon.cyan, 0.13) }} />
      ),
    },
    {
      field: 'subject', headerName: 'On', flex: 1, minWidth: 180,
      renderCell: (p) => (
        <Tooltip title={String(p.value ?? '')}>
          <Box sx={{ fontFamily: `'Share Tech Mono', monospace`, fontSize: 12,
                     overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {p.value}
          </Box>
        </Tooltip>
      ),
    },
    {
      field: 'state', headerName: 'Status', width: 124,
      renderCell: (p) => {
        const c = STATE_COLOUR[String(p.value)] ?? neon.muted
        return (
          <Box sx={{ color: c, fontWeight: 600, fontSize: 12 }}>
            {p.value}
            {p.row.attempts > 0 && p.row.state !== 'complete' && (
              <Tooltip title={`${p.row.attempts} failed attempt(s). Two are retried automatically; after that it waits for someone to restart it.`}>
                <Box component="span" sx={{ color: neon.muted, fontWeight: 400 }}>
                  {' '}×{p.row.attempts}
                </Box>
              </Tooltip>
            )}
          </Box>
        )
      },
    },
    {
      // "Which Jaws" — empty while pooled, which is a real state and
      // not missing data, so it says so rather than showing a blank.
      field: 'agent_name', headerName: 'Jaws', width: 170,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (p.value
        ? <Box sx={{ color: neon.text, fontSize: 12 }}>{p.value}</Box>
        : <Tooltip title="Queued for the project, so no agent owns it yet. The routing mode decides who takes it.">
            <Box sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic',
                       fontSize: 11.5 }}>pool</Box>
          </Tooltip>),
    },
    { field: 'created_at', headerName: 'Created', width: 108,
      renderCell: (p) => <Stamp value={p.value} /> },
    { field: 'started_at', headerName: 'Started', width: 108,
      renderCell: (p) => <Stamp value={p.value} /> },
    { field: 'finished_at', headerName: 'Finished', width: 108,
      renderCell: (p) => <Stamp value={p.value} /> },
    {
      field: 'notes', headerName: 'Notes', flex: 1.4, minWidth: 200,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (p.value
        ? <Tooltip title={String(p.value)}>
            <Box sx={{ color: p.row.state === 'failed' ? neon.red : neon.muted,
                       fontSize: 11.5, overflow: 'hidden',
                       textOverflow: 'ellipsis' }}>
              {p.value}
            </Box>
          </Tooltip>
        : <Box component="span" sx={{ color: alpha(neon.muted, 0.3) }}>—</Box>),
    },
    {
      field: 'actions', headerName: '', width: 52, sortable: false,
      filterable: false, align: 'center', headerAlign: 'center',
      renderCell: (p) => {
        // Only a failed one. A queued task is already going to run and
        // one in flight would then exist twice.
        if (p.row.state !== 'failed' || !canWrite(project)) return null
        return (
          <Tooltip title={`Put #${p.row.id} back in the queue. The attempt count resets.`}>
            <span>
              <IconButton size="small" disabled={retry.isPending}
                onClick={() => retry.mutate(p.row.id)}
                sx={{ color: neon.muted, '&:hover': { color: neon.green } }}>
                <ReplayIcon fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
        )
      },
    },
  ]

  return (
    <DataTable
      // Its own id, so sort, filters, column visibility and density are
      // remembered per browser and separately from the fleet table
      // above it.
      tableId="jaws-tasks"
      rows={q.data ?? []}
      columns={columns as GridColDef[]}
      loading={q.isLoading}
      error={q.error as Error | null}
      initialSort={{ field: 'id', sort: 'desc' }}
    />
  )
}
