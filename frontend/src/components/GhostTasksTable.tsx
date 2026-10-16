import { useEffect, useMemo, useState } from 'react'
import { Box, Chip, IconButton, Tooltip, alpha } from '@mui/material'
import ReplayIcon from '@mui/icons-material/ReplayOutlined'
import type { ColumnDef } from '../lib/columns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type GhostTaskRow } from '../lib/api'
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

/**
 * A ticking clock, but only while something is actually running.
 *
 * A table that re-renders every second forever is a laptop fan on a
 * page nobody is looking at. `live` is false when nothing is in
 * progress, and then this costs one render and no timer at all.
 */
function useNow(live: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!live) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [live])
  return now
}

/** "3m 07s", "1h 04m", "12s". */
export function elapsed(ms: number): string {
  if (ms < 0) ms = 0
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h) return `${h}h ${String(m).padStart(2, '0')}m`
  if (m) return `${m}m ${String(sec).padStart(2, '0')}s`
  return `${sec}s`
}

/** The long form, for the tooltip. Said in full words because the
 *  compact form is for scanning and this is for reading. */
export function elapsedLong(ms: number): string {
  if (ms < 0) ms = 0
  const s = Math.floor(ms / 1000)
  const parts: string[] = []
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h) parts.push(`${h} hr${h === 1 ? '' : 's'}`)
  if (m) parts.push(`${m} min${m === 1 ? '' : 's'}`)
  parts.push(`${sec} sec${sec === 1 ? '' : 's'}`)
  return parts.join(', ')
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

export function GhostTasksTable({ project }: { project: string }) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()

  const q = useQuery({
    queryKey: ['ghost-tasks', project],
    queryFn: () => api.ghostTasks(project),
    // Tasks move between states on their own as agents pick them up
    // and report back, so a table that only refreshed on navigation
    // would be describing a fleet that had moved on.
    refetchInterval: 5000,
  })

  // Only tick while something is actually in progress. Nothing
  // running means no timer, which matters because this table sits
  // on a page people leave open.
  const anyRunning = useMemo(
    () => (q.data ?? []).some((t) => t.state === 'in progress'),
    [q.data])
  const now = useNow(anyRunning)

  const retry = useMutation({
    mutationFn: (id: number) => api.retryGhostTask(project, id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['ghost-tasks', project] })
      await qc.invalidateQueries({ queryKey: ['ghost-routing', project] })
      // Both keys. The fleet table above this one is `ghost-agents` and
      // was missing from here, so the Ghost that picked a retry up went
      // on showing idle; `agents` is Targets' own list of who is live
      // and still needs the nudge.
      await qc.invalidateQueries({ queryKey: ['ghost-agents', project] })
      await qc.invalidateQueries({ queryKey: ['agents', project] })
    },
  })

  const columns: ColumnDef<GhostTaskRow>[] = [
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
            {/* How long it has been going. A task that has run for
                two minutes and one that has been wedged for three
                hours look identical otherwise, and the second is
                the one worth knowing about. Shown inline so it can
                be scanned down the column, with the full reading on
                hover. */}
            {p.row.state === 'in progress' && p.row.started_at && (
              <Tooltip title={`Running for ${elapsedLong(
                now - new Date(String(p.row.started_at)).getTime())}`}>
                <Box component="span" sx={{ color: neon.muted,
                                            fontWeight: 400, fontSize: 11 }}>
                  {' '}{elapsed(now - new Date(String(p.row.started_at)).getTime())}
                </Box>
              </Tooltip>
            )}
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
      // "Which Ghost" — empty while pooled, which is a real state and
      // not missing data, so it says so rather than showing a blank.
      field: 'agent_name', headerName: 'Ghost', width: 170,
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
      tableId="ghost-tasks"
      rows={q.data ?? []}
      columns={columns as ColumnDef[]}
      loading={q.isLoading}
      error={q.error as Error | null}
      initialSort={{ field: 'id', sort: 'desc' }}
    />
  )
}
