import { useEffect, useMemo, useState } from 'react'
import { Box, Button, Chip, Dialog, DialogContent, DialogTitle, IconButton, Menu, MenuItem, Tooltip, alpha } from '@mui/material'
import ReplayIcon from '@mui/icons-material/ReplayOutlined'
import MoreVertIcon from '@mui/icons-material/MoreVertOutlined'
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpwardOutlined'
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownwardOutlined'
import VerticalAlignTopIcon from '@mui/icons-material/VerticalAlignTopOutlined'
import VerticalAlignBottomIcon from '@mui/icons-material/VerticalAlignBottomOutlined'
import PlayArrowIcon from '@mui/icons-material/PlayArrowOutlined'
import type { ColumnDef } from '../lib/columns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type GhostTaskRow, type GhostTaskDetail } from '../lib/api'
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

/** Per-row queue actions: reorder within the queue, or launch now. */
function TaskActions({ id, failed, queued, project }: {
  id: number; failed: boolean; queued: boolean; project: string
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const qc = useQueryClient()

  const invalidate = () => qc.invalidateQueries({ queryKey: ['ghost-tasks', project] })

  const reorder = useMutation({
    mutationFn: (dir: string) => api.reorderGhostTask(project, id, dir),
    onSuccess: invalidate,
  })
  const launch = useMutation({
    mutationFn: () => api.launchGhostTask(project, id),
    onSuccess: invalidate,
  })
  const retry = useMutation({
    mutationFn: () => api.retryGhostTask(project, id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['ghost-tasks', project] })
      await qc.invalidateQueries({ queryKey: ['ghost-routing', project] })
      await qc.invalidateQueries({ queryKey: ['ghost-agents', project] })
      await qc.invalidateQueries({ queryKey: ['agents', project] })
    },
  })

  const busy = reorder.isPending || launch.isPending || retry.isPending
  const close = () => setAnchor(null)
  const act = (fn: () => void) => { fn(); close() }

  return (
    <>
      <Tooltip title={queued ? 'Queue actions' : 'Retry'}>
        <span>
          <IconButton size="small" disabled={busy} onClick={(e) => setAnchor(e.currentTarget)}
            sx={{ color: neon.muted, '&:hover': { color: neon.green } }}>
            <MoreVertIcon fontSize="small" />
          </IconButton>
        </span>
      </Tooltip>
      <Menu anchorEl={anchor} open={!!anchor} onClose={close}>
        {queued && (
          <>
            <MenuItem onClick={() => act(() => reorder.mutate('top'))}>
              <VerticalAlignTopIcon fontSize="small" sx={{ mr: 1 }} />Send to top
            </MenuItem>
            <MenuItem onClick={() => act(() => reorder.mutate('bottom'))}>
              <VerticalAlignBottomIcon fontSize="small" sx={{ mr: 1 }} />Send to bottom
            </MenuItem>
            <MenuItem onClick={() => act(() => reorder.mutate('up'))}>
              <ArrowUpwardIcon fontSize="small" sx={{ mr: 1 }} />Move up one
            </MenuItem>
            <MenuItem onClick={() => act(() => reorder.mutate('down'))}>
              <ArrowDownwardIcon fontSize="small" sx={{ mr: 1 }} />Move down one
            </MenuItem>
            <MenuItem onClick={() => act(() => launch.mutate())}>
              <PlayArrowIcon fontSize="small" sx={{ mr: 1 }} />Launch now
            </MenuItem>
          </>
        )}
        {failed && (
          <MenuItem onClick={() => act(() => retry.mutate())}>
            <ReplayIcon fontSize="small" sx={{ mr: 1 }} />Retry
          </MenuItem>
        )}
      </Menu>
    </>
  )
}

/** The modal that opens when a completed task row is clicked. Shows the
 *  tool's raw output and offers to re-run the importer over it. */
function TaskDetailModal({ project, taskId, onClose }: {
  project: string; taskId: number | null; onClose: () => void
}) {
  const qc = useQueryClient()
  const { canWrite } = useAuth()

  const detail = useQuery({
    queryKey: ['ghost-task-detail', project, taskId],
    queryFn: () => api.ghostTaskDetail(project, taskId!),
    enabled: taskId !== null,
  })

  const reimport = useMutation({
    mutationFn: () => {
      // The agent id is needed for the route; the detail has it.
      const d = detail.data
      if (!d) throw new Error('no detail')
      return api.reimportGhostTask(project, d.agent_id!, d.id)
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['ghost-task-detail', project, taskId] })
      await qc.invalidateQueries({ queryKey: ['ghost-tasks', project] })
      await qc.invalidateQueries({ queryKey: ['targets', project] })
      await qc.invalidateQueries({ queryKey: ['services', project] })
    },
  })

  const d = detail.data as GhostTaskDetail | undefined
  const output = d?.output ?? ''
  const imp = d?.import_result ?? null

  return (
    <Dialog open={taskId !== null} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle sx={{ color: neon.text, fontSize: 15 }}>
        Task #{taskId} — {d?.kind ?? ''} on {d?.subject ?? ''}
      </DialogTitle>
      <DialogContent dividers>
        {/* The tool's actual output. Monospace, scrollable, because a
            masscan over a /16 is several megabytes of JSON. */}
        <Box sx={{ mb: 2 }}>
          <Box component="div" sx={{ color: neon.muted, fontSize: 11, mb: 0.5, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Output
          </Box>
          {detail.isLoading && <Box sx={{ color: alpha(neon.muted, 0.5), fontSize: 12 }}>Loading…</Box>}
          {!detail.isLoading && !output && (
            <Box sx={{ color: alpha(neon.muted, 0.4), fontSize: 12, fontStyle: 'italic' }}>
              No output stored on this task.
            </Box>
          )}
          {output && (
            <Box component="pre" sx={{
              m: 0, p: 1.5, bgcolor: '#0a0e14', border: `1px solid ${alpha(neon.muted, 0.2)}`,
              borderRadius: 1, fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
              color: neon.text, maxHeight: 380, overflow: 'auto', whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}>
              {output}
            </Box>
          )}
        </Box>

        {/* What the importer made of it. */}
        <Box sx={{ mb: 2 }}>
          <Box component="div" sx={{ color: neon.muted, fontSize: 11, mb: 0.5, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Import result
          </Box>
          {!imp && (
            <Box sx={{ color: alpha(neon.muted, 0.4), fontSize: 12, fontStyle: 'italic' }}>
              Not imported yet.
            </Box>
          )}
          {imp && 'error' in imp && (
            <Box sx={{ color: neon.red, fontSize: 12 }}>{(imp as { error: string }).error}</Box>
          )}
          {imp && !('error' in imp) && (
            <Box component="div" sx={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11.5, color: neon.text }}>
              <Box>hosts seen: {(imp as any).hosts_seen}</Box>
              <Box>targets: +{(imp as any).targets_created} created, {(imp as any).targets_updated} updated</Box>
              <Box>services: +{(imp as any).services_created} created, {(imp as any).services_updated} updated</Box>
              {(imp as any).needs_decision && (
                <Box sx={{ color: neon.yellow }}>needs decision — {(imp as any).unknown_hosts?.length ?? 0} unknown host(s)</Box>
              )}
            </Box>
          )}
        </Box>

        {/* Reimport button. Only when the task has importable output and
            the operator can write to the project. */}
        {canWrite(project) && d?.import_as && (
          <Button
            variant="outlined"
            size="small"
            startIcon={<ReplayIcon />}
            onClick={() => reimport.mutate()}
            disabled={reimport.isPending || !d?.has_output}
            sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.4), '&:hover': { borderColor: neon.cyan } }}
          >
            {reimport.isPending ? 'Re-importing…' : 'Re-import'}
          </Button>
        )}
        {reimport.isError && (
          <Box sx={{ color: neon.red, fontSize: 12, mt: 1 }}>
            {(reimport.error as Error).message}
          </Box>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function GhostTasksTable({ project }: { project: string }) {
  const { canWrite } = useAuth()
  const [selectedTask, setSelectedTask] = useState<number | null>(null)

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

  // Memoised: a fresh array every render makes every memo in
  // TableGrid keyed on `columns` recompute, and TanStack rebuild
  // its column model from them.
  const columns: ColumnDef<GhostTaskRow>[] = useMemo(() => [
    {
      field: 'id', headerName: 'Task', width: 86, type: 'number',
      renderCell: (p) => (
        <Box sx={{ color: neon.pink, fontWeight: 700 }}>#{p.value}</Box>
      ),
    },
    {
      field: 'kind', headerName: 'Kind', width: 110,
      type: 'singleSelect', valueOptions: ['nmap', 'masscan', 'portscan', 'amass', 'gobuster', 'vhost', 'katana', 'screenshot', 'nuclei', 'nuclei_tech', 'nuclei_confirm', 'httpx', 'replay', 'nslookup', 'reverse_ip', 'semgrep', 'trufflehog', 'osv', 'install'],
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
      type: 'singleSelect', valueOptions: ['queued', 'claimed', 'running', 'done', 'failed', 'cancelled'],
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
        if (!canWrite(project)) return null
        const isFailed = p.row.state === 'failed'
        const isQueued = p.row.state === 'awaiting'
        // A running or complete task has nothing to act on.
        if (!isFailed && !isQueued) return null
        return (
          <TaskActions id={p.row.id} failed={isFailed} queued={isQueued} project={project} />
        )
      },
    },
  ], [canWrite, now, project])

  return (
    <>
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
        onRowClick={(row) => {
          // Completed tasks with output open the detail modal. A task
          // that has not finished has nothing to show yet, and one with
          // no importable output (a lookup, a poc) has nothing to
          // re-import.
          if (row.state === 'complete' && row.has_output) {
            setSelectedTask(row.id)
          }
        }}
      />
      <TaskDetailModal
        project={project}
        taskId={selectedTask}
        onClose={() => setSelectedTask(null)}
      />
    </>
  )
}
