import { useState } from 'react'
import {
  Box, Button, Chip, CircularProgress, Collapse, MenuItem, Stack, TextField,
  Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type TimelineEvent } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * Everything found and done to one target, newest first.
 *
 * The entries are written by whatever made the change — the scan importer,
 * a field edit, a note — rather than reconstructed here, so a gap in this
 * list means a code path that mutates a target without recording it, not a
 * rendering problem.
 */

const KIND_COLOUR: Record<string, string> = {
  discovered: neon.cyan,
  note: neon.purple,
  scan: neon.green,
  service: neon.cyan,
  vuln: neon.orange,
  poc: neon.green,
  credential: neon.yellow,
  change: neon.muted,
  status: neon.red,
}

const FILTERS = [
  { value: '', label: 'Everything' },
  { value: 'note', label: 'Notes' },
  { value: 'scan', label: 'Scans' },
  { value: 'service', label: 'Services' },
  { value: 'change', label: 'Changes' },
  { value: 'vuln', label: 'Findings' },
]

function when(iso: string): string {
  const d = new Date(iso)
  const diff = (Date.now() - d.getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function Entry({ e }: { e: TimelineEvent }) {
  const [open, setOpen] = useState(false)
  const colour = KIND_COLOUR[e.kind] ?? neon.muted
  const hasDetail = !!e.detail?.trim()

  return (
    <Box sx={{ position: 'relative', pl: 3, pb: 2 }}>
      {/* the rail and its node */}
      <Box sx={{
        position: 'absolute', left: 5, top: 14, bottom: 0, width: '1px',
        background: alpha(neon.purple, 0.28),
      }} />
      <Box sx={{
        position: 'absolute', left: 0, top: 6, width: 11, height: 11, borderRadius: '50%',
        background: alpha(colour, 0.22), border: `1px solid ${colour}`,
        boxShadow: `0 0 8px ${alpha(colour, 0.6)}`,
      }} />

      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Chip size="small" label={e.kind} sx={{
          height: 17, fontSize: 9.5, letterSpacing: '0.08em', textTransform: 'uppercase',
          bgcolor: alpha(colour, 0.14), color: colour,
          border: `1px solid ${alpha(colour, 0.5)}`,
        }} />
        <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.9) }}
                    title={new Date(e.at).toLocaleString()}>
          {when(e.at)}
        </Typography>
        {e.actor && (
          <Typography sx={{ fontSize: 10.5, color: alpha(neon.cyan, 0.8) }}>
            {e.actor}
          </Typography>
        )}
        {e.source && (
          <Typography sx={{ fontSize: 10, color: alpha(neon.muted, 0.55) }}>
            {e.source}
          </Typography>
        )}
      </Stack>

      <Typography sx={{
        mt: 0.4, fontSize: 12.5, color: neon.text, lineHeight: 1.55,
        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      }}>{e.summary}</Typography>

      {hasDetail && (
        <>
          <Button size="small" onClick={() => setOpen(!open)}
            endIcon={<ExpandMoreIcon sx={{
              fontSize: 14, transition: 'transform .15s',
              transform: open ? 'rotate(180deg)' : 'none' }} />}
            sx={{ mt: 0.2, px: 0.5, minWidth: 0, fontSize: 10.5, color: alpha(neon.cyan, 0.9) }}>
            {open ? 'less' : 'detail'}
          </Button>
          <Collapse in={open} unmountOnExit>
            <Box sx={{
              mt: 0.5, p: 1.25, borderRadius: 1, maxHeight: 360, overflow: 'auto',
              background: alpha(neon.bgDeep, 0.6),
              border: `1px solid ${alpha(neon.purple, 0.22)}`,
              fontFamily: `'Share Tech Mono', monospace`, fontSize: 11.5,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: alpha(neon.text, 0.92),
            }}>{e.detail}</Box>
          </Collapse>
        </>
      )}
    </Box>
  )
}

export function Timeline({ project, host, canWrite }: {
  project: string; host: string; canWrite: boolean
}) {
  const qc = useQueryClient()
  const [kind, setKind] = useState('')
  const [adding, setAdding] = useState(false)
  const [text, setText] = useState('')

  const { data, isLoading, error } = useQuery({
    queryKey: ['timeline', project, host, kind],
    queryFn: () => api.timeline(project, host, kind || undefined),
  })

  const add = useMutation({
    mutationFn: () => {
      const lines = text.trim().split('\n')
      return api.addTimelineNote(project, host, {
        kind: 'note',
        summary: lines[0].slice(0, 2000),
        // Only send a body when there is more than the one line already in
        // the summary, so a short note does not render twice.
        detail: lines.length > 1 ? text.trim() : null,
      })
    },
    onSuccess: async () => {
      setText(''); setAdding(false)
      await qc.invalidateQueries({ queryKey: ['timeline', project, host] })
    },
  })

  return (
    <Box sx={{ mt: 3 }}>
      <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }} flexWrap="wrap" useFlexGap>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.16em',
          textTransform: 'uppercase', color: neon.pink, textShadow: glow(neon.pink, 0.5),
        }}>Timeline</Typography>
        <Typography sx={{ color: neon.muted, fontSize: 11 }}>{data?.total ?? 0}</Typography>
        <Box sx={{ flex: 1 }} />
        <TextField select size="small" value={kind} onChange={(e) => setKind(e.target.value)}
          sx={{ minWidth: 140 }}
          slotProps={{ htmlInput: { style: { fontSize: 12 } } }}>
          {FILTERS.map((f) => (
            <MenuItem key={f.value} value={f.value} sx={{ fontSize: 12.5 }}>{f.label}</MenuItem>
          ))}
        </TextField>
        {canWrite && (
          <Button size="small" startIcon={<AddIcon sx={{ fontSize: 15 }} />}
            onClick={() => setAdding(!adding)}
            sx={{ color: neon.green, fontSize: 11 }}>Note</Button>
        )}
      </Stack>

      <Collapse in={adding} unmountOnExit>
        <Box sx={{ mb: 2 }}>
          <TextField fullWidth multiline minRows={3} size="small" value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="What did you find or do? First line becomes the summary." />
          <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
            <Button size="small" variant="outlined" disabled={!text.trim() || add.isPending}
              onClick={() => add.mutate()}
              sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5) }}>
              {add.isPending ? '…' : 'Add to timeline'}
            </Button>
            <Button size="small" onClick={() => { setAdding(false); setText('') }}
              sx={{ color: neon.muted }}>Cancel</Button>
          </Stack>
          {add.isError && (
            <Typography sx={{ mt: 1, fontSize: 11.5, color: neon.red }}>
              {(add.error as Error).message}
            </Typography>
          )}
        </Box>
      </Collapse>

      {isLoading && <CircularProgress size={18} sx={{ color: neon.cyan }} />}
      {error && <Typography sx={{ color: neon.red, fontSize: 12.5 }}>
        {(error as Error).message}
      </Typography>}
      {data && data.items.length === 0 && (
        <Typography sx={{ color: alpha(neon.muted, 0.6), fontSize: 12.5 }}>
          Nothing recorded{kind ? ` under “${kind}”` : ''} yet.
        </Typography>
      )}
      {data?.items.map((e) => <Entry key={e.id} e={e} />)}
      {data && data.total > data.items.length && (
        <Typography sx={{ fontSize: 11, color: neon.muted, pl: 3 }}>
          Showing the {data.items.length} most recent of {data.total}.
        </Typography>
      )}
    </Box>
  )
}
