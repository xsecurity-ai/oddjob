import { useMemo, useState } from 'react'
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, LinearProgress, MenuItem, Stack, Table, TableBody,
  TableCell,
  TableHead, TableRow, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api, type HostDecision, type UnknownHost } from '../lib/api'
import { sortedStrings } from '../lib/sortOptions'
import { neon, glow } from '../theme'

/**
 * What to do about hosts an import names that the project does not have.
 *
 * All of them at once, in one table. The alternative — a prompt per host
 * — is unusable on a file that names fourteen, which is exactly the size
 * of the accident this exists to prevent.
 *
 * The default for every row is **Skip**. That is the whole safety
 * property: the failure that actually happens is importing into the wrong
 * project, and the cost of that is another client's data in your
 * engagement. The cost of over-caution is one more click.
 */

type Action = 'reject' | 'add' | 'map'

const ACTION_LABEL: Record<Action, string> = {
  reject: 'Skip — discard its data',
  add: 'Add as a new target',
  map: 'Attach to an existing target',
}

/** Bytes in units a person reads. */
function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024, i = 0
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`
}

export function UnknownHostsDialog({
  project, hosts, format, onCancel, onConfirm, busy, progress,
}: {
  project: string
  hosts: UnknownHost[]
  format: string
  busy?: boolean
  /** Upload progress for the re-send, when the file is streamed.
   *  Confirming here re-uploads the whole file and then imports it,
   *  which for a large proxy history is minutes of work -- the button
   *  going quiet was the only feedback there was. */
  progress?: { loaded: number; total: number; secs: number } | null
  onCancel: () => void
  onConfirm: (decisions: Record<string, HostDecision>) => void
}) {
  const [choice, setChoice] = useState<Record<string, Action>>({})
  const [mapTo, setMapTo] = useState<Record<string, string>>({})

  const targets = useQuery({
    queryKey: ['targets-for-mapping', project],
    queryFn: () => api.targets(project),
  })
  const names = useMemo(
    () => sortedStrings((targets.data?.items ?? []).map((t) => t.host)),
    [targets.data])

  const act = (h: string): Action => choice[h] ?? 'reject'
  const setAll = (a: Action) =>
    setChoice(Object.fromEntries(hosts.map((h) => [h.host, a])))

  const counts = hosts.reduce((acc, h) => {
    const a = act(h.host)
    acc[a] = (acc[a] ?? 0) + 1
    return acc
  }, {} as Record<string, number>)

  // A row set to "attach" with nothing chosen cannot be submitted — it
  // would be silently rejected by the server, which is worse than saying
  // so here.
  const incomplete = hosts.filter(
    (h) => act(h.host) === 'map' && !(mapTo[h.host] ?? '').trim())

  const submit = () => {
    const out: Record<string, HostDecision> = {}
    for (const h of hosts) {
      const a = act(h.host)
      out[h.host] = a === 'map'
        ? { action: 'map', target: mapTo[h.host] }
        : { action: a }
    }
    onConfirm(out)
  }

  const dropped = hosts
    .filter((h) => act(h.host) === 'reject')
    .reduce((n, h) => n + h.total, 0)

  return (
    <Dialog open onClose={onCancel} maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.yellow, 0.5)}`,
        boxShadow: `0 0 44px ${alpha(neon.yellow, 0.2)}`,
        width: '94vw', maxWidth: 1140,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.yellow,
                         textShadow: glow(neon.yellow, 0.5),
                         borderBottom: `1px solid ${alpha(neon.yellow, 0.3)}` }}>
        {hosts.length} HOST{hosts.length === 1 ? '' : 'S'} NOT IN {project}
      </DialogTitle>

      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
            This {format} file names {hosts.length} host
            {hosts.length === 1 ? '' : 's'} that <b>{project}</b> does not have.
            Nothing has been imported yet. Anything left on <b>Skip</b> is
            discarded — if this file belongs to a different engagement, close
            this and import it there.
          </Alert>

          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography sx={{ fontSize: 11, color: neon.muted }}>Set all:</Typography>
            {(['reject', 'add'] as Action[]).map((a) => (
              <Button key={a} size="small" onClick={() => setAll(a)}
                sx={{ fontSize: 10.5, color: a === 'add' ? neon.green : neon.muted }}>
                {a === 'add' ? 'Add all' : 'Skip all'}
              </Button>
            ))}
            <Box sx={{ flex: 1 }} />
            {counts.add > 0 && (
              <Chip size="small" label={`${counts.add} to add`} sx={tag(neon.green)} />
            )}
            {counts.map > 0 && (
              <Chip size="small" label={`${counts.map} to attach`} sx={tag(neon.cyan)} />
            )}
            {counts.reject > 0 && (
              <Chip size="small"
                label={`${counts.reject} skipped · ${dropped} rows dropped`}
                sx={tag(neon.muted)} />
            )}
          </Stack>

          <Box sx={{ maxHeight: '52vh', overflow: 'auto',
                     border: `1px solid ${alpha(neon.purple, 0.25)}`, borderRadius: 1 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  {['Host', 'Brings', 'What to do', 'Attach to'].map((h) => (
                    <TableCell key={h} sx={headSx}>{h}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {hosts.map((h) => {
                  const a = act(h.host)
                  return (
                    <TableRow key={h.host} hover sx={{
                      opacity: a === 'reject' ? 0.55 : 1,
                    }}>
                      <TableCell sx={{ ...cellSx, color: neon.cyan }}>
                        {h.host}
                        {h.ip && (
                          <Typography sx={{ fontSize: 10, color: neon.muted }}>
                            {h.ip}
                          </Typography>
                        )}
                      </TableCell>

                      <TableCell sx={{ ...cellSx, width: 280 }}>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {([['web', 'URLs', neon.cyan],
                             ['services', 'services', neon.green],
                             ['vulns', 'findings', neon.orange],
                             ['credentials', 'creds', neon.yellow],
                             ['implants', 'implants', neon.red],
                             ['notes', 'notes', neon.purple]] as const)
                            .filter(([k]) => (h as unknown as Record<string, number>)[k] > 0)
                            .map(([k, label, c]) => (
                              <Chip key={k} size="small"
                                label={`${(h as unknown as Record<string, number>)[k]} ${label}`}
                                sx={tag(c)} />
                            ))}
                        </Stack>
                      </TableCell>

                      <TableCell sx={{ ...cellSx, width: 230 }}>
                        <TextField select size="small" fullWidth value={a}
                          onChange={(e) =>
                            setChoice((c) => ({ ...c, [h.host]: e.target.value as Action }))}
                          slotProps={{ htmlInput: { style: { fontSize: 11.5 } } }}>
                          {(['reject', 'add', 'map'] as Action[]).map((v) => (
                            <MenuItem key={v} value={v} sx={{ fontSize: 12.5 }}>
                              {ACTION_LABEL[v]}
                            </MenuItem>
                          ))}
                        </TextField>
                      </TableCell>

                      <TableCell sx={{ ...cellSx, width: 300 }}>
                        {a === 'map' ? (
                          <Autocomplete
                            size="small" options={names}
                            value={mapTo[h.host] ?? null}
                            onChange={(_, v) =>
                              setMapTo((m) => ({ ...m, [h.host]: v ?? '' }))}
                            renderInput={(p) => (
                              <TextField {...p} placeholder="existing target"
                                error={!(mapTo[h.host] ?? '').trim()} />
                            )} />
                        ) : (
                          <Typography sx={{ fontSize: 11, color: alpha(neon.muted, 0.5) }}>
                            {a === 'add' ? 'creates a new target' : 'data discarded'}
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Box>

          {incomplete.length > 0 && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
              {incomplete.length} row{incomplete.length === 1 ? '' : 's'} set to
              attach without a target chosen: {incomplete.map((h) => h.host).join(', ')}
            </Alert>
          )}
        </Stack>
      </DialogContent>

      {busy && (
        <Box sx={{ px: 3, pb: 1 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
            <CircularProgress
              size={13} thickness={6}
              variant={progress && progress.loaded < progress.total
                ? 'determinate' : 'indeterminate'}
              value={progress && progress.total
                ? (progress.loaded / progress.total) * 100 : 0}
              sx={{ color: neon.cyan }} />
            <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>
              {progress && progress.loaded < progress.total
                ? `re-sending the file — ${fmtBytes(progress.loaded)} of `
                  + `${fmtBytes(progress.total)}`
                : 'importing on the server — this can take a while for a large file'}
            </Typography>
            {progress && progress.secs > 0 && (
              <Typography sx={{ fontSize: 11, color: neon.muted }}>
                {progress.secs < 60
                  ? `${progress.secs}s`
                  : `${Math.floor(progress.secs / 60)}m `
                    + `${String(progress.secs % 60).padStart(2, '0')}s`}
              </Typography>
            )}
          </Stack>
          <LinearProgress
            variant={progress && progress.loaded < progress.total
              ? 'determinate' : 'indeterminate'}
            value={progress && progress.total
              ? (progress.loaded / progress.total) * 100 : 0}
            sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                  '& .MuiLinearProgress-bar': { bgcolor: neon.cyan } }} />
        </Box>
      )}

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onCancel} disabled={busy} sx={{ color: neon.muted }}>
          Cancel the import
        </Button>
        <Tooltip title={incomplete.length
          ? 'Choose a target for every row set to attach'
          : `Imports ${hosts.length - (counts.reject ?? 0)} host(s) and discards ${counts.reject ?? 0}`}>
          <span>
            <Button variant="outlined" disabled={busy || incomplete.length > 0}
              onClick={submit}
              sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
              {busy ? 'Importing…' : 'Continue import'}
            </Button>
          </span>
        </Tooltip>
      </DialogActions>
    </Dialog>
  )
}

const tag = (c: string) => ({
  height: 17, fontSize: 9.5, bgcolor: alpha(c, 0.14), color: c,
  border: `1px solid ${alpha(c, 0.4)}`,
})
const headSx = {
  fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.12em',
  textTransform: 'uppercase', color: alpha(neon.yellow, 0.85),
  backgroundColor: alpha(neon.bgDeep, 0.96),
  borderBottom: `1px solid ${alpha(neon.yellow, 0.3)}`, py: 0.7,
} as const
const cellSx = {
  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12, color: neon.text,
  borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`, py: 0.7,
  verticalAlign: 'top',
} as const
