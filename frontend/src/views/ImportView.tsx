import { useEffect, useRef, useState, type DragEvent } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, LinearProgress, MenuItem, Paper, Stack,
  TextField, Typography, alpha,
} from '@mui/material'
import UploadIcon from '@mui/icons-material/UploadFile'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import ErrorIcon from '@mui/icons-material/ErrorOutline'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type HostDecision, type ImportResult } from '../lib/api'
import { UnknownHostsDialog } from '../components/UnknownHostsDialog'
import { neon, glow } from '../theme'
import { sorted } from '../lib/sortOptions'

/**
 * Drop tool output here.
 *
 * A page rather than a dialog because importing is rarely one file: an
 * engagement produces a directory of them, and a modal that closes after
 * each one makes a twenty-file session twenty interactions. Dropping the
 * whole set at once and reading the results afterwards is the actual job.
 *
 * Format detection is per-file, so a mixed drop works — which is the normal
 * case, since the directory holds nmap XML next to nuclei JSONL.
 */

interface Done {
  file: string
  result?: ImportResult
  error?: string
  /** Set when the work was handed to a background job instead of
   *  finishing inline; the jobs panel reports it from there. */
  queued?: string
}

/** A file held back because it names hosts the project does not have. */
interface Pending {
  file: string
  content: string
  /** Set when the file was streamed. Kept so answering the strict-mode
   *  survey re-sends the same handle instead of a buffered copy. */
  handle?: File
  result: ImportResult
}

interface Sent { name: string; loaded: number; total: number }

/** Elapsed seconds as m:ss, so a long import reads as a duration. */
function fmtElapsed(s: number): string {
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`
}

/** Bytes in units a person reads, for the upload progress line. */
function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024, i = 0
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`
}

const BLURB: Record<string, string> = {
  auto: 'Each file is identified from its content.',
  nmap: 'nmap -sV -O -A -oX scan.xml',
  masscan: 'masscan -oX, -oJ or -oL',
  nessus: 'Nessus → Export → .nessus',
  metasploit: 'msfconsole: db_export -f xml out.xml',
  burp: 'Burp → Scanner → Report issues → XML',
  nikto: 'nikto -Format json',
  nuclei: 'nuclei -jsonl',
  httpx: 'httpx -json (also reads naabu)',
  cobaltstrike: 'Beacon metadata as JSON',
  mythic: 'Mythic callbacks as JSON',
  merlin: 'Merlin agents as JSON',
  sliver: 'sliver sessions/beacons as JSON',
  havoc: 'Havoc demons as JSON',
}

export function ImportView({ project }: { project: string | null }) {
  const qc = useQueryClient()
  const [format, setFormat] = useState('auto')
  const [over, setOver] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [sent, setSent] = useState<Sent | null>(null)
  const [done, setDone] = useState<Done[]>([])
  const [text, setText] = useState('')
  // Strict mode holds a file back rather than importing it. Queued, so a
  // drop of twenty files asks once per file instead of racing.
  const [pending, setPending] = useState<Pending[]>([])
  const [deciding, setDeciding] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const formats = useQuery({ queryKey: ['import-formats'], queryFn: api.importFormats })

  // Background imports. Polled rather than pushed, and polled faster
  // while one is live: this view is the only place that reports an
  // import you started and then navigated away from.
  const jobs = useQuery({
    queryKey: ['import-jobs', project],
    queryFn: () => api.importJobs(project!),
    enabled: !!project,
    refetchInterval: (q) =>
      (q.state.data ?? []).some((j) => j.status === 'queued' || j.status === 'running')
        ? 2000 : 15000,
  })
  const live = (jobs.data ?? []).filter(
    (j) => j.status === 'queued' || j.status === 'running')

  // Seconds the current import has been running. A spinner on its own
  // only says "not dead"; on a file that takes minutes to parse, the
  // number is the part that tells you it is worth waiting for.
  const [secs, setSecs] = useState(0)
  useEffect(() => {
    if (!busy) { setSecs(0); return }
    const t0 = Date.now()
    const id = setInterval(() => setSecs(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => clearInterval(id)
  }, [busy])

  // The same clock for the unknown-hosts modal, which runs its import
  // under `deciding` rather than `busy`.
  const [decideSecs, setDecideSecs] = useState(0)
  useEffect(() => {
    if (!deciding) { setDecideSecs(0); return }
    const t0 = Date.now()
    const id = setInterval(() => setDecideSecs(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => clearInterval(id)
  }, [deciding])

  const runOne = async (name: string, content: string,
                        decisions: Record<string, HostDecision> = {}) => {
    if (!project) return
    setBusy(name)
    try {
      const r = await api.importReport(project, content, format, 'strict', decisions)
      if (r.needs_decision) {
        // Nothing was written. Ask, then post the same file again.
        setPending((q) => [...q, { file: name, content, result: r }])
      } else {
        setDone((d) => [{ file: name, result: r }, ...d])
      }
    } catch (e) {
      setDone((d) => [{ file: name, error: e instanceof Error ? e.message : String(e) }, ...d])
    } finally {
      setBusy(null)
    }
  }

  /** Import a file by streaming it, never by reading it into a string.
   *
   *  The file is held as a `File` handle and re-sent if the strict-mode
   *  survey comes back needing decisions, so a 2.5 GB history is not
   *  buffered anywhere on this side.
   */
  const runFile = async (f: File, decisions: Record<string, HostDecision> = {}) => {
    if (!project) return
    setBusy(f.name)
    setSent({ name: f.name, loaded: 0, total: f.size })
    try {
      const r = await api.uploadReport(project, f, format, 'strict', decisions,
                                       (loaded, total) =>
                                         setSent({ name: f.name, loaded, total }))
      if (r.needs_decision) {
        setPending((q) => [...q, { file: f.name, content: '', handle: f, result: r }])
      } else {
        setDone((d) => [{ file: f.name, result: r }, ...d])
      }
    } catch (e) {
      setDone((d) => [{ file: f.name,
                        error: e instanceof Error ? e.message : String(e) }, ...d])
    } finally {
      setBusy(null)
      setSent(null)
    }
  }

  const head = pending[0]

  const decide = async (decisions: Record<string, HostDecision>) => {
    if (!head) return
    setDeciding(true)
    try {
      // The server kept the file from the survey, so answering costs a
      // few hundred bytes instead of another full upload. Re-uploading
      // is the fallback for a held file that expired or was lost to a
      // restart.
      const r = head.result.upload_id
        // Queued, not awaited: a large import runs for a long time and
        // must not die with the tab.
        ? await api.resumeImport(project!, head.result.upload_id, decisions,
                                 'strict', true)
        : head.handle
          ? await api.uploadReport(project!, head.handle, format, 'strict',
                                   decisions,
                                   (loaded, total) =>
                                     setSent({ name: head.file, loaded, total }))
          : await api.importReport(project!, head.content, format,
                                   'strict', decisions)
      if (r.job_id) {
        setDone((d) => [{ file: head.file,
                          queued: `queued as import #${r.job_id} — it keeps `
                                  + `running if you navigate away` }, ...d])
        await qc.invalidateQueries({ queryKey: ['import-jobs', project] })
      } else {
        setDone((d) => [{ file: head.file, result: r }, ...d])
      }
    } catch (e) {
      setDone((d) => [{ file: head.file,
                        error: e instanceof Error ? e.message : String(e) }, ...d])
    } finally {
      setDeciding(false)
      setSent(null)
      setPending((q) => q.slice(1))
      await qc.invalidateQueries()
    }
  }

  const take = async (files: FileList | File[]) => {
    // Sequential, not Promise.all: each import is one transaction against
    // the same project, and firing twenty at once just makes SQLite
    // serialise them while the progress display lies about it.
    //
    // Every file goes up as a stream. This used to be
    // `runOne(f.name, await f.text())`, which has a silent cliff:
    // `Blob.text()` resolves with an empty string for anything 512 MiB
    // or larger, so a big file produced no error and no import — it
    // just appeared to do nothing.
    for (const f of Array.from(files)) {
      await runFile(f)
    }
    await qc.invalidateQueries()
  }

  const onDrop = async (e: DragEvent) => {
    e.preventDefault()
    setOver(false)
    if (e.dataTransfer.files?.length) return take(e.dataTransfer.files)
    const dropped = e.dataTransfer.getData('text')
    if (dropped.trim()) {
      await runOne('pasted text', dropped)
      await qc.invalidateQueries()
    }
  }

  if (!project) {
    return (
      <Box sx={{ p: 4 }}>
        <Alert severity="info" variant="outlined" sx={{ fontSize: 12.5 }}>
          Choose an engagement in the header first — an import has to land
          somewhere.
        </Alert>
      </Box>
    )
  }

  return (
    <Box sx={{ flex: 1, overflow: 'auto', p: { xs: 1.5, sm: 2.5 } }}>
      {head && (
        <UnknownHostsDialog
          project={project} hosts={head.result.unknown_hosts}
          format={head.result.format} busy={deciding}
          progress={sent ? { loaded: sent.loaded, total: sent.total, secs: decideSecs }
                         : (deciding ? { loaded: 0, total: 0, secs: decideSecs } : null)}
          onCancel={() => {
            // Release the server's copy; otherwise a cancelled 2.5 GB
            // import leaves 2.5 GB in the temp directory until the TTL.
            if (head.result.upload_id) {
              void api.discardHeld(project, head.result.upload_id).catch(() => {})
            }
            setDone((d) => [{ file: head.file,
                              error: 'cancelled — nothing was imported' }, ...d])
            setPending((q) => q.slice(1))
          }}
          onConfirm={decide} />
      )}

      <Stack spacing={2.5} sx={{ maxWidth: 940, mx: 'auto' }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems="flex-start">
          <TextField select size="small" label="Format" value={format}
            sx={{ minWidth: 260 }} onChange={(e) => setFormat(e.target.value)}
            helperText={BLURB[format] ?? 'Pick the tool that produced the file.'}>
            <MenuItem value="auto" sx={{ fontSize: 13 }}>Detect automatically</MenuItem>
            {sorted(formats.data ?? [], (f) => f.label).map((f) => (
              <MenuItem key={f.name} value={f.name} sx={{ fontSize: 13 }}>{f.label}</MenuItem>
            ))}
          </TextField>
          <Box sx={{ flex: 1 }} />
          <Chip size="small" label={`into ${project}`} sx={{
            mt: 0.6, height: 22, fontSize: 11, bgcolor: alpha(neon.pink, 0.14),
            color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.5)}` }} />
        </Stack>

        {/* ---- the drop zone ---- */}
        <Paper elevation={0}
          onDragOver={(e) => { e.preventDefault(); setOver(true) }}
          onDragLeave={() => setOver(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          sx={{
            p: 5, textAlign: 'center', cursor: 'pointer',
            borderRadius: 2, transition: 'all .15s',
            border: `2px dashed ${alpha(over ? neon.cyan : neon.purple, over ? 0.9 : 0.4)}`,
            background: alpha(over ? neon.cyan : neon.paper, over ? 0.08 : 0.6),
            boxShadow: over ? `0 0 44px ${alpha(neon.cyan, 0.25)}` : 'none',
          }}>
          <input ref={fileRef} type="file" multiple
                 accept=".xml,.json,.jsonl,.nessus,.txt,.log"
                 style={{ display: 'none' }}
                 onChange={(e) => e.target.files && take(e.target.files)} />
          <UploadIcon sx={{ fontSize: 42, color: over ? neon.cyan : alpha(neon.purple, 0.7),
                            filter: over ? `drop-shadow(0 0 10px ${neon.cyan})` : 'none' }} />
          <Typography sx={{
            mt: 1.5, fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
            letterSpacing: '0.12em', color: over ? neon.cyan : neon.text,
            textShadow: over ? glow(neon.cyan, 0.6) : 'none',
          }}>
            {over ? 'DROP IT' : 'DRAG FILES HERE'}
          </Typography>
          <Typography sx={{ mt: 0.8, fontSize: 11.5, color: alpha(neon.muted, 0.9) }}>
            or click to choose · several at once is fine, mixed formats too
          </Typography>
        </Paper>

        {live.length > 0 && (
          <Stack spacing={1}>
            {live.map((j) => (
              <Paper key={j.id} variant="outlined"
                sx={{ p: 1.5, borderColor: alpha(neon.cyan, 0.4),
                      bgcolor: alpha(neon.cyan, 0.04) }}>
                <Stack direction="row" alignItems="center" spacing={1}>
                  <CircularProgress size={13} thickness={6}
                    variant={j.rows_total ? 'determinate' : 'indeterminate'}
                    value={j.rows_total ? (j.rows_done / j.rows_total) * 100 : 0}
                    sx={{ color: neon.cyan }} />
                  <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>
                    {j.status === 'queued' ? 'queued' : 'importing'} {j.filename}
                  </Typography>
                  <Typography sx={{ fontSize: 11, color: neon.muted }}>
                    {j.rows_done.toLocaleString()} rows
                    {j.hosts_seen ? ` · ${j.hosts_seen} hosts` : ''}
                  </Typography>
                </Stack>
                <LinearProgress
                  variant={j.rows_total ? 'determinate' : 'indeterminate'}
                  value={j.rows_total ? (j.rows_done / j.rows_total) * 100 : 0}
                  sx={{ mt: 0.75, height: 2, bgcolor: alpha(neon.purple, 0.2),
                        '& .MuiLinearProgress-bar': { bgcolor: neon.cyan } }} />
                <Typography sx={{ fontSize: 10.5, color: neon.muted, mt: 0.5 }}>
                  this keeps running if you navigate away or close the tab
                </Typography>
              </Paper>
            ))}
          </Stack>
        )}

        {busy && (
          <Box>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
              <CircularProgress
                size={13} thickness={6}
                variant={sent && sent.loaded < sent.total ? 'determinate' : 'indeterminate'}
                value={sent && sent.total ? (sent.loaded / sent.total) * 100 : 0}
                sx={{ color: neon.cyan }} />
              <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>
              {/* Two phases, and for a large file they take very different
                  amounts of time. Saying which one is running stops a long
                  server-side parse looking like a stalled upload. */}
              {sent && sent.loaded < sent.total
                ? `uploading ${busy} — ${fmtBytes(sent.loaded)} of ${fmtBytes(sent.total)}`
                : sent
                  ? `reading ${busy} (${fmtBytes(sent.total)}) on the server…`
                  : `importing ${busy}…`}
              </Typography>
              {secs > 0 && (
                <Typography sx={{ fontSize: 11, color: neon.muted }}>
                  {fmtElapsed(secs)}
                </Typography>
              )}
            </Stack>
            <LinearProgress
              variant={sent && sent.loaded < sent.total ? 'determinate' : 'indeterminate'}
              value={sent && sent.total ? (sent.loaded / sent.total) * 100 : 0}
              sx={{ height: 2, bgcolor: alpha(neon.purple, 0.2),
                    '& .MuiLinearProgress-bar': { bgcolor: neon.cyan } }} />
          </Box>
        )}

        {/* ---- paste, for when the output is in a terminal not a file ---- */}
        <Box>
          <TextField size="small" fullWidth multiline minRows={4} maxRows={12}
            value={text} onChange={(e) => setText(e.target.value)}
            placeholder="…or paste a report here"
            slotProps={{ htmlInput: { style: { fontFamily: `'Share Tech Mono', monospace`,
                                               fontSize: 11.5 } } }} />
          <Button size="small" variant="outlined" sx={{ mt: 1, color: neon.cyan,
                    borderColor: alpha(neon.cyan, 0.5) }}
            disabled={!text.trim() || !!busy}
            onClick={async () => {
              await runOne('pasted text', text)
              setText('')
              await qc.invalidateQueries()
            }}>
            Import pasted text
          </Button>
        </Box>

        {/* ---- results ---- */}
        {done.map((d, i) => (
          <Paper key={i} elevation={0} sx={{
            p: 2, backgroundColor: alpha(neon.paper, 0.7),
            border: `1px solid ${alpha(d.error ? neon.red : neon.green, 0.35)}`,
          }}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: d.error ? 0.5 : 1 }}>
              {d.error
                ? <ErrorIcon sx={{ fontSize: 16, color: neon.red }} />
                : <CheckCircleIcon sx={{ fontSize: 16, color: neon.green }} />}
              <Typography sx={{ fontSize: 12.5, color: neon.text, fontWeight: 600 }}>
                {d.file}
              </Typography>
              {d.result && (
                <Chip size="small" label={d.result.format} sx={{
                  height: 18, fontSize: 10, bgcolor: alpha(neon.cyan, 0.15),
                  color: neon.cyan, border: `1px solid ${alpha(neon.cyan, 0.5)}` }} />
              )}
            </Stack>
            {d.error && (
              <Typography sx={{ fontSize: 11.5, color: neon.red }}>{d.error}</Typography>
            )}
            {d.queued && (
              <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>{d.queued}</Typography>
            )}
            {d.result && <Summary r={d.result} />}
          </Paper>
        ))}
      </Stack>
    </Box>
  )
}

function Summary({ r }: { r: ImportResult }) {
  const bits: [string, number, string][] = [
    ['targets +', r.targets_created, neon.green],
    ['targets ~', r.targets_updated, neon.muted],
    ['services +', r.services_created, neon.green],
    ['services ~', r.services_updated, neon.muted],
    ['unidentified ports', r.services_unknown, neon.yellow],
    ['findings +', r.vulns_created, neon.orange],
    ['findings ~', r.vulns_updated, neon.muted],
    ['web addresses +', r.urls_created, neon.cyan],
    ['web addresses ~', r.urls_updated, neon.muted],
    ['credentials', r.credentials_created, neon.yellow],
    ['C2 callbacks', r.implants_created, neon.red],
    ['newly pwned', r.hosts_flagged, neon.red],
    ['NSE results', r.scripts_captured, neon.purple],
  ]
  const skipped = Object.keys(r.rejected_hosts ?? {}).length
  const mapped = Object.keys(r.mapped_hosts ?? {}).length
  const shown = bits.filter(([, n]) => n > 0)
  return (
    <>
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {shown.length === 0 && (
          <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
            Nothing new — everything in this file was already recorded.
          </Typography>
        )}
        {shown.map(([label, n, c]) => (
          <Chip key={label} size="small" label={`${label} ${n}`} sx={{
            height: 20, fontSize: 10.5, bgcolor: alpha(c, 0.14), color: c,
            border: `1px solid ${alpha(c, 0.45)}` }} />
        ))}
      </Stack>
      {(skipped > 0 || mapped > 0) && (
        <Typography sx={{ mt: 0.8, fontSize: 10.5, color: alpha(neon.muted, 0.95) }}>
          {skipped > 0 && `${skipped} host(s) skipped: `
            + Object.keys(r.rejected_hosts).slice(0, 6).join(', ')
            + (skipped > 6 ? ` and ${skipped - 6} more` : '') + '. '}
          {mapped > 0 && Object.entries(r.mapped_hosts)
            .map(([from, to]) => `${from} → ${to}`).join(', ') + '.'}
        </Typography>
      )}
      {r.errors.length > 0 && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 1.2, fontSize: 11 }}>
          {r.errors.slice(0, 8).map((e, i) => <Box key={i}>{e}</Box>)}
          {r.errors.length > 8 && <Box>…and {r.errors.length - 8} more</Box>}
        </Alert>
      )}
    </>
  )
}
