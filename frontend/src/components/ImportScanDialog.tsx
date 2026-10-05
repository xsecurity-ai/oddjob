import { useEffect, useRef, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle,
  MenuItem, Stack, TextField, Typography, alpha,
} from '@mui/material'
import UploadIcon from '@mui/icons-material/UploadFile'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type HostDecision, type ImportResult } from '../lib/api'
import { UnknownHostsDialog } from './UnknownHostsDialog'
import { neon, glow } from '../theme'
import { sorted } from '../lib/sortOptions'

/**
 * Import a report from any supported tool.
 *
 * The format list comes from the server rather than being hard-coded here,
 * so adding an importer is one backend change. "Detect automatically" is the
 * default because operators have directories of mixed output and making them
 * classify each file by hand is how the wrong parser meets the wrong file.
 */

const HINTS: Record<string, string> = {
  auto: 'Paste or choose a file — the format is worked out from the content.',
  nmap: 'nmap -sV -O -A -oX scan.xml',
  masscan: 'masscan -oX, -oJ or -oL — all three are accepted',
  nessus: 'Nessus → Export → .nessus (v2)',
  metasploit: 'msfconsole: db_export -f xml /path/out.xml',
  burp: 'Burp → Scanner → Report issues → XML',
  nikto: 'nikto -Format json -output out.json',
  nuclei: 'nuclei -jsonl -o out.jsonl',
  httpx: 'httpx -json — also reads naabu JSONL',
  cobaltstrike: 'Beacon metadata as JSON: id, computer, user, listener, …',
  mythic: 'Mythic callbacks as JSON (API or GraphQL export)',
  merlin: 'Merlin agent list as JSON',
  sliver: 'sliver: sessions/beacons as JSON',
  havoc: 'Havoc demon list as JSON',
}

export function ImportScanDialog({ project, onClose }: {
  project: string; onClose: () => void
}) {
  const qc = useQueryClient()
  const [content, setContent] = useState('')
  // Set when a file was chosen rather than pasted. The file is streamed
  // on import and the textarea shows only its head: reading a large one
  // into a string gives back an empty string with no error, so the box
  // would simply look empty.
  const [file, setFile] = useState<File | null>(null)
  const [sent, setSent] = useState<{ loaded: number; total: number } | null>(null)
  const [format, setFormat] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  // Seconds the current import has run, so a long server-side parse
  // shows something moving rather than a button that went quiet.
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!busy) { setElapsed(0); return }
    const t0 = Date.now()
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => clearInterval(id)
  }, [busy])

  const [result, setResult] = useState<ImportResult | null>(null)
  // Strict mode holds the import back when the file names hosts this
  // project does not have.
  const [unknown, setUnknown] = useState<ImportResult | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const formats = useQuery({ queryKey: ['import-formats'], queryFn: api.importFormats })

  //: How much of a chosen file to show. Enough to recognise the format
  //: by eye; the whole file is streamed on import regardless.
  const PREVIEW = 64 * 1024

  const pick = async (f: File | undefined) => {
    if (!f) return
    setErr(null)
    setFile(f)
    setContent(await f.slice(0, PREVIEW).text())
  }

  const run = async (decisions: Record<string, HostDecision> = {}) => {
    setBusy(true); setErr(null); setResult(null)
    try {
      // Resume off the server's held copy when there is one: answering
      // the unknown-host question should not re-send the whole file.
      const r = unknown?.upload_id
        ? await api.resumeImport(project, unknown.upload_id, decisions)
        : file
          ? await api.uploadReport(project, file, format, 'strict', decisions,
                                   (loaded, total) => setSent({ loaded, total }))
          : await api.importReport(project, content, format, 'strict', decisions)
      if (r.needs_decision) {
        setUnknown(r)        // nothing written yet
      } else {
        setUnknown(null)
        setResult(r)
        await qc.invalidateQueries()
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false); setSent(null) }
  }

  const row = (label: string, value: number, colour: string = neon.text) => (
    value === 0 ? null : (
      <Stack key={label} direction="row" spacing={1} justifyContent="space-between">
        <Typography sx={{ fontSize: 12, color: neon.muted }}>{label}</Typography>
        <Typography sx={{ fontSize: 12, color: colour, fontWeight: 600 }}>{value}</Typography>
      </Stack>
    )
  )

  if (unknown) {
    return (
      <UnknownHostsDialog
        project={project} hosts={unknown.unknown_hosts}
        format={unknown.format} busy={busy}
        progress={busy ? { loaded: sent?.loaded ?? 0, total: sent?.total ?? 0,
                           secs: elapsed } : null}
        onCancel={() => {
          if (unknown.upload_id) {
            void api.discardHeld(project, unknown.upload_id).catch(() => {})
          }
          setUnknown(null)
        }}
        onConfirm={(d) => run(d)} />
    )
  }

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 44px ${alpha(neon.cyan, 0.22)}`,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan,
                         textShadow: glow(neon.cyan, 0.5),
                         borderBottom: `1px solid ${alpha(neon.cyan, 0.28)}` }}>
        IMPORT REPORT → {project}
      </DialogTitle>

      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}

          {result ? (
            <Box sx={{ p: 2, borderRadius: 1, background: alpha(neon.bgDeep, 0.5),
                       border: `1px solid ${alpha(neon.green, 0.35)}` }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.2 }}>
                <Chip size="small" label={result.format} sx={{
                  height: 19, fontSize: 10, bgcolor: alpha(neon.cyan, 0.15),
                  color: neon.cyan, border: `1px solid ${alpha(neon.cyan, 0.5)}` }} />
                <Typography sx={{ fontSize: 12, color: neon.green }}>
                  {result.tool} · {result.hosts_seen} host(s)
                </Typography>
              </Stack>
              <Stack spacing={0.6}>
                {row('Targets created', result.targets_created, neon.green)}
                {row('Targets updated', result.targets_updated)}
                {row('Services created', result.services_created, neon.green)}
                {row('Services updated', result.services_updated)}
                {row('Unidentified open ports', result.services_unknown, neon.yellow)}
                {row('Findings created', result.vulns_created, neon.orange)}
                {row('Findings updated', result.vulns_updated)}
                {row('Credentials captured', result.credentials_created, neon.yellow)}
                {row('C2 callbacks recorded', result.implants_created, neon.red)}
                {row('C2 callbacks updated', result.implants_updated)}
                {row('Hosts newly marked pwned', result.hosts_flagged, neon.red)}
                {row('NSE script results kept', result.scripts_captured, neon.cyan)}
                {row('Timeline notes added', result.notes_recorded)}
              </Stack>
              {result.command && (
                <Typography sx={{ mt: 1.5, fontSize: 10.5, color: alpha(neon.muted, 0.8),
                                  fontFamily: `'Share Tech Mono', monospace`,
                                  wordBreak: 'break-all' }}>
                  {result.command}
                </Typography>
              )}
              {result.errors.length > 0 && (
                <Alert severity="warning" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
                  {result.errors.map((e, i) => <Box key={i}>{e}</Box>)}
                </Alert>
              )}
            </Box>
          ) : (
            <>
              <TextField select size="small" fullWidth label="Format" value={format}
                onChange={(e) => setFormat(e.target.value)}
                helperText={HINTS[format] ?? 'Paste the report below, or choose a file.'}>
                <MenuItem value="auto" sx={{ fontSize: 13 }}>Detect automatically</MenuItem>
                {sorted(formats.data ?? [], (f) => f.label).map((f) => (
                  <MenuItem key={f.name} value={f.name} sx={{ fontSize: 13 }}>
                    {f.label}
                  </MenuItem>
                ))}
              </TextField>
              <Box>
                <input ref={fileRef} type="file"
                       accept=".xml,.json,.jsonl,.nessus,.txt,.log,text/xml,application/json"
                       style={{ display: 'none' }}
                       onChange={(e) => pick(e.target.files?.[0])} />
                <Button size="small" variant="outlined" startIcon={<UploadIcon sx={{ fontSize: 16 }} />}
                  onClick={() => fileRef.current?.click()}
                  sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.5) }}>
                  Choose file
                </Button>
              </Box>
              <TextField
                size="small" fullWidth multiline minRows={7} maxRows={14} value={content}
                onChange={(e) => {
                  // Typing over a chosen file means the text is now the
                  // source of truth; otherwise the edit would be ignored
                  // and the original file imported instead.
                  setFile(null)
                  setContent(e.target.value)
                }}
                placeholder="…or paste the report here"
                slotProps={{ htmlInput: { style: { fontFamily: `'Share Tech Mono', monospace`,
                                                   fontSize: 11.5 } } }} />
              <Typography sx={{ fontSize: 11, color: neon.muted, mt: -1 }}>
                {file
                  ? `${file.name} — ${(file.size / 1048576).toFixed(1)} MB, streamed on import`
                    + (file.size > PREVIEW ? ` (showing the first ${PREVIEW / 1024} KB)` : '')
                  : content ? `${(content.length / 1024).toFixed(1)} KB loaded`
                            : 'nothing loaded'}
                {sent && sent.loaded < sent.total
                  ? ` · uploading ${Math.round((sent.loaded / sent.total) * 100)}%`
                  : ' · re-importing updates what is already here rather than duplicating it'}
              </Typography>
            </>
          )}
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>
          {result ? 'Done' : 'Cancel'}
        </Button>
        {result && (
          <Button onClick={() => { setResult(null); setContent('') }}
            sx={{ color: neon.cyan }}>Import another</Button>
        )}
        {!result && (
          <Button variant="outlined" disabled={busy || (!file && !content.trim())}
            onClick={() => run()}
            startIcon={busy
              ? <CircularProgress
                  size={13} thickness={6}
                  variant={sent && sent.loaded < sent.total ? 'determinate' : 'indeterminate'}
                  value={sent && sent.total ? (sent.loaded / sent.total) * 100 : 0}
                  sx={{ color: neon.cyan }} />
              : undefined}
            sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
            {busy
              ? (sent && sent.loaded < sent.total ? 'Uploading…' : 'Importing…')
              : 'Import'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}
