/**
 * Queue an nmap run on a Jaws agent, in words rather than flags.
 *
 * The flags are shown as secondary text because the operator has to be
 * able to check them, but the choices are named for what they do. The
 * dialog's real job is the gap between what is asked for and what will
 * run: the agent builds the command line from its own capabilities, so
 * "SYN scan" on an unprivileged agent is a connect scan and the only
 * honest thing to do is say so before it is queued. See `nmapPlan`.
 */
import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, DialogActions, DialogContent,
  FormControlLabel, Radio, RadioGroup, Stack, TextField, Tooltip,
  Typography, alpha,
} from '@mui/material'
import { useQueryClient } from '@tanstack/react-query'
import { neon } from '../theme'
import {
  AgentChooser, Argv, Caveat, EnumerateDialog, FleetNotice,
} from './EnumerateBits'
import {
  NMAP_DEFAULTS, nmapPlan, queue, rawSockets, needsRegion,
  useFleet, type AgentChoice, type NmapOptions,
} from './jawsTasking'

/** Label plus its flag, so both readings are available at a glance. */
function Flag({ text, flag }: { text: string; flag: string }) {
  return (
    <Stack direction="row" spacing={1} alignItems="baseline">
      <Box sx={{ fontSize: 13 }}>{text}</Box>
      <Box sx={{ fontFamily: `'Share Tech Mono', monospace`, fontSize: 11,
                 color: alpha(neon.cyan, 0.85) }}>{flag}</Box>
    </Stack>
  )
}

export function NmapScanDialog({ project, targets, onClose, onQueued }: {
  project: string
  /** Hosts or ranges, exactly as nmap will be given them. */
  targets: string[]
  onClose: () => void
  /** Called with the confirmation once work is queued. The parent
   *  closes this and says so elsewhere: a modal that stays open on
   *  success is one the operator has to dismiss before carrying on,
   *  and the next thing they want is the table behind it. */
  onQueued?: (summary: string) => void
}) {
  const qc = useQueryClient()
  const fleet = useFleet(project)
  const [agent, setAgent] = useState<AgentChoice>(null)
  const [region, setRegion] = useState('')
  const [o, setO] = useState<NmapOptions>(NMAP_DEFAULTS)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  const priv = rawSockets(fleet, agent)
  const plan = useMemo(
    () => nmapPlan(o, targets, priv, agent === null),
    [o, targets, priv, agent])

  const set = <K extends keyof NmapOptions>(k: K, v: NmapOptions[K]) =>
    setO((p) => ({ ...p, [k]: v }))

  const regionMissing = needsRegion(fleet, agent) && !region.trim()
  const stop = plan.blockers.length > 0 || !!fleet.blocked || regionMissing

  const run = async () => {
    setBusy(true); setErr(null)
    try {
      // The install goes first and as a separate task: the server only
      // accepts `install` addressed to one agent, and nmap's package is
      // what carries the NSE library. Queued before the scan so the
      // agent takes them in order.
      if (o.installTools && agent !== null) {
        await queue(project, agent, 'install', { tools: ['nmap'] }, region)
      }
      const t = await queue(project, agent, 'nmap', plan.args, region)
      const msg = (`Queued as task ${t.id}. It is waiting for an agent, not running `
              + `yet — the Jaws page shows when it starts.`)
      if (onQueued) onQueued(msg); else setDone(msg)
      await qc.invalidateQueries({ queryKey: ['agents'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <EnumerateDialog accent={neon.cyan} onClose={onClose}
      title={`ENUMERATE WITH NMAP → ${targets.length === 1 ? targets[0]
        : `${targets.length} targets`}`}>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>{err}</Alert>}
          {done && <Alert severity="success" variant="outlined" sx={{ fontSize: 12.5 }}>{done}</Alert>}
          <FleetNotice fleet={fleet} />

          <AgentChooser fleet={fleet} value={agent} onChange={setAgent}
            region={region} onRegion={setRegion} />

          <Box>
            <Typography sx={{ fontSize: 11, letterSpacing: '0.12em',
                              textTransform: 'uppercase', color: neon.cyan,
                              fontFamily: `'Orbitron', sans-serif`, mb: 0.5 }}>
              Scan type
            </Typography>
            <RadioGroup value={o.scan}
              onChange={(e) => set('scan', e.target.value as 'syn' | 'connect')}>
              <FormControlLabel value="syn" control={<Radio size="small" />}
                label={<Flag text="SYN scan" flag="-sS" />} />
              <FormControlLabel value="connect" control={<Radio size="small" />}
                label={<Flag text="TCP connect scan" flag="-sT" />} />
            </RadioGroup>
            <Caveat>
              A SYN scan needs raw sockets and the agent may not have them —
              the Jaws list reports that as <i>privileged</i>. The agent picks
              the scan type itself from what it can do; Oddjob cannot override
              it either way.
            </Caveat>
          </Box>

          <Stack>
            <Tooltip title={o.aggressive
              ? 'Aggressive already runs version detection'
              : 'Ask each open port what it is running'}>
              <FormControlLabel
                control={<Checkbox size="small" disabled={o.aggressive}
                  checked={o.versionDetect || o.aggressive}
                  onChange={(e) => set('versionDetect', e.target.checked)} />}
                label={<Flag text="Service and version detection" flag="-sV" />} />
            </Tooltip>
            <FormControlLabel
              control={<Checkbox size="small" checked={o.skipHostDiscovery}
                onChange={(e) => set('skipHostDiscovery', e.target.checked)} />}
              label={<Flag text="Skip host discovery, treat every target as online"
                            flag="-Pn" />} />
            <FormControlLabel
              control={<Checkbox size="small" checked={o.aggressive}
                onChange={(e) => set('aggressive', e.target.checked)} />}
              label={<Flag text="Aggressive: OS, version, default scripts, traceroute"
                            flag="-A" />} />
            <Tooltip title={o.aggressive
              ? 'Aggressive already includes OS detection'
              : 'Fingerprint the operating system'}>
              <FormControlLabel
                control={<Checkbox size="small" disabled={o.aggressive}
                  checked={o.osDetect || o.aggressive}
                  onChange={(e) => set('osDetect', e.target.checked)} />}
                label={<Flag text="OS detection" flag="-O" />} />
            </Tooltip>
            {o.aggressive && (
              <Caveat>
                <b>-A</b> implies <b>-sV</b> and <b>-O</b>, so those two are
                locked on and are not sent again. Passing them alongside it
                would be a longer command line saying the same thing.
              </Caveat>
            )}
          </Stack>

          <TextField
            size="small" label="Ports" value={o.ports} placeholder="22,80,443 or 1-1024"
            onChange={(e) => set('ports', e.target.value)}
            helperText="Left empty, the agent decides. Naming ports also stops it
                        adding -F, which nmap refuses alongside -p." />

          <Tooltip title={agent === null
            ? 'Installing is addressed to one agent — the server refuses it for the pool'
            : ''}>
            <FormControlLabel
              control={<Checkbox size="small" checked={o.installTools}
                disabled={agent === null}
                onChange={(e) => set('installTools', e.target.checked)} />}
              label={<Box sx={{ fontSize: 13 }}>
                Install any NSE script it needs automatically
              </Box>} />
          </Tooltip>
          <Caveat>
            What this can actually do is install <b>nmap</b> on the agent, which
            brings its script library with it. Jaws has no way to fetch an
            individual NSE script, so a script that is not in that library will
            still be missing and nmap will say so.
          </Caveat>

          {plan.warnings.map((w) => (
            <Alert key={w} severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
              {w}
            </Alert>
          ))}
          {plan.blockers.map((b) => (
            <Alert key={b} severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
              {b}
            </Alert>
          ))}

          <Box>
            <Typography sx={{ fontSize: 10.5, color: neon.muted, mb: 0.5 }}>
              What the agent will run
            </Typography>
            <Argv text={plan.argv} />
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Close</Button>
        <Button variant="outlined" disabled={busy || stop} onClick={run}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6) }}>
          {busy ? '…' : 'Queue scan'}
        </Button>
      </DialogActions>
    </EnumerateDialog>
  )
}
