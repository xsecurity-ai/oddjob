import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import {
  Box, Chip, CircularProgress, Dialog, DialogContent, DialogTitle, Divider,
  IconButton, Stack, Table, TableBody, TableCell, TableHead, TableRow,
  Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import { useQuery } from '@tanstack/react-query'
import { api, SEVERITY_RANK } from '../lib/api'
import { Timeline } from './Timeline'
import { useAuth } from '../lib/auth'
import { neon, glow } from '../theme'

/* --------------------------------------------------------------------------
   A single modal instance lives at the app root; any grid cell opens it via
   useHostModal(). That avoids threading open/close state and a <Dialog>
   through four separate views, and means only one detail query is ever in
   flight.
   -------------------------------------------------------------------------- */

type Ctx = { open: (project: string, host: string) => void }
const HostModalCtx = createContext<Ctx | null>(null)

export function useHostModal(): Ctx {
  const c = useContext(HostModalCtx)
  if (!c) throw new Error('useHostModal outside HostModalProvider')
  return c
}

const SEV_COLOUR: Record<string, string> = {
  critical: neon.red, high: neon.orange, medium: neon.yellow,
  low: neon.cyan, info: neon.muted,
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Box sx={{ minWidth: 150 }}>
      <Typography sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.16em',
        textTransform: 'uppercase', color: alpha(neon.cyan, 0.75), mb: 0.4,
      }}>{label}</Typography>
      <Box sx={{ fontSize: 13, color: neon.text, wordBreak: 'break-word' }}>{children}</Box>
    </Box>
  )
}

const dash = <Box component="span" sx={{ color: alpha(neon.muted, 0.4) }}>—</Box>

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <Box sx={{ mt: 3 }}>
      <Stack direction="row" spacing={1} alignItems="baseline" sx={{ mb: 1 }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 11, letterSpacing: '0.16em',
          textTransform: 'uppercase', color: neon.pink, textShadow: glow(neon.pink, 0.5),
        }}>{title}</Typography>
        <Typography sx={{ color: neon.muted, fontSize: 11 }}>{count}</Typography>
      </Stack>
      {count === 0
        ? <Typography sx={{ color: alpha(neon.muted, 0.6), fontSize: 12.5 }}>None recorded.</Typography>
        : children}
    </Box>
  )
}

const headSx = {
  fontFamily: `'Orbitron', sans-serif`, fontSize: 9.5, letterSpacing: '0.12em',
  textTransform: 'uppercase', color: alpha(neon.cyan, 0.8),
  borderBottom: `1px solid ${alpha(neon.cyan, 0.3)}`, py: 0.6,
} as const
const cellSx = {
  fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5, color: neon.text,
  borderBottom: `1px solid ${alpha(neon.purple, 0.12)}`, py: 0.6,
} as const

function Body({ project, host }: { project: string; host: string }) {
  const { canWrite } = useAuth()
  const { data, isLoading, error } = useQuery({
    queryKey: ['target-detail', project, host],
    queryFn: () => api.targetDetail(project, host),
  })

  if (isLoading) {
    return <Box sx={{ display: 'grid', placeItems: 'center', py: 8 }}>
      <CircularProgress sx={{ color: neon.cyan }} />
    </Box>
  }
  if (error) {
    return <Typography sx={{ color: neon.red, py: 4 }}>{(error as Error).message}</Typography>
  }
  if (!data) return null

  const t = data.target
  const open = data.services.filter((s) => s.state === 'open')
  const other = data.services.filter((s) => s.state !== 'open')
  const vulns = [...data.vulns].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9))

  return (
    <>
      {/* ---- overview ---- */}
      <Box sx={{
        display: 'grid', gap: 2.5, p: 2, borderRadius: 1,
        gridTemplateColumns: 'repeat(auto-fill, minmax(165px, 1fr))',
        background: alpha(neon.bgDeep, 0.5),
        border: `1px solid ${alpha(neon.purple, 0.25)}`,
      }}>
        <Field label="Hostname">
          <Box sx={{ color: neon.pink, textShadow: glow(neon.pink, 0.4), fontWeight: 600 }}>
            {t.host}
          </Box>
        </Field>
        {/* Every one of them, not the first. A host with an A record, a
            AAAA record and two more behind a load balancer has four
            addresses, and showing one made the other three invisible to
            anybody reading the modal — which is where somebody goes to
            find out what a host actually is. */}
        <Field label={t.ip_addresses.length > 1 ? 'IP Addresses' : 'IP Address'}>
          {t.ip_addresses.length
            ? <Stack spacing={0.2}>
                {t.ip_addresses.map((a) => <span key={a}>{a}</span>)}
              </Stack>
            : dash}
        </Field>
        <Field label="Operating System">
          {t.os
            ? <Stack direction="row" spacing={0.8} alignItems="baseline" flexWrap="wrap" useFlexGap>
                <span>{t.os}</span>
                {/* A fingerprint is a guess; printing the name alone turns an
                    87% match into a statement of fact. */}
                {t.os_accuracy != null && (
                  <Typography component="span" sx={{ fontSize: 10.5, color: neon.muted }}>
                    {t.os_accuracy}% match
                  </Typography>
                )}
              </Stack>
            : dash}
        </Field>
        <Field label="Project">
          <Box sx={{ color: neon.purple }}>{t.project_code}</Box>
        </Field>
        <Field label="Alive">
          {t.alive === null || t.alive === undefined ? (
            <Tooltip title="Not probed yet"><span>{dash}</span></Tooltip>
          ) : (
            <Box sx={{ color: t.alive ? neon.green : neon.red,
                       textShadow: glow(t.alive ? neon.green : neon.red, 0.5) }}>
              {t.alive ? 'UP' : 'DOWN'}
            </Box>
          )}
        </Field>
        <Field label="Hacked">
          {t.hacked
            ? <Box sx={{ color: neon.red, textShadow: glow(neon.red, 0.6) }}>💀 PWNED</Box>
            : dash}
        </Field>
        <Field label="Open Ports">
          <Box sx={{ color: neon.cyan, fontWeight: 700 }}>{t.total_ports}</Box>
        </Field>
        <Field label="Findings">
          <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
            {(['critical', 'high'] as const).map((k) => {
              const n = k === 'critical' ? t.total_criticals : t.total_highs
              const c = SEV_COLOUR[k]
              return <Chip key={k} size="small" label={`${k.slice(0, 4)} ${n}`} sx={{
                height: 19, fontSize: 10, bgcolor: alpha(c, n ? 0.18 : 0.05),
                color: n ? c : alpha(neon.muted, 0.5),
                border: `1px solid ${alpha(c, n ? 0.6 : 0.2)}`,
              }} />
            })}
            <Chip size="small" label={`all ${t.total_vulns}`} sx={{
              height: 19, fontSize: 10, bgcolor: alpha(neon.purple, 0.15),
              color: neon.text, border: `1px solid ${alpha(neon.purple, 0.45)}`,
            }} />
            <Chip size="small" label={`pocs ${t.total_pocs}`} sx={{
              height: 19, fontSize: 10, bgcolor: alpha(neon.green, t.total_pocs ? 0.16 : 0.05),
              color: t.total_pocs ? neon.green : alpha(neon.muted, 0.5),
              border: `1px solid ${alpha(neon.green, t.total_pocs ? 0.55 : 0.2)}`,
            }} />
          </Stack>
        </Field>
        {t.mac_address && (
          <Field label="MAC">
            <Stack direction="row" spacing={0.8} alignItems="baseline" flexWrap="wrap" useFlexGap>
              <span>{t.mac_address}</span>
              {t.mac_vendor && (
                <Typography component="span" sx={{ fontSize: 10.5, color: neon.muted }}>
                  {t.mac_vendor}
                </Typography>
              )}
            </Stack>
          </Field>
        )}
        {t.hostnames && t.hostnames.length > 1 && (
          <Field label="Hostnames">{t.hostnames.join(', ')}</Field>
        )}
        {t.tags && <Field label="Other Names">{t.tags.split(',').join(', ')}</Field>}
      </Box>

      {/* ---- notes ---- */}
      <Section title="Notes" count={t.notes ? 1 : 0}>
        <Box sx={{
          whiteSpace: 'pre-wrap', fontSize: 12.5, color: neon.text, lineHeight: 1.6,
          p: 1.5, borderRadius: 1, background: alpha(neon.bgDeep, 0.45),
          border: `1px solid ${alpha(neon.purple, 0.2)}`,
        }}>{t.notes}</Box>
      </Section>

      {/* ---- ports ---- */}
      <Section title="Open Ports" count={open.length}>
        <Table size="small">
          <TableHead><TableRow>
            {['Port', 'Proto', 'Service', 'Product', 'Version', 'Notes'].map((h) =>
              <TableCell key={h} sx={headSx}>{h}</TableCell>)}
          </TableRow></TableHead>
          <TableBody>
            {open.map((s) => (
              <TableRow key={s.id} hover>
                <TableCell sx={{ ...cellSx, color: neon.cyan, fontWeight: 700 }}>{s.port}</TableCell>
                <TableCell sx={cellSx}>{s.protocol}</TableCell>
                <TableCell sx={{ ...cellSx,
                                 color: s.name === 'UNKNOWN' ? neon.yellow : neon.green }}>
                  {s.name || 'UNKNOWN'}
                  {Object.keys(s.scripts ?? {}).length > 0 && (
                    <Tooltip title={Object.keys(s.scripts).join(', ')}>
                      <Box component="span" sx={{ ml: 0.7, fontSize: 9.5, color: neon.cyan,
                                                  border: `1px solid ${alpha(neon.cyan, 0.45)}`,
                                                  borderRadius: 0.5, px: 0.4 }}>
                        nse {Object.keys(s.scripts).length}
                      </Box>
                    </Tooltip>
                  )}
                </TableCell>
                <TableCell sx={cellSx}>{s.product || ''}</TableCell>
                <TableCell sx={{ ...cellSx, color: neon.muted }}>{s.banner || ''}</TableCell>
                {/* An operator's note about the service, which used to be
                    jammed into the banner column. */}
                <TableCell sx={{ ...cellSx, color: alpha(neon.purple, 0.95),
                                 fontFamily: 'inherit', fontSize: 11.5 }}>
                  {s.notes || ''}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {other.length > 0 && (
          <Typography sx={{ mt: 1, fontSize: 11.5, color: alpha(neon.muted, 0.75) }}>
            {other.length} further port(s) recorded as closed or filtered.
          </Typography>
        )}
      </Section>

      {/* ---- vulns ---- */}
      <Section title="Vulnerabilities" count={vulns.length}>
        <Table size="small">
          <TableHead><TableRow>
            {['Severity', 'Title', 'Status', 'Port'].map((h) =>
              <TableCell key={h} sx={headSx}>{h}</TableCell>)}
          </TableRow></TableHead>
          <TableBody>
            {vulns.map((v) => {
              const c = SEV_COLOUR[v.severity] ?? neon.muted
              return (
                <TableRow key={v.id} hover>
                  <TableCell sx={{ ...cellSx, width: 92 }}>
                    <Box sx={{ color: c, textShadow: glow(c, 0.4), fontSize: 11,
                               letterSpacing: '0.06em' }}>{v.severity}</Box>
                  </TableCell>
                  <TableCell sx={cellSx}>{v.title}</TableCell>
                  <TableCell sx={{ ...cellSx, width: 86, color: neon.muted }}>{v.status}</TableCell>
                  <TableCell sx={{ ...cellSx, width: 70 }}>{v.port ?? ''}</TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </Section>

      {/* ---- pocs ---- */}
      <Section title="Proofs of Concept" count={data.pocs.length}>
        <Table size="small">
          <TableHead><TableRow>
            {['Title', 'Status', 'Exit', 'Path'].map((h) =>
              <TableCell key={h} sx={headSx}>{h}</TableCell>)}
          </TableRow></TableHead>
          <TableBody>
            {data.pocs.map((p) => (
              <TableRow key={p.id} hover>
                <TableCell sx={cellSx}>{p.title}</TableCell>
                <TableCell sx={{ ...cellSx, width: 110,
                                 color: p.status === 'confirmed' ? neon.green : neon.yellow }}>
                  {p.status}
                </TableCell>
                {/* 0 reproduced, 1 not reproduced, 2 could not test */}
                <TableCell sx={{ ...cellSx, width: 60 }}>{p.exit_code ?? ''}</TableCell>
                <TableCell sx={{ ...cellSx, color: neon.muted }}>{p.path || ''}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Section>

      {/* ---- C2 callbacks ---- */}
      <Section title="C2 Callbacks" count={data.implants.length}>
        <Table size="small">
          <TableHead><TableRow>
            {['Framework', 'ID', 'User', 'Integrity', 'Process', 'Listener', 'Last seen']
              .map((h) => <TableCell key={h} sx={headSx}>{h}</TableCell>)}
          </TableRow></TableHead>
          <TableBody>
            {data.implants.map((im) => {
              // SYSTEM/high is the thing a reader scans this table for.
              const ic = im.integrity === 'system' ? neon.red
                : im.integrity === 'high' ? neon.orange
                : im.integrity ? neon.muted : alpha(neon.muted, 0.4)
              return (
                <TableRow key={im.id} hover sx={{ opacity: im.active === false ? 0.5 : 1 }}>
                  <TableCell sx={{ ...cellSx, color: neon.pink }}>{im.framework}</TableCell>
                  <TableCell sx={{ ...cellSx, color: neon.muted }}>{im.implant_id}</TableCell>
                  <TableCell sx={cellSx}>
                    {im.domain ? `${im.domain}\\${im.user ?? ''}` : (im.user || dash)}
                  </TableCell>
                  <TableCell sx={{ ...cellSx, color: ic, textShadow: glow(ic, 0.4) }}>
                    {im.integrity || '—'}
                  </TableCell>
                  <TableCell sx={cellSx}>
                    {im.process || ''}{im.pid ? ` (${im.pid})` : ''}
                  </TableCell>
                  <TableCell sx={{ ...cellSx, color: neon.muted }}>{im.listener || ''}</TableCell>
                  <TableCell sx={{ ...cellSx, color: neon.muted }}>
                    {im.last_seen ? new Date(im.last_seen).toLocaleString() : '—'}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </Section>

      {/* ---- timeline ---- */}
      <Timeline project={project} host={host} canWrite={canWrite(project)} />
    </>
  )
}

export function HostModalProvider({ children }: { children: ReactNode }) {
  const [at, setAt] = useState<{ project: string; host: string } | null>(null)
  const ctx = useMemo<Ctx>(() => ({ open: (project, host) => setAt({ project, host }) }), [])

  return (
    <HostModalCtx.Provider value={ctx}>
      {children}
      <Dialog
        open={!!at} onClose={() => setAt(null)} maxWidth="xl" fullWidth scroll="paper"
        slotProps={{
          paper: {
            sx: {
              backgroundColor: alpha(neon.paper, 0.97),
              backgroundImage: 'none',
              border: `1px solid ${alpha(neon.pink, 0.45)}`,
              boxShadow: `0 0 50px ${alpha(neon.pink, 0.25)}`,
              // XXL: fill the viewport rather than MUI's default max width.
              width: '96vw', maxWidth: '1700px', height: '92vh',
            },
          },
        }}
      >
        <DialogTitle sx={{
          display: 'flex', alignItems: 'center', gap: 1, py: 1.4,
          borderBottom: `1px solid ${alpha(neon.pink, 0.3)}`,
        }}>
          <Typography sx={{
            fontFamily: `'Orbitron', sans-serif`, fontSize: 13, letterSpacing: '0.14em',
            color: neon.cyan, textShadow: glow(neon.cyan, 0.6),
          }}>TARGET</Typography>
          <Box sx={{ flex: 1 }} />
          <IconButton size="small" onClick={() => setAt(null)}
            sx={{ color: neon.muted, '&:hover': { color: neon.pink } }}>
            <CloseIcon fontSize="small" />
          </IconButton>
        </DialogTitle>
        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
        <DialogContent>
          {at && <Body project={at.project} host={at.host} />}
        </DialogContent>
      </Dialog>
    </HostModalCtx.Provider>
  )
}
