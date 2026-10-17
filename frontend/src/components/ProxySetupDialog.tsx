import { useState } from 'react'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, IconButton, Stack, Table, TableBody, TableCell,
  TableRow, Tooltip, Typography, alpha,
} from '@mui/material'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type GhostAgent, type ProxyGrant } from '../lib/api'
import { neon, glow } from '../theme'

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <Tooltip title={done ? 'Copied' : 'Copy'}>
      <IconButton size="small" onClick={() => {
        void navigator.clipboard?.writeText(text)
        setDone(true)
        setTimeout(() => setDone(false), 1200)
      }}>
        <ContentCopyIcon sx={{ fontSize: 14,
          color: done ? neon.green : neon.muted }} />
      </IconButton>
    </Tooltip>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <TableRow>
      <TableCell sx={{ border: 0, py: 0.4, pl: 0, width: 150,
                       color: neon.muted, fontSize: 11.5 }}>{label}</TableCell>
      <TableCell sx={{ border: 0, py: 0.4 }}>
        <Stack direction="row" sx={{ alignItems: 'center' }}>
          <Box component="code" sx={{
            fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12,
            color: neon.cyan, wordBreak: 'break-all',
          }}>{value}</Box>
          <Copy text={value} />
        </Stack>
      </TableCell>
    </TableRow>
  )
}

/**
 * What to do once proxying is on for a Ghost.
 *
 * Opened by the toggle, because the credential is shown exactly once
 * and a dialog that has to be found again afterwards is a dialog
 * whose secret gets written down somewhere worse.
 *
 * The browser settings and the credential are in one place on
 * purpose: they are useless apart, and an operator copying four
 * fields out of a README into a proxy dialog is how the DNS tickbox
 * gets missed.
 */
export function ProxySetupDialog({ project, agent, host, onClose }: {
  project: string
  agent: GhostAgent
  /** Where Oddjob is reachable, for the tunnel instruction. */
  host: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [fresh, setFresh] = useState<{ username: string; password: string } | null>(null)

  const grants = useQuery({
    queryKey: ['proxy-grants', project, agent.id],
    queryFn: () => api.proxyGrants(project, agent.id),
  })

  const make = useMutation({
    mutationFn: () => api.newProxyGrant(project, agent.id, { expires_days: 14 }),
    onSuccess: (r) => {
      setFresh({ username: r.username, password: r.password })
      void qc.invalidateQueries({ queryKey: ['proxy-grants', project, agent.id] })
    },
  })

  const revoke = useMutation({
    mutationFn: (id: number) => api.revokeProxyGrant(project, agent.id, id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['proxy-grants', project, agent.id] })
    },
  })

  const live = (grants.data ?? []).filter((g) => !g.revoked_at)

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.4)}`,
      } } }}>
      <DialogTitle sx={{
        fontFamily: `'Orbitron', sans-serif`, fontSize: 12.5,
        letterSpacing: '0.16em', textTransform: 'uppercase',
        color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
        borderBottom: `1px solid ${alpha(neon.cyan, 0.22)}`, py: 1.4,
      }}>
        Browse through {agent.name}
      </DialogTitle>

      <DialogContent sx={{ pt: 2.5 }}>
        <Typography sx={{ fontSize: 12.5, color: neon.text, mb: 2 }}>
          Your browser talks SOCKS5 to Oddjob; Oddjob hands the stream to
          this Ghost over the tunnel it already holds open, and the Ghost
          makes the connection. Requests arrive <b>from inside the estate</b>,
          at the address the client already sees you at.
        </Typography>

        {!agent.proxy_connected && (
          <Alert severity="warning" variant="outlined"
            sx={{ mb: 2, fontSize: 12 }}>
            This Ghost has not opened its tunnel yet. It dials out on its
            own and usually appears within a minute; until it does,
            connections are answered <b>network-unreachable</b> rather than
            refused — the credential is fine, the Ghost is simply not here.
          </Alert>
        )}

        <Typography sx={{ fontSize: 11, letterSpacing: '0.12em',
                          textTransform: 'uppercase', color: neon.cyan,
                          fontFamily: `'Orbitron', sans-serif`, mb: 0.5 }}>
          1 · Reach the listener
        </Typography>
        <Typography sx={{ fontSize: 12, color: neon.muted, mb: 1 }}>
          It binds loopback on the Oddjob host, which is useless from
          anywhere else — on purpose. Tunnel to it:
        </Typography>
        <Box component="pre" sx={{
          m: 0, mb: 2, p: 1.2, fontSize: 11.5,
          fontFamily: 'ui-monospace, Menlo, monospace', color: neon.green,
          backgroundColor: alpha(neon.green, 0.06),
          border: `1px solid ${alpha(neon.green, 0.25)}`, borderRadius: 1,
          overflowX: 'auto',
        }}>{`ssh -N -L 8443:127.0.0.1:8443 ${host}`}</Box>

        <Typography sx={{ fontSize: 11, letterSpacing: '0.12em',
                          textTransform: 'uppercase', color: neon.cyan,
                          fontFamily: `'Orbitron', sans-serif`, mb: 0.5 }}>
          2 · Firefox → Settings → Network Settings → Manual proxy
        </Typography>
        <Table size="small" sx={{ mb: 1 }}>
          <TableBody>
            <Field label="SOCKS Host" value="127.0.0.1" />
            <Field label="Port" value="8443" />
            <TableRow>
              <TableCell sx={{ border: 0, py: 0.4, pl: 0, color: neon.muted,
                               fontSize: 11.5 }}>Version</TableCell>
              <TableCell sx={{ border: 0, py: 0.4, color: neon.text,
                               fontSize: 12 }}>SOCKS v5</TableCell>
            </TableRow>
          </TableBody>
        </Table>
        {/* The one setting people miss, and the one that decides
            whether the gate sees the name you typed. */}
        <Alert severity="info" variant="outlined" sx={{ mb: 2, fontSize: 12 }}>
          <b>Tick “Proxy DNS when using SOCKS v5”.</b> Without it Firefox
          resolves the name on <i>your</i> machine and sends an address —
          which defeats the point, because split-horizon DNS inside an
          estate is normal and the Ghost should resolve it where it sits.
          It is also the name the scope gate rules on.
          <Box sx={{ mt: 0.8, fontFamily: 'ui-monospace, Menlo, monospace',
                     fontSize: 11 }}>
            curl: use <b>socks5h://</b>, not socks5:// — the h is what makes
            the far end resolve.
          </Box>
        </Alert>

        <Divider sx={{ my: 2, borderColor: alpha(neon.cyan, 0.2) }} />

        <Typography sx={{ fontSize: 11, letterSpacing: '0.12em',
                          textTransform: 'uppercase', color: neon.cyan,
                          fontFamily: `'Orbitron', sans-serif`, mb: 1 }}>
          3 · Credential
        </Typography>

        {fresh ? (
          <>
            <Alert severity="success" variant="outlined"
              sx={{ mb: 1, fontSize: 12 }}>
              Shown <b>once</b>. Only a hash is stored — if you lose it,
              make another and revoke this one.
            </Alert>
            <Table size="small">
              <TableBody>
                <Field label="Username" value={fresh.username} />
                <Field label="Password" value={fresh.password} />
              </TableBody>
            </Table>
          </>
        ) : (
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
            <Button size="small" variant="outlined"
              disabled={make.isPending}
              onClick={() => make.mutate()}
              sx={{ fontSize: 11, color: neon.green,
                    borderColor: alpha(neon.green, 0.5) }}>
              {make.isPending ? 'Issuing…' : 'Issue a credential'}
            </Button>
            <Typography sx={{ fontSize: 11.5, color: neon.muted }}>
              Expires in 14 days. Bound to this Ghost only.
            </Typography>
          </Stack>
        )}

        {make.error && (
          <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 12 }}>
            {(make.error as Error).message}
          </Alert>
        )}

        {live.length > 0 && (
          <Box sx={{ mt: 2 }}>
            <Typography sx={{ fontSize: 11, color: neon.muted, mb: 0.5 }}>
              Live credentials for this Ghost
            </Typography>
            {live.map((g: ProxyGrant) => (
              <Stack key={g.id} direction="row" spacing={1}
                sx={{ alignItems: 'center', py: 0.3 }}>
                <Box component="code" sx={{
                  fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 11.5,
                  color: neon.text, flex: 1,
                }}>{g.username}</Box>
                {g.last_used_at
                  ? <Chip size="small" label="used" variant="outlined"
                      sx={{ height: 18, fontSize: 10, color: neon.yellow,
                            borderColor: alpha(neon.yellow, 0.4) }} />
                  : <Chip size="small" label="never used" variant="outlined"
                      sx={{ height: 18, fontSize: 10, color: neon.muted,
                            borderColor: alpha(neon.muted, 0.3) }} />}
                <Button size="small" disabled={revoke.isPending}
                  onClick={() => revoke.mutate(g.id)}
                  sx={{ fontSize: 10.5, color: neon.red }}>
                  Revoke
                </Button>
              </Stack>
            ))}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ borderTop: `1px solid ${alpha(neon.cyan, 0.18)}` }}>
        <Button onClick={onClose} sx={{ color: neon.cyan, fontSize: 11.5 }}>
          Done
        </Button>
      </DialogActions>
    </Dialog>
  )
}
