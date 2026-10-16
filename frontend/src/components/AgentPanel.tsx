import { useEffect, useRef, useState } from 'react'
import {
  Alert, Box, Chip, CircularProgress, Collapse, Drawer, IconButton, Stack,
  TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import SendIcon from '@mui/icons-material/Send'
import BuildIcon from '@mui/icons-material/BuildCircle'
import DeleteSweepIcon from '@mui/icons-material/DeleteSweep'
import { useQuery } from '@tanstack/react-query'
import { api, type AgentStep } from '../lib/api'
import { SlackHandlePrompt } from './SlackHandlePrompt'
import { neon, glow } from '../theme'

/**
 * A chat about the open engagement, docked to the right.
 *
 * The transcript lives here rather than on the server: it is already in
 * front of the person who owns it, and a server-side session store would
 * be a second place for engagement data to sit and a second thing to
 * expire. The provider-shaped `history` the API returns is passed straight
 * back on the next turn, so neither side has to model the conversation.
 *
 * Tool calls are shown, not hidden. An agent that says "I found three
 * criticals" is only worth anything if you can see which query it ran.
 */

interface Turn {
  role: 'user' | 'agent'
  text: string
  steps?: AgentStep[]
  error?: string
}

export function AgentPanel({ project, open, onClose }: {
  project: string | null; open: boolean; onClose: () => void
}) {
  const [turns, setTurns] = useState<Turn[]>([])
  const [history, setHistory] = useState<unknown[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  const status = useQuery({
    queryKey: ['agent-status', project],
    queryFn: () => api.agentStatus(project!),
    enabled: open && !!project,
  })

  // A new engagement is a new conversation; carrying one project's
  // transcript into another would feed it the wrong context entirely.
  useEffect(() => { setTurns([]); setHistory([]) }, [project])
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) },
            [turns, busy])

  const send = async () => {
    const msg = input.trim()
    if (!msg || !project || busy) return
    setInput('')
    setTurns((t) => [...t, { role: 'user', text: msg }])
    setBusy(true)
    try {
      const r = await api.agentChat(project, msg, history)
      setHistory(r.history)
      setTurns((t) => [...t, { role: 'agent', text: r.text, steps: r.steps }])
    } catch (e) {
      setTurns((t) => [...t, { role: 'agent', text: '',
                               error: e instanceof Error ? e.message : String(e) }])
    } finally { setBusy(false) }
  }

  const s = status.data

  return (
    <>
      {/* Not the agent's business, but this is the one component App
          renders for every signed-in view with the open engagement already
          in hand — so it is where a once-per-engagement prompt can live
          without being repeated in eight views and still missing the
          ninth. It renders its own dialog or nothing; the panel below is
          unaffected either way. */}
      <SlackHandlePrompt project={project} />
      <Drawer anchor="right" open={open} onClose={onClose} variant="persistent"
        slotProps={{ paper: { sx: {
          width: { xs: '100vw', sm: 420, md: 480 },
          backgroundColor: alpha(neon.bgDeep, 0.97), backgroundImage: 'none',
          borderLeft: `1px solid ${alpha(neon.cyan, 0.35)}`,
          boxShadow: `-16px 0 44px ${alpha('#000', 0.5)}`,
        } } }}>
        <Stack sx={{ height: '100%' }}>
          {/* header */}
          <Stack direction="row" spacing={1} alignItems="center" sx={{
            px: 1.5, py: 1, borderBottom: `1px solid ${alpha(neon.cyan, 0.25)}` }}>
            <Typography sx={{
              fontFamily: `'Orbitron', sans-serif`, fontSize: 11.5,
              letterSpacing: '0.16em', color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
            }}>AGENT</Typography>
            {project && <Chip size="small" label={project} sx={{
              height: 18, fontSize: 10, bgcolor: alpha(neon.pink, 0.14),
              color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.45)}` }} />}
            <Box sx={{ flex: 1 }} />
            {turns.length > 0 && (
              <Tooltip title="Clear the conversation">
                <IconButton size="small" onClick={() => { setTurns([]); setHistory([]) }}
                  sx={{ color: neon.muted }}>
                  <DeleteSweepIcon sx={{ fontSize: 17 }} />
                </IconButton>
              </Tooltip>
            )}
            <IconButton size="small" onClick={onClose} sx={{ color: neon.muted }}>
              <CloseIcon sx={{ fontSize: 17 }} />
            </IconButton>
          </Stack>

          {/* provider line */}
          {s && (
            <Stack direction="row" spacing={0.8} alignItems="center" flexWrap="wrap"
              useFlexGap sx={{ px: 1.5, py: 0.8,
                               borderBottom: `1px solid ${alpha(neon.purple, 0.18)}` }}>
              <Chip size="small" label={s.provider} sx={tag(neon.cyan)} />
              <Chip size="small" label={s.model} sx={tag(neon.purple)} />
              {s.endpoint
                ? <Tooltip title={`The Oddjob server calls ${s.endpoint}`}>
                    <Chip size="small" label="local" sx={tag(neon.yellow)} />
                  </Tooltip>
                : <Chip size="small" label={`creds: ${s.source}`} sx={tag(neon.muted)} />}
              {/* The kind matters: an OAuth token from `claude setup-token`
                  and an API key go on different headers. */}
              <Chip size="small" label={s.token_kind} sx={tag(
                s.token_kind === 'not set' ? neon.red : neon.green)} />
              <Chip size="small" label={s.allow_writes ? 'can write' : 'read-only'}
                    sx={tag(s.allow_writes ? neon.orange : neon.muted)} />
              <Tooltip title={s.tools.join(', ')}>
                <Chip size="small" label={`${s.tools.length} tools`} sx={tag(neon.green)} />
              </Tooltip>
            </Stack>
          )}

          {/* body */}
          <Box sx={{ flex: 1, overflow: 'auto', px: 1.5, py: 1.5 }}>
            {!project && (
              <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
                Choose an engagement in the header — the agent works on one
                project at a time, and cannot reach the others.
              </Alert>
            )}
            {project && s && !s.configured && (
              <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
                {s.detail}
              </Alert>
            )}
            {project && s?.configured && turns.length === 0 && (
              <Box sx={{ color: alpha(neon.muted, 0.9), fontSize: 12.5, lineHeight: 1.7 }}>
                <Typography sx={{ fontSize: 12.5, mb: 1 }}>
                  Ask about this engagement. The agent reads the data through
                  tools — it knows nothing else about it.
                </Typography>
                {['What are the critical findings?',
                  'Which open ports could not be identified?',
                  'Summarise what we know about the compromised hosts.',
                  'Suggest subdomains worth trying under the main domain.',
                ].map((q) => (
                  <Box key={q} onClick={() => setInput(q)} sx={{
                    mt: 0.8, px: 1.2, py: 0.8, borderRadius: 1, cursor: 'pointer',
                    border: `1px solid ${alpha(neon.purple, 0.3)}`,
                    '&:hover': { borderColor: neon.cyan, color: neon.cyan },
                  }}>{q}</Box>
                ))}
              </Box>
            )}

            {turns.map((t, i) => <TurnBlock key={i} t={t} />)}
            {busy && (
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1.5 }}>
                <CircularProgress size={13} sx={{ color: neon.cyan }} />
                <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>thinking…</Typography>
              </Stack>
            )}
            <div ref={endRef} />
          </Box>

          {/* composer */}
          <Box sx={{ p: 1.2, borderTop: `1px solid ${alpha(neon.cyan, 0.25)}` }}>
            <Stack direction="row" spacing={1} alignItems="flex-end">
              <TextField
                fullWidth size="small" multiline maxRows={6} value={input}
                disabled={!project || !s?.configured || busy}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  // Enter sends; Shift+Enter is a newline. A chat box that
                  // needs a mouse to send is a chat box nobody uses.
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
                }}
                placeholder={s?.configured ? 'Ask about this engagement…'
                                           : 'No agent token configured'}
                slotProps={{ htmlInput: { style: { fontSize: 12.5 } } }} />
              <IconButton size="small" onClick={send}
                disabled={!input.trim() || busy || !s?.configured}
                sx={{ mb: 0.3, color: neon.cyan,
                      '&.Mui-disabled': { color: alpha(neon.muted, 0.35) } }}>
                <SendIcon sx={{ fontSize: 19 }} />
              </IconButton>
            </Stack>
          </Box>
        </Stack>
      </Drawer>
    </>
  )
}

function TurnBlock({ t }: { t: Turn }) {
  if (t.role === 'user') {
    return (
      <Box sx={{
        mt: 1.5, ml: 4, p: 1.2, borderRadius: 1.5,
        background: alpha(neon.pink, 0.1),
        border: `1px solid ${alpha(neon.pink, 0.35)}`,
        fontSize: 12.5, whiteSpace: 'pre-wrap', color: neon.text,
      }}>{t.text}</Box>
    )
  }
  return (
    <Box sx={{ mt: 1.5, mr: 2 }}>
      {t.steps?.filter((s) => s.kind === 'tool').map((s, i) => (
        <ToolCall key={i} step={s} />
      ))}
      {t.error
        ? <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>{t.error}</Alert>
        : <Box sx={{ p: 1.2, borderRadius: 1.5,
                     background: alpha(neon.cyan, 0.06),
                     border: `1px solid ${alpha(neon.cyan, 0.28)}`,
                     fontSize: 12.5, lineHeight: 1.65, whiteSpace: 'pre-wrap',
                     color: neon.text }}>
            {t.text || '(no answer)'}
          </Box>}
    </Box>
  )
}

function ToolCall({ step }: { step: AgentStep }) {
  const [open, setOpen] = useState(false)
  return (
    <Box sx={{ mb: 0.6 }}>
      <Stack direction="row" spacing={0.6} alignItems="center"
        onClick={() => setOpen(!open)}
        sx={{ cursor: 'pointer', color: alpha(neon.green, 0.9),
              '&:hover': { color: neon.green } }}>
        <BuildIcon sx={{ fontSize: 13 }} />
        <Typography sx={{ fontSize: 10.5, fontFamily: `'Share Tech Mono', monospace` }}>
          {step.tool}({Object.entries(step.args || {})
            .map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})
        </Typography>
      </Stack>
      <Collapse in={open} unmountOnExit>
        <Box sx={{
          mt: 0.4, p: 1, borderRadius: 1, maxHeight: 260, overflow: 'auto',
          background: alpha(neon.bgDeep, 0.8),
          border: `1px solid ${alpha(neon.green, 0.22)}`,
          fontFamily: `'Share Tech Mono', monospace`, fontSize: 10.5,
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          color: alpha(neon.text, 0.85),
        }}>{step.result}</Box>
      </Collapse>
    </Box>
  )
}

const tag = (c: string) => ({
  height: 17, fontSize: 9.5, bgcolor: alpha(c, 0.14), color: c,
  border: `1px solid ${alpha(c, 0.4)}`,
})
