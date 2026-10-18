import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert, Box, Chip, CircularProgress, Collapse, Drawer, IconButton, Stack,
  Tab, Tabs, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import SendIcon from '@mui/icons-material/Send'
import BuildIcon from '@mui/icons-material/BuildCircle'
import AddIcon from '@mui/icons-material/Add'
import OpenInFullIcon from '@mui/icons-material/OpenInFull'
import CloseFullscreenIcon from '@mui/icons-material/CloseFullscreen'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type AgentSessionBrief, type AgentStep } from '../lib/api'
import { SlackHandlePrompt } from './SlackHandlePrompt'
import { useStoredFlag } from '../lib/useStoredFlag'
import { neon, glow, TAB_SX } from '../theme'

/**
 * A chat about the open engagement, docked to the right or filling the
 * window.
 *
 * **The transcript belongs to the ENGAGEMENT, not to this browser.**
 * It used to live here, on the reasoning that it was already in front
 * of the person who owns it. What that missed is that an engagement is
 * worked by several people: "what have we already asked" is a fact
 * about the engagement, and two testers asking the same question — or
 * an answer lost when a tab closes — costs more than the extra store.
 * So the thread is loaded from the server and everyone with a role on
 * the project reads the same one.
 *
 * **The TAB STRIP is the engagement's too.** It lists the project's
 * open threads, not this browser's tabs, for exactly the reason the
 * transcript moved to the server: a question a colleague left running
 * an hour ago should be one you can pick up, not one you cannot see.
 * The consequence is deliberate and is stated in the UI — closing a
 * tab closes that thread for everyone on the project. It is closed,
 * never deleted; what was asked during an engagement is part of the
 * engagement.
 *
 * Switching project lands on THAT project's threads, or none.
 * Carrying a conversation across would feed the agent the wrong
 * context and put two clients' data in one scroll-back.
 *
 * **Every open thread stays mounted**, hidden rather than unmounted,
 * which is what makes a tab switch free: the half-typed question, the
 * scroll position and a question still in flight all belong to their
 * own `AgentThread` and survive both switching tabs and popping the
 * window out. Unmounting the inactive ones would save a little memory
 * and throw away a draft, which is the wrong trade for six threads.
 *
 * A credential is never in it: the one tool that returns one has its
 * result replaced before the turn is stored. See routers/agent.py.
 *
 * Tool calls are shown, not hidden. An agent that says "I found three
 * criticals" is only worth anything if you can see which query it ran.
 */

interface Turn {
  role: 'user' | 'agent'
  text: string
  steps?: AgentStep[]
  error?: string
  /** Who asked, when it was not you. Only set for turns loaded from
   *  the shared thread — the point of sharing it is knowing which of
   *  you already asked. */
  author?: string | null
}

/** Widest the conversation is allowed to get when popped out.
 *
 *  Full screen is for reading a long answer with its tool output open,
 *  not for a 2560px line of prose: past roughly 90 characters the eye
 *  loses the start of the next line. The window grows; the column does
 *  not. */
const READING_WIDTH = 920

export function AgentPanel({ project, open, onClose }: {
  project: string | null; open: boolean; onClose: () => void
}) {
  const qc = useQueryClient()
  // Popped out or docked, remembered per device. Whoever reads long
  // answers full-screen reads the next one that way too, and having
  // to say so on every page load is the kind of friction that makes
  // the feature not get used.
  const [full, toggleFull] = useStoredFlag('oddjob.agent.fullscreen', false)
  const [active, setActive] = useState<number | null>(null)

  const status = useQuery({
    queryKey: ['agent-status', project],
    queryFn: () => api.agentStatus(project!),
    enabled: open && !!project,
  })

  // The engagement's open threads, not this tab's. Keyed on the
  // project so switching lands on that project's conversations rather
  // than carrying one client's into another's view.
  const sessions = useQuery({
    queryKey: ['agent-sessions', project],
    queryFn: () => api.agentSessions(project!),
    enabled: open && !!project,
  })
  const list = useMemo<AgentSessionBrief[]>(
    () => sessions.data ?? [], [sessions.data])

  const fresh = useMutation({
    mutationFn: () => api.newAgentSession(project!, false),
    onSuccess: (sess) => {
      // Alongside, not instead of: `close_current=false`. A second
      // question is a second thread, and the one already open may be
      // somebody else's.
      qc.setQueryData(['agent-session', project, sess.id], sess)
      void qc.invalidateQueries({ queryKey: ['agent-sessions', project] })
      setActive(sess.id)
    },
  })

  const shut = useMutation({
    mutationFn: (id: number) => api.closeAgentSession(project!, id),
    onSuccess: (brief) => {
      qc.removeQueries({ queryKey: ['agent-session', project, brief.id] })
      void qc.invalidateQueries({ queryKey: ['agent-sessions', project] })
      // Null rather than a guess at the neighbour: the effect below
      // settles on whichever thread the refreshed list puts first.
      setActive((cur) => (cur === brief.id ? null : cur))
    },
  })

  // A stale selection must not survive a project change even for the
  // moment before the new list lands — an id from one engagement can
  // never address a thread in another.
  useEffect(() => { setActive(null) }, [project])

  // Keep the selection on a thread that still exists. Newest first,
  // so a panel opened cold lands on the most recent conversation.
  useEffect(() => {
    if (!list.length) { setActive((cur) => (cur === null ? cur : null)); return }
    setActive((cur) => (cur !== null && list.some((s) => s.id === cur)
                        ? cur : list[0].id))
  }, [list])

  const s = status.data
  const configured = !!s?.configured

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
          // Popped out is the same Drawer at full width, deliberately:
          // swapping to a Dialog would remount everything below and
          // discard the drafts and in-flight questions that the whole
          // mounted-but-hidden arrangement exists to keep.
          width: full ? '100vw' : { xs: '100vw', sm: 420, md: 480 },
          backgroundColor: alpha(neon.bgDeep, 0.97), backgroundImage: 'none',
          borderLeft: `1px solid ${alpha(neon.cyan, 0.35)}`,
          boxShadow: `-16px 0 44px ${alpha('#000', 0.5)}`,
        } } }}>
        <Stack sx={{ height: '100%' }}>
          {/* header */}
          <Stack
            direction="row"
            spacing={1}
            sx={{
              alignItems: "center",
              px: 1.5,
              py: 1,
              borderBottom: `1px solid ${alpha(neon.cyan, 0.25)}`
            }}>
            <Typography sx={{
              fontFamily: `'Orbitron', sans-serif`, fontSize: 11.5,
              letterSpacing: '0.16em', color: neon.cyan, textShadow: glow(neon.cyan, 0.5),
            }}>AGENT</Typography>
            {project && <Chip size="small" label={project} sx={{
              height: 18, fontSize: 10, bgcolor: alpha(neon.pink, 0.14),
              color: neon.pink, border: `1px solid ${alpha(neon.pink, 0.45)}` }} />}
            <Box sx={{ flex: 1 }} />
            {/* Opens a thread beside the others rather than replacing
                the one in front of you. The conversation is the
                engagement's and somebody else may be mid-question in
                it, so ending theirs to start yours is not a thing a
                "new chat" button should do. */}
            {project && (
              <Tooltip title="Start another conversation. The ones already
                              open stay open — they belong to the
                              engagement, and others on it may be using
                              them.">
                <span>
                  <IconButton size="small" disabled={fresh.isPending}
                    onClick={() => fresh.mutate()}
                    sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
                    <AddIcon sx={{ fontSize: 18 }} />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            <Tooltip title={full ? 'Dock the agent back to the side'
                                 : 'Pop the agent out to the full window'}>
              <IconButton size="small" onClick={toggleFull}
                sx={{ color: full ? neon.cyan : neon.muted,
                      '&:hover': { color: neon.cyan } }}>
                {full ? <CloseFullscreenIcon sx={{ fontSize: 15 }} />
                      : <OpenInFullIcon sx={{ fontSize: 15 }} />}
              </IconButton>
            </Tooltip>
            <IconButton size="small" onClick={onClose} sx={{ color: neon.muted }}>
              <CloseIcon sx={{ fontSize: 17 }} />
            </IconButton>
          </Stack>

          {/* provider line */}
          {s && (
            <Stack
              direction="row"
              spacing={0.8}
              useFlexGap
              sx={{
                alignItems: "center",
                flexWrap: "wrap",
                px: 1.5,
                py: 0.8,
                borderBottom: `1px solid ${alpha(neon.purple, 0.18)}`
              }}>
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

          {/* One tab per OPEN thread on the engagement. A single
              thread gets no strip: a tab bar with one tab in it is
              chrome that explains nothing. */}
          {list.length > 1 && (
            <Tabs value={active ?? false} variant="scrollable"
              scrollButtons="auto" allowScrollButtonsMobile
              onChange={(_, v: number) => setActive(v)}
              sx={{ minHeight: 34, borderBottom: `1px solid ${alpha(neon.cyan, 0.2)}`,
                    '& .MuiTabs-indicator': { backgroundColor: neon.cyan } }}>
              {list.map((t) => (
                <Tab key={t.id} value={t.id}
                  sx={{ ...TAB_SX, minWidth: 0, maxWidth: 220, pr: 0.5 }}
                  label={
                    <Stack direction="row" spacing={0.5}
                      sx={{ alignItems: 'center', minWidth: 0 }}>
                      <Tooltip title={threadTooltip(t)}>
                        <Box component="span" sx={{
                          maxWidth: 150, overflow: 'hidden',
                          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>{threadLabel(t)}</Box>
                      </Tooltip>
                      {/* A span, not a button: a Tab is already a
                          button and nesting one inside it is invalid
                          markup that browsers resolve by unnesting it. */}
                      <Tooltip title="Close this conversation. It closes for
                                      everyone on the engagement — it is the
                                      engagement's, not your tab — and it is
                                      kept, not deleted.">
                        <Box component="span" role="button" aria-label="Close thread"
                          onClick={(e) => { e.stopPropagation(); shut.mutate(t.id) }}
                          sx={{ display: 'flex', alignItems: 'center',
                                borderRadius: '50%', p: 0.2, color: alpha(neon.muted, 0.8),
                                '&:hover': { color: neon.pink } }}>
                          <CloseIcon sx={{ fontSize: 13 }} />
                        </Box>
                      </Tooltip>
                    </Stack>
                  } />
              ))}
            </Tabs>
          )}

          {/* body — one per open thread, only one of them visible */}
          {!project && (
            <Box sx={{ px: 1.5, py: 1.5 }}>
              <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
                Choose an engagement in the header — the agent works on one
                project at a time, and cannot reach the others.
              </Alert>
            </Box>
          )}
          {project && s && !s.configured && (
            <Box sx={{ px: 1.5, py: 1.5 }}>
              <Alert severity="warning" variant="outlined" sx={{ fontSize: 12 }}>
                {s.detail}
              </Alert>
            </Box>
          )}
          {project && list.map((t) => (
            <AgentThread key={t.id} project={project} thread={t.id}
              configured={configured} active={t.id === active} full={full} />
          ))}
          {/* Nothing has been asked on this project yet. The thread is
              not created on load — a project with no conversation says
              so rather than being given an empty one — so this stands
              in until the first question opens one. */}
          {project && !list.length && (
            <AgentThread key="first" project={project} thread={null}
              configured={configured} active full={full}
              onOpened={() => {
                void qc.invalidateQueries({
                  queryKey: ['agent-sessions', project] })
              }} />
          )}
        </Stack>
      </Drawer>
    </>
  );
}

/** What the tab says. The title is the first question asked, trimmed
 *  by the server; an unused thread has none yet. */
function threadLabel(t: AgentSessionBrief): string {
  return (t.title || '').trim() || 'New thread'
}

function threadTooltip(t: AgentSessionBrief): string {
  const who = t.opened_by ? `opened by ${t.opened_by}` : 'opened by someone since removed'
  const n = t.turn_count === 1 ? '1 message' : `${t.turn_count} messages`
  return `${threadLabel(t)} — ${who}, ${n}`
}

/**
 * One conversation.
 *
 * Mounted for every open thread and hidden when it is not the one in
 * front of you, which is what carries a draft, a scroll position and a
 * question still in flight across a tab switch. A question asked here
 * goes to THIS thread by id: the server's "newest open thread" default
 * is the right answer for a client with no tab strip and the wrong one
 * for a client that has three of them open.
 */
function AgentThread({ project, thread, configured, active, full, onOpened }: {
  project: string
  /** Null before the project has any thread at all; the first question
   *  opens one server-side and reports its id back. */
  thread: number | null
  configured: boolean
  active: boolean
  full: boolean
  onOpened?: (id: number) => void
}) {
  const qc = useQueryClient()
  const [turns, setTurns] = useState<Turn[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  const data = useQuery({
    queryKey: ['agent-session', project, thread],
    queryFn: () => api.agentSession(project, thread ?? undefined),
  })

  useEffect(() => {
    const t = data.data
    if (!t) { setTurns([]); return }
    setTurns(t.turns.map((x) => ({
      role: x.role === 'user' ? 'user' as const : 'agent' as const,
      text: x.text,
      steps: x.steps,
      author: x.role === 'user' ? x.author : null,
    })))
  }, [data.data])

  // Only the visible thread scrolls: `scrollIntoView` on a hidden one
  // does nothing anyway, and `active` is in the deps so the tab you
  // switch TO lands on its last message rather than wherever the
  // re-layout left it.
  useEffect(() => {
    if (active) endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [turns, busy, active])

  const send = async () => {
    const msg = input.trim()
    if (!msg || busy) return
    setInput('')
    setTurns((t) => [...t, { role: 'user', text: msg }])
    setBusy(true)
    try {
      // No history posted: the server reads the engagement's thread.
      // Two people in one conversation would otherwise each rewrite
      // it with their own copy.
      const r = await api.agentChat(project, msg, [], thread ?? undefined)
      setTurns((t) => [...t, { role: 'agent', text: r.text, steps: r.steps }])
      void qc.invalidateQueries({ queryKey: ['agent-session', project, thread] })
      // The first question on a project opens the thread server-side,
      // and the reply is the only place its id appears. Without this
      // the strip would not know a conversation had started.
      if (thread === null && r.session_id) onOpened?.(r.session_id)
    } catch (e) {
      setTurns((t) => [...t, { role: 'agent', text: '',
                               error: e instanceof Error ? e.message : String(e) }])
    } finally { setBusy(false) }
  }

  // The column, not the window. See READING_WIDTH.
  const column = full
    ? { maxWidth: READING_WIDTH, mx: 'auto', width: '100%' }
    : {}

  return (
    <Stack
      // Which thread this is, in the markup. One conversation looks
      // exactly like another once it is hidden, and "is the inactive
      // one still mounted" is the question both the render test and a
      // person with the inspector open are actually asking.
      data-thread={thread ?? 'new'}
      sx={{
        // Hidden, not unmounted: see the panel's docstring. `flex: 1`
        // only applies to the visible one, or several of them would
        // each claim a share of a column they are not in.
        display: active ? 'flex' : 'none',
        flex: active ? 1 : 0, minHeight: 0,
      }}>
      <Box sx={{ flex: 1, overflow: 'auto', px: 1.5, py: 1.5 }}>
        <Box sx={column}>
          {configured && turns.length === 0 && (
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
            <Stack
              direction="row"
              spacing={1}
              sx={{
                alignItems: "center",
                mt: 1.5
              }}>
              <CircularProgress size={13} sx={{ color: neon.cyan }} />
              <Typography sx={{ fontSize: 11.5, color: neon.cyan }}>thinking…</Typography>
            </Stack>
          )}
          <div ref={endRef} />
        </Box>
      </Box>

      {/* composer */}
      <Box sx={{ p: 1.2, borderTop: `1px solid ${alpha(neon.cyan, 0.25)}` }}>
        <Stack direction="row" spacing={1} sx={{
          alignItems: "flex-end", ...column
        }}>
          <TextField
            fullWidth size="small" multiline maxRows={full ? 14 : 6} value={input}
            disabled={!configured || busy}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              // Enter sends; Shift+Enter is a newline. A chat box that
              // needs a mouse to send is a chat box nobody uses.
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send() }
            }}
            placeholder={configured ? 'Ask about this engagement…'
                                    : 'No agent token configured'}
            slotProps={{ htmlInput: { style: { fontSize: 12.5 } } }} />
          <IconButton size="small" onClick={() => { void send() }}
            disabled={!input.trim() || busy || !configured}
            sx={{ mb: 0.3, color: neon.cyan,
                  '&.Mui-disabled': { color: alpha(neon.muted, 0.35) } }}>
            <SendIcon sx={{ fontSize: 19 }} />
          </IconButton>
        </Stack>
      </Box>
    </Stack>
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
      }}>
        {/* Who asked, when it was not you. The point of a shared
            thread is knowing which of you already asked. */}
        {t.author && (
          <Typography component="span" sx={{
            display: 'block', fontSize: 10, letterSpacing: '0.08em',
            color: alpha(neon.pink, 0.8), mb: 0.4,
          }}>{t.author}</Typography>
        )}
        {t.text}
      </Box>
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
      <Stack
        direction="row"
        spacing={0.6}
        onClick={() => setOpen(!open)}
        sx={{
          alignItems: "center",
          cursor: 'pointer',
          color: alpha(neon.green, 0.9),
          '&:hover': { color: neon.green }
        }}>
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
  );
}

const tag = (c: string) => ({
  height: 17, fontSize: 9.5, bgcolor: alpha(c, 0.14), color: c,
  border: `1px solid ${alpha(c, 0.4)}`,
})
