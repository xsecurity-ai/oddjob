/**
 * A real terminal on a live shell.
 *
 * The transcript beside this is the engagement record — command
 * and output paired, attributed to whoever typed it. This is the
 * other thing an operator needs: a screen that behaves like a
 * terminal, so `Ctrl-C` interrupts, `vim` paints, colours are
 * colours and not `ESC[0;31m`.
 *
 * **Keystrokes, not lines.** The line-based input could not send
 * Ctrl-C at all — there is no line to end — and a full-screen
 * program reads single keys. So this streams bytes over a
 * websocket as they are typed, and the server records them
 * buffered into lines so the record still says who ran what.
 *
 * Nothing here is the record. If this disagrees with the
 * transcript, the transcript is right: it is written from the
 * bytes the Ghost relayed, where this is a rendering of them in a
 * browser that may have been opened late.
 */
import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Chip, Stack, Typography, alpha } from '@mui/material'
import { FitAddon } from '@xterm/addon-fit'
import { Terminal as XTerm } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import type { C2Session } from '../lib/api'
import { neon } from '../theme'

type State = 'connecting' | 'live' | 'closed'

export function LiveTerminal({ project, session }: {
  project: string
  session: C2Session
}) {
  const host = useRef<HTMLDivElement | null>(null)
  const [state, setState] = useState<State>('connecting')
  const [why, setWhy] = useState<string | null>(null)

  useEffect(() => {
    if (!host.current) return
    const term = new XTerm({
      // LF is treated as CRLF.
      //
      // A shell WITHOUT a pty -- `nc -e /bin/sh`, which is the
      // commonest callback there is -- ends its lines with a bare
      // \n. A terminal takes that as "down one row" and not "back
      // to column one", so every line starts where the last one
      // ended and the output walks off the right of the screen:
      //
      //     uname -a
      //             Darwin Mac.lan 25.6.0 ...
      //                                      sh-3.2$
      //
      // Harmless for a pty, which sends \r\n: the \r returns to
      // column one and the converted \n returns to a column it is
      // already in.
      convertEol: true,
      cursorBlink: true,
      fontFamily: "'Share Tech Mono', ui-monospace, monospace",
      fontSize: 12.5,
      theme: {
        background: '#00000059',
        foreground: neon.text,
        cursor: neon.cyan,
      },
      // The shell on the far end does not know how big this is and
      // mostly does not care; 1000 lines of scrollback is what a
      // person reaches back through before giving up and reading
      // the transcript instead.
      scrollback: 1000,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host.current)
    fit.fit()

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(
      `${proto}//${window.location.host}/api/c2/sessions/${session.id}`
      + `/ws?project=${encodeURIComponent(project)}`)
    ws.binaryType = 'arraybuffer'

    ws.onopen = () => { setState('live'); term.focus() }
    ws.onmessage = (e) => {
      term.write(new Uint8Array(e.data as ArrayBuffer))
    }
    ws.onclose = (e) => {
      setState('closed')
      // 1008 is what the server closes with when it refuses:
      // not signed in, no write access, no such session here.
      if (e.reason) setWhy(e.reason)
    }
    ws.onerror = () => setState('closed')

    const typed = term.onData((data) => {
      if (ws.readyState !== WebSocket.OPEN) return
      ws.send(new TextEncoder().encode(data))
    })

    const onResize = () => { try { fit.fit() } catch { /* detached */ } }
    window.addEventListener('resize', onResize)
    // The pane can change size without the window doing so — the
    // session list collapsing, a tab switching — and a terminal
    // sized to the wrong width wraps every line in the wrong place.
    const ro = new ResizeObserver(onResize)
    ro.observe(host.current)

    return () => {
      typed.dispose()
      ro.disconnect()
      window.removeEventListener('resize', onResize)
      ws.close()
      term.dispose()
    }
  }, [project, session.id])

  const live = session.state === 'open' && session.connected

  return (
    <Stack sx={{ flex: 1, minWidth: 0, minHeight: 0 }}>
      <Stack direction="row" spacing={1}
        sx={{ alignItems: 'center', px: 2, py: 1,
              borderBottom: `1px solid ${alpha(neon.purple, 0.2)}` }}>
        <Typography sx={{ fontSize: 11, color: neon.muted }}>
          live terminal
        </Typography>
        <Chip size="small"
          label={state === 'live' ? 'connected'
            : state === 'connecting' ? 'connecting…' : 'disconnected'}
          sx={{ height: 17, fontSize: 9.5,
                color: state === 'live' ? neon.green : neon.yellow,
                border: `1px solid ${alpha(
                  state === 'live' ? neon.green : neon.yellow, 0.45)}` }} />
        <Box sx={{ flex: 1 }} />
        <Typography sx={{ fontSize: 10, color: neon.muted }}>
          keystrokes go straight through — Ctrl-C works
        </Typography>
      </Stack>

      {!live && (
        <Alert severity="info" variant="outlined"
          sx={{ m: 1.5, mb: 0, fontSize: 11.5 }}>
          This session is {session.state}
          {session.state === 'open' ? ' but not reachable from here' : ''}.
          What was done on it is in the Transcript tab; there is nothing
          to type at.
        </Alert>
      )}
      {why && (
        <Alert severity="warning" variant="outlined"
          sx={{ m: 1.5, mb: 0, fontSize: 11.5 }}>{why}</Alert>
      )}

      <Box ref={host} sx={{
        flex: 1, minHeight: 0, m: 1.5, p: 1,
        border: `1px solid ${alpha(neon.cyan, 0.22)}`,
        borderRadius: 1, bgcolor: alpha('#000', 0.35),
        '& .xterm': { height: '100%' },
      }} />
    </Stack>
  )
}
