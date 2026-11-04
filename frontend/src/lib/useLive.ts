import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { sessionSpoke } from './c2unseen'

export type LiveState = 'connecting' | 'live' | 'offline'

/**
 * Subscribes to the server's SSE change stream and invalidates the React Query
 * cache when anything changes, which is what makes the grids refresh by
 * themselves.
 *
 * Why invalidate rather than push rows down the wire: the event carries no
 * data, only "this kind changed". The client then refetches the authoritative
 * state. That keeps one source of truth and means a missed event is
 * self-healing rather than leaving the grid permanently wrong.
 *
 * Bursty writes — a bulk import publishes one event, but a script firing 50
 * single POSTs publishes 50 — are coalesced on a short timer so the grid
 * refetches once instead of 50 times.
 */
const COALESCE_MS = 250

/**
 * ...but the coalescing timer is reset by every event, so a stream of them
 * arriving closer together than COALESCE_MS never reaches the end of it. A
 * long import publishing steadily would hold the refresh off for the whole
 * import — the grid stops updating exactly while the most is happening, and
 * `refetchOnWindowFocus` is off, so nothing else comes along to fix it.
 *
 * This is the ceiling on that wait: however busy the stream, the grid
 * refreshes at least this often.
 */
const MAX_WAIT_MS = 2_000

/**
 * How long the next refresh should wait, given when the current burst
 * started. 0 means "the ceiling is reached, refresh now".
 *
 * Pulled out of the hook so the starvation case can be tested without a
 * browser: the bug it exists for is invisible in any single call, and only
 * shows up as a sequence of events that each look perfectly reasonable.
 */
export function coalesceDelay(now: number, burstAt: number): number {
  if (!burstAt) return COALESCE_MS
  const waited = now - burstAt
  if (waited >= MAX_WAIT_MS) return 0
  // Never schedule past the ceiling, or the cap is only advisory.
  return Math.min(COALESCE_MS, MAX_WAIT_MS - waited)
}

export function useLive(enabled: boolean): LiveState {
  const qc = useQueryClient()
  const [state, setState] = useState<LiveState>('connecting')
  const timer = useRef<number | undefined>(undefined)
  //: When the current burst began, so the wait can be capped. 0 = no burst.
  const burstAt = useRef(0)
  //: A refresh that was due while the tab was hidden. Refetching into a
  //: document nobody is looking at buys nothing and costs a round trip per
  //: query per event; this remembers that one is owed instead.
  const owed = useRef(false)

  useEffect(() => {
    // Only connect once authenticated. /api/events is behind auth, and an
    // EventSource that receives an HTTP error does NOT retry (unlike a
    // dropped connection) -- so one attempt made while signed out would stay
    // dead for the rest of the session. `enabled` in the dep array is what
    // rebuilds it after login.
    if (!enabled) {
      setState('offline')
      return
    }
    const es = new EventSource('/api/events')

    const fire = () => {
      window.clearTimeout(timer.current)
      timer.current = undefined
      burstAt.current = 0
      if (document.visibilityState === 'hidden') {
        owed.current = true
        return
      }
      owed.current = false
      // Everything derives from the same tables — a new service changes a
      // target's open-port count — so refresh the lot rather than trying to
      // be clever about which grid is affected. Narrowing this by the
      // event's `kind` is the obvious next step and it is the wrong one:
      // the kinds do not partition the grids, so a scoped invalidation
      // leaves a count stale somewhere and looks like a server bug.
      void qc.invalidateQueries()
    }

    const refresh = () => {
      const now = Date.now()
      const delay = coalesceDelay(now, burstAt.current)
      if (!burstAt.current) burstAt.current = now
      if (delay === 0) {
        fire()                      // the burst has had its grace; refresh now
        return
      }
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(fire, delay)
    }

    // Coming back to the tab settles whatever was skipped while it was
    // hidden. Without this the skip above would be a correctness bug
    // rather than an optimisation: `refetchOnWindowFocus` is off, so
    // nothing else would ever refetch.
    const onVisible = () => {
      if (document.visibilityState === 'visible' && owed.current) {
        owed.current = false
        void qc.invalidateQueries()
      }
    }
    document.addEventListener('visibilitychange', onVisible)

    // A shell speaking is the one change that has to be noticed
    // rather than merely refetched: the row it belongs to may be on a
    // page the operator is not looking at. Everything else about the
    // event is still handled by refetching -- this only remembers
    // that the session is unread.
    const note = (e: MessageEvent<string>) => {
      try {
        const m = JSON.parse(e.data) as {
          kind?: string; action?: string; project?: string; session?: number
        }
        if (m.kind !== 'c2' || !m.project || typeof m.session !== 'number') return
        if (m.action === 'arrived' || m.action === 'output') {
          sessionSpoke(m.project, m.session)
        }
      } catch {
        // A payload we cannot read is not worth breaking the stream
        // for; the refetch below still happens.
      }
    }

    es.addEventListener('hello', () => setState('live'))
    es.addEventListener('change', (e) => { note(e); refresh() })
    es.onopen = () => setState('live')
    es.onerror = () => {
      // EventSource reconnects on its own; just reflect the gap in the UI.
      setState((s) => (s === 'live' ? 'connecting' : 'offline'))
    }

    return () => {
      document.removeEventListener('visibilitychange', onVisible)
      window.clearTimeout(timer.current)
      es.close()
    }
  }, [qc, enabled])

  return state
}
