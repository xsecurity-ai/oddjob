import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'

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

export function useLive(enabled: boolean): LiveState {
  const qc = useQueryClient()
  const [state, setState] = useState<LiveState>('connecting')
  const timer = useRef<number | undefined>(undefined)

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

    const refresh = () => {
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => {
        // Everything derives from the same tables — a new service changes a
        // target's open-port count — so refresh the lot rather than trying to
        // be clever about which grid is affected.
        void qc.invalidateQueries()
      }, COALESCE_MS)
    }

    es.addEventListener('hello', () => setState('live'))
    es.addEventListener('change', refresh)
    es.onopen = () => setState('live')
    es.onerror = () => {
      // EventSource reconnects on its own; just reflect the gap in the UI.
      setState((s) => (s === 'live' ? 'connecting' : 'offline'))
    }

    return () => {
      window.clearTimeout(timer.current)
      es.close()
    }
  }, [qc, enabled])

  return state
}
