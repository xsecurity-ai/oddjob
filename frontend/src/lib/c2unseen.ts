/**
 * Which shell sessions have said something nobody has read yet.
 *
 * A module-level store rather than a context or a query: the events
 * arrive in `useLive`, which is mounted in App, and are read both by
 * the C2 nav item and by the session list inside C2View. Threading
 * them down through the view tree would mean App re-rendering every
 * grid on every byte a shell prints, and a shell printing bytes is
 * the normal case.
 *
 * Keyed by project as well as id. An operator can read several
 * engagements; a C2 tab blinking for a session that belongs to a
 * project you are not looking at is a tab you click and find nothing
 * on.
 */
import { useSyncExternalStore } from 'react'

/** `project` and `id` together, because an id alone is only unique
 *  within one installation's database and the set holds several
 *  engagements at once. NUL is not legal in a project code. */
export const key = (project: string, id: number) => `${project}\u0000${id}`

let unseen: ReadonlySet<string> = new Set()
let reading: string | null = null
const listeners = new Set<() => void>()

function emit(next: ReadonlySet<string>): void {
  unseen = next
  for (const l of listeners) l()
}

function subscribe(l: () => void): () => void {
  listeners.add(l)
  return () => { listeners.delete(l) }
}

/**
 * New output, or a new callback, on a session.
 *
 * Ignored for the session on screen: blinking at output that is
 * already being read is how an operator learns to stop looking at the
 * blink, and then the one that matters goes unnoticed too.
 */
export function sessionSpoke(project: string, id: number): void {
  const k = key(project, id)
  if (k === reading || unseen.has(k)) return
  const next = new Set(unseen)
  next.add(k)
  emit(next)
}

/**
 * Which session is on screen, or null when the page is not.
 *
 * Opening one clears it. C2View clears this on unmount, which is what
 * makes output arriving after you navigate away start blinking again.
 */
export function readingSession(project: string, id: number | null): void {
  const k = id === null ? null : key(project, id)
  reading = k
  if (k === null || !unseen.has(k)) return
  const next = new Set(unseen)
  next.delete(k)
  emit(next)
}

/** The whole set, as it stands. Stable between changes, which is what
 *  `useSyncExternalStore` needs -- a filtered copy per call would be a
 *  new object every render and loop forever. */
export function snapshot(): ReadonlySet<string> {
  return unseen
}

/** Whether anything on this engagement is unread. */
export function anyUnseen(project: string | null): boolean {
  if (project === null) return false
  const prefix = `${project}\u0000`
  for (const k of unseen) if (k.startsWith(prefix)) return true
  return false
}

export function useUnseenSessions(): ReadonlySet<string> {
  return useSyncExternalStore(subscribe, snapshot)
}

export function useAnyUnseen(project: string | null): boolean {
  // A boolean, so recomputing it per call is safe -- the identity
  // rule only bites on objects.
  return useSyncExternalStore(subscribe, () => anyUnseen(project))
}

/** Test seam. Nothing in the app calls this -- the store is a
 *  singleton and a suite that cannot reset it can only run once. */
export function reset(): void {
  reading = null
  emit(new Set())
}
