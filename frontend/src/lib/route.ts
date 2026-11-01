import { useEffect, useState } from 'react'

/**
 * The URL is the app's state, not a side effect of it.
 *
 * Two things follow from that, and both were bugs before:
 *
 * **Changing the theme stopped sending you back to Targets.** Switching
 * palettes remounts the tree (see lib/appearance.tsx — `alpha()` cannot
 * take a CSS variable, so the values are recomputed on render), which
 * reset the view held in `useState`. Reading the view from the location
 * instead means a remount re-derives exactly where you were.
 *
 * **A page became a thing you can paste to someone.** `/projects/ACME/
 * targets/web01.corp.com/services/tcp/443` opens that service, and the
 * same URL handed to curl returns the JSON for it — the server
 * redirects non-browser clients to `/api/…` of the same path.
 *
 * Hand-rolled rather than react-router: the shape below is the whole
 * route table, and the History API is three calls. A router would be a
 * dependency and a restructure of App for no behaviour that is missing.
 */

export interface Route {
  /** Which left-nav view is showing. */
  view: View
  /** Project code, or null for "All projects". */
  project: string | null
  /** A target to open the host modal on. */
  host?: string
  /** A service to open, when the path names one. */
  protocol?: string
  port?: number
  /** A finding to open on top of whatever view is showing.
   *
   *  A QUERY parameter where `host` is a path segment, and the split
   *  is not arbitrary. The path names an ASSET -- a host, and under
   *  it a service -- which is a thing this engagement owns a record
   *  of and which the server will redirect a non-browser client to
   *  the JSON for. A finding is not an asset: it is something open
   *  ON TOP of a view, it can be opened from several of them, and
   *  `parts[3]` of a scoped path already means "host" for every view
   *  there is. Spending that slot on a second meaning would make
   *  `/projects/ACME/vulns/1234` ambiguous with a host called 1234.
   *
   *  Presence is the whole signal. There is deliberately no
   *  `modal=true` beside it: a flag saying a modal is open, separate
   *  from the thing it is open on, is a second copy of one fact and
   *  the two can disagree -- `modal=true` with nothing to show is a
   *  state that cannot render. */
  finding?: number
}

/**
 * Every view there is. This is the route table AND the key set of
 * App's `body` map, which is typed `Record<View, ReactNode>` — so a
 * view added to one and not the other does not compile.
 *
 * That coupling is the point. These were two hand-written lists that
 * agreed by memory, and they stopped agreeing: `ghost-debug` shipped
 * in App without being added here, so `parse` did not recognise it,
 * fell through to the default, and reloading `/projects/X/ghost-debug`
 * silently landed you on Targets. The page worked perfectly — it just
 * could not be reloaded, bookmarked or pasted to anyone. Nothing
 * errored, so nothing said so.
 */
export const GLOBAL_VIEWS = ['projects', 'config', 'users', 'profile',
                             'health'] as const

/** Views that live under a project.
 *
 *  `settings` is the project's own configuration — its name, client and
 *  scope lists. Deliberately not called `config`, which is the SITE
 *  screen and is global: `/projects/ACME/config` would read as a
 *  per-project copy of the deployment settings, and `/config` is already
 *  that page. */
export const SCOPED_VIEWS = ['targets', 'services', 'web', 'vulns',
                             'credentials', 'reports', 'ghosts',
                             'ghost-debug', 'import', 'settings',
                             // Shell sessions a Ghost caught. Scoped,
                             // like everything else an engagement owns.
                             'c2',
                             // The agent's conversations filling a page.
                             // Not in the nav: it is reached from the
                             // panel's pop-out, which opens it in a window
                             // of its own. It is a route because a window
                             // needs a URL, and because being one means
                             // the window survives a refresh.
                             'agent'] as const

export type GlobalView = (typeof GLOBAL_VIEWS)[number]
export type ScopedView = (typeof SCOPED_VIEWS)[number]
export type View = GlobalView | ScopedView

const GLOBAL: ReadonlySet<string> = new Set(GLOBAL_VIEWS)
const SCOPED: ReadonlySet<string> = new Set(SCOPED_VIEWS)

function asView(s: string): View | null {
  return GLOBAL.has(s) || SCOPED.has(s) ? (s as View) : null
}

/** Where a bare `/` lands. The project list, not targets-across-
 *  everything: with no project chosen, "which engagement" is the
 *  question, and a grid of 4,600 hosts from nine clients is not an
 *  answer to it. */
export const ROOT_VIEW = 'projects'

/** Where `/projects/ACME` lands — a project's own default view. */
export const DEFAULT_VIEW = 'targets'

function clean(s: string): string {
  return decodeURIComponent(s || '').trim()
}

/**
 * `/projects/ACME/targets/web01/services/tcp/443` ->
 * `{view:'targets', project:'ACME', host:'web01', protocol:'tcp', port:443}`
 *
 * Unrecognised paths fall back to the default rather than erroring: a URL
 * is something people edit by hand, and a typo should land you somewhere
 * usable.
 */
export function parse(pathname: string, search?: string): Route {
  const r = parsePath(pathname)
  const n = Number(new URLSearchParams(search ?? currentSearch()).get('finding'))
  // `Number('')` is 0 and `Number(null)` is 0, so the guard is on the
  // value being a positive integer rather than on the string being
  // present -- `?finding=` and `?finding=nonsense` both mean nothing
  // is open, which is what a hand-edited URL most often means.
  if (Number.isInteger(n) && n > 0) r.finding = n
  return r
}


function parsePath(pathname: string): Route {
  const parts = pathname.split('/').map(clean).filter(Boolean)
  if (parts.length === 0) return { view: ROOT_VIEW, project: null }

  if (parts[0] === 'projects') {
    // /projects              -> the project list
    if (parts.length === 1) return { view: 'projects', project: null }

    const project = parts[1].toUpperCase()
    // /projects/ACME         -> that project's targets
    if (parts.length === 2) return { view: DEFAULT_VIEW, project }

    const view = asView(parts[2].toLowerCase())
    if (view === null) return { view: DEFAULT_VIEW, project }
    const out: Route = { view, project }

    // /projects/ACME/targets/web01.corp.com
    if (parts.length >= 4) out.host = parts[3].toLowerCase()
    // /projects/ACME/targets/web01.corp.com/services/tcp/443
    if (parts.length >= 7 && parts[4].toLowerCase() === 'services') {
      out.protocol = parts[5].toLowerCase()
      const port = Number(parts[6])
      if (Number.isFinite(port)) out.port = port
    }
    return out
  }

  // /config, /users, /profile — no project involved. And /targets and
  // friends without a project, which means "all projects".
  const view = asView(parts[0].toLowerCase())
  return view === null
    ? { view: ROOT_VIEW, project: null }
    : { view, project: null }
}

/** The inverse. Kept next to `parse` so the two cannot drift apart. */
export function build(r: Route): string {
  // A global view never sits under a project. Site Config, Users and
  // Profile describe the deployment or the person, not the engagement,
  // so `/projects/ACME/config` was a URL that said otherwise — it
  // reads as a per-project setting and shares as one.
  if (!r.project || GLOBAL.has(r.view)) {
    return GLOBAL.has(r.view) || SCOPED.has(r.view) ? `/${r.view}` : '/'
  }
  const bits = ['projects', r.project, r.view]
  if (r.host) {
    bits.push(r.host)
    if (r.protocol && r.port != null) {
      bits.push('services', r.protocol, String(r.port))
    }
  }
  return '/' + bits.map(encodeURIComponent).join('/') + query(r)
}


/** The address bar's query, or nothing when there is no address bar.
 *
 *  `parse` and `build` are pure functions over a URL and the logic
 *  tests exercise them in node, where `window` does not exist. A bare
 *  `window.location.search` as a default argument is evaluated at call
 *  time and threw there -- which is the test doing its job, since the
 *  same expression would throw in any non-browser caller. */
function currentSearch(): string {
  return typeof window === 'undefined' ? '' : window.location.search
}


/** The query half of `build`, kept beside it for the same reason. */
function query(r: Route): string {
  const q = new URLSearchParams(currentSearch())
  // Only the keys this module owns are touched. Anything else in the
  // bar belongs to somebody else -- `next` on the sign-in detour, for
  // one -- and dropping it here would break them silently.
  if (r.finding) q.set('finding', String(r.finding))
  else q.delete('finding')
  const out = q.toString()
  return out ? `?${out}` : ''
}


//: Told when the address bar changes, so the app can re-read it.
//:
//: `popstate` fires for Back and Forward and NOT for `pushState`, so
//: anything navigating in code has to say so. Without this the app's
//: idea of the route silently diverged from the bar the moment
//: something pushed: opening a host wrote the URL, the view did not
//: know, and Back then had nothing to go back to as far as it was
//: concerned.
const listeners = new Set<() => void>()

export function onNavigate(fn: () => void): () => void {
  listeners.add(fn)
  return () => { listeners.delete(fn) }
}

function announce(): void {
  for (const fn of listeners) fn()
}

/** Replace the address bar without adding a history entry.
 *
 *  Used for state the user did not navigate to — switching tabs within a
 *  view, say. A back button that walks through every tab click is worse
 *  than one that does not. */
export function replace(r: Route): void {
  const next = build(r)
  if (next !== here()) {
    window.history.replaceState(null, '', next)
    announce()
  }
}

/** Add a history entry, so Back returns here. */
export function push(r: Route): void {
  const next = build(r)
  if (next !== here()) {
    window.history.pushState(null, '', next)
    announce()
  }
}


/** Path and query together: `build` now returns both, so comparing
 *  against the pathname alone would make `?finding=` a no-op. */
function here(): string {
  return window.location.pathname + window.location.search
}


/**
 * Where to go after signing in.
 *
 * The gate redirects an unauthenticated navigation to `/?next=<path>`,
 * so the page someone asked for survives the detour. Validated here as
 * well as on the server: `next` arrives in a URL anyone can craft, and a
 * value like `//evil.com` is a protocol-relative URL that browsers
 * follow off-site. Checking it in one place only is how that becomes a
 * phishing link.
 */
const PATH_OK = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?#%[\]]+$/

/**
 * Where to go after signing in.
 *
 * The gate redirects an unauthenticated navigation to `/?next=<path>`,
 * so the page someone asked for survives the detour.
 *
 * Validated here as well as on the server, and validated the same way:
 * an ALLOWLIST of what a path may contain, applied after removing the
 * characters a browser discards. The first version of this was a
 * denylist — reject `//`, reject `://` — and five inputs walked through
 * it, including `/<TAB>/evil.com`, which Chrome strips to `//evil.com`
 * and then follows off-site. You cannot enumerate what a browser will
 * normalise; you can enumerate what a path is allowed to look like.
 *
 * Checking on one side only is how this becomes a phishing link, so both
 * sides check and both reject on anything they do not recognise.
 */
export function pendingNext(): string | null {
  const raw = new URLSearchParams(window.location.search).get('next')
  if (!raw) return null
  // Exactly what a browser drops before parsing, so we validate the
  // string it will actually act on.
  const p = raw.replace(/[\t\n\r]/g, '')
  if (!p || !p.startsWith('/') || p.startsWith('//')) return null
  if (!PATH_OK.test(p)) return null
  // Belt and braces: resolved against our own origin it must stay there.
  try {
    const u = new URL(p, window.location.origin)
    if (u.origin !== window.location.origin) return null
  } catch {
    return null
  }
  return p.slice(0, 2048)
}

/** Go to the remembered page and drop `next` from the address bar. */
export function consumeNext(): Route | null {
  const next = pendingNext()
  if (!next) return null
  const route = parse(next.split('?')[0])
  window.history.replaceState(null, '', build(route))
  return route
}

/** The engagement to assume when the URL does not name one.
 *
 *  Global views (`/config`, `/users`, `/profile`) carry no project in
 *  their path, but the header selector and the stats beside it still
 *  need one — and dropping back to "All projects" every time someone
 *  opened Site Config meant re-choosing the engagement afterwards.
 *
 *  Best-effort: localStorage throws in a private window, and a
 *  forgotten selection is a smaller problem than a page that will not
 *  render.
 */
const LAST_PROJECT = 'oddjob.last-project'

export function lastProject(): string | null {
  try {
    return window.localStorage.getItem(LAST_PROJECT) || null
  } catch {
    return null
  }
}

export function rememberProject(code: string | null): void {
  try {
    if (code) window.localStorage.setItem(LAST_PROJECT, code)
    else window.localStorage.removeItem(LAST_PROJECT)
  } catch { /* best effort */ }
}


/** The finding the address bar says is open, or null.
 *
 *  A hook rather than a prop threaded down from App, because the
 *  finding window is opened from four places -- the findings grid,
 *  both rollups, and the host window -- and threading it through all
 *  of them is four chances for one of them to set state without
 *  touching the URL, which is the bug this replaced.
 *
 *  Subscribed to both kinds of navigation: `popstate` for Back and
 *  Forward, `onNavigate` for anything that pushed in code.
 */
export function useRouteFinding(): number | null {
  const read = () =>
    parse(window.location.pathname, window.location.search).finding ?? null
  const [id, setId] = useState<number | null>(read)
  useEffect(() => {
    const sync = () => setId(read())
    window.addEventListener('popstate', sync)
    const off = onNavigate(sync)
    // Read once on mount too: a component can mount after the
    // navigation that set this, and would otherwise show nothing
    // until the next one.
    sync()
    return () => { window.removeEventListener('popstate', sync); off() }
  }, [])
  return id
}
