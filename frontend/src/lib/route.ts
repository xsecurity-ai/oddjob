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
  view: string
  /** Project code, or null for "All projects". */
  project: string | null
  /** A target to open the host modal on. */
  host?: string
  /** A service to open, when the path names one. */
  protocol?: string
  port?: number
}

/** Views that exist without a project in the path. */
const GLOBAL = new Set(['projects', 'config', 'users', 'profile'])
/** Views that live under a project.
 *
 *  `settings` is the project's own configuration — its name, client and
 *  scope lists. Deliberately not called `config`, which is the SITE
 *  screen and is global: `/projects/ACME/config` would read as a
 *  per-project copy of the deployment settings, and `/config` is already
 *  that page. */
const SCOPED = new Set(['targets', 'services', 'web', 'vulns', 'credentials',
                        'reports', 'drones', 'import', 'settings'])

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
export function parse(pathname: string): Route {
  const parts = pathname.split('/').map(clean).filter(Boolean)
  if (parts.length === 0) return { view: ROOT_VIEW, project: null }

  if (parts[0] === 'projects') {
    // /projects              -> the project list
    if (parts.length === 1) return { view: 'projects', project: null }

    const project = parts[1].toUpperCase()
    // /projects/ACME         -> that project's targets
    if (parts.length === 2) return { view: DEFAULT_VIEW, project }

    const view = parts[2].toLowerCase()
    if (!SCOPED.has(view) && !GLOBAL.has(view)) {
      return { view: DEFAULT_VIEW, project }
    }
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

  // /config, /users, /profile — no project involved.
  const view = parts[0].toLowerCase()
  if (GLOBAL.has(view)) return { view, project: null }
  // /targets and friends without a project means "all projects".
  if (SCOPED.has(view)) return { view, project: null }
  return { view: ROOT_VIEW, project: null }
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
  return '/' + bits.map(encodeURIComponent).join('/')
}

/** Replace the address bar without adding a history entry.
 *
 *  Used for state the user did not navigate to — switching tabs within a
 *  view, say. A back button that walks through every tab click is worse
 *  than one that does not. */
export function replace(r: Route): void {
  const next = build(r)
  if (next !== window.location.pathname) {
    window.history.replaceState(null, '', next + window.location.search)
  }
}

/** Add a history entry, so Back returns here. */
export function push(r: Route): void {
  const next = build(r)
  if (next !== window.location.pathname) {
    window.history.pushState(null, '', next + window.location.search)
  }
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
