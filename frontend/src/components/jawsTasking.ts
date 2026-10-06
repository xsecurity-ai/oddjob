/**
 * Shared ground for the Targets page's enumeration actions.
 *
 * Everything on that menu ends up as a Jaws task, and the three things
 * that go wrong are the same every time: there is no agent to run it,
 * the project routes by region and a pooled task has none, or the flags
 * asked for are not the flags that will run. All three are decided
 * here so the dialogs agree with each other.
 */
import { useQuery } from '@tanstack/react-query'
import { api, type JawsAgent, type JawsRouting } from '../lib/api'

/** Where a task should go. `null` is the project pool. */
export type AgentChoice = number | null

export interface Fleet {
  agents: JawsAgent[]
  /** Heartbeating now. Only these will pick anything up promptly. */
  online: JawsAgent[]
  routing: JawsRouting | null
  loading: boolean
  /** Why nothing can be queued, or null. Shown verbatim in the UI. */
  blocked: string | null
  /** Queueing will work but the operator should know something. */
  caution: string | null
}

/**
 * The fleet, and a plain statement of what it can actually do.
 *
 * "No agent" and "no agent right now" are different: an enrolled agent
 * that is between heartbeats will take the task when it returns, so
 * that is a caution. Nothing enrolled at all means the task would sit
 * in the queue forever, which is a block — a queued task that nothing
 * will ever run looks exactly like a scan in progress.
 */
export function useFleet(project: string | null): Fleet {
  const agents = useQuery({
    queryKey: ['agents', project],
    queryFn: () => api.agents(project as string),
    enabled: !!project,
  })
  const routing = useQuery({
    queryKey: ['jaws-routing', project],
    queryFn: () => api.jawsRouting(project as string),
    enabled: !!project,
  })

  const list = agents.data ?? []
  const live = list.filter((a) => a.status === 'online')
  const loading = agents.isLoading || routing.isLoading

  let blocked: string | null = null
  let caution: string | null = null
  if (!loading && !list.length) {
    blocked = `No Jaws agent is enrolled on ${project}. Enumeration runs on `
            + `an agent, not from this browser — enrol one on the Jaws page `
            + `first. Queueing now would leave work nothing picks up, which `
            + `is indistinguishable from a scan in progress.`
  } else if (!loading && !live.length) {
    caution = `No agent on ${project} has checked in in the last 90 seconds. `
            + `The task will be queued and will start whenever one returns — `
            + `it is waiting, not running.`
  }
  return { agents: list, online: live, routing: routing.data ?? null,
           loading, blocked, caution }
}

/** The agent a choice resolves to, or undefined for the pool. */
export function agentOf(fleet: Fleet, choice: AgentChoice): JawsAgent | undefined {
  return choice === null ? undefined : fleet.agents.find((a) => a.id === choice)
}

/**
 * Raw-socket capability for the agent that will run this.
 *
 * `null` means unknowable, which is the honest answer for a pooled task
 * in a mixed fleet: the routing policy picks on the poll, so nothing
 * here can say which agent it will be.
 */
export function rawSockets(fleet: Fleet, choice: AgentChoice): boolean | null {
  const a = agentOf(fleet, choice)
  if (a) return a.privileged
  const pool = fleet.online.length ? fleet.online : fleet.agents
  if (!pool.length) return null
  if (pool.every((x) => x.privileged)) return true
  if (pool.every((x) => !x.privileged)) return false
  return null
}

/** Geo routing refuses a pooled task with no region — see create_pooled_task. */
export function needsRegion(fleet: Fleet, choice: AgentChoice): boolean {
  return choice === null && (fleet.routing?.mode ?? 'mesh') === 'geo'
}

/** Queue one task, pooled or addressed, with the region rule applied. */
export function queue(project: string, choice: AgentChoice, kind: string,
                      args: Record<string, unknown>, region: string) {
  const r = region.trim() || undefined
  return choice === null
    ? api.queuePooledTask(project, kind, args, r)
    : api.queueTask(project, choice, kind, args)
}

// ------------------------------------------------------------- nmap
export interface NmapOptions {
  /** What the operator is asking for. Whether they get it is another
   *  question — see `nmapPlan`. */
  scan: 'syn' | 'connect'
  versionDetect: boolean
  skipHostDiscovery: boolean
  ports: string
  aggressive: boolean
  osDetect: boolean
  /** Have Jaws install nmap (and with it the NSE library) first. */
  installTools: boolean
}

export const NMAP_DEFAULTS: NmapOptions = {
  scan: 'syn', versionDetect: true, skipHostDiscovery: false,
  ports: '', aggressive: false, osDetect: false, installTools: false,
}

export interface NmapPlan {
  /** Task args for kind `nmap`. */
  args: Record<string, unknown>
  /** What the agent will actually run, for the operator to read. */
  argv: string
  /** True things the operator should know before queueing. */
  warnings: string[]
  /** Reasons this cannot be queued as asked. */
  blockers: string[]
}

/**
 * Turn the dialog's answers into task args, and say what will really run.
 *
 * The agent builds the command line, not us — see `nmapArgv` in
 * jaws/internal/tasks/tasks.go. It adds `-sV` unless the profile is
 * `quick`, adds `-sS` when and only when it has raw sockets, and adds
 * `-F` only when no ports were named. So:
 *
 * - We never put a scan-type flag in `extra`. Asking for `-sT` on a
 *   privileged agent would produce `-sS -sT`, which is the same class of
 *   bug as the `-F` with `-p` pair that shipped once already: nmap
 *   refuses the combination, exits non-zero, and still writes an XML
 *   file that imports as a finished scan over nothing.
 * - We never put `-F` in `extra` either. The agent owns that flag and
 *   already suppresses it when ports are given; a second source for it
 *   would reintroduce exactly the conflict the agent guards.
 * - `-A` already implies `-sV`, `-O`, the default scripts and
 *   traceroute, so when it is on we send neither `-sV` nor `-O`. The
 *   dialog shows those two as on-and-locked rather than letting someone
 *   tick a box that does nothing.
 */
export function nmapPlan(o: NmapOptions, targets: string[],
                         privileged: boolean | null,
                         pooled: boolean): NmapPlan {
  const extra: string[] = []
  const args: Record<string, unknown> = { targets }
  const warnings: string[] = []
  const blockers: string[] = []

  const ports = o.ports.trim()
  if (ports) args.ports = ports
  if (o.skipHostDiscovery) extra.push('-Pn')

  if (o.aggressive) {
    extra.push('-A')
  } else if (o.osDetect) {
    extra.push('-O')
  }

  // The only way to stop the agent adding -sV is the quick profile,
  // which is not merely "the same scan without -sV": it also sets -T4,
  // and -F when no ports were named. Said out loud rather than silently
  // narrowing the scan.
  const quick = !o.versionDetect && !o.aggressive
  if (quick) {
    args.profile = 'quick'
    warnings.push(
      'Turning version detection off selects the agent\'s quick profile. '
      + 'That also sets -T4'
      + (ports ? '' : ' and -F, nmap\'s top 100 ports')
      + ' — a narrower scan, not the same scan without -sV.')
  }

  if (extra.length) args.extra = extra.join(' ')
  // Recorded so the task carries what was asked for, not only what ran.
  // The agent ignores args it does not know.
  args.scan_requested = o.scan

  if (o.scan === 'syn' && privileged === false) {
    warnings.push(
      'This agent has no raw sockets, so nmap will fall back to a TCP '
      + 'connect scan. That is a different scan — louder on the wire and '
      + 'a different thing to report.')
  }
  if (o.scan === 'connect' && privileged === true) {
    blockers.push(
      'This agent has raw sockets, so Jaws always passes -sS. Oddjob '
      + 'cannot force -sT through it: the agent builds the command line '
      + 'and sending -sT as well would give nmap two scan types. Queue '
      + 'this on an agent without raw sockets to get a connect scan.')
  }
  if (o.scan === 'connect' && privileged === null) {
    warnings.push(
      'Which agent takes a pooled task is decided when one polls, and '
      + 'this fleet is mixed. An agent with raw sockets will SYN scan '
      + 'regardless. Name an agent to be sure of a connect scan.')
  }
  if ((o.aggressive || o.osDetect) && privileged === false) {
    warnings.push(
      'OS detection needs raw sockets. nmap will say it cannot do it and '
      + 'carry on with the rest.')
  }
  if (o.installTools && pooled) {
    blockers.push(
      'Installing is addressed to one agent, not to the pool — the server '
      + 'refuses it. Name the agent you mean to change.')
  }
  if (!targets.length) blockers.push('Nothing to scan.')

  // Mirrors nmapArgv so the preview is the command, not a description
  // of one. The conditional -sS is written as a condition because that
  // is what it is.
  const argv = ['nmap', '-oX', '<task output>']
  if (ports) argv.push('-p', ports)
  if (quick) {
    argv.push('-T4')
    if (!ports) argv.push('-F')
  } else {
    argv.push('-sV')
  }
  if (privileged === true) argv.push('-sS')
  else if (privileged === null) argv.push('[-sS if the agent has raw sockets]')
  argv.push(...extra)
  argv.push(...(targets.length > 3
    ? [...targets.slice(0, 3), `…+${targets.length - 3} more`] : targets))

  return { args, argv: argv.join(' '), warnings, blockers }
}
