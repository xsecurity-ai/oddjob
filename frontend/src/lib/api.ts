/** Typed client for the Oddjob API. Mirrors backend/app/schemas.py. */

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface Project {
  id: number; code: string; name: string; client: string | null
  /** The operation's internal name — a client code is ACME, its operation name FALCON.
   *  The code is the client's and goes in their deliverables; the
   *  codename is what the scan directories and Slack channels use. */
  codename: string | null
  description: string | null; status: string
  /** The token itself is never returned — only whether an override exists. */
  slack_token_set: boolean
  /** Whether a notification posted now would reach a channel: a token
   *  resolves AND the channel has been seen in the workspace. Distinct
   *  from `slack_token_set`: a project on the site-wide bot has no
   *  override of its own and working Slack. */
  slack_active: boolean
  /** present: seen in the workspace. missing: the workspace answered
   *  and it was not there. unknown: Slack could not be asked, which is
   *  NOT the same as missing. no_token: nothing to ask with. */
  slack_channel_state: 'present' | 'missing' | 'unknown' | 'no_token'
  slack_channel_checked_at: string | null
  slack_channel_error: string | null
  /** site | override | both — which token(s) the project posts through. */
  slack_delivery: string
  slack_channel: string | null
  total_targets: number; total_services: number; total_vulns: number; total_pocs: number
  created_at: string; updated_at: string
}

export interface Target {
  id: number; host: string; project_id: number; project_code: string
  /** host: a machine at an address. mobile: an application named by
   *  its bundle/package id, with no IP and no meaningful liveness.
   *  cloud: a managed resource, named as its provider names it. */
  kind: 'host' | 'mobile' | 'cloud'
  /** Which cloud, for kind=cloud. */
  provider: string | null
  ip_address: string | null
  /** Tri-state: true responding, false probed-no-response, null not probed. */
  alive: boolean | null
  hacked: boolean
  os: string | null; notes: string | null; tags: string | null
  /** Populated by a scan import; a hand-made target has none of these. */
  os_accuracy: number | null
  mac_address: string | null; mac_vendor: string | null
  hostnames: string[]
  /** Anything the scanner reported that has no column: uptime, traceroute,
   *  competing OS matches, host-level NSE output. */
  extra: Record<string, unknown>
  total_vulns: number; total_criticals: number; total_highs: number
  total_pocs: number; total_ports: number
  created_at: string; updated_at: string
}

export interface Service {
  id: number; target_id: number; host: string; project_code: string
  port: number; protocol: string; state: string
  /** UNKNOWN when a port answered but could not be identified. An empty
   *  value means nothing has looked at it, which is a different claim. */
  name: string | null; product: string | null; version: string | null
  /** What the service said about itself — "nginx 1.25". Shown as
   *  "Version"; the field keeps the scanners' name for it. */
  banner: string | null
  /** What a person recorded about it. Deliberately not the banner. */
  notes: string | null
  extrainfo: string | null; tunnel: string | null
  method: string | null; confidence: number | null; reason: string | null
  cpe: string[]
  /** Port-level NSE output, keyed by script id. */
  scripts: Record<string, string>
  created_at: string; updated_at: string
}

export interface Vuln {
  id: number; target_id: number; host: string; project_code: string
  title: string; severity: string; status: string
  port: number | null; protocol: string | null
  description: string | null; remediation: string | null
  external_id: string | null
  created_at: string; updated_at: string
}

/** One host carrying the same finding. */
export interface VulnOccurrence {
  id: number; target_id: number; host: string; project_code: string
  port: number | null; protocol: string | null
  status: string; severity: string
}

/** A finding in full, with every host it was found on. */
export interface VulnDetail extends Vuln {
  occurrences: VulnOccurrence[]
  /** Whether the hosts were grouped by identifier or by title. */
  grouped_by: string
}

export interface Poc {
  id: number; target_id: number; host: string; project_code: string
  title: string; status: string; path: string | null
  exit_code: number | null; notes: string | null
  created_at: string; updated_at: string
}

export interface TargetDetail {
  target: Target; services: Service[]; vulns: Vuln[]; pocs: Poc[]
  implants: Implant[]
}

/** Worst-first. Severity is a string in the DB, so every sort needs this —
 *  alphabetically "critical" sorts below "high" and above "info", which is
 *  actively misleading in a findings table. */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export interface NameCount { name: string; count: number }

export interface ExploreHost {
  host: string; project_code: string; port: number; protocol: string
  state: string; name: string | null; banner: string | null
  vulns: number; criticals: number
}

export interface Explore {
  dimension: 'port' | 'service'
  value: string
  protocol: string | null
  total_services: number
  total_hosts: number
  by_state: Record<string, number>
  service_names: NameCount[]
  ports: NameCount[]
  products: NameCount[]
  banners: NameCount[]
  vulns_total: number
  vulns_by_severity: Record<string, number>
  hosts: ExploreHost[]
  truncated: boolean
}

export interface Credential {
  id: number; project_id: number; project_code: string
  host: string | null; service: string | null; port: number | null
  username: string | null
  /** null when the caller is readonly on the project — see secret_set. */
  secret: string | null
  secret_set: boolean
  kind: string; source: string | null; validated: string; notes: string | null
  created_at: string; updated_at: string
}

export interface Action {
  id: number; kind: string; service_id: number; status: string
  result: string | null; error: string | null
  created_at: string; finished_at: string | null
}

export interface BulkOpResult {
  kind: string; requested: number; changed: number; skipped: number; errors: string[]
}

export type EntityKind = 'targets' | 'services' | 'vulns' | 'pocs' | 'credentials'

export interface SettingSpec {
  key: string; group: string; label: string
  /** `dsn` is a connection string: stored whole, returned with only
   *  the password masked, so you can still see which database it is. */
  type: 'text' | 'number' | 'bool' | 'select' | 'secret' | 'dsn'
  options?: string[]; default?: unknown; help?: string
  /** Which Test button governs this field; it cannot be saved untested. */
  gate?: 'smtp' | 'google' | 'postgres'
  /** Show this field only when every named setting has the given value.
   *  Keeps the Agent group from showing three providers' credentials at
   *  once when only one of them is in use. */
  show_if?: Record<string, unknown>
}
export interface SettingsBundle {
  spec: SettingSpec[]
  groups: string[]
  values: Record<string, unknown>
  /** Secrets are never sent back — only whether one is stored. */
  secrets_set: Record<string, boolean>
}
export interface WebAddress {
  id: number; target_id: number; service_id: number | null
  host: string; project_code: string
  url: string; scheme: string; port: number | null; path: string
  /** "" when the source never said. Part of the row's identity, so
   *  GET /login and POST /login are different addresses. */
  method: string
  status_code: number | null; title: string | null
  content_type: string | null; content_length: number | null
  webserver: string | null; tech: string[]
  sources: string | null
  /** True once something actually fetched it, as opposed to referencing it. */
  crawled: boolean
  notes: string | null
  created_at: string; updated_at: string
}
export interface DomainCandidate {
  id: number; name: string; root_domain: string
  source: string; score: number; reason: string | null
  state: string; times_seen: number; created_at: string
}
export interface DomainSearch {
  id: number; domain: string; runs: number; last_run_at: string | null
  candidates_found: number; known_at_last_run: number; note: string | null
}
export interface DomainRoot { domain: string; known_hosts: number; searched: boolean }
export interface DetectResult {
  domain: string; candidates: DomainCandidate[]
  new_candidates: number; already_known: number; previously_suggested: number
  runs: number; note: string | null
  error?: string | null
  /** Present when auto_promote ran. Named, not counted. */
  promoted?: string[]
  promoted_skipped?: string[]
  promoted_refused?: Record<string, string>
}
/** What /api/domains/detect actually returns: one entry per domain, so
 *  a typo in the fourth of eight never costs you the other seven.
 *
 *  This shape was the bug. The client declared DetectResult and read
 *  `.candidates` off the batch, which has no such key — so a run that
 *  produced 200 candidates rendered as "No candidates". */
export interface DetectBatch {
  results: DetectResult[]
  new_candidates: number; domains_run: number; domains_skipped: number
  promoted: number; promoted_refused: number
}
export interface AgentStep {
  kind: string; text: string; tool: string | null
  args: Record<string, unknown>; result: string | null
}
export interface AgentStatus {
  configured: boolean; provider: string; model: string
  source: string
  /** For a local provider, the server the backend will call. */
  endpoint: string | null
  /** api-key | oauth | not set — they use different auth headers. */
  token_kind: string
  allow_writes: boolean; max_steps: number; tools: string[]
  detail: string | null
}
export interface AgentReply {
  text: string; provider: string; model: string
  steps: AgentStep[]; stop_reason: string
  usage: Record<string, number>; history: unknown[]
}
export interface Report {
  id: number; project_code: string; kind: string; title: string
  /** queued | running | ready | failed. The UI shows the first two as
   *  "In Progress" and the third as "Ready to Download". */
  status: string
  requested_by_name: string | null
  created_at: string; started_at: string | null; finished_at: string | null
  size_bytes: number | null
  error: string | null
  emailed_to: string | null; email_error: string | null
  agent_edited: boolean; agent_note: string | null
}
export interface ReportKind { name: string; label: string; sections: string[] }
/** Whether the Slack listener is actually up. "Configured" and
 *  "connected" are different claims, and the gap between them is where
 *  the problems live. */
export interface SlackBotStatus {
  enabled: boolean
  configured: boolean
  connected: boolean
  detail: string | null
}

export interface RemediationStatus {
  enabled: boolean; configured: boolean
  min_severity: string; delay_seconds: number
  running: boolean; last_outcome: string | null
  pending: number; written_by_agent: number; from_scanner: number
  gave_up: number
  by_severity: Record<string, number>
  /** Rough wall-clock for the backlog; a local model is far slower. */
  estimate: string | null
}
export interface UnknownHost {
  host: string; ip: string | null
  services: number; web: number; vulns: number
  credentials: number; implants: number; notes: number
  total: number
}
export interface HostDecision { action: 'add' | 'map' | 'reject'; target?: string }

/** A Jaws instance. Bound to exactly one project, for its whole life. */
export interface JawsAgent {
  id: number
  project_code: string
  name: string
  status: string
  platform: string | null
  arch: string | null
  version: string | null
  hostname: string | null
  privileged: boolean
  tools: Record<string, string>
  call_in_url: string | null
  last_seen: string | null
  /** Where the connection arrived from — the last hop, not the agent. */
  last_ip: string | null
  /** The agent's own internet-facing address, from its routing table. */
  outbound_ip: string | null
  interfaces: string[]
  queued_tasks: number
  /** Taken by the agent and in flight, as distinct from waiting. */
  running_tasks: number
  /** Finished successfully. */
  completed_tasks: number
  /** Finished and did not. An agent with no completions and forty
   *  failures is broken, not idle. */
  failed_tasks: number
  connection_mode: string
  target_os: string | null
  priority: number
  regions: string[]
  /** It has completed the identity exchange. */
  has_identity: boolean
  /** Its payload is encrypted end to end. False means results reach
   *  Oddjob protected only by whatever TLS is in between. */
  sealed: boolean
  /** Enrolled, token still good, has never connected. */
  enrolled_pending: boolean
  created_at: string | null
}
/** Shown once, at enrollment. None of it is recoverable afterwards. */
export interface AgentEnrolled {
  agent: JawsAgent
  callback_key: string
  call_in_key: string
  /** One-time. The agent trades it for a keypair it generates itself. */
  enroll_token: string
  enroll_expires_at: string
  /** This Oddjob's public key. The agent pins it, so it will only ever
   *  take tasking from this instance. */
  server_public_key: string
}
export interface JawsRouting {
  mode: 'mesh' | 'primary' | 'geo'
  /** Who is serving right now in primary mode. Derived from live
   *  heartbeats — an observation, not a setting. */
  current_primary: number | null
  current_primary_name: string | null
  eligible: number
  unassigned_tasks: number
}
export interface JawsTask {
  id: number
  agent_id: number
  project_code: string
  kind: string
  args: Record<string, unknown>
  status: string
  summary: string | null
  exit_code: number | null
  error: string | null
  import_as: string | null
  import_result: ImportResult | null
  created_at: string | null
  started_at: string | null
  finished_at: string | null
}
export const JAWS_KINDS = ['nmap', 'masscan', 'amass', 'gobuster', 'nuclei',
  'httpx', 'nslookup', 'reverse_ip'] as const
export interface WebPacket {
  id: number; url: string; method: string | null; status_code: number | null
  host: string
  request: string | null; response: string | null
  /** The capture was cut at the import cap; this is not the whole thing. */
  truncated: boolean
  sources: string | null; notes: string | null
}
/** A URL, standing for every exchange recorded against it. */
export interface WebGroup extends WebAddress {
  hits: number
  methods: string[]
  statuses: number[]
}

export interface ReplayResult {
  web: WebAddress
  status_code: number | null
  elapsed_ms: number
  error: string | null
}

/** Everything /api/web and /api/web/grouped accept. Named rather than
 *  inlined because referring to it as `Parameters<typeof api.web>[0]`
 *  from inside `api` is circular, and TypeScript resolves the whole
 *  object to `{}` when it is — which shows up as unrelated errors in
 *  completely different files. */
export interface WebQuery {
  project?: string; host?: string; q?: string; crawled?: boolean
  status_code?: number; status_in?: string; scheme?: string
  sort?: string; order?: 'asc' | 'desc'
  filters?: string; logic?: 'and' | 'or'
  limit?: number; offset?: number
}

export interface ImportFormat { name: string; label: string }
export interface ImportResult {
  project: string; format: string; tool: string; command: string | null
  hosts_seen: number
  targets_created: number; targets_updated: number
  services_created: number; services_updated: number
  services_unknown: number
  vulns_created: number; vulns_updated: number
  urls_created: number; urls_updated: number
  /** True when strict mode found hosts the project does not have. Nothing
   *  was written; decide and post again. */
  needs_decision: boolean
  unknown_hosts: UnknownHost[]
  rejected_hosts: Record<string, number>
  mapped_hosts: Record<string, string>
  created_hosts: string[]
  credentials_created: number
  implants_created: number; implants_updated: number
  hosts_flagged: number
  scripts_captured: number; notes_recorded: number
  errors: string[]
  /** Present when the server is holding the file for a decision. */
  upload_id?: string | null
  /** Present when the import was queued rather than run inline. */
  job_id?: number | null
}

/** A background import. Outlives the page that started it. */
export interface ImportJob {
  id: number
  project: string
  filename: string
  format: string
  status: 'queued' | 'running' | 'done' | 'failed'
  rows_done: number
  rows_total: number | null
  hosts_seen: number
  error: string | null
  result: ImportResult | null
  started_at: string | null
  finished_at: string | null
  created_at: string | null
}
export interface Implant {
  id: number; target_id: number; host: string; project_code: string
  framework: string; implant_id: string
  listener: string | null; user: string | null; domain: string | null
  process: string | null; pid: number | null; arch: string | null
  /** unknown | low | medium | high | system */
  integrity: string | null
  internal_ip: string | null; external_ip: string | null; os: string | null
  first_seen: string | null; last_seen: string | null
  active: boolean | null; note: string | null
  extra: Record<string, unknown>
  created_at: string; updated_at: string
}
export interface TimelineEvent {
  id: number; target_id: number; at: string; kind: string
  summary: string; detail: string | null
  actor: string | null; source: string | null
}
export interface PublicDefaults {
  slack_channel_prefix: string
  slack_default_private: boolean
}
export interface TestResult {
  ok: boolean; detail: string
  /** Proof of a pass, bound to the exact values tested. Present on success. */
  token?: string | null
}
export interface SelectableUser { id: number; username: string; full_name: string | null }
export interface Acl {
  id: number; project_code: string; role: string
  username: string | null; group: string | null
}

export interface ScopeEntry {
  id: number; kind: 'cidr' | 'ipv4' | 'ipv6' | 'fqdn'; value: string
  included: boolean; notes: string | null
}
export interface Contact {
  id?: number; name: string; email?: string | null; phone?: string | null
  title?: string | null; primary_contact?: boolean; notes?: string | null
}
export interface ProjectCreated {
  project: Project
  scope: ScopeEntry[]
  contacts: Contact[]
  members: Acl[]
  scope_errors: string[]
  member_errors: string[]
}

export interface Group { id: number; name: string; description: string | null }
export interface User {
  id: number; username: string; email: string | null; full_name: string | null
  avatar_url: string | null
  /** Offered as the default when joining an engagement that uses Slack.
   *  Stored bare, without the @. */
  slack_handle: string | null
  is_site_admin: boolean; is_active: boolean
  /** Which sign-in methods actually work for this account. */
  has_password: boolean; has_google: boolean
  groups: Group[]; created_at: string
}
export interface Me { user: User; projects: Record<string, string> }

export interface Stats {
  projects: number; targets: number; hacked: number; services: number
  open_ports: number; vulns: number; by_severity: Record<string, number>; pocs: number
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...init?.headers },
    credentials: 'same-origin',   // the login cookie is httpOnly
  })
  if (!res.ok) {
    // Surface the server's own `detail` — "user required on FALCON-1; you
    // have readonly" is actionable in a way that "403" is not.
    let msg = `${res.status} ${res.statusText}`
    try {
      const b = await res.json()
      if (b?.detail) msg = typeof b.detail === 'string' ? b.detail : JSON.stringify(b.detail)
    } catch { /* non-JSON body; keep the status line */ }
    throw new ApiError(res.status, msg)
  }
  return res.status === 204 ? (undefined as T) : (res.json() as Promise<T>)
}

const qs = (o: Record<string, unknown>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  // auth
  setupRequired: () => req<{ setup_required: boolean }>('/api/auth/setup-required'),
  setup: (b: { username: string; password: string; email?: string }) =>
    req<{ user: User }>('/api/auth/setup', { method: 'POST', body: JSON.stringify(b) }),
  login: (username: string, password: string) =>
    req<{ user: User }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => req<void>('/api/auth/logout', { method: 'POST' }),
  me: () => req<Me>('/api/auth/me'),

  // data — `project` is the code; omitted means every project you can see
  projects: () => req<Page<Project>>('/api/projects' + qs({ limit: 1000 })),
  createProject: (b: Record<string, unknown>) =>
    req<ProjectCreated>('/api/projects', { method: 'POST', body: JSON.stringify(b) }),
  projectScope: (project: string) =>
    req<ScopeEntry[]>(`/api/projects/${encodeURIComponent(project)}/scope`),
  projectContacts: (project: string) =>
    req<Contact[]>(`/api/projects/${encodeURIComponent(project)}/contacts`),
  targets: (project?: string) => req<Page<Target>>('/api/targets' + qs({ project, limit: 100000 })),
  ports: (project?: string) => req<Page<Service>>('/api/ports' + qs({ project, limit: 100000 })),
  services: (project?: string) => req<Page<Service>>('/api/services' + qs({ project, limit: 100000 })),
  vulns: (project?: string) => req<Page<Vuln>>('/api/vulns' + qs({ project, limit: 100000 })),
  /** One finding, with its full text and every host it appears on. */
  vuln: (id: number) => req<VulnDetail>(`/api/vulns/${id}`),
  /** Exact-match service lookup — distinct from `q`, which is a substring
   *  search across every column and would also match a banner. */
  servicesWhere: (o: { project?: string; port?: number; name?: string }) =>
    req<Page<Service>>('/api/services' + qs({ ...o, limit: 100000 })),
  explore: (o: { dimension: 'port' | 'service'; value: string; project?: string; protocol?: string }) =>
    req<Explore>('/api/explore' + qs(o)),
  targetDetail: (project: string, host: string) =>
    req<TargetDetail>(`/api/targets/${encodeURIComponent(project)}/${encodeURIComponent(host)}/detail`),
  stats: (project?: string) => req<Stats>('/api/stats' + qs({ project })),

  credentials: (project?: string) =>
    req<Page<Credential>>('/api/credentials' + qs({ project, limit: 100000 })),
  createCredential: (project: string, body: Record<string, unknown>) =>
    req<Credential>('/api/credentials' + qs({ project }), { method: 'POST', body: JSON.stringify(body) }),

  createTarget: (project: string, body: Record<string, unknown>) =>
    req<Target>('/api/targets' + qs({ project }), { method: 'POST', body: JSON.stringify(body) }),
  createService: (project: string, body: Record<string, unknown>) =>
    req<Service>('/api/services' + qs({ project }), { method: 'POST', body: JSON.stringify(body) }),
  createVuln: (project: string, body: Record<string, unknown>) =>
    req<Vuln>('/api/vulns' + qs({ project }), { method: 'POST', body: JSON.stringify(body) }),

  bulkDelete: (kind: EntityKind, ids: number[]) =>
    req<BulkOpResult>('/api/bulk/delete', { method: 'POST', body: JSON.stringify({ kind, ids }) }),
  bulkPatch: (kind: EntityKind, ids: number[], fields: Record<string, unknown>) =>
    req<BulkOpResult>('/api/bulk/patch', { method: 'POST', body: JSON.stringify({ kind, ids, fields }) }),

  runAction: (serviceId: number, kind: string) =>
    req<Action>(`/api/services/${serviceId}/actions`, { method: 'POST', body: JSON.stringify({ kind }) }),
  actions: (serviceId?: number) =>
    req<Page<Action>>('/api/actions' + qs({ service_id: serviceId, limit: 200 })),

  timeline: (project: string, host: string, kind?: string) =>
    req<Page<TimelineEvent>>(
      `/api/targets/${encodeURIComponent(project)}/${encodeURIComponent(host)}/timeline`
      + qs({ kind, limit: 200 })),
  addTimelineNote: (project: string, host: string, body: Record<string, unknown>) =>
    req<TimelineEvent>(
      `/api/targets/${encodeURIComponent(project)}/${encodeURIComponent(host)}/timeline`,
      { method: 'POST', body: JSON.stringify(body) }),
  importFormats: () => req<ImportFormat[]>('/api/scans/formats'),

  remediationStatus: () => req<RemediationStatus>('/api/agent/remediation'),
  slackBotStatus: () => req<SlackBotStatus>('/api/agent/slack'),

  reportKinds: () => req<ReportKind[]>('/api/reports/kinds'),
  reports: (project: string) => req<Report[]>('/api/reports' + qs({ project })),
  createReport: (project: string, kind: string, agentic: boolean,
                 min_severity: string) =>
    req<Report>('/api/reports' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ kind, agentic, min_severity }) }),
  deleteReport: (id: number) =>
    req<void>(`/api/reports/${id}`, { method: 'DELETE' }),
  /** A plain link so the browser downloads it rather than buffering the
   *  file through fetch; the session cookie carries the auth. */
  reportDownloadUrl: (id: number, format: 'pdf' | 'docx') =>
    `/api/reports/${id}/download?format=${format}`,

  /** One page of web addresses, paged and searched in the database.
   *
   *  It used to pass `limit: 5000` and let the browser do the rest. For
   *  an engagement with 211,012 addresses that silently showed the
   *  first 5,000, and the search box searched only those — a URL
   *  outside the window did not exist as far as the UI was concerned.
   */
  web: (p: WebQuery = {}) =>
    req<Page<WebAddress>>('/api/web' + qs({ limit: 100, ...p })),
  /** One exchange, on demand. Never part of the listing — see WebPacket. */
  packet: (id: number) => req<WebPacket>(`/api/web/${id}/packet`),

  /** The listing, one row per URL instead of per captured exchange. */
  webGrouped: (p: WebQuery = {}) =>
    req<Page<WebGroup>>('/api/web/grouped' + qs({ limit: 100, ...p })),

  /** Every exchange recorded for one URL. Drives the expanded row. */
  webByUrl: (target_id: number, url: string) =>
    req<Page<WebAddress>>('/api/web/by-url' + qs({ target_id, url, limit: 500 })),

  /** Send an edited request again. The result is a NEW row, so the
   *  original and the edit sit side by side under the same URL. */
  replay: (id: number, raw: string, opts: {
    follow_redirects?: boolean; verify_tls?: boolean; timeout?: number } = {}) =>
    req<ReplayResult>(`/api/web/${id}/replay`, {
      method: 'POST', body: JSON.stringify({ raw, ...opts }) }),
  /** Whether a Web view would have anything to show here. */
  webApplicable: (project?: string) =>
    req<{ applicable: boolean; web_services: number; web_addresses: number }>(
      '/api/web/applicable' + qs({ project })),
  webStats: (project?: string) =>
    req<{ total: number; crawled: number; hosts: number
          by_status: Record<string, number> }>('/api/web/stats' + qs({ project })),

  domainRoots: (project: string) =>
    req<DomainRoot[]>('/api/domains/roots' + qs({ project })),
  domainSearches: (project: string) =>
    req<DomainSearch[]>('/api/domains/searches' + qs({ project })),
  /** Pattern-based candidate generation. Offline — nothing is resolved
   *  and no packets are sent; see `enumerateDomains` for the opposite.
   *
   *  Takes one domain or many and returns the batch flattened into a
   *  single list, which is what every caller wants and what the old
   *  single-result signature pretended the server already did. */
  detectDomains: async (project: string, domains: string | string[],
                        force = false, autoPromote = false) => {
    const list = Array.isArray(domains) ? domains : [domains]
    const b = await req<DetectBatch>('/api/domains/detect' + qs({ project }), {
      method: 'POST',
      body: JSON.stringify({ domains: list, force, limit: 200,
                             auto_promote: autoPromote }),
    })
    const seen = new Set<number>()
    const candidates: DomainCandidate[] = []
    for (const r of b.results) {
      for (const c of r.candidates) {
        if (!seen.has(c.id)) { seen.add(c.id); candidates.push(c) }
      }
    }
    candidates.sort((a, b2) => (b2.score ?? 0) - (a.score ?? 0))
    const notes = b.results.filter((r) => r.note).map((r) => r.note!)
    const errors = b.results.filter((r) => r.error)
                            .map((r) => `${r.domain}: ${r.error}`)
    return {
      batch: b,
      domain: list.length === 1 ? list[0] : `${list.length} domain(s)`,
      candidates,
      new_candidates: b.new_candidates,
      already_known: b.results.reduce((n, r) => n + (r.already_known ?? 0), 0),
      previously_suggested: b.results.reduce(
        (n, r) => n + (r.previously_suggested ?? 0), 0),
      runs: Math.max(0, ...b.results.map((r) => r.runs ?? 0)),
      note: notes.length ? notes.join(' · ') : null,
      promoted: b.results.flatMap((r) => r.promoted ?? []),
      promoted_refused: Object.assign(
        {}, ...b.results.map((r) => r.promoted_refused ?? {})),
      errors,
    }
  },

  /** Hand domains to a Jaws agent to actually enumerate, and let the
   *  results file themselves as targets when they come back. Accepts a
   *  pasted list: newlines, commas, schemes and wildcards are all
   *  tolerated and normalised server-side. */
  enumerateDomains: (project: string, domains: string,
                     mode: 'passive' | 'active' = 'passive') =>
    req<{
      queued: Array<{ domain: string; task_id: number }>
      refused: Record<string, string>
      agents_online: number
      mode: string
    }>('/api/domains/enumerate' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ domains, mode }) }),
  promoteDomains: (project: string, ids: number[]) =>
    req<{ created: string[]; already_existed: string[] }>(
      '/api/domains/candidates/promote' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ ids }) }),
  rejectDomains: (project: string, ids: number[]) =>
    req<{ rejected: string[] }>('/api/domains/candidates/reject' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ ids }) }),

  /** Everything waiting to run on this project, oldest first — the
   *  pool and work addressed to one agent that has not taken it. */
  jawsQueue: (project: string) => req<Array<{
    id: number; kind: string; subject: string
    args: Record<string, unknown>
    agent_id: number | null; agent_name: string | null
    region: string | null; requested_by: string | null
    created_at: string | null; status: string
  }>>('/api/agents/queue' + qs({ project })),

  /** Take a queued task back out. Refused once an agent has it: the
   *  scan is already running and deleting the row would only lose the
   *  result. */
  cancelJawsTask: (project: string, id: number) =>
    req<void>(`/api/agents/tasks/${id}` + qs({ project }),
              { method: 'DELETE' }),

  agentStatus: (project: string) =>
    req<AgentStatus>('/api/agent/status' + qs({ project })),
  agentChat: (project: string, message: string, history: unknown[]) =>
    req<AgentReply>('/api/agent/chat' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ message, history }) }),
  importReport: (project: string, content: string, format = 'auto',
                 mode: 'strict' | 'open' = 'strict',
                 decisions: Record<string, HostDecision> = {}) =>
    req<ImportResult>('/api/scans/import' + qs({ project }),
      { method: 'POST',
        body: JSON.stringify({ content, format, mode, decisions }) }),

  /** Upload a file for import without ever holding it in memory.
   *
   *  This exists because reading the file into a string does not work
   *  and does not say so. `Blob.text()` on anything 512 MiB or larger
   *  resolves with an EMPTY STRING in Chrome — no exception, no
   *  rejection — so a 2.5 GB Burp history arrived at the server as "",
   *  which it then reported as "could not tell what produced this".
   *  Measured: 400 MiB reads back whole, 512 MiB and up reads back as
   *  length 0.
   *
   *  XHR rather than fetch, only because fetch still cannot report
   *  upload progress and a multi-gigabyte post with no progress bar is
   *  indistinguishable from the hang this replaced.
   */
  uploadReport: (project: string, file: File, format = 'auto',
                 mode: 'strict' | 'open' = 'strict',
                 decisions: Record<string, HostDecision> = {},
                 onProgress?: (sent: number, total: number) => void) =>
    new Promise<ImportResult>((resolve, reject) => {
      const body = new FormData()
      body.append('file', file, file.name)
      const url = '/api/scans/import/upload' + qs({
        project, format, mode,
        decisions: Object.keys(decisions).length ? JSON.stringify(decisions) : '',
      })
      const xhr = new XMLHttpRequest()
      xhr.open('POST', url)
      xhr.withCredentials = true
      if (onProgress) {
        xhr.upload.onprogress = (e) =>
          onProgress(e.loaded, e.lengthComputable ? e.total : file.size)
      }
      xhr.onload = () => {
        let parsed: unknown = null
        try { parsed = JSON.parse(xhr.responseText) } catch { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(parsed as ImportResult)
        } else {
          const detail = (parsed as { detail?: unknown } | null)?.detail
          reject(new Error(typeof detail === 'string' ? detail
                           : `import failed (HTTP ${xhr.status})`))
        }
      }
      xhr.onerror = () => reject(new Error('the upload did not reach the server'))
      xhr.onabort = () => reject(new Error('upload cancelled'))
      xhr.send(body)
    }),

  /** Finish an import whose file the server still holds.
   *
   *  The strict-mode survey keeps the uploaded file and hands back an
   *  `upload_id`. Answering the unknown-host question with this sends
   *  a few hundred bytes of decisions instead of the whole file again
   *  — which for a multi-gigabyte proxy history is the difference
   *  between a second upload and none.
   */
  resumeImport: (project: string, upload_id: string,
                 decisions: Record<string, HostDecision> = {},
                 mode: 'strict' | 'open' = 'strict',
                 background = false) =>
    req<ImportResult>('/api/scans/import/resume' + qs({ project }),
      { method: 'POST',
        body: JSON.stringify({ upload_id, decisions, mode, background }) }),

  importJobs: (project: string) =>
    req<ImportJob[]>('/api/scans/import/jobs' + qs({ project })),

  /** Release a held upload when the operator cancels. */
  discardHeld: (project: string, upload_id: string) =>
    req<void>(`/api/scans/import/held/${encodeURIComponent(upload_id)}`
              + qs({ project }), { method: 'DELETE' }),

  settings: () => req<SettingsBundle>('/api/settings'),
  /** The handful of site settings any signed-in user may see. */
  settingsDefaults: () => req<PublicDefaults>('/api/settings/defaults'),
  saveSettings: (values: Record<string, unknown>,
                 tokens: Record<string, string> = {}) =>
    req<SettingsBundle>('/api/settings', {
      method: 'PATCH', body: JSON.stringify({ values, test_tokens: tokens }),
    }),
  clearSetting: (key: string) =>
    req<void>(`/api/settings/${encodeURIComponent(key)}`, { method: 'DELETE' }),
  /** Tests the values in the form, not the ones already stored. */
  testProvider: (provider: string, values: Record<string, unknown>, to?: string) =>
    req<TestResult>(`/api/settings/test/${provider}`, {
      method: 'POST', body: JSON.stringify({ values, to: to || null }),
    }),

  users: () => req<User[]>('/api/users'),
  selectableUsers: () => req<SelectableUser[]>('/api/users/selectable'),
  createUser: (b: { username: string; password: string; email?: string; full_name?: string }) =>
    req<User>('/api/users', { method: 'POST', body: JSON.stringify(b) }),
  updateUser: (username: string, b: Record<string, unknown>) =>
    req<User>(`/api/users/${encodeURIComponent(username)}`, { method: 'PATCH', body: JSON.stringify(b) }),
  deleteUser: (username: string) =>
    req<void>(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  groups: () => req<Group[]>('/api/groups'),
  createGroup: (name: string, description?: string) =>
    req<Group>('/api/groups', { method: 'POST', body: JSON.stringify({ name, description }) }),
  addGroupMember: (group: string, username: string) =>
    req<Group>(`/api/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(username)}`, { method: 'POST' }),
  removeGroupMember: (group: string, username: string) =>
    req<void>(`/api/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(username)}`, { method: 'DELETE' }),

  acl: (project: string) => req<Acl[]>(`/api/projects/${encodeURIComponent(project)}/acl`),
  grant: (project: string, b: { username?: string; group?: string; role: string }) =>
    req<Acl>(`/api/projects/${encodeURIComponent(project)}/acl`, { method: 'POST', body: JSON.stringify(b) }),
  revoke: (project: string, aclId: number) =>
    req<void>(`/api/projects/${encodeURIComponent(project)}/acl/${aclId}`, { method: 'DELETE' }),

  authMethods: () => req<{ password: boolean; google: boolean; magic_link: boolean; self_registration: boolean }>('/api/auth/methods'),
  requestMagicLink: (identifier: string) =>
    req<{ status: string; detail: string }>('/api/auth/magic-link',
      { method: 'POST', body: JSON.stringify({ identifier }) }),
  invite: (username: string) =>
    req<TestResult>(`/api/auth/invite/${encodeURIComponent(username)}`, { method: 'POST' }),

  googleStatus: () => req<{ enabled: boolean; reason: string | null }>('/api/auth/google/status'),
  updateProfile: (body: Record<string, unknown>) =>
    req<User>('/api/auth/me', { method: 'PATCH', body: JSON.stringify(body) }),
  apiKeys: () => req<Array<{ id: number; name: string; prefix: string; revoked: boolean; last_used_at: string | null; created_at: string }>>('/api/auth/keys'),
  createApiKey: (name: string) =>
    req<{ id: number; key: string; prefix: string }>('/api/auth/keys' + qs({ name }), { method: 'POST' }),
  revokeApiKey: (id: number) => req<void>(`/api/auth/keys/${id}`, { method: 'DELETE' }),

  patchTarget: (project: string, host: string, body: Partial<Pick<Target, 'hacked' | 'alive' | 'notes'>>) =>
    req<Target>(`/api/targets/${encodeURIComponent(project)}/${encodeURIComponent(host)}`,
      { method: 'PATCH', body: JSON.stringify(body) }),

  // Jaws agents. Every call is project-scoped because an agent is:
  // enrolled into one project, tasked only from that project, and its
  // results import only there.
  agents: (project: string) => req<JawsAgent[]>('/api/agents' + qs({ project })),
  enrollAgent: (project: string, body: {
    name: string; connection_mode?: string; target_os?: string; notes?: string
  }) =>
    req<AgentEnrolled>('/api/agents' + qs({ project }),
      { method: 'POST', body: JSON.stringify(body) }),
  /** Rename, re-prioritise, set the regions it serves, or annotate it.
   *  Priority only matters in `primary` routing (lower goes first);
   *  regions only in `geo`. */
  patchAgent: (project: string, id: number, body: {
    name?: string; priority?: number; regions?: string; notes?: string
  }) =>
    req<JawsAgent>(`/api/agents/${id}` + qs({ project }),
      { method: 'PATCH', body: JSON.stringify(body) }),
  /** Rotate an agent's keys, keeping its record and history.
   *
   *  Its current identity stops being accepted immediately — a
   *  rotation that leaves the old key usable has rotated nothing — so
   *  the agent is dead until someone redeems the returned token on
   *  the host. The response says what to do there. */
  reenrollAgent: (project: string, id: number) => req<{
    agent: JawsAgent
    enroll_token: string
    enroll_expires_at: string
    server_public_key: string
    server_kex_public_key: string
    instructions: string
  }>(`/api/agents/${id}/reenroll` + qs({ project }), { method: 'POST' }),

  /** Stop it. Keeps the agent and everything it found; see the backend
   *  route for why this is not a delete. */
  killAgent: (project: string, id: number) =>
    req<JawsAgent>(`/api/agents/${id}/kill` + qs({ project }), { method: 'POST' }),
  deleteAgent: (project: string, id: number) =>
    req<void>(`/api/agents/${id}` + qs({ project }), { method: 'DELETE' }),

  jawsDownloads: () => req<{
    builds: Array<{ os: string; arch: string; name: string
                    available: boolean; bytes: number }>
    any: boolean
  }>('/api/agents/downloads'),
  /** The binary itself is a normal authenticated GET; the cookie goes
   *  with it, so a plain link works and the browser streams it. */
  jawsDownloadUrl: (goos: string, arch: string) =>
    `/api/agents/download/${encodeURIComponent(goos)}/${encodeURIComponent(arch)}`,
  reachAgent: (project: string, id: number) =>
    req<{ ok: boolean; detail: string; status: Record<string, unknown> | null }>(
      `/api/agents/${id}/reach` + qs({ project }), { method: 'POST' }),

  jawsRouting: (project: string) =>
    req<JawsRouting>('/api/agents/routing' + qs({ project })),
  setJawsRouting: (project: string, mode: string) =>
    req<JawsRouting>('/api/agents/routing' + qs({ project }),
      { method: 'PUT', body: JSON.stringify({ mode }) }),
  /** Queue for the project rather than a named agent, so the routing
   *  mode decides which Jaws runs it. */
  queuePooledTask: (project: string, kind: string,
                    args: Record<string, unknown>, region?: string) =>
    req<JawsTask>('/api/agents/tasks' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ kind, args, region }) }),

  agentTasks: (project: string, id: number, limit = 50) =>
    req<JawsTask[]>(`/api/agents/${id}/tasks` + qs({ project, limit })),
  queueTask: (project: string, id: number, kind: string, args: Record<string, unknown>) =>
    req<JawsTask>(`/api/agents/${id}/tasks` + qs({ project }),
      { method: 'POST', body: JSON.stringify({ kind, args }) }),
  // The step that makes a scan count: a result arrives with no operator
  // attached, so anything the project has not seen is surveyed and
  // nothing is written until someone answers.
  importTaskResult: (project: string, agentId: number, taskId: number,
                     decisions: Record<string, HostDecision>) =>
    req<ImportResult>(`/api/agents/${agentId}/tasks/${taskId}/import` + qs({ project }),
      { method: 'POST', body: JSON.stringify({ decisions }) }),

  // --- slack handles ---
  /**
   * One person's Slack handle for one engagement.
   *
   * Three routes, one resource, one state: GET says whether to ask and
   * with what, POST records an answer and attempts the channel invites,
   * POST `/decline` stops the asking for this engagement. All three
   * return the same shape, so they are one call here — which also keeps
   * the response type written once rather than three times.
   *
   * `answer` omitted is the GET. It never writes, so it is safe to run
   * on opening a project.
   */
  slackMe: (project: string,
            answer?: { handle: string; save_as_default: boolean }
                     | 'decline' | 'adopt') =>
    req<{
      slack_enabled: boolean
      /** Ask now: Slack is on for this project and this person has
       *  neither confirmed a handle nor declined FOR THIS WORKSPACE.
       *  Scoped to the workspace rather than the engagement — a handle
       *  given once should not be asked for again because a second
       *  engagement started in the same Slack. */
      prompt: boolean
      /** A handle is on record for this workspace, but they are not in
       *  this engagement's channel yet. Offer to add them instead of
       *  asking a question they have answered. */
      can_adopt: boolean
      /** Their profile default, for the one-click answer. */
      default_handle: string | null
      /** What they already gave for THIS project, which may differ from
       *  the default — a consultant can be in the client's workspace
       *  under another name. */
      handle: string | null
      confirmed: boolean
      declined: boolean
      channels: string[]
      /** Verbatim from the server: `channel: added` or `channel: <reason>`
       *  per destination, joined with "; ". An invite can fail — commonly
       *  because the person is not in the Slack workspace yet — and this
       *  is the only place that says so. */
      invite_result: string | null
    }>(`/api/projects/${encodeURIComponent(project)}/slack/me`
         + (answer === 'decline' ? '/decline'
            : answer === 'adopt' ? '/adopt' : ''),
      answer === undefined ? undefined : {
        method: 'POST',
        // The decline route takes no body; an empty object keeps the
        // Content-Type honest rather than sending `null`.
        body: JSON.stringify(
          answer === 'decline' || answer === 'adopt' ? {} : answer),
      }),
  // --- user invites ---
  /**
   * Create an account from an email address and invite its owner to it,
   * granting the projects named in one step.
   *
   * `password` is only for a deployment with no SMTP, where no invitation
   * can be sent. With mail configured, leave it out: the account is created
   * with no password at all until its owner sets one through the link.
   *
   * Collisions are 409s, never merges — the server will not attach an
   * invitation to an account that already exists. `invited: false` with a
   * 201 means the account and grants were created but the email did not go
   * out; `detail` says why and the per-row Invite button retries.
   */
  inviteUser: (b: {
    email: string
    full_name?: string
    /** Omit to let the server derive it from the address. */
    username?: string
    password?: string
    grants: Array<{ project: string; role: string }>
  }) => req<{ user: User; invited: boolean; detail: string; grants: Acl[] }>(
    '/api/users/invite', { method: 'POST', body: JSON.stringify(b) }),
  // --- end user invites ---
  // --- targets enumerate ---
  // Shapes are written inline rather than as exported interfaces so the
  // whole addition stays in one fenced block; other sessions are editing
  // this file and a type declaration three hundred lines up is the part
  // that does not merge. Consumers derive them with
  // `Awaited<ReturnType<typeof api.enumeratePending>>[number]`.

  /** Finished Jaws lookups whose answer the inventory does not carry yet.
   *
   *  The raw task output is not on TaskOut and should not be — the agent
   *  list would then haul every scan's output — so the server reads it
   *  and returns only the choice. Derived, never stored: applying one
   *  makes it stop being returned. */
  enumeratePending: (project: string) =>
    req<Array<{
      task_id: number
      /** reverse_ip (address → names) or nslookup (name → addresses). */
      kind: string
      subject: string
      target_host: string
      field: 'host' | 'ip_address'
      options: string[]
      /** A source did not answer, so `options` is a floor, not a total. */
      partial: boolean
      note: string | null
      finished_at: string | null
    }>>('/api/enumerate/pending' + qs({ project })),

  /** Write a chosen lookup answer onto the target. Refuses a rename that
   *  would collide with another target rather than merging the two. */
  enumerateResolve: (project: string, body: {
    host: string; field: 'host' | 'ip_address'; value: string
    /** Every name the lookup returned, not only the chosen one. The
     *  server records the rest against the target: an address
     *  answering to several names is usually shared hosting or a load
     *  balancer, and those others are leads worth keeping. */
    also_resolved?: string[]
  }) =>
    req<{ host: string; ip_address: string | null }>(
      '/api/enumerate/resolve' + qs({ project }),
      { method: 'POST', body: JSON.stringify(body) }),

  /** The project's included CIDR scope, with how many targets sit in
   *  each. `targets: 0` means nothing there has been looked at — which
   *  is not the same claim as the range being empty. */
  enumerateRanges: (project: string) =>
    req<Array<{ value: string; kind: string; addresses: number; targets: number }>>(
      '/api/enumerate/ranges' + qs({ project })),
  /** What this engagement will actually do with Slack, resolved.
   *  Three of these are not stored on the project — a project with no
   *  channel still has one, derived from its codename and the site
   *  prefix, and whether anything is sent at all depends on tokens
   *  rather than on the channel. A page showing only the stored
   *  fields would be misleading. */
  projectSlack: (project: string) => req<{
    /** A token resolves AND its channel exists. Both, because a token
     *  on its own posts into a channel_not_found. */
    active: boolean
    token_resolves: boolean
    channel_state: 'present' | 'missing' | 'unknown' | 'no_token'
    channel_checked_at: string | null
    channel: string
    channel_is_explicit: boolean
    delivery: 'site' | 'override' | 'both'
    site_token_set: boolean
    project_token_set: boolean
    private: boolean
    /** Why it is off, when it is. Empty when it is on. */
    inactive_reason: string
  }>(`/api/projects/${encodeURIComponent(project)}/slack`),

  /** Ask Slack which engagement channels actually exist. One listing
   *  call per distinct bot token, so this covers every project at
   *  roughly the cost of covering one. Omit `project` for all of them. */
  refreshSlackChannels: (project?: string) => req<{
    checked: number
    states: Record<string, number>
    projects: Record<string, 'present' | 'missing' | 'unknown' | 'no_token'>
  }>('/api/projects/slack/refresh' + qs({ project }), { method: 'POST' }),
  setProjectSlack: (project: string, body: {
    channel?: string; delivery?: string; token?: string
    private?: boolean; create?: boolean
  }) => req<Awaited<ReturnType<typeof api.projectSlack>>>(
    `/api/projects/${encodeURIComponent(project)}/slack`,
    { method: 'PUT', body: JSON.stringify(body) }),

  /** What merging one target into another would do. Writes nothing —
   *  fetched and shown before the operator is asked to confirm. */
  mergePlan: (project: string, host: string, into: string) => req<{
    source: string; destination: string
    services_moved: number; vulns_moved: number; pocs_moved: number
    web_moved: number; implants_moved: number; events_moved: number
    /** Ports on both sides. The records are combined, not dropped. */
    service_conflicts: string[]
    implant_conflicts: string[]
    /** Byte-identical captures already held. The only thing a merge
     *  actually removes. */
    web_duplicates: number
    fields_filled: string[]
    fields_differing: string[]
    warnings: string[]
  }>('/api/enumerate/merge-plan' + qs({ project, host, into })),

  /** Fold one target into another. The destination survives. */
  mergeTargets: (project: string, host: string, into: string) =>
    req<{ ok: boolean; surviving: string; removed: string; summary: string }>(
      '/api/enumerate/merge' + qs({ project, host }),
      { method: 'POST', body: JSON.stringify({ into, confirm: true }) }),

  /** What deleting a project would destroy. Counted, not estimated. */
  deletionPreview: (project: string) => req<{
    code: string; targets: number; services: number; vulns: number
    pocs: number; credentials: number; agents: number
    /** Non-empty when agents would go with it — the one consequence
     *  that reaches outside this database. */
    agent_warning: string
  }>(`/api/projects/${encodeURIComponent(project)}/deletion`),

  /** Delete a project and everything in it. The code must be passed
   *  back; the server refuses otherwise, so this cannot be done by a
   *  stray scripted DELETE either. */
  deleteProject: (project: string) =>
    req<void>(`/api/projects/${encodeURIComponent(project)}`
              + qs({ confirm: project }), { method: 'DELETE' }),

  // --- project scope ---
  // The shapes are written inline rather than as exported interfaces so
  // this block stays one contiguous addition; ProjectConfigView derives
  // its types from these signatures, so there is still only one
  // definition. Note `kind` includes 'wildcard' and 'country', which the
  // older ScopeEntry above predates.
  projectConfig: (project: string) =>
    req<{
      project: Project
      scope: Array<{
        id: number
        kind: 'cidr' | 'ipv4' | 'ipv6' | 'fqdn' | 'wildcard' | 'country'
        value: string
        included: boolean
        /** Operator-declared, never looked up. Null is "undetermined",
         *  which is a different claim from "no country". */
        country: string | null
        notes: string | null
      }>
      /** Whether anything in the lists could refuse anything. */
      scope_defined: boolean
      /** Once true the project may not acquire anything outside the list. */
      allowlist_active: boolean
    }>(`/api/projects/${encodeURIComponent(project)}/config`),

  updateProject: (project: string, body: {
    name?: string; client?: string | null; codename?: string | null
    description?: string | null; status?: string
  }) =>
    req<Project>(`/api/projects/${encodeURIComponent(project)}`,
      { method: 'PATCH', body: JSON.stringify(body) }),

  /** Append entries. `included` picks the list; a line's own leading `!`
   *  still wins, because that is how scope documents are pasted. */
  addProjectScope: (project: string, body: {
    lines?: string[]; countries?: string[]; included?: boolean
    country?: string | null
  }) =>
    req<ProjectCreated>(`/api/projects/${encodeURIComponent(project)}/scope`,
      { method: 'POST', body: JSON.stringify(body) }),

  patchProjectScope: (project: string, entryId: number, body: {
    included?: boolean; country?: string | null; notes?: string | null
  }) =>
    req<{ id: number; kind: string; value: string; included: boolean
          country: string | null; notes: string | null }>(
      `/api/projects/${encodeURIComponent(project)}/scope/${entryId}`,
      { method: 'PATCH', body: JSON.stringify(body) }),

  deleteProjectScope: (project: string, entryId: number) =>
    req<void>(`/api/projects/${encodeURIComponent(project)}/scope/${entryId}`,
      { method: 'DELETE' }),

  /** Which hosts the project already holds that the lists would refuse.
   *  Read-only: nothing is deleted until `applyProjectScope`. */
  scopeViolations: (project: string) =>
    req<ScopeApplyResult>(
      `/api/projects/${encodeURIComponent(project)}/scope/violations`),

  /** `remove` needs the hosts named. Applying to "whatever the report
   *  said" acts on a list that may have moved since it was read, and the
   *  server refuses it for the same reason. */
  applyProjectScope: (project: string, action: 'report' | 'remove' | 'ignore',
                      hosts: string[] = []) =>
    req<ScopeApplyResult>(
      `/api/projects/${encodeURIComponent(project)}/scope/apply`,
      { method: 'POST', body: JSON.stringify({ action, hosts }) }),
}

/** The violation report, shared by the read and the apply. */
export interface ScopeApplyResult {
  project: string
  scope_defined: boolean
  violations: Array<{
    id: number
    host: string
    ip_address: string | null
    /** 'barred' — on the out-of-scope list, nothing may touch it.
     *  'outside' — an in-scope list exists and this is not on it, so it
     *  could not be added today. The two want different answers. */
    verdict: 'barred' | 'outside'
    reason: string
    services: number; vulns: number; pocs: number
  }>
  action: string
  removed: string[]
  detail: string
}
