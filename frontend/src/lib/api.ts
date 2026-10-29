/** Typed client for the Oddjob API. Mirrors backend/app/schemas.py. */

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface WebAsset {
  id: number
  url: string
  host: string | null
  kind: string
  third_party: boolean
  name: string | null
  /** null means the URL did not say — a fingerprinted bundle. NOT
   *  "current": unknown and up-to-date are different answers. */
  version: string | null
  seen_on: number
  sha256: string | null
  bytes: number | null
  content_type: string | null
  status_code: number | null
  fetched: boolean
  first_page: string | null
  /** The pages that pull this in. The asset holds the bytes once;
   *  these are the sightings. */
  loaded_by: string[]
  /** What this asset is CARRYING: findings raised out of its own
   *  bytes, not findings on the host that serves it. A CDN bundle's
   *  host is somebody else's infrastructure; the bundle is ours to
   *  answer for. */
  vulns: number
  criticals: number
  highs: number
  /** Counted apart from the total. A stored credential is not a
   *  severity — it is the one finding somebody goes looking for by
   *  name, and burying it in a total is how it gets missed. */
  secrets: number
}

export interface Project {
  id: number; code: string; name: string; client: string | null
  /** The operation's internal name — a client code is ACME, its operation name FALCON.
   *  The code is the client's and goes in their deliverables; the
   *  codename is what the scan directories and Slack channels use. */
  codename: string | null
  description: string | null; status: string
  /** Standing orders: work the project does on its own as hosts
   *  arrive. All default off — each one queues scans at a client. */
  auto_amass: boolean
  auto_resolve_ips: boolean
  auto_reverse_dns: boolean
  /** 'off' | 'top100' | 'full'. Not a boolean: the hundred commonest
   *  ports and all 65,535 are hours apart in traffic at the far end. */
  auto_nmap: string
  /** 'off' | 'crawl' | 'gobuster' | 'both'. Crawling follows what the
   *  application links to; content discovery asks for what it does
   *  not, so neither covers the other. */
  auto_web: string
  auto_nuclei: string
  /** Ask each web origin what OTHER names it answers to. */
  auto_vhost: boolean
  /** Probe every URL the project knows. */
  auto_httpx: boolean
  /** Everything on, at its most thorough. Resolved by the server when
   *  the policies are read rather than copied into the fields above,
   *  so turning it off returns the project to whatever was set
   *  before. Does NOT imply the lookups that send the client's domain
   *  to a third party. */
  kitchen_sink: boolean
  /** Extra content-discovery paths, one per line. APPENDED to the
   *  wordlist the agent carries, never replacing it. */
  url_wordlist: string | null
  /** What tools that send a User-Agent should call themselves. null
   *  means the agent's own attributable default. */
  user_agent: string | null
  /** The other two sentences in the authorisation letter. The scope
   *  list has always been enforced config; these are now too.
   *
   *  null at either end means UNBOUNDED — which is what every project
   *  had before this existed, and is not the same as "starts now". */
  engagement_starts_at: string | null
  engagement_ends_at: string | null
  /** The most intrusive technique this engagement permits:
   *  read_only | state_changing | destructive. Defaults to
   *  `destructive`, i.e. everything, because this arrived after
   *  engagements were already running. */
  max_impact: string
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
  /** The first address observed, or null. A host legitimately has
   *  several — an A record, a AAAA record, more behind a load balancer
   *  — so this is a convenience for the places that can show one, and
   *  `ip_addresses` is the whole truth. */
  ip_address: string | null
  /** Every address, oldest observation first. */
  ip_addresses: string[]
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
  /** Which provider naming template this host's NAME matches, e.g.
   *  `gcp-compute`, or null for a name somebody chose.
   *
   *  Derived server-side from the hostname — see
   *  backend/app/cloudnames.py. It says nothing about whether the
   *  host matters: a `*.bc.googleusercontent.com` with an open port
   *  is a finding, the PTR just is not its name. */
  cloud_family: string | null
  /** Which cloud, when the name is a provider template. */
  cloud_provider: string | null
  /** True when the provider assigns the name per address, so it
   *  carries no information about who is using it. These are the
   *  rows worth condensing; a name chosen inside a cloud is not. */
  cloud_ephemeral: boolean
  /** ISO code of the first located address, or null when none has
   *  been. Read `geo_pending` before reading null as "not known": a
   *  null with addresses still unlooked-up means nobody asked. */
  geo_country: string | null
  geo_country_name: string | null
  /** Every distinct country this host's addresses are in. More than
   *  one is normal behind a CDN or an anycast front, and is usually
   *  the most interesting thing on the row. */
  geo_countries: string[]
  /** Addresses never looked up. Non-zero means the blank is a gap in
   *  our coverage, not a fact about the host. */
  geo_pending: number
  total_vulns: number; total_criticals: number; total_highs: number
  total_pocs: number; total_ports: number
  created_at: string; updated_at: string
}

/** The state of, or the result of, locating a project's addresses.
 *
 *  Three outcomes rather than two, deliberately: `located` is an
 *  answer, `unknown` means asked and the databases hold nothing, and
 *  `remaining` means never asked. Collapsing the last two is how a
 *  coverage gap comes to read as a finished job. */
export interface GeoReport {
  /** False when geolocation is off or no database is installed. A
   *  configuration state, not an error — `note` says which switch. */
  usable: boolean
  note: string
  /** address -> "Tokyo, Japan (AS2497 Internet Initiative Japan)" */
  located: Record<string, string>
  unknown: string[]
  /** Never asked. After a run, what the batch limit left behind. */
  remaining: number
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
  /** What a PERSON concluded, as opposed to `status`, which is what
   *  has been done about it. Defaults to `needs_investigating`:
   *  a scanner has not decided anything. */
  triage: string
  port: number | null; protocol: string | null
  description: string | null; remediation: string | null
  external_id: string | null
  created_at: string; updated_at: string

  /** Which tool reported it. null for a finding somebody typed in,
   *  and for anything imported before the lifecycle existed. */
  scanner: string | null
  /** When a scan first reported it and when one last did. NOT
   *  created_at/updated_at, which move when somebody edits a
   *  severity or writes a remediation. */
  first_seen_at: string | null
  last_seen_at: string | null
  /** new | present | resolved | unconfirmed.
   *
   *  Four, not three. `unconfirmed` means nothing that reports this
   *  kind of finding has looked since it was last seen — it is a
   *  real answer and not a hedged `resolved`. */
  lifecycle: string
  /** The sentence behind that word. `resolved` is a claim, and a
   *  reader is entitled to see what it rests on. */
  lifecycle_why: string | null
  /** When a tool that reports this kind of finding last looked at
   *  this host. null means never. */
  last_looked_at: string | null
}

/** What changed between the last scan and the one before it. */
export interface VulnLifecycle {
  project_code: string
  counts: Record<string, number>
  meaning: Record<string, string>
  /** Per scanner: when it last looked, and at how many hosts. Makes
   *  the counts readable — "0 resolved" from a tool that has not run
   *  in six weeks is not good news. */
  scanners: { scanner: string; hosts: number; last_looked_at: string | null }[]
  unconfirmed_hosts: string[]
}

/** One host carrying the same finding. */
export interface VulnOccurrence {
  id: number; target_id: number; host: string; project_code: string
  port: number | null; protocol: string | null
  status: string; severity: string
}

/** One stored credential, with the asset it was found in.
 *
 *  `asset_url`/`path`/`line` are null when the origin was never
 *  recorded in columns — rows written before they existed whose
 *  description did not parse. That is "not recorded", not "no
 *  URL", and the table says so rather than showing a blank. */
/** The file a credential was found in, positioned on it.
 *
 *  `body` may be a WINDOW rather than the whole file: a `raw` bundle
 *  is routinely megabytes on one line, and sending all of it to
 *  highlight forty characters in the middle is what `offset` and
 *  `first_line` exist to avoid.
 *
 *  `match_start`/`match_end` are character offsets INTO `body`, not
 *  into the file — the window is already subtracted. They are what
 *  the highlight uses: a line number names the whole of a minified
 *  file and so points at nothing. */
/** One readable rendering of the asset a credential sits in. */
export interface SourceView {
  origin: string
  path: string
  bytes: number
  /** Produced for this request rather than read from storage — so
   *  its line numbers have never been stored and cannot be quoted. */
  generated: boolean
  /** The file the finding was recorded against. Only this one has a
   *  meaningful `line`. */
  recorded: boolean
}

export interface SecretSource {
  path: string
  /** raw | beautified | source. A line in `beautified` is a line in
   *  a file we produced, not in the developer's own source. */
  origin: string
  generated: boolean
  /** The origin of the file the finding was RECORDED against, which
   *  is not always the one on screen. */
  recorded_origin: string
  /** Every rendering that can be asked for. */
  views: SourceView[]
  asset_url: string | null
  line: number | null
  body: string
  total: number
  offset: number
  first_line: number
  truncated: boolean
  match_start: number | null
  match_end: number | null
  /** confirmed | moved | found | absent — see the endpoint. Four
   *  answers, because scrolling confidently to the wrong place is
   *  worse than saying the file has shifted, and quoting a line from
   *  a rendering the scanner never read is worse again. */
  located: string
}

export interface SecretRow {
  vuln_id: number
  secret: string
  detector: string | null
  asset_url: string | null
  path: string | null
  line: number | null
  host: string | null
  project_code: string
  severity: string
  triage: string
  title: string
}

/** A finding in full, with every host it was found on. */
export interface VulnsByTargetRow {
  host: string
  project_code: string
  total: number
  critical: number; high: number; medium: number; low: number; info: number
}

/** A rollup, and whether it is all of it. A bare list cannot say
 *  "there was more", and on FALCON the by-title rollup is 5,013 rows
 *  — a limit that cut it silently would look complete. */
export interface Rollup<T> { items: T[]; truncated: boolean }

/** One finding AT one severity.
 *
 *  Unique on (title, severity), not title alone: the same title does
 *  arrive at two severities because scanners disagree, and rolling
 *  those together forces a choice between reporting the worst — which
 *  overstates the other — and listing both in a cell that cannot be
 *  sorted or counted. Two rows states it plainly. */
export interface VulnsByTitleRow {
  title: string
  severity: string
  hosts: number
  total: number
}

export interface VulnDetail extends Vuln {
  has_secret?: boolean
  occurrences: VulnOccurrence[]
  /** Whether the hosts were grouped by identifier or by title. */
  grouped_by: string
  /** When a later scan could not clear this finding because it was
   *  configured differently, WHICH part changed. Empty when there is
   *  nothing to say — "the configuration changed" on its own is a
   *  dead end for whoever reads it. */
  configuration_changed: string[]
}

export interface Poc {
  id: number; target_id: number; host: string; project_code: string
  title: string; status: string; path: string | null
  exit_code: number | null; notes: string | null
  created_at: string; updated_at: string
}

/** One place a target was discovered in.
 *
 *  A cloud resource is in no CIDR, nothing links to it and no port
 *  scan meets it — the file that named it is the only reason we know
 *  it exists, and this is that file.
 *
 *  **An empty list means NOT RECORDED, never "found nowhere".** Only
 *  the code that discovers a target writes provenance, and only the
 *  asset sweep does: a target typed in by hand, loaded from a scan
 *  import or created before this existed has none, and nothing in the
 *  system knows where it came from. Rendering that as an absence of
 *  sources would state a fact nobody established. */
export interface TargetOrigin {
  id: number; target_id: number
  /** `asset` — named in the code of a web asset this project fetched. */
  source: string
  /** The bundle the identifier was read out of. Snapshotted at
   *  discovery, so it outlives the asset being refetched or deleted. */
  asset_url: string | null
  /** Which recovered file inside that bundle. `src/config.ts` out of a
   *  source map says far more than "somewhere in app.min.js". */
  file_path: string | null
  /** The page that bundle was first seen on. */
  page_url: string | null
  /** Every page known to load that bundle, capped — read live from
   *  the page references, because a page crawled later genuinely is
   *  another site this resource was found on. */
  pages: string[]
  pages_total: number
  /** Hostname of the page it was found on, for a one-value cell.
   *  Null when no page is known, which is not the same as none. */
  site: string | null
  created_at: string
}

export interface TargetDetail {
  target: Target; services: Service[]; vulns: Vuln[]; pocs: Poc[]
  implants: Implant[]
  /** Where this target came from. Empty means nothing recorded it —
   *  see `TargetOrigin`. */
  origins: TargetOrigin[]
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
/** A name pointing at a service that hands out subdomains to whoever
 *  asks first.
 *
 *  `verdict` is not a severity, and the four values do not point the
 *  same way. `dangling` and `fingerprint` are evidence the name is
 *  unclaimed; `live` is evidence it is claimed and serving, which is
 *  the answer most of the time; `candidate` is the absence of all
 *  three, kept visible because "points at Heroku, could not check"
 *  is a real state and not a finding. See backend/app/takeover.py. */
export interface Takeover {
  id: number
  hostname: string
  cname: string
  cname_chain: string[]
  provider: string
  /** False when the name is not freely re-registerable — the record
   *  still dangles, but it is hygiene rather than a hostile takeover. */
  claimable: boolean
  verdict: 'dangling' | 'fingerprint' | 'live' | 'candidate'
  evidence: string | null
  state: string
  note: string | null
  target_id: number | null
  seen_at: string | null
  /** How hard it would ACTUALLY be to take the name. Derived from the
   *  provider's claim process, capped by how much evidence there is:
   *  an unchecked row is never better than `hard`, however easy the
   *  provider. */
  difficulty: 'easy' | 'medium' | 'hard' | 'impossible'
  /** What that difficulty means as a finding severity. */
  severity: string
  /** What an operator would do, in order. Present whatever the
   *  difficulty — an `impossible` row carries the reason and what to
   *  do instead. */
  steps: string[]
}

/** A SOCKS5 credential for one ghost. Never carries the password:
 *  that is returned once, by the call that makes it. */
export interface ProxyGrant {
  id: number
  username: string
  note: string | null
  created_at: string | null
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
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
/** `searched` is always false now that nothing generates names to search
 *  for. Kept so an older client does not break on a missing field. */
export interface DomainRoot { domain: string; known_hosts: number; searched: boolean }
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
/** One message in a shared agent thread. */
export interface AgentTurn {
  id: number
  seq: number
  role: 'user' | 'assistant'
  text: string
  steps: AgentStep[]
  /** Who typed it, for a user turn. The point of sharing the thread
   *  is knowing which of you already asked. */
  author: string | null
  at: string | null
}

/** An agent conversation, owned by the ENGAGEMENT rather than by the
 *  browser that started it. Switching project lands on that
 *  project's threads, never carries this one across. */
export interface AgentSession {
  id: number
  project_code: string
  title: string | null
  opened_by: string | null
  closed: boolean
  at: string | null
  turns: AgentTurn[]
}

/** One thread without its turns — what a tab is drawn from.
 *
 *  The list is the ENGAGEMENT's open threads, not this browser's
 *  tabs: a thread a colleague opened is one you can pick up, which
 *  is the same reason the transcript itself lives on the server. */
export interface AgentSessionBrief {
  id: number
  project_code: string
  title: string | null
  opened_by: string | null
  closed: boolean
  at: string | null
  turn_count: number
}

export interface AgentReply {
  text: string; provider: string; model: string
  steps: AgentStep[]; stop_reason: string
  usage: Record<string, number>; history: unknown[]
  /** Which thread it landed in. Null only in the all-engagements
   *  mode, which has no single project to own a thread. Needed when
   *  the first message of a project opens one: that is the only way
   *  the client learns the id it must then address. */
  session_id: number | null
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

/** A Ghost instance. Bound to exactly one project, for its whole life. */
/** A task as the tasks table shows it. Distinct from `GhostTask`,
 *  which is the per-agent record: this one carries the pooled tasks
 *  no agent owns, and the words an operator reads rather than the
 *  words the column stores. */
export interface GhostTaskRow {
  id: number
  kind: string
  subject: string
  /** awaiting | in progress | complete | failed. What an operator
   *  reading a table means by the stored queued/claimed/running
   *  /done/failed. */
  state: string
  raw_status: string
  agent_id: number | null
  agent_name: string | null
  attempts: number
  created_at: string | null
  started_at: string | null
  finished_at: string | null
  /** Why it failed, or why it went back in the queue. Empty on a task
   *  that behaved. */
  notes: string | null
  requested_by: string | null
}

export interface GhostDebugLine {
  id: number
  agent_id: number
  agent: string
  at: string | null
  line: string
}

export interface GhostDebugOut {
  lines: GhostDebugLine[]
  /** Names of the agents currently collecting. An agent absent from
   *  this list has no lines because it was never asked for any —
   *  which looks identical to a quiet agent and is not the same. */
  debugging: string[]
  keep: number
}

export interface GhostAgent {
  id: number
  project_code: string
  name: string
  status: string
  /** Whether this ghost is shipping its own log back right now. */
  debug?: boolean
  platform: string | null
  arch: string | null
  version: string | null
  hostname: string | null
  privileged: boolean
  /** Whether this ghost will carry proxied browser traffic. Off
   *  unless somebody turned it on, per ghost. */
  proxy_enabled: boolean
  /** Whether its tunnel is up right now. Not stored anywhere — a
   *  tunnel is only true while its socket is, so this is false
   *  after a server restart until the ghost redials. */
  proxy_connected: boolean
  tools: Record<string, string>
  call_in_url: string | null
  last_seen: string | null
  /** Where the connection arrived from — the last hop, not the agent. */
  last_ip: string | null
  /** What the agent decided its host can run at once, and why. Null
   *  until it has reported. */
  capacity: number | null
  capacity_reason: string | null
  /** The effective limit: the operator's per-ghost override if set,
   *  otherwise the agent's own assessment, with the project ceiling
   *  on top of either. What the dispatcher honours. */
  max_parallel: number
  /** The operator's number for this one ghost, null when the agent is
   *  deciding. Separate from `max_parallel`, which is the result —
   *  they differ whenever the project ceiling is the binding one, and
   *  a box showing 5 when somebody typed 8 is how a control stops
   *  being trusted. */
  parallel_override: number | null
  /** What is executing right now — the work, not just a count. */
  running: Array<{
    id: number; kind: string; subject: string; started_at: string | null
  }>
  /** The agent's own answer for its internet-facing address. */
  outbound_ip: string | null
  /** How it got there: public-service, host-route,
   *  container-host-netns, container-internal, interface, unknown.
   *  Null from a Ghost too old to say. The six are not
   *  interchangeable — `container-internal` is a private address that
   *  will appear in nobody's logs — and they are all the same shape,
   *  so the label is the only thing that tells them apart. */
  outbound_ip_source: string | null
  /** Which lookup failed, what the address is not. Prose. */
  outbound_ip_note: string | null
  interfaces: string[]
  /** The OS of the machine underneath, where it differs from
   *  `platform`. A Linux container on WSL2 on Windows Server is
   *  platform=linux, host_platform=windows. Null means undetermined,
   *  which is not the same as linux. */
  host_platform: string | null
  /** The evidence, so the claim above can be checked. */
  host_platform_source: string | null
  /** The container runtime it is inside, null if none was detected.
   *  Not finding a marker is not proof there is no container. */
  container: string | null
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
  /** Empty means this ghost takes work anywhere, the default. */
  scan_countries: string[]
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
  agent: GhostAgent
  callback_key: string
  call_in_key: string
  /** One-time. The agent trades it for a keypair it generates itself. */
  enroll_token: string
  enroll_expires_at: string
  /** This Oddjob's public key. The agent pins it, so it will only ever
   *  take tasking from this instance. */
  server_public_key: string
}
export interface GhostRouting {
  mode: 'mesh' | 'primary' | 'geo'
  /** Who is serving right now in primary mode. Derived from live
   *  heartbeats — an observation, not a setting. */
  current_primary: number | null
  current_primary_name: string | null
  eligible: number
  unassigned_tasks: number
  /** What the fleet is doing now and what it got through in the last
   *  hour. A queue depth alone cannot say whether anything is
   *  happening — these turn a number into a direction. */
  running_tasks: number
  completed_last_hour: number
  /** The engagement's ceiling on simultaneous tasks per agent. An
   *  agent's own assessment of its host still applies; the lower of
   *  the two is what runs. */
  max_parallel: number
  /** ISO 3166-1 alpha-2 codes this engagement may test. Empty means
   *  everywhere, which is the default. */
  scan_countries: string[]
  /** Whether the country gate can answer at all: false when
   *  geolocation is off or no GeoLite2 database is on disk. The
   *  controls are disabled rather than offered and silently ignored. */
  geoip_available: boolean
}
export interface GhostTask {
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
export const GHOST_KINDS = ['nmap', 'masscan', 'amass', 'gobuster', 'nuclei',
  'httpx', 'nslookup', 'reverse_ip'] as const
export interface WebPacket {
  id: number; url: string; method: string | null; status_code: number | null
  host: string
  request: string | null; response: string | null
  /** The capture was cut at the import cap; this is not the whole thing. */
  truncated: boolean
  sources: string | null; notes: string | null
  /** The picture a ghost took of this URL, if one is on file.
   *  Metadata only — the image is its own request. */
  screenshot: WebShot | null
}

/** A stored screenshot, minus the bytes. */
export interface WebShot {
  id: number
  url: string
  /** Where the browser ended up, when it is not where it was sent. */
  final_url: string | null
  status_code: number | null
  title: string | null
  width: number | null
  height: number | null
  bytes: number
  sha256: string | null
  /** When the shutter went, not when the row was written. A picture
   *  is only as good as its date. */
  captured_at: string | null
  sources: string | null
}

/** Where the PNG itself lives. Fetched by the browser with the
 *  session cookie, like any other same-origin image. */
export const screenshotUrl = (id: number) =>
  `/api/web/screenshots/${id}/image`

/** A URL, standing for every exchange recorded against it. */
export interface WebGroup extends WebAddress {
  hits: number
  methods: string[]
  statuses: number[]
}

/** Where a replayed request went, and — once the ghost reports — what
 *  came back.
 *
 *  The POST answers the first half only. A replay leaves from a ghost
 *  inside the client's estate, never from the Oddjob server, so at the
 *  moment Send is pressed there is a task waiting for an agent and no
 *  response yet. `replayStatus` fills in the rest. */
export interface ReplayResult {
  task_id: number
  /** Which ghost. Part of the result: the egress address the packet
   *  leaves from is the whole reason this is not sent from the server. */
  agent: string
  agent_id: number
  /** idle | busy | absent — how far ahead of it the queue was. */
  dispatch: string
  /** queued | claimed | running | done | failed | cancelled */
  state: string
  note: string
  web: WebAddress | null
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
  /** Who FOUND the URL, as opposed to `crawled`, which is whether we
   *  fetched it. `discovery` means content discovery found it and no
   *  crawler did — the unlinked paths, which is most of what gobuster
   *  is for and which no amount of crawling would turn up. */
  found_by?: 'crawl' | 'discovery'
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
  /**
   * Set when a document with real size in it parsed to nothing at all.
   * "Found nothing" and "could not read it" are different answers;
   * this is the one that is usually a changed output format rather
   * than a clean estate.
   */
  parsed_nothing?: string | null
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
  /** An FQDN entry whose zone comes with it. Always false on the other
   *  kinds — a wildcard already says it and a range has no subdomains. */
  include_subdomains: boolean
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
  /** When this account last signed in. `null` means it never has,
   *  which is what an invited account looks like until the link is
   *  used -- and the only state in which an invite makes sense. */
  last_login_at: string | null
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

  /** One project, for the views that need its settings rather than the
   *  whole list — the standing-orders bar reads this so a toggle shows
   *  what the server holds and not what the browser last sent. */
  project: (code: string) =>
    req<Project>(`/api/projects/${encodeURIComponent(code)}`),

  /** Hosts this project has never run nmap or masscan against.
   *  "Never tasked", not "has no ports" — see the endpoint. */
  /** Hosts that still owe a scan.
   *
   *  With no `technique` this is the old question: never tasked with
   *  nmap or masscan at all. With one it becomes "has THIS technique
   *  run, on these ports", and `gaps` carries the per-host remainder
   *  as an nmap spec — so the caller queues the gap rather than the
   *  whole range again. See app/portcoverage.py for the ordering that
   *  decides when one technique makes another redundant. */
  /** Cloud providers an engagement may be authorised against.
   *  Approving one adds its domains to the in-scope list; it does not
   *  widen scope to every tenant there, and no provider zone is ever
   *  enumerated regardless. */
  /** Third-party scripts, stylesheets and fonts the project's pages
   *  pull in. Dependencies, not addresses — the host serving them is
   *  usually a CDN and is barred as a target. */
  webAssets: (project: string, thirdParty?: boolean, contains?: string) =>
    req<{ items: WebAsset[]; total: number; third_party: number
          versioned: number; hosts: number; pages: number
          refs: { asset_id: number; page: string }[] }>(
      '/api/web/assets' + qs({ project,
        third_party: thirdParty === undefined ? undefined : String(thirdParty),
        // Matched against the FILE, in the database. The rows that
        // come back still carry no body — searching the contents and
        // showing the contents are different things, and shipping
        // every bundle to the browser to filter a table would be
        // tens of megabytes to render a column of filenames.
        contains: contains?.trim() || undefined })),

  /** One asset WITH the file itself.
   *
   *  Separate from the listing because `body` is the largest text the
   *  database holds; it is fetched when something actually asks to
   *  read it, which is one asset at a time. */
  webAsset: (id: number) =>
    req<WebAsset & {
      body: string; truncated: boolean
      /** What the scanners found IN this asset. `line` comes from the
       *  stored finding position where there is one, which is what
       *  lets the viewer scroll to it rather than hand back the whole
       *  bundle. */
      findings: Array<{
        id: number; title: string; severity: string
        scanner: string | null; external_id: string | null
        status: string; triage: string
        line: number | null; path: string | null
      }>
    }>(`/api/web/assets/${id}`),

  /** Grep the bundles whose bytes were actually pulled back.
   *
   *  `searched` is how many bodies there were to look at, which is
   *  the difference between "nothing matched" and "nothing has ever
   *  been fetched" — and the second is the default state, because
   *  fetching is opt-in per crawl. */
  searchAssets: (project: string, q: string,
                 mode: 'text' | 'secrets' = 'text') =>
    req<{
      mode: string; q: string; matches: number
      searched: number; stored: number; truncated: boolean
      assets: Array<{
        asset_id: number; url: string; host: string | null
        third_party: boolean; name: string | null; bytes: number | null
        capped: boolean
        hits: Array<{ offset: number; snippet: string; rule: string
                      confidence: string }>
      }>
    }>('/api/web/assets/search' + qs({ project, q, mode })),

  /** Subjects httpx or nuclei has not been pointed at yet.
   *
   *  `takes` is 'host' or 'url' and is not cosmetic: httpx probes a
   *  host to find what answers, nuclei needs a URL to request. */
  probePending: (project: string, tool: 'httpx' | 'nuclei',
                 kitchenSink = false) =>
    req<{ tool: string; subjects: string[]; count: number
          out_of_scope: number; considered: number
          takes: 'host' | 'url'; kitchen_sink: boolean; repeats: number }>(
      '/api/targets/probe-pending'
      + qs({ project, tool,
             kitchen_sink: kitchenSink ? 'true' : undefined })),

  cloudProviders: () =>
    req<{ key: string; name: string; domains: string[] }[]>('/api/projects/clouds'),
  /** URLs that still owe web discovery, and which kinds each owes.
   *  A URL and not a host: neither katana nor gobuster can be pointed
   *  at a bare hostname. */
  webPending: (project: string, mode: string, kitchenSink = false) =>
    req<{ urls: { url: string; host: string; owes: string[] }[]
          count: number; tasks: number; out_of_scope: number
          considered: number; mode: string; kitchen_sink: boolean
          by_kind: Record<string, number>
          /** Offered tasks that have been run before. Only non-zero
           *  with `kitchenSink`, which is the only way one is
           *  offered at all. */
          repeats: number }>(
      '/api/targets/web-pending'
      + qs({ project, mode,
             kitchen_sink: kitchenSink ? 'true' : undefined })),

  /** `kitchenSink` drops the "never tasked" filter and returns every
   *  host the project knows, still gated and still minus mobile. */
  unscannedTargets: (project: string, technique?: string, ports?: string,
                     kitchenSink = false) =>
    req<{ hosts: string[]; count: number; out_of_scope: number
          considered: number; kitchen_sink?: boolean
          technique?: string; ports_asked?: number
          gaps?: { host: string; ports: string; count: number }[] }>(
      '/api/targets/unscanned'
      + qs({ project, technique, ports,
             kitchen_sink: kitchenSink ? 'true' : undefined })),
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
  /** The same findings rolled up two ways. Aggregated on the SERVER:
   *  a project with 23,000 findings cannot be grouped in the browser,
   *  and the rows a tab shows are a few hundred either way. The
   *  findings behind a row are fetched only when it is expanded. */
  vulnsByTarget: (project: string, q?: string) =>
    req<Rollup<VulnsByTargetRow>>('/api/vulns/by-target' + qs({ project, q })),
  vulnsByTitle: (project: string, q?: string) =>
    req<Rollup<VulnsByTitleRow>>('/api/vulns/by-title' + qs({ project, q })),
  /** The findings behind one rollup row, fetched when it is expanded.
   *  `title` is an EXACT match, not the substring `q` does: a title
   *  that merely contains this one is a different finding. */
  vulnsForHost: (project: string, host: string) =>
    req<Page<Vuln>>('/api/vulns' + qs({ project, host, limit: 500 })),
  vulnsForTitle: (project: string, title: string, severity?: string) =>
    req<Page<Vuln>>('/api/vulns'
      + qs({ project, title, severity, limit: 500 })),
  /** New since the last scan, still present, resolved — and unknown.
   *
   *  Derived on the server per request from the sweep table, so a
   *  scan that finds something again revives it with nothing to
   *  clear first. */
  vulnLifecycle: (project: string) =>
    req<VulnLifecycle>('/api/vulns/lifecycle' + qs({ project })),
  /** Exact-match service lookup — distinct from `q`, which is a substring
   *  search across every column and would also match a banner. */
  servicesWhere: (o: { project?: string; port?: number; name?: string }) =>
    req<Page<Service>>('/api/services' + qs({ ...o, limit: 100000 })),
  explore: (o: { dimension: 'port' | 'service'; value: string; project?: string; protocol?: string }) =>
    req<Explore>('/api/explore' + qs(o)),
  targetDetail: (project: string, host: string) =>
    req<TargetDetail>(`/api/targets/${encodeURIComponent(project)}/${encodeURIComponent(host)}/detail`),
  /** Where the project's targets came from, keyed by target id.
   *
   *  One request for a whole page of rows: the Targets view renders
   *  thousands and a fetch per row is a fetch per row. A target
   *  MISSING from the map has no recorded origin — not an origin of
   *  nowhere. */
  targetOrigins: (project?: string) =>
    req<Record<string, TargetOrigin[]>>('/api/targets/origins' + qs({ project })),
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

  /** How many rows each `found_by` choice would show, under whatever
   *  other filters are in force. One query, so the chooser can say
   *  what it costs before it is clicked. */
  webSourceCounts: (p: WebQuery = {}) =>
    req<{ all: number; crawl: number; discovery: number }>(
      '/api/web/source-counts' + qs({ ...p })),

  /** Every exchange recorded for one URL. Drives the expanded row. */
  webByUrl: (target_id: number, url: string) =>
    req<Page<WebAddress>>('/api/web/by-url' + qs({ target_id, url, limit: 500 })),

  /** Turn SOCKS proxying on or off for one ghost. Admin only, and
   *  switching it off drops the live tunnel immediately. */
  setGhostProxy: (project: string, agentId: number, enabled: boolean) =>
    req<GhostAgent>(`/api/ghosts/${agentId}/proxy` + qs({ project }),
               { method: 'PATCH', body: JSON.stringify({ enabled }) }),

  /** Credentials issued for one ghost. Never the secrets. */
  proxyGrants: (project: string, agentId: number) =>
    req<ProxyGrant[]>(`/api/ghosts/${agentId}/proxy/grants` + qs({ project })),

  /** Issue one. The password comes back ONCE and is never retrievable. */
  newProxyGrant: (project: string, agentId: number,
                  body: { note?: string; expires_days?: number } = {}) =>
    req<{ grant: ProxyGrant; username: string; password: string }>(
      `/api/ghosts/${agentId}/proxy/grants` + qs({ project }),
      { method: 'POST', body: JSON.stringify(body) }),

  /** Revoke one. It stops working on the next connection. */
  revokeProxyGrant: (project: string, agentId: number, grantId: number) =>
    req<ProxyGrant>(
      `/api/ghosts/${agentId}/proxy/grants/${grantId}` + qs({ project }),
      { method: 'DELETE' }),

  /** Names in this engagement pointing at something unclaimed.
   *  Reads rows already decided; it resolves nothing itself. */
  takeovers: (p: { project?: string; verdict?: string; state?: string
                   q?: string; sort?: string; order?: string } = {}) =>
    req<Page<Takeover>>('/api/web/takeovers' + qs({ limit: 1000, ...p })),

  /** Re-derive the table from the CNAMEs currently on record. Sends
   *  nothing anywhere — the chains are already here. */
  refreshTakeovers: (project: string) =>
    req<{ counts: Record<string, number>; total: number }>(
      '/api/web/takeovers/refresh' + qs({ project }), { method: 'POST' }),

  /** Triage one row. Only state and note — the rest is DNS. */
  updateTakeover: (id: number, project: string,
                   body: { state?: string; note?: string }) =>
    req<Takeover>(`/api/web/takeovers/${id}` + qs({ project }),
                  { method: 'PATCH', body: JSON.stringify(body) }),

  /** Queue an edited request for a ghost to send. The result is a NEW
   *  row, so the original and the edit sit side by side under the same
   *  URL — but it exists only once the ghost has reported, so this
   *  returns the task to poll with `replayStatus`.
   *
   *  No `follow_redirects`: the ghost writes the request to a socket
   *  byte for byte, and following a redirect means building a second
   *  request out of the first one's parsed fields, which is the one
   *  thing that path must not do. A 302 is the answer. */
  replay: (id: number, raw: string, opts: {
    verify_tls?: boolean; timeout?: number } = {}) =>
    req<ReplayResult>(`/api/web/${id}/replay`, {
      method: 'POST', body: JSON.stringify({ raw, ...opts }) }),
  /** Has the ghost sent it yet, and what came back. */
  replayStatus: (taskId: number) =>
    req<ReplayResult>(`/api/web/replays/${taskId}`),
  /** Whether a Web view would have anything to show here. */
  webApplicable: (project?: string) =>
    req<{ applicable: boolean; web_services: number; web_addresses: number
          web_assets: number }>(
      '/api/web/applicable' + qs({ project })),
  webStats: (project?: string) =>
    req<{ total: number; crawled: number; hosts: number
          by_status: Record<string, number> }>('/api/web/stats' + qs({ project })),

  domainRoots: (project: string) =>
    req<DomainRoot[]>('/api/domains/roots' + qs({ project })),
  enumerateDomains: (project: string, domains: string,
                     mode: 'passive' | 'active' = 'passive',
                     /** Kitchen Sink Lookup: take every hostname the
                      *  project knows, drop the addresses, and walk each
                      *  name back to its registrable domain. `rescan`
                      *  re-queues domains already handed to amass. */
                     opts: { kitchenSink?: boolean; rescan?: boolean } = {}) =>
    req<{
      queued: Array<{ domain: string; task_id: number }>
      refused: Record<string, string>
      /** Already handed to amass for this project, so not sent again.
       *  Reported rather than dropped — "queued 12, skipped 30" is the
       *  only way the operator can tell a quiet run from a broken one. */
      skipped: Array<{ domain: string; runs: number
                       last_run_at: string | null }>
      /** Over the per-submission task cap. No search row is written for
       *  these, so the next Kitchen Sink run picks them up. */
      deferred: string[]
      agents_online: number
      mode: string
      kitchen_sink: boolean
      /** How many distinct domains the request considered, before scope,
       *  skipping and the cap. */
      considered: number
    }>('/api/domains/enumerate' + qs({ project }),
      { method: 'POST',
        body: JSON.stringify({ domains, mode,
                               kitchen_sink: !!opts.kitchenSink,
                               rescan: !!opts.rescan }) }),
  promoteDomains: (project: string, ids: number[]) =>
    req<{ created: string[]; already_existed: string[] }>(
      '/api/domains/candidates/promote' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ ids }) }),
  rejectDomains: (project: string, ids: number[]) =>
    req<{ rejected: string[] }>('/api/domains/candidates/reject' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ ids }) }),

  /** Every task on the engagement, newest first. The per-agent list
   *  answers "what has this scanner done"; this answers "what is
   *  happening here", which is the question with a queue in it. */
  ghostTasks: (project: string) =>
    req<GhostTaskRow[]>('/api/ghosts/tasks' + qs({ project })),

  /** Put a failed task back in the queue by hand. The automatic retry
   *  stops after two; this is what happens once a person has looked. */
  retryGhostTask: (project: string, id: number) =>
    req<GhostTaskRow>(`/api/ghosts/tasks/${id}/retry` + qs({ project }),
                  { method: 'POST' }),

  /** Everything waiting to run on this project, oldest first — the
   *  pool and work addressed to one agent that has not taken it. */
  ghostQueue: (project: string) => req<Array<{
    id: number; kind: string; subject: string
    args: Record<string, unknown>
    agent_id: number | null; agent_name: string | null
    region: string | null; requested_by: string | null
    created_at: string | null; status: string
  }>>('/api/ghosts/queue' + qs({ project })),

  /** Take a queued task back out. Refused once an agent has it: the
   *  scan is already running and deleting the row would only lose the
   *  result. */
  cancelGhostTask: (project: string, id: number) =>
    req<void>(`/api/ghosts/tasks/${id}` + qs({ project }),
              { method: 'DELETE' }),

  agentStatus: (project: string) =>
    req<AgentStatus>('/api/agent/status' + qs({ project })),
  /** Ask in one thread. `thread` omitted means the newest open one,
   *  which is what a caller with no tab strip gets. */
  agentChat: (project: string, message: string, history: unknown[],
              thread?: number) =>
    req<AgentReply>('/api/agent/chat' + qs({ project, thread }),
      { method: 'POST', body: JSON.stringify({ message, history }) }),
  /** This engagement's open threads, newest activity first. Everyone
   *  on the project sees the same list. */
  agentSessions: (project: string) =>
    req<AgentSessionBrief[]>('/api/agent/sessions' + qs({ project })),
  /** One of this engagement's agent threads, as everyone on it sees
   *  it. Null when the project has not been asked anything yet —
   *  which is different from an empty thread somebody started. */
  agentSession: (project: string, thread?: number) =>
    req<AgentSession | null>('/api/agent/session' + qs({ project, thread })),
  /** Open a fresh thread. `closeCurrent` true replaces the
   *  conversation, closing the one that was open — closing, never
   *  deleting: what was asked during an engagement is part of it.
   *  False leaves it running and opens one alongside, which is what
   *  a new tab is. */
  newAgentSession: (project: string, closeCurrent = true) =>
    req<AgentSession>('/api/agent/session/new'
                      + qs({ project, close_current: closeCurrent }),
      { method: 'POST', body: '{}' }),
  /** Close one thread, for everyone on the engagement — it is the
   *  engagement's thread, not your tab. It stays readable by id. */
  closeAgentSession: (project: string, thread: number) =>
    req<AgentSessionBrief>(`/api/agent/session/${thread}/close`
                           + qs({ project }),
      { method: 'POST', body: '{}' }),
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

  // Ghost agents. Every call is project-scoped because an agent is:
  // enrolled into one project, tasked only from that project, and its
  // results import only there.
  agents: (project: string) => req<GhostAgent[]>('/api/ghosts' + qs({ project })),
  /** What the fleet has been logging, newest first. */
  ghostDebug: (project: string, p: {
    agent_id?: number; limit?: number; contains?: string
  } = {}) =>
    req<GhostDebugOut>('/api/ghosts/debug' + qs({ project, ...p })),
  enrollAgent: (project: string, body: {
    name: string; connection_mode?: string; target_os?: string; notes?: string
  }) =>
    req<AgentEnrolled>('/api/ghosts' + qs({ project }),
      { method: 'POST', body: JSON.stringify(body) }),
  /** Rename, re-prioritise, set the regions it serves, or annotate it.
   *  Priority only matters in `primary` routing (lower goes first);
   *  regions only in `geo`. */
  patchAgent: (project: string, id: number, body: {
    name?: string; priority?: number; regions?: string; notes?: string
    /** Countries whose targets this ghost will accept. `[]` clears
     *  the restriction; omitting it leaves the list alone. */
    scan_countries?: string[]
    /** Collect this ghost's own log and send it back. Turning it off
     *  also discards what was already collected. */
    debug?: boolean
    /** Tasks this ghost may run at once. `0` clears the override and
     *  hands the decision back to the agent — `undefined` means "not
     *  supplied", so there has to be an explicit value for "undo". */
    parallel_override?: number
  }) =>
    req<GhostAgent>(`/api/ghosts/${id}` + qs({ project }),
      { method: 'PATCH', body: JSON.stringify(body) }),
  /** Rotate an agent's keys, keeping its record and history.
   *
   *  Its current identity stops being accepted immediately — a
   *  rotation that leaves the old key usable has rotated nothing — so
   *  the agent is dead until someone redeems the returned token on
   *  the host. The response says what to do there. */
  reenrollAgent: (project: string, id: number) => req<{
    agent: GhostAgent
    enroll_token: string
    enroll_expires_at: string
    server_public_key: string
    server_kex_public_key: string
    instructions: string
  }>(`/api/ghosts/${id}/reenroll` + qs({ project }), { method: 'POST' }),

  /** Stop it. Keeps the agent and everything it found; see the backend
   *  route for why this is not a delete. */
  killAgent: (project: string, id: number) =>
    req<GhostAgent>(`/api/ghosts/${id}/kill` + qs({ project }), { method: 'POST' }),
  deleteAgent: (project: string, id: number) =>
    req<void>(`/api/ghosts/${id}` + qs({ project }), { method: 'DELETE' }),

  ghostDownloads: () => req<{
    builds: Array<{ os: string; arch: string; name: string
                    available: boolean; bytes: number }>
    any: boolean
  }>('/api/ghosts/downloads'),
  /** The binary itself is a normal authenticated GET; the cookie goes
   *  with it, so a plain link works and the browser streams it. */
  ghostDownloadUrl: (goos: string, arch: string) =>
    `/api/ghosts/download/${encodeURIComponent(goos)}/${encodeURIComponent(arch)}`,
  reachAgent: (project: string, id: number) =>
    req<{ ok: boolean; detail: string; status: Record<string, unknown> | null }>(
      `/api/ghosts/${id}/reach` + qs({ project }), { method: 'POST' }),

  /** Record what somebody concluded about one finding. */
  setTriage: (vulnId: number, triage: string) =>
    req<{ changed: number; refused: number[] }>(
      `/api/vulns/${vulnId}/triage`,
      { method: 'PATCH', body: JSON.stringify({ triage }) }),

  /** The same verdict across a selection.
   *
   *  Triage is the bulk job — a scanner produces thousands of
   *  findings and most of a review is marking families of them at
   *  once. `refused` names anything the caller could not write to,
   *  rather than silently skipping it. */
  setTriageBulk: (ids: number[], triage: string) =>
    req<{ changed: number; refused: number[] }>(
      '/api/vulns/triage',
      { method: 'POST', body: JSON.stringify({ ids, triage }) }),

  /** The credential behind a secret finding.
   *
   *  Its own call, not a field on the vuln: a value returned by the
   *  detail endpoint is a value in every list and export that
   *  endpoint feeds. Needs the `user` role and is written to the
   *  audit log before it answers. */
  revealSecret: (vulnId: number) =>
    req<{ secret: string; detector: string | null }>(
      `/api/vulns/${vulnId}/secret`),

  /** Every stored credential, in clear, with where it came from.
   *
   *  Bulk and unmasked, which `revealSecret` deliberately is not.
   *  The job it serves is triaging several hundred of these at
   *  once; the guards that survive at that size are the `user`
   *  role per project and one audit entry per read. */
  secrets: (project?: string) =>
    req<SecretRow[]>('/api/secrets' + qs({ project })),

  /** The source around a credential. Same guards as `revealSecret`:
   *  it returns a file that CONTAINS the value, so it discloses
   *  everything that endpoint does and the surrounding code too. */
  secretSource: (vulnId: number, view?: string) =>
    req<SecretSource>(
      `/api/vulns/${vulnId}/secret/source` + qs({ view })),

  ghostRouting: (project: string) =>
    req<GhostRouting>('/api/ghosts/routing' + qs({ project })),
  /** Either field alone: changing the parallelism must not require
   *  restating the routing mode. */
  setGhostRouting: (project: string,
                   body: { mode?: string; max_parallel?: number
                           scan_countries?: string[] }) =>
    req<GhostRouting>('/api/ghosts/routing' + qs({ project }),
      { method: 'PUT', body: JSON.stringify(body) }),
  /** One task per subject, created server-side in one request.
   *
   *  The client used to POST once per subject, which is 1,738 requests
   *  for a reverse-lookup sweep. Scope is checked per subject and the
   *  refusals come back named: one target being out of scope is not a
   *  reason to refuse the rest. */
  /** `skipped` maps a subject to the task that already answered it with
   *  nothing. Set `rescanUnresponsive` to ask those again anyway. */
  queueTasksBulk: (project: string, kind: string, subjects: string[],
                   args: Record<string, unknown> = {},
                   agentId: number | null = null, region?: string,
                   rescanUnresponsive = false, rescan = false) =>
    req<{ ids: number[]; refused: Record<string, string>; queued: number
          skipped: Record<string, number>; already_queued?: string[]
          already_done?: string[] }>(
      '/api/ghosts/tasks/bulk' + qs({ project }),
      { method: 'POST',
        body: JSON.stringify({ kind, subjects, args, agent_id: agentId,
                               region: region || undefined,
                               rescan_unresponsive: rescanUnresponsive,
                               rescan }) }),

  /** Queue for the project rather than a named agent, so the routing
   *  mode decides which Ghost runs it. */
  queuePooledTask: (project: string, kind: string,
                    args: Record<string, unknown>, region?: string) =>
    req<GhostTask>('/api/ghosts/tasks' + qs({ project }),
      { method: 'POST', body: JSON.stringify({ kind, args, region }) }),

  agentTasks: (project: string, id: number, limit = 50) =>
    req<GhostTask[]>(`/api/ghosts/${id}/tasks` + qs({ project, limit })),
  queueTask: (project: string, id: number, kind: string, args: Record<string, unknown>) =>
    req<GhostTask>(`/api/ghosts/${id}/tasks` + qs({ project }),
      { method: 'POST', body: JSON.stringify({ kind, args }) }),
  // The step that makes a scan count: a result arrives with no operator
  // attached, so anything the project has not seen is surveyed and
  // nothing is written until someone answers.
  importTaskResult: (project: string, agentId: number, taskId: number,
                     decisions: Record<string, HostDecision>) =>
    req<ImportResult>(`/api/ghosts/${agentId}/tasks/${taskId}/import` + qs({ project }),
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

  /** Finished Ghost lookups whose answer the inventory does not carry yet.
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
      /** What the server will do with this, if anything.
       *
       *  auto     deterministic — `POST /api/enumerate/auto` applies it
       *  choice   genuinely ambiguous; a person picks
       *  blocked  nothing to pick. Scope refused it, somebody already
       *           refused it, or the lookup came back empty. Reported,
       *           never applied, and NOT a question — the fix is a
       *           scope edit, not a dropdown. */
      decision: 'auto' | 'choice' | 'blocked'
      /** One sentence saying what will happen, or why nothing will. */
      plan: string
      /** The subset of `options` that would actually be written. */
      applicable: string[]
      /** Each entry that will not be, and why. Named, never counted. */
      refused: Record<string, string>
    }>>('/api/enumerate/pending' + qs({ project })),

  /** Apply every lookup result whose answer is not in doubt.
   *
   *  Idempotent and safe on every refresh: the work list is derived
   *  from what the inventory is still missing, so a second call with
   *  nothing to do writes nothing. What counts as "not in doubt" is
   *  decided server-side — adding an address to a host we already hold
   *  never is, and anything that turns on an address being SHARED
   *  stays with a person. */
  enumerateAuto: (project: string) =>
    req<{
      /** host → the addresses it gained. */
      addresses_added: Record<string, string[]>
      /** Address-named rows that learned their name. */
      renamed: Record<string, string>
      /** Address-named rows folded into a target already held. */
      merged: Record<string, string>
      /** New targets created from the other names on a shared address. */
      created: string[]
      refused: Record<string, string>
      /** Still a person's decision, with the question. */
      deferred: Record<string, string>
    }>('/api/enumerate/auto' + qs({ project }), { method: 'POST', body: '{}' }),

  /** Write a chosen lookup answer onto the target.
   *
   *  An ADDRESS-named row taking a name the project already holds is
   *  merged into it — the operator ruled that automatic, and it is low
   *  risk because such a row is nearly always sparse. Two established
   *  FQDNs still refuse with a 409 and point at /api/enumerate/merge,
   *  where the plan is shown first. */
  enumerateResolve: (project: string, body: {
    host: string; field: 'host' | 'ip_address'; value: string
    /** Every name the lookup returned, not only the chosen one. The
     *  server records the rest against the target: an address
     *  answering to several names is usually shared hosting or a load
     *  balancer, and those others are leads worth keeping. */
    also_resolved?: string[]
    /** Of those others, the ones to create as targets in their own
     *  right. Scope decides, as everywhere else. */
    add?: string[]
    /** And the ones to refuse. Remembered rather than skipped, so
     *  domain detection does not propose them again next week. */
    deny?: string[]
  }) =>
    req<{
      host: string; ip_address: string | null
      ip_addresses: string[]
      /** Named rather than counted: "3 added" with no list is not
       *  something anybody can check, and `out_of_scope` is the half
       *  that most needs reading. */
      added: string[]
      denied: string[]
      out_of_scope: Record<string, string>
    }>('/api/enumerate/resolve' + qs({ project }),
      { method: 'POST', body: JSON.stringify(body) }),

  /** The project's included CIDR scope, with how many targets sit in
   *  each. `targets: 0` means nothing there has been looked at — which
   *  is not the same claim as the range being empty. */
  enumerateRanges: (project: string) =>
    req<Array<{ value: string; kind: string; addresses: number; targets: number }>>(
      '/api/enumerate/ranges' + qs({ project })),

  /** How many addresses have never been located, and whether we can
   *  locate them at all. Writes nothing. */
  enumerateGeolocation: (project: string) =>
    req<GeoReport>('/api/enumerate/geolocation' + qs({ project })),
  /** Locate every address that has not been looked up yet.
   *
   *  The one Enumerate action that sends no packets and needs no
   *  agent: it reads MaxMind's GeoLite2 files on the Oddjob host's
   *  own disk, and nothing about the estate leaves the installation.
   *
   *  Bounded per call — a non-zero `remaining` in the reply means
   *  press it again, not that it failed. */
  enumerateGeolocate: (project: string) =>
    req<GeoReport>('/api/enumerate/geolocate' + qs({ project }),
                   { method: 'POST', body: '{}' }),
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
        /** An FQDN entry whose zone comes with it: `acme.example` set
         *  this way also covers `a.acme.example`. Only ever true on an
         *  `fqdn`. */
        include_subdomains: boolean
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
    /** Standing orders. Admin only — the server answers 403 to anyone
     *  else, which is why the UI does not offer them to a plain user. */
    auto_amass?: boolean; auto_resolve_ips?: boolean
    auto_reverse_dns?: boolean; auto_nmap?: string; auto_web?: string;
    auto_nuclei?: string
    auto_vhost?: boolean; auto_httpx?: boolean; kitchen_sink?: boolean
    url_wordlist?: string | null; user_agent?: string | null
    /** The rules of engagement. ISO-8601 UTC for the dates.
     *
     *  `null` here means LEAVE ALONE, not clear — the server skips
     *  it deliberately, so a form that posts every field cannot
     *  remove an engagement's expiry on the way past while saving
     *  something else. Use `clearEngagementWindow`. */
    engagement_starts_at?: string | null
    engagement_ends_at?: string | null
    /** read_only | state_changing | destructive. */
    max_impact?: string
  }) =>
    req<Project>(`/api/projects/${encodeURIComponent(project)}`,
      { method: 'PATCH', body: JSON.stringify(body) }),

  /** What the standing orders that are ON have still not done.
   *
   *  An empty list means nothing is outstanding. It does NOT mean the
   *  estate is fully enumerated — a policy that is off has no gap by
   *  definition, which is why each entry names its policy. */
  standingOrderGaps: (project: string) =>
    req<{ policy: string; what: string; outstanding: number }[]>(
      `/api/projects/${encodeURIComponent(project)}/standing-orders/gaps`),

  /** Remove both engagement dates, leaving testing unbounded by date.
   *
   *  Its own call because a PATCH cannot do it: taking the bound off
   *  an authorisation has to be something somebody meant, and the
   *  server audits who did. */
  clearEngagementWindow: (project: string) =>
    req<void>(
      `/api/projects/${encodeURIComponent(project)}/engagement-window`,
      { method: 'DELETE' }),

  /** Append entries. `included` picks the list; a line's own leading `!`
   *  still wins, because that is how scope documents are pasted.
   *
   *  `include_subdomains` applies to the FQDN lines in the batch and is
   *  dropped on the rest. On an entry the project ALREADY has in scope
   *  the server refuses it and says so in `scope_errors` rather than
   *  widening a live allowlist from a re-paste — use `patchProjectScope`
   *  on that one entry. */
  addProjectScope: (project: string, body: {
    lines?: string[]; countries?: string[]; included?: boolean
    country?: string | null; include_subdomains?: boolean
  }) =>
    req<ProjectCreated>(`/api/projects/${encodeURIComponent(project)}/scope`,
      { method: 'POST', body: JSON.stringify(body) }),

  patchProjectScope: (project: string, entryId: number, body: {
    included?: boolean; country?: string | null; notes?: string | null
    include_subdomains?: boolean
  }) =>
    req<{ id: number; kind: string; value: string; included: boolean
          include_subdomains: boolean
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

  // site health and the audit trail — site admin only
  siteHealth: () => req<SiteHealth>('/api/health/site'),
  /** Download the configured GeoLite2 editions from MaxMind.
   *
   *  The one outbound request geolocation ever makes, and it carries
   *  no addresses — it is a file download. Every lookup afterwards is
   *  against that file on this host. Site admin only. */
  refreshGeoip: () => req<{
    ok: boolean
    /** edition -> "ok", or what went wrong with that one. Three
     *  downloads are three outcomes and one boolean cannot say which
     *  of them failed. */
    editions: Record<string, string>
    databases: Record<string, { size: number; built: string }>
  }>('/api/settings/geoip/refresh', { method: 'POST', body: '{}' }),
  auditLog: (f: AuditFilter = {}) => req<AuditPage>('/audit/json' + qs({ ...f })),
  /** The export is a download, not a fetch: it carries the filters so the
   *  file matches the table that was on screen, and the browser handles
   *  the Content-Disposition. */
  auditCsvUrl: (f: AuditFilter = {}) => '/audit/csv' + qs({ ...f }),
}

/** Three states, never two. `unused` is not a kind of healthy: a Slack
 *  integration nothing has ever sent through is neither working nor
 *  broken, and showing it as either is how a status page stops being
 *  read. `idle` is "it worked, but not lately". */
export type HealthState = 'ok' | 'idle' | 'failing' | 'unused'

export interface HealthBlock {
  state: HealthState
  note?: string | null
  last_ok?: string | null
  last_error_at?: string | null
  last_error?: string | null
  last_detail?: string | null
  ok_count?: number
  error_count?: number
  configured?: boolean
  [k: string]: unknown
}

/** One version, and how much of the fleet is on it.
 *
 *  `parsed` is false for anything that is not semver — an agent old
 *  enough to predate the VERSION file reports `dev`, and a `git
 *  describe` string from before that reports `v0.1.0-14-gdeadbee`.
 *  Those rows sort to the bottom and are shown as unorderable rather
 *  than as the oldest version, because they are not comparable at all. */
export interface GhostVersionRow {
  version: string
  count: number
  /** Whether this is the same version Oddjob itself is running. */
  matches_server: boolean
  /** A `-dev-<commit time>` build. Decided by the server so the view
   *  is not the second place that knows what a dev build looks like. */
  dev: boolean
  parsed: boolean
}

/** What the fleet is running, which is not the same question as what
 *  the newest ghost is running. A fleet split across three versions is
 *  the thing a site admin needs to see; "the newest one is 0.1.0" says
 *  nothing about the two that are not. */
export interface GhostFleetVersions {
  state: HealthState
  note: string | null
  /** Newest first. Unparseable versions last — see `parsed`. */
  versions: GhostVersionRow[]
  distinct: number
  /** Ghosts that reported a version. */
  reported: number
  /** Ghosts that have not. Counted separately and never folded into a
   *  bucket: "we do not know" is a third answer. */
  unreported: number
  newest: string | null
  matching_server: number
  server_version: string | null
}

export interface SiteHealth {
  generated_at: string
  server: HealthBlock & {
    /** Oddjob's own version, from the VERSION file at the repository
     *  root — the single place a version number is decided. */
    version: string
    /** True when that version carries the `-dev-` marker, i.e. this is
     *  an unreleased build. Stated by the server rather than inferred
     *  from the string here. */
    dev: boolean
    started_at: string; uptime_seconds: number; sse_subscribers: number
  }
  database: HealthBlock & {
    latency_ms?: number; dialect?: string; url?: string; size?: string
    pool?: { checked_out: number; in_pool: number }
    rows?: Record<string, number>
  }
  cve_feed: HealthBlock & { label: string; records: number; age_seconds?: number | null; synced?: string }
  exploit_feed: HealthBlock & { label: string; records: number; age_seconds?: number | null; synced?: string }
  slack: HealthBlock
  slack_socket: { connected: boolean; last: string | null }
  smtp: HealthBlock & { host?: string | null }
  /** MaxMind GeoLite2. `configured` is the licence key being present;
   *  `state` is whether a download has ever worked. Separate on
   *  purpose — a key that has never fetched anything is the common
   *  misconfiguration and one boolean cannot show it. */
  maxmind: HealthBlock & {
    configured: boolean
    enabled: boolean
    editions: string[]
    /** What is on disk, with each file's build date. GeoLite2 is
     *  rebuilt twice a week and a year-old database answers
     *  confidently and wrongly, so the age is the thing to see. */
    databases: Record<string, { size: number; built: string }>
  }
  ghosts: HealthBlock & {
    ghosts: Array<{ id: number; name: string; state: string; last_seen: string | null
                    age_seconds: number | null; missing_tools: string | null
                    /** Null when the ghost has never reported one. */
                    version: string | null }>
    by_state: Record<string, number>
    queue: Record<string, number>
    queued_over_an_hour: number
    versions: GhostFleetVersions
  }
  audit: HealthBlock & { newest: string | null; retain_days?: unknown }
  /** 24 hours of history for the cards that have any, oldest point
   *  first and every bucket present including the empty ones. Keyed
   *  by the same service names the rows above use. */
  series: Record<string, Array<{
    t: string; ok: number; errors: number
    /** Null for a bucket nobody measured in — a gap, not a zero. */
    latency: number | null
    samples: number
  }>>
}

export interface AuditFilter {
  q?: string
  source?: string
  username?: string
  project?: string
  action?: string
  hours?: number
  limit?: number
  before?: number
}

export interface AuditEntry {
  id: number
  at: string
  source: string
  action: string
  username: string | null
  ip: string | null
  method: string | null
  path: string | null
  status: number | null
  ms: number | null
  project: string | null
  detail: string | null
}

export interface AuditPage {
  retain_days: number
  source: string | null
  count: number
  /** `null` when this is the last page. */
  next_before: number | null
  entries: AuditEntry[]
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
