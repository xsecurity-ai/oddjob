/**
 * A line-by-line port of `classify()` in backend/app/scope.py, so a pill
 * can say what kind of thing an operator just pasted without a round trip.
 *
 * ── Why this exists at all, given the server already does it ────────────
 *
 * The whole point of a pill input over a textarea is that it can show the
 * state of line 217 before the form is submitted. A textarea cannot: it
 * holds 400 lines of undifferentiated text and the first anyone hears
 * about the typo is `scope_errors` coming back from a POST. That round
 * trip is the feature being removed.
 *
 * ── Why a port and not an opinion ───────────────────────────────────────
 *
 * The danger with client-side classification is not that it is wrong, it
 * is that it is *confidently* wrong in a way nobody notices: the pill says
 * `fqdn`, the server files `cidr`, and the operator reconciles a scope
 * document against a label that was never what got stored. A hint that
 * disagrees with the authority is worse than no hint, because it is
 * trusted.
 *
 * So this is not an approximation and it is not "close enough". It is the
 * same decisions in the same order, including the ones that look like
 * bugs and are not:
 *
 *   - `203.0.113.0/255.255.255.0` is NOT a range. `_looks_like_cidr`
 *     wants a numeric suffix, a dotted netmask is not numeric, so the
 *     server treats the `/…` as a URL path, strips it, and files a bare
 *     ipv4. Reproduced here deliberately.
 *   - `2001:db8::/nonsense` is likewise an address with a path stripped,
 *     not a malformed range.
 *   - A leading `!` or `-` means "put this on the other list", so the
 *     pill reports `included: false` and the raw line keeps its marker.
 *   - `fe80::1%eth0` is a valid ipv6 entry. Python's `ip_address` has
 *     accepted scoped addresses since 3.9 and the server never sees the
 *     `%` branch of `validate_host` because of it.
 *
 * The agreement is not maintained by care alone — test/logic.test.ts and
 * backend/tests/scopetest.py run the SAME fixture, test/scope-cases.json,
 * through this function and through `classify()`, and both fail if the
 * two ever answer differently. Change one side and the other side's gate
 * goes red. That is the only reason it is safe to classify here.
 *
 * ── What callers may do with the answer ─────────────────────────────────
 *
 * Display it. Nothing else. No submit button is disabled because of a
 * verdict reached in here, and no line is withheld from a payload because
 * this function disliked it: `scope.py` and `hosts.py` decide what is
 * valid, and a browser that quietly drops a line the server would have
 * accepted is a scope entry that silently never got enforced.
 */

/** The kinds `classify()` can return. `country` is a separate server-side
 *  concept with its own field in the UI, so it is not derived from a line. */
export type ScopeKind = 'cidr' | 'ipv4' | 'ipv6' | 'fqdn' | 'wildcard'

export type ScopeEntry =
  | { ok: true; kind: ScopeKind; value: string; included: boolean
      /** Only ever true on an `fqdn`, exactly as the server stores it. */
      includeSubdomains: boolean }
  /** `reason` is phrased for a human reading a tooltip, and is NOT the
   *  server's wording. The fixture asserts that both sides agree on
   *  *whether* a line parses, never on the sentence — matching error
   *  prose across two languages buys nothing and breaks on every reword. */
  | { ok: false; reason: string }

// ─────────────────────────────────────────────────────────────── numbers

/** Python's `str.isdigit()` is Unicode-aware, so `_looks_like_cidr` says
 *  yes to a prefix written in Devanagari digits and the parse then fails.
 *  `\p{Nd}` reproduces that for every decimal digit set; Python also
 *  accepts a handful of non-decimal digit characters (superscripts), which
 *  this does not. The divergence is one class of input that we call an
 *  address-with-a-path and the server calls a bad range — cosmetic, since
 *  the line is submitted either way and the server's answer is the one
 *  that lands. */
const UNICODE_DIGITS = /^\p{Nd}+$/u
/** Where a value is actually *parsed*, only ASCII counts — Python's
 *  `_DECIMAL_DIGITS.issuperset` is an explicit "0123456789" set. */
const ASCII_DIGITS = /^[0-9]+$/

// ──────────────────────────────────────────────────────────────── IPv4

/** -> four octets, or null. Mirrors `IPv4Address._parse_octet`: exactly
 *  four parts, ASCII digits only, at most three of them, no leading zero
 *  on a multi-digit part (CVE-2021-29921 — `010.0.0.1` used to be read as
 *  octal by some libraries and as decimal by others, so Python refuses
 *  it outright), and each below 256. */
function parseIPv4(s: string): number[] | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const out: number[] = []
  for (const p of parts) {
    if (!ASCII_DIGITS.test(p) || p.length > 3) return null
    if (p.length > 1 && p[0] === '0') return null
    const n = Number(p)
    if (n > 255) return null
    out.push(n)
  }
  return out
}

// ──────────────────────────────────────────────────────────────── IPv6

const HEXTET = /^[0-9A-Fa-f]{1,4}$/

/** -> eight 16-bit groups plus the zone id, or null.
 *
 *  Mirrors `IPv6Address._ip_int_from_string`, including the rules that
 *  are easy to get subtly wrong: a lone `::` is legal, `:` at either end
 *  is only legal as part of `::`, there may be at most one `::`, a
 *  trailing dotted quad becomes the last two groups, and an address with
 *  no `::` must name all eight groups. */
function parseIPv6(s: string): { groups: number[]; zone: string } | null {
  // A scope id attaches to the whole address and may not be empty. Python
  // splits on the first '%' and refuses the rest if it contains another.
  let zone = ''
  const pct = s.indexOf('%')
  if (pct >= 0) {
    zone = s.slice(pct + 1)
    if (!zone || zone.includes('%') || zone.includes(':')) return null
    s = s.slice(0, pct)
  }

  const parts = s.split(':')
  // '::' is the shortest legal address and splits into three empties, so
  // anything shorter cannot be one.
  if (parts.length < 3) return null

  // A trailing dotted quad ('::ffff:203.0.113.1') contributes two groups.
  let tail: number[] = []
  if (parts[parts.length - 1].includes('.')) {
    const quad = parseIPv4(parts.pop() as string)
    if (!quad) return null
    tail = [(quad[0] << 8) | quad[1], (quad[2] << 8) | quad[3]]
  }

  // An empty first or last part is only legal as half of a '::'.
  if (parts[0] === '' && parts[1] !== '') return null
  if (parts.length > 1 && parts[parts.length - 1] === ''
      && parts[parts.length - 2] !== '') return null

  // The gap, if there is one, is an empty part somewhere in the middle.
  let skip = -1
  for (let i = 1; i < parts.length - 1; i++) {
    if (parts[i] !== '') continue
    if (skip >= 0) return null        // two gaps: which one expands?
    skip = i
  }

  const want = 8 - tail.length
  let head: string[]
  let rest: string[]
  if (skip >= 0) {
    let hi = skip
    let lo = parts.length - skip - 1
    // The empties that '::' itself produced are not groups.
    if (parts[0] === '') hi -= 1
    if (parts[parts.length - 1] === '') lo -= 1
    if (hi < 0 || lo < 0) return null
    const filled = 8 - (hi + lo + tail.length)
    if (filled < 1) return null        // '::' must stand for >= 1 group
    head = parts.slice(0, hi)
    rest = parts.slice(parts.length - lo)
    const groups: number[] = []
    for (const p of head) { if (!HEXTET.test(p)) return null; groups.push(parseInt(p, 16)) }
    for (let i = 0; i < filled; i++) groups.push(0)
    for (const p of rest) { if (!HEXTET.test(p)) return null; groups.push(parseInt(p, 16)) }
    return { groups: [...groups, ...tail], zone }
  }

  if (parts.length !== want) return null
  if (parts[0] === '' || parts[parts.length - 1] === '') return null
  const groups: number[] = []
  for (const p of parts) { if (!HEXTET.test(p)) return null; groups.push(parseInt(p, 16)) }
  return { groups: [...groups, ...tail], zone }
}

/** RFC 5952, the way `_compress_hextets` does it: the longest run of two
 *  or more zero groups collapses, and on a tie the LEFTMOST run wins
 *  (Python's comparison is a strict `>`, so a later equal run never
 *  displaces an earlier one). Getting the tie-break backwards would make
 *  `2001:db8:0:0:1:0:0:1` render two different ways on the two sides and
 *  the duplicate detector would stop seeing them as the same entry.
 *
 *  The IPv4-mapped special case in front of it is not decoration either.
 *  CPython prints `::ffff:cb00:7101` as `::ffff:203.0.113.1`, and only
 *  for that exact shape — `::1.2.3.4` (v4-*compatible*) and
 *  `::fffe:1.2.3.4` both come out as plain hextets. Without it the two
 *  sides disagree on the stored value of every v4-mapped entry. */
function formatIPv6(groups: number[], zone: string): string {
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0
      && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff) {
    const quad = [groups[6] >> 8, groups[6] & 0xff,
                  groups[7] >> 8, groups[7] & 0xff].join('.')
    return zone ? `::ffff:${quad}%${zone}` : `::ffff:${quad}`
  }
  const hex = groups.map((g) => g.toString(16))
  let bestStart = -1, bestLen = 0, start = -1, len = 0
  for (let i = 0; i < hex.length; i++) {
    if (hex[i] === '0') {
      if (start === -1) start = i
      len += 1
      if (len > bestLen) { bestLen = len; bestStart = start }
    } else { start = -1; len = 0 }
  }
  let body: string
  if (bestLen > 1) {
    const left = hex.slice(0, bestStart).join(':')
    const right = hex.slice(bestStart + bestLen).join(':')
    body = `${left}::${right}`
  } else {
    body = hex.join(':')
  }
  return zone ? `${body}%${zone}` : body
}

// ─────────────────────────────────────────────────────── addresses, nets

type Parsed = { kind: 'ipv4' | 'ipv6'; value: string }

/** `ipaddress.ip_address(s)` — v4 is tried first, exactly as Python does. */
function parseAddress(s: string): Parsed | null {
  const v4 = parseIPv4(s)
  if (v4) return { kind: 'ipv4', value: v4.join('.') }
  const v6 = parseIPv6(s)
  if (v6) return { kind: 'ipv6', value: formatIPv6(v6.groups, v6.zone) }
  return null
}

/** Clear every bit below the prefix. `strict=False` on the server side
 *  means `203.0.113.5/24` is accepted and *stored* as `203.0.113.0/24`,
 *  which is why this masks rather than merely validating: two lines that
 *  differ only in host bits are one entry to the server, and the pill
 *  list has to call that a duplicate for the same reason. */
function mask(groups: number[], bits: number, prefix: number): number[] {
  const full = (1 << bits) - 1
  return groups.map((g, i) => {
    const used = prefix - i * bits
    if (used >= bits) return g
    if (used <= 0) return 0
    return g & ((full << (bits - used)) & full)
  })
}

/** `ipaddress.ip_network(s, strict=False)`. The prefix must be a plain
 *  integer here: the dotted-netmask form Python also accepts can never
 *  reach this, because `looksLikeCidr` has already sent it down the
 *  strip-the-path branch. */
function parseNetwork(s: string): Parsed | null {
  const slash = s.indexOf('/')
  if (slash < 0) return null
  const addr = s.slice(0, slash)
  const plen = s.slice(slash + 1)
  if (!ASCII_DIGITS.test(plen)) return null
  const n = Number(plen)

  const v4 = parseIPv4(addr)
  if (v4) {
    if (n > 32) return null
    return { kind: 'ipv4', value: `${mask(v4, 8, n).join('.')}/${n}` }
  }
  const v6 = parseIPv6(addr)
  if (v6) {
    if (n > 128) return null
    const masked = mask(v6.groups, 16, n)
    // Whether a zone id survives into the stored value looks arbitrary
    // and is not: CPython only *rebuilds* the network address when the
    // host bits are actually non-zero, and rebuilding is what drops the
    // scope. So `fe80::%eth0/64` keeps its zone and `fe80::1%eth0/64`
    // loses it, because only the second one needed masking. Written out
    // because nobody would guess it, and getting it wrong would show as
    // a pill whose text does not match the row the server stored.
    const touched = masked.some((g, i) => g !== v6.groups[i])
    return { kind: 'ipv6',
             value: `${formatIPv6(masked, touched ? '' : v6.zone)}/${n}` }
  }
  return null
}

// ─────────────────────────────────────────────────────────── hostnames

// Straight from backend/app/hosts.py. Underscore is in the label set
// because real zones use it (_dmarc, _acme-challenge) and refusing it
// would bar scope entries the server accepts.
const LABEL = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?'
const HOSTNAME = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`)
const ALLOWED = /^[a-z0-9._-]+$/

/** `entry_label` in backend/app/scope.py.
 *
 *  That function exists because the string appears in three places that
 *  have to agree — the sentence in a `Ruling`, the scope section of the
 *  client report and the Slack welcome post — and a row that silently
 *  covers a whole zone must not print as the bare apex in something the
 *  client reads. A pill is a fourth place, and it is the one the
 *  operator is looking at while they decide whether the box is ticked
 *  correctly, so it says it the same way. */
export function entryLabel(kind: string, value: string,
                           includeSubdomains = false): string {
  return includeSubdomains && kind === 'fqdn' ? `${value} (+subdomains)` : value
}

/** `is_ip` in backend/app/domains.py — brackets stripped, because an
 *  address pasted out of a URL arrives as `[2001:db8::1]`. Used where the
 *  question is "is this a name or an address", which for amass is the
 *  difference between a zone it can enumerate and a refusal. */
export function isIpLiteral(raw: string): boolean {
  // Python's `.strip("[]")` takes either bracket off either end, so this
  // does too rather than assuming they come as a matched pair.
  return parseAddress((raw || '').trim().replace(/^[[\]]+|[[\]]+$/g, '')) !== null
}

/** `normalise_host`: lowercase, trim, drop the trailing root dot. */
export function normaliseHost(raw: string): string {
  return (raw || '').trim().replace(/\.+$/, '').toLowerCase()
}

/** `validate_host` — the normalised host, or null if it is not one. */
export function validateHost(raw: string): string | null {
  const h = normaliseHost(raw)
  if (!h) return null
  if (h.length > 253) return null
  // IP literals short-circuit before the character check, because they
  // legitimately contain ':' and '%'.
  if (parseAddress(h.split('%')[0])) return h
  if (!ALLOWED.test(h)) return null
  if (h.includes('..') || h.startsWith('.') || h.startsWith('-')) return null
  if (!HOSTNAME.test(h)) return null
  return h
}

// ───────────────────────────────────────────────────────────── classify

/** `_looks_like_cidr`: a numeric suffix on something that could be an
 *  address. Deciding this wrong is what separates "range" from "hostname
 *  with a path", so it is the same two conditions in the same order. */
function looksLikeCidr(s: string): boolean {
  const i = s.indexOf('/')
  if (i < 0) return false
  const head = s.slice(0, i)
  const tail = s.slice(i + 1)
  if (!UNICODE_DIGITS.test(tail)) return false
  return head.includes(':') || UNICODE_DIGITS.test(head.replace(/\./g, ''))
}

/**
 * Classify one pasted line. Never throws.
 *
 * The order of the branches is load-bearing and matches the server: strip
 * an exclusion marker, strip a scheme, strip a path unless the thing
 * after the slash is a prefix length, then try range → address →
 * wildcard → hostname. Reordering any pair changes what a line means.
 */
export function classifyScopeEntry(
  raw: string, includeSubdomains = false,
): ScopeEntry {
  let s = (raw || '').trim()
  if (!s) return { ok: false, reason: 'empty entry' }

  let included = true
  if ((s[0] === '!' || s[0] === '-') && s.length > 1) {
    included = false
    s = s.slice(1).trim()
  }

  if (s.includes('://')) s = s.slice(s.indexOf('://') + 3)
  if (s.includes('/') && !looksLikeCidr(s)) s = s.slice(0, s.indexOf('/'))
  s = s.trim().replace(/\.+$/, '')
  if (!s) return { ok: false, reason: 'there is no host part here' }

  if (s.includes('/')) {
    const net = parseNetwork(s)
    if (!net) {
      return { ok: false,
               reason: 'looks like a range, but it is not a valid one' }
    }
    // The flag is DROPPED on every kind but `fqdn`, never an error:
    // a range has no subdomains, and refusing the line would make a
    // mixed paste — the normal case — unusable with the box ticked.
    return { ok: true, kind: 'cidr', value: net.value, included,
             includeSubdomains: false }
  }

  const addr = parseAddress(s)
  if (addr) {
    return { ok: true, kind: addr.kind, value: addr.value, included,
             includeSubdomains: false }
  }

  // A wildcard is not a host — nothing can scan one — but it is a
  // perfectly good scope entry, and only the leading-label form is
  // accepted. `a.*.example` and `*acme.example` are patterns an operator
  // has to squint at, and a pattern you squint at bars the wrong thing.
  if (s.startsWith('*.')) {
    const base = validateHost(s.slice(2))
    if (!base) return { ok: false, reason: 'not a usable wildcard' }
    if (!base.includes('.')) {
      return { ok: false,
               reason: 'wildcards a single label, which covers a whole TLD' }
    }
    // A wildcard already covers its subdomains, so the flag adds
    // nothing and is not carried.
    return { ok: true, kind: 'wildcard', value: `*.${base}`, included,
             includeSubdomains: false }
  }
  if (s.includes('*')) {
    return { ok: false,
             reason: "a '*' anywhere but the first label is not understood; "
                     + 'only *.name.example' }
  }

  const host = validateHost(s)
  if (!host) return { ok: false, reason: 'not a well-formed hostname' }
  if (!host.includes('.')) {
    return { ok: false, reason: 'a single label, not a fully-qualified name' }
  }
  return { ok: true, kind: 'fqdn', value: host, included, includeSubdomains }
}
