/**
 * Reading a JSON Web Token without verifying it.
 *
 * **Nothing here checks a signature, and the UI must never imply it
 * does.** Verifying needs the key, which is the thing we do not
 * have — a token whose claims decode perfectly may be forged, and
 * saying "valid" about it would be the worst possible word. What
 * this answers is "what does this token SAY", which is the question
 * an operator holding a leaked credential actually has: whose it is,
 * what it grants, and whether it is still live.
 *
 * Decoded in the browser. The token is already on screen — it is a
 * secret finding — but sending it to the server to be decoded would
 * put a live credential in a request log for no benefit at all.
 */

/** Three dot-separated base64url segments. Loose on purpose: the
 *  point is to decide whether decoding is worth attempting, and a
 *  strict check would reject tokens that real systems issue. */
const SHAPE = /^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$/

/** Claims whose value is a NumericDate, per RFC 7519 §2. */
const TIME_CLAIMS = ['exp', 'iat', 'nbf', 'auth_time', 'updated_at']

export interface JwtView {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  /** Present and possibly empty. An empty one means `alg: none`
   *  territory, which is worth seeing. */
  signature: string
  /** What is worth saying out loud about it, worst first. */
  notes: JwtNote[]
}

export interface JwtNote {
  level: 'alarm' | 'warn' | 'info'
  text: string
}

function b64url(seg: string): string | null {
  try {
    const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4))
    const s = seg.replace(/-/g, '+').replace(/_/g, '/') + pad
    // `escape` is deprecated and `decodeURIComponent` on percent-
    // encoded bytes is the standard way to get UTF-8 out of atob.
    const bytes = atob(s)
    let out = ''
    for (let i = 0; i < bytes.length; i++) {
      out += '%' + bytes.charCodeAt(i).toString(16).padStart(2, '0')
    }
    return decodeURIComponent(out)
  } catch {
    return null
  }
}

function asObject(text: string | null): Record<string, unknown> | null {
  if (text === null) return null
  try {
    const v = JSON.parse(text)
    return v && typeof v === 'object' && !Array.isArray(v)
      ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/** Looks like a JWT? Cheap, for deciding whether to show the pane. */
export function looksLikeJwt(value: string): boolean {
  const v = value.trim()
  return SHAPE.test(v) && decodeJwt(v) !== null
}

/**
 * Decode a token, or null if it is not one.
 *
 * Null rather than a partial result: a side pane headed "Decoded
 * JWT" showing two empty objects is worse than no pane, because it
 * asserts the thing is a token.
 */
export function decodeJwt(value: string): JwtView | null {
  const v = value.trim()
  if (!SHAPE.test(v)) return null
  const [h, p, sig = ''] = v.split('.')
  const header = asObject(b64url(h))
  const payload = asObject(b64url(p))
  // BOTH must decode. A random three-part string occasionally
  // base64-decodes into something JSON-shaped; needing a real
  // header and a real payload is what keeps this from claiming a
  // path or a hash is a token.
  if (!header || !payload) return null
  return { header, payload, signature: sig, notes: notes(header, payload, sig) }
}

/** Seconds since the epoch as a readable instant, or null. */
export function claimTime(value: unknown): Date | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  // Seconds, per the spec. A value far past the year 3000 is almost
  // certainly milliseconds from a library that got it wrong, and
  // rendering it as the year 55000 helps nobody.
  const ms = value > 1e11 ? value : value * 1000
  const d = new Date(ms)
  return Number.isNaN(d.getTime()) ? null : d
}

export const TIME_CLAIM_NAMES = TIME_CLAIMS

function notes(header: Record<string, unknown>,
               payload: Record<string, unknown>,
               sig: string): JwtNote[] {
  const out: JwtNote[] = []
  const alg = String(header.alg ?? '')

  // `alg: none` means the token is self-asserted: anyone can mint
  // one. If a service accepts it, that is a finding in its own
  // right and not a detail of this credential.
  if (alg.toLowerCase() === 'none' || sig === '') {
    out.push({ level: 'alarm',
               text: alg.toLowerCase() === 'none'
                 ? 'alg is "none" — this token is unsigned, so anyone can '
                   + 'mint one. If a service accepts it, that is a finding.'
                 : 'The signature segment is empty, so nothing signs this '
                   + 'token.' })
  }

  const exp = claimTime(payload.exp)
  const nbf = claimTime(payload.nbf)
  const now = Date.now()
  if (exp) {
    out.push(exp.getTime() < now
      ? { level: 'info',
          text: `Expired ${exp.toISOString().slice(0, 16).replace('T', ' ')}Z `
                + '— still evidence it leaked, but it will not authenticate.' }
      : { level: 'alarm',
          text: `LIVE until ${exp.toISOString().slice(0, 16).replace('T', ' ')}Z.` })
  } else {
    // No exp is the one people miss. A bearer token with no expiry
    // is valid until something revokes it, which is usually never.
    out.push({ level: 'alarm',
               text: 'No `exp` claim: this token does not expire on its own.' })
  }
  if (nbf && nbf.getTime() > now) {
    out.push({ level: 'info',
               text: `Not valid until ${nbf.toISOString().slice(0, 16)
                 .replace('T', ' ')}Z.` })
  }

  // Said LAST so it is the thing left on screen. Everything above is
  // read off a token nobody has verified.
  out.push({ level: 'warn',
             text: 'Not verified. The signature cannot be checked without '
                   + 'the key, so these claims are what the token says, not '
                   + 'what anyone has confirmed.' })
  return out
}
