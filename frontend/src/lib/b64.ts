/**
 * Reading a base64 blob that a detector called a secret.
 *
 * "Base64 High Entropy String" is the detector saying the
 * characters are varied, not that the value is a credential. Very
 * often it decodes into something that answers the question
 * immediately: a JSON config, a connection string, a PEM header,
 * a sentence of English. An operator who can see that spends no
 * time on it.
 *
 * **Nothing here decides anything.** It shows what the bytes say
 * so a person can. A blob that decodes to binary is reported as
 * binary rather than as a wall of replacement characters.
 */

/** Base64, standard or url-safe, long enough to be worth decoding
 *  and with no characters that cannot appear in either alphabet. */
const SHAPE = /^[A-Za-z0-9+/_-]{16,}={0,2}$/

export interface Decoded {
  /** The decoded bytes as text, when they are text. */
  text: string | null
  /** What it looks like: json | pem | url | text | binary. */
  kind: string
  /** How many bytes it decoded to. */
  bytes: number
  /** Worth saying out loud, worst first. */
  notes: string[]
}

function bytes(value: string): Uint8Array | null {
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/')
    const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4))
    const bin = atob(padded + pad)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

/** Is this printable text rather than a compressed blob or an image? */
function readable(b: Uint8Array): boolean {
  if (b.length === 0) return false
  let printable = 0
  for (const byte of b) {
    if ((byte >= 0x20 && byte < 0x7f) || byte === 9 || byte === 10 || byte === 13) {
      printable++
    }
  }
  // 85%, not 100%: UTF-8 text carries multi-byte sequences that
  // are individually non-printable, and a JSON document with an
  // accented character would otherwise read as binary.
  return printable / b.length >= 0.85
}

/** Decode, or null when it is not base64 at all. */
export function decodeB64(value: string): Decoded | null {
  const v = value.trim()
  if (!SHAPE.test(v)) return null
  const raw = bytes(v)
  if (!raw || raw.length < 8) return null

  if (!readable(raw)) {
    const notes = ['Decodes to binary, so it is data rather than text — '
                   + 'an image, a key in DER, or something compressed.']
    // A gzip header is worth naming: it is the commonest reason a
    // bundle carries a base64 blob that is not a credential.
    if (raw[0] === 0x1f && raw[1] === 0x8b) {
      notes.unshift('Starts with the gzip magic bytes — compressed data.')
    }
    return { text: null, kind: 'binary', bytes: raw.length, notes }
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(raw)
  const trimmed = text.trim()
  const notes: string[] = []
  let kind = 'text'

  if (trimmed.startsWith('-----BEGIN')) {
    kind = 'pem'
    notes.push('A PEM block. If it is a PRIVATE KEY, that is the finding.')
  } else if ((trimmed.startsWith('{') && trimmed.endsWith('}'))
             || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      JSON.parse(trimmed)
      kind = 'json'
      notes.push('Valid JSON. Read it — service-account keys and config '
                 + 'blobs arrive this way.')
    } catch { /* looks like JSON and is not */ }
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    kind = 'url'
    notes.push('A URL. A connection string with credentials in it is '
               + 'the one to look for.')
  }

  // The reason most of these are not secrets.
  if (kind === 'text' && /\s/.test(trimmed)) {
    notes.push('Decodes to prose, which is what most high-entropy '
               + 'base64 in a bundle turns out to be.')
  }
  notes.push('High entropy only means the characters are varied. What '
             + 'this is, is what it decodes to.')
  return { text, kind, bytes: raw.length, notes }
}
