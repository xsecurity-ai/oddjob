/**
 * What a base64 blob decodes to, beside the file it was found in.
 *
 * "Base64 High Entropy String" means the characters are varied,
 * not that the value is a credential — and most of them in a
 * minified bundle are a sourcemap fragment, a compressed payload
 * or a sentence of English. Decoding answers it in a glance.
 *
 * Decoded in the browser, like the JWT pane and for the same
 * reason: the value is already on screen, and posting it to the
 * server would put a possible credential in a request log.
 */
import { Box, Chip, Stack, Typography, alpha } from '@mui/material'
import type { Decoded } from '../lib/b64'
import { neon, glow } from '../theme'

const KIND_COLOUR: Record<string, string> = {
  pem: neon.red,
  json: neon.yellow,
  url: neon.yellow,
  binary: neon.muted,
  text: neon.muted,
}

/** How much of the decoded text to show. A base64 blob in a bundle
 *  can be a whole embedded font; the first page answers the
 *  question and the rest is scrolling. */
const SHOWN = 4000

export function B64Pane({ decoded }: { decoded: Decoded }) {
  const c = KIND_COLOUR[decoded.kind] ?? neon.muted
  const body = decoded.text ?? ''
  const clipped = body.length > SHOWN

  return (
    <Box sx={{
      width: 360, flexShrink: 0, overflow: 'auto',
      borderLeft: `1px solid ${alpha(neon.purple, 0.3)}`,
      p: 1.5, bgcolor: alpha('#000', 0.2),
    }}>
      <Stack direction="row" spacing={1}
        sx={{ alignItems: 'center', mb: 1.2 }}>
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
                          letterSpacing: '0.14em', color: neon.cyan,
                          textShadow: glow(neon.cyan, 0.5) }}>
          DECODED BASE64
        </Typography>
        <Chip size="small" label={decoded.kind} sx={{
          height: 18, fontSize: 10, color: c,
          border: `1px solid ${alpha(c, 0.5)}` }} />
        <Box sx={{ flex: 1 }} />
        <Typography sx={{ fontSize: 10, color: neon.muted }}>
          {decoded.bytes} bytes
        </Typography>
      </Stack>

      <Stack spacing={0.7} sx={{ mb: 1.6 }}>
        {decoded.notes.map((n, i) => (
          <Box key={i} sx={{
            fontSize: 11, lineHeight: 1.5,
            // The last note is the caveat, like the JWT pane's.
            color: i === decoded.notes.length - 1 ? neon.muted : c,
            borderLeft: `2px solid ${alpha(
              i === decoded.notes.length - 1 ? neon.muted : c, 0.6)}`,
            pl: 1,
          }}>{n}</Box>
        ))}
      </Stack>

      {decoded.text !== null && (
        <Box component="pre" sx={{
          m: 0, fontSize: 11, lineHeight: 1.5, color: neon.text,
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        }}>
          {body.slice(0, SHOWN)}
          {clipped && (
            <Box component="span" sx={{ color: neon.muted }}>
              {`\n… ${(body.length - SHOWN).toLocaleString()} more characters`}
            </Box>
          )}
        </Box>
      )}
    </Box>
  )
}
