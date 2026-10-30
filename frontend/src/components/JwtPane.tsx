/**
 * A decoded JWT, beside the file it was found in.
 *
 * **It never says the token is valid**, because nothing here checks
 * the signature — that needs the key, which is the thing we do not
 * have. What it answers is "what does this token say": whose it is,
 * what it grants, and whether it is still live. That is the question
 * an operator holding a leaked credential actually has, and the
 * answer changes what they do next: a live token with no expiry is a
 * call to the client tonight, an expired one is a finding to write
 * up.
 *
 * Decoded in the browser — see lib/jwt.ts.
 */
import { Box, Chip, Stack, Tooltip, Typography, alpha } from '@mui/material'
import { claimTime, type JwtNote, type JwtView } from '../lib/jwt'
import { neon, glow } from '../theme'

const LEVEL_COLOUR: Record<JwtNote['level'], string> = {
  alarm: neon.red,
  warn: neon.yellow,
  info: neon.muted,
}

/** Claims worth pulling out of the payload and showing first. The
 *  rest are shown too, below — this is about reading order, not
 *  about hiding anything. */
const HEADLINE = ['sub', 'iss', 'aud', 'scope', 'scp', 'roles', 'email',
                  'preferred_username', 'client_id', 'azp']

function Row({ k, v }: { k: string; v: unknown }) {
  const when = claimTime(v)
  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start',
               py: 0.25 }}>
      <Box sx={{ flex: '0 0 auto', minWidth: 92, color: neon.cyan,
                 fontSize: 11 }}>{k}</Box>
      <Box sx={{ flex: 1, minWidth: 0, color: neon.text, fontSize: 11.5,
                 wordBreak: 'break-all',
                 fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>
        {typeof v === 'object' && v !== null
          ? JSON.stringify(v)
          : String(v)}
        {/* A NumericDate is unreadable as a number, and reading it
            wrong is how an expired token gets chased. */}
        {when && (
          <Box component="span" sx={{ color: neon.muted, ml: 1 }}>
            {when.toISOString().slice(0, 16).replace('T', ' ')}Z
          </Box>
        )}
      </Box>
    </Box>
  )
}

export function JwtPane({ jwt }: { jwt: JwtView }) {
  const payload = jwt.payload
  const keys = Object.keys(payload)
  const first = HEADLINE.filter((k) => k in payload)
  const rest = keys.filter((k) => !first.includes(k)).sort()

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
          DECODED JWT
        </Typography>
        {jwt.header.alg != null && (
          <Tooltip title="The algorithm the token claims. Not checked —
                          checking needs the key.">
            <Chip size="small" label={String(jwt.header.alg)} sx={{
              height: 18, fontSize: 10,
              color: String(jwt.header.alg).toLowerCase() === 'none'
                ? neon.red : neon.muted,
              border: `1px solid ${alpha(
                String(jwt.header.alg).toLowerCase() === 'none'
                  ? neon.red : neon.muted, 0.5)}` }} />
          </Tooltip>
        )}
      </Stack>

      {/* Worst first, and the "not verified" caveat is last so it is
          the line left on screen. */}
      <Stack spacing={0.7} sx={{ mb: 1.6 }}>
        {jwt.notes.map((n, i) => (
          <Box key={i} sx={{
            fontSize: 11, lineHeight: 1.5, color: LEVEL_COLOUR[n.level],
            borderLeft: `2px solid ${alpha(LEVEL_COLOUR[n.level], 0.6)}`,
            pl: 1,
          }}>{n.text}</Box>
        ))}
      </Stack>

      {first.length > 0 && (
        <Box sx={{ mb: 1.4 }}>
          {first.map((k) => <Row key={k} k={k} v={payload[k]} />)}
        </Box>
      )}

      {rest.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 10, color: neon.muted, mb: 0.4,
                            letterSpacing: '0.1em',
                            textTransform: 'uppercase' }}>
            other claims
          </Typography>
          {rest.map((k) => <Row key={k} k={k} v={payload[k]} />)}
        </Box>
      )}

      <Typography sx={{ fontSize: 10, color: neon.muted, mt: 1.6,
                        lineHeight: 1.5 }}>
        Header: {JSON.stringify(jwt.header)}
      </Typography>
    </Box>
  )
}
