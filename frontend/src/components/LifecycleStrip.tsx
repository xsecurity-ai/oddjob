import { useState } from 'react'
import { Box, Chip, Stack, Tooltip, Typography, alpha } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { LIFECYCLE, LIFECYCLE_COLOUR, LIFECYCLE_LABEL } from '../lib/lifecycle'
import { neon } from '../theme'

/**
 * What changed between the last scan and the one before it.
 *
 * The answer recurring scanning is bought for, and the one a list
 * that only ever grows cannot give.
 *
 * Shows all four counts including the zeros. A strip that hid
 * `Resolved` because nothing had been resolved would read as a tool
 * that cannot answer the question, when the honest reading is "we
 * looked and nothing has been fixed".
 *
 * The per-scanner line underneath is not decoration. "0 resolved"
 * from a tool that has not run in six weeks is not good news, and
 * the counts above are uninterpretable without knowing when anybody
 * last looked.
 */

/** "3 days ago", or "never". Relative, because the question here is
 *  always "is this stale", never "what was the date".
 *
 *  `now` is passed in rather than read from the clock: reading it
 *  during a render makes the render impure, and a component whose
 *  output depends on the moment it happened to run cannot be
 *  compared between renders. Captured once per mount, which is also
 *  the honest granularity — "3 days ago" does not need to tick.
 */
function ago(iso: string | null, now: number): string {
  if (!iso) return 'never'
  const ms = now - Date.parse(iso)
  if (Number.isNaN(ms)) return 'unknown'
  const days = Math.floor(ms / 86_400_000)
  if (days > 1) return `${days} days ago`
  const hours = Math.floor(ms / 3_600_000)
  if (hours >= 1) return `${hours}h ago`
  return 'under an hour ago'
}

export function LifecycleStrip({ project }: { project: string | null }) {
  // Read once, in the one place React sanctions reading a clock.
  const [now] = useState(() => Date.now())
  const { data } = useQuery({
    queryKey: ['vuln-lifecycle', project],
    queryFn: () => api.vulnLifecycle(project as string),
    enabled: !!project,
  })

  if (!project || !data) return null

  const total = LIFECYCLE.reduce((n, k) => n + (data.counts[k] ?? 0), 0)
  if (!total) return null

  const stalest = data.scanners.length
    ? data.scanners.reduce((a, b) =>
        (Date.parse(a.last_looked_at ?? '') || 0)
        < (Date.parse(b.last_looked_at ?? '') || 0) ? a : b)
    : null

  return (
    <Box sx={{ mb: 1.2 }}>
      <Stack direction="row" spacing={0.8} useFlexGap sx={{ flexWrap: 'wrap',
                                                            alignItems: 'center' }}>
        {LIFECYCLE.map((k) => {
          const c = LIFECYCLE_COLOUR[k] ?? neon.muted
          const n = data.counts[k] ?? 0
          return (
            <Tooltip key={k} title={data.meaning[k] ?? ''}>
              <Chip size="small" label={`${LIFECYCLE_LABEL[k]} ${n}`} sx={{
                height: 21, fontSize: 10.5, cursor: 'help',
                // Zeroes are shown, and dimmed rather than hidden.
                // "Resolved 0" is a real answer; an absent chip is not.
                bgcolor: alpha(c, n ? 0.16 : 0.05),
                color: n ? c : alpha(neon.muted, 0.8),
                border: `1px solid ${alpha(c, n ? 0.55 : 0.2)}` }} />
            </Tooltip>
          )
        })}
      </Stack>

      {data.scanners.length > 0 && (
        <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.95),
                          mt: 0.6 }}>
          Last looked:{' '}
          {data.scanners.map((s) => `${s.scanner} ${ago(s.last_looked_at, now)}`)
            .join(' · ')}
        </Typography>
      )}

      {/* The counts above mean nothing without this. A scan that has
          not run in weeks has not resolved anything and has not
          failed to — it has not looked. */}
      {stalest && now - Date.parse(stalest.last_looked_at ?? '')
                  > 14 * 86_400_000 && (
        <Typography sx={{ fontSize: 10.5, color: neon.yellow, mt: 0.4 }}>
          {stalest.scanner} has not run in {ago(stalest.last_looked_at, now)} —
          nothing it reports can be called resolved or still present on the
          strength of that.
        </Typography>
      )}

      {data.unconfirmed_hosts.length > 0 && (
        <Typography sx={{ fontSize: 10.5, color: alpha(neon.cyan, 0.95),
                          mt: 0.4 }}>
          {data.unconfirmed_hosts.length} host(s) carry findings nothing has
          revisited: {data.unconfirmed_hosts.slice(0, 6).join(', ')}
          {data.unconfirmed_hosts.length > 6
            && ` and ${data.unconfirmed_hosts.length - 6} more`}.
        </Typography>
      )}
    </Box>
  )
}
