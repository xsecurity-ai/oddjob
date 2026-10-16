import { useMemo, useState } from 'react'
import { Box, Chip, Collapse, Stack, Tooltip, alpha } from '@mui/material'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import type { Target } from '../lib/api'
import { neon, glow } from '../theme'

/** Does this row have anything behind it? */
function hasEvidence(t: Target): boolean {
  return !!t.alive || !!t.total_ports || !!t.total_vulns
    || (t.hostnames?.length ?? 0) > 0
}

interface Group {
  key: string
  provider: string
  label: string
  rows: Target[]
  evidence: Target[]
}

/**
 * Cloud-provider naming, condensed.
 *
 * A reverse lookup across a provider's ranges does not find the
 * client's assets — it finds the provider's PTR template, once per
 * address. On this engagement that is the overwhelming majority of
 * the target list, and listing it row by row is what makes the real
 * estate a rounding error on its own page.
 *
 * So each template collapses to ONE row carrying its count. Nothing
 * is deleted and nothing with evidence is buried: every host that is
 * alive, has an open port, has a finding or has picked up a real
 * name is listed above the fold inside its group, and the count of
 * those is on the group header. A `*.bc.googleusercontent.com` with
 * an open port is a finding — the ephemeral PTR simply is not its
 * name, which is the only thing being said here.
 */
export function CloudTargetsPanel({ rows, onOpen }: {
  rows: Target[]
  onOpen: (t: Target) => void
}) {
  const [open, setOpen] = useState<Set<string>>(new Set())

  const groups = useMemo<Group[]>(() => {
    const by = new Map<string, Group>()
    for (const t of rows) {
      // kind=cloud with no template name still belongs here — it is a
      // managed resource, just one somebody named.
      const key = t.cloud_family ?? (t.kind === 'cloud' ? 'cloud-named' : 'other')
      let g = by.get(key)
      if (!g) {
        g = {
          key,
          provider: t.cloud_provider ?? t.provider ?? 'Cloud',
          label: t.cloud_family ? '' : 'named resources',
          rows: [], evidence: [],
        }
        by.set(key, g)
      }
      g.rows.push(t)
      if (hasEvidence(t)) g.evidence.push(t)
    }
    // Groups with something behind them first; then the biggest.
    return [...by.values()].sort((a, b) =>
      (b.evidence.length - a.evidence.length) || (b.rows.length - a.rows.length))
  }, [rows])

  if (!rows.length) {
    return (
      <Box sx={{ p: 3, color: neon.muted, fontSize: 12.5 }}>
        No cloud-provider names in this engagement.
      </Box>
    )
  }

  const toggle = (k: string) => setOpen((p) => {
    const n = new Set(p)
    if (n.has(k)) n.delete(k); else n.add(k)
    return n
  })

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: 2, py: 1.5 }}>
      <Box sx={{ fontSize: 11.5, color: alpha(neon.muted, 0.9), mb: 1.5 }}>
        {rows.length.toLocaleString()} name(s) assigned by a provider, in{' '}
        {groups.length} template{groups.length === 1 ? '' : 's'}. These are the
        provider&rsquo;s naming, not the client&rsquo;s — one fact per range,
        written out once per address. Nothing here is hidden: anything with a
        port, a finding or a real name is listed first inside its group.
      </Box>

      <Stack spacing={1}>
        {groups.map((g) => {
          const isOpen = open.has(g.key)
          // Evidence first, then the rest — and only the first slice
          // of the silent ones, because a group can hold thousands
          // and rendering them all is how a page stops scrolling.
          const quiet = g.rows.filter((t) => !hasEvidence(t))
          const shown = isOpen
            ? [...g.evidence, ...quiet.slice(0, 200)]
            : []
          const hidden = isOpen ? quiet.length - Math.min(quiet.length, 200) : 0
          return (
            <Box key={g.key}
              sx={{ border: `1px solid ${alpha(neon.purple, 0.25)}`,
                    borderRadius: 1, overflow: 'hidden' }}>
              <Stack direction="row" spacing={1.5}
                onClick={() => toggle(g.key)}
                sx={{ alignItems: 'center', px: 1.5, py: 1.2, cursor: 'pointer',
                      backgroundColor: alpha(neon.purple, 0.07),
                      '&:hover': { backgroundColor: alpha(neon.purple, 0.13) } }}>
                {isOpen
                  ? <ExpandMoreIcon sx={{ fontSize: 18, color: neon.muted }} />
                  : <ChevronRightIcon sx={{ fontSize: 18, color: neon.muted }} />}
                <Box sx={{ fontSize: 12.5, color: neon.cyan, fontWeight: 600,
                           textShadow: glow(neon.cyan, 0.35) }}>
                  {g.provider}
                </Box>
                {g.label && (
                  <Box sx={{ fontSize: 11.5, color: neon.text }}>{g.label}</Box>
                )}
                <Chip size="small" label={`${g.rows.length.toLocaleString()} names`}
                  sx={{ height: 19, fontSize: 10.5, color: neon.muted,
                        borderColor: alpha(neon.muted, 0.35) }}
                  variant="outlined" />
                {/* The number that decides whether this group is
                    noise or a finding. Zero is said out loud rather
                    than left blank — "none of these answered" is an
                    answer. */}
                <Tooltip title={g.evidence.length
                  ? 'Alive, or carrying an open port, a finding or a real name. Listed first when expanded.'
                  : 'Not one of these has answered anything. Reverse-lookup rows with nothing behind them.'}>
                  <Chip size="small" variant="outlined"
                    label={g.evidence.length
                      ? `${g.evidence.length} with something behind them`
                      : 'nothing answered'}
                    sx={{ height: 19, fontSize: 10.5, cursor: 'help',
                          color: g.evidence.length ? neon.yellow : alpha(neon.muted, 0.7),
                          borderColor: alpha(g.evidence.length ? neon.yellow : neon.muted, 0.4) }} />
                </Tooltip>
              </Stack>

              <Collapse in={isOpen} unmountOnExit>
                <Box sx={{ px: 1.5, py: 1 }}>
                  {shown.map((t) => (
                    <Stack key={t.id} direction="row" spacing={1}
                      onClick={() => onOpen(t)}
                      sx={{ alignItems: 'center', py: 0.35, cursor: 'pointer',
                            '&:hover .h': { color: neon.cyan,
                                            textShadow: glow(neon.cyan, 0.5) } }}>
                      <Box className="h" sx={{
                        fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 11,
                        color: hasEvidence(t) ? neon.text : alpha(neon.muted, 0.75),
                        overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap', flex: 1, minWidth: 0,
                      }}>{t.host}</Box>
                      {!!t.total_ports && (
                        <Box sx={{ fontSize: 10.5, color: neon.yellow }}>
                          {t.total_ports} port{t.total_ports === 1 ? '' : 's'}
                        </Box>
                      )}
                      {!!t.total_vulns && (
                        <Box sx={{ fontSize: 10.5, color: neon.pink }}>
                          {t.total_vulns} finding{t.total_vulns === 1 ? '' : 's'}
                        </Box>
                      )}
                    </Stack>
                  ))}
                  {hidden > 0 && (
                    <Box sx={{ fontSize: 11, color: alpha(neon.muted, 0.8),
                               pt: 0.8, fontStyle: 'italic' }}>
                      …and {hidden.toLocaleString()} more with nothing behind
                      them, not rendered. Everything that answered is above.
                    </Box>
                  )}
                </Box>
              </Collapse>
            </Box>
          )
        })}
      </Stack>
    </Box>
  )
}
