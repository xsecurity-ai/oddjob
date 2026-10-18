import { useMemo, useState } from 'react'
import { Box, Chip, Collapse, Stack, Tooltip, alpha } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import { api, type Target, type TargetOrigin } from '../lib/api'
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

/** How many origins one row prints before it says how many there are. */
const SHOW_ORIGINS = 3
/** And how many pages inside one of those. */
const SHOW_PAGES = 2

const mono = {
  fontFamily: 'ui-monospace, Menlo, monospace',
  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
} as const

/**
 * Where one cloud resource came from.
 *
 * A bucket is in no CIDR, nothing links to it and no port scan meets
 * it — the bundle that named it is the only reason it is in the
 * engagement at all. A row that shows the identifier and nothing
 * else leaves an operator holding a hostname with no account of it,
 * and "why is this in my project" then has no answer anywhere.
 *
 * **Nothing recorded is said out loud rather than left blank.** An
 * empty list is NOT evidence the resource was found nowhere.
 * Provenance is written by whatever discovers a target and only the
 * asset sweep does so, so a resource typed in by hand, loaded from a
 * scan import or created before any of this existed has none — and
 * nobody knows where it came from. Printing that as "no sources"
 * would state a fact nobody established, which is the one thing this
 * tool must not do.
 */
function Provenance({ origins, pending }: {
  origins: TargetOrigin[] | undefined
  pending: boolean
}) {
  // Still asking. Saying "not recorded" here would be a claim about
  // the data made before the data arrived.
  if (pending) return null

  if (!origins?.length) {
    return (
      <Tooltip title={'Nothing recorded where this came from. A resource added '
        + 'by hand, loaded from a scan import, or created before provenance '
        + 'was kept has no origin — which is not the same as having been '
        + 'found nowhere.'}>
        <Box sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.7),
                   fontStyle: 'italic', cursor: 'help', pl: 1.5 }}>
          origin not recorded
        </Box>
      </Tooltip>
    )
  }

  const shown = origins.slice(0, SHOW_ORIGINS)
  const hidden = origins.length - shown.length

  return (
    <Box sx={{ pl: 1.5, pb: 0.4 }}>
      {shown.map((o) => {
        // `pages` already folds in the page the asset was first seen
        // on; the asset URL is the fallback for an asset no page is
        // known to load, which is a different thing from no page.
        const pages = o.pages.slice(0, SHOW_PAGES)
        const morePages = o.pages_total - pages.length
        return (
          <Box key={o.id} sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.95),
                                lineHeight: 1.5 }}>
            <Box component="span" sx={{ color: alpha(neon.muted, 0.7) }}>
              found in{' '}
            </Box>
            <Tooltip title={o.file_path
              ? `${o.asset_url ?? 'an asset'} — ${o.file_path}`
              : (o.asset_url ?? 'an asset with no URL recorded')}>
              <Box component="span" sx={{ ...mono, color: neon.cyan, cursor: 'help' }}>
                {o.asset_url ?? 'an asset with no URL recorded'}
              </Box>
            </Tooltip>
            {o.file_path && (
              <Box component="span" sx={{ ...mono, color: alpha(neon.cyan, 0.65) }}>
                {' '}({o.file_path})
              </Box>
            )}
            {pages.length > 0 && (
              <>
                <Box component="span" sx={{ color: alpha(neon.muted, 0.7) }}>
                  {' '}· on{' '}
                </Box>
                {pages.map((p, i) => (
                  <Box component="span" key={p}
                    sx={{ ...mono, color: neon.yellow }}>
                    {i ? ', ' : ''}{p}
                  </Box>
                ))}
                {morePages > 0 && (
                  <Box component="span" sx={{ color: alpha(neon.muted, 0.7) }}>
                    {' '}+{morePages} more page{morePages === 1 ? '' : 's'}
                  </Box>
                )}
              </>
            )}
            {/* An asset nothing is known to load is not an asset
                loaded by nothing. Said, rather than left to read as
                an empty list. */}
            {pages.length === 0 && (
              <Box component="span" sx={{ color: alpha(neon.muted, 0.7),
                                          fontStyle: 'italic' }}>
                {' '}· no page recorded as loading it
              </Box>
            )}
          </Box>
        )
      })}
      {hidden > 0 && (
        <Box sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.7),
                   fontStyle: 'italic' }}>
          …and {hidden} more place{hidden === 1 ? '' : 's'} it was found in.
        </Box>
      )}
    </Box>
  )
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
export function CloudTargetsPanel({ rows, project, onOpen }: {
  rows: Target[]
  /** The project the view is scoped to, or null for every visible
   *  one. Only used to narrow the provenance fetch. */
  project: string | null
  onOpen: (t: Target) => void
}) {
  const [open, setOpen] = useState<Set<string>>(new Set())

  // ONE request for the whole panel, keyed by target id. A group here
  // holds thousands of rows and a fetch per row is a fetch per row.
  const origins = useQuery({
    queryKey: ['target-origins', project],
    queryFn: () => api.targetOrigins(project ?? undefined),
  })

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
                    <Box key={t.id} sx={{ py: 0.35 }}>
                      <Stack direction="row" spacing={1}
                        onClick={() => onOpen(t)}
                        sx={{ alignItems: 'center', cursor: 'pointer',
                              '&:hover .h': { color: neon.cyan,
                                              textShadow: glow(neon.cyan, 0.5) } }}>
                        <Box className="h" sx={{
                          ...mono, fontSize: 11,
                          color: hasEvidence(t) ? neon.text : alpha(neon.muted, 0.75),
                          flex: 1, minWidth: 0,
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
                      {/* Only for a managed resource. A name the
                          provider assigned per address came from a
                          reverse lookup, not from anybody's code, and
                          asking where it came from is the wrong
                          question to put against thousands of PTRs. */}
                      {t.kind === 'cloud' && (
                        <Provenance origins={origins.data?.[String(t.id)]}
                          pending={origins.isPending} />
                      )}
                    </Box>
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
