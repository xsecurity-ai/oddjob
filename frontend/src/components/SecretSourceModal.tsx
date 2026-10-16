import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert, Box, Chip, CircularProgress, Dialog, DialogContent, DialogTitle,
  IconButton, MenuItem, Stack, TextField, ToggleButton, ToggleButtonGroup,
  Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { TRIAGE } from '../lib/triage'
import { neon, glow } from '../theme'

/** What `origin` means, said once rather than in three tooltips.
 *
 *  `beautified` is the one worth spelling out: it is OUR reformatting
 *  of a minified bundle, so a line number in it names a line in a file
 *  the developer has never seen. Reporting that as though it were
 *  their own source is the mistake `WebAssetFile` was split three ways
 *  to prevent. */
const ORIGIN_WHY: Record<string, string> = {
  raw: 'Exactly what the server returned.',
  beautified: 'Our reformatting of a minified bundle — these line '
    + 'numbers exist only in this copy, not in the original source.',
  source: 'An original file recovered from the bundle’s source map.',
}

/** How the recorded position held up, in the UI’s words.
 *
 *  Three outcomes and not two. A file that was re-fetched after the
 *  scan can still contain the credential at a different line, and a
 *  stored body that no longer contains it at all is a third thing
 *  again — scrolling confidently to a line in either case would be
 *  the tool asserting something it has not checked. */
const LOCATED: Record<string, { sev: 'success' | 'warning' | 'error' | 'info'; say: string }> = {
  confirmed: { sev: 'success', say: 'Found at the recorded line.' },
  found: {
    sev: 'info',
    say: 'This is a readable rendering of the same file. The scanner read '
      + 'the other one, so its line number does not apply here — the value '
      + 'was located by searching for it, and is highlighted below.',
  },
  moved: {
    sev: 'warning',
    say: 'The file has changed since it was scanned: the value is still '
      + 'in it, but not at the recorded line. Highlighted where it is now.',
  },
  absent: {
    sev: 'error',
    say: 'The stored copy of this file does not contain the value. It was '
      + 're-fetched and changed after the scan, so this is the file at that '
      + 'URL now, not the one the finding was made against. Nothing is '
      + 'highlighted.',
  },
}

/** The source behind one credential, scrolled to it.
 *
 *  The highlight is driven by CHARACTER offsets rather than the line
 *  number, and that is the whole reason this is useful on real data:
 *  a `raw` bundle is one line of two megabytes, so "line 1" names the
 *  entire file. Offsets name the value.
 */
export function SecretSourceModal({ vulnId, triage, onClose }: {
  vulnId: number | null
  /** The verdict as the table currently has it. Seeded from the row
   *  rather than fetched: the panel already holds it for every
   *  secret, and a second request per modal would be asking the
   *  server something the caller just told us. */
  triage: string | null
  onClose: () => void
}) {
  const qc = useQueryClient()

  // The control is driven locally so the select moves the moment it
  // is used, rather than after the list behind it has refetched.
  // Seeded from the row and re-seeded when a DIFFERENT secret is
  // opened -- without that, the second modal of a session opens
  // showing the first one's verdict.
  const [verdict, setVerdict] = useState(triage ?? 'needs_investigating')
  useEffect(() => {
    setVerdict(triage ?? 'needs_investigating')
  }, [vulnId, triage])

  const mark = useMutation({
    mutationFn: (t: string) => api.setTriage(vulnId as number, t),
    onSuccess: (_d, t) => {
      setVerdict(t)
      // The secrets table shows the same verdict in a column, and
      // the findings views show it too. Both are invalidated, so a
      // judgement made here is not contradicted by the list behind
      // it.
      void qc.invalidateQueries({ queryKey: ['secrets'] })
      void qc.invalidateQueries({ queryKey: ['vulns'] })
      void qc.invalidateQueries({ queryKey: ['vuln', vulnId] })
    },
  })

  // Which rendering is on screen. `undefined` means "whichever the
  // server thinks is most readable", which is what it opens on.
  // Reset per secret: a view chosen for one bundle says nothing about
  // which renderings the next one even has.
  const [pick, setPick] = useState<string | undefined>(undefined)
  useEffect(() => { setPick(undefined) }, [vulnId])

  const { data, isLoading, error } = useQuery({
    queryKey: ['secret-source', vulnId, pick],
    queryFn: () => api.secretSource(vulnId!, pick),
    enabled: vulnId != null,
    // Source containing a credential. Same reasoning as the secrets
    // list: it does not sit in the cache after navigating away.
    gcTime: 0,
    staleTime: 0,
    retry: false,
  })

  const markRef = useRef<HTMLSpanElement | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // Split once per payload, not per render: the body can be 120 kB.
  const rows = useMemo(() => {
    if (!data) return []
    const lines = data.body.split('\n')
    const ms = data.match_start
    const me = data.match_end
    // Which line the match opens on, and where within it. Counted
    // from the window's own text, so it is correct whether or not
    // the file was windowed.
    let hitLine = -1
    let hitCol = 0
    if (ms != null) {
      let seen = 0
      for (let i = 0; i < lines.length; i++) {
        const next = seen + lines[i].length + 1
        if (ms < next) { hitLine = i; hitCol = ms - seen; break }
        seen = next
      }
    }
    return lines.map((text, i) => ({
      n: data.first_line + i,
      text,
      hit: i === hitLine ? { col: hitCol, len: (me ?? 0) - (ms ?? 0) } : null,
    }))
  }, [data])

  // Scroll the value into the middle of the pane once it is painted.
  useEffect(() => {
    if (!data || !markRef.current) return
    markRef.current.scrollIntoView({ block: 'center', inline: 'nearest' })
  }, [data])

  const loc = data ? LOCATED[data.located] : null

  return (
    <Dialog open={vulnId != null} onClose={onClose} maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        height: '85vh',
      } } }}>
      <DialogTitle sx={{ pr: 6, pb: 1 }}>
        <Stack
          direction="row"
          spacing={1.25}
          sx={{
            alignItems: "center",
            flexWrap: "wrap"
          }}>
          <Typography sx={{
            fontFamily: `'Orbitron', sans-serif`, fontSize: 13, fontWeight: 700,
            letterSpacing: '0.06em', color: neon.text,
            textShadow: glow(neon.cyan, 0.3), wordBreak: 'break-all',
          }}>
            {data?.path ?? (isLoading ? 'loading…' : 'source')}
          </Typography>
          {data && (
            <Tooltip title={ORIGIN_WHY[data.origin] ?? ''}>
              <Chip size="small" label={data.origin} sx={{
                height: 19, fontSize: 10, letterSpacing: '0.06em',
                bgcolor: alpha(neon.purple, 0.18), color: neon.purple,
                border: `1px solid ${alpha(neon.purple, 0.5)}`,
              }} />
            </Tooltip>
          )}
          {data?.line != null && (
            <Box sx={{ fontSize: 11, color: alpha(neon.muted, 0.9) }}>
              line {data.line}
            </Box>
          )}
        </Stack>
        {data?.asset_url && (
          <Box component="a" href={data.asset_url} target="_blank"
            rel="noreferrer noopener"
            sx={{
              display: 'block', mt: 0.5, fontSize: 10.5, color: neon.cyan,
              textDecoration: 'none', wordBreak: 'break-all',
              '&:hover': { textShadow: glow(neon.cyan, 0.6) },
            }}>
            {data.asset_url}
          </Box>
        )}
        <IconButton onClick={onClose} size="small"
          sx={{ position: 'absolute', top: 10, right: 10, color: neon.muted }}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </DialogTitle>

      {/* Judged here, where the evidence is. Reading the source IS
          the act of deciding whether a hit is real, and making
          somebody close this and find the same finding in another
          table to say so is how a verdict never gets recorded.
          The same control and the same vocabulary as VulnModal and
          the table column -- a fourth spelling of these three states
          is how they stop agreeing. */}
      <Box sx={{
        px: 3, pb: 1.5, display: 'flex', alignItems: 'center', gap: 1.5,
        flexWrap: 'wrap',
      }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 10.5,
          letterSpacing: '0.16em', color: neon.cyan,
        }}>
          TRIAGE
        </Typography>
        <TextField select size="small" value={verdict}
          disabled={mark.isPending || vulnId == null}
          onChange={(e) => mark.mutate(e.target.value)}
          sx={{ minWidth: 210 }}>
          {TRIAGE.map((t) => (
            <MenuItem key={t.value} value={t.value}
              sx={{ fontSize: 12.5, color: t.colour }}>{t.label}</MenuItem>
          ))}
        </TextField>
        {mark.isError && (
          <Typography sx={{ fontSize: 11, color: neon.red }}>
            {(mark.error as Error).message}
          </Typography>
        )}

        {/* Which rendering of the same bytes to read. Only shown when
            there is a choice: one button that cannot be turned off is
            furniture. `raw` is labelled Minified rather than Raw
            because that is the property a reader cares about -- it is
            the reason the other option exists. */}
        {data && data.views.length > 1 && (
          <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 1 }}>
            <ToggleButtonGroup size="small" exclusive value={data.origin}
              onChange={(_e, v) => { if (v) setPick(v) }}>
              {data.views.map((v) => (
                <ToggleButton key={v.origin} value={v.origin}
                  sx={{ fontSize: 10.5, py: 0.25, px: 1.25,
                        letterSpacing: '0.06em' }}>
                  {v.origin === 'raw' ? 'Minified'
                    : v.origin === 'beautified' ? 'Beautified' : 'Source'}
                  {v.recorded && (
                    <Tooltip title="The file the scanner actually read">
                      <Box component="span" sx={{ ml: 0.5, color: neon.cyan }}>•</Box>
                    </Tooltip>
                  )}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>
        )}
      </Box>

      <DialogContent dividers
        sx={{ borderColor: alpha(neon.purple, 0.3), p: 0,
              display: 'flex', flexDirection: 'column' }}>
        {isLoading && (
          <Box sx={{ display: 'grid', placeItems: 'center', py: 6 }}>
            <CircularProgress size={22} sx={{ color: neon.cyan }} />
          </Box>
        )}
        {error && (
          <Alert severity="error" sx={{ m: 2 }}>
            {(error as Error).message}
          </Alert>
        )}
        {data && (
          <>
            {loc && (
              <Alert severity={loc.sev} sx={{ m: 1.5, mb: 0.5, py: 0.25, fontSize: 12 }}>
                {loc.say}
              </Alert>
            )}
            {data.generated && (
              <Alert severity="info" sx={{ mx: 1.5, my: 0.5, py: 0.25, fontSize: 12 }}>
                No readable copy of this file was stored, so this one was
                produced just now. Its line numbers exist only here — quote
                the minified file's if you need to cite a position.
              </Alert>
            )}
            {data.truncated && (
              <Alert severity="info" sx={{ mx: 1.5, my: 0.5, py: 0.25, fontSize: 12 }}>
                This file is {data.total.toLocaleString()} characters; showing
                {' '}{data.body.length.toLocaleString()} around the value.
                Lines are numbered from the file, not from this window.
              </Alert>
            )}
            <Box ref={scrollRef} sx={{
              flex: 1, overflow: 'auto', m: 1.5, mt: 1,
              border: `1px solid ${alpha(neon.muted, 0.25)}`,
              borderRadius: 1, bgcolor: alpha('#000', 0.35),
            }}>
              <Box component="pre" sx={{
                m: 0, p: 0, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                fontSize: 11.5, lineHeight: '1.55em',
              }}>
                {rows.map((r) => (
                  <Box key={r.n} sx={{
                    display: 'flex', alignItems: 'flex-start',
                    bgcolor: r.hit ? alpha(neon.yellow, 0.08) : 'transparent',
                  }}>
                    <Box component="span" sx={{
                      flex: '0 0 auto', width: 62, textAlign: 'right', pr: 1.5,
                      color: alpha(neon.muted, 0.55), userSelect: 'none',
                      position: 'sticky', left: 0,
                      bgcolor: alpha(neon.paper, 0.95),
                    }}>{r.n}</Box>
                    {/* `pre-wrap`: a minified bundle is one line of
                        120 kB and a nowrap row would be a horizontal
                        scrollbar the length of the file. */}
                    <Box component="span" sx={{
                      flex: 1, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                      color: neon.text, pr: 1.5,
                    }}>
                      {r.hit ? (<>
                        {r.text.slice(0, r.hit.col)}
                        <Box component="span" ref={markRef} sx={{
                          bgcolor: alpha(neon.yellow, 0.3),
                          color: neon.yellow, fontWeight: 700,
                          outline: `1px solid ${alpha(neon.yellow, 0.8)}`,
                          borderRadius: '2px',
                        }}>
                          {r.text.slice(r.hit.col, r.hit.col + r.hit.len)}
                        </Box>
                        {r.text.slice(r.hit.col + r.hit.len)}
                      </>) : r.text}
                    </Box>
                  </Box>
                ))}
              </Box>
            </Box>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
