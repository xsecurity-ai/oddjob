import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode, Ref } from 'react'
import {
  Alert, Box, Chip, CircularProgress, Dialog, DialogContent, DialogTitle,
  IconButton, Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import LaunchIcon from '@mui/icons-material/Launch'
import WrapIcon from '@mui/icons-material/WrapText'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'
import { SEVERITY_COLOUR as SEV } from '../lib/severity'

/**
 * One asset, and the file itself.
 *
 * Fetched when it is opened rather than coming down with the table.
 * On a project that has pulled its bundles back, the bodies are the
 * largest text in the database; sending them all to render a list of
 * filenames would be tens of megabytes for something nobody is
 * reading.
 *
 * **Wrapping is off by default and that is the important default.**
 * A minified bundle is one line several hundred thousand characters
 * long. Wrapped, it is a wall; unwrapped it is one line you can
 * scroll, and a search hit stays where the eye left it.
 */

/** Bytes, as something a person reads. */
function size(n: number | null | undefined): string {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

/** The file, with a line number against every line.
 *
 *  The numbers used to appear only once a finding had pointed at a
 *  line, on the reasoning that a 2 MB minified bundle is one line and
 *  splitting it costs. The reasoning held and the conclusion did not:
 *  reading a file is the ordinary case and "which line is this" is
 *  the ordinary question, so the gutter is always there. A minified
 *  bundle is still one row, because it is still one line.
 *
 *  The cap stays and is the reason there is a second rendering at
 *  all: 2 MB of short lines is 50,000 divs, which is a frozen tab
 *  rather than a feature.
 */
const MAX_NUMBERED_LINES = 20_000

function AssetBody({ body, wrap, atLine, highlight }: {
  body: string
  wrap: boolean
  atLine: number | null
  /** A literal to pick out everywhere it occurs — the value behind a
   *  secret finding, once somebody has asked to see it. Finding the
   *  line is not the same as finding the key on it: a minified line
   *  is thousands of characters and the eye does not do that. */
  highlight: string | null
}) {
  const hit = useRef<HTMLDivElement | null>(null)
  const markRef = useRef<HTMLElement | null>(null)

  const lines = useMemo(() => body.split('\n'), [body])
  const numbered = lines.length <= MAX_NUMBERED_LINES

  // Which line holds the first occurrence of the highlight, so the
  // ref lands on one mark rather than on the last one rendered.
  const firstHitLine = useMemo(() => {
    if (!highlight || highlight.length < 4) return -1
    return lines.findIndex((l) => l.includes(highlight))
  }, [lines, highlight])

  useEffect(() => {
    // `block: center` rather than the default: a finding scrolled to
    // the very top of the pane has no context above it, and the lines
    // around a match are most of what makes it readable.
    //
    // The MARK wins when there is one. A secret finding carries both
    // a line and a value, and the line is the coarser answer: on a
    // minified bundle every match is on line 1, so scrolling to the
    // line would be scrolling to the top of the file and calling it
    // found.
    const to = markRef.current ?? hit.current
    to?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    // `highlight` as well as `atLine`: revealing a secret changes
    // only the former, and without it the viewer highlighted the
    // value and left it wherever the scroll happened to be.
  }, [atLine, highlight, firstHitLine])

  const sx = {
    m: 0, p: 1.2, maxHeight: '60vh', overflow: 'auto',
    bgcolor: alpha('#000', 0.35),
    border: `1px solid ${alpha(neon.purple, 0.3)}`,
    fontFamily: `'Share Tech Mono', monospace`,
    fontSize: 11.5, lineHeight: 1.5, color: neon.text,
    whiteSpace: wrap ? 'pre-wrap' as const : 'pre' as const,
    wordBreak: wrap ? 'break-all' as const : 'normal' as const,
  }

  if (!numbered) {
    return (
      <Box>
        <Box component="pre" sx={sx}>
          <Marked text={body} needle={highlight} first={markRef} />
        </Box>
        <Typography sx={{ fontSize: 10.5, color: neon.yellow, mt: 0.4 }}>
          {lines.length.toLocaleString()} lines — too many to number
          without freezing the tab{atLine ? `, so line ${atLine} is not
          marked; the position is on the finding above` : ''}.
        </Typography>
      </Box>
    )
  }

  return (
    <Box sx={sx}>
      {lines.map((text, i) => {
        const n = i + 1
        const on = n === atLine
        return (
          <Box key={n} ref={on ? hit : undefined}
            sx={{ display: 'flex', gap: 1.2,
                  bgcolor: on ? alpha(neon.cyan, 0.16) : 'transparent' }}>
            <Box component="span" sx={{
              color: on ? neon.cyan : alpha(neon.muted, 0.6),
              userSelect: 'none', textAlign: 'right', minWidth: 46,
              flexShrink: 0,
            }}>{n}</Box>
            <Box component="span" sx={{ minWidth: 0 }}>
              {text
                ? <Marked text={text} needle={highlight}
                    first={i === firstHitLine ? markRef : undefined} />
                : ' '}
            </Box>
          </Box>
        )
      })}
    </Box>
  )
}


/** `text`, with every occurrence of `needle` picked out.
 *
 *  A plain indexOf walk rather than a regex: the needle is a
 *  credential, which routinely contains `.`, `+`, `/` and `$`, and
 *  building a pattern out of it would either throw or match the
 *  wrong thing. Escaping it would work and would still be a regex
 *  engine doing a substring search.
 *
 *  Case-sensitive, deliberately. A key differing only in case is a
 *  different key, and marking it would say we found this one here
 *  when we did not.
 */
function Marked({ text, needle, first }: {
  text: string
  needle: string | null
  /** Attached to the FIRST occurrence in this text, and only when
   *  this is the first text that contains one. That is what the
   *  viewer scrolls to: a key on line 4,000 of a bundle is
   *  highlighted and off screen, which is a highlight nobody sees. */
  first?: Ref<HTMLElement>
}) {
  if (!needle || needle.length < 4 || !text.includes(needle)) {
    return <>{text}</>
  }
  const out: ReactNode[] = []
  let at = 0
  let n = 0
  for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, at)) {
    if (i > at) out.push(text.slice(at, i))
    out.push(
      <Box key={i} component="mark"
        ref={n === 0 ? first : undefined}
        sx={{
          bgcolor: alpha(neon.yellow, 0.3), color: neon.yellow,
          fontWeight: 700, borderRadius: 0.4, px: 0.2,
        }}>{needle}</Box>,
    )
    n += 1
    at = i + needle.length
  }
  if (at < text.length) out.push(text.slice(at))
  return <>{out}</>
}


/** Does this finding have a stored credential behind it?
 *
 *  By scanner rather than by title: trufflehog and detect-secrets are
 *  what write a `FindingSecret`, and a title match would both miss a
 *  rule nobody thought of and fire on a finding that merely says the
 *  word. A wrong guess here is a click that reveals nothing and an
 *  audit entry for a look that found no value.
 */
function isSecret(f: { scanner: string | null; title: string }): boolean {
  const s = (f.scanner || '').toLowerCase()
  return s.includes('trufflehog') || s.includes('detect-secrets')
}


export function AssetModal({ id, onClose }: {
  id: number
  onClose: () => void
}) {
  // On. A bundle has lines thousands of characters long and reading
  // one meant dragging a horizontal scrollbar, which loses your place
  // in a way vertical scrolling does not. The toggle stays for the
  // case wrapping genuinely hurts — comparing two indented blocks —
  // but that is the exception and is now the one you opt into.
  const [wrap, setWrap] = useState(true)
  const [copied, setCopied] = useState(false)
  //: Which finding's line to scroll to and highlight. Null means
  //: nobody has asked, and the file renders as one block -- which is
  //: the fast path and what a minified bundle wants anyway.
  const [atLine, setAtLine] = useState<number | null>(null)
  //: The finding whose credential has been revealed, and the value.
  //: Null until somebody asks: `revealSecret` needs the `user` role
  //: and writes an audit entry before it answers, so it is not
  //: something to call on render for every secret in the list.
  const [shown, setShown] = useState<{ id: number; secret: string } | null>(null)
  const [revealing, setRevealing] = useState<number | null>(null)
  const [denied, setDenied] = useState<string | null>(null)

  const q = useQuery({
    queryKey: ['web-asset', id],
    queryFn: () => api.webAsset(id),
  })
  const a = q.data

  /** Show the credential behind a finding, and mark it in the file.
   *
   *  Deliberately one call per finding rather than fetching them all
   *  with the asset: each is audited as a deliberate look, and a
   *  modal that revealed six credentials because somebody opened a
   *  file would make the audit trail say something that is not true
   *  about intent.
   */
  const reveal = (vulnId: number) => {
    if (shown?.id === vulnId) { setShown(null); return }
    setRevealing(vulnId)
    setDenied(null)
    api.revealSecret(vulnId)
      .then((r) => setShown({ id: vulnId, secret: r.secret }))
      .catch((e) => setDenied(
        // Said plainly. A highlight that silently does not appear
        // reads as "the secret is not in this file", which is a
        // different and wrong answer.
        e instanceof Error && /403|forbidden/i.test(e.message)
          ? 'Showing the value needs the user role on this project.'
          : 'Could not read the stored value for that finding.'))
      .finally(() => setRevealing(null))
  }

  const copy = () => {
    if (!a?.body) return
    void navigator.clipboard.writeText(a.body).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    })
  }

  return (
    <Dialog open onClose={onClose} maxWidth="lg" fullWidth
      slotProps={{
        paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), border: `1px solid ${alpha(neon.cyan, 0.35)}`,
          boxShadow: glow(neon.cyan), backgroundImage: 'none',
        } }
      }}>
      <DialogTitle sx={{ pb: 1 }}>
        <Stack direction="row" spacing={1} sx={{
          alignItems: "flex-start"
        }}>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography sx={{
              fontFamily: `'Share Tech Mono', monospace`, fontSize: 13,
              color: neon.cyan, wordBreak: 'break-all',
            }}>
              {a?.name || a?.url || `asset ${id}`}
            </Typography>
            {!!a && (
              <Typography sx={{
                fontSize: 11, color: neon.muted, wordBreak: 'break-all',
              }}>{a.url}</Typography>
            )}
          </Box>
          {!!a?.body && (
            <Tooltip title={wrap ? 'Stop wrapping' : 'Wrap long lines'}>
              <IconButton size="small" onClick={() => setWrap((w) => !w)}
                sx={{ color: wrap ? neon.cyan : neon.muted }}>
                <WrapIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          {!!a?.body && (
            <Tooltip title={copied ? 'Copied' : 'Copy the file'}>
              <IconButton size="small" onClick={copy}
                sx={{ color: copied ? neon.green : neon.muted }}>
                <ContentCopyIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          {!!a?.url && (
            <Tooltip title="Open the original">
              <IconButton size="small" component="a" href={a.url}
                target="_blank" rel="noreferrer noopener"
                sx={{ color: neon.muted }}>
                <LaunchIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          <IconButton size="small" onClick={onClose} sx={{ color: neon.muted }}>
            <CloseIcon fontSize="small" />
          </IconButton>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ pt: 0 }}>
        {q.isLoading ? (
          <Stack
            sx={{
              alignItems: "center",
              py: 4
            }}>
            <CircularProgress size={22} sx={{ color: neon.cyan }} />
          </Stack>
        ) : q.error ? (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 12 }}>
            {(q.error as Error).message}
          </Alert>
        ) : !a ? null : (
          <>
            <Stack
              direction="row"
              spacing={0.7}
              useFlexGap
              sx={{
                flexWrap: "wrap",
                mb: 1.2
              }}>
              <Chip size="small" label={a.kind} sx={chip(neon.purple)} />
              {a.third_party && (
                <Chip size="small" label="third party" sx={chip(neon.yellow)} />
              )}
              {/* Absent means the URL did not say, which is the case
                  for a fingerprinted bundle — not "current". */}
              <Chip size="small" sx={chip(a.version ? neon.green : neon.muted)}
                label={a.version ? `v${a.version}` : 'version unknown'} />
              <Chip size="small" label={size(a.bytes)} sx={chip(neon.muted)} />
              {!!a.content_type && (
                <Chip size="small" label={a.content_type} sx={chip(neon.muted)} />
              )}
              {!!a.host && (
                <Chip size="small" label={a.host} sx={chip(neon.muted)} />
              )}
              <Chip size="small" sx={chip(neon.muted)}
                label={`on ${a.seen_on} page${a.seen_on === 1 ? '' : 's'}`} />
            </Stack>

            {!!a.sha256 && (
              <Typography sx={{
                fontFamily: `'Share Tech Mono', monospace`, fontSize: 10.5,
                color: neon.muted, mb: 1, wordBreak: 'break-all',
              }}>sha256 {a.sha256}</Typography>
            )}

            {a.truncated && (
              <Alert severity="info" variant="outlined"
                sx={{ fontSize: 11.5, mb: 1 }}>
                Showing the first {size(a.body.length)} of this file. There
                is more — use Copy to take what is shown, or fetch the
                original if you need all of it.
              </Alert>
            )}

            {!a.fetched ? (
              // "Never fetched" and "fetched and empty" are different
              // facts and the second is not a gap.
              <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
                The bytes for this asset have never been pulled back, so
                there is nothing to show. Fetching is opt-in per crawl
                (<code>fetch_assets</code>) because most asset URLs are on
                third-party hosts the engagement does not have.
              </Alert>
            ) : !a.body ? (
              <Alert severity="info" variant="outlined" sx={{ fontSize: 12 }}>
                This asset was fetched and the file is empty. That is a
                result, not a gap.
              </Alert>
            ) : (
              <>
                {/* The value can be real and still not be in THIS
                    text. A secret is found in a `WebAssetFile` --
                    which may be an original recovered from a source
                    map -- and what is on screen is the asset as it
                    was served. Saying so beats highlighting nothing
                    and leaving the reader to conclude the secret is
                    not there. */}
                {shown && !a.body.includes(shown.secret) && (
                  <Alert severity="info" variant="outlined"
                    sx={{ fontSize: 11.5, mb: 1 }}>
                    The value is not in the file as it was served — it
                    was found in a file recovered from this bundle, so
                    there is nothing here to scroll to. The finding
                    names the path.
                  </Alert>
                )}
                <AssetBody body={a.body} wrap={wrap} atLine={atLine}
                  highlight={shown?.secret ?? null} />
              </>
            )}

            {denied && (
              <Alert severity="warning" variant="outlined"
                sx={{ fontSize: 11.5, mt: 1 }} onClose={() => setDenied(null)}>
                {denied}
              </Alert>
            )}

            {a.findings.length > 0 && (
              <Box sx={{ mt: 1.4 }}>
                <Typography sx={{ fontSize: 11, color: neon.muted, mb: 0.4 }}>
                  {a.findings.length} finding
                  {a.findings.length === 1 ? '' : 's'} in this file
                </Typography>
                <Box sx={{ maxHeight: 190, overflowY: 'auto' }}>
                  {a.findings.map((f) => (
                    <Box key={f.id}
                      onClick={() => {
                        if (f.line) setAtLine(f.line)
                        // A secret finding carries a stored value, so
                        // clicking it does the thing somebody clicking
                        // it wants: shows the key and marks it in the
                        // file. Finding the LINE is not finding the
                        // key on it — a minified line is thousands of
                        // characters and the eye does not do that.
                        if (isSecret(f)) reveal(f.id)
                      }}
                      sx={{
                        display: 'flex', gap: 1, alignItems: 'baseline',
                        px: 0.6, py: 0.35, borderRadius: 0.5,
                        // Only clickable when there is somewhere to go.
                        // A pointer on a row that cannot move is a
                        // promise the row does not keep.
                        cursor: f.line || isSecret(f) ? 'pointer' : 'default',
                        bgcolor: atLine && f.line === atLine
                          ? alpha(neon.cyan, 0.14) : 'transparent',
                        '&:hover': f.line
                          ? { bgcolor: alpha(neon.cyan, 0.1) } : undefined,
                      }}>
                      <Box sx={{
                        fontSize: 10, fontWeight: 700, minWidth: 54,
                        color: SEV[f.severity] ?? neon.muted,
                        textTransform: 'uppercase',
                      }}>{f.severity}</Box>
                      <Box sx={{ fontSize: 11.5, color: neon.text,
                                 flex: 1, minWidth: 0 }}>
                        {f.title}
                        {!!f.path && (
                          <Box component="span" sx={{ color: neon.muted,
                                                      fontSize: 10.5 }}>
                            {' '}· {f.path}{f.line ? `:${f.line}` : ''}
                          </Box>
                        )}
                      </Box>
                      <Box sx={{ fontSize: 10, color: neon.muted }}>
                        {revealing === f.id
                          ? '…'
                          : shown?.id === f.id
                            ? <Box component="span" sx={{ color: neon.yellow }}>
                                marked
                              </Box>
                            : f.scanner || '—'}
                      </Box>
                    </Box>
                  ))}
                </Box>
                {a.findings.every((f) => !f.line) && (
                  <Typography sx={{ fontSize: 10.5, color: neon.muted,
                                    mt: 0.4 }}>
                    None of these carry a line number, so there is nowhere
                    to jump to. opengrep reports one; detect-secrets only
                    does for the file it matched in.
                  </Typography>
                )}
              </Box>
            )}

            {a.loaded_by.length > 0 && (
              <Box sx={{ mt: 1.4 }}>
                <Typography sx={{ fontSize: 11, color: neon.muted, mb: 0.4 }}>
                  Loaded by {a.loaded_by.length} page
                  {a.loaded_by.length === 1 ? '' : 's'}
                </Typography>
                <Box sx={{
                  maxHeight: 120, overflowY: 'auto',
                  fontFamily: `'Share Tech Mono', monospace`,
                  fontSize: 10.5, color: neon.muted,
                }}>
                  {a.loaded_by.map((p) => <div key={p}>{p}</div>)}
                </Box>
              </Box>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

const chip = (c: string) => ({
  fontSize: 10, height: 19, borderRadius: 0.5,
  border: `1px solid ${alpha(c, 0.45)}`,
  bgcolor: alpha(c, 0.1), color: c,
})
