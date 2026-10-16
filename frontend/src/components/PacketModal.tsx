import { useMemo, useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogContent,
  DialogTitle,
  IconButton, Stack, Tooltip, Typography, alpha,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import LaunchIcon from '@mui/icons-material/Launch'
import WrapIcon from '@mui/icons-material/WrapText'
import SendIcon from '@mui/icons-material/Send'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { neon, glow } from '../theme'

/**
 * The exchange, request and response side by side.
 *
 * Fetched on demand rather than coming down with the table: a listing of
 * five thousand addresses carrying every body would be hundreds of
 * megabytes for data nobody is looking at.
 *
 * Headers are separated from the body because that is how anyone reads
 * one — the status line and the headers are scanned, the body is skimmed.
 */

const STATUS_COLOUR = (c: number | null | undefined): string => {
  if (c == null) return neon.muted
  if (c >= 500) return neon.red
  if (c >= 400) return c === 401 || c === 403 ? neon.orange : neon.muted
  if (c >= 300) return neon.yellow
  return neon.green
}

/** HTTP separates headers from body with a blank line. */
function split(raw: string | null | undefined): [string, string] {
  if (!raw) return ['', '']
  const i = raw.search(/\r?\n\r?\n/)
  if (i === -1) return [raw, '']
  const gap = raw.slice(i).match(/^\r?\n\r?\n/)?.[0].length ?? 2
  return [raw.slice(0, i), raw.slice(i + gap)]
}

function Pane({ title, colour, raw, wrap }: {
  title: string; colour: string; raw: string | null | undefined; wrap: boolean
}) {
  const [headers, body] = useMemo(() => split(raw), [raw])
  const copy = () => { if (raw) navigator.clipboard?.writeText(raw) }

  return (
    <Box sx={{
      flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column',
      border: `1px solid ${alpha(colour, 0.35)}`, borderRadius: 1,
      background: alpha(neon.bgDeep, 0.55), overflow: 'hidden',
    }}>
      <Stack
        direction="row"
        spacing={1}
        sx={{
          alignItems: "center",
          px: 1.2,
          py: 0.6,
          borderBottom: `1px solid ${alpha(colour, 0.3)}`,
          background: alpha(colour, 0.08)
        }}>
        <Typography sx={{
          fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
          letterSpacing: '0.16em', color: colour, textShadow: glow(colour, 0.4),
        }}>{title}</Typography>
        <Box sx={{ flex: 1 }} />
        {raw && (
          <>
            <Typography sx={{ fontSize: 9.5, color: alpha(neon.muted, 0.8) }}>
              {(raw.length / 1024).toFixed(1)} KB
            </Typography>
            <Tooltip title="Copy">
              <IconButton size="small" onClick={copy}
                sx={{ color: alpha(neon.muted, 0.8), '&:hover': { color: colour } }}>
                <ContentCopyIcon sx={{ fontSize: 13 }} />
              </IconButton>
            </Tooltip>
          </>
        )}
      </Stack>

      <Box sx={{ flex: 1, overflow: 'auto', p: 1.2 }}>
        {/* This said only a proxy history carries the exchange, and
            that the scanners report an address exists and nothing more.
            It was wrong, and in a way that discouraged asking: katana,
            nuclei and httpx all know what they sent and what came back,
            and the first two were simply not being asked for it. They
            are now. What is left is the genuinely unknowable — a port
            scan has no exchange to record, and a crawl that ran before
            the agent reported one carries only the address. */}
        {!raw ? (
          <Typography sx={{ fontSize: 11.5, color: alpha(neon.muted, 0.75) }}>
            Not captured for this address. A crawl, a nuclei match, an
            httpx probe and an imported proxy history all record the
            exchange. A port scan has none to record, content discovery
            keeps the status and size but not the body, and anything
            crawled before the agent began reporting responses carries
            only the URL — re-crawl it to fill this in.
          </Typography>
        ) : (
          <>
            <Box component="pre" sx={{
              m: 0, fontFamily: `'Share Tech Mono', monospace`, fontSize: 11,
              lineHeight: 1.6, color: alpha(colour, 0.95),
              whiteSpace: wrap ? 'pre-wrap' : 'pre',
              wordBreak: wrap ? 'break-all' : 'normal',
            }}>{headers}</Box>
            {body && (
              <Box component="pre" sx={{
                mt: 1.2, pt: 1.2, m: 0,
                borderTop: `1px dashed ${alpha(neon.purple, 0.3)}`,
                fontFamily: `'Share Tech Mono', monospace`, fontSize: 11,
                lineHeight: 1.6, color: alpha(neon.text, 0.9),
                whiteSpace: wrap ? 'pre-wrap' : 'pre',
                wordBreak: wrap ? 'break-all' : 'normal',
              }}>{body}</Box>
            )}
          </>
        )}
      </Box>
    </Box>
  );
}

export function PacketModal({ id, onClose, onReplay }: {
  id: number
  onClose: () => void
  /** Hand this exchange to the editor. Reaching the editor used to
   *  mean closing this, finding the row again and using its context
   *  menu — which is a lot of steps between reading a response and
   *  the thought it just gave you. */
  onReplay?: (id: number) => void
}) {
  const [wrap, setWrap] = useState(true)
  const { data, isLoading, error } = useQuery({
    queryKey: ['packet', id],
    queryFn: () => api.packet(id),
  })

  return (
    <Dialog open onClose={onClose} maxWidth={false} fullWidth
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 44px ${alpha(neon.cyan, 0.2)}`,
        width: '96vw', maxWidth: 1500, height: '88vh',
      } } }}>
      <DialogTitle sx={{
        py: 1.2, borderBottom: `1px solid ${alpha(neon.cyan, 0.28)}`,
      }}>
        <Stack
          direction="row"
          spacing={1}
          useFlexGap
          sx={{
            alignItems: "center",
            flexWrap: "wrap"
          }}>
          {data?.method && (
            <Chip size="small" label={data.method} sx={{
              height: 21, fontSize: 11, fontWeight: 700, letterSpacing: '0.06em',
              bgcolor: alpha(neon.pink, 0.16), color: neon.pink,
              border: `1px solid ${alpha(neon.pink, 0.5)}` }} />
          )}
          {data?.status_code != null && (
            <Chip size="small" label={data.status_code} sx={{
              height: 21, fontSize: 11, fontWeight: 700,
              bgcolor: alpha(STATUS_COLOUR(data.status_code), 0.16),
              color: STATUS_COLOUR(data.status_code),
              border: `1px solid ${alpha(STATUS_COLOUR(data.status_code), 0.5)}` }} />
          )}
          <Typography sx={{
            fontFamily: `'Share Tech Mono', monospace`, fontSize: 12.5,
            color: neon.cyan, wordBreak: 'break-all', flex: 1, minWidth: 0,
          }}>{data?.url ?? '…'}</Typography>
          {data?.url && (
            <Tooltip title="Open in a new tab">
              {/* noreferrer: an engagement URL must not leak this app's
                  address to the target in a Referer header. */}
              <IconButton size="small" component="a" href={data.url}
                target="_blank" rel="noopener noreferrer"
                sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
                <LaunchIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
          )}
          {onReplay && data?.request && (
            <Tooltip title="Edit this request and send it again. The
                            original is kept; sending files the answer
                            as a new exchange beside it.">
              <Button size="small" variant="outlined"
                startIcon={<SendIcon sx={{ fontSize: 15 }} />}
                onClick={() => onReplay(id)}
                sx={{ fontSize: 11, py: 0.1, color: neon.pink,
                      borderColor: alpha(neon.pink, 0.5),
                      '&:hover': { borderColor: neon.pink } }}>
                Edit &amp; resend
              </Button>
            </Tooltip>
          )}
          <Tooltip title={wrap ? 'Stop wrapping lines' : 'Wrap long lines'}>
            <IconButton size="small" onClick={() => setWrap(!wrap)}
              sx={{ color: wrap ? neon.cyan : neon.muted }}>
              <WrapIcon sx={{ fontSize: 17 }} />
            </IconButton>
          </Tooltip>
          <IconButton size="small" onClick={onClose} sx={{ color: neon.muted }}>
            <CloseIcon sx={{ fontSize: 17 }} />
          </IconButton>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 1.2, pt: 2 }}>
        {isLoading && (
          <Box sx={{ display: 'grid', placeItems: 'center', flex: 1 }}>
            <CircularProgress sx={{ color: neon.cyan }} />
          </Box>
        )}
        {error && (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 12.5 }}>
            {(error as Error).message}
          </Alert>
        )}
        {data && (
          <>
            {data.truncated && (
              <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5, py: 0.3 }}>
                Captured up to a size limit on import — this is the start of
                the exchange, not all of it.
              </Alert>
            )}
            {(data.request || data.response) && (
              <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5, py: 0.3 }}>
                A captured exchange routinely contains session cookies and
                bearer tokens. Treat this pane as credential material.
              </Alert>
            )}
            {/* Side by side, because the point is comparing them. */}
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.2}
                   sx={{ flex: 1, minHeight: 0 }}>
              <Pane title="REQUEST" colour={neon.pink} raw={data.request} wrap={wrap} />
              <Pane title="RESPONSE" colour={neon.green} raw={data.response} wrap={wrap} />
            </Stack>
            {(data.sources || data.notes) && (
              <Stack direction="row" spacing={1} useFlexGap sx={{
                flexWrap: "wrap"
              }}>
                {data.sources && (
                  <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.9) }}>
                    found by {data.sources}
                  </Typography>
                )}
                {data.notes && (
                  <Typography sx={{ fontSize: 10.5, color: neon.purple }}>
                    {data.notes}
                  </Typography>
                )}
              </Stack>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
