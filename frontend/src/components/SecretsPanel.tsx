import { useMemo, useState } from 'react'
import { Box, Stack, Tooltip, alpha } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '../lib/columns'
import { api, type SecretRow } from '../lib/api'
import { DataTable } from './DataTable'
import { SecretSourceModal } from './SecretSourceModal'
import { SEVERITY_COLOUR as SEV_COLOUR } from '../lib/severity'
import { neon, glow } from '../theme'

/** The value, in clear, in a monospace cell. Click it for the source.
 *
 *  Never shortened. An ellipsis through the middle of a credential
 *  is the one place it is actively harmful: half a key is not a
 *  key, and somebody deciding whether two rows are the same secret
 *  needs the characters that differ, which are as likely to be at
 *  the end as the start.
 *
 *  So the whole value is in the DOM and the cell scrolls sideways
 *  rather than wrapping.
 *
 *  `user-select: all` is deliberately NOT set any more. It made one
 *  click copy the whole value, which is a good trick and the wrong
 *  one here now that the same click opens the source: selecting and
 *  opening on the same gesture meant doing both every time. Dragging
 *  across the text still selects it, and the modal shows the value
 *  in context for anyone who wants to copy it from there. */
function SecretCell({ value, onSource }: {
  value: string
  onSource: () => void
}) {
  return (
    <Tooltip title="Show the source this was found in" enterDelay={400}>
      <Box
        component="code"
        onClick={(e) => { e.stopPropagation(); onSource() }}
        sx={{
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          fontSize: 11.5, color: neon.yellow,
          cursor: 'pointer',
          whiteSpace: 'nowrap', overflowX: 'auto', maxWidth: '100%',
          display: 'block',
          '&:hover': { textShadow: glow(neon.yellow, 0.6) },
          '&::-webkit-scrollbar': { height: 4 },
          '&::-webkit-scrollbar-thumb': {
            background: alpha(neon.muted, 0.4), borderRadius: 2,
          },
        }}>
        {value}
      </Box>
    </Tooltip>
  )
}

/** Not recorded, which is not the same as empty. */
function Unrecorded({ why }: { why: string }) {
  return (
    <Tooltip title={why}>
      <Box component="span" sx={{ color: alpha(neon.muted, 0.5), fontStyle: 'italic' }}>
        not recorded
      </Box>
    </Tooltip>
  )
}

/** One row of the single table: a host, a file, or a secret.
 *
 *  Three shapes in one list rather than three tables or a grid with
 *  master-detail. The MIT DataGrid cannot do master-detail at all
 *  (see CLAUDE.md), so expansion is done here and the grid is handed
 *  one finished page of rows — which is the same arrangement paging,
 *  sorting and filtering already use in this codebase.
 */
type Row =
  | { kind: 'host'; id: string; host: string; files: number
      secrets: number; worst: string }
  | { kind: 'file'; id: string; host: string; url: string
      path: string | null; secrets: number; worst: string }
  | { kind: 'secret'; id: string; depth: 2; row: SecretRow }

const SEV_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

function worstOf(rows: SecretRow[]): string {
  return rows.map((r) => r.severity)
    .sort((a, b) => (SEV_RANK[a] ?? 9) - (SEV_RANK[b] ?? 9))[0] ?? 'info'
}

/** Group by host, then by the file within it.
 *
 *  The file key is the URL plus the path inside it: one bundle can
 *  hold several source files and they are different places, which
 *  is the distinction the flat table lost. A secret with no URL
 *  recorded gets its own group rather than being dropped — "we do
 *  not know where this came from" is a thing the page has to be
 *  able to say.
 */
function group(rows: SecretRow[]) {
  const byHost = new Map<string, Map<string, SecretRow[]>>()
  for (const r of rows) {
    const host = r.host || '(host not recorded)'
    const file = r.asset_url
      ? r.asset_url + (r.path ? ` · ${r.path}` : '')
      : '(origin not recorded)'
    if (!byHost.has(host)) byHost.set(host, new Map())
    const files = byHost.get(host)!
    if (!files.has(file)) files.set(file, [])
    files.get(file)!.push(r)
  }
  return byHost
}

/** Every stored credential on the estate, in clear.
 *
 *  A deliberate widening of what the single-finding Reveal keeps
 *  narrow, and the reasoning is on the endpoint. The short version:
 *  the work this serves is judging several hundred candidate
 *  secrets against each other, which one audited click at a time
 *  nobody actually does.
 *
 *  The server still refuses the values to a readonly account and
 *  writes an audit entry before answering, so "who could have seen
 *  this key" stays answerable.
 */
export function SecretsPanel({ project, onFinding }: {
  project: string | null
  onFinding: (vulnId: number) => void
}) {
  // The ROW, not just its id: the modal shows the verdict too, and
  // the row already carries it. Holding the id alone would mean
  // asking the server for something this table just rendered.
  const [sourceFor, setSourceFor] = useState<SecretRow | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['secrets', project],
    queryFn: () => api.secrets(project ?? undefined),
    // Credentials, so they do not sit in the cache behind the
    // user's back after they navigate away.
    gcTime: 0,
    staleTime: 0,
  })

  // Which groups are open. Hosts start closed: the whole point of
  // the change is that an estate's worth of secrets is unreadable
  // as a flat list, and opening every one of them again on load
  // would put it straight back.
  const [openHosts, setOpenHosts] = useState<Set<string>>(new Set())
  const [openFiles, setOpenFiles] = useState<Set<string>>(new Set())

  const toggle = (set: Set<string>, key: string,
                  put: (s: Set<string>) => void) => {
    const next = new Set(set)
    if (!next.delete(key)) next.add(key)
    put(next)
  }

  // Memoised on the response, not rebuilt per render: `stat` below
  // keys off it, and a dependency whose identity changes every time
  // is a memo that never hits and reads as though it does.
  const grouped = useMemo(() => group(data ?? []), [data])
  // One finished list, in the order it is read: host, then its
  // files when the host is open, then their secrets when the file
  // is. Sorted worst-first within each level so the thing worth
  // looking at is nearest the top of its group.
  const rows: Row[] = []
  for (const [host, files] of [...grouped].sort((a, b) =>
      a[0].localeCompare(b[0]))) {
    const all = [...files.values()].flat()
    rows.push({ kind: 'host', id: `h:${host}`, host,
                files: files.size, secrets: all.length,
                worst: worstOf(all) })
    if (!openHosts.has(host)) continue
    for (const [file, secrets] of [...files].sort((a, b) =>
        (SEV_RANK[worstOf(a[1])] ?? 9) - (SEV_RANK[worstOf(b[1])] ?? 9))) {
      const key = `${host}|${file}`
      const [url, path] = file.split(' · ')
      rows.push({ kind: 'file', id: `f:${key}`, host, url,
                  path: path ?? null, secrets: secrets.length,
                  worst: worstOf(secrets) })
      if (!openFiles.has(key)) continue
      for (const r of [...secrets].sort((a, b) =>
          (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))) {
        rows.push({ kind: 'secret', id: `s:${r.vuln_id}`, depth: 2, row: r })
      }
    }
  }

  // What a row sorts BY, which is never the row's own value.
  //
  // This grid is a flattened tree -- host, then its files, then their
  // secrets -- and a flat sorter over it would put a secret above the
  // host it belongs to. So every row in a host's block reports the
  // HOST's value, which makes sorting mean "order the hosts by this"
  // and leaves the block intact: rows inside it compare equal, and
  // `Array.prototype.sort` has been stable since ES2019, so they keep
  // the order this function built them in. Descending reverses the
  // hosts and still does not reverse their contents.
  //
  // It also fixes the reason sorting did nothing at all: the columns
  // name `severity`, `detector`, `count` and `label`, and not one of
  // those is a field on these rows -- a secret's live under `row.`
  // and the group rows have `worst` and `secrets`. Every comparison
  // was reading undefined.
  const hostOf = (r: Row) => (r.kind === 'secret' ? r.row.host ?? '' : r.host)
  const stat = useMemo(() => {
    const m = new Map<string, { worst: number; secrets: number }>()
    for (const [host, files] of grouped) {
      const all = [...files.values()].flat()
      m.set(host, { worst: SEV_RANK[worstOf(all)] ?? 9, secrets: all.length })
    }
    return m
  }, [grouped])
  const by = (pick: (s: { worst: number; secrets: number }) => number) =>
    (_raw: unknown, row: Row) => {
      const h = stat.get(hostOf(row))
      return h ? pick(h) : Number.MAX_SAFE_INTEGER
    }

  const columns: ColumnDef<Row>[] = [
    {
      field: 'label', headerName: 'Host · file · secret', flex: 4,
      minWidth: 360,
      valueGetter: (_v, row) => hostOf(row as Row),
      // One column for all three levels. Indentation is what makes
      // a flat grid read as a tree, and splitting the levels across
      // columns would leave two of them blank on every row.
      renderCell: (p) => {
        const r = p.row as Row
        if (r.kind === 'host') {
          return (
            <Box onClick={() => toggle(openHosts, r.host, setOpenHosts)}
              sx={{ cursor: 'pointer', color: neon.pink, fontWeight: 700,
                    fontSize: 12.5, display: 'flex', gap: 0.8,
                    alignItems: 'center',
                    '&:hover': { textShadow: glow(neon.pink, 0.7) } }}>
              <Box component="span" sx={{ fontSize: 10, width: 10 }}>
                {openHosts.has(r.host) ? '▾' : '▸'}
              </Box>
              {r.host}
            </Box>
          )
        }
        if (r.kind === 'file') {
          const key = `${r.host}|${r.url}${r.path ? ` · ${r.path}` : ''}`
          return (
            <Stack sx={{ pl: 2.2, minWidth: 0, py: 0.4 }} spacing={0}>
              <Box onClick={() => toggle(openFiles, key, setOpenFiles)}
                sx={{ cursor: 'pointer', color: neon.cyan, fontSize: 11.5,
                      display: 'flex', gap: 0.8, alignItems: 'center',
                      overflow: 'hidden', textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      '&:hover': { textShadow: glow(neon.cyan, 0.6) } }}>
                <Box component="span" sx={{ fontSize: 10, width: 10 }}>
                  {openFiles.has(key) ? '▾' : '▸'}
                </Box>
                {r.url}
              </Box>
              {/* The file inside the bundle, when a source map gave
                  us one. A different fact from the URL: the URL is
                  what was served, this is where in it the value
                  sits. */}
              {r.path && (
                <Box sx={{ pl: 2.3, fontSize: 10.5,
                           color: alpha(neon.muted, 0.8),
                           overflow: 'hidden', textOverflow: 'ellipsis',
                           whiteSpace: 'nowrap' }}>
                  {r.path}
                </Box>
              )}
            </Stack>
          )
        }
        return (
          <Box sx={{ pl: 4.6, minWidth: 0 }}>
            <SecretCell value={r.row.secret}
              onSource={() => setSourceFor(r.row)} />
          </Box>
        )
      },
    },
    {
      field: 'count', headerName: 'Secrets', width: 96,
      valueGetter: by((h) => h.secrets),
      renderCell: (p) => {
        const r = p.row as Row
        if (r.kind === 'secret') return null
        return (
          <Box sx={{ color: neon.text, fontSize: 11.5 }}>
            {r.secrets}
            {r.kind === 'host' && (
              <Box component="span" sx={{ color: alpha(neon.muted, 0.8),
                                          fontSize: 10.5 }}>
                {` in ${r.files} file${r.files === 1 ? '' : 's'}`}
              </Box>
            )}
          </Box>
        )
      },
    },
    {
      field: 'detector', headerName: 'Detector', width: 180,
      // Not sortable, and this is the honest answer rather than a
      // missing feature: a host block holds several detectors, so
      // "order the hosts by detector" has no value to order by. A
      // header that offered it would be offering a no-op, which is
      // what the whole table was doing before.
      sortable: false,
      renderCell: (p) => {
        const r = p.row as Row
        if (r.kind !== 'secret') return null
        return (
          <Box sx={{ color: alpha(neon.muted, 0.9), fontSize: 11 }}>
            {r.row.detector || <Unrecorded why="No detector recorded." />}
          </Box>
        )
      },
    },
    {
      field: 'severity', headerName: 'Sev', width: 86,
      // The rank, not the word: sorted as a string, severity reads
      // critical, high, info, low, medium — "info" third, which is
      // actively misleading on a findings table.
      valueGetter: by((h) => h.worst),
      renderCell: (p) => {
        const r = p.row as Row
        // A group carries the worst of what is inside it, so a
        // collapsed host still says whether it is worth opening.
        const sev = r.kind === 'secret' ? r.row.severity : r.worst
        // On a secret row this is also the way to the finding behind
        // it. There used to be a `Finding` column for that and it was
        // a wide repeat of the title beside a label that already says
        // host, file and secret -- but it carried the only link, so
        // the link moves here rather than going with it.
        const open = r.kind === 'secret'
          ? () => onFinding(r.row.vuln_id) : undefined
        return (
          <Box onClick={open ? (e) => { e.stopPropagation(); open() } : undefined}
            title={open ? 'Show the full finding' : undefined}
            sx={{ color: SEV_COLOUR[sev] ?? neon.muted, fontSize: 10.5,
                  letterSpacing: '0.08em', textTransform: 'uppercase',
                  opacity: r.kind === 'secret' ? 1 : 0.75,
                  cursor: open ? 'pointer' : 'default',
                  '&:hover': open
                    ? { textShadow: glow(SEV_COLOUR[sev] ?? neon.muted, 0.7) }
                    : undefined }}>
            {sev}
          </Box>
        )
      },
    },
  ]

  return (
    <>
    <DataTable
      rows={rows}
      columns={columns as ColumnDef[]}
      loading={isLoading}
      error={error as Error | null}
      // Composed, because the list holds three kinds of row and a
      // host and a secret can no longer share a numeric id.
      getRowId={(r) => (r as Row).id}
      // No `kind`: that switch turns on add / bulk-edit / delete,
      // and this table is a reading of findings that live
      // elsewhere. Editing one here would edit nothing.
      tableId="secrets"
      project={project}
      canWrite={false}
      note={`${data?.length ?? 0} stored in clear across ${grouped.size} `
            + `host(s) — reading this list is written to the audit log`}
      extraActions={
        <Box
          onClick={() => {
            // Open everything, or shut everything. Two states and
            // no third: a control that half-opens is one nobody can
            // predict.
            if (openHosts.size) { setOpenHosts(new Set()); setOpenFiles(new Set()) }
            else {
              setOpenHosts(new Set(grouped.keys()))
              const files = new Set<string>()
              for (const [h, fs] of grouped) {
                for (const f of fs.keys()) files.add(`${h}|${f}`)
              }
              setOpenFiles(files)
            }
          }}
          sx={{ cursor: 'pointer', fontSize: 11.5, color: neon.cyan,
                '&:hover': { textShadow: glow(neon.cyan, 0.6) } }}>
          {openHosts.size ? 'Collapse all' : 'Expand all'}
        </Box>
      }
    />
    <SecretSourceModal
      vulnId={sourceFor?.vuln_id ?? null}
      triage={sourceFor?.triage ?? null}
      onClose={() => setSourceFor(null)} />
    </>
  )
}
