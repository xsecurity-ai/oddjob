import { useState } from 'react'
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
  const [sourceFor, setSourceFor] = useState<number | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['secrets', project],
    queryFn: () => api.secrets(project ?? undefined),
    // Credentials, so they do not sit in the cache behind the
    // user's back after they navigate away.
    gcTime: 0,
    staleTime: 0,
  })

  const columns: ColumnDef<SecretRow>[] = [
    {
      field: 'secret', headerName: 'Secret', flex: 3, minWidth: 300,
      renderCell: (p) => (
        <SecretCell value={String(p.value ?? '')}
          onSource={() => setSourceFor((p.row as SecretRow).vuln_id)} />
      ),
    },
    {
      field: 'asset_url', headerName: 'URL', flex: 3, minWidth: 280,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => {
        const row = p.row as SecretRow
        if (!row.asset_url) {
          return <Unrecorded why="This finding predates the origin being stored as a field. The URL may still be in the finding's description." />
        }
        return (
          <Stack spacing={0} sx={{ py: 0.5, minWidth: 0 }}>
            <Box
              component="a" href={row.asset_url} target="_blank" rel="noreferrer noopener"
              onClick={(e) => e.stopPropagation()}
              sx={{
                color: neon.cyan, fontSize: 11.5, textDecoration: 'none',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                '&:hover': { textShadow: glow(neon.cyan, 0.6) },
              }}>
              {row.asset_url}
            </Box>
            {/* The file inside the bundle, when a sourcemap gave us
                one. Different fact from the URL: the URL is what
                was served, this is where in it the value sits. */}
            {row.path && (
              <Box sx={{
                fontSize: 10.5, color: alpha(neon.muted, 0.8),
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {row.path}{row.line ? `:${row.line}` : ''}
              </Box>
            )}
          </Stack>
        )
      },
    },
    {
      field: 'host', headerName: 'Target', flex: 1, minWidth: 180,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (
        <Box sx={{ color: neon.pink, fontWeight: 600, fontSize: 11.5 }}>
          {String(p.value || '—')}
        </Box>
      ),
    },
    {
      field: 'detector', headerName: 'Detector', width: 180,
      valueGetter: (v) => v ?? '',
      renderCell: (p) => (
        <Box sx={{ color: alpha(neon.muted, 0.9), fontSize: 11 }}>{p.value}</Box>
      ),
    },
    {
      field: 'severity', headerName: 'Sev', width: 86,
      renderCell: (p) => (
        <Box sx={{
          color: SEV_COLOUR[String(p.value)] ?? neon.muted,
          fontSize: 10.5, letterSpacing: '0.08em', textTransform: 'uppercase',
        }}>{p.value}</Box>
      ),
    },
    {
      field: 'title', headerName: 'Finding', flex: 2, minWidth: 220,
      renderCell: (p) => (
        <Box
          onClick={(e) => { e.stopPropagation(); onFinding((p.row as SecretRow).vuln_id) }}
          title="Show the full finding"
          sx={{
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            cursor: 'pointer', color: neon.text, fontSize: 11.5,
            '&:hover': { color: neon.cyan, textShadow: glow(neon.cyan, 0.5) },
          }}>
          {p.value}
        </Box>
      ),
    },
    {
      field: 'project_code', headerName: 'Project', width: 120,
      renderCell: (p) => (
        <Box sx={{ color: neon.purple, fontSize: 11.5, letterSpacing: '0.06em' }}>
          {p.value}
        </Box>
      ),
    },
  ]

  return (
    <>
    <DataTable
      rows={data ?? []}
      columns={columns as ColumnDef[]}
      loading={isLoading}
      error={error as Error | null}
      getRowId={(r) => (r as SecretRow).vuln_id}
      // No `kind`: that switch turns on add / bulk-edit / delete,
      // and this table is a reading of findings that live
      // elsewhere. Editing one here would edit nothing.
      tableId="secrets"
      project={project}
      canWrite={false}
      hiddenColumns={project ? { project_code: false } : undefined}
      note={`${data?.length ?? 0} stored in clear — reading this list is written to the audit log`}
    />
    <SecretSourceModal vulnId={sourceFor} onClose={() => setSourceFor(null)} />
    </>
  )
}
