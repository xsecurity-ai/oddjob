/**
 * Where a scope document contradicts itself, and how to resolve it.
 *
 * A host named in the IN list whose address is named in the OUT
 * list. The gate refuses it — out wins, because the traffic would
 * still reach an excluded machine — so every one of these is a host
 * the engagement believes it is testing and is not.
 *
 * **The two shapes point opposite ways**, which is why this shows
 * them apart rather than offering one button:
 *
 *   - an address serving ONE in-scope host: the exclusion was about
 *     that host, so the NAME is what should go.
 *   - an address serving SEVERAL: a CDN edge or shared hosting, so
 *     the exclusion was about the infrastructure and not the
 *     applications on it — the ADDRESS entry is what should go.
 *
 * One rule for both is how an engagement either scans a box the
 * client excluded or drops coverage it was authorised for. Nothing
 * here happens on its own: the rows to delete are named, and the
 * server re-checks them against what the strategy would choose at
 * the moment of the click.
 */
import { useState } from 'react'
import {
  Alert, Box, Button, Chip, CircularProgress, Paper, Stack, Table,
  TableBody, TableCell, TableHead, TableRow, Tooltip, Typography, alpha,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ScopeConflict } from '../lib/api'
import { neon } from '../theme'

/** Which entries a strategy removes, worked out on the client so the
 *  button can say how many before it is pressed. Mirrors
 *  `scopeconflicts.entries_to_remove`; the server recomputes it and
 *  refuses anything outside, so a drift here is caught rather than
 *  acted on. */
function wouldRemove(rows: ScopeConflict[], strategy: string): number[] {
  const ids = new Set<number>()
  for (const c of rows) {
    if (strategy === 'suggested') {
      ids.add(c.kind === 'shared' ? c.out_entry_id : c.in_entry_id)
    } else if (strategy === 'keep_exclusions') {
      ids.add(c.in_entry_id)
    } else if (strategy === 'keep_names') {
      ids.add(c.out_entry_id)
    }
  }
  return [...ids]
}

export function ScopeConflicts({ project, canAdmin }: {
  project: string
  canAdmin: boolean
}) {
  const qc = useQueryClient()
  const [said, setSaid] = useState<string | null>(null)
  const [show, setShow] = useState(false)

  const q = useQuery({
    queryKey: ['scope-conflicts', project],
    queryFn: () => api.scopeConflicts(project),
  })

  const resolve = useMutation({
    mutationFn: (strategy: string) =>
      api.resolveScopeConflicts(project, strategy,
                                wouldRemove(q.data?.conflicts ?? [], strategy)),
    onSuccess: (r) => {
      setSaid(r.detail)
      void qc.invalidateQueries({ queryKey: ['scope-conflicts', project] })
      void qc.invalidateQueries({ queryKey: ['scope', project] })
      void qc.invalidateQueries({ queryKey: ['scope-violations', project] })
    },
    onError: (e) => setSaid((e as Error).message),
  })

  const d = q.data
  const rows = d?.conflicts ?? []

  return (
    <Box sx={{ mt: 3 }}>
      <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
                        letterSpacing: '0.14em', textTransform: 'uppercase',
                        color: neon.cyan, mb: 1 }}>
        Contradictions
      </Typography>
      <Paper variant="outlined"
        sx={{ p: 2, borderColor: alpha(neon.red, 0.3) }}>
        {q.isLoading && <CircularProgress size={18} sx={{ color: neon.cyan }} />}
        {q.error && (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 12 }}>
            {(q.error as Error).message}
          </Alert>
        )}

        {d && rows.length === 0 && (
          <Typography sx={{ fontSize: 12.5, color: neon.muted }}>
            {d.detail}
          </Typography>
        )}

        {d && rows.length > 0 && (
          <>
            <Typography sx={{ fontSize: 12.5, color: neon.text, mb: 1,
                              lineHeight: 1.7 }}>
              <strong>{rows.length}</strong> contradiction(s) across{' '}
              <strong>{d.hosts}</strong> host(s). Each is in scope by name
              and out of scope by address, so the gate refuses it — these
              hosts are not being tested.
            </Typography>
            <Typography sx={{ fontSize: 11.5, color: neon.muted, mb: 1.6,
                              lineHeight: 1.7 }}>
              <strong>{d.shared}</strong> are on an address shared by
              several in-scope hosts — a CDN edge or shared hosting, where
              the exclusion was about the infrastructure rather than the
              applications on it.{' '}
              <strong>{d.single}</strong> are on an address serving one
              host, where the exclusion was most likely about that host.
            </Typography>

            {canAdmin && (
              <Stack direction="row" spacing={1} useFlexGap
                sx={{ flexWrap: 'wrap', mb: 1.6 }}>
                <Tooltip title="Drops the exclusion where an address is
                                shared by several in-scope hosts, and the
                                name where it serves one.">
                  <Button size="small" variant="outlined"
                    disabled={resolve.isPending}
                    onClick={() => resolve.mutate('suggested')}
                    sx={{ color: neon.green,
                          borderColor: alpha(neon.green, 0.5) }}>
                    Resolve as suggested
                    {' '}({wouldRemove(rows, 'suggested').length})
                  </Button>
                </Tooltip>
                <Tooltip title="Drops every conflicting NAME. Nothing new
                                becomes testable — the behaviour is
                                unchanged and the contradiction goes.">
                  <Button size="small" disabled={resolve.isPending}
                    onClick={() => resolve.mutate('keep_exclusions')}
                    sx={{ color: neon.muted }}>
                    Keep exclusions ({wouldRemove(rows, 'keep_exclusions').length})
                  </Button>
                </Tooltip>
                <Tooltip title="Drops every conflicting ADDRESS EXCLUSION,
                                which makes these hosts testable. This one
                                puts traffic where the lists currently say
                                not to.">
                  <Button size="small" disabled={resolve.isPending}
                    onClick={() => resolve.mutate('keep_names')}
                    sx={{ color: neon.yellow }}>
                    Keep names ({wouldRemove(rows, 'keep_names').length})
                  </Button>
                </Tooltip>
              </Stack>
            )}

            {said && (
              <Alert severity={resolve.isError ? 'error' : 'success'}
                variant="outlined" sx={{ fontSize: 12, mb: 1.6 }}
                onClose={() => setSaid(null)}>
                {said}
              </Alert>
            )}

            <Button size="small" onClick={() => setShow((v) => !v)}
              sx={{ color: neon.cyan, fontSize: 11.5 }}>
              {show ? 'Hide' : `Show all ${rows.length}`}
            </Button>

            {show && (
              <Table size="small" sx={{ mt: 1 }}>
                <TableHead>
                  <TableRow>
                    {['Host', 'Address', 'On that address', 'Resolve by']
                      .map((h) => (
                        <TableCell key={h} sx={{ fontSize: 10.5 }}>{h}</TableCell>
                      ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map((c) => (
                    <TableRow key={`${c.host}-${c.address}`} hover>
                      <TableCell sx={{ py: 0.4, fontSize: 12,
                                       fontFamily: `'Share Tech Mono', monospace` }}>
                        {c.host}
                      </TableCell>
                      <TableCell sx={{ py: 0.4, fontSize: 12,
                                       color: neon.muted,
                                       fontFamily: `'Share Tech Mono', monospace` }}>
                        {c.address}
                      </TableCell>
                      <TableCell sx={{ py: 0.4, fontSize: 11.5 }}>
                        {c.shared_with} in-scope host
                        {c.shared_with === 1 ? '' : 's'}
                      </TableCell>
                      <TableCell sx={{ py: 0.4 }}>
                        <Chip size="small"
                          label={c.suggestion === 'out_entry'
                            ? `drop exclusion ${c.out_entry}`
                            : `drop name ${c.in_entry}`}
                          sx={{ height: 18, fontSize: 10,
                                color: c.suggestion === 'out_entry'
                                  ? neon.yellow : neon.muted,
                                border: `1px solid ${alpha(
                                  c.suggestion === 'out_entry'
                                    ? neon.yellow : neon.muted, 0.45)}` }} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}
      </Paper>
    </Box>
  )
}
