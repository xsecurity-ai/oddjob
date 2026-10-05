import { useState, type FormEvent } from 'react'
import {
  Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControlLabel, MenuItem, Stack, TextField, Typography, alpha,
} from '@mui/material'
import { useQueryClient } from '@tanstack/react-query'
import { api, type EntityKind } from '../lib/api'
import { SPECS, LABELS, createFor, type FieldSpec } from '../lib/entities'
import { neon, glow } from '../theme'
import { maybeSortedBy } from '../lib/sortOptions'

/**
 * One dialog serving both "add a row" and "edit the selected rows".
 *
 * In bulk mode each field has an explicit "change this" checkbox. Without it
 * there is no way to distinguish "leave as-is" from "set to empty", and a
 * bulk edit that silently blanks every field the user did not think about is
 * unrecoverable.
 */
export function EntityDialog({
  kind, project, mode, ids, onClose,
}: {
  kind: EntityKind
  project: string
  mode: 'create' | 'bulk'
  ids?: number[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const spec = SPECS[kind].filter((f) => (mode === 'bulk' ? f.bulk !== false : true))
  const [values, setValues] = useState<Record<string, unknown>>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [err, setErr] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const set = (n: string, v: unknown) => setValues((o) => ({ ...o, [n]: v }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(null); setNote(null); setBusy(true)
    try {
      if (mode === 'create') {
        const body: Record<string, unknown> = {}
        for (const f of spec) {
          const v = values[f.name]
          if (v !== undefined && v !== '') body[f.name] = v
          if (f.required && (v === undefined || v === '')) {
            throw new Error(`${f.label} is required`)
          }
        }
        await createFor(kind, project, body)
      } else {
        const fields: Record<string, unknown> = {}
        for (const f of spec) if (touched[f.name]) fields[f.name] = values[f.name] ?? null
        if (!Object.keys(fields).length) throw new Error('Tick at least one field to change.')
        const r = await api.bulkPatch(kind, ids ?? [], fields)
        if (r.errors.length) {
          // Partial success is the normal case for a selection spanning
          // projects, so report it rather than implying it all worked.
          setNote(`${r.changed} changed, ${r.skipped} skipped — ${r.errors.join('; ')}`)
          await qc.invalidateQueries()
          setBusy(false)
          return
        }
      }
      await qc.invalidateQueries()
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const field = (f: FieldSpec) => {
    const v = values[f.name]
    const disabled = mode === 'bulk' && !touched[f.name]
    const common = { size: 'small' as const, fullWidth: true, disabled }

    let input
    if (f.type === 'bool') {
      input = (
        <FormControlLabel
          disabled={disabled}
          control={<Checkbox checked={!!v} onChange={(e) => set(f.name, e.target.checked)}
                             sx={{ color: neon.muted, '&.Mui-checked': { color: neon.pink } }} />}
          label={<Typography sx={{ fontSize: 13 }}>{f.label}</Typography>}
        />
      )
    } else if (f.type === 'tristate' || f.type === 'select') {
      input = (
        <TextField {...common} select label={f.label}
          value={v === null ? '__null__' : v ?? ''}
          onChange={(e) => {
            const raw = e.target.value
            set(f.name, raw === '__null__' ? null : raw === 'true' ? true : raw === 'false' ? false : raw)
          }}>
          {maybeSortedBy(f.options ?? [], (o) => o.value, (o) => o.label).map((o) => (
            <MenuItem key={String(o.value)} value={o.value === null ? '__null__' : String(o.value)}
                      sx={{ fontSize: 13 }}>
              {o.label}
            </MenuItem>
          ))}
        </TextField>
      )
    } else {
      input = (
        <TextField {...common} label={f.label}
          type={f.type === 'number' ? 'number' : 'text'}
          multiline={f.type === 'multiline'} minRows={f.type === 'multiline' ? 2 : undefined}
          value={(v as string) ?? ''}
          onChange={(e) => set(f.name,
            f.type === 'number'
              ? (e.target.value === '' ? null : Number(e.target.value))
              : e.target.value)}
          required={mode === 'create' && f.required}
        />
      )
    }

    return (
      <Stack key={f.name} direction="row" spacing={1} alignItems="flex-start">
        {mode === 'bulk' && (
          <Checkbox
            checked={!!touched[f.name]} size="small"
            onChange={(e) => setTouched((o) => ({ ...o, [f.name]: e.target.checked }))}
            sx={{ mt: 0.6, color: neon.muted, '&.Mui-checked': { color: neon.cyan } }}
          />
        )}
        <Box sx={{ flex: 1 }}>
          {input}
          {f.help && (
            <Typography sx={{ mt: 0.4, fontSize: 10.5, color: alpha(neon.muted, 0.8) }}>
              {f.help}
            </Typography>
          )}
        </Box>
      </Stack>
    )
  }

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth component="form" onSubmit={submit}
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.97), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 36px ${alpha(neon.cyan, 0.2)}`,
      } } }}>
      <DialogTitle sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 13,
                         letterSpacing: '0.14em', color: neon.cyan,
                         textShadow: glow(neon.cyan, 0.5) }}>
        {mode === 'create'
          ? `NEW ${LABELS[kind].toUpperCase()}`
          : `EDIT ${ids?.length} ${LABELS[kind].toUpperCase()}${(ids?.length ?? 0) > 1 ? 'S' : ''}`}
      </DialogTitle>
      <DialogContent>
        {mode === 'bulk' && (
          <Typography sx={{ mb: 2, fontSize: 12, color: neon.muted }}>
            Tick a field to change it. Unticked fields are left exactly as they are.
          </Typography>
        )}
        {err && <Alert severity="error" variant="outlined" sx={{ mb: 2, fontSize: 12.5 }}>{err}</Alert>}
        {note && <Alert severity="warning" variant="outlined" sx={{ mb: 2, fontSize: 12.5 }}>{note}</Alert>}
        <Stack spacing={1.8} sx={{ mt: 0.5 }}>{spec.map(field)}</Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ color: neon.muted }}>Cancel</Button>
        <Button type="submit" variant="outlined" disabled={busy}
          sx={{ color: neon.cyan, borderColor: alpha(neon.cyan, 0.6),
                '&:hover': { borderColor: neon.cyan } }}>
          {busy ? '…' : mode === 'create' ? 'Create' : 'Apply'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
