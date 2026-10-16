/**
 * Several filter conditions at once, joined by AND or OR.
 *
 * This is the thing the free `@mui/x-data-grid` would not do. Its
 * `useDataGridProps` hardcodes `disableMultipleColumnsFiltering: true`, so
 * adding a second condition replaced the first — multi-column filtering is
 * a paid-tier gate. "Status 500 AND the URL contains admin" is an ordinary
 * question to ask of a findings table, and having to ask it one half at a
 * time is how something gets missed.
 *
 * The model is a list and a connective, which is exactly what
 * `backend/app/filtering.py` already accepted:
 *
 *     filters=[{"field":"status_code","op":">=","value":"500"},
 *              {"field":"url","op":"contains","value":"admin"}]
 *     logic=and
 *
 * so the server-paged tables got multi-filter the moment the UI could
 * express it. The operator names offered here are only ones that file
 * knows — it raises 400 on anything else rather than returning unfiltered
 * rows, and a 400 reads to an operator as a broken table.
 */
import { useMemo } from 'react'
import {
  Box, Button, IconButton, MenuItem, Popover, Stack, TextField,
  ToggleButton, ToggleButtonGroup, Tooltip, Typography, alpha,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import CloseIcon from '@mui/icons-material/Close'
import StorageIcon from '@mui/icons-material/StorageOutlined'
import {
  defaultOperator, filterableColumns, findOperator, operatorsFor,
  type ColumnDef, type FilterItem, type FilterModel, type ValueOption,
} from '../lib/columns'
import { neon } from '../theme'

/** Ids only have to be unique within one panel; they never travel. */
let nextId = 1
export function blankFilter(columns: ColumnDef[]): FilterItem {
  const col = filterableColumns(columns)[0]
  return { id: nextId++, field: col?.field ?? '', operator: defaultOperator(col) }
}

function options(col: ColumnDef | undefined): ValueOption[] {
  return (col?.valueOptions ?? []).map((o) =>
    (typeof o === 'object' && o !== null && 'value' in o)
      ? o as ValueOption
      : { value: o, label: String(o) })
}

const field = {
  '& .MuiInputBase-input': {
    py: 0.55, fontSize: 12, fontFamily: `'Share Tech Mono', monospace`,
    color: neon.text,
  },
  '& .MuiOutlinedInput-notchedOutline': { borderColor: alpha(neon.purple, 0.4) },
} as const

export function TableFilterPanel({
  open, anchorEl, onClose, columns, model, onChange, serverSide,
}: {
  open: boolean
  anchorEl: HTMLElement | null
  onClose: () => void
  /** Already narrowed: in server mode, a column the API will not filter
   *  on has been marked unfilterable upstream and so never appears. */
  columns: ColumnDef[]
  model: FilterModel
  onChange: (next: FilterModel) => void
  serverSide?: boolean
}) {
  const filterable = useMemo(() => filterableColumns(columns), [columns])
  const byField = useMemo(
    () => new Map(columns.map((c) => [c.field, c])), [columns])

  const items = model.items ?? []
  const logic = model.logicOperator ?? 'and'

  const put = (next: FilterItem[]) => onChange({ ...model, items: next })
  const patch = (i: number, change: Partial<FilterItem>) =>
    put(items.map((item, n) => (n === i ? { ...item, ...change } : item)))

  /** Changing the column can invalidate the operator — a number column
   *  has no "starts with" — so fall back rather than send one the server
   *  will reject. The value goes too: it was chosen for the old column. */
  const changeColumn = (i: number, f: string) => {
    const col = byField.get(f)
    const keep = findOperator(col, String(items[i].operator))
    patch(i, {
      field: f,
      operator: keep ? items[i].operator : defaultOperator(col),
      value: keep ? items[i].value : undefined,
    })
  }

  const row = (item: FilterItem, i: number) => {
    const col = byField.get(item.field)
    const op = findOperator(col, String(item.operator))
    const choices = options(col)

    const value = () => {
      if (op && !op.needsValue) {
        return (
          <Typography sx={{ fontSize: 11.5, color: alpha(neon.muted, 0.8),
                            alignSelf: 'center', flex: 1 }}>
            no value needed
          </Typography>
        )
      }
      if (op?.list) {
        // A list, typed as one string. Splitting on the comma here rather
        // than making the user add rows one at a time is the difference
        // between "is any of 200, 401, 403" and three OR conditions.
        const shown = Array.isArray(item.value)
          ? (item.value as unknown[]).map(String).join(', ')
          : String(item.value ?? '')
        return (
          <TextField size="small" sx={{ ...field, flex: 1 }} value={shown}
            placeholder="200, 401, 403"
            onChange={(e) => patch(i, {
              value: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
            })} />
        )
      }
      if (col?.type === 'boolean') {
        return (
          <TextField select size="small" sx={{ ...field, flex: 1 }}
            value={item.value === undefined || item.value === null ? '' : String(item.value)}
            onChange={(e) => patch(i, { value: e.target.value === 'true' })}>
            <MenuItem value="true" sx={{ fontSize: 12 }}>true</MenuItem>
            <MenuItem value="false" sx={{ fontSize: 12 }}>false</MenuItem>
          </TextField>
        )
      }
      if (choices.length) {
        return (
          <TextField select size="small" sx={{ ...field, flex: 1 }}
            value={item.value === undefined || item.value === null ? '' : String(item.value)}
            onChange={(e) => {
              // Hand back the option's own value, not the string the
              // Select carried it in: `alive` is a real boolean and the
              // comparison downstream depends on it staying one.
              const picked = choices.find((o) => String(o.value) === e.target.value)
              patch(i, { value: picked ? picked.value : e.target.value })
            }}>
            {choices.map((o) => (
              <MenuItem key={String(o.value)} value={String(o.value)} sx={{ fontSize: 12 }}>
                {o.label}
              </MenuItem>
            ))}
          </TextField>
        )
      }
      return (
        <TextField size="small" sx={{ ...field, flex: 1 }}
          type={col?.type === 'number' ? 'number' : 'text'}
          value={item.value === undefined || item.value === null ? '' : String(item.value)}
          placeholder="value"
          onChange={(e) => patch(i, { value: e.target.value })} />
      )
    }

    return (
      <Stack key={String(item.id ?? i)} direction="row" spacing={0.8} alignItems="center">
        <Box sx={{ width: 42, flexShrink: 0, fontSize: 10.5, letterSpacing: '0.1em',
                   textTransform: 'uppercase', color: alpha(neon.muted, 0.85),
                   textAlign: 'right' }}>
          {i === 0 ? 'where' : logic}
        </Box>
        <TextField select size="small" sx={{ ...field, width: 150 }}
          value={byField.has(item.field) ? item.field : ''}
          onChange={(e) => changeColumn(i, e.target.value)}>
          {filterable.map((c) => (
            <MenuItem key={c.field} value={c.field} sx={{ fontSize: 12 }}>
              {c.headerName || c.field}
            </MenuItem>
          ))}
        </TextField>
        <TextField select size="small" sx={{ ...field, width: 140 }}
          value={op ? item.operator : defaultOperator(byField.get(item.field))}
          onChange={(e) => patch(i, { operator: e.target.value })}>
          {operatorsFor(byField.get(item.field)).map((o) => (
            <MenuItem key={o.value} value={o.value} sx={{ fontSize: 12 }}>
              {o.label}
            </MenuItem>
          ))}
        </TextField>
        {value()}
        <Tooltip title="Remove this condition">
          <IconButton size="small" onClick={() => put(items.filter((_, n) => n !== i))}
            sx={{ color: alpha(neon.muted, 0.8), '&:hover': { color: neon.red } }}>
            <CloseIcon sx={{ fontSize: 15 }} />
          </IconButton>
        </Tooltip>
      </Stack>
    )
  }

  return (
    <Popover open={open} anchorEl={anchorEl} onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.99), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.45)}`,
        boxShadow: `0 0 26px ${alpha(neon.cyan, 0.2)}`,
        p: 1.5, maxWidth: '96vw',
      } } }}>
      <Stack spacing={1}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10.5,
                            letterSpacing: '0.16em', textTransform: 'uppercase',
                            color: neon.cyan }}>
            Show rows where
          </Typography>
          <Box sx={{ flex: 1 }} />
          {items.length > 1 && (
            <ToggleButtonGroup size="small" exclusive value={logic}
              onChange={(_, v) => v && onChange({ ...model, logicOperator: v })}>
              <ToggleButton value="and" sx={toggleSx}>all of them</ToggleButton>
              <ToggleButton value="or" sx={toggleSx}>any of them</ToggleButton>
            </ToggleButtonGroup>
          )}
        </Stack>

        {items.length === 0 && (
          <Typography sx={{ fontSize: 12, color: alpha(neon.muted, 0.85), py: 1 }}>
            No conditions. Everything is shown.
          </Typography>
        )}
        {items.map(row)}

        <Stack direction="row" spacing={1} alignItems="center">
          <Button size="small" startIcon={<AddIcon sx={{ fontSize: 15 }} />}
            onClick={() => put([...items, blankFilter(filterable)])}
            sx={{ color: neon.green, fontSize: 11 }}>
            Add condition
          </Button>
          {items.length > 0 && (
            <Button size="small" onClick={() => put([])}
              sx={{ color: neon.muted, fontSize: 11 }}>
              Remove all
            </Button>
          )}
          <Box sx={{ flex: 1 }} />
          {serverSide && (
            <Tooltip title={'Evaluated in SQL over the whole table, not over '
                          + 'the page on screen. Columns the API will not '
                          + 'filter on are left out of the list rather than '
                          + 'offered and then rejected.'}>
              <Stack direction="row" spacing={0.5} alignItems="center">
                <StorageIcon sx={{ fontSize: 14, color: alpha(neon.muted, 0.8) }} />
                <Typography sx={{ fontSize: 10.5, color: alpha(neon.muted, 0.8) }}>
                  filtered in the database
                </Typography>
              </Stack>
            </Tooltip>
          )}
        </Stack>
      </Stack>
    </Popover>
  )
}

const toggleSx = {
  fontSize: 10, py: 0.2, px: 0.9, color: neon.muted,
  borderColor: alpha(neon.purple, 0.4),
  '&.Mui-selected': { color: neon.cyan, bgcolor: alpha(neon.cyan, 0.12) },
} as const
