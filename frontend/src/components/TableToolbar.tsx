/**
 * The bar above every table: search, conditions, columns, density, export.
 *
 * Two things here are safety features rather than conveniences.
 *
 * **It is unconditional.** The old toolbar only appeared when the view
 * supplied an action, a note or write access, so `DroneTasksTable` — a
 * queue that is read-only by nature — had no search box, no filters and
 * no column control at all. A table with no way to filter it is not a
 * simpler table, it is a table you have to read by eye.
 *
 * **Every armed condition shows as a chip, always.** With one filter, a
 * closed panel and a small chip saying "filtered" was survivable. With
 * several, "why are there four rows" needs an answer you can read without
 * opening anything, which is the failure `backend/app/filtering.py` opens
 * its docstring by warning about. The chips are also how you remove one.
 */
import { useState, type ReactNode } from 'react'
import {
  Badge, Box, Button, Chip, Divider, FormControlLabel, InputAdornment,
  Menu, MenuItem, Popover, Stack, Switch, TextField, Tooltip, Typography, alpha,
} from '@mui/material'
import SearchIcon from '@mui/icons-material/Search'
import FilterListIcon from '@mui/icons-material/FilterList'
import ViewColumnIcon from '@mui/icons-material/ViewColumnOutlined'
import DensityIcon from '@mui/icons-material/DensityMediumOutlined'
import DownloadIcon from '@mui/icons-material/FileDownloadOutlined'
import {
  armedItems, describeItem,
  type ColumnDef, type Density, type FilterModel,
} from '../lib/columns'
import { TableFilterPanel, blankFilter } from './TableFilterPanel'
import { neon } from '../theme'

const DENSITIES: { value: Density; label: string }[] = [
  { value: 'compact', label: 'Compact' },
  { value: 'standard', label: 'Standard' },
  { value: 'comfortable', label: 'Comfortable' },
]

const btn = {
  fontSize: 11, py: 0.3, px: 1, color: neon.muted, minWidth: 0,
  '&:hover': { color: neon.cyan, backgroundColor: alpha(neon.cyan, 0.08) },
} as const

export function TableToolbar({
  columns, filter, onFilter, search, onSearch, columnVisibility,
  onColumnVisibility, density, onDensity, onExport, serverSide, actions,
  status, searchNote,
}: {
  columns: ColumnDef[]
  /** The model that is actually in force — the client view state, or the
   *  server query's. The toolbar must never read one while the other is
   *  doing the filtering, which is how Web ended up unable to show that
   *  it was filtered at all. */
  filter: FilterModel
  onFilter: (next: FilterModel) => void
  search: string
  onSearch: (next: string) => void
  columnVisibility: Record<string, boolean>
  onColumnVisibility: (next: Record<string, boolean>) => void
  density: Density
  onDensity: (next: Density) => void
  onExport: () => void
  serverSide?: boolean
  /** Add / edit / delete and whatever the view adds. */
  actions?: ReactNode
  /** The "remembered view" chip and the view's note. */
  status?: ReactNode
  searchNote?: string
}) {
  const [filterAt, setFilterAt] = useState<HTMLElement | null>(null)
  const [columnsAt, setColumnsAt] = useState<HTMLElement | null>(null)
  const [densityAt, setDensityAt] = useState<HTMLElement | null>(null)

  const armed = armedItems(filter)
  const byField = new Map(columns.map((c) => [c.field, c]))

  const openFilters = (el: HTMLElement) => {
    // Open on a blank row when there is nothing yet, so the first click
    // lands on something to fill in rather than on an empty box. It is
    // not armed, so it filters nothing until a value is typed.
    if (!(filter.items ?? []).length) {
      onFilter({ ...filter, items: [blankFilter(columns)] })
    }
    setFilterAt(el)
  }

  const dropItem = (item: typeof armed[number]) =>
    onFilter({ ...filter, items: (filter.items ?? []).filter((i) => i !== item) })

  return (
    <>
      <Stack direction="row" spacing={1} alignItems="center" sx={{
        px: 1.5, py: 0.9, borderBottom: `1px solid ${alpha(neon.pink, 0.22)}`,
        backgroundColor: alpha(neon.bgDeep, 0.45), flexWrap: 'wrap', rowGap: 0.8,
      }}>
        {actions}
        <Box sx={{ flex: 1, minWidth: 8 }} />
        {status}

        <TextField size="small" value={search} placeholder="search"
          onChange={(e) => onSearch(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ fontSize: 15, color: alpha(neon.muted, 0.8) }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{
            width: 190,
            '& .MuiInputBase-input': { py: 0.5, fontSize: 12, color: neon.text,
                                       fontFamily: `'Share Tech Mono', monospace` },
            '& .MuiOutlinedInput-notchedOutline': { borderColor: alpha(neon.purple, 0.4) },
          }} />

        <Tooltip title={searchNote ?? ''} disableHoverListener={!searchNote}>
          <span>
            <Badge badgeContent={armed.length} color="warning"
              slotProps={{ badge: { style: { fontSize: 9, height: 15, minWidth: 15 } } }}>
              <Button size="small" startIcon={<FilterListIcon sx={{ fontSize: 16 }} />}
                onClick={(e) => openFilters(e.currentTarget)}
                sx={{ ...btn, color: armed.length ? neon.yellow : neon.muted }}>
                Filters
              </Button>
            </Badge>
          </span>
        </Tooltip>

        <Button size="small" startIcon={<ViewColumnIcon sx={{ fontSize: 16 }} />}
          onClick={(e) => setColumnsAt(e.currentTarget)} sx={btn}>
          Columns
        </Button>
        <Button size="small" startIcon={<DensityIcon sx={{ fontSize: 15 }} />}
          onClick={(e) => setDensityAt(e.currentTarget)} sx={btn}>
          Density
        </Button>
        <Tooltip title="Download the rows on screen as CSV">
          <Button size="small" startIcon={<DownloadIcon sx={{ fontSize: 16 }} />}
            onClick={onExport} sx={btn}>
            Export
          </Button>
        </Tooltip>
      </Stack>

      {armed.length > 0 && (
        <Stack direction="row" spacing={0.7} alignItems="center" sx={{
          px: 1.5, py: 0.6, flexWrap: 'wrap', rowGap: 0.6,
          borderBottom: `1px solid ${alpha(neon.yellow, 0.25)}`,
          backgroundColor: alpha(neon.yellow, 0.06),
        }}>
          <Typography sx={{ fontSize: 10, letterSpacing: '0.14em',
                            textTransform: 'uppercase', color: neon.yellow,
                            fontFamily: `'Orbitron', sans-serif` }}>
            showing rows where
          </Typography>
          {armed.map((item, i) => (
            <Stack key={String(item.id ?? i)} direction="row" spacing={0.7}
              alignItems="center">
              {i > 0 && (
                <Typography sx={{ fontSize: 10, letterSpacing: '0.1em',
                                  textTransform: 'uppercase', color: alpha(neon.muted, 0.9) }}>
                  {filter.logicOperator === 'or' ? 'or' : 'and'}
                </Typography>
              )}
              <Chip size="small" label={describeItem(item, byField.get(item.field))}
                onDelete={() => dropItem(item)}
                onClick={(e) => openFilters(e.currentTarget)}
                sx={{
                  height: 20, fontSize: 10.5, maxWidth: 320,
                  bgcolor: alpha(neon.yellow, 0.14), color: neon.yellow,
                  border: `1px solid ${alpha(neon.yellow, 0.5)}`,
                  '& .MuiChip-deleteIcon': {
                    color: 'inherit', fontSize: 14, '&:hover': { color: neon.pink } },
                }} />
            </Stack>
          ))}
        </Stack>
      )}

      <TableFilterPanel
        open={!!filterAt} anchorEl={filterAt} onClose={() => setFilterAt(null)}
        columns={columns} model={filter} onChange={onFilter} serverSide={serverSide} />

      <Popover open={!!columnsAt} anchorEl={columnsAt} onClose={() => setColumnsAt(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.99), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.4)}`, p: 1, maxHeight: 420,
        } } }}>
        <Stack sx={{ minWidth: 190 }}>
          {columns.map((c) => (
            <FormControlLabel key={c.field} sx={{ ml: 0, mr: 0 }}
              control={
                <Switch size="small" checked={columnVisibility[c.field] !== false}
                  onChange={(e) => onColumnVisibility({
                    ...columnVisibility, [c.field]: e.target.checked,
                  })}
                  sx={{ '& .Mui-checked': { color: neon.cyan } }} />
              }
              label={
                <Typography sx={{ fontSize: 12, color: neon.text }}>
                  {c.headerName || c.field}
                </Typography>
              } />
          ))}
          <Divider sx={{ my: 0.5, borderColor: alpha(neon.purple, 0.25) }} />
          <Button size="small" sx={{ ...btn, alignSelf: 'flex-start' }}
            onClick={() => onColumnVisibility(
              Object.fromEntries(columns.map((c) => [c.field, true])))}>
            Show all
          </Button>
        </Stack>
      </Popover>

      <Menu open={!!densityAt} anchorEl={densityAt} onClose={() => setDensityAt(null)}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.4)}`,
        } } }}>
        {DENSITIES.map((d) => (
          <MenuItem key={d.value} selected={d.value === density}
            onClick={() => { onDensity(d.value); setDensityAt(null) }}
            sx={{ fontSize: 12.5, color: d.value === density ? neon.cyan : neon.text }}>
            {d.label}
          </MenuItem>
        ))}
      </Menu>
    </>
  )
}
