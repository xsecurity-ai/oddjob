/**
 * Right-click on a column header.
 *
 * The filter panel in the toolbar is the full instrument — every column,
 * every operator, AND/OR joins — but it starts from nothing: you open it
 * and then find your column in a dropdown. "I want THIS column to be only
 * 500s" deserves a shorter path than that, and right-clicking the header
 * of the column is where that intent already lives.
 *
 * So this menu does one thing well: it pre-fills a condition for the
 * column under the cursor and hands it to the same `FilterModel` the panel
 * edits. Whatever is chosen here shows up as a chip in the toolbar, can be
 * refined or removed there, and survives a reload exactly like any other
 * condition — because it IS one of those, written through the same model.
 */
import { Menu, MenuItem, Typography, alpha } from '@mui/material'
import FilterListIcon from '@mui/icons-material/FilterList'
import {
  armedItems, operatorsFor, withFieldCondition,
  type ColumnDef, type FilterModel,
} from '../lib/columns'
import { neon } from '../theme'

export function TableHeaderMenu({
  open, anchorEl, onClose, column, model, onFilter,
}: {
  open: boolean
  anchorEl: HTMLElement | null
  onClose: () => void
  /** The column under the cursor. `null` closes nothing — the menu is
   *  only ever opened for a real column. */
  column: ColumnDef | null
  model: FilterModel
  onFilter: (next: FilterModel) => void
}) {
  if (!column) return null

  const ops = operatorsFor(column)
  const existing = armedItems(model).find((i) => i.field === column.field)
  const name = column.headerName || column.field

  return (
    <Menu open={open} anchorEl={anchorEl} onClose={onClose}
      slotProps={{ paper: { sx: {
        backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
        border: `1px solid ${alpha(neon.cyan, 0.4)}`,
        boxShadow: `0 0 20px ${alpha(neon.cyan, 0.15)}`,
        minWidth: 230, p: 0.5,
      } } }}>
      <Typography sx={{ px: 1.5, py: 0.9, fontSize: 10.5, letterSpacing: '0.14em',
                       textTransform: 'uppercase', color: neon.cyan,
                       fontFamily: `'Orbitron', sans-serif` }}>
        Filter {name}
      </Typography>
      {ops.map((o) => (
        <MenuItem key={o.value} onClick={() => {
          onFilter(withFieldCondition(model, column.field, o.value))
          onClose()
        }}
          sx={{ fontSize: 12.5, color: neon.text, py: 0.5 }}>
          {o.label}
        </MenuItem>
      ))}
      <MenuItem onClick={() => {
        onFilter({ ...model, items: (model.items ?? [])
          .filter((i) => i.field !== column.field) })
        onClose()
      }}
        disabled={!existing}
        sx={{ fontSize: 12.5, color: existing ? neon.pink : alpha(neon.muted, 0.6), py: 0.5 }}>
        <FilterListIcon sx={{ fontSize: 14, mr: 1 }} />
        Remove filter on {name}
      </MenuItem>
    </Menu>
  )
}
