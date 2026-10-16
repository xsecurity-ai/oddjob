/** Our own pagination bar.
 *
 * The MIT DataGrid throws for any page size above 100, so it cannot be
 * the thing paginating when the answer needs to be 250 or 500. The grid
 * is handed one page and told to show all of it; this is the control
 * that decides which page.
 */
import { Box, IconButton, MenuItem, Stack, TextField, Tooltip, Typography, alpha } from '@mui/material'
import FirstPageIcon from '@mui/icons-material/FirstPage'
import LastPageIcon from '@mui/icons-material/LastPage'
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import { PAGE_SIZES } from '../lib/useServerTable'
import { neon } from '../theme'

export function TableFooter({
  page, pageSize, total, onPage, onPageSize, loading, note,
}: {
  page: number
  pageSize: number
  total: number
  onPage: (n: number) => void
  onPageSize: (n: number) => void
  loading?: boolean
  /** Shown on the left, e.g. where the rows came from. */
  note?: string
}) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  const here = Math.min(page, pages - 1)
  const first = total === 0 ? 0 : here * pageSize + 1
  const last = Math.min(total, (here + 1) * pageSize)

  const nav = (label: string, icon: React.ReactNode, to: number, off: boolean) => (
    <Tooltip title={label}>
      <span>
        <IconButton size="small" disabled={off || loading} onClick={() => onPage(to)}
          sx={{ color: neon.cyan, '&.Mui-disabled': { color: alpha(neon.muted, 0.4) } }}>
          {icon}
        </IconButton>
      </span>
    </Tooltip>
  )

  return (
    <Stack direction="row" alignItems="center" spacing={1.5}
      sx={{ px: 1.5, py: 0.75, borderTop: `1px solid ${alpha(neon.cyan, 0.25)}`,
            flexWrap: 'wrap', rowGap: 0.5 }}>
      {note && (
        <Typography sx={{ fontSize: 11, color: neon.muted }}>{note}</Typography>
      )}
      <Box sx={{ flex: 1 }} />

      <Typography sx={{ fontSize: 11.5, color: neon.muted }}>rows per page</Typography>
      <TextField
        select size="small" value={pageSize}
        onChange={(e) => onPageSize(Number(e.target.value))}
        slotProps={{ select: { MenuProps: { disablePortal: false } } }}
        sx={{ width: 92, '& .MuiInputBase-input': { py: 0.4, fontSize: 11.5,
              fontFamily: `'Share Tech Mono', monospace`, color: neon.text } }}>
        {PAGE_SIZES.map((n) => (
          <MenuItem key={n} value={n} sx={{ fontSize: 11.5 }}>{n}</MenuItem>
        ))}
      </TextField>

      <Typography sx={{ fontSize: 11.5, color: neon.text, minWidth: 150,
                        textAlign: 'right' }}>
        {total === 0
          ? 'no rows'
          : `${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}`}
      </Typography>

      {nav('First page', <FirstPageIcon sx={{ fontSize: 18 }} />, 0, here === 0)}
      {nav('Previous page', <ChevronLeftIcon sx={{ fontSize: 18 }} />, here - 1, here === 0)}
      <Typography sx={{ fontSize: 11.5, color: neon.muted, minWidth: 74,
                        textAlign: 'center' }}>
        {pages.toLocaleString()} page{pages === 1 ? '' : 's'}
      </Typography>
      {nav('Next page', <ChevronRightIcon sx={{ fontSize: 18 }} />, here + 1, here >= pages - 1)}
      {nav('Last page', <LastPageIcon sx={{ fontSize: 18 }} />, pages - 1, here >= pages - 1)}
    </Stack>
  )
}
