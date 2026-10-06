/**
 * The Targets toolbar's Enumerate menu, and the per-row actions.
 *
 * Both are presentation only: they decide what is offered and why
 * something is not, and hand the decision back to the view. Keeping the
 * dialogs out of here is what stops a row action and the toolbar
 * opening two different versions of the same thing.
 */
import { useState, type ReactNode } from 'react'
import {
  Box, Button, Divider, IconButton, ListItemIcon, ListItemText, Menu,
  MenuItem, Tooltip, Typography, alpha,
} from '@mui/material'
import DnsIcon from '@mui/icons-material/DnsOutlined'
import MergeIcon from '@mui/icons-material/MergeTypeOutlined'
import LanIcon from '@mui/icons-material/LanOutlined'
import MoreVertIcon from '@mui/icons-material/MoreVert'
import RadarIcon from '@mui/icons-material/RadarOutlined'
import TravelExploreIcon from '@mui/icons-material/TravelExplore'
import { neon } from '../theme'

export type EnumerateAction =
  | 'detect-domains'
  | 'fqdn-all'
  | 'fqdn-selected'
  | 'scan-ranges'

/** A menu entry that is off, and the true reason why. */
function Blocked({ label, why, icon }: {
  label: string; why: string; icon: ReactNode
}) {
  return (
    <Tooltip title={why} placement="left">
      {/* A disabled MenuItem swallows pointer events, so the tooltip
          needs a wrapper or it never shows — which would leave the
          operator with a dead entry and no reason given. */}
      <Box>
        <MenuItem disabled>
          <ListItemIcon sx={{ minWidth: 30, color: neon.muted }}>{icon}</ListItemIcon>
          <ListItemText primaryTypographyProps={{ fontSize: 13 }}>{label}</ListItemText>
        </MenuItem>
      </Box>
    </Tooltip>
  )
}

export function EnumerateMenu({ onPick, selectedCount, unnamedCount,
                                unnamedSelectedCount }: {
  onPick: (a: EnumerateAction) => void
  selectedCount: number
  /** Targets in the project with an address and no name. */
  unnamedCount: number
  /** The same, within the current selection. */
  unnamedSelectedCount: number
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const close = () => setAnchor(null)
  const choose = (a: EnumerateAction) => { close(); onPick(a) }

  const item = (a: EnumerateAction, label: string, icon: ReactNode,
                secondary?: string) => (
    <MenuItem onClick={() => choose(a)}>
      <ListItemIcon sx={{ minWidth: 30, color: neon.green }}>{icon}</ListItemIcon>
      <ListItemText
        primaryTypographyProps={{ fontSize: 13 }}
        secondaryTypographyProps={{ fontSize: 10.5, color: neon.muted }}
        primary={label} secondary={secondary} />
    </MenuItem>
  )

  return (
    <>
      <Button size="small" variant="outlined"
        startIcon={<TravelExploreIcon sx={{ fontSize: 16 }} />}
        onClick={(e) => setAnchor(e.currentTarget)}
        sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5),
              fontSize: 11, py: 0.3 }}>
        Enumerate
      </Button>
      <Menu anchorEl={anchor} open={!!anchor} onClose={close}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.green, 0.35)}`,
        } } }}>
        {item('detect-domains', 'Detect new domains', <TravelExploreIcon fontSize="small" />,
              'Extrapolated from names already known — no packets sent')}
        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />

        {unnamedCount
          ? item('fqdn-all', 'Find FQDNs for all IPs without one',
                 <DnsIcon fontSize="small" />,
                 `${unnamedCount} target${unnamedCount === 1 ? '' : 's'} named by `
                 + `an address, with no hostname yet`)
          : <Blocked label="Find FQDNs for all IPs without one"
              icon={<DnsIcon fontSize="small" />}
              why="No target here is named by an address — they all already carry a hostname." />}

        {!selectedCount
          ? <Blocked label="Find FQDNs for selected IPs without one"
              icon={<DnsIcon fontSize="small" />}
              why="Nothing is selected. Tick the rows you want looked up." />
          : unnamedSelectedCount
            ? item('fqdn-selected', 'Find FQDNs for selected IPs without one',
                   <DnsIcon fontSize="small" />,
                   `${unnamedSelectedCount} of ${selectedCount} selected `
                   + `row${selectedCount === 1 ? '' : 's'} need one`)
            : <Blocked label="Find FQDNs for selected IPs without one"
                icon={<DnsIcon fontSize="small" />}
                why={`All ${selectedCount} selected row(s) already have a name, or have no address to look up.`} />}

        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
        {item('scan-ranges', 'Scan new ranges', <RadarIcon fontSize="small" />,
              'Discovery over scope ranges nothing has been scanned in')}
      </Menu>
    </>
  )
}

export type RowAction = 'find-hostname' | 'find-ip' | 'nmap' | 'merge'

/**
 * Per-target actions.
 *
 * A mobile app has no address and no name to resolve — see the Target
 * model — so the whole menu is withheld rather than shown with three
 * dead entries. The cell says why.
 */
export function TargetRowActions({ kind, hasIp, hasName, allowed, onPick }: {
  kind: string
  hasIp: boolean
  /** The target is named by something other than its own address. */
  hasName: boolean
  allowed: boolean
  onPick: (a: RowAction) => void
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const close = () => setAnchor(null)
  const choose = (a: RowAction) => { close(); onPick(a) }

  if (kind === 'mobile') {
    return (
      <Tooltip title="An application has no address and nothing to resolve or scan">
        <Typography component="span"
          sx={{ color: alpha(neon.muted, 0.7), fontStyle: 'italic', fontSize: 12 }}>
          N/A
        </Typography>
      </Tooltip>
    )
  }

  return (
    <>
      <Tooltip title={allowed ? 'Enumerate this target' : 'Read-only on this project'}>
        <span>
          <IconButton size="small" disabled={!allowed}
            onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget) }}
            sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
            <MoreVertIcon fontSize="small" />
          </IconButton>
        </span>
      </Tooltip>
      <Menu anchorEl={anchor} open={!!anchor} onClose={close}
        slotProps={{ paper: { sx: {
          backgroundColor: alpha(neon.paper, 0.98), backgroundImage: 'none',
          border: `1px solid ${alpha(neon.cyan, 0.35)}`,
        } } }}>
        {hasIp
          ? <MenuItem onClick={() => choose('find-hostname')}>
              <ListItemIcon sx={{ minWidth: 30, color: neon.green }}>
                <DnsIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primaryTypographyProps={{ fontSize: 13 }}
                secondaryTypographyProps={{ fontSize: 10.5, color: neon.muted }}
                primary="Find hostname"
                secondary={hasName ? 'Reverse lookup — it already has a name'
                                   : 'Reverse lookup on its address'} />
            </MenuItem>
          : <Blocked label="Find hostname" icon={<DnsIcon fontSize="small" />}
              why="No address recorded for this target, so there is nothing to look up." />}

        {!hasName
          ? <Blocked label="Find IP" icon={<LanIcon fontSize="small" />}
              why="This target is named by its address, so a forward lookup has nothing to resolve." />
          : <MenuItem onClick={() => choose('find-ip')}>
              <ListItemIcon sx={{ minWidth: 30, color: neon.green }}>
                <LanIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primaryTypographyProps={{ fontSize: 13 }}
                secondaryTypographyProps={{ fontSize: 10.5, color: neon.muted }}
                primary="Find IP"
                secondary={hasIp ? 'Forward lookup — it already has an address'
                                 : 'Forward lookup on its name'} />
            </MenuItem>}

        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
        <MenuItem onClick={() => choose('nmap')}>
          <ListItemIcon sx={{ minWidth: 30, color: neon.cyan }}>
            <RadarIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primaryTypographyProps={{ fontSize: 13 }}
            primary="Enumerate with nmap" />
        </MenuItem>

        <Divider sx={{ borderColor: alpha(neon.purple, 0.2) }} />
        <MenuItem onClick={() => choose('merge')}>
          <ListItemIcon sx={{ minWidth: 30, color: neon.pink }}>
            <MergeIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primaryTypographyProps={{ fontSize: 13 }}
            primary="Combine with another target"
            secondary="When an address and a name turn out to be one host"
            secondaryTypographyProps={{ fontSize: 11, color: neon.muted }} />
        </MenuItem>
      </Menu>
    </>
  )
}
