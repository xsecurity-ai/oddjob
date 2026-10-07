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
  | 'ip-all'
  | 'ip-selected'
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

/** Why nothing can be enumerated, or '' when something can.
 *
 *  Two different problems with two different fixes, and the tooltip has
 *  to say which: enrolling a scanner is a different job from starting
 *  one that already exists. "No agents" for both would send somebody to
 *  the wrong screen. */
export function noAgentReason(live: number, enrolled: number): string {
  if (live > 0) return ''
  if (!enrolled) {
    return 'No Drone agent is enrolled on this project, so there is '
         + 'nothing to run the scan. Add one under Drone.'
  }
  return `All ${enrolled} Drone agent${enrolled === 1 ? '' : 's'} on this `
       + `project ${enrolled === 1 ? 'is' : 'are'} offline. Work queued now `
       + `would sit unclaimed until one comes back.`
}

export function EnumerateMenu({ onPick, selectedCount, unnamedCount,
                                unnamedSelectedCount, unaddressedCount,
                                unaddressedSelectedCount,
                                liveAgents, enrolledAgents }: {
  onPick: (a: EnumerateAction) => void
  /** Agents online now, and enrolled at all. Both, because "none
   *  enrolled" and "all offline" need different things done about them. */
  liveAgents: number
  enrolledAgents: number
  selectedCount: number
  /** Targets in the project with an address and no name. */
  unnamedCount: number
  /** The mirror: a name on record and no address against it. */
  unaddressedCount: number
  unaddressedSelectedCount: number
  /** The same, within the current selection. */
  unnamedSelectedCount: number
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const close = () => setAnchor(null)
  const choose = (a: EnumerateAction) => { close(); onPick(a) }
  const noAgents = noAgentReason(liveAgents, enrolledAgents)

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
      {/* Off at the button, not inside it. A menu whose every entry is
          disabled is a menu that wasted the click it took to open. */}
      <Tooltip title={noAgents || 'Find more of the estate'}>
        <span>
          <Button size="small" variant="outlined" disabled={!!noAgents}
            startIcon={<TravelExploreIcon sx={{ fontSize: 16 }} />}
            onClick={(e) => setAnchor(e.currentTarget)}
            sx={{ color: neon.green, borderColor: alpha(neon.green, 0.5),
                  fontSize: 11, py: 0.3 }}>
            Enumerate
          </Button>
        </span>
      </Tooltip>
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

        {unaddressedCount
          ? item('ip-all', 'Find IPs for all hosts without one',
                 <LanIcon fontSize="small" />,
                 `${unaddressedCount} target${unaddressedCount === 1 ? '' : 's'} `
                 + `named but with no address recorded`)
          : <Blocked label="Find IPs for all hosts without one"
              icon={<LanIcon fontSize="small" />}
              why="Every named target here already has an address." />}

        {!selectedCount
          ? <Blocked label="Find IPs for selected hosts without one"
              icon={<LanIcon fontSize="small" />}
              why="Nothing is selected. Tick the rows you want resolved." />
          : unaddressedSelectedCount
            ? item('ip-selected', 'Find IPs for selected hosts without one',
                   <LanIcon fontSize="small" />,
                   `${unaddressedSelectedCount} of ${selectedCount} selected `
                   + `row${selectedCount === 1 ? '' : 's'} need one`)
            : <Blocked label="Find IPs for selected hosts without one"
                icon={<LanIcon fontSize="small" />}
                why={`All ${selectedCount} selected row(s) already have an address, or are mobile apps that cannot have one.`} />}

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
export function TargetRowActions({ kind, hasIp, hasName, allowed,
                                   liveAgents, enrolledAgents, onPick }: {
  kind: string
  hasIp: boolean
  /** The target is named by something other than its own address. */
  hasName: boolean
  allowed: boolean
  liveAgents: number
  enrolledAgents: number
  onPick: (a: RowAction) => void
}) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const close = () => setAnchor(null)
  const choose = (a: RowAction) => { close(); onPick(a) }
  // Only the three that are work for an agent. Combining two targets is
  // a database operation this server does by itself, so withholding it
  // because no scanner is connected would be withholding it for no
  // reason — and it is the action most likely to be wanted precisely
  // when scanning is not available.
  const noAgents = noAgentReason(liveAgents, enrolledAgents)

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
        {noAgents
          ? <Blocked label="Find hostname" icon={<DnsIcon fontSize="small" />}
              why={noAgents} />
          : hasIp
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

        {noAgents
          ? <Blocked label="Find IP" icon={<LanIcon fontSize="small" />}
              why={noAgents} />
          : !hasName
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
        {noAgents
          ? <Blocked label="Enumerate with nmap"
              icon={<RadarIcon fontSize="small" />} why={noAgents} />
          : <MenuItem onClick={() => choose('nmap')}>
              <ListItemIcon sx={{ minWidth: 30, color: neon.cyan }}>
                <RadarIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText primaryTypographyProps={{ fontSize: 13 }}
                primary="Enumerate with nmap" />
            </MenuItem>}

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
