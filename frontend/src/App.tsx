import { useCallback, useEffect, useState } from 'react'
import {
  AppBar, Box, Chip, CircularProgress, Divider, Drawer, IconButton, List,
  ListItemButton, ListItemIcon, ListItemText, MenuItem, Select, Stack,
  Toolbar, Tooltip, Typography, alpha, useMediaQuery, useTheme,
} from '@mui/material'
import FolderIcon from '@mui/icons-material/FolderOutlined'
import DnsIcon from '@mui/icons-material/DnsOutlined'
import LanIcon from '@mui/icons-material/LanOutlined'
import BugReportIcon from '@mui/icons-material/BugReportOutlined'
import KeyIcon from '@mui/icons-material/VpnKeyOutlined'
import PublicIcon from '@mui/icons-material/PublicOutlined'
import UploadIcon from '@mui/icons-material/UploadFileOutlined'
import DescriptionIcon from '@mui/icons-material/DescriptionOutlined'
import MemoryIcon from '@mui/icons-material/MemoryOutlined'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import SmartToyIcon from '@mui/icons-material/SmartToyOutlined'
import PersonIcon from '@mui/icons-material/PersonOutline'
import SettingsIcon from '@mui/icons-material/SettingsOutlined'
import GroupIcon from '@mui/icons-material/GroupOutlined'
import LogoutIcon from '@mui/icons-material/Logout'
import MenuIcon from '@mui/icons-material/Menu'
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import { useQuery } from '@tanstack/react-query'
import { api } from './lib/api'
import { useAuth } from './lib/auth'
import { useLive, type LiveState } from './lib/useLive'
import { useStoredFlag } from './lib/useStoredFlag'
import { lastProject, parse, push, rememberProject, replace, type Route } from './lib/route'
import { GateView } from './views/GateView'
import { ProjectsView } from './views/ProjectsView'
import { TargetsView } from './views/TargetsView'
import { ServicesView } from './views/ServiceViews'
import { VulnsView } from './views/VulnsView'
import { CredentialsView } from './views/CredentialsView'
import { ProfileView } from './views/ProfileView'
import { SiteConfigView } from './views/SiteConfigView'
import { WebView } from './views/WebView'
import { ImportView } from './views/ImportView'
import { ReportsView } from './views/ReportsView'
import { JawsView } from './views/JawsView'
import { useHostModal } from './components/HostModal'
import { AgentPanel } from './components/AgentPanel'
import { UsersView } from './views/UsersView'
import { neon, glow } from './theme'
import { sorted } from './lib/sortOptions'

const ALL = '__all__'
const RAIL = 186
const RAIL_COLLAPSED = 58

function LiveDot({ state }: { state: LiveState }) {
  const c = state === 'live' ? neon.green : state === 'connecting' ? neon.yellow : neon.red
  const label = state === 'live' ? 'Live — views refresh when data changes'
    : state === 'connecting' ? 'Reconnecting to the change stream…'
    : 'Offline — no change stream'
  return (
    <Tooltip title={label}>
      <Stack direction="row" spacing={0.9} alignItems="center">
        <Box sx={{ width: 9, height: 9, borderRadius: '50%', bgcolor: c,
                   boxShadow: `0 0 8px ${c}`,
                   animation: state === 'live' ? 'neonPulse 2.4s ease-out infinite' : 'none' }} />
        <Typography sx={{ fontFamily: `'Orbitron', sans-serif`, fontSize: 10,
                          letterSpacing: '0.16em', color: c, textShadow: glow(c, 0.5) }}>
          {state === 'live' ? 'LIVE' : state === 'connecting' ? 'SYNC' : 'DOWN'}
        </Typography>
      </Stack>
    </Tooltip>
  )
}

function StatChip({ label, value, colour }: { label: string; value: number; colour: string }) {
  return (
    <Chip size="small" sx={{
      bgcolor: alpha(neon.bgDeep, 0.6), border: `1px solid ${alpha(colour, 0.45)}`, fontSize: 11,
    }} label={
      <span>
        <span style={{ color: alpha(neon.muted, 0.85), letterSpacing: '0.08em' }}>{label} </span>
        <span style={{ color: colour, fontWeight: 700, textShadow: glow(colour, 0.5) }}>{value}</span>
      </span>
    } />
  )
}

export default function App() {
  const { me, loading, setupRequired, signOut } = useAuth()
  // Initialised FROM the URL, so a theme switch — which remounts the
  // tree to recompute alpha() colours — lands back where you were
  // instead of resetting to Targets.
  const [route, setRoute] = useState<Route>(() => parse(window.location.pathname))
  const view = route.view
  const setView = useCallback((v: string) => {
    setRoute((r) => {
      const next = { ...r, view: v, host: undefined,
                     protocol: undefined, port: undefined }
      push(next)
      return next
    })
  }, [])
  const [agentOpen, setAgentOpen] = useState(false)
  // Which nav groups are open. Undefined means "follow the selection", so
  // landing on Web from a link opens Services without being told to.
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({})
  // The project lives in the URL — except on a global view, whose URL
  // has no room for one. Remembering the last engagement keeps the
  // header selector meaningful there, and keeps it selected on the way
  // back out to Targets.
  const project = route.project ?? lastProject() ?? ALL
  const setProject = useCallback((code: string) => {
    rememberProject(code === ALL ? null : code)
    setRoute((r) => {
      const next: Route = { ...r, project: code === ALL ? null : code,
                            host: undefined, protocol: undefined, port: undefined }
      push(next)
      return next
    })
  }, [])

  // Keep the memory current as the URL changes, so a link someone
  // pasted sets the engagement for the rest of the session too.
  useEffect(() => {
    if (route.project) rememberProject(route.project)
  }, [route.project])

  // `/` resolves to the project list; say so in the address bar rather
  // than leaving a path that does not describe the page. replace, not
  // push, so Back does not bounce between / and /projects.
  useEffect(() => {
    if (window.location.pathname === '/') replace(route)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Back and Forward have to work, or the URL is decoration.
  useEffect(() => {
    const onPop = () => setRoute(parse(window.location.pathname))
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // A pasted link naming a host opens it. Keyed on the path so it fires
  // once per navigation rather than on every render.
  const hostModal = useHostModal()
  const deepLink = route.host ? `${route.project}/${route.host}` : null
  useEffect(() => {
    if (route.host && route.project) hostModal.open(route.project, route.host)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepLink])
  const [navOpen, setNavOpen] = useState(false)
  const [collapsed, toggleCollapsed] = useStoredFlag('oddjob.nav.collapsed', false)

  // The bloom is global, so it goes on <body> rather than a wrapper — the
  // backdrop grid and scanlines are body pseudo-elements and have to glow too.
  const authed = !!me
  const live = useLive(authed)
  const theme = useTheme()
  const wide = useMediaQuery(theme.breakpoints.up('lg'))
  const compact = useMediaQuery(theme.breakpoints.down('md'))

  const { data: projects } = useQuery({
    queryKey: ['projects'], queryFn: api.projects, enabled: authed,
  })
  const scope = project === ALL ? null : project
  const { data: stats } = useQuery({
    queryKey: ['stats', scope], queryFn: () => api.stats(scope ?? undefined), enabled: authed,
  })

  // One visible project means there is nothing to choose; preselect it.
  useEffect(() => {
    const items = projects?.items ?? []
    if (project === ALL && items.length === 1) setProject(items[0].code)
  }, [projects, project])

  // EVERY hook must be above the early returns below. Putting these two
  // after them meant React saw 15 hooks on the sign-in screen and 17
  // once authenticated, which is a hard error and rendered a blank page.
  const webCheck = useQuery({
    queryKey: ['web-applicable', project],
    queryFn: () => api.webApplicable(project === ALL ? undefined : project),
    enabled: authed,
  })
  const webApplicable = webCheck.data?.applicable ?? false

  // Switching to a project with no web services while standing on Web
  // would leave an empty pane and a nav with nothing selected.
  useEffect(() => {
    if (view === 'web' && webCheck.data && !webApplicable) setView('services')
  }, [view, webApplicable, webCheck.data, setView])

  if (loading) {
    return <Box sx={{ flex: 1, display: 'grid', placeItems: 'center' }}>
      <CircularProgress sx={{ color: neon.cyan }} />
    </Box>
  }
  if (setupRequired || !authed) {
    return <Box className="scanlines" sx={{ height: '100%', display: 'flex' }}><GateView /></Box>
  }

  const siteAdmin = me.user.is_site_admin
  // Project admins get user management too — they administer membership of
  // their own projects. The server decides what they can actually do; this
  // only decides whether showing them the screen is useful.
  const projectAdmin = Object.values(me.projects).includes('admin')

  // One renderer for leaves and children alike, so a nested item is
  // visually a nav item with an indent rather than a different thing.
  const navItem = (n: { key: string; label: string; icon: React.ReactNode },
                   on: boolean, depth: number) => (
    <ListItemButton key={`${depth}-${n.key}`} selected={on}
      onClick={() => { setView(n.key); setNavOpen(false) }}
      sx={{
        mx: 1, mb: 0.3, borderRadius: 1,
        pl: isCollapsed ? 1 : 2 + depth * 1.6,
        justifyContent: isCollapsed ? 'center' : 'flex-start',
        pr: isCollapsed ? 1 : 2,
        '&.Mui-selected': {
          background: alpha(neon.cyan, 0.12),
          borderLeft: `2px solid ${neon.cyan}`,
          '&:hover': { background: alpha(neon.cyan, 0.18) },
        },
        '&:hover': { background: alpha(neon.pink, 0.08) },
      }}>
      <ListItemIcon sx={{ minWidth: isCollapsed ? 0 : 34,
                          color: on ? neon.cyan : neon.muted }}>
        {n.icon}
      </ListItemIcon>
      {!isCollapsed && (
        <ListItemText primary={n.label} slotProps={{ primary: {
          sx: { fontFamily: `'Orbitron', sans-serif`,
                fontSize: depth ? 10.5 : 11,
                letterSpacing: '0.12em', textTransform: 'uppercase',
                color: on ? neon.cyan : neon.muted } } }} />
      )}
    </ListItemButton>
  )

  const groupSx = (anyOn: boolean, collapsed: boolean) => ({
    mx: 1, mb: 0.3, borderRadius: 1,
    justifyContent: collapsed ? 'center' : 'flex-start',
    px: collapsed ? 1 : 2,
    '&.Mui-selected': { background: alpha(neon.cyan, 0.12) },
    '&:hover': { background: alpha(neon.pink, 0.08) },
    ...(anyOn && !collapsed ? { borderLeft: `2px solid ${alpha(neon.cyan, 0.4)}` } : {}),
  })

  const NAV = [
    { key: 'projects', label: 'Projects', icon: <FolderIcon fontSize="small" /> },
    { key: 'targets', label: 'Targets', icon: <DnsIcon fontSize="small" /> },
    // Services is a group, not a leaf: a URL is one protocol's view of a
    // port, and SMB shares, SNMP trees and database instances will want
    // the same treatment. Nesting them now means adding the next one is a
    // line in this array rather than a fourth top-level entry.
    {
      key: 'services', label: 'Services', icon: <LanIcon fontSize="small" />,
      children: [
        { key: 'services', label: 'All', icon: <LanIcon fontSize="small" /> },
        // Web appears only once an http(s) port exists. An empty view
        // you have to click to discover is empty is worse than no entry.
        ...(webApplicable
          ? [{ key: 'web', label: 'Web', icon: <PublicIcon fontSize="small" /> }]
          : []),
      ],
    },
    { key: 'vulns', label: 'Vulns', icon: <BugReportIcon fontSize="small" /> },
    { key: 'credentials', label: 'Credentials', icon: <KeyIcon fontSize="small" /> },
    // Jaws sits under Reports as a sibling of the written deliverable:
    // both answer "what has this engagement actually done".
    {
      key: 'reports', label: 'Reports', icon: <DescriptionIcon fontSize="small" />,
      children: [
        { key: 'reports', label: 'Written', icon: <DescriptionIcon fontSize="small" /> },
        { key: 'jaws', label: 'Jaws', icon: <MemoryIcon fontSize="small" /> },
      ],
    },
    { key: 'import', label: 'Import', icon: <UploadIcon fontSize="small" /> },
  ]
  const ADMIN_NAV = [
    ...(siteAdmin ? [{ key: 'config', label: 'Site Config',
                       icon: <SettingsIcon fontSize="small" /> }] : []),
    ...(siteAdmin || projectAdmin ? [{ key: 'users', label: 'Users',
                                       icon: <GroupIcon fontSize="small" /> }] : []),
  ]

  const body = {
    projects: <ProjectsView onOpen={(c) => {
      // One history entry, not two: setProject then setView would make
      // Back land on the project's target list rather than the list of
      // projects you came from.
      const next: Route = { view: 'targets', project: c }
      push(next)
      setRoute(next)
    }} />,
    targets: <TargetsView project={scope} />,
    services: <ServicesView project={scope} />,
    vulns: <VulnsView project={scope} />,
    credentials: <CredentialsView project={scope} />,
    web: <WebView project={scope} />,
    import: <ImportView project={project === ALL ? null : project} />,
    reports: <ReportsView project={project === ALL ? null : project} />,
    jaws: <JawsView project={project === ALL ? null : project} />,
    config: <SiteConfigView />,
    users: <UsersView />,
    profile: <ProfileView />,
  }[view]

  // The drawer is already an overlay on small screens, so collapsing there
  // would just make it a narrower overlay. Only the docked rail collapses.
  const isCollapsed = collapsed && !compact
  const railWidth = isCollapsed ? RAIL_COLLAPSED : RAIL

  const nav = (
    <Box sx={{ width: railWidth, height: '100%', display: 'flex', flexDirection: 'column',
               transition: 'width 160ms ease', overflowX: 'hidden',
               background: alpha(neon.bgDeep, 0.8), backdropFilter: 'blur(10px)',
               borderRight: `1px solid ${alpha(neon.pink, 0.3)}` }}>
      <Box sx={{ px: isCollapsed ? 0 : 2, py: 1.6, display: 'flex', alignItems: 'center',
                 justifyContent: isCollapsed ? 'center' : 'space-between', gap: 0.5 }}>
        <Typography variant="h6" sx={{ color: neon.pink, textShadow: glow(neon.pink, 1.4),
                                       fontSize: 17, userSelect: 'none', whiteSpace: 'nowrap' }}>
          {/* Split so the two halves take different accents. Collapsed,
              only the first survives — hence a three-letter first half. */}
          ODD{!isCollapsed && (
            <Box component="span" sx={{ color: neon.cyan, textShadow: glow(neon.cyan, 1.4) }}>JOB</Box>
          )}
        </Typography>
        {!compact && !isCollapsed && (
          <Tooltip title="Collapse sidebar">
            <IconButton size="small" onClick={toggleCollapsed}
              sx={{ color: neon.muted, '&:hover': { color: neon.cyan } }}>
              <ChevronLeftIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Box>
      {!compact && isCollapsed && (
        <Tooltip title="Expand sidebar" placement="right">
          <IconButton size="small" onClick={toggleCollapsed}
            sx={{ mx: 'auto', mb: 0.5, color: neon.muted, '&:hover': { color: neon.cyan } }}>
            <ChevronRightIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      )}
      <Divider sx={{ borderColor: alpha(neon.pink, 0.22) }} />
      <List dense sx={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', pt: 1 }}>
        {NAV.flatMap((n) => {
          const kids = (n as { children?: typeof NAV }).children
          if (!kids) return [navItem(n, view === n.key, 0)]
          const anyOn = kids.some((k) => view === k.key)
          const expanded = openGroups[n.key] ?? anyOn
          return [
            <ListItemButton key={n.key} selected={anyOn && isCollapsed}
              onClick={() => {
                if (isCollapsed) { setView(kids[0].key); setNavOpen(false); return }
                setOpenGroups((g) => ({ ...g, [n.key]: !expanded }))
              }}
              sx={groupSx(anyOn, isCollapsed)}>
              <ListItemIcon sx={{ minWidth: isCollapsed ? 0 : 34,
                                  color: anyOn ? neon.cyan : neon.muted }}>
                {n.icon}
              </ListItemIcon>
              {!isCollapsed && (
                <>
                  <ListItemText primary={n.label} slotProps={{ primary: {
                    sx: { fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
                          letterSpacing: '0.12em', textTransform: 'uppercase',
                          color: anyOn ? neon.cyan : neon.muted } } }} />
                  <ExpandMoreIcon sx={{
                    fontSize: 16, color: neon.muted,
                    transition: 'transform .15s',
                    transform: expanded ? 'rotate(180deg)' : 'none' }} />
                </>
              )}
            </ListItemButton>,
            ...(!isCollapsed && expanded
              ? kids.map((k) => navItem(k, view === k.key, 1))
              : []),
          ]
        })}
        {ADMIN_NAV.length > 0 && (
          <Divider sx={{ my: 1, mx: isCollapsed ? 1 : 2,
                         borderColor: alpha(neon.purple, 0.35) }} />
        )}
        {ADMIN_NAV.map((n) => {
          const on = view === n.key
          const item = (
            <ListItemButton key={n.key} selected={on}
              onClick={() => { setView(n.key); setNavOpen(false) }}
              sx={{
                mx: 1, mb: 0.3, borderRadius: 1,
                justifyContent: isCollapsed ? 'center' : 'flex-start',
                px: isCollapsed ? 1 : 2,
                '&.Mui-selected': {
                  background: alpha(neon.purple, 0.16),
                  borderLeft: `2px solid ${neon.purple}`,
                  '&:hover': { background: alpha(neon.purple, 0.22) },
                },
                '&:hover': { background: alpha(neon.purple, 0.1) },
              }}>
              <ListItemIcon sx={{ minWidth: isCollapsed ? 0 : 34,
                                  color: on ? neon.purple : neon.muted }}>
                {n.icon}
              </ListItemIcon>
              {!isCollapsed && (
                <ListItemText primary={n.label} slotProps={{ primary: {
                  sx: { fontFamily: `'Orbitron', sans-serif`, fontSize: 11,
                        letterSpacing: '0.12em', textTransform: 'uppercase',
                        color: on ? neon.purple : neon.muted,
                        textShadow: on ? glow(neon.purple, 0.5) : undefined },
                } }} />
              )}
            </ListItemButton>
          )
          return isCollapsed
            ? <Tooltip key={n.key} title={n.label} placement="right">{item}</Tooltip>
            : item
        })}
      </List>
      <Divider sx={{ borderColor: alpha(neon.pink, 0.22) }} />
      <Tooltip title={isCollapsed ? me.user.username : ''} placement="right">
        <ListItemButton selected={view === 'profile'}
          onClick={() => { setView('profile'); setNavOpen(false) }}
          sx={{
            // flex:0 0 auto and an explicit height: as the last child of a
            // column flex container this button was absorbing all the
            // leftover space and rendering 408px tall.
            flex: '0 0 auto', minHeight: 34, maxHeight: 34, py: 0,
            m: 1, borderRadius: 1,
            justifyContent: isCollapsed ? 'center' : 'flex-start',
            px: isCollapsed ? 1 : 2,
            '&.Mui-selected': { background: alpha(neon.cyan, 0.12) } }}>
          <ListItemIcon sx={{ minWidth: isCollapsed ? 0 : 34,
                              color: view === 'profile' ? neon.cyan : neon.muted }}>
            <PersonIcon fontSize="small" />
          </ListItemIcon>
          {!isCollapsed && (
            <ListItemText primary={me.user.username} slotProps={{ primary: {
              sx: { fontSize: 12, color: view === 'profile' ? neon.cyan : neon.text,
                    overflow: 'hidden', textOverflow: 'ellipsis' } } }} />
          )}
        </ListItemButton>
      </Tooltip>
    </Box>
  )

  return (
    <Box className="scanlines" sx={{ height: '100%', display: 'flex' }}>
      {compact
        ? <Drawer open={navOpen} onClose={() => setNavOpen(false)}
            slotProps={{ paper: { sx: { backgroundImage: 'none', border: 0 } } }}>{nav}</Drawer>
        : <Box sx={{ flexShrink: 0 }}>{nav}</Box>}

      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        {/* The header is about the PROJECT — which one, and how big it is.
            Navigation lives in the rail, so the two do not compete. */}
        <AppBar position="static" elevation={0}>
          <Toolbar variant="dense" sx={{ gap: 1.5, flexWrap: 'wrap', py: 0.5 }}>
            {compact && (
              <IconButton size="small" onClick={() => setNavOpen(true)} sx={{ color: neon.pink }}>
                <MenuIcon fontSize="small" />
              </IconButton>
            )}
            <Select size="small" value={project} onChange={(e) => setProject(e.target.value)}
              sx={{
                minWidth: 210, height: 32, fontSize: 12.5,
                fontFamily: `'Share Tech Mono', monospace`, color: neon.cyan,
                '.MuiOutlinedInput-notchedOutline': { borderColor: alpha(neon.cyan, 0.45) },
                '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: neon.cyan },
                '.MuiSelect-icon': { color: neon.cyan },
              }}>
              <MenuItem value={ALL} sx={{ fontSize: 12.5 }}>All projects</MenuItem>
              <Divider />
              {sorted(projects?.items ?? [], (p) => p.code).map((p) => (
                <MenuItem key={p.code} value={p.code} sx={{ fontSize: 12.5 }}>
                  {p.code}
                  <Box component="span" sx={{ ml: 1, color: neon.muted, fontSize: 11 }}>
                    {p.total_targets}
                  </Box>
                </MenuItem>
              ))}
            </Select>

            {scope && (
              <Typography sx={{ fontSize: 12.5, color: neon.muted,
                                display: { xs: 'none', sm: 'block' } }}>
                {projects?.items.find((p) => p.code === scope)?.name}
              </Typography>
            )}

            <Box sx={{ flex: 1 }} />

            {wide && stats && (
              <Stack direction="row" spacing={1} alignItems="center">
                <StatChip label="TARGETS" value={stats.targets} colour={neon.pink} />
                <StatChip label="PWNED" value={stats.hacked} colour={neon.red} />
                <StatChip label="OPEN" value={stats.open_ports} colour={neon.cyan} />
                <StatChip label="VULNS" value={stats.vulns} colour={neon.yellow} />
                <StatChip label="CRIT" value={stats.by_severity?.critical ?? 0} colour={neon.red} />
              </Stack>
            )}
            <Tooltip title={project === ALL
              ? 'Choose an engagement to talk to the agent about it'
              : agentOpen ? 'Close the agent' : 'Ask the agent about this engagement'}>
              <span>
                <IconButton size="small" disabled={project === ALL}
                  onClick={() => setAgentOpen((o) => !o)}
                  sx={{
                    color: agentOpen ? neon.cyan : alpha(neon.muted, 0.8),
                    filter: agentOpen ? `drop-shadow(0 0 6px ${neon.cyan})` : undefined,
                    '&:hover': { color: neon.cyan },
                  }}>
                  <SmartToyIcon fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <LiveDot state={live} />
            <Tooltip title="Sign out">
              <IconButton size="small" onClick={signOut}
                sx={{ color: neon.muted, '&:hover': { color: neon.pink } }}>
                <LogoutIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Toolbar>
        </AppBar>

        {body}
      </Box>

      <AgentPanel project={project === ALL ? null : project}
        open={agentOpen} onClose={() => setAgentOpen(false)} />
    </Box>
  )
}
