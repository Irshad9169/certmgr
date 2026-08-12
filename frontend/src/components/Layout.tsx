import { useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  AppBar,
  Avatar,
  Box,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import DashboardIcon from '@mui/icons-material/Dashboard'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import AddCircleIcon from '@mui/icons-material/AddCircle'
import FileUploadIcon from '@mui/icons-material/FileUpload'
import DnsIcon from '@mui/icons-material/Dns'
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch'
import TravelExploreIcon from '@mui/icons-material/TravelExplore'
import TuneIcon from '@mui/icons-material/Tune'
import NotificationsIcon from '@mui/icons-material/Notifications'
import HistoryIcon from '@mui/icons-material/History'
import GroupIcon from '@mui/icons-material/Group'
import SettingsIcon from '@mui/icons-material/Settings'
import FactCheckIcon from '@mui/icons-material/FactCheck'
import DescriptionIcon from '@mui/icons-material/Description'
import SmartToyIcon from '@mui/icons-material/SmartToy'
import LogoutIcon from '@mui/icons-material/Logout'
import ShieldIcon from '@mui/icons-material/Shield'
import { useAuth } from '../lib/auth-context'

const DRAWER_WIDTH = 248

interface NavItem {
  to: string
  label: string
  icon: ReactNode
  adminOnly?: boolean
}

const NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: <DashboardIcon /> },
  { to: '/certificates', label: 'Certificates', icon: <VerifiedUserIcon /> },
  { to: '/issue', label: 'Issue Wizard', icon: <AddCircleIcon /> },
  { to: '/import', label: 'Import', icon: <FileUploadIcon /> },
  { to: '/servers', label: 'Servers', icon: <DnsIcon /> },
  { to: '/deployments', label: 'Deployments', icon: <RocketLaunchIcon /> },
  { to: '/discovery', label: 'Discovery', icon: <TravelExploreIcon /> },
  { to: '/hooks', label: 'Hooks', icon: <TuneIcon /> },
  { to: '/notifications', label: 'Notifications', icon: <NotificationsIcon /> },
  { to: '/compliance', label: 'Compliance', icon: <FactCheckIcon /> },
  { to: '/reports', label: 'Reports', icon: <DescriptionIcon /> },
  { to: '/ai', label: 'AI Assistant', icon: <SmartToyIcon /> },
  { to: '/audit', label: 'Audit Log', icon: <HistoryIcon /> },
  { to: '/users', label: 'Users & Roles', icon: <GroupIcon />, adminOnly: true },
  { to: '/settings', label: 'Settings', icon: <SettingsIcon />, adminOnly: true },
]

export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout, can } = useAuth()
  const navigate = useNavigate()
  const [anchor, setAnchor] = useState<null | HTMLElement>(null)

  const handleLogout = async () => {
    setAnchor(null)
    await logout()
    navigate('/login')
  }

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
        }}
      >
        <Toolbar sx={{ gap: 1.5, px: 2 }}>
          <ShieldIcon color="primary" sx={{ fontSize: 34 }} />
          <Box>
            <Typography variant="h6" sx={{ lineHeight: 1.1 }}>
              CertMgr
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Certificate Lifecycle Platform
            </Typography>
          </Box>
        </Toolbar>
        <Divider />
        <List sx={{ px: 1, py: 1, flex: 1, overflowY: 'auto' }}>
          {NAV.filter((n) => !n.adminOnly || can('admin:settings')).map((item) => (
            <ListItem key={item.to} disablePadding sx={{ mb: 0.25 }}>
              <ListItemButton
                component={NavLink}
                to={item.to}
                end={item.to === '/'}
                sx={{
                  borderRadius: 2,
                  '&.active': {
                    bgcolor: 'primary.main',
                    color: 'primary.contrastText',
                    '& .MuiListItemIcon-root': { color: 'inherit' },
                  },
                }}
              >
                <ListItemIcon sx={{ minWidth: 38 }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} primaryTypographyProps={{ fontSize: 14 }} />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
        <Divider />
        <Box sx={{ p: 1.5, display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Avatar sx={{ width: 36, height: 36, bgcolor: 'secondary.main' }}>
            {(user?.username ?? '?')[0].toUpperCase()}
          </Avatar>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="body2" noWrap>
              {user?.full_name || user?.username}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'capitalize' }}>
              {user?.role}
            </Typography>
          </Box>
          <Tooltip title="Logout">
            <IconButton onClick={handleLogout} size="small">
              <LogoutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, minWidth: 0 }}>
        <AppBar position="sticky" color="default" elevation={0} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Toolbar variant="dense" sx={{ justifyContent: 'flex-end' }}>
            <IconButton
              onClick={(e) => setAnchor(e.currentTarget)}
              size="small"
              sx={{ gap: 1, borderRadius: 2, px: 1.5 }}
            >
              <Avatar sx={{ width: 28, height: 28, bgcolor: 'secondary.main' }}>
                {(user?.username ?? '?')[0].toUpperCase()}
              </Avatar>
              <Typography variant="body2">{user?.username}</Typography>
            </IconButton>
            <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
              <MenuItem onClick={() => navigate('/settings')}>Account &amp; API tokens</MenuItem>
              <MenuItem onClick={handleLogout}>Sign out</MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>
        <Box sx={{ p: { xs: 2, md: 3 } }}>{children}</Box>
      </Box>
    </Box>
  )
}
