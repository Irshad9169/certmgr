import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import { api, apiErrorMessage } from '../lib/api'
import type { NotificationSettings } from '../types'
import { ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

const EVENTS = [
  'expiry_60', 'expiry_30', 'expiry_15', 'expiry_7', 'expiry_3', 'expiry_1',
  'issued', 'renewed', 'failure', 'deployed', 'deployment_failed', 'revoked', 'imported', 'expired',
]

interface ChannelConfig {
  webhook_url?: string
  host?: string
  port?: number
  username?: string
  password?: string
  from?: string
  recipients?: string
  url?: string
  channel?: string
}

export default function NotificationsPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [editChannel, setEditChannel] = useState<NotificationSettings | null>(null)
  const [events, setEvents] = useState<string[]>([])
  const [config, setConfig] = useState<ChannelConfig>({})

  const { data: settings, isLoading, error, refetch } = useQuery({
    queryKey: ['notif-settings'],
    queryFn: () => api.get<NotificationSettings[]>('/notifications/settings').then((r) => r.data),
  })
  const history = useQuery({
    queryKey: ['notif-history'],
    queryFn: () =>
      api
        .get<{ items: { id: number; event_type: string; channel: string; subject?: string; status: string; error?: string; created_at?: string }[] }>(
          '/notifications', { params: { page_size: 25 } },
        )
        .then((r) => r.data),
  })

  const save = useMutation({
    mutationFn: () =>
      api.put(`/notifications/settings/${editChannel?.channel}`, {
        channel: editChannel?.channel,
        name: editChannel?.name,
        enabled: true,
        events,
        config,
      }),
    onSuccess: () => {
      setEditChannel(null)
      setToast({ message: 'Notification settings saved', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['notif-settings'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const test = useMutation({
    mutationFn: (channel: string) => api.post(`/notifications/settings/${channel}/test`),
    onSuccess: (res) => {
      const r = res.data as { success: boolean; error?: string }
      setToast({ message: r.success ? 'Test notification sent' : `Test failed: ${r.error ?? ''}`, severity: r.success ? 'success' : 'error' })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const openEditor = (s: NotificationSettings) => {
    setEditChannel(s)
    setEvents(s.events ?? [])
    setConfig({})
  }

  return (
    <Box>
      <PageHeader title="Notifications" subtitle="Channels, events and delivery history" />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load notification settings" onRetry={() => refetch()} />
      ) : (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {(settings ?? []).map((s) => (
            <Grid item xs={12} sm={6} md={3} key={s.channel}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>{s.channel}</Typography>
                    <StatusChip value={s.enabled ? 'active' : 'disabled'} />
                  </Box>
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                    {s.configured ? 'Configured' : 'Not configured'}
                  </Typography>
                  <Typography variant="caption" display="block" sx={{ mb: 1.5 }}>
                    Events: {s.events?.length ?? 0}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button size="small" onClick={() => openEditor(s)} disabled={!can('notification:manage')}>
                      Configure
                    </Button>
                    <Button size="small" onClick={() => test.mutate(s.channel)} disabled={!s.configured}>
                      Test
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      <Typography variant="h6" sx={{ mb: 1 }}>Recent deliveries</Typography>
      {history.isLoading ? (
        <Loading />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Event</TableCell>
                <TableCell>Channel</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Error</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(history.data?.items ?? []).map((n) => (
                <TableRow key={n.id}>
                  <TableCell>#{n.id}</TableCell>
                  <TableCell>{n.event_type}</TableCell>
                  <TableCell>{n.channel}</TableCell>
                  <TableCell><StatusChip value={n.status} /></TableCell>
                  <TableCell>{n.created_at ? new Date(n.created_at).toLocaleString() : '—'}</TableCell>
                  <TableCell><Typography variant="caption" color="error">{n.error}</Typography></TableCell>
                </TableRow>
              ))}
              {(history.data?.items ?? []).length === 0 && (
                <TableRow><TableCell colSpan={6} align="center">No notifications yet</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog open={Boolean(editChannel)} onClose={() => setEditChannel(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Configure {editChannel?.channel}</DialogTitle>
        <DialogContent>
          {editChannel?.channel === 'smtp' && (
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid item xs={6}><TextField label="SMTP host" fullWidth value={config.host ?? ''} onChange={(e) => setConfig((c) => ({ ...c, host: e.target.value }))} /></Grid>
              <Grid item xs={6}><TextField label="Port" type="number" fullWidth value={config.port ?? 587} onChange={(e) => setConfig((c) => ({ ...c, port: Number(e.target.value) }))} /></Grid>
              <Grid item xs={6}><TextField label="Username" fullWidth value={config.username ?? ''} onChange={(e) => setConfig((c) => ({ ...c, username: e.target.value }))} /></Grid>
              <Grid item xs={6}><TextField label="Password" type="password" fullWidth value={config.password ?? ''} onChange={(e) => setConfig((c) => ({ ...c, password: e.target.value }))} /></Grid>
              <Grid item xs={6}><TextField label="From" fullWidth value={config.from ?? ''} onChange={(e) => setConfig((c) => ({ ...c, from: e.target.value }))} /></Grid>
              <Grid item xs={6}><TextField label="Recipients (comma)" fullWidth value={config.recipients ?? ''} onChange={(e) => setConfig((c) => ({ ...c, recipients: e.target.value }))} /></Grid>
            </Grid>
          )}
          {(editChannel?.channel === 'slack' || editChannel?.channel === 'teams') && (
            <TextField label="Webhook URL" fullWidth sx={{ mt: 2 }} value={config.webhook_url ?? ''} onChange={(e) => setConfig((c) => ({ ...c, webhook_url: e.target.value }))} />
          )}
          {editChannel?.channel === 'webhook' && (
            <TextField label="Webhook URL" fullWidth sx={{ mt: 2 }} value={config.url ?? ''} onChange={(e) => setConfig((c) => ({ ...c, url: e.target.value }))} />
          )}
          <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Events</Typography>
          <Box sx={{ display: 'flex', gap: 0.6, flexWrap: 'wrap' }}>
            {EVENTS.map((ev) => (
              <Chip
                key={ev}
                label={ev}
                color={events.includes(ev) ? 'primary' : 'default'}
                onClick={() =>
                  setEvents((prev) => (prev.includes(ev) ? prev.filter((x) => x !== ev) : [...prev, ev]))
                }
              />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditChannel(null)}>Cancel</Button>
          <Button variant="contained" onClick={() => save.mutate()}>Save</Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
