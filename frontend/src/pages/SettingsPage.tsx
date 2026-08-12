import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import {
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
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
import { ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

interface SettingRow {
  key: string
  value: string
  is_secret: boolean
  description: string
  configured: boolean
}

export default function SettingsPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [edit, setEdit] = useState<SettingRow | null>(null)
  const [value, setValue] = useState('')
  const [maintenance, setMaintenance] = useState(false)
  const [maintReason, setMaintReason] = useState('')

  const maint = useQuery({
    queryKey: ['maintenance'],
    queryFn: () => api.get<{ active: boolean; reason?: string | null }>('/settings/maintenance').then((r) => r.data),
  })

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<{ settings: SettingRow[] }>('/settings').then((r) => r.data),
  })
  useEffect(() => {
    if (maint.data) {
      setMaintenance(maint.data.active)
      setMaintReason(maint.data.reason ?? '')
    }
  }, [maint.data])

  const saveSetting = useMutation({
    mutationFn: () =>
      api.put(`/settings/${edit?.key}`, {
        value,
        is_secret: edit?.is_secret ? true : undefined,
      }),
    onSuccess: () => {
      setEdit(null)
      setToast({ message: 'Setting saved', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['settings'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const toggleMaintenance = useMutation({
    mutationFn: () =>
      api.put('/settings/maintenance', {
        active: !maintenance,
        reason: maintReason || undefined,
        pauses: { renewals: true, deployments: true, notifications: true, imports: true, background_jobs: true },
      }),
    onSuccess: () => {
      setToast({ message: `Maintenance ${maintenance ? 'ended' : 'started'}`, severity: 'success' })
      qc.invalidateQueries({ queryKey: ['maintenance'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorBox message="Failed to load settings" onRetry={() => refetch()} />

  const adminOnly = !can('admin:settings')
  const settingsList = data.settings

  return (
    <Box>
      <PageHeader title="Settings" subtitle="Platform configuration, secrets masked" />

      <Card sx={{ mb: 3, border: maintenance ? 1 : 0, borderColor: 'warning.main' }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
            <Typography variant="h6">Maintenance mode</Typography>
            <StatusChip value={maintenance ? 'active' : 'disabled'} />
            <TextField
              size="small"
              label="Reason"
              value={maintReason}
              onChange={(e) => setMaintReason(e.target.value)}
              sx={{ flex: 1, minWidth: 240 }}
            />
            <Button
              color={maintenance ? 'success' : 'warning'}
              variant="contained"
              onClick={() => toggleMaintenance.mutate()}
              disabled={adminOnly}
            >
              {maintenance ? 'End maintenance' : 'Start maintenance'}
            </Button>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Maintenance pauses renewals, deployments, notifications, imports and background jobs.
          </Typography>
        </CardContent>
      </Card>

      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Setting</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Value</TableCell>
              <TableCell align="right">Action</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {settingsList.map((s) => (
              <TableRow key={s.key}>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{s.key}</Typography>
                </TableCell>
                <TableCell>{s.description}</TableCell>
                <TableCell>
                  {s.is_secret ? (s.configured ? '[SET]' : '(empty)') : s.value || '(empty)'}
                </TableCell>
                <TableCell align="right">
                  <Button size="small" disabled={adminOnly} onClick={() => { setEdit(s); setValue('') }}>
                    {s.configured ? 'Update' : 'Set'}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={Boolean(edit)} onClose={() => setEdit(null)} maxWidth="xs" fullWidth>
        <DialogTitle>{edit?.configured ? 'Update' : 'Set'} {edit?.key}</DialogTitle>
        <DialogContent>
          {edit?.is_secret && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
              Leave empty to keep the existing value; a new value replaces it (encrypted at rest).
            </Typography>
          )}
          <TextField
            label={edit?.is_secret ? 'Secret value' : 'Value'}
            fullWidth
            type={edit?.is_secret ? 'password' : 'text'}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Cancel</Button>
          <Button variant="contained" onClick={() => saveSetting.mutate()} disabled={!value}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
