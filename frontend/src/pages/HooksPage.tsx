import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import { api, apiErrorMessage } from '../lib/api'
import type { Hook } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

const HOOK_TYPES = ['auth', 'cleanup', 'pre_deploy', 'post_deploy', 'rollback', 'custom']

export default function HooksPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [form, setForm] = useState({
    name: '', hook_type: 'auth', script_path: '', env_vars: '{}',
    execution_user: '', working_directory: '', timeout_seconds: 300,
  })

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['hooks'],
    queryFn: () => api.get<Hook[]>('/hooks').then((r) => r.data),
  })

  const create = useMutation({
    mutationFn: () => {
      let env = {}
      try {
        env = JSON.parse(form.env_vars || '{}')
      } catch {
        throw new Error('Environment variables must be valid JSON')
      }
      return api.post('/hooks', {
        ...form,
        env_vars: env,
        execution_user: form.execution_user || undefined,
        working_directory: form.working_directory || undefined,
      })
    },
    onSuccess: () => {
      setOpen(false)
      setToast({ message: 'Hook created', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['hooks'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const toggle = useMutation({
    mutationFn: (hook: Hook) => api.patch(`/hooks/${hook.id}`, { is_active: !hook.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hooks'] }),
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  return (
    <Box>
      <PageHeader
        title="Hooks"
        subtitle="Authentication, cleanup and deployment hook scripts"
        actions={
          can('hook:manage') && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
              New hook
            </Button>
          )
        }
      />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load hooks" onRetry={() => refetch()} />
      ) : !data || data.length === 0 ? (
        <EmptyState text="No hooks configured. Create auth/cleanup scripts for DNS-01 or custom validation." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Script path</TableCell>
                <TableCell>Env vars</TableCell>
                <TableCell>Run as</TableCell>
                <TableCell>Workdir</TableCell>
                <TableCell>Timeout</TableCell>
                <TableCell>Active</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((h) => (
                <TableRow key={h.id}>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{h.name}</Typography>
                    {h.is_default && <Chip size="small" label="default" color="secondary" sx={{ mt: 0.5 }} />}
                  </TableCell>
                  <TableCell><StatusChip value={h.hook_type} /></TableCell>
                  <TableCell><Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{h.script_path}</Typography></TableCell>
                  <TableCell>
                    <Typography variant="caption">
                      {Object.keys(h.env_vars ?? {}).length} variable(s)
                    </Typography>
                  </TableCell>
                  <TableCell>{h.execution_user ?? 'current'}</TableCell>
                  <TableCell>{h.working_directory ?? '—'}</TableCell>
                  <TableCell>{h.timeout_seconds}s</TableCell>
                  <TableCell>
                    <Switch
                      checked={h.is_active}
                      onChange={() => toggle.mutate(h)}
                      disabled={!can('hook:manage')}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>New hook</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid item xs={12} sm={6}>
              <TextField label="Name *" fullWidth value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Type</InputLabel>
                <Select label="Type" value={form.hook_type} onChange={(e) => setForm((f) => ({ ...f, hook_type: e.target.value }))}>
                  {HOOK_TYPES.map((t) => (
                    <MenuItem key={t} value={t}>{t}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField label="Script path (absolute, executable) *" fullWidth value={form.script_path} onChange={(e) => setForm((f) => ({ ...f, script_path: e.target.value }))} placeholder="/export/home/secauto/scripts/certbot/vip/authenticator.pl" />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField label="Execution user" fullWidth value={form.execution_user} onChange={(e) => setForm((f) => ({ ...f, execution_user: e.target.value }))} />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField label="Working directory" fullWidth value={form.working_directory} onChange={(e) => setForm((f) => ({ ...f, working_directory: e.target.value }))} />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField label="Timeout (seconds)" type="number" fullWidth value={form.timeout_seconds} onChange={(e) => setForm((f) => ({ ...f, timeout_seconds: Number(e.target.value) }))} />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField label="Environment variables (JSON)" fullWidth value={form.env_vars} onChange={(e) => setForm((f) => ({ ...f, env_vars: e.target.value }))} placeholder='{"API_TOKEN":"…"}' />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => create.mutate()} disabled={!form.name || !form.script_path}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
