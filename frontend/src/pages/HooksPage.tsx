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
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import EditIcon from '@mui/icons-material/Edit'
import LockIcon from '@mui/icons-material/Lock'
import { api, apiErrorMessage } from '../lib/api'
import type { Hook } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

const HOOK_TYPES = ['auth', 'cleanup', 'pre_deploy', 'post_deploy', 'rollback', 'custom']

const EMPTY_FORM = {
  name: '', hook_type: 'auth', script_path: '', env_vars: '{}',
  execution_user: '', working_directory: '', timeout_seconds: 300,
  ssh_target_host: '', ssh_private_key: '',
}

export default function HooksPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [hasExistingKey, setHasExistingKey] = useState(false)
  const [replaceKey, setReplaceKey] = useState(false)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [form, setForm] = useState(EMPTY_FORM)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['hooks'],
    queryFn: () => api.get<Hook[]>('/hooks').then((r) => r.data),
  })

  const openCreate = () => {
    setForm(EMPTY_FORM)
    setEditingId(null)
    setHasExistingKey(false)
    setReplaceKey(true)
    setOpen(true)
  }

  const openEdit = (h: Hook) => {
    setForm({
      name: h.name,
      hook_type: h.hook_type,
      script_path: h.script_path,
      env_vars: JSON.stringify(h.env_vars ?? {}),
      execution_user: h.execution_user ?? '',
      working_directory: h.working_directory ?? '',
      timeout_seconds: h.timeout_seconds,
      ssh_target_host: h.ssh_target_host ?? '',
      ssh_private_key: '',
    })
    setEditingId(h.id)
    setHasExistingKey(h.has_ssh_key)
    setReplaceKey(!h.has_ssh_key)
    setOpen(true)
  }

  const save = useMutation({
    mutationFn: () => {
      let env = {}
      try {
        env = JSON.parse(form.env_vars || '{}')
      } catch {
        throw new Error('Environment variables must be valid JSON')
      }
      const payload: Record<string, unknown> = {
        name: form.name,
        hook_type: form.hook_type,
        script_path: form.script_path,
        env_vars: env,
        execution_user: form.execution_user || undefined,
        working_directory: form.working_directory || undefined,
        timeout_seconds: form.timeout_seconds,
        ssh_target_host: form.ssh_target_host || undefined,
      }
      // Jenkins-credential-style masking: only send ssh_private_key when the
      // user actually opted to set/replace/clear it. Omitting it on update
      // leaves whatever key is already stored untouched.
      if (editingId == null || replaceKey) {
        payload.ssh_private_key = form.ssh_private_key
      }
      return editingId == null
        ? api.post('/hooks', payload)
        : api.patch(`/hooks/${editingId}`, payload)
    },
    onSuccess: () => {
      setOpen(false)
      setToast({ message: editingId == null ? 'Hook created' : 'Hook updated', severity: 'success' })
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
            <Button variant="contained" startIcon={<AddIcon />} onClick={openCreate}>
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
                <TableCell>SSH credential</TableCell>
                <TableCell>Active</TableCell>
                <TableCell align="right">Actions</TableCell>
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
                    {h.has_ssh_key ? (
                      <Tooltip title={h.ssh_target_host ? `Target: ${h.ssh_target_host}` : 'No target host set'}>
                        <Chip size="small" icon={<LockIcon />} label="configured" color="success" variant="outlined" />
                      </Tooltip>
                    ) : (
                      <Typography variant="caption" color="text.secondary">—</Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={h.is_active}
                      onChange={() => toggle.mutate(h)}
                      disabled={!can('hook:manage')}
                    />
                  </TableCell>
                  <TableCell align="right">
                    {can('hook:manage') && (
                      <IconButton size="small" onClick={() => openEdit(h)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{editingId == null ? 'New hook' : 'Edit hook'}</DialogTitle>
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

            <Grid item xs={12}>
              <Typography variant="subtitle2" sx={{ mt: 1 }}>
                SSH credential (optional)
              </Typography>
              <Typography variant="caption" color="text.secondary">
                For scripts that SSH to a remote host with no identity file of their own —
                CertMgr stages this key as a temporary, host-scoped ssh_config entry for the
                duration of a single issuance, then removes it. Requires a one-time server
                setup step; see docs/administration.md.
              </Typography>
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="SSH target host"
                fullWidth
                value={form.ssh_target_host}
                onChange={(e) => setForm((f) => ({ ...f, ssh_target_host: e.target.value }))}
                placeholder="lets-encrypt01.vgs.qa8.untd.com"
              />
            </Grid>
            <Grid item xs={12}>
              {!replaceKey && hasExistingKey ? (
                <Stack direction="row" spacing={1} alignItems="center">
                  <TextField
                    label="SSH private key"
                    fullWidth
                    disabled
                    value="•••••••••••••••• (configured)"
                  />
                  <Button size="small" onClick={() => setReplaceKey(true)}>Replace</Button>
                </Stack>
              ) : (
                <Stack spacing={0.5}>
                  <TextField
                    label="SSH private key (PEM)"
                    fullWidth
                    multiline
                    minRows={4}
                    value={form.ssh_private_key}
                    onChange={(e) => setForm((f) => ({ ...f, ssh_private_key: e.target.value }))}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;…&#10;-----END OPENSSH PRIVATE KEY-----"
                    sx={{ fontFamily: 'monospace' }}
                  />
                  {hasExistingKey && (
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="caption" color="text.secondary">
                        Leave blank and save to remove the stored key.
                      </Typography>
                      <Button size="small" onClick={() => { setReplaceKey(false); setForm((f) => ({ ...f, ssh_private_key: '' })) }}>
                        Cancel
                      </Button>
                    </Stack>
                  )}
                </Stack>
              )}
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => save.mutate()} disabled={!form.name || !form.script_path}>
            {editingId == null ? 'Create' : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
