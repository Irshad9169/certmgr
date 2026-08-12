import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box,
  Button,
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
import type { Page } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'

interface UserRow {
  id: number
  username: string
  email?: string | null
  full_name: string
  role: string
  is_active: boolean
  mfa_enabled: boolean
  last_login_at?: string | null
}

interface RoleRow {
  name: string
  description: string
  permissions: string[]
}

export default function UsersPage() {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [form, setForm] = useState({ username: '', email: '', full_name: '', password: '', role: 'read_only' })

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<Page<UserRow>>('/users', { params: { page_size: 500 } }).then((r) => r.data),
  })
  const roles = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.get<RoleRow[]>('/users/roles').then((r) => r.data),
  })

  const create = useMutation({
    mutationFn: () =>
      api.post('/users', {
        username: form.username,
        email: form.email || undefined,
        full_name: form.full_name,
        password: form.password,
        role: form.role,
      }),
    onSuccess: () => {
      setOpen(false)
      setToast({ message: 'User created', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['users'] })
      setForm({ username: '', email: '', full_name: '', password: '', role: 'read_only' })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const toggleActive = useMutation({
    mutationFn: (u: UserRow) => api.patch(`/users/${u.id}`, { is_active: !u.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  return (
    <Box>
      <PageHeader
        title="Users & roles"
        subtitle="Accounts, RBAC roles and permission codes"
        actions={
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
            New user
          </Button>
        }
      />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load users" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No users" />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Username</TableCell>
                <TableCell>Full name</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>MFA</TableCell>
                <TableCell>Active</TableCell>
                <TableCell>Last login</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.items.map((u) => (
                <TableRow key={u.id}>
                  <TableCell><Typography variant="body2" sx={{ fontWeight: 600 }}>{u.username}</Typography></TableCell>
                  <TableCell>{u.full_name}</TableCell>
                  <TableCell>{u.email ?? '—'}</TableCell>
                  <TableCell><StatusChip value={u.role} /></TableCell>
                  <TableCell>{u.mfa_enabled ? 'enabled' : '—'}</TableCell>
                  <TableCell>
                    <Switch checked={u.is_active} onChange={() => toggleActive.mutate(u)} />
                  </TableCell>
                  <TableCell>{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Typography variant="h6" sx={{ mt: 4, mb: 1 }}>Role permission matrix</Typography>
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Role</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Permissions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(roles.data ?? []).map((r) => (
              <TableRow key={r.name}>
                <TableCell><StatusChip value={r.name} /></TableCell>
                <TableCell>{r.description}</TableCell>
                <TableCell>
                  <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                    {r.permissions.join(', ')}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>New user</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid item xs={12}><TextField label="Username *" fullWidth value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} /></Grid>
            <Grid item xs={12}><TextField label="Full name" fullWidth value={form.full_name} onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} /></Grid>
            <Grid item xs={12}><TextField label="Email" fullWidth value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} /></Grid>
            <Grid item xs={12}>
              <TextField label="Initial password *" type="password" fullWidth value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} helperText="Min 12 chars: upper, lower, digit, special" />
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Role</InputLabel>
                <Select label="Role" value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
                  {(roles.data ?? []).map((r) => (
                    <MenuItem key={r.name} value={r.name}>{r.name}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => create.mutate()} disabled={!form.username || !form.password}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
