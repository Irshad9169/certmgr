import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DnsIcon from '@mui/icons-material/Dns'
import WifiTetheringIcon from '@mui/icons-material/WifiTethering'
import { api, apiErrorMessage } from '../lib/api'
import type { Page, Server } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

export default function ServersPage() {
  const navigate = useNavigate()
  const { can } = useAuth()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [open, setOpen] = useState(false)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [form, setForm] = useState({
    hostname: '', ip_address: '', environment: 'production', ssh_port: 22,
    auth_method: 'ssh_key', ssh_user: 'root', ssh_password: '', ssh_key_path: '',
    web_server_type: 'nginx', tags: '',
  })

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['servers', page, pageSize],
    queryFn: () => api.get<Page<Server>>('/servers', { params: { page, page_size: pageSize } }).then((r) => r.data),
  })

  const create = useMutation({
    mutationFn: () =>
      api.post('/servers', {
        ...form,
        tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
        ssh_password: form.ssh_password || undefined,
      }),
    onSuccess: () => {
      setOpen(false)
      setToast({ message: 'Server added', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['servers'] })
      setForm({ hostname: '', ip_address: '', environment: 'production', ssh_port: 22, auth_method: 'ssh_key', ssh_user: 'root', ssh_password: '', ssh_key_path: '', web_server_type: 'nginx', tags: '' })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const testConnection = useMutation({
    mutationFn: (id: number) => api.post(`/servers/${id}/test`),
    onSuccess: (res) => {
      const r = res.data as { reachable: boolean; error?: string }
      setToast({ message: r.reachable ? 'Server reachable' : `Unreachable: ${r.error ?? ''}`, severity: r.reachable ? 'success' : 'error' })
      qc.invalidateQueries({ queryKey: ['servers'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  return (
    <Box>
      <PageHeader
        title="Servers"
        subtitle="Managed Linux server inventory for deployment targets"
        actions={
          can('server:manage') && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
              Add server
            </Button>
          )
        }
      />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load servers" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No servers registered. Add your first deployment target." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Hostname</TableCell>
                <TableCell>IP</TableCell>
                <TableCell>Environment</TableCell>
                <TableCell>SSH</TableCell>
                <TableCell>Web server</TableCell>
                <TableCell>Connection</TableCell>
                <TableCell>Tags</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.items.map((s) => (
                <TableRow key={s.id} hover sx={{ cursor: 'pointer' }} onClick={() => navigate(`/servers/${s.id}`)}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <DnsIcon color="primary" fontSize="small" />
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{s.hostname}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell>{s.ip_address ?? '—'}</TableCell>
                  <TableCell><StatusChip value={s.environment} /></TableCell>
                  <TableCell>
                    <Typography variant="caption">{s.ssh_user}@{s.ssh_port} ({s.auth_method})</Typography>
                  </TableCell>
                  <TableCell>{s.web_server_type ?? '—'}</TableCell>
                  <TableCell><StatusChip value={s.connection_status} /></TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.4, flexWrap: 'wrap' }}>
                      {s.tags.slice(0, 3).map((t) => (
                        <StatusChip key={t} value={t} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                    <Button
                      size="small"
                      startIcon={<WifiTetheringIcon />}
                      onClick={() => testConnection.mutate(s.id)}
                      disabled={testConnection.isPending}
                    >
                      Test
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <TablePagination
            component="div"
            count={data.total}
            page={page - 1}
            rowsPerPage={pageSize}
            rowsPerPageOptions={[10, 25, 50]}
            onPageChange={(_, p) => setPage(p + 1)}
            onRowsPerPageChange={(e) => {
              setPageSize(Number(e.target.value))
              setPage(1)
            }}
          />
        </TableContainer>
      )}

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add server</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid item xs={12} sm={6}>
              <TextField label="Hostname *" fullWidth value={form.hostname} onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))} />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField label="IP address" fullWidth value={form.ip_address} onChange={(e) => setForm((f) => ({ ...f, ip_address: e.target.value }))} />
            </Grid>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Environment</InputLabel>
                <Select label="Environment" value={form.environment} onChange={(e) => setForm((f) => ({ ...f, environment: e.target.value }))}>
                  {['production', 'development', 'testing', 'dr', 'cloud', 'on_premise'].map((s) => (
                    <MenuItem key={s} value={s}>{s}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6}>
              <TextField label="SSH port" type="number" fullWidth value={form.ssh_port} onChange={(e) => setForm((f) => ({ ...f, ssh_port: Number(e.target.value) }))} />
            </Grid>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Auth method</InputLabel>
                <Select label="Auth method" value={form.auth_method} onChange={(e) => setForm((f) => ({ ...f, auth_method: e.target.value }))}>
                  <MenuItem value="ssh_key">SSH key</MenuItem>
                  <MenuItem value="password">Password</MenuItem>
                  <MenuItem value="agent">Agent</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6}>
              <TextField label="SSH user" fullWidth value={form.ssh_user} onChange={(e) => setForm((f) => ({ ...f, ssh_user: e.target.value }))} />
            </Grid>
            {form.auth_method === 'password' ? (
              <Grid item xs={12}>
                <TextField label="SSH password (encrypted at rest)" type="password" fullWidth value={form.ssh_password} onChange={(e) => setForm((f) => ({ ...f, ssh_password: e.target.value }))} />
              </Grid>
            ) : (
              <Grid item xs={12}>
                <TextField label="SSH key path (on platform host)" fullWidth value={form.ssh_key_path} onChange={(e) => setForm((f) => ({ ...f, ssh_key_path: e.target.value }))} placeholder="/var/lib/certmgr/keys/server1.pem" />
              </Grid>
            )}
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Web server</InputLabel>
                <Select label="Web server" value={form.web_server_type} onChange={(e) => setForm((f) => ({ ...f, web_server_type: e.target.value }))}>
                  {['nginx', 'apache', 'haproxy', 'openvpn', 'tomcat', 'custom'].map((s) => (
                    <MenuItem key={s} value={s}>{s}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6}>
              <TextField label="Tags (comma)" fullWidth value={form.tags} onChange={(e) => setForm((f) => ({ ...f, tags: e.target.value }))} />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => create.mutate()} disabled={!form.hostname || create.isPending}>
            Add
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
