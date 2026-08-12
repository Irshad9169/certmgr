import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import {
  Box,
  Button,
  Card,
  CardContent,
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
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
import { api, apiErrorMessage } from '../lib/api'
import type { Page, Server } from '../types'
import { ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

const ALLOWED_SERVICES = ['nginx', 'apache2', 'httpd', 'openvpn', 'haproxy', 'tomcat9', 'sshd']
const ALLOWED_ACTIONS = ['status', 'restart', 'reload', 'stop', 'start']

export default function ServerDetailPage() {
  const { id } = useParams()
  const serverId = Number(id)
  const { can } = useAuth()
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [command, setCommand] = useState('systemctl status nginx')
  const [output, setOutput] = useState('')
  const [service, setService] = useState('nginx')
  const [action, setAction] = useState('restart')

  const server = useQuery({
    queryKey: ['server', serverId],
    queryFn: () => api.get<Server>(`/servers?search=${serverId}`).then(() => fetchServer()),
  })

  const fetchServer = async () => {
    const res = await api.get<Page<Server>>('/servers', { params: { page_size: 1000 } })
    const found = res.data.items.find((s) => s.id === serverId)
    if (!found) throw new Error('not found')
    return found
  }

  const runCommand = useMutation({
    mutationFn: (cmd: string) => api.post(`/servers/${serverId}/command`, { command: cmd }),
    onSuccess: (res) => {
      const r = res.data as { stdout?: string; stderr?: string; exit_code?: number; error?: string }
      setOutput(`$ ${command}\n${r.stdout ?? ''}${r.stderr ? `\n[stderr]\n${r.stderr}` : ''}${r.error ? `\n[error]\n${r.error}` : ''}\n[exit: ${r.exit_code}]`)
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const controlService = useMutation({
    mutationFn: () => api.post(`/servers/${serverId}/service/${service}/${action}`),
    onSuccess: (res) => {
      const r = res.data as { stdout?: string; exit_code?: number }
      setOutput(`$ systemctl ${action} ${service}\n${r.stdout ?? ''}\n[exit: ${r.exit_code}]`)
      qc.invalidateQueries({ queryKey: ['server', serverId] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  if (server.isLoading) return <Loading />
  if (server.error || !server.data) return <ErrorBox message="Server not found" onRetry={() => server.refetch()} />

  const s = server.data

  return (
    <Box>
      <PageHeader
        title={s.hostname}
        subtitle={`${s.ip_address ?? ''} · ${s.environment} · SSH ${s.ssh_user}@:${s.ssh_port} (${s.auth_method})`}
      />

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>Server info</Typography>
              {[
                ['Connection status', <StatusChip key="s" value={s.connection_status} />],
                ['OS', s.os_type],
                ['Web server', s.web_server_type ?? '—'],
                ['Certificate dir', s.certificate_directory ?? '—'],
                ['Proxy jump', s.proxy_jump ?? '—'],
                ['Last check', s.last_check_at ? new Date(s.last_check_at).toLocaleString() : '—'],
                ['Notes', s.notes ?? '—'],
              ].map(([k, v]) => (
                <Box key={k as string} sx={{ py: 0.5 }}>
                  <Typography variant="caption" color="text.secondary" display="block">{k}</Typography>
                  <Typography variant="body2">{v}</Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>Service control</Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                <FormControl size="small" sx={{ minWidth: 130 }}>
                  <InputLabel>Service</InputLabel>
                  <Select label="Service" value={service} onChange={(e) => setService(e.target.value)}>
                    {ALLOWED_SERVICES.map((sv) => (
                      <MenuItem key={sv} value={sv}>{sv}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 110 }}>
                  <InputLabel>Action</InputLabel>
                  <Select label="Action" value={action} onChange={(e) => setAction(e.target.value)}>
                    {ALLOWED_ACTIONS.map((a) => (
                      <MenuItem key={a} value={a}>{a}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Button variant="contained" onClick={() => controlService.mutate()} disabled={!can('server:command')}>
                  Execute
                </Button>
              </Box>

              <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>Remote command center</Typography>
              <Typography variant="caption" color="text.secondary">
                Only allowlisted maintenance commands are accepted — everything is audited.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                <TextField
                  size="small"
                  fullWidth
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  placeholder="systemctl restart nginx"
                />
                <Button
                  variant="outlined"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => runCommand.mutate(command)}
                  disabled={!can('server:command') || runCommand.isPending}
                >
                  Run
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {output && (
        <Paper sx={{ p: 0, mb: 2 }}>
          <pre className="console-output" style={{ margin: 0, borderRadius: 0 }}>{output}</pre>
        </Paper>
      )}

      <Typography variant="h6" sx={{ mb: 1 }}>Deployments to this server</Typography>
      <DeploymentsForServer serverId={serverId} />
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}

function DeploymentsForServer({ serverId }: { serverId: number }) {
  const { data } = useQuery({
    queryKey: ['server-deployments', serverId],
    queryFn: () => api.get<Page<{ id: number; certificate_domain?: string; status: string; method: string; started_at?: string; error_message?: string }>>(
      '/deployments', { params: { server_id: serverId, page_size: 20 } },
    ).then((r) => r.data),
  })
  return (
    <TableContainer component={Paper}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Certificate</TableCell>
            <TableCell>Method</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Started</TableCell>
            <TableCell>Error</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {(data?.items ?? []).map((d) => (
            <TableRow key={d.id}>
              <TableCell>#{d.id}</TableCell>
              <TableCell>{d.certificate_domain}</TableCell>
              <TableCell>{d.method}</TableCell>
              <TableCell><StatusChip value={d.status} /></TableCell>
              <TableCell>{d.started_at ? new Date(d.started_at).toLocaleString() : '—'}</TableCell>
              <TableCell><Typography variant="caption" color="error">{d.error_message}</Typography></TableCell>
            </TableRow>
          ))}
          {(data?.items ?? []).length === 0 && (
            <TableRow><TableCell colSpan={6} align="center">No deployments yet</TableCell></TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
