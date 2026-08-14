import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
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
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Typography,
} from '@mui/material'
import AutorenewIcon from '@mui/icons-material/Autorenew'
import BlockIcon from '@mui/icons-material/Block'
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch'
import ArchiveIcon from '@mui/icons-material/Archive'
import DeleteForeverIcon from '@mui/icons-material/DeleteForever'
import { api, apiErrorMessage, downloadFile } from '../lib/api'
import type { Certificate, Deployment, Execution, Page } from '../types'
import { ConfirmDialog, ErrorBox, Loading, PageHeader, StatusChip, Toast, daysColor } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

const DELETABLE_STATUSES = ['failed', 'revoked', 'archived']

export default function CertificateDetailPage() {
  const { id } = useParams()
  const certId = Number(id)
  const { can } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState(0)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [confirm, setConfirm] = useState<null | 'renew' | 'revoke' | 'deploy' | 'delete'>(null)
  const [revokeReason, setRevokeReason] = useState('unspecified')
  const [deployTarget, setDeployTarget] = useState({ server_id: 0, method: 'sftp', target_service: 'nginx' })

  const cert = useQuery({
    queryKey: ['cert', certId],
    queryFn: () => api.get<Certificate>(`/certificates/${certId}`).then((r) => r.data),
  })
  const executions = useQuery({
    queryKey: ['cert-executions', certId],
    queryFn: () => api.get<Page<Execution>>(`/certificates/${certId}/executions`, { params: { page_size: 50 } }).then((r) => r.data),
    enabled: tab === 1,
  })
  const deployments = useQuery({
    queryKey: ['cert-deployments', certId],
    queryFn: () => api.get<Page<Deployment>>('/deployments', { params: { certificate_id: certId, page_size: 50 } }).then((r) => r.data),
    enabled: tab === 2,
  })
  const servers = useQuery({
    queryKey: ['servers-min'],
    queryFn: () => api.get<Page<{ id: number; hostname: string }>>('/servers', { params: { page_size: 500 } }).then((r) => r.data),
    enabled: confirm === 'deploy',
  })

  const action = useMutation({
    mutationFn: async () => {
      if (confirm === 'renew') return api.post(`/certificates/${certId}/renew`, { force: false })
      if (confirm === 'revoke') return api.post(`/certificates/${certId}/revoke`, { reason: revokeReason, delete_after: true })
      if (confirm === 'delete') return api.delete(`/certificates/${certId}`)
      if (confirm === 'deploy') {
        if (!deployTarget.server_id) throw new Error('Select a target server')
        return api.post('/deployments', {
          certificate_id: certId,
          server_id: deployTarget.server_id,
          method: deployTarget.method,
          target_service: deployTarget.target_service,
        })
      }
      throw new Error('unknown action')
    },
    onSuccess: (res) => {
      const wasDelete = confirm === 'delete'
      setConfirm(null)
      qc.invalidateQueries({ queryKey: ['certificates'] })
      if (wasDelete) {
        setToast({ message: 'Certificate deleted', severity: 'success' })
        navigate('/certificates')
        return
      }
      setToast({ message: `Action queued: ${(res.data as { status?: string }).status ?? 'ok'}`, severity: 'success' })
      qc.invalidateQueries({ queryKey: ['cert', certId] })
      qc.invalidateQueries({ queryKey: ['cert-executions', certId] })
    },
    onError: (e) => {
      setToast({ message: apiErrorMessage(e), severity: 'error' })
      setConfirm(null)
    },
  })

  const download = (fmt: string) => {
    const includeKey = fmt === 'key' || fmt === 'pfx' || fmt === 'zip'
    if (includeKey && !can('certificate:download_key')) {
      setToast({ message: 'You are not authorized to download private keys', severity: 'error' })
      return
    }
    downloadFile(`/certificates/${certId}/download/${fmt}`, { include_key: includeKey }, `certificate-${certId}.${fmt}`)
      .then(() => setToast({ message: `Downloaded ${fmt}`, severity: 'success' }))
      .catch((e) => setToast({ message: apiErrorMessage(e), severity: 'error' }))
  }

  if (cert.isLoading) return <Loading />
  if (cert.error || !cert.data) return <ErrorBox message="Certificate not found" onRetry={() => cert.refetch()} />

  const c = cert.data

  const InfoRow = ({ label, value, mono }: { label: string; value?: React.ReactNode; mono?: boolean }) => (
    <Box sx={{ py: 0.75 }}>
      <Typography variant="caption" color="text.secondary" display="block">
        {label}
      </Typography>
      {value ? (
        <Typography variant="body2" sx={{ wordBreak: 'break-all', fontFamily: mono ? 'monospace' : undefined }}>
          {value}
        </Typography>
      ) : (
        <Typography variant="body2" color="text.disabled">—</Typography>
      )}
    </Box>
  )

  return (
    <Box>
      <PageHeader
        title={c.domain}
        subtitle={`Certificate #${c.id} · ${c.cert_type} · ${c.provider_name}`}
        actions={
          <>
            {can('certificate:renew') && (
              <Button startIcon={<AutorenewIcon />} onClick={() => setConfirm('renew')}>Renew</Button>
            )}
            {can('certificate:deploy') && (
              <Button startIcon={<RocketLaunchIcon />} onClick={() => setConfirm('deploy')}>Deploy</Button>
            )}
            {can('certificate:revoke') && !DELETABLE_STATUSES.includes(c.status) && (
              <Button color="error" startIcon={<BlockIcon />} onClick={() => setConfirm('revoke')}>Revoke</Button>
            )}
            {can('certificate:delete') && DELETABLE_STATUSES.includes(c.status) && (
              <Button color="error" startIcon={<DeleteForeverIcon />} onClick={() => setConfirm('delete')}>Delete</Button>
            )}
          </>
        }
      />

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>Status</Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
                <StatusChip value={c.status} />
                <StatusChip value={c.renewal_status} />
                <Chip size="small" variant="outlined" label={c.environment} />
                <Chip size="small" variant="outlined" label={c.imported ? 'imported' : 'managed'} />
              </Box>
              <InfoRow label="Expires" value={c.valid_until ? new Date(c.valid_until).toLocaleString() : undefined} />
              <InfoRow label="Days remaining" value={<span style={{ color: daysColor(c.days_remaining), fontWeight: 600 }}>{c.days_remaining}</span>} />
              <InfoRow label="Auto renew" value={c.auto_renew ? 'Enabled' : 'Disabled'} />
              <InfoRow label="Health score" value={c.health_score != null ? `${c.health_score}/100 (${c.health_status})` : 'Not scanned'} />
              {c.renewal_error && (
                <Alert severity="error" sx={{ mt: 1 }}>{c.renewal_error}</Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>Certificate details</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <InfoRow label="Subject" value={c.subject} />
                  <InfoRow label="Issuer" value={c.issuer} />
                  <InfoRow label="Serial number" value={c.serial_number} mono />
                  <InfoRow label="Key" value={c.key_type ? `${c.key_type} ${c.key_size ?? ''}`.trim() : undefined} />
                  <InfoRow label="Signature algorithm" value={c.signature_algorithm} />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <InfoRow label="Fingerprint (SHA-256)" value={c.fingerprint_sha256} mono />
                  <InfoRow label="Valid from" value={c.valid_from ? new Date(c.valid_from).toLocaleString() : undefined} />
                  <InfoRow label="Cert name" value={c.cert_name} mono />
                  <InfoRow label="Validation" value={c.validation_method} />
                  <InfoRow label="Notes" value={c.notes} />
                </Grid>
              </Grid>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                SANs: {c.sans.join(', ')}
              </Typography>
              {c.tags.length > 0 && (
                <Box sx={{ mt: 1, display: 'flex', gap: 0.5 }}>
                  {c.tags.map((t) => (
                    <Chip key={t} size="small" label={t} />
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper sx={{ mb: 2 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)}>
          <Tab label="Execution history" />
          <Tab label="Deployments" />
          <Tab label="Downloads" />
        </Tabs>
      </Paper>

      {tab === 0 &&
        (executions.isLoading ? <Loading /> : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Job</TableCell>
                  <TableCell>Trigger</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Exit</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Output</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(executions.data?.items ?? []).map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>#{e.id}</TableCell>
                    <TableCell>{e.job_type}</TableCell>
                    <TableCell>{e.trigger}</TableCell>
                    <TableCell><StatusChip value={e.status} /></TableCell>
                    <TableCell>{e.exit_code ?? '—'}</TableCell>
                    <TableCell>{e.execution_time_ms != null ? `${e.execution_time_ms}ms` : '—'}</TableCell>
                    <TableCell>{e.started_at ? new Date(e.started_at).toLocaleString() : '—'}</TableCell>
                    <TableCell>
                      <details>
                        <summary style={{ cursor: 'pointer', fontSize: 12 }}>view log</summary>
                        <pre className="console-output" style={{ marginTop: 6 }}>
                          {e.stdout || '—'}{e.stderr ? `\n\n[stderr]\n${e.stderr}` : ''}
                        </pre>
                      </details>
                    </TableCell>
                  </TableRow>
                ))}
                {(executions.data?.items ?? []).length === 0 && (
                  <TableRow><TableCell colSpan={8} align="center">No executions yet</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        ))}

      {tab === 1 &&
        (deployments.isLoading ? <Loading /> : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Server</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Method</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Backup</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Error</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(deployments.data?.items ?? []).map((d) => (
                  <TableRow key={d.id}>
                    <TableCell>#{d.id}</TableCell>
                    <TableCell>{d.server_hostname}</TableCell>
                    <TableCell>{d.target_service}</TableCell>
                    <TableCell>{d.method}</TableCell>
                    <TableCell><StatusChip value={d.status} /></TableCell>
                    <TableCell>{d.backup_path ? 'yes' : '—'}</TableCell>
                    <TableCell>{d.started_at ? new Date(d.started_at).toLocaleString() : '—'}</TableCell>
                    <TableCell><Typography variant="caption" color="error">{d.error_message}</Typography></TableCell>
                  </TableRow>
                ))}
                {(deployments.data?.items ?? []).length === 0 && (
                  <TableRow><TableCell colSpan={8} align="center">No deployments yet</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        ))}

      {tab === 2 && (
        <Card>
          <CardContent>
            <Grid container spacing={1.5}>
              {[
                ['pem', 'Certificate (PEM)'],
                ['chain', 'Chain'],
                ['fullchain', 'Fullchain'],
                ['zip', 'ZIP bundle (cert+key+chain)'],
                ['pfx', 'PFX (PKCS12)'],
                ['key', 'Private key'],
              ].map(([fmt, label]) => (
                <Grid item xs={12} sm={6} md={4} key={fmt}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<ArchiveIcon />}
                    onClick={() => download(fmt)}
                    disabled={fmt === 'key' && !can('certificate:download_key')}
                  >
                    {label}
                  </Button>
                </Grid>
              ))}
            </Grid>
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1.5 }}>
              All downloads are recorded in the audit log. Private key downloads require the
              <b> certificate:download_key</b> permission.
            </Typography>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={confirm === 'renew'}
        title="Renew this certificate?"
        body="A renewal attempt will be executed for this certificate."
        confirmLabel="Renew"
        onConfirm={() => action.mutate()}
        onClose={() => setConfirm(null)}
      />
      <ConfirmDialog
        open={confirm === 'delete'}
        title="Permanently delete this certificate?"
        body="This removes the certificate record and its material (if any) entirely — immediate and irreversible. Only failed, revoked, or archived certificates can be deleted."
        confirmLabel="Delete"
        danger
        onConfirm={() => action.mutate()}
        onClose={() => setConfirm(null)}
      />
      <Dialog open={confirm === 'revoke'} onClose={() => setConfirm(null)} maxWidth="xs" fullWidth>
        <DialogTitle>Revoke certificate</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Reason</InputLabel>
            <Select value={revokeReason} label="Reason" onChange={(e) => setRevokeReason(e.target.value)}>
              {['unspecified', 'keycompromise', 'affiliationchanged', 'superseded', 'cessationofoperation'].map((r) => (
                <MenuItem key={r} value={r}>{r}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => action.mutate()}>Revoke</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={confirm === 'deploy'} onClose={() => setConfirm(null)} maxWidth="xs" fullWidth>
        <DialogTitle>Deploy certificate</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
          <FormControl fullWidth>
            <InputLabel>Target server</InputLabel>
            <Select
              label="Target server"
              value={deployTarget.server_id || ''}
              onChange={(e) => setDeployTarget((d) => ({ ...d, server_id: Number(e.target.value) }))}
            >
              {(servers.data?.items ?? []).map((s) => (
                <MenuItem key={s.id} value={s.id}>{s.hostname}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl fullWidth>
            <InputLabel>Service</InputLabel>
            <Select
              label="Service"
              value={deployTarget.target_service}
              onChange={(e) => setDeployTarget((d) => ({ ...d, target_service: e.target.value }))}
            >
              {['nginx', 'apache', 'haproxy', 'openvpn', 'tomcat', 'custom'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl fullWidth>
            <InputLabel>Method</InputLabel>
            <Select
              label="Method"
              value={deployTarget.method}
              onChange={(e) => setDeployTarget((d) => ({ ...d, method: e.target.value }))}
            >
              {['sftp', 'scp', 'ssh', 'rsync'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button variant="contained" startIcon={<RocketLaunchIcon />} onClick={() => action.mutate()}>
            Deploy
          </Button>
        </DialogActions>
      </Dialog>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
