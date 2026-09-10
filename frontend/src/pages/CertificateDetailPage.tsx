import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  LinearProgress,
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
  TextField,
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
const USAGE_STATUSES = ['confirmed', 'different_certificate', 'unreachable', 'dns_failed', 'tls_failed', 'timeout']
const USAGE_PORTS = [443, 8443, 9443]

interface NetworkSighting {
  id: number
  certificate_id: number
  host: string
  port: number
  sni_hostname: string | null
  first_seen_at?: string
  last_seen_at?: string
}

interface CTFindingRow {
  id: number
  domain: string
  match_type: string
  detections: { code: string; weight: number; reason: string }[]
  risk_score: number
  severity: string
  status: string
  first_seen_at?: string
  last_seen_at?: string
}

interface UsageResult {
  id: number
  hostname: string
  ip_address: string | null
  port: number
  status: string
  presented_fingerprint: string | null
  presented_subject: string | null
  presented_issuer: string | null
  discovery_source: string
  error_code: string | null
  error_message: string | null
  first_seen_at?: string
  last_seen_at?: string
  last_checked_at?: string
}

interface UsageSummary {
  candidates: number
  confirmed: number
  different_certificate: number
  unreachable: number
  dns_failed: number
  tls_failed: number
  timeout: number
}

interface UsageScan {
  id: number
  status: string
  candidate_count: number
  scanned_count: number
  confirmed_count: number
  different_certificate_count: number
  unreachable_count: number
  error_count: number
  log?: string | null
}

const SCAN_TERMINAL_STATUSES = ['completed', 'failed', 'cancelled']

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

  const [usageStatus, setUsageStatus] = useState('confirmed')
  const [usagePort, setUsagePort] = useState('')
  const [usageSearch, setUsageSearch] = useState('')
  const [usagePage, setUsagePage] = useState(1)
  const [scanDialogOpen, setScanDialogOpen] = useState(false)
  const [scanSources, setScanSources] = useState({ sans: true, inventory: true, network_sightings: true, manual: true })
  const [scanHostnames, setScanHostnames] = useState('')
  const [scanPorts, setScanPorts] = useState<Record<number, boolean>>({ 443: true, 8443: true, 9443: true })
  const [scanTimeout, setScanTimeout] = useState(5)
  const [activeScanId, setActiveScanId] = useState<number | null>(null)

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
  const sightings = useQuery({
    queryKey: ['cert-network-sightings', certId],
    queryFn: () =>
      api.get<NetworkSighting[]>('/discovery/network-sightings', { params: { certificate_id: certId } }).then((r) => r.data),
    enabled: tab === 3,
  })
  const ctFindings = useQuery({
    queryKey: ['cert-ct-findings', certId],
    queryFn: () =>
      api.get<Page<CTFindingRow>>('/findings', { params: { certificate_id: certId, page_size: 50 } }).then((r) => r.data),
    enabled: tab === 4,
  })
  const servers = useQuery({
    queryKey: ['servers-min'],
    queryFn: () => api.get<Page<{ id: number; hostname: string }>>('/servers', { params: { page_size: 500 } }).then((r) => r.data),
    enabled: confirm === 'deploy',
  })
  const usageParams = {
    status: usageStatus || undefined, port: usagePort || undefined,
    search: usageSearch || undefined, page: usagePage, page_size: 25,
  }
  const usage = useQuery({
    queryKey: ['cert-usage', certId, usageParams],
    queryFn: () =>
      api.get<Page<UsageResult> & { summary: UsageSummary }>(`/certificates/${certId}/usage`, { params: usageParams })
        .then((r) => r.data),
    enabled: tab === 5,
  })
  const scanProgress = useQuery({
    queryKey: ['cert-usage-scan', activeScanId],
    queryFn: () => api.get<UsageScan>(`/certificate-usage/scans/${activeScanId}`).then((r) => r.data),
    enabled: activeScanId !== null,
    refetchInterval: (query) => (query.state.data && SCAN_TERMINAL_STATUSES.includes(query.state.data.status) ? false : 2000),
  })
  useEffect(() => {
    if (scanProgress.data && SCAN_TERMINAL_STATUSES.includes(scanProgress.data.status)) {
      // Pull the freshly-finished scan's results into view, then stop polling.
      qc.invalidateQueries({ queryKey: ['cert-usage', certId] })
      setActiveScanId(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanProgress.data?.status])

  const triggerScan = useMutation({
    mutationFn: () => {
      const hostnames = scanHostnames.split('\n').map((h) => h.trim()).filter(Boolean)
      const sources = Object.entries(scanSources).filter(([, v]) => v).map(([k]) => k)
      const ports = Object.entries(scanPorts).filter(([, v]) => v).map(([k]) => Number(k))
      return api.post<{ scan_id?: number; status: string }>(`/certificates/${certId}/usage/scan`, {
        sources, hostnames, ports, timeout: scanTimeout,
      })
    },
    onSuccess: (res) => {
      setScanDialogOpen(false)
      setToast({ message: 'Usage discovery scan started', severity: 'success' })
      if (res.data.scan_id) setActiveScanId(res.data.scan_id)
      qc.invalidateQueries({ queryKey: ['cert-usage', certId] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
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
  const usageEligible = c.is_wildcard || (c.sans?.length ?? 0) > 1

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
            {can('certificate:renew') && c.managed_by_platform && (
              <Button startIcon={<AutorenewIcon />} onClick={() => setConfirm('renew')}>Renew</Button>
            )}
            {can('certificate:deploy') && (
              <Button startIcon={<RocketLaunchIcon />} onClick={() => setConfirm('deploy')}>Deploy</Button>
            )}
            {can('certificate:revoke') && c.managed_by_platform && !DELETABLE_STATUSES.includes(c.status) && (
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
          <Tab label="Seen on network" />
          <Tab label="CT Findings" />
          <Tab label="Usage Discovery" />
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

      {tab === 3 &&
        (sightings.isLoading ? <Loading /> : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell>Port</TableCell>
                  <TableCell>SNI hostname</TableCell>
                  <TableCell>First seen</TableCell>
                  <TableCell>Last seen</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(sightings.data ?? []).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>{s.host}</TableCell>
                    <TableCell>{s.port}</TableCell>
                    <TableCell>{s.sni_hostname ?? '—'}</TableCell>
                    <TableCell>{s.first_seen_at ? new Date(s.first_seen_at).toLocaleString() : '—'}</TableCell>
                    <TableCell>{s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '—'}</TableCell>
                  </TableRow>
                ))}
                {(sightings.data ?? []).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center">
                      Not seen via a network scan — see Discovery → Network scan
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        ))}

      {tab === 4 &&
        (ctFindings.isLoading ? <Loading /> : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Domain</TableCell>
                  <TableCell>Match</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Risk</TableCell>
                  <TableCell>Detections</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Last seen</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(ctFindings.data?.items ?? []).map((f) => (
                  <TableRow key={f.id}>
                    <TableCell>{f.domain}</TableCell>
                    <TableCell>{f.match_type}</TableCell>
                    <TableCell><StatusChip value={f.severity} /></TableCell>
                    <TableCell>{f.risk_score}</TableCell>
                    <TableCell>
                      <Typography variant="caption">{f.detections.map((d) => d.code).join(', ') || '—'}</Typography>
                    </TableCell>
                    <TableCell><StatusChip value={f.status} /></TableCell>
                    <TableCell>{f.last_seen_at ? new Date(f.last_seen_at).toLocaleString() : '—'}</TableCell>
                  </TableRow>
                ))}
                {(ctFindings.data?.items ?? []).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      Not observed via Certificate Transparency — see Discovery → CT Monitoring
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        ))}

      {tab === 5 && (
        !usageEligible ? (
          <Alert severity="info">
            Usage discovery is only available for wildcard (e.g. <code>*.example.com</code>) or
            multi-domain (SAN) certificates — it determines which real endpoints are actually
            presenting <b>this exact</b> certificate, distinct from which hostnames the certificate
            merely covers. A single-domain certificate has only one possible hostname, so there's
            no coverage-vs-usage question to answer.
          </Alert>
        ) : (
          <Box>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    {c.is_wildcard ? 'Wildcard certificate usage' : 'Multi-domain (SAN) certificate usage'}
                  </Typography>
                  {can('certificate:usage_scan') && (
                    <Button variant="contained" onClick={() => setScanDialogOpen(true)} disabled={activeScanId !== null}>
                      Scan Now
                    </Button>
                  )}
                </Box>
                {activeScanId !== null && scanProgress.data && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" sx={{ mb: 0.5 }}>
                      Scan #{scanProgress.data.id} — {scanProgress.data.status.toUpperCase()} —{' '}
                      {scanProgress.data.scanned_count}/{scanProgress.data.candidate_count} scanned
                    </Typography>
                    <LinearProgress
                      variant={scanProgress.data.candidate_count ? 'determinate' : 'indeterminate'}
                      value={scanProgress.data.candidate_count
                        ? (scanProgress.data.scanned_count / scanProgress.data.candidate_count) * 100 : 0}
                    />
                  </Box>
                )}
                <Grid container spacing={2}>
                  {[
                    ['Candidates', usage.data?.summary?.candidates ?? 0, 'text.primary'],
                    ['Confirmed', usage.data?.summary?.confirmed ?? 0, 'success.main'],
                    ['Different', usage.data?.summary?.different_certificate ?? 0, 'warning.main'],
                    ['Unreachable', usage.data?.summary?.unreachable ?? 0, 'error.main'],
                  ].map(([label, value, color]) => (
                    <Grid item xs={6} sm={3} key={label as string}>
                      <Typography variant="caption" color="text.secondary">{label}</Typography>
                      <Typography variant="h5" sx={{ color: color as string }}>{value}</Typography>
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>

            <Paper sx={{ mb: 2, p: 2 }}>
              <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
                <TextField
                  label="Search hostname" size="small" sx={{ minWidth: 220 }}
                  value={usageSearch}
                  onChange={(e) => { setUsageSearch(e.target.value); setUsagePage(1) }}
                />
                <FormControl size="small" sx={{ minWidth: 170 }}>
                  <InputLabel>Status</InputLabel>
                  <Select label="Status" value={usageStatus} onChange={(e) => { setUsageStatus(e.target.value); setUsagePage(1) }}>
                    <MenuItem value="">All</MenuItem>
                    {USAGE_STATUSES.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 130 }}>
                  <InputLabel>Port</InputLabel>
                  <Select label="Port" value={usagePort} onChange={(e) => { setUsagePort(e.target.value); setUsagePage(1) }}>
                    <MenuItem value="">All</MenuItem>
                    {USAGE_PORTS.map((p) => <MenuItem key={p} value={p}>{p}</MenuItem>)}
                  </Select>
                </FormControl>
              </Box>
            </Paper>

            {usage.isLoading ? (
              <Loading />
            ) : (
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Hostname</TableCell>
                      <TableCell>IP</TableCell>
                      <TableCell>Port</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Source</TableCell>
                      <TableCell>Last checked</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(usage.data?.items ?? []).map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>{r.hostname}</TableCell>
                        <TableCell>{r.ip_address ?? '—'}</TableCell>
                        <TableCell>{r.port}</TableCell>
                        <TableCell>
                          <StatusChip value={r.status} />
                          {r.error_message && (
                            <Typography variant="caption" color="text.secondary" display="block">
                              {r.error_message}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>{r.discovery_source}</TableCell>
                        <TableCell>{r.last_checked_at ? new Date(r.last_checked_at).toLocaleString() : '—'}</TableCell>
                      </TableRow>
                    ))}
                    {(usage.data?.items ?? []).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={6} align="center">
                          No usage results yet — click "Scan Now" to discover which endpoints present this certificate
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )
      )}

      <Dialog open={scanDialogOpen} onClose={() => setScanDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Discover certificate usage</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
          <Typography variant="body2" color="text.secondary">
            Certificate: <b>{c.domain}</b>
          </Typography>
          <Box>
            <Typography variant="subtitle2">Discovery sources</Typography>
            {c.sans.length > 1 && (
              <FormControlLabel
                control={<Checkbox checked={scanSources.sans}
                  onChange={(e) => setScanSources((s) => ({ ...s, sans: e.target.checked }))} />}
                label={`This certificate's own SAN list (${c.sans.filter((s) => !s.startsWith('*.')).length})`}
              />
            )}
            <FormControlLabel
              control={<Checkbox checked={scanSources.inventory}
                onChange={(e) => setScanSources((s) => ({ ...s, inventory: e.target.checked }))} />}
              label="Existing CertMgr inventory"
            />
            <FormControlLabel
              control={<Checkbox checked={scanSources.network_sightings}
                onChange={(e) => setScanSources((s) => ({ ...s, network_sightings: e.target.checked }))} />}
              label="Previously seen via network scan"
            />
            <FormControlLabel
              control={<Checkbox checked={scanSources.manual}
                onChange={(e) => setScanSources((s) => ({ ...s, manual: e.target.checked }))} />}
              label="Manual hostnames"
            />
          </Box>
          {scanSources.manual && (
            <TextField
              label="Hostnames (one per line, optionally host:port)"
              multiline minRows={4} fullWidth
              value={scanHostnames}
              onChange={(e) => setScanHostnames(e.target.value)}
              placeholder={'api.example.com\nportal.example.com\nvpn.example.com:8443'}
            />
          )}
          <Box>
            <Typography variant="subtitle2">Ports</Typography>
            {USAGE_PORTS.map((p) => (
              <FormControlLabel
                key={p}
                control={<Checkbox checked={!!scanPorts[p]}
                  onChange={(e) => setScanPorts((s) => ({ ...s, [p]: e.target.checked }))} />}
                label={String(p)}
              />
            ))}
          </Box>
          <TextField
            label="Timeout (seconds)" type="number" size="small"
            value={scanTimeout}
            onChange={(e) => setScanTimeout(Number(e.target.value) || 5)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScanDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => triggerScan.mutate()} disabled={triggerScan.isPending}>
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>

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
