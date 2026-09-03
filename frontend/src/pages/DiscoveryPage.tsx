import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  IconButton,
  Paper,
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
import TravelExploreIcon from '@mui/icons-material/TravelExplore'
import RestoreIcon from '@mui/icons-material/Restore'
import RouterIcon from '@mui/icons-material/Router'
import { api, apiErrorMessage } from '../lib/api'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

interface DiscoveryRun {
  id: number
  status: string
  scan_type: 'filesystem' | 'network'
  scan_paths: string[]
  scan_targets: string[]
  scan_ports: number[]
  found: number
  imported: number
  skipped: number
  log?: string
  started_at?: string
  finished_at?: string
}

interface DiscoveryIgnore {
  id: number
  fingerprint_sha256: string
  domain: string | null
  source_path: string | null
  created_at?: string
}

export default function DiscoveryPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [paths, setPaths] = useState('')
  const [networkTargets, setNetworkTargets] = useState('')
  const [networkPorts, setNetworkPorts] = useState('')
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const canNetworkScan = can('discovery:network_scan')

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['discovery-runs'],
    queryFn: () => api.get<DiscoveryRun[]>('/discovery/runs').then((r) => r.data),
  })

  // Admin-configured default ports (Settings → tls_scan.default_ports) —
  // fetched rather than hardcoded so a changed setting actually reflects
  // here instead of two sources of truth drifting apart.
  const defaultPortsQuery = useQuery({
    queryKey: ['settings-tls-scan-defaults'],
    queryFn: () => api.get<{ settings: { key: string; value: string }[] }>('/settings').then((r) => r.data),
    enabled: canNetworkScan,
  })
  const defaultPorts = defaultPortsQuery.data?.settings.find((s) => s.key === 'tls_scan.default_ports')?.value

  useEffect(() => {
    // Pre-fill once on first load, without overwriting further user edits.
    if (defaultPorts && !networkPorts) setNetworkPorts(defaultPorts)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultPorts])

  const { data: ignored } = useQuery({
    queryKey: ['discovery-ignored'],
    queryFn: () => api.get<DiscoveryIgnore[]>('/discovery/ignored').then((r) => r.data),
  })

  const unignore = useMutation({
    mutationFn: (id: number) => api.delete(`/discovery/ignored/${id}`),
    onSuccess: () => {
      setToast({ message: 'Removed from ignore list — the next scan may re-import it', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['discovery-ignored'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const run = useMutation({
    mutationFn: () =>
      api.post('/discovery/run', paths ? { paths: paths.split(',').map((p) => p.trim()).filter(Boolean) } : {}),
    onSuccess: () => {
      setToast({ message: 'Discovery run triggered', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['discovery-runs'] })
      setTimeout(() => qc.invalidateQueries({ queryKey: ['discovery-runs'] }), 5000)
      setTimeout(() => qc.invalidateQueries({ queryKey: ['discovery-runs'] }), 15000)
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const networkScan = useMutation({
    mutationFn: () =>
      api.post('/discovery/network-scan', {
        targets: networkTargets.split(/[,\n]/).map((t) => t.trim()).filter(Boolean),
        ports: networkPorts
          ? networkPorts.split(',').map((p) => Number(p.trim())).filter((p) => !Number.isNaN(p))
          : undefined,
      }),
    onSuccess: () => {
      setToast({ message: 'Network scan triggered', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['discovery-runs'] })
      setTimeout(() => qc.invalidateQueries({ queryKey: ['discovery-runs'] }), 5000)
      setTimeout(() => qc.invalidateQueries({ queryKey: ['discovery-runs'] }), 15000)
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  return (
    <Box>
      <PageHeader
        title="Certificate discovery"
        subtitle="Scan filesystem paths and automatically import newly discovered certificates"
        actions={
          can('discovery:run') && (
            <Button variant="contained" startIcon={<TravelExploreIcon />} onClick={() => run.mutate()} disabled={run.isPending}>
              {run.isPending ? 'Scanning…' : 'Run discovery'}
            </Button>
          )
        }
      />

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle2" gutterBottom>
            Extra scan paths (optional, comma-separated) — defaults: /etc/letsencrypt/live, /etc/pki/tls/certs, /etc/nginx…
          </Typography>
          <TextField
            fullWidth
            size="small"
            value={paths}
            onChange={(e) => setPaths(e.target.value)}
            placeholder="/etc/letsencrypt/live,/custom/certs"
          />
        </CardContent>
      </Card>

      {canNetworkScan && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Typography variant="subtitle2" gutterBottom>
              Network scan — find TLS certificates served live at an IP/hostname/CIDR range,
              regardless of trust (self-signed, expired and internal-CA certs are found too).
              A network-found certificate has no private key CertMgr can extract, so it's
              read-only inventory (not renewable/deployable) unless separately imported.
            </Typography>
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid item xs={12} md={8}>
                <TextField
                  fullWidth
                  size="small"
                  multiline
                  minRows={2}
                  label="Targets (IPs, hostnames, or CIDR ranges — comma or newline separated)"
                  value={networkTargets}
                  onChange={(e) => setNetworkTargets(e.target.value)}
                  placeholder={'10.0.0.0/24\nfront-end01.example.com'}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  size="small"
                  label="Ports (comma-separated)"
                  value={networkPorts}
                  onChange={(e) => setNetworkPorts(e.target.value)}
                  placeholder="443,8443,636,465"
                />
              </Grid>
            </Grid>
            <Button
              sx={{ mt: 1.5 }}
              variant="contained"
              startIcon={<RouterIcon />}
              onClick={() => networkScan.mutate()}
              disabled={networkScan.isPending || !networkTargets.trim()}
            >
              {networkScan.isPending ? 'Scanning…' : 'Run network scan'}
            </Button>
          </CardContent>
        </Card>
      )}

      {ignored && ignored.length > 0 && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Typography variant="subtitle2" gutterBottom>
              Ignored certificates ({ignored.length}) — deleted from tracking; future scans skip these
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Domain</TableCell>
                    <TableCell>Source path</TableCell>
                    <TableCell>Ignored</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ignored.map((i) => (
                    <TableRow key={i.id}>
                      <TableCell>{i.domain ?? '—'}</TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{i.source_path ?? '—'}</Typography>
                      </TableCell>
                      <TableCell>{i.created_at ? new Date(i.created_at).toLocaleString() : '—'}</TableCell>
                      <TableCell align="right">
                        {can('discovery:run') && (
                          <Tooltip title="Un-ignore — the next scan may re-import it">
                            <IconButton size="small" onClick={() => unignore.mutate(i.id)}>
                              <RestoreIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load discovery runs" onRetry={() => refetch()} />
      ) : !data || data.length === 0 ? (
        <EmptyState text="No discovery runs yet. Trigger one to scan configured paths." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Run</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Paths / Targets</TableCell>
                <TableCell>Found</TableCell>
                <TableCell>Imported</TableCell>
                <TableCell>Skipped</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Log</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>#{r.id}</TableCell>
                  <TableCell>
                    <Chip size="small" variant="outlined" color={r.scan_type === 'network' ? 'primary' : 'default'}
                         label={r.scan_type === 'network' ? 'Network' : 'Filesystem'} />
                  </TableCell>
                  <TableCell><StatusChip value={r.status} /></TableCell>
                  <TableCell>
                    <Typography variant="caption">
                      {r.scan_type === 'network'
                        ? `${(r.scan_targets ?? []).join(', ')} : ${(r.scan_ports ?? []).join(',')}`
                        : r.scan_paths.join(', ')}
                    </Typography>
                  </TableCell>
                  <TableCell>{r.found}</TableCell>
                  <TableCell>{r.imported}</TableCell>
                  <TableCell>{r.skipped}</TableCell>
                  <TableCell>{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</TableCell>
                  <TableCell>
                    <details>
                      <summary style={{ cursor: 'pointer', fontSize: 12 }}>view log</summary>
                      <pre className="console-output" style={{ marginTop: 6 }}>{r.log}</pre>
                    </details>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
