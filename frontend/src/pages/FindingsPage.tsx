import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box,
  FormControl,
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
import { api, apiErrorMessage } from '../lib/api'
import type { Page } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

interface Finding {
  id: number
  certificate_id: number
  domain: string
  match_type: string
  detections: { code: string; weight: number; reason: string }[]
  risk_score: number
  severity: string
  status: string
  resolution_reason: string | null
  assigned_to: number | null
  first_seen_at?: string
  last_seen_at?: string
}

const STATUSES = ['open', 'acknowledged', 'investigating', 'false_positive', 'resolved']
const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical']

export default function FindingsPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [domain, setDomain] = useState('')
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const canManage = can('finding:manage')

  const params = { page, page_size: pageSize, status: status || undefined, severity: severity || undefined,
                   domain: domain || undefined }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.get<Page<Finding>>('/findings', { params }).then((r) => r.data),
  })

  const updateStatus = useMutation({
    mutationFn: ({ id, newStatus }: { id: number; newStatus: string }) =>
      api.patch(`/findings/${id}`, { status: newStatus }),
    onSuccess: () => {
      setToast({ message: 'Finding updated', severity: 'success' })
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  return (
    <Box>
      <PageHeader
        title="Findings"
        subtitle="Certificate Transparency findings — certificates observed for your monitored domains that need review"
      />

      <Paper sx={{ mb: 2, p: 2 }}>
        <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
              <MenuItem value="">All</MenuItem>
              {STATUSES.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select label="Severity" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
              <MenuItem value="">All</MenuItem>
              {SEVERITIES.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
            </Select>
          </FormControl>
          <TextField
            label="Domain" size="small" sx={{ minWidth: 220 }}
            value={domain}
            onChange={(e) => { setDomain(e.target.value); setPage(1) }}
            placeholder="example.com"
          />
        </Box>
      </Paper>

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load findings" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No findings match. Run a CT monitoring scan from the Discovery page to populate this list." />
      ) : (
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
              {data.items.map((f) => (
                <TableRow key={f.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{f.domain}</Typography>
                  </TableCell>
                  <TableCell>{f.match_type}</TableCell>
                  <TableCell><StatusChip value={f.severity} /></TableCell>
                  <TableCell>{f.risk_score}</TableCell>
                  <TableCell>
                    <details>
                      <summary style={{ cursor: 'pointer', fontSize: 12 }}>
                        {f.detections.map((d) => d.code).join(', ') || '—'}
                      </summary>
                      <Box component="ul" sx={{ m: 0, pl: 2, fontSize: 12 }}>
                        {f.detections.map((d, i) => (
                          <li key={i}>+{d.weight} {d.reason}</li>
                        ))}
                      </Box>
                    </details>
                  </TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    {canManage ? (
                      <Select
                        size="small" variant="standard" value={f.status}
                        onChange={(e) => updateStatus.mutate({ id: f.id, newStatus: e.target.value })}
                      >
                        {STATUSES.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
                      </Select>
                    ) : (
                      <StatusChip value={f.status} />
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption">
                      {f.last_seen_at ? new Date(f.last_seen_at).toLocaleString() : '—'}
                    </Typography>
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
            rowsPerPageOptions={[10, 25, 50, 100]}
            onPageChange={(_, p) => setPage(p + 1)}
            onRowsPerPageChange={(e) => { setPageSize(Number(e.target.value)); setPage(1) }}
          />
        </TableContainer>
      )}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
