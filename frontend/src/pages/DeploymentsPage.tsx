import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
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
  Typography,
} from '@mui/material'
import { api } from '../lib/api'
import type { Page } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip } from '../components/Shared'

interface DeploymentRow {
  id: number
  certificate_domain?: string
  server_hostname?: string
  method: string
  target_service?: string
  status: string
  backup_path?: string
  verification: Record<string, unknown>
  started_at?: string
  finished_at?: string
  error_message?: string
}

export default function DeploymentsPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [status, setStatus] = useState('')

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['deployments', page, pageSize, status],
    queryFn: () =>
      api
        .get<Page<DeploymentRow>>('/deployments', { params: { page, page_size: pageSize, status: status || undefined } })
        .then((r) => r.data),
  })

  return (
    <Box>
      <PageHeader
        title="Deployments"
        subtitle="Certificate deployment history with verification and rollback status"
      />
      <Paper sx={{ p: 2, mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel>Status</InputLabel>
          <Select label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
            <MenuItem value="">All</MenuItem>
            {['pending', 'running', 'success', 'failed', 'rolled_back'].map((s) => (
              <MenuItem key={s} value={s}>{s}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Paper>

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load deployments" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No deployments yet — deploy a certificate from its details page." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Certificate</TableCell>
                <TableCell>Server</TableCell>
                <TableCell>Service</TableCell>
                <TableCell>Method</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Backup</TableCell>
                <TableCell>Verification</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Error</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.items.map((d) => (
                <TableRow key={d.id}>
                  <TableCell>#{d.id}</TableCell>
                  <TableCell>{d.certificate_domain}</TableCell>
                  <TableCell>{d.server_hostname}</TableCell>
                  <TableCell>{d.target_service ?? '—'}</TableCell>
                  <TableCell>{d.method}</TableCell>
                  <TableCell><StatusChip value={d.status} /></TableCell>
                  <TableCell>{d.backup_path ? 'yes' : '—'}</TableCell>
                  <TableCell>
                    <Typography variant="caption">
                      {d.verification && 'ok' in d.verification
                        ? d.verification.ok ? 'verified ✓' : `failed: ${String(d.verification.error ?? '')}`
                        : '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>{d.started_at ? new Date(d.started_at).toLocaleString() : '—'}</TableCell>
                  <TableCell>
                    <Typography variant="caption" color="error">{d.error_message}</Typography>
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
    </Box>
  )
}
