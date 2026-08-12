import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
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
import { api } from '../lib/api'
import type { AuditEntry, Page } from '../types'
import { EmptyState, ErrorBox, Loading, PageHeader, StatusChip } from '../components/Shared'

export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [username, setUsername] = useState('')
  const [action, setAction] = useState('')
  const [result, setResult] = useState('')

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['audit', page, pageSize, username, action, result],
    queryFn: () =>
      api
        .get<Page<AuditEntry>>('/audit', {
          params: {
            page, page_size: pageSize,
            username: username || undefined,
            action: action || undefined,
            result: result || undefined,
          },
        })
        .then((r) => r.data),
  })

  return (
    <Box>
      <PageHeader title="Audit log" subtitle="Immutable trail of every platform action" />

      <Paper sx={{ p: 2, mb: 2, display: 'flex', gap: 1.5, flexWrap: 'wrap' }}>
        <TextField size="small" label="Username" value={username} onChange={(e) => { setUsername(e.target.value); setPage(1) }} />
        <TextField size="small" label="Action" value={action} onChange={(e) => { setAction(e.target.value); setPage(1) }} />
        <FormControl size="small" sx={{ minWidth: 130 }}>
          <InputLabel>Result</InputLabel>
          <Select label="Result" value={result} onChange={(e) => { setResult(e.target.value); setPage(1) }}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="success">success</MenuItem>
            <MenuItem value="failure">failure</MenuItem>
            <MenuItem value="denied">denied</MenuItem>
          </Select>
        </FormControl>
      </Paper>

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load audit log" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No audit entries match." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>User</TableCell>
                <TableCell>Action</TableCell>
                <TableCell>Resource</TableCell>
                <TableCell>Result</TableCell>
                <TableCell>IP</TableCell>
                <TableCell>Client</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>
                    <Typography variant="caption">
                      {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>{a.username ?? 'system'}</TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{a.action}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption">
                      {a.resource_type ? `${a.resource_type}:${a.resource_id ?? ''}` : '—'}
                    </Typography>
                  </TableCell>
                  <TableCell><StatusChip value={a.result} /></TableCell>
                  <TableCell>{a.ip_address ?? '—'}</TableCell>
                  <TableCell>
                    <Typography variant="caption">{a.browser ?? ''} / {a.device ?? ''}</Typography>
                  </TableCell>
                  <TableCell>{a.duration_ms != null ? `${a.duration_ms}ms` : '—'}</TableCell>
                  <TableCell>
                    <details>
                      <summary style={{ cursor: 'pointer', fontSize: 12 }}>details</summary>
                      <pre style={{ fontSize: 11 }}>{JSON.stringify(a.details, null, 1)}</pre>
                    </details>
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
            rowsPerPageOptions={[25, 50, 100, 250, 500]}
            onPageChange={(_, p) => setPage(p + 1)}
            onRowsPerPageChange={(e) => { setPageSize(Number(e.target.value)); setPage(1) }}
          />
        </TableContainer>
      )}
    </Box>
  )
}
