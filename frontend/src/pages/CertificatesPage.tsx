import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Button,
  Checkbox,
  Chip,
  FormControl,
  IconButton,
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
  TableSortLabel,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import RefreshIcon from '@mui/icons-material/Refresh'
import AutorenewIcon from '@mui/icons-material/Autorenew'
import BlockIcon from '@mui/icons-material/Block'
import StarIcon from '@mui/icons-material/Star'
import StarBorderIcon from '@mui/icons-material/StarBorder'
import DeleteForeverIcon from '@mui/icons-material/DeleteForever'
import { api, apiErrorMessage } from '../lib/api'
import type { Certificate, Page } from '../types'
import { ConfirmDialog, EmptyState, ErrorBox, Loading, PageHeader, StatusChip, Toast, daysColor } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

/** Friendly issuer label for the compact list view — prefers the CA's
 * organization name (e.g. "Let's Encrypt") or common name over the raw DN
 * string; the full DN is still available via the cell's tooltip. */
function issuerLabel(issuer?: string | null): string {
  if (!issuer) return '—'
  const attrs: Record<string, string> = {}
  for (const part of issuer.split(',')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    attrs[part.slice(0, eq).trim()] = part.slice(eq + 1).trim()
  }
  return attrs.organizationName || attrs.commonName || issuer
}

interface Filters {
  search: string
  status: string
  environment: string
  provider: string
  key_type: string
  auto_renew: string
}

export default function CertificatesPage() {
  const navigate = useNavigate()
  const { can } = useAuth()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [sortBy, setSortBy] = useState('valid_until')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [filters, setFilters] = useState<Filters>({
    search: '', status: '', environment: '', provider: '', key_type: '', auto_renew: '',
  })
  const [selected, setSelected] = useState<number[]>([])
  const [bulkAction, setBulkAction] = useState<null | 'renew' | 'revoke' | 'delete'>(null)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const params = useMemo(() => ({
    page, page_size: pageSize, sort_by: sortBy, sort_dir: sortDir,
    search: filters.search || undefined,
    status: filters.status || undefined,
    environment: filters.environment || undefined,
    provider: filters.provider || undefined,
    key_type: filters.key_type || undefined,
    auto_renew: filters.auto_renew || undefined,
  }), [page, pageSize, sortBy, sortDir, filters])

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['certificates', params],
    queryFn: () => api.get<Page<Certificate>>('/certificates', { params }).then((r) => r.data),
  })

  const bulkMutation = useMutation({
    mutationFn: (action: 'renew' | 'revoke' | 'delete') =>
      api.post<{ queued: number; failed: number }>('/certificates/bulk', {
        action, ids: selected, options: action === 'revoke' ? { reason: 'superseded' } : {},
      }),
    onSuccess: (res) => {
      const { queued, failed } = res.data
      // The endpoint always returns 200 even when every item failed — it
      // reports outcomes in the body, not via HTTP status — so this must be
      // read explicitly rather than treating a 200 response as success.
      setToast(
        failed > 0
          ? { message: `Bulk ${bulkAction}: ${queued} succeeded, ${failed} failed (check a certificate's execution history or the server logs for why)`, severity: queued > 0 ? 'success' : 'error' }
          : { message: `Bulk ${bulkAction} queued for ${queued} certificate(s)`, severity: 'success' }
      )
      setSelected([])
      qc.invalidateQueries({ queryKey: ['certificates'] })
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const favoriteMutation = useMutation({
    mutationFn: (cert: Certificate) => api.post(`/certificates/${cert.id}/favorite`, { favorite: !cert.favorite }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certificates'] }),
  })

  const toggleSelect = (id: number) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))

  const onSort = (col: string) => {
    if (sortBy === col) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortBy(col)
      setSortDir('asc')
    }
  }

  return (
    <Box>
      <PageHeader
        title="Certificates"
        subtitle={`${data?.total ?? 0} certificates managed by the platform`}
        actions={
          <>
            {can('certificate:bulk') && selected.length > 0 && (
              <>
                <Button startIcon={<AutorenewIcon />} onClick={() => setBulkAction('renew')}>
                  Renew ({selected.length})
                </Button>
                <Button color="error" startIcon={<BlockIcon />} onClick={() => setBulkAction('revoke')}>
                  Revoke ({selected.length})
                </Button>
              </>
            )}
            {can('certificate:delete') && selected.length > 0 && (
              <Button color="error" startIcon={<DeleteForeverIcon />} onClick={() => setBulkAction('delete')}>
                Delete ({selected.length})
              </Button>
            )}
            <Button startIcon={<RefreshIcon />} onClick={() => refetch()} disabled={isFetching}>
              Refresh
            </Button>
          </>
        }
      />

      <Paper sx={{ mb: 2, p: 2 }}>
        <Toolbar disableGutters sx={{ gap: 1.5, flexWrap: 'wrap' }}>
          <TextField
            label="Search"
            size="small"
            sx={{ minWidth: 260 }}
            value={filters.search}
            onChange={(e) => {
              setFilters((f) => ({ ...f, search: e.target.value }))
              setPage(1)
            }}
            placeholder="domain, issuer, fingerprint…"
          />
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel>Status</InputLabel>
            <Select
              label="Status"
              value={filters.status}
              onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              {['active', 'expiring', 'expired', 'revoked', 'failed', 'issuing'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel>Env</InputLabel>
            <Select
              label="Env"
              value={filters.environment}
              onChange={(e) => setFilters((f) => ({ ...f, environment: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              {['production', 'development', 'testing', 'staging', 'dr'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel>Provider</InputLabel>
            <Select
              label="Provider"
              value={filters.provider}
              onChange={(e) => setFilters((f) => ({ ...f, provider: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              {['letsencrypt', 'openssl-ca', 'imported'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel>Key type</InputLabel>
            <Select
              label="Key type"
              value={filters.key_type}
              onChange={(e) => setFilters((f) => ({ ...f, key_type: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              {['rsa', 'ecdsa', 'ed25519'].map((s) => (
                <MenuItem key={s} value={s}>{s}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Auto renew</InputLabel>
            <Select
              label="Auto renew"
              value={filters.auto_renew}
              onChange={(e) => setFilters((f) => ({ ...f, auto_renew: e.target.value }))}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="true">Enabled</MenuItem>
              <MenuItem value="false">Disabled</MenuItem>
            </Select>
          </FormControl>
        </Toolbar>
      </Paper>

      {isLoading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message="Failed to load certificates" onRetry={() => refetch()} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState text="No certificates match. Issue your first certificate from the wizard." />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={selected.length > 0 && selected.length < data.items.length}
                    checked={data.items.length > 0 && data.items.every((c) => selected.includes(c.id))}
                    onChange={(e) => setSelected(e.target.checked ? data.items.map((c) => c.id) : [])}
                  />
                </TableCell>
                <TableCell sortDirection={sortBy === 'domain' ? sortDir : false}>
                  <TableSortLabel active={sortBy === 'domain'} direction={sortBy === 'domain' ? sortDir : 'asc'} onClick={() => onSort('domain')}>
                    Domain
                  </TableSortLabel>
                </TableCell>
                <TableCell>SANs</TableCell>
                <TableCell>Issuer</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Key</TableCell>
                <TableCell sortDirection={sortBy === 'valid_until' ? sortDir : false}>
                  <TableSortLabel active={sortBy === 'valid_until'} direction={sortBy === 'valid_until' ? sortDir : 'asc'} onClick={() => onSort('valid_until')}>
                    Expires
                  </TableSortLabel>
                </TableCell>
                <TableCell>Days</TableCell>
                <TableCell>Renewal</TableCell>
                <TableCell>Tags</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {data.items.map((cert) => (
                <TableRow
                  key={cert.id}
                  hover
                  onClick={() => navigate(`/certificates/${cert.id}`)}
                  sx={{ cursor: 'pointer' }}
                  selected={selected.includes(cert.id)}
                >
                  <TableCell padding="checkbox" onClick={(e) => e.stopPropagation()}>
                    <Checkbox checked={selected.includes(cert.id)} onChange={() => toggleSelect(cert.id)} />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {cert.domain}
                    </Typography>
                    {cert.is_wildcard && <Chip size="small" label="wildcard" color="secondary" sx={{ mt: 0.5 }} />}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {cert.sans.join(', ')}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Tooltip title={cert.issuer ?? ''}>
                      <Typography variant="caption" sx={{ display: 'block', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {issuerLabel(cert.issuer)}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Chip size="small" variant="outlined" label={cert.environment} />
                  </TableCell>
                  <TableCell>
                    <StatusChip value={cert.status} />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption">{cert.key_type}{cert.key_size ? `-${cert.key_size}` : ''}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption">{cert.valid_until ? new Date(cert.valid_until).toLocaleDateString() : '—'}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ color: daysColor(cert.days_remaining), fontWeight: 600 }}>
                      {cert.days_remaining ?? '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <StatusChip value={cert.renewal_status} />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.4, flexWrap: 'wrap', maxWidth: 140 }}>
                      {cert.tags.slice(0, 3).map((t) => (
                        <Chip key={t} size="small" variant="outlined" label={t} sx={{ fontSize: 10 }} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <IconButton size="small" onClick={() => favoriteMutation.mutate(cert)}>
                      {cert.favorite ? <StarIcon color="warning" fontSize="small" /> : <StarBorderIcon fontSize="small" />}
                    </IconButton>
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
            rowsPerPageOptions={[10, 25, 50, 100, 250]}
            onPageChange={(_, p) => setPage(p + 1)}
            onRowsPerPageChange={(e) => {
              setPageSize(Number(e.target.value))
              setPage(1)
            }}
          />
        </TableContainer>
      )}

      <ConfirmDialog
        open={bulkAction === 'renew'}
        title={`Renew ${selected.length} certificate(s)?`}
        body="A renewal will be scheduled for each selected certificate."
        confirmLabel="Renew"
        onConfirm={() => bulkMutation.mutate('renew')}
        onClose={() => setBulkAction(null)}
      />
      <ConfirmDialog
        open={bulkAction === 'revoke'}
        title={`Revoke ${selected.length} certificate(s)?`}
        body="Revocation is immediate and irreversible. Deployed services will keep serving until the next reload."
        confirmLabel="Revoke"
        danger
        onConfirm={() => bulkMutation.mutate('revoke')}
        onClose={() => setBulkAction(null)}
      />
      <ConfirmDialog
        open={bulkAction === 'delete'}
        title={`Permanently delete ${selected.length} certificate(s)?`}
        body="Removes the certificate record and material (if any) entirely — immediate and irreversible. Only failed, revoked, or archived certificates can be deleted; any active/in-progress ones selected will be skipped and reported as failed."
        confirmLabel="Delete"
        danger
        onConfirm={() => bulkMutation.mutate('delete')}
        onClose={() => setBulkAction(null)}
      />
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
