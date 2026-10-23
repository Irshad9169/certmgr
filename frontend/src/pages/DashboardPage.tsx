import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Box, Card, CardContent, FormControl, Grid, MenuItem, Select, Typography } from '@mui/material'
import type { SelectChangeEvent } from '@mui/material'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import WarningIcon from '@mui/icons-material/Warning'
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline'
import BlockIcon from '@mui/icons-material/Block'
import FileUploadIcon from '@mui/icons-material/FileUpload'
import SyncProblemIcon from '@mui/icons-material/SyncProblem'
import AutorenewIcon from '@mui/icons-material/Autorenew'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ReTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '../lib/api'
import type { DashboardStats } from '../types'
import { Loading, ErrorBox, PageHeader, StatCard } from '../components/Shared'

const PIE_COLORS = ['#1e3a5f', '#4dabf7', '#51cf66', '#ffa94d', '#ff6b6b', '#9775fa', '#f783ac']

const EXPIRING_WINDOWS = [
  { value: 7, label: '7 days' },
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
] as const

export default function DashboardPage() {
  const navigate = useNavigate()
  const [expiringWindow, setExpiringWindow] = useState<7 | 30 | 60>(30)
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/dashboard/stats').then((r) => r.data),
  })
  const monthly = useQuery({
    queryKey: ['dashboard-monthly'],
    queryFn: () => api.get<{ month: string; issued: number; renewed: number }[]>('/dashboard/monthly-issuance?months=12').then((r) => r.data),
  })

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorBox message="Failed to load dashboard" onRetry={() => navigate(0)} />

  const t = data.totals
  const pieData = Object.entries(data.by_status ?? {}).map(([name, value]) => ({ name, value }))
  const expiringValue = { 7: t.expiring_7, 30: t.expiring_30, 60: t.expiring_60 }[expiringWindow]

  return (
    <Box>
      <PageHeader title="Dashboard" subtitle="Certificate estate overview and trends" />

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard label="Total certificates" value={t.total} icon={<VerifiedUserIcon fontSize="large" />} onClick={() => navigate('/certificates')} />
        </Grid>
        <Grid item xs={6} sm={3} md={2.4}>
          <StatCard label="Active" value={t.active} icon={<VerifiedUserIcon />} color="success" onClick={() => navigate('/certificates?status=active')} />
        </Grid>
        <Grid item xs={6} sm={3} md={2.4}>
          <Box
            onClick={() => navigate('/certificates?status=expiring')}
            sx={{
              bgcolor: 'background.paper',
              border: 1,
              borderColor: 'divider',
              borderRadius: 3,
              p: 2.5,
              display: 'flex',
              alignItems: 'center',
              gap: 2,
              cursor: 'pointer',
              '&:hover': { borderColor: 'primary.main' },
            }}
          >
            <Box sx={{ color: 'warning.main', display: 'flex' }}>
              <WarningIcon fontSize="large" />
            </Box>
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h4" sx={{ lineHeight: 1.1 }}>
                {expiringValue}
              </Typography>
              <FormControl size="small" variant="standard" onClick={(e) => e.stopPropagation()}>
                <Select
                  value={expiringWindow}
                  onChange={(e: SelectChangeEvent<number>) => setExpiringWindow(Number(e.target.value) as 7 | 30 | 60)}
                  disableUnderline
                  sx={{ fontSize: '0.875rem', color: 'text.secondary' }}
                >
                  {EXPIRING_WINDOWS.map((w) => (
                    <MenuItem key={w.value} value={w.value}>
                      Expiring in {w.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>
          </Box>
        </Grid>
        <Grid item xs={6} sm={3} md={2.4}>
          <StatCard label="Expired" value={t.expired} icon={<ErrorOutlineIcon />} color="error" onClick={() => navigate('/certificates?status=expired')} />
        </Grid>
        <Grid item xs={6} sm={3} md={2.4}>
          <StatCard label="Renewing" value={t.renewing} icon={<AutorenewIcon />} color="info" onClick={() => navigate('/certificates?status=renewing')} />
        </Grid>
      </Grid>

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} sm={3} md={2}>
          <StatCard label="Failures 7d" value={t.failures_7d} icon={<SyncProblemIcon />} color="error" />
        </Grid>
        <Grid item xs={6} sm={3} md={2}>
          <StatCard label="Revoked" value={t.revoked} icon={<BlockIcon />} color="error" />
        </Grid>
        <Grid item xs={6} sm={3} md={2}>
          <StatCard label="Imported" value={t.imported} icon={<FileUploadIcon />} color="info" />
        </Grid>
      </Grid>

      <Grid container spacing={2}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Monthly issuance &amp; renewals
              </Typography>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={monthly.data ?? []}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="month" tick={{ fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                  <ReTooltip />
                  <Legend />
                  <Bar dataKey="issued" fill="#1e3a5f" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="renewed" fill="#4dabf7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Status distribution
              </Typography>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95} label={(e) => e.name}>
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <ReTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Certificates by environment
              </Typography>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={Object.entries(data.by_environment ?? {}).map(([name, value]) => ({ name, value }))}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                  <ReTooltip />
                  <Bar dataKey="value" fill="#51cf66" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Certificates by provider
              </Typography>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={Object.entries(data.by_provider ?? {}).map(([name, value]) => ({ name, value }))}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                  <ReTooltip />
                  <Line type="monotone" dataKey="value" stroke="#f08c00" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  )
}
