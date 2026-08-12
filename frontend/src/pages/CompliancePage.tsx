import { useQuery } from '@tanstack/react-query'
import {
  Box,
  Card,
  CardContent,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'
import { api } from '../lib/api'
import { ErrorBox, Loading, PageHeader, StatCard } from '../components/Shared'
import FactCheckIcon from '@mui/icons-material/FactCheck'

interface ComplianceData {
  total: number
  compliant: number
  non_compliant: number
  compliance_rate: number
  issue_counts: Record<string, number>
  duplicates: { fingerprint: string; count: number }[]
  unused: { id: number; domain: string }[]
}

export default function CompliancePage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['compliance'],
    queryFn: () => api.get<ComplianceData>('/compliance/dashboard').then((r) => r.data),
  })

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorBox message="Failed to load compliance data" onRetry={() => refetch()} />

  return (
    <Box>
      <PageHeader title="Compliance" subtitle="Security compliance: key strength, signatures, lifetime, duplicates" />

      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(4, 1fr)' }, mb: 3 }}>
        <StatCard label="Total evaluated" value={data.total} icon={<FactCheckIcon fontSize="large" />} />
        <StatCard label="Compliant" value={data.compliant} color="success" />
        <StatCard label="Non-compliant" value={data.non_compliant} color="error" />
        <StatCard label="Compliance rate" value={`${data.compliance_rate}%`} color={data.compliance_rate >= 90 ? 'success' : 'warning'} />
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>Overall score</Typography>
          <LinearProgress variant="determinate" value={data.compliance_rate} color={data.compliance_rate >= 90 ? 'success' : 'warning'} sx={{ height: 10, borderRadius: 5 }} />
        </CardContent>
      </Card>

      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' } }}>
        <Card>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>Issue distribution</Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Issue</TableCell>
                    <TableCell align="right">Count</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {Object.entries(data.issue_counts ?? {}).map(([issue, count]) => (
                    <TableRow key={issue}>
                      <TableCell>{issue}</TableCell>
                      <TableCell align="right">{count}</TableCell>
                    </TableRow>
                  ))}
                  {Object.keys(data.issue_counts ?? {}).length === 0 && (
                    <TableRow><TableCell colSpan={2} align="center">No issues found 🎉</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>Duplicates ({data.duplicates?.length ?? 0})</Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Fingerprint</TableCell>
                    <TableCell align="right">Count</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(data.duplicates ?? []).map((d) => (
                    <TableRow key={d.fingerprint}>
                      <TableCell><Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{d.fingerprint}</Typography></TableCell>
                      <TableCell align="right">{d.count}</TableCell>
                    </TableRow>
                  ))}
                  {(data.duplicates ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={2} align="center">No duplicates</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <Typography variant="h6" sx={{ mt: 3, mb: 1 }}>Unused certificates ({data.unused?.length ?? 0})</Typography>
            <Typography variant="caption" color="text.secondary">
              Active certificates expiring &gt;90 days with no deployments — candidates for cleanup.
            </Typography>
          </CardContent>
        </Card>
      </Box>
    </Box>
  )
}
