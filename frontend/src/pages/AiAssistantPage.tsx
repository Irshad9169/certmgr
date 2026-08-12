import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Box,
  Button,
  Card,
  CardContent,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import SmartToyIcon from '@mui/icons-material/SmartToy'
import { api } from '../lib/api'
import { ErrorBox, Loading, PageHeader } from '../components/Shared'

interface Explanation {
  execution_id: number
  job_type?: string
  category?: string
  cause?: string
  recommendation?: string
  confidence?: number
  raw_tail?: string
  suggestions?: string[]
}

export default function AiAssistantPage() {
  const [executionId, setExecutionId] = useState('')
  const [explanation, setExplanation] = useState<Explanation | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const recurring = useQuery({
    queryKey: ['ai-recurring'],
    queryFn: () => api.get<{ failures: { job_type: string; category: string; count: number; cause: string; recommendation: string; certificate_ids: number[] }[] }>('/ai/recurring-failures').then((r) => r.data),
  })
  const predicted = useQuery({
    queryKey: ['ai-predict'],
    queryFn: () => api.get<{ at_risk: { certificate_id: number; domain: string; days_remaining: number; recent_failures: number; risk: string }[] }>('/ai/predict-renewal-failures').then((r) => r.data),
  })

  const explain = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await api.get<Explanation>(`/ai/explain/${executionId}`)
      setExplanation(res.data)
    } catch (e) {
      setError('Failed to analyze execution — check the ID')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box>
      <PageHeader title="AI Assistant" subtitle="Explain Certbot failures, detect patterns, predict renewal risks" />

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>Explain a failed execution</Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <TextField
              label="Execution ID (from the certificates page)"
              value={executionId}
              onChange={(e) => setExecutionId(e.target.value)}
              sx={{ flex: 1 }}
              type="number"
            />
            <Button variant="contained" startIcon={<SmartToyIcon />} onClick={explain} disabled={!executionId || loading}>
              {loading ? 'Analyzing…' : 'Explain'}
            </Button>
          </Box>
          {error && <Typography color="error" sx={{ mt: 1 }}>{error}</Typography>}
          {explanation && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2">Category</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{explanation.category}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2">Confidence</Typography>
                  <Typography variant="body2">{Math.round((explanation.confidence ?? 0) * 100)}%</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2">Cause</Typography>
                  <Typography variant="body2">{explanation.cause}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2">Recommended fix</Typography>
                  <Typography variant="body2">{explanation.recommendation}</Typography>
                </Grid>
                {explanation.suggestions && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Suggestions</Typography>
                    <ul>
                      {explanation.suggestions.map((s) => (
                        <li key={s}><Typography variant="body2">{s}</Typography></li>
                      ))}
                    </ul>
                  </Grid>
                )}
                {explanation.raw_tail && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Raw output tail</Typography>
                    <pre className="console-output" style={{ marginTop: 6 }}>{explanation.raw_tail}</pre>
                  </Grid>
                )}
              </Grid>
            </Box>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" sx={{ mb: 1 }}>Recurring failures (30d)</Typography>
          {recurring.isLoading ? (
            <Loading />
          ) : recurring.error ? (
            <ErrorBox message="Failed to load recurring failures" />
          ) : (
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Job</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell align="right">Count</TableCell>
                    <TableCell>Cause</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(recurring.data?.failures ?? []).map((f) => (
                    <TableRow key={`${f.job_type}-${f.category}`}>
                      <TableCell>{f.job_type}</TableCell>
                      <TableCell><Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{f.category}</Typography></TableCell>
                      <TableCell align="right">{f.count}</TableCell>
                      <TableCell><Typography variant="caption">{f.cause}</Typography></TableCell>
                    </TableRow>
                  ))}
                  {(recurring.data?.failures ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={4} align="center">No recurring failures detected</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Grid>

        <Grid item xs={12} md={6}>
          <Typography variant="h6" sx={{ mb: 1 }}>Predicted renewal failures</Typography>
          {predicted.isLoading ? (
            <Loading />
          ) : (
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Domain</TableCell>
                    <TableCell align="right">Days left</TableCell>
                    <TableCell align="right">Failures</TableCell>
                    <TableCell>Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(predicted.data?.at_risk ?? []).map((c) => (
                    <TableRow key={c.certificate_id}>
                      <TableCell>{c.domain}</TableCell>
                      <TableCell align="right">{c.days_remaining}</TableCell>
                      <TableCell align="right">{c.recent_failures}</TableCell>
                      <TableCell>
                        <Typography color="error" sx={{ fontWeight: 600, textTransform: 'uppercase', fontSize: 12 }}>
                          {c.risk}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(predicted.data?.at_risk ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={4} align="center">No certificates at risk</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Grid>
      </Grid>
    </Box>
  )
}
