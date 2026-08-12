import { Box, Button, Card, CardContent, Grid, Typography } from '@mui/material'
import DescriptionIcon from '@mui/icons-material/Description'
import { useState } from 'react'
import { apiErrorMessage, downloadFile } from '../lib/api'
import { PageHeader, Toast } from '../components/Shared'

const REPORTS: { type: string; title: string; description: string }[] = [
  { type: 'inventory', title: 'Certificate inventory', description: 'All certificates with full metadata' },
  { type: 'expiry', title: 'Expiry report', description: 'Certificates sorted by expiration date' },
  { type: 'renewal_history', title: 'Renewal history', description: 'Every renewal attempt with outcome' },
  { type: 'deployment_history', title: 'Deployment history', description: 'Every deployment run and result' },
  { type: 'failures', title: 'Failures', description: 'All failed jobs with errors' },
  { type: 'audit', title: 'Audit log', description: 'All audited actions' },
]

const FORMATS = ['csv', 'xlsx', 'pdf', 'json'] as const

export default function ReportsPage() {
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const generate = (type: string, fmt: string) => {
    downloadFile(`/reports/${type}.${fmt}`, {}, `${type}.${fmt}`)
      .then(() => setToast({ message: `Downloaded ${type}.${fmt}`, severity: 'success' }))
      .catch((e) => setToast({ message: apiErrorMessage(e), severity: 'error' }))
  }

  return (
    <Box>
      <PageHeader title="Reports" subtitle="Export inventory, expiry, history, failures and audit as CSV, XLSX, PDF or JSON" />

      <Grid container spacing={2}>
        {REPORTS.map((r) => (
          <Grid item xs={12} sm={6} md={4} key={r.type}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <DescriptionIcon color="primary" />
                  <Typography variant="h6">{r.title}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 40 }}>
                  {r.description}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {FORMATS.map((fmt) => (
                    <Button key={fmt} size="small" variant="outlined" onClick={() => generate(r.type, fmt)}>
                      {fmt.toUpperCase()}
                    </Button>
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
