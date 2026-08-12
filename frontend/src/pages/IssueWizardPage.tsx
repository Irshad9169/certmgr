import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Button,
  Checkbox,
  Chip,
  FormControl,
  FormControlLabel,
  FormHelperText,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Step,
  StepLabel,
  Stepper,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { api, apiErrorMessage } from '../lib/api'
import type { Hook, IssuePayload, ProviderInfo } from '../types'
import { PageHeader, Toast } from '../components/Shared'

const STEPS = ['Type', 'Domains', 'Validation', 'Key type', 'Hooks', 'Review', 'Issue']

const VALIDATION_LABELS: Record<string, string> = {
  'http-01': 'HTTP-01 (port 80 challenge)',
  'dns-01': 'DNS-01 (TXT record challenge)',
  'manual-http': 'Manual HTTP',
  'manual-dns': 'Manual DNS',
  standalone: 'Standalone (bind port 80)',
  webroot: 'Webroot',
  custom: 'Custom auth/cleanup hooks',
}

export default function IssueWizardPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [step, setStep] = useState(0)
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const [payload, setPayload] = useState<IssuePayload>({
    domains: [],
    email: '',
    provider: 'letsencrypt',
    validation_method: 'http-01',
    key_type: 'rsa2048',
    environment: 'production',
    staging: false,
    dry_run: false,
    auto_renew: true,
    tags: [],
    auth_hook_id: null,
    cleanup_hook_id: null,
    hook_env: {},
    webroot_path: '',
  })

  const [domainInput, setDomainInput] = useState('')
  const [tagInput, setTagInput] = useState('')
  const [consoleText, setConsoleText] = useState('')

  const providers = useQuery({
    queryKey: ['providers'],
    queryFn: () => api.get<ProviderInfo[]>('/providers').then((r) => r.data),
  })
  const hooks = useQuery({
    queryKey: ['hooks'],
    queryFn: () => api.get<Hook[]>('/hooks').then((r) => r.data),
  })

  const addDomain = () => {
    const d = domainInput.trim().toLowerCase()
    if (d && !payload.domains.includes(d)) {
      setPayload((p) => ({ ...p, domains: [...p.domains, d] }))
      setDomainInput('')
    }
  }

  const addTag = () => {
    const t = tagInput.trim()
    if (t && !payload.tags.includes(t)) {
      setPayload((p) => ({ ...p, tags: [...p.tags, t] }))
      setTagInput('')
    }
  }

  const issue = useMutation({
    mutationFn: () =>
      api.post<{ certificate_id: number; status: string; execution?: { id: number } | null }>(
        '/certificates/issue', payload,
      ),
    onSuccess: async (res) => {
      const body = res.data
      setToast({ message: `Issuance ${body.status} — certificate #${body.certificate_id}`, severity: body.status === 'failed' ? 'error' : 'success' })
      if (body.status === 'queued' || body.status === 'issuing' || body.status === 'active' || body.status === 'failed') {
        setStep(6)
        if (body.execution?.id) {
          void fetchExecutionLogs(body.execution.id)
        }
      }
      if (body.status === 'active') {
        qc.invalidateQueries({ queryKey: ['certificates'] })
        setTimeout(() => navigate(`/certificates/${body.certificate_id}`), 1500)
      }
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const fetchExecutionLogs = async (id: number) => {
    try {
      const res = await api.get(`/jobs/${id}`)
      const e = res.data
      const text = `[stdout]\n${e.stdout ?? ''}\n\n[stderr]\n${e.stderr ?? ''}`
      setConsoleText(text)
      if (e.status === 'running' || e.status === 'queued') {
        setTimeout(() => fetchExecutionLogs(id), 2500)
      }
    } catch {
      /* polling best-effort */
    }
  }

  const canNext = (): boolean => {
    switch (step) {
      case 0:
        return true
      case 1:
        return payload.domains.length > 0
      case 2:
        return payload.validation_method !== 'webroot' || Boolean(payload.webroot_path)
      case 3:
        return true
      case 4:
        return true
      default:
        return true
    }
  }

  return (
    <Box>
      <PageHeader title="Issue certificate" subtitle="Step-by-step wizard with live Certbot console" />
      <Paper sx={{ p: 3 }}>
        <Stepper activeStep={step} alternativeLabel sx={{ mb: 4 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {step === 0 && (
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Certificate type</InputLabel>
                <Select
                  label="Certificate type"
                  value={payload.domains.length > 1 ? 'multi' : payload.domains.some((d) => d.startsWith('*.')) ? 'wildcard' : payload.provider === 'openssl-ca' ? 'internal' : 'single'}
                  onChange={(e) => {
                    const v = e.target.value
                    if (v === 'wildcard' && !payload.domains.some((d) => d.startsWith('*.'))) {
                      setPayload((p) => ({ ...p, domains: ['*.' + (p.domains[0]?.replace('*.', '') || 'example.com')] }))
                    }
                  }}
                >
                  <MenuItem value="single">Single domain</MenuItem>
                  <MenuItem value="multi">Multi domain (SAN)</MenuItem>
                  <MenuItem value="wildcard">Wildcard</MenuItem>
                  <MenuItem value="internal">Internal (OpenSSL CA)</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Provider</InputLabel>
                <Select
                  label="Provider"
                  value={payload.provider}
                  onChange={(e) => setPayload((p) => ({ ...p, provider: e.target.value as string }))}
                >
                  {(providers.data ?? []).map((pr) => (
                    <MenuItem key={pr.key} value={pr.key}>{pr.display_name}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        )}

        {step === 1 && (
          <Box>
            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <TextField
                label="Domain (e.g. example.com or *.example.com)"
                fullWidth
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addDomain())}
              />
              <Button variant="outlined" onClick={addDomain}>Add</Button>
            </Box>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              {payload.domains.map((d) => (
                <Chip
                  key={d}
                  label={d}
                  color={d.startsWith('*.') ? 'secondary' : 'default'}
                  onDelete={() => setPayload((p) => ({ ...p, domains: p.domains.filter((x) => x !== d) }))}
                />
              ))}
            </Box>
            <FormHelperText>
              The first domain becomes the certificate name. Wildcards require DNS-01 or custom hooks.
            </FormHelperText>
          </Box>
        )}

        {step === 2 && (
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Validation method</InputLabel>
                <Select
                  label="Validation method"
                  value={payload.validation_method}
                  onChange={(e) => setPayload((p) => ({ ...p, validation_method: e.target.value as string }))}
                >
                  {Object.entries(VALIDATION_LABELS).map(([k, v]) => (
                    <MenuItem key={k} value={k}>{v}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            {payload.validation_method === 'webroot' && (
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Webroot path"
                  fullWidth
                  value={payload.webroot_path}
                  onChange={(e) => setPayload((p) => ({ ...p, webroot_path: e.target.value }))}
                  placeholder="/var/www/html"
                />
              </Grid>
            )}
            {payload.validation_method === 'standalone' && (
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Standalone port"
                  type="number"
                  fullWidth
                  value={payload.standalone_port ?? 80}
                  onChange={(e) => setPayload((p) => ({ ...p, standalone_port: Number(e.target.value) }))}
                />
              </Grid>
            )}
            <Grid item xs={12}>
              <FormControlLabel
                control={<Switch checked={payload.staging} onChange={(e) => setPayload((p) => ({ ...p, staging: e.target.checked }))} />}
                label="Staging (Let's Encrypt staging environment)"
              />
              <FormControlLabel
                control={<Switch checked={payload.dry_run} onChange={(e) => setPayload((p) => ({ ...p, dry_run: e.target.checked }))} />}
                label="Dry run (test without persisting)"
              />
            </Grid>
          </Grid>
        )}

        {step === 3 && (
          <FormControl fullWidth sx={{ maxWidth: 360 }}>
            <InputLabel>Key type</InputLabel>
            <Select
              label="Key type"
              value={payload.key_type}
              onChange={(e) => setPayload((p) => ({ ...p, key_type: e.target.value as string }))}
            >
              <MenuItem value="rsa2048">RSA 2048</MenuItem>
              <MenuItem value="rsa4096">RSA 4096</MenuItem>
              <MenuItem value="ecdsa_p256">ECDSA P-256</MenuItem>
              <MenuItem value="ecdsa_p384">ECDSA P-384</MenuItem>
            </Select>
            <FormHelperText>RSA 2048/4096 for broad compatibility; ECDSA for modern stacks.</FormHelperText>
          </FormControl>
        )}

        {step === 4 && (
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Auth hook</InputLabel>
                <Select
                  label="Auth hook"
                  value={payload.auth_hook_id ?? ''}
                  onChange={(e) => setPayload((p) => ({ ...p, auth_hook_id: e.target.value ? Number(e.target.value) : null }))}
                >
                  <MenuItem value="">None</MenuItem>
                  {(hooks.data ?? []).filter((h) => h.hook_type === 'auth' && h.is_active).map((h) => (
                    <MenuItem key={h.id} value={h.id}>{h.name} — {h.script_path}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Cleanup hook</InputLabel>
                <Select
                  label="Cleanup hook"
                  value={payload.cleanup_hook_id ?? ''}
                  onChange={(e) => setPayload((p) => ({ ...p, cleanup_hook_id: e.target.value ? Number(e.target.value) : null }))}
                >
                  <MenuItem value="">None</MenuItem>
                  {(hooks.data ?? []).filter((h) => h.hook_type === 'cleanup' && h.is_active).map((h) => (
                    <MenuItem key={h.id} value={h.id}>{h.name} — {h.script_path}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                label={'Extra hook environment (JSON, e.g. {"API_TOKEN":"x"})'}
                fullWidth
                multiline
                rows={2}
                value={JSON.stringify(payload.hook_env ?? {}, null, 0)}
                onChange={(e) => {
                  try {
                    setPayload((p) => ({ ...p, hook_env: JSON.parse(e.target.value) }))
                  } catch {
                    /* keep last valid */
                  }
                }}
              />
            </Grid>
          </Grid>
        )}

        {step === 5 && (
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>Review configuration</Typography>
            </Grid>
            {[
              ['Domains', payload.domains.join(', ')],
              ['Provider', payload.provider],
              ['Validation', VALIDATION_LABELS[payload.validation_method] ?? payload.validation_method],
              ['Key type', payload.key_type],
              ['Environment', payload.environment],
              ['Auto renew', payload.auto_renew ? 'yes' : 'no'],
              ['Staging', payload.staging ? 'yes' : 'no'],
              ['Dry run', payload.dry_run ? 'yes' : 'no'],
              ['Email', payload.email || 'default'],
            ].map(([k, v]) => (
              <Grid item xs={12} sm={6} key={k}>
                <Typography variant="caption" color="text.secondary" display="block">{k}</Typography>
                <Typography variant="body2">{v}</Typography>
              </Grid>
            ))}
            <Grid item xs={12} sm={6}>
              <TextField
                label="Contact email (Let's Encrypt)"
                fullWidth
                value={payload.email}
                onChange={(e) => setPayload((p) => ({ ...p, email: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Tags (comma separated)"
                fullWidth
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onBlur={addTag}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={payload.auto_renew}
                    onChange={(e) => setPayload((p) => ({ ...p, auto_renew: e.target.checked }))}
                  />
                }
                label="Enable automatic renewal"
              />
            </Grid>
          </Grid>
        )}

        {step === 6 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              {issue.isPending ? 'Issuing certificate…' : 'Issuance result'}
            </Typography>
            <pre className="console-output">{consoleText || 'Waiting for execution logs…'}</pre>
            {issue.isError && <Typography color="error">{apiErrorMessage(issue.error)}</Typography>}
          </Box>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
          <Button disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
            Back
          </Button>
          {step < 5 ? (
            <Button variant="contained" disabled={!canNext()} onClick={() => setStep((s) => s + 1)}>
              Next
            </Button>
          ) : step === 5 ? (
            <Button variant="contained" color="success" onClick={() => issue.mutate()} disabled={issue.isPending}>
              {issue.isPending ? 'Issuing…' : 'Issue certificate'}
            </Button>
          ) : (
            <Button variant="outlined" onClick={() => navigate('/certificates')}>
              Back to certificates
            </Button>
          )}
        </Box>
      </Paper>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
