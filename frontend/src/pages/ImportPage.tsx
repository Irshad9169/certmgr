import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import CloudUploadIcon from '@mui/icons-material/CloudUpload'
import DownloadIcon from '@mui/icons-material/CloudDownload'
import { api, apiErrorMessage } from '../lib/api'
import { PageHeader, Toast } from '../components/Shared'
import { useAuth } from '../lib/auth-context'

export default function ImportPage() {
  const { can } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [files, setFiles] = useState<{ certificate?: File; private_key?: File; chain?: File; pfx?: File }>({})
  const [pfxPassword, setPfxPassword] = useState('')
  const [environment, setEnvironment] = useState('production')
  const [autoRenew, setAutoRenew] = useState(false)
  const [tags, setTags] = useState('')
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)
  const [godaddyLookup, setGodaddyLookup] = useState<'domain' | 'certificate_id'>('domain')
  const [godaddyValue, setGodaddyValue] = useState('')
  const [godaddyEnvironment, setGodaddyEnvironment] = useState('production')

  const mutation = useMutation({
    mutationFn: async () => {
      const form = new FormData()
      if (files.pfx) {
        form.append('pfx', files.pfx)
      } else {
        if (files.certificate) form.append('certificate', files.certificate)
        if (files.private_key) form.append('private_key', files.private_key)
        if (files.chain) form.append('chain', files.chain)
      }
      return api.post('/certificates/import/upload', form, {
        params: {
          environment,
          auto_renew: autoRenew,
          tags: tags || undefined,
          pfx_password: pfxPassword || undefined,
        },
        headers: { 'Content-Type': 'multipart/form-data' },
      })
    },
    onSuccess: (res) => {
      const { certificate_id, domain } = res.data as { certificate_id: number; domain: string; fingerprint: string }
      setToast({ message: `Imported ${domain} (#${certificate_id})`, severity: 'success' })
      qc.invalidateQueries({ queryKey: ['certificates'] })
      setTimeout(() => navigate(`/certificates/${certificate_id}`), 1200)
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const godaddyMutation = useMutation({
    mutationFn: () =>
      api.post('/certificates/import/godaddy', {
        [godaddyLookup]: godaddyValue,
        environment: godaddyEnvironment,
      }),
    onSuccess: (res) => {
      const { certificate_id, domain } = res.data as { certificate_id: number; domain: string }
      setToast({ message: `Fetched ${domain} from GoDaddy (#${certificate_id})`, severity: 'success' })
      qc.invalidateQueries({ queryKey: ['certificates'] })
      setGodaddyValue('')
      setTimeout(() => navigate(`/certificates/${certificate_id}`), 1200)
    },
    onError: (e) => setToast({ message: apiErrorMessage(e), severity: 'error' }),
  })

  const setFile = (key: keyof typeof files, f?: File) => setFiles((prev) => ({ ...prev, [key]: f }))

  const canSubmit = Boolean(files.pfx || files.certificate) && can('certificate:import')

  return (
    <Box>
      <PageHeader
        title="Import certificate"
        subtitle="Upload existing certificate material — metadata is detected automatically; private keys are encrypted at rest"
      />

      <Card sx={{ maxWidth: 720 }}>
        <CardContent>
          {!can('certificate:import') && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              Your role does not allow importing certificates.
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <div>
              <Typography variant="subtitle2" gutterBottom>Option A — PFX / PKCS12 bundle</Typography>
              <Button variant="outlined" component="label" startIcon={<CloudUploadIcon />} fullWidth>
                {files.pfx ? files.pfx.name : 'Choose .pfx / .p12 file'}
                <input type="file" hidden accept=".pfx,.p12" onChange={(e) => setFile('pfx', e.target.files?.[0])} />
              </Button>
              {files.pfx && (
                <TextField
                  label="PFX password"
                  type="password"
                  fullWidth
                  sx={{ mt: 1 }}
                  value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.target.value)}
                />
              )}
            </div>

            <div>
              <Typography variant="subtitle2" gutterBottom>Option B — PEM / CRT / CER components</Typography>
              <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, 1fr)' } }}>
                <Button variant="outlined" component="label" startIcon={<CloudUploadIcon />}>
                  {files.certificate ? files.certificate.name : 'Certificate *'}
                  <input type="file" hidden accept=".pem,.crt,.cer,.cert" onChange={(e) => setFile('certificate', e.target.files?.[0])} />
                </Button>
                <Button variant="outlined" component="label" startIcon={<CloudUploadIcon />}>
                  {files.private_key ? files.private_key.name : 'Private key'}
                  <input type="file" hidden accept=".pem,.key" onChange={(e) => setFile('private_key', e.target.files?.[0])} />
                </Button>
                <Button variant="outlined" component="label" startIcon={<CloudUploadIcon />}>
                  {files.chain ? files.chain.name : 'Chain'}
                  <input type="file" hidden accept=".pem,.crt" onChange={(e) => setFile('chain', e.target.files?.[0])} />
                </Button>
              </Box>
            </div>

            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' } }}>
              <FormControl fullWidth>
                <InputLabel>Environment</InputLabel>
                <Select value={environment} label="Environment" onChange={(e) => setEnvironment(e.target.value)}>
                  {['production', 'development', 'testing', 'staging', 'dr'].map((s) => (
                    <MenuItem key={s} value={s}>{s}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField label="Tags (comma separated)" value={tags} onChange={(e) => setTags(e.target.value)} />
            </Box>

            <FormControlLabel
              control={<Switch checked={autoRenew} onChange={(e) => setAutoRenew(e.target.checked)} />}
              label="Enable automatic renewal (best-effort for imported certificates)"
            />

            <Button
              variant="contained"
              size="large"
              disabled={!canSubmit || mutation.isPending}
              onClick={() => mutation.mutate()}
            >
              {mutation.isPending ? 'Importing…' : 'Import certificate'}
            </Button>

            <Alert severity="info" sx={{ fontSize: 12 }}>
              The platform detects issuer, subject, SANs, fingerprint, algorithm and key size automatically.
              Private keys are Fernet-encrypted at rest — never stored in the database. Duplicates are rejected.
            </Alert>
          </Box>
        </CardContent>
      </Card>

      <Card sx={{ maxWidth: 720, mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>Fetch from GoDaddy</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Pulls an already-issued certificate straight from your GoDaddy account (via the API key/secret
            configured in Settings) instead of manually downloading and re-uploading it. Only fetches
            certificates that already exist in GoDaddy — it does not request new ones.
          </Typography>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: '160px 1fr' } }}>
              <FormControl fullWidth>
                <InputLabel>Look up by</InputLabel>
                <Select
                  value={godaddyLookup}
                  label="Look up by"
                  onChange={(e) => setGodaddyLookup(e.target.value as 'domain' | 'certificate_id')}
                >
                  <MenuItem value="domain">Domain</MenuItem>
                  <MenuItem value="certificate_id">Certificate ID</MenuItem>
                </Select>
              </FormControl>
              <TextField
                label={godaddyLookup === 'domain' ? 'Domain' : 'GoDaddy certificate ID'}
                placeholder={godaddyLookup === 'domain' ? 'track.example.com' : 'atrhpmgufimpgsdvgyuw1a4liig9buh9'}
                fullWidth
                value={godaddyValue}
                onChange={(e) => setGodaddyValue(e.target.value)}
              />
            </Box>

            <FormControl fullWidth sx={{ maxWidth: { md: 240 } }}>
              <InputLabel>Environment</InputLabel>
              <Select value={godaddyEnvironment} label="Environment" onChange={(e) => setGodaddyEnvironment(e.target.value)}>
                {['production', 'development', 'testing', 'staging', 'dr'].map((s) => (
                  <MenuItem key={s} value={s}>{s}</MenuItem>
                ))}
              </Select>
            </FormControl>

            <Button
              variant="contained"
              size="large"
              startIcon={<DownloadIcon />}
              disabled={!godaddyValue.trim() || !can('certificate:import') || godaddyMutation.isPending}
              onClick={() => godaddyMutation.mutate()}
            >
              {godaddyMutation.isPending ? 'Fetching…' : 'Fetch from GoDaddy'}
            </Button>

            <Alert severity="info" sx={{ fontSize: 12 }}>
              GoDaddy never has your private key — it's downloaded certificate-and-chain only, same as importing
              a cert-only PEM above. Domain lookup checks every match's actual domains itself rather than trusting
              GoDaddy's own filter, since it doesn't always narrow results correctly; if it can't find the right
              one, use the exact certificate ID from your GoDaddy account instead.
            </Alert>
          </Box>
        </CardContent>
      </Card>

      <Toast toast={toast} onClose={() => setToast(null)} />
    </Box>
  )
}
