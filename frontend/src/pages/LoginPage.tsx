import { useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  LinearProgress,
  TextField,
  Typography,
} from '@mui/material'
import ShieldIcon from '@mui/icons-material/Shield'
import { useAuth } from '../lib/auth-context'

export default function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [mfa, setMfa] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(username.trim(), password, mfa.trim() || undefined)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(1200px 600px at 20% 10%, rgba(77,171,247,.14), transparent), #f4f6fb',
      }}
    >
      <Card sx={{ width: 420, maxWidth: '92vw' }}>
        {busy && <LinearProgress />}
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
            <ShieldIcon color="primary" sx={{ fontSize: 42 }} />
            <Box>
              <Typography variant="h5">CertMgr</Typography>
              <Typography variant="body2" color="text.secondary">
                Enterprise SSL Certificate Lifecycle Management
              </Typography>
            </Box>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <form onSubmit={submit}>
            <TextField
              label="Username"
              fullWidth
              margin="normal"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
            <TextField
              label="Password"
              type="password"
              fullWidth
              margin="normal"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
            <TextField
              label="MFA code (if enabled)"
              fullWidth
              margin="normal"
              value={mfa}
              onChange={(e) => setMfa(e.target.value)}
              inputProps={{ maxLength: 8 }}
            />
            <Button type="submit" variant="contained" fullWidth size="large" sx={{ mt: 3 }} disabled={busy || !username || !password}>
              Sign in
            </Button>
          </form>
        </CardContent>
      </Card>
    </Box>
  )
}
