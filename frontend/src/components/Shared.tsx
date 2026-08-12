import type { ReactNode } from 'react'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Snackbar,
  Typography,
} from '@mui/material'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import ErrorIcon from '@mui/icons-material/Error'
import WarningIcon from '@mui/icons-material/Warning'
import ScheduleIcon from '@mui/icons-material/Schedule'

// ── Status chip with semantic colors ────────────────────────────────────────
const STATUS_COLORS: Record<string, 'success' | 'error' | 'warning' | 'info' | 'default'> = {
  active: 'success',
  expiring: 'warning',
  expired: 'error',
  revoked: 'error',
  failed: 'error',
  issuing: 'info',
  renewing: 'info',
  importing: 'info',
  discovered: 'info',
  success: 'success',
  running: 'info',
  queued: 'info',
  pending: 'warning',
  rolled_back: 'warning',
  healthy: 'success',
  warning: 'warning',
  critical: 'error',
  unknown: 'default',
  reachable: 'success',
  unreachable: 'error',
  compliant: 'success',
  non_compliant: 'error',
  sent: 'success',
  delivered: 'success',
}

export function StatusChip({ value }: { value?: string | null }) {
  if (!value) return <Chip size="small" label="—" />
  const color = STATUS_COLORS[value] ?? 'default'
  const Icon = color === 'success' ? CheckCircleIcon : color === 'error' ? ErrorIcon : color === 'warning' ? WarningIcon : ScheduleIcon
  return <Chip size="small" color={color} label={value} icon={<Icon sx={{ fontSize: 15 }} />} />
}

// ── Page header ─────────────────────────────────────────────────────────────
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <Box sx={{ mb: 3, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
      <Box>
        <Typography variant="h4">{title}</Typography>
        {subtitle && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {subtitle}
          </Typography>
        )}
      </Box>
      {actions && <Box sx={{ display: 'flex', gap: 1 }}>{actions}</Box>}
    </Box>
  )
}

// ── Stat card ───────────────────────────────────────────────────────────────
export function StatCard({ label, value, icon, color = 'primary', onClick }: {
  label: string
  value: ReactNode
  icon?: ReactNode
  color?: 'primary' | 'success' | 'warning' | 'error' | 'info'
  onClick?: () => void
}) {
  const palette: Record<string, string> = {
    primary: 'primary.main',
    success: 'success.main',
    warning: 'warning.main',
    error: 'error.main',
    info: 'info.main',
  }
  return (
    <Box
      onClick={onClick}
      sx={{
        bgcolor: 'background.paper',
        border: 1,
        borderColor: 'divider',
        borderRadius: 3,
        p: 2.5,
        display: 'flex',
        alignItems: 'center',
        gap: 2,
        cursor: onClick ? 'pointer' : 'default',
        '&:hover': onClick ? { borderColor: 'primary.main' } : undefined,
      }}
    >
      {icon && (
        <Box sx={{ color: palette[color], display: 'flex' }}>{icon}</Box>
      )}
      <Box>
        <Typography variant="h4" sx={{ lineHeight: 1.1 }}>
          {value}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </Box>
    </Box>
  )
}

// ── Confirm dialog ──────────────────────────────────────────────────────────
export function ConfirmDialog({ open, title, body, confirmLabel = 'Confirm', danger, onConfirm, onClose }: {
  open: boolean
  title: string
  body: ReactNode
  confirmLabel?: string
  danger?: boolean
  onConfirm: () => void
  onClose: () => void
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{body}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button color={danger ? 'error' : 'primary'} variant="contained" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Loading / error wrappers ────────────────────────────────────────────────
export function Loading() {
  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
      <CircularProgress />
    </Box>
  )
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <Alert severity="error" action={onRetry ? <Button onClick={onRetry}>Retry</Button> : undefined}>
      {message}
    </Alert>
  )
}

export function EmptyState({ text }: { text: string }) {
  return (
    <Box sx={{ textAlign: 'center', py: 6, color: 'text.secondary' }}>
      <Typography variant="body1">{text}</Typography>
    </Box>
  )
}

// ── Toast host ──────────────────────────────────────────────────────────────
export interface ToastState {
  message: string
  severity: 'success' | 'error' | 'warning' | 'info'
}

export function Toast({ toast, onClose }: { toast: ToastState | null; onClose: () => void }) {
  return (
    <Snackbar
      open={Boolean(toast)}
      autoHideDuration={4000}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      {toast ? (
        <Alert severity={toast.severity} variant="filled" onClose={onClose} sx={{ minWidth: 280 }}>
          {toast.message}
        </Alert>
      ) : undefined}
    </Snackbar>
  )
}

// ── Days remaining color helper ─────────────────────────────────────────────
export function daysColor(days: number | null | undefined): string {
  if (days === null || days === undefined) return 'text.secondary'
  if (days < 0) return 'error.main'
  if (days <= 7) return 'error.main'
  if (days <= 30) return 'warning.main'
  if (days <= 60) return 'warning.main'
  return 'success.main'
}
