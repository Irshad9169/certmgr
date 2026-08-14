// ── API types (mirrors backend schemas) ─────────────────────────────────────

export interface User {
  id: number
  username: string
  email?: string | null
  full_name: string
  role: string
  permissions: string[]
  mfa_enabled: boolean
  must_change_password: boolean
  last_login_at?: string | null
}

export interface Certificate {
  id: number
  domain: string
  cert_name?: string | null
  sans: string[]
  is_wildcard: boolean
  cert_type: string
  subject?: string | null
  issuer?: string | null
  serial_number?: string | null
  fingerprint_sha256?: string | null
  public_key_algorithm?: string | null
  key_type: string
  key_size?: number | null
  signature_algorithm?: string | null
  valid_from?: string | null
  valid_until?: string | null
  status: string
  environment: string
  provider_name: string
  validation_method: string
  auto_renew: boolean
  renewal_status: string
  renewal_error?: string | null
  last_renewed_at?: string | null
  imported: boolean
  staging: boolean
  owner_id?: number | null
  notes?: string | null
  favorite: boolean
  health_score?: number | null
  health_status: string
  compliance_status: string
  days_remaining?: number | null
  created_at: string
  updated_at: string
  tags: string[]
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages?: number
  summary?: Record<string, number>
}

export interface Execution {
  id: number
  job_type: string
  certificate_id?: number | null
  server_id?: number | null
  status: string
  exit_code?: number | null
  stdout?: string
  stderr?: string
  error_message?: string | null
  execution_time_ms?: number | null
  started_at?: string | null
  finished_at?: string | null
  trigger?: string
  retry_count?: number
  created_at?: string
}

export interface Server {
  id: number
  hostname: string
  ip_address?: string | null
  environment: string
  os_type: string
  ssh_port: number
  auth_method: string
  ssh_user: string
  ssh_key_path?: string | null
  proxy_jump?: string | null
  certificate_directory?: string | null
  web_server_type?: string | null
  owner_id?: number | null
  connection_status: string
  last_check_at?: string | null
  tags: string[]
  notes?: string | null
  created_at?: string
}

export interface Deployment {
  id: number
  certificate_id: number
  server_id: number
  template_id?: number | null
  method: string
  target_service?: string | null
  status: string
  backup_path?: string | null
  verification: Record<string, unknown>
  error_message?: string | null
  started_at?: string | null
  finished_at?: string | null
  server_hostname?: string
  certificate_domain?: string
}

export interface DeploymentTemplate {
  id: number
  name: string
  target_type: string
  description?: string | null
  verify_enabled: boolean
  rollback_enabled: boolean
  variables: Record<string, string>
  is_active: boolean
  deploy_script?: string
}

export interface Hook {
  id: number
  name: string
  hook_type: string
  script_path: string
  env_vars: Record<string, string>
  execution_user?: string | null
  working_directory?: string | null
  timeout_seconds: number
  is_active: boolean
  is_default: boolean
  description?: string | null
  has_ssh_key: boolean
  ssh_target_host?: string | null
}

export interface DashboardStats {
  totals: {
    total: number
    active: number
    expired: number
    revoked: number
    imported: number
    failures_7d: number
    expiring_60: number
    expiring_30: number
    expiring_7: number
  }
  by_status: Record<string, number>
  by_provider: Record<string, number>
  by_environment: Record<string, number>
  by_type: Record<string, number>
  by_key_type: Record<string, number>
}

export interface AuditEntry {
  id: number
  username?: string | null
  action: string
  resource_type?: string | null
  resource_id?: string | null
  result: string
  ip_address?: string | null
  browser?: string | null
  device?: string | null
  duration_ms?: number | null
  details: Record<string, unknown>
  created_at?: string | null
}

export interface IssuePayload {
  domains: string[]
  email?: string | null
  provider: string
  validation_method: string
  key_type: string
  environment: string
  staging: boolean
  dry_run: boolean
  auto_renew: boolean
  webroot_path?: string | null
  standalone_port?: number | null
  auth_hook?: string | null
  cleanup_hook?: string | null
  auth_hook_id?: number | null
  cleanup_hook_id?: number | null
  hook_env?: Record<string, string>
  cert_name?: string | null
  owner_id?: number | null
  tags: string[]
  notes?: string | null
}

export interface ProviderInfo {
  key: string
  display_name: string
  capabilities: {
    validation_methods: string[]
    key_types: string[]
    cert_types: string[]
    supports_revoke: boolean
  }
}

export interface NotificationSettings {
  channel: string
  name: string
  enabled: boolean
  events: string[]
  configured: boolean
}
