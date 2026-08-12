"""Enumerations shared across models, schemas and services."""

from __future__ import annotations

import enum


class StrEnum(str, enum.Enum):
    """Enum that serializes to its plain string value."""

    def __str__(self) -> str:
        return self.value

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


class RoleName(StrEnum):
    ADMIN = "administrator"
    CERT_MANAGER = "certificate_manager"
    OPERATOR = "operator"
    READ_ONLY = "read_only"


class CertificateType(StrEnum):
    SINGLE = "single"
    MULTI = "multi"
    WILDCARD = "wildcard"
    INTERNAL = "internal"
    IMPORTED = "imported"


class CertificateStatus(StrEnum):
    ACTIVE = "active"
    ISSUING = "issuing"
    RENEWING = "renewing"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"
    IMPORTING = "importing"
    DISCOVERED = "discovered"
    ARCHIVED = "archived"


class RenewalStatus(StrEnum):
    NONE = "none"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    DISABLED = "disabled"


class KeyType(StrEnum):
    RSA_2048 = "rsa2048"
    RSA_4096 = "rsa4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    OTHER = "other"


class ValidationMethod(StrEnum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    MANUAL_HTTP = "manual-http"
    MANUAL_DNS = "manual-dns"
    STANDALONE = "standalone"
    WEBROOT = "webroot"
    CUSTOM = "custom"


class ProviderName(StrEnum):
    LETS_ENCRYPT = "letsencrypt"
    OPENSSL_CA = "openssl-ca"
    DIGICERT = "digicert"
    GODADDY = "godaddy"
    SECTIGO = "sectigo"
    GLOBALSIGN = "globalsign"
    ENTRUST = "entrust"
    MS_ADCS = "ms-adcs"
    INTERNAL_PKI = "internal-pki"


class ServerEnvironment(StrEnum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DR = "dr"
    CLOUD = "cloud"
    ON_PREMISE = "on_premise"


class AuthMethod(StrEnum):
    PASSWORD = "password"  # noqa: S105 — SSH auth method name, not a credential
    SSH_KEY = "ssh_key"
    AGENT = "agent"


class ConnectionStatus(StrEnum):
    UNKNOWN = "unknown"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


class WebServerType(StrEnum):
    NGINX = "nginx"
    APACHE = "apache"
    HAPROXY = "haproxy"
    OPENVPN = "openvpn"
    TOMCAT = "tomcat"
    JETTY = "jetty"
    NODEJS = "nodejs"
    IIS = "iis"
    CUSTOM = "custom"


class DeploymentMethod(StrEnum):
    SSH = "ssh"
    SCP = "scp"
    SFTP = "sftp"
    RSYNC = "rsync"


class DeploymentStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class NotificationChannel(StrEnum):
    SMTP = "smtp"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"


class NotificationStatus(StrEnum):
    QUEUED = "queued"
    SENT = "sent"
    FAILED = "failed"


class NotificationEvent(StrEnum):
    EXPIRY_60 = "expiry_60"
    EXPIRY_30 = "expiry_30"
    EXPIRY_15 = "expiry_15"
    EXPIRY_7 = "expiry_7"
    EXPIRY_3 = "expiry_3"
    EXPIRY_1 = "expiry_1"
    ISSUED = "issued"
    RENEWED = "renewed"
    FAILURE = "failure"
    DEPLOYED = "deployed"
    DEPLOYMENT_FAILED = "deployment_failed"
    REVOKED = "revoked"
    IMPORTED = "imported"
    EXPIRED = "expired"
    DAILY_SUMMARY = "daily_summary"


class JobType(StrEnum):
    ISSUE = "issue"
    RENEW = "renew"
    REVOKE = "revoke"
    DEPLOY = "deploy"
    IMPORT = "import"
    DISCOVERY = "discovery"
    BACKUP = "backup"
    VERIFY = "verify"
    COMPLIANCE = "compliance"
    NOTIFICATION = "notification"
    CLEANUP = "cleanup"
    HEALTH = "health"
    REPORTS = "reports"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


class JobTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULER = "scheduler"
    API = "api"
    SYSTEM = "system"


class HookType(StrEnum):
    AUTH = "auth"
    CLEANUP = "cleanup"
    PRE_DEPLOY = "pre_deploy"
    POST_DEPLOY = "post_deploy"
    ROLLBACK = "rollback"
    CUSTOM = "custom"


class AuditResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PENDING = "pending"
    UNKNOWN = "unknown"


class BackupKind(StrEnum):
    CERTIFICATE = "certificate"
    DATABASE = "database"
    CONFIG = "config"
    FULL = "full"


class ScheduleType(StrEnum):
    INTERVAL = "interval"
    CRON = "cron"


class StorageKind(StrEnum):
    FILESYSTEM = "filesystem"
    ENCRYPTED_FILESYSTEM = "encrypted-filesystem"
    NFS = "nfs"


class OIDC_STATUS(StrEnum):
    NONE = "none"
    ENABLED = "enabled"
