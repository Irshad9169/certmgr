# User Guide (Operators)

## Issue a certificate (wizard)

1. **Certificate type** — Single, Multi (SAN), Wildcard, Internal.
2. **Domains** — add FQDNs (wildcards allowed, e.g. `*.example.com`).
3. **Validation method** — HTTP-01, DNS-01, Manual DNS/HTTP, Standalone, Webroot, or
   Custom hooks (select auth/cleanup hook, environment variables, execution user,
   working directory, timeout).
4. **Key type** — RSA 2048/4096, ECDSA P-256/P-384.
5. **Hooks** — pick configured hooks or enter paths/env directly (admin-managed).
6. **Review** — confirm everything; toggle staging/dry-run for testing.
7. **Issue** — watch live Certbot output in the console panel; the certificate
   appears in the inventory with full metadata.

## Manage the inventory

- Search by domain, issuer, subject, serial, fingerprint, cert name.
- Filter by status, environment, provider, key type, renewal status, tags.
- Sort any column; paginate; bulk-select for **renew / revoke / deploy**.
- Tag certificates, mark favorites, set ownership (owner field).

## Certificate details

Subject, issuer, SANs, fingerprint, serial, validity, key algorithm/size, and
health score are shown above the tabs. Tabs: **Execution history** (every
issue/renew/revoke run with stdout/stderr/exit code/duration),
**Deployments**, **Downloads** (PEM/key/chain/fullchain/PFX/zip — key
downloads restricted to authorized roles and audited), **Seen on network**
(hosts the network scanner has found this certificate's fingerprint served
at), **CT Findings** (Certificate Transparency findings for this
certificate's domains), **Usage Discovery** (wildcard/multi-SAN certificates
only — see below).

Actions: Renew, Revoke (with reason), Deploy, Clone, Delete, Backup.

### Usage Discovery

For a wildcard (`*.example.com`) or multi-domain (SAN) certificate, this tab
answers "which real endpoints are actually presenting *this exact*
certificate right now" — distinct from which hostnames it merely covers.
Click **Scan Now**, choose candidate sources (the certificate's own SAN
list, existing CertMgr inventory, previously-seen network scan sightings,
and/or manual hostnames), and watch live progress. Results default to the
`confirmed` filter; a `different_certificate` result links to the actual
certificate being served there if CertMgr already tracks it. Also available
in bulk from the Certificates list page (select multiple, click **Usage
Scan**).

## Import an existing certificate

Upload PEM/CRT/CER (+ optional key and chain) or a PFX/PKCS12 with its password.
The platform automatically detects issuer, expiry, subject, SANs, algorithm,
fingerprint and key size, validates key/cert match, and stores the private key
encrypted. Duplicates (by fingerprint) are rejected.

## Deploy to a server

1. Add the server (hostname/IP, env, SSH auth method, cert directory, web server).
2. Test connectivity.
3. From a certificate, choose **Deploy**: pick the server, target service
   (Apache/Nginx/HAProxy/OpenVPN/Tomcat/custom) and method (SFTP/SCP/rsync).
4. The engine backs up remote files, installs material, reloads the service,
   verifies TLS, and rolls back automatically on failure.

## Remote command center

Server detail → Run command: only allowlisted maintenance commands are accepted
(restart/reload/status services, view cert files, permissions, logs, disk/memory).
Everything is audited.

## Discovery

Three independent discovery mechanisms, all from the Discovery page:

- **Filesystem scan** — scans configured paths (`/etc/letsencrypt/live`,
  `/etc/pki/tls/certs`, `/etc/nginx`, custom), parses found cert/key/PFX
  files, deduplicates by fingerprint, and imports new certificates. Run
  manually or rely on the daily schedule.
- **Network scan** — connects to given IP/CIDR/hostname targets over TLS and
  records whatever certificate each one actually presents, trusted or not —
  answers "what's reachable," including self-signed or internal-CA
  certificates nobody registered with CertMgr. Admin-only (touches
  infrastructure outside CertMgr's control). Manual trigger or the weekly
  schedule against admin-configured targets.
- **CT monitoring** — queries crt.sh (free, public, no API key) for
  admin-configured domains and surfaces certificates issued for them,
  including ones never deployed anywhere — answers "what's been *issued*,"
  a different question from what's reachable. Findings (a real
  open→acknowledged/resolved lifecycle, not just a log) show on the
  Findings page and each certificate's CT Findings tab. Admin-only trigger;
  daily schedule once `ct_monitoring.domains` is configured.

See `docs/administration.md` for configuration details on all three, plus
**Usage Discovery** (a related but separate feature — see Certificate
details above), which answers yet another question: not "what's out there"
but "is *this specific* certificate actually the one being served."

## Notifications

Configure channels (SMTP/Slack/Teams/webhook) and subscribe to events. Expiry
warnings are emitted at 60/30/15/7/3/1 days; lifecycle events (issued, renewed,
failed, deployed, revoked, imported) trigger immediately. Test delivery from the UI.

## Reports

Download inventory, expiry, renewal history, deployment history, failure and audit
reports as CSV, XLSX, PDF or JSON.

## AI assistant

On any failed job: **Explain** (root cause), **Troubleshoot** (recommendations),
**Recurring failures** (pattern detection), **Predict renewal failures** (at-risk
certificates based on history).
