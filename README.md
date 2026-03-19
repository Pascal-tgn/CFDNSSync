# CfDnsSync

**One-way DNS synchronization from Cloudflare to a local Active Directory Domain Controller.**

CfDnsSync is a Windows Service that periodically fetches DNS records from your Cloudflare zone and replicates them into a local AD-integrated DNS zone. Synchronization is strictly **one-way**: Cloudflare → DC. The service never reads from or writes to Cloudflare beyond fetching records.

---

## Features

- **One-way sync** — Cloudflare is the source of truth. The DC zone is kept in sync automatically.
- **Safe by default** — starts in Dry Run mode. No changes are applied until you explicitly enable live sync.
- **Record ownership model** — every record is tagged as *CF Managed*, *DC Managed*, or *Conflict*. DC-only records are never touched.
- **Web dashboard** — embedded HTTPS dashboard with Windows (NTLM) authentication. View records, resolve conflicts, adjust settings, restart the service.
- **Batch execution** — all DNS changes are executed in a single PowerShell process per sync cycle.
- **Orphan protection** — records deleted from Cloudflare are held for N cycles before being removed from DC. If Cloudflare returns 0 records, sync is aborted entirely.
- **Serilog logging** — rolling file logs (30-day retention) + selective Windows Event Log (errors and critical warnings only).
- **DPAPI token storage** — Cloudflare API token encrypted with Windows Data Protection API, scoped to the service account.

---

## Requirements

- Windows Server 2016 or later (Domain Controller)
- .NET 8 runtime — or use the self-contained build (no runtime needed)
- Cloudflare API token with `Zone → DNS → Read` permission
- Local Administrator rights on the DC

---

## Installation

### 1. Build

```powershell
dotnet publish src\CfDnsSync.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o .\publish
```

### 2. Copy to DC

Copy `publish\CfDnsSync.exe` and `deploy\Install-CfDnsSync.ps1` to the Domain Controller.

### 3. Run the installer

```powershell
# Run as Administrator
.\Install-CfDnsSync.ps1 -StartAfterInstall

# Custom directory and port
.\Install-CfDnsSync.ps1 -InstallDir "С:\Services\CfDnsSync" -Port 8765 -StartAfterInstall
```

The installer registers the Windows Service, creates an Event Log source, runs interactive configuration, encrypts the Cloudflare API token, and creates a Firewall Allow rule for the dashboard port.

**Token alternative:** place your API token in `token.txt` in the install directory. On next service start it is automatically encrypted with DPAPI and the plaintext file is deleted.

---

## First Run

The service starts in **Dry Run mode** by default — it simulates sync operations without applying any changes.

1. Open the dashboard at `https://<dc-hostname>:8765`
2. Review planned changes on the Dashboard tab
3. Resolve any conflicts on the Records tab
4. Go to **Settings**, uncheck **Dry Run Mode**, and save to enable live sync

---

## Web Dashboard

| Tab | Description |
|-----|-------------|
| Dashboard | Sync status, statistics, history, planned changes (dry run) |
| Records | All DNS records with ownership mode, filtering, manual assignment |
| Diff | Live Cloudflare vs DC comparison |
| Settings | Edit config, Skipped Records, Dry Run toggle, Restart Service |
| Documentation | Built-in reference documentation |

Access requires membership in the configured AD group (default: `Domain Admins`).

---

## Configuration

Key fields in `config.json` (editable via Settings tab or directly):

| Field | Default | Description |
|-------|---------|-------------|
| `cloudflareZoneId` | *required* | Cloudflare Zone ID |
| `dnsDomain` | `corp.example.com` | DNS zone name on the DC |
| `syncIntervalMinutes` | `5` | Sync interval in minutes |
| `webDashboardPort` | `8765` | HTTPS port for the dashboard |
| `dryRunMode` | `true` | Simulate without applying changes |
| `orphanDeleteAfterCycles` | `3` | Cycles before orphaned records are deleted |
| `recordModesRetentionDays` | `90` | Days to retain stale entries in record_modes.json |
| `skippedRecords` | `[]` | Record names to skip entirely (e.g. DKIM selectors) |

---

## CLI Commands

```powershell
# Interactive first-time configuration
.\CfDnsSync.exe setup-config

# Encrypt and store Cloudflare API token
.\CfDnsSync.exe setup-token

# Run one sync cycle immediately (for debugging)
.\CfDnsSync.exe sync-now
```

---

## Uninstall

```powershell
# Remove service and all data
.\Uninstall-CfDnsSync.ps1

# Remove service but keep config, token, and logs (useful before upgrade)
.\Uninstall-CfDnsSync.ps1 -KeepData
```

---

## Record Ownership

| Mode | Behaviour |
|------|-----------|
| **CF Managed** | Owned by Cloudflare. Kept in sync, deleted from DC if orphaned. |
| **DC Managed** | Owned by the DC. Never touched by the service. |
| **Conflict** | Different type or value on each side. Skipped until manually resolved. |

Auto-detection runs on every sync cycle. Ownership can be overridden manually in the Records tab.

---

## Known Limitations

- TXT records on nodes with dots in the name (e.g. DKIM selectors like `selector1._domainkey`) are added via `dnscmd` but cannot be reliably read back by `Get-DnsServerResourceRecord`. Add these to **Skipped Records** and manage them manually.
- The service requires the DNS Server PowerShell module (`RSAT-DNS-Server`) to be installed on the DC.
- DPAPI token encryption uses `CurrentUser` scope — `setup-token` must be run as the same account that runs the service.

---

## Security

- Cloudflare API token stored with DPAPI (`CurrentUser` scope)
- Dashboard requires NTLM Windows authentication
- Dashboard served over TLS (auto-generated self-signed cert by default)
- Use a read-only Cloudflare token (`Zone → DNS → Read`) — the service never writes to Cloudflare
- Dry Run mode is on by default — no DNS changes without explicit opt-in

---

## License

MIT License — see [LICENSE](LICENSE).
