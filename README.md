# 365-User AD and Cloud Setup

A production-ready Python GUI tool for MSP and enterprise admins that automates end-to-end user provisioning:

1. **Create** a user in on-prem Active Directory
2. **Trigger** Entra ID (Azure AD Connect) delta sync
3. **Assign** Microsoft 365 licenses via Microsoft Graph
4. **Manage** both on-prem AD groups and cloud-only Entra ID groups

Runs on a Windows Domain Controller under a domain admin context.

## Features

- Tkinter GUI — no web server, no browser required
- Auto-detects Entra Connect sync server (local, SCP, or DC scan)
- Separate AD group and cloud-only Entra ID group assignment
- License seat availability check with refresh (blocks provisioning if no seats available)
- Password generation with complexity validation
- Manager search via AD lookup
- Auto-generated display name and username (editable)
- Full audit logging to `C:\Logs\UserProvisioning.log`
- Single-file script — no external config files required
- Certificate-based auth for Microsoft Graph (no plaintext credentials)

## Prerequisites

### Software
- Windows Server with Active Directory role (Domain Controller)
- Python 3.10+ with Tkinter (included in standard Windows Python installer)
- PowerShell with `ActiveDirectory` module (present by default on DCs)
- Azure AD Connect / Entra Connect installed (on this DC or another server)

### Python Dependencies
```
pip install msal requests
```

## Setup

### 1. Configure the Script

Edit the configuration constants at the top of `provision_user.py`:

```python
AD_DOMAIN = "yourdomain.com"
AD_NETBIOS = "YOURDOMAIN"
EMAIL_DOMAINS = ["yourdomain.com", "alias.com"]

GRAPH_TENANT_ID = "your-tenant-id"
GRAPH_CLIENT_ID = "your-app-registration-id"
GRAPH_CERT_THUMBPRINT = "your-cert-thumbprint"
GRAPH_CERT_PATH = r"C:\Certs\graph_app.pem"
```

### 2. Create an Azure App Registration

1. Go to **Azure Portal > Entra ID > App registrations > New registration**
2. Name it (e.g., "User Provisioning Tool")
3. Under **Certificates & secrets**, upload a certificate (`.cer` or `.pem` public key)
4. Place the corresponding private key PEM file at the path specified in `GRAPH_CERT_PATH`
5. Under **API permissions**, add these **Application** permissions and grant admin consent:

| Permission | Type | Purpose |
|---|---|---|
| `User.ReadWrite.All` | Application | Read users, assign licenses |
| `Directory.ReadWrite.All` | Application | Modify license assignments |
| `Organization.Read.All` | Application | Read subscribed SKUs |
| `Group.ReadWrite.All` | Application | Read cloud groups |
| `GroupMember.ReadWrite.All` | Application | Add users to cloud groups |

### 3. Entra Connect Sync Server

The script auto-detects the Entra Connect server at startup:

1. Checks if ADSync service runs locally
2. Queries the AD Service Connection Point
3. Scans domain controllers for the ADSync service
4. Falls back to manual entry if not found

You can override auto-detection by setting `ADSYNC_SERVER` in the config, or by using the override field in the GUI.

## Usage

### Run from Source
```
python provision_user.py
```

### Run as EXE
```
UserProvisioning.exe
```

## Required Permissions

### Active Directory
The user running the script must have:
- Create User objects in the target OUs
- Modify group membership for target security groups
- Read all OUs and groups
- (If Entra Connect is remote) WinRM/PSRemoting access to the sync server

Typically this means **Domain Admin** or equivalent delegated permissions.

### Network
- Outbound HTTPS (443) to `login.microsoftonline.com` and `graph.microsoft.com`
- If Entra Connect is remote: WinRM (5985/5986) to the sync server

## Build to EXE

```batch
pip install pyinstaller msal requests
pyinstaller --onefile --windowed --name "UserProvisioning" provision_user.py
```

The resulting `dist\UserProvisioning.exe` is a standalone executable — no Python installation required on the target machine. It still needs:
- Network access to the DC (or to be running on one)
- Network access to `login.microsoftonline.com` and `graph.microsoft.com`
- The certificate PEM file at the configured path
- PowerShell with the `ActiveDirectory` module available

## Known Limitations

- **No rollback**: If the user is created in AD but a later step fails (e.g., license assignment), the AD user is not deleted. Fix the issue and retry manually, or re-run the cloud steps.
- **Single license**: Currently assigns one license per provisioning run. Run again or use M365 admin center for additional licenses.
- **Password in memory**: The password exists in process memory during execution. The script uses `-EncodedCommand` to avoid shell interpolation, and never logs the password.
- **Cloud group pagination**: Fetches up to 999 cloud groups. If you have more, the script will need pagination support.
- **Entra sync timing**: Delta sync typically takes 30s-3min. The default poll timeout is 5 minutes. Adjust `ENTRA_POLL_TIMEOUT_SECONDS` if your environment is slower.

## Logging

All operations are logged to `C:\Logs\UserProvisioning.log` with timestamps and severity levels. Passwords are never logged (replaced with `[REDACTED]`).

## License

MIT
