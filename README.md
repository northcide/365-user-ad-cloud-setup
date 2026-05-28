# 365-User AD and Cloud Setup

A Tkinter desktop tool for MSP and enterprise admins that automates end-to-end user provisioning on a Windows Domain Controller:

1. **Create** the user in on-prem Active Directory (with mail attributes, country, office, etc.)
2. **Trigger** an Entra ID (Azure AD Connect) delta sync
3. **Set** `usageLocation` on the Entra user (early — before group-based licensing can fail)
4. **Reprocess** group license assignments so any failed group-based assignments retry
5. **Assign** a Microsoft 365 license manually (optional — group-based assignment is the recommended default)
6. **Add** the user to on-prem AD groups and cloud-only Entra ID groups (Graph + Exchange Online for mail-enabled groups)

One universal EXE works for any customer — per-customer settings live in `config.json` next to the EXE.

---

## Features

- **First-run Setup Wizard** — auto-detects AD domain + NetBIOS, loads OU list, finds/creates the customer's App Registration via Microsoft Graph device-code flow, generates a DPAPI-encrypted certificate, uploads the public key to the App Registration, assigns the Exchange Administrator role to the service principal, and opens the admin-consent URL in the browser. Walks the admin through the whole setup without leaving the tool.
- **Single universal EXE** — built with `--uac-admin`, prompts for elevation on launch. UAC-aware preflight check (a non-elevated process can't even pass an admin-membership test).
- **DPAPI-encrypted certificates** — private keys bound to the Windows user account + machine. Stolen `.protected` file is useless elsewhere.
- **No flashing console windows** — every PowerShell call uses `CREATE_NO_WINDOW`.
- **Customizable lookup files** — `titles.txt`, `departments.txt`, `offices.txt` sit next to `config.json`. Admin populates one value per line; the form's Job Title / Department / Office combos read from them (lines starting with `#` are comments). Free-text values are still allowed.
- **Default OU** — saved in `config.json` during setup; pre-selected on every launch. "Save as default" button on the form lets you change it without reopening the wizard. Auto-updates on each successful provision into a different OU.
- **Copy-from user required** — the form blocks provisioning until you pick a template user. Their AD + Entra group memberships are auto-selected, and their assigned licenses (including group-based / dynamic) are compared against tenant inventory.
- **Always-visible license inventory** — read-only panel listing every tenant SKU with available/total seats. Common SKUs are translated to friendly names (e.g. `DESKLESSPACK` → "Office 365 F3").
- **Manual license selection is opt-in** — License combo is grayed out by default with a warning that licenses might be assigned dynamically. Tick "Manually select license" to override.
- **Mail-enabled cloud groups via Exchange Online** — Microsoft Graph can't manage members of DLs / mail-enabled security groups, so the workflow auto-installs the `ExchangeOnlineManagement` PS module and uses `Add-DistributionGroupMember` via app-only cert auth. M365 (Unified) groups stay on Graph.
- **Dynamic groups filtered** — dynamic-membership cloud groups are hidden from the selection list (their membership is computed automatically; manual add isn't supported).
- **Resilient against propagation races** — `usageLocation` is set with verify+retry; cloud group adds retry on transient "Resource does not exist" errors; `reprocessLicenseAssignment` is called after `usageLocation` lands to unstick group-based licensing.
- **Manager picker** — search AD by name, results listbox, selected manager set on the new user.
- **Collapsible advanced panels** — the M365 Licensing frame, AD Groups picker, and Cloud Groups frame are hidden by default; click the small **π** button in the bottom-right of the status bar to reveal them. OU + Manager + Copy-from User panels stay visible.
- **Passphrase generator** — Generate button produces a memorable 8–10 char passphrase in the form `Word1<sep>word2N` (e.g. `Apple#fox4`): two simple 3- or 4-letter words separated by one of `@#$%*!`, first word capitalized, trailing single digit. Satisfies upper/lower/digit/special by construction.

---

## Customer Deployment (Quick Start)

For each new customer:

1. **Copy** `UserProvisioning.exe` to the customer's Domain Controller (or any machine with the AD PowerShell module + line of sight to a DC).
2. **Run as administrator** (the EXE will prompt for elevation automatically). The first launch shows the preflight; when `config.json` is missing it offers the Setup Wizard.
3. In the wizard:
   - Page 1 (Domain Settings) — auto-detects AD FQDN + NetBIOS, loads OUs, pick the default OU.
   - Page 2 (M365 / Entra ID) — click **"Find or Create App Registration"**, complete device-code sign-in as a customer Global Admin. Wizard either reuses an existing app named "User Provisioning Tool" or creates a new one with all required Graph + Exchange permissions and assigns the Exchange Administrator role.
   - Page 3 (Certificate) — click **"Generate Certificate"**. The wizard self-signs a 2-year cert on the DC, DPAPI-encrypts the PEM private key, and uploads the `.cer` to the App Registration automatically.
   - Page 4 (Review & Save) — saves `config.json`, creates empty `titles.txt`/`departments.txt`/`offices.txt`, then click **"Grant Admin Consent (browser)"** to consent the API permissions tenant-wide.
4. Edit `titles.txt`, `departments.txt`, `offices.txt` next to the EXE (one value per line).
5. Back in the preflight, click **"Retry All Checks"** — all should pass.
6. Click **Continue** and provision users.

### What gets deployed per customer

```
C:\Tools\UserProvisioning\
  UserProvisioning.exe          # same EXE for every customer
  config.json                   # customer-specific settings (wizard-generated)
  titles.txt                    # Job Title dropdown values
  departments.txt               # Department dropdown values
  offices.txt                   # Office dropdown values
  C:\Certs\
    graph_app.pem.protected     # DPAPI-encrypted private key (machine-bound)
    graph_app.cer               # Public key (already uploaded to Entra)
```

---

## Provisioning Workflow

1. Validate form. Reject if no copy-from user is picked.
2. **Create AD user** — sets first/last/display/UPN, mail attributes (`mailNickname` = full email, `proxyAddresses[0] = SMTP:<email>`), country attributes (`c`/`co`/`countryCode`), office (`physicalDeliveryOfficeName`), AD group memberships, manager.
3. **Optionally persist default OU** — if the chosen OU differs from `cfg.default_ou_canonical`, silently update `config.json`.
4. **Trigger Entra Connect delta sync** (skippable).
5. **Poll Microsoft Graph** every `entra_poll_interval_seconds` for the new user by UPN (= email's domain, NOT the AD domain). Timeout `entra_poll_timeout_seconds`.
6. **Set `usageLocation`** with verify+retry, then **reprocess license assignments** for the user to unstick any group-based licensing that already failed.
7. (Optional) **Assign a license manually** if the admin ticked "Manually select license" and picked a SKU.
8. **Add to cloud groups** — partition selection:
   - Graph: plain security + M365/Unified groups (with retry on the user-replication race).
   - Exchange Online PowerShell: mail-enabled DLs and mail-enabled security groups (auto-installs the EXO module on first use; connects with the same cert as Graph; uses `Add-DistributionGroupMember -BypassSecurityGroupManagerCheck`).

---

## Security Model

| Component | Protection |
|---|---|
| `config.json` | Non-secret values only (tenant ID, client ID are public identifiers). |
| `*.pem.protected` private key | DPAPI-encrypted; bound to the Windows user account + machine. Stolen file is useless elsewhere. |
| Graph access token | In-memory only; never written to disk. |
| Passwords | Passed to PowerShell via `-EncodedCommand` (base64); never interpolated or logged (always `[REDACTED]` in logs). |
| App Registration | Certificate-based app-only auth. No client secrets. |
| Elevation | EXE manifest requires `requireAdministrator`; preflight refuses to continue without it. |

**Recommendations**

- Restrict NTFS permissions on `config.json` and `*.pem.protected` to the service account.
- Set certificate expiry to 1–2 years and rotate.
- The same cert is reused by Microsoft Graph (MSAL) and Exchange Online (`Connect-ExchangeOnline -CertificateThumbprint`); rotating one rotates both.

---

## `config.json` Reference

Generated by the Setup Wizard; can also be edited manually.

```json
{
  "ad_domain": "customer.com",
  "ad_netbios": "CUSTOMER",
  "email_domains": ["customer.com"],
  "default_ou_canonical": "customer.com/Users",
  "default_ou_dn": "OU=Users,DC=customer,DC=com",
  "default_usage_location": "US",
  "adsync_server": null,
  "graph_tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "graph_client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "graph_cert_thumbprint": "AABBCCDD...",
  "graph_cert_path": "C:\\Certs\\graph_app.pem.protected",
  "password_min_length": 8,
  "entra_poll_interval_seconds": 15,
  "entra_poll_timeout_seconds": 300,
  "license_skus": {}
}
```

| Key | Required | Description |
|---|---|---|
| `ad_domain` | yes | Customer's AD domain FQDN. |
| `ad_netbios` | yes | NetBIOS domain name. |
| `email_domains` | yes | List of email domain options for the form's Email dropdown. The Entra tenant's *default* verified domain is auto-promoted to the top on launch. |
| `default_ou_canonical` | no | Canonical path of the default OU. Pre-selected in the form. |
| `default_ou_dn` | no | DN form of the same OU (used at creation time). |
| `default_usage_location` | no | ISO 3166-1 alpha-2 country code (default `US`). The form shows the friendly name. |
| `graph_tenant_id` | yes | Entra ID Directory (tenant) ID. |
| `graph_client_id` | yes | App Registration Application (client) ID. |
| `graph_cert_thumbprint` | yes | Certificate thumbprint. |
| `graph_cert_path` | yes | Path to the DPAPI-encrypted PEM file. |
| `adsync_server` | no | Override sync server hostname. Default `null` triggers auto-detect (local service, AD SCP, then DC scan). |
| `password_min_length` | no | Default `8`. Matches the built-in passphrase generator output (8–10 chars). Raise to `12+` if you need stronger passwords than the generator produces. |
| `entra_poll_interval_seconds` | no | Default `15`. |
| `entra_poll_timeout_seconds` | no | Default `300`. |
| `license_skus` | no | Optional `{"Friendly Name": "<sku_id-guid>"}` map. Overrides the built-in SKU → friendly-name dictionary for the License inventory panel. |

---

## Lookup files (sit next to `config.json`)

```
titles.txt          # one job title per line
departments.txt     # one department per line
offices.txt         # one office name per line
```

- Lines starting with `#` are treated as comments.
- Duplicate values (case-insensitive) are collapsed.
- Re-read on every form open — edit and reopen the form, no app restart needed.
- The Job Title / Department / Office controls remain free-text comboboxes; the txt files just seed the dropdown.

---

## Prerequisites

### On the Domain Controller (or jump box)

- Windows Server with the **Active Directory** PowerShell module (built-in on a DC).
- **PowerShell 5.1+** (default on modern Windows).
- **Entra Connect / Azure AD Connect** somewhere reachable (the tool auto-detects).
- Outbound HTTPS (443) to `login.microsoftonline.com`, `graph.microsoft.com`, and `outlook.office365.com`.
- Account that is a member of **Domain Admins** (or has delegated *Create User Object* rights on the target OU). The preflight blocks non-admin accounts.

### Azure / Entra ID (per customer — automated by the wizard)

The wizard creates / reuses an App Registration with these **Application** permissions (consent must still be granted):

| API | Permission | Purpose |
|---|---|---|
| Microsoft Graph | `User.ReadWrite.All` | Read users, set `usageLocation`, manage licenses. |
| Microsoft Graph | `Directory.ReadWrite.All` | Manage license assignments. |
| Microsoft Graph | `Organization.Read.All` | Read subscribed SKUs (inventory). |
| Microsoft Graph | `Group.ReadWrite.All` | Read cloud groups. |
| Microsoft Graph | `GroupMember.ReadWrite.All` | Add users to cloud groups. |
| Office 365 Exchange Online | `Exchange.ManageAsApp` | Mail-enabled group management via EXO PowerShell. |

The wizard also assigns the **Exchange Administrator** built-in directory role to the app's service principal (required for `Add-DistributionGroupMember` to work via app-only auth).

---

## Preflight checks

Run on every launch. Required checks block the **Continue** button if they fail:

| Check | Required | What it verifies |
|---|---|---|
| **Administrator Elevation** | yes | Process is elevated. Domain Admins still get UAC-filtered tokens without elevation. |
| **Configuration** | yes | `config.json` exists and has the required keys. |
| **PowerShell** | yes | `powershell.exe` works. |
| **AD PowerShell Module** | yes | `Import-Module ActiveDirectory` succeeds and `Get-ADDomain` returns. |
| **AD Permissions** | yes | Current token is a member of Domain Admins, Enterprise Admins, Administrators, or Account Operators. |
| **Network Connectivity** | yes | TCP 443 to Entra login + Graph endpoints. |
| **Graph API Certificate** | yes | Cert file exists, DPAPI-decryptable, thumbprint matches `config.json`. |
| **Microsoft 365 Login** | yes | App-only Graph token can be acquired. |
| **Graph API Permissions** | no | All required Graph Application permissions are consented (warning only). |
| **Entra Connect Sync Server** | no | Auto-detect found a sync server (warning only — sync can be skipped). |

Click any check to see its detailed message. Failed required checks show a remediation note in the detail pane.

---

## Build to EXE

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller
.venv\Scripts\pyinstaller.exe --onefile --windowed --uac-admin --name "UserProvisioning" provision_user.py
```

The resulting `dist\UserProvisioning.exe` is a standalone executable (~18 MB). No Python installation needed on the DC. The `--uac-admin` flag embeds a `requireAdministrator` manifest so Windows prompts for elevation on launch. The GitHub Action builds this automatically on push to `main`.

---

## Usage

### Run from source (development)

```powershell
.venv\Scripts\python.exe provision_user.py
```

### Run as EXE (production)

Double-click `UserProvisioning.exe`. UAC prompts for elevation; first launch shows the Setup Wizard, subsequent launches go straight to preflight checks.

---

## Known Limitations

- **No rollback** — if AD user creation succeeds but a later step fails, the user is not auto-deleted. Fix the issue and re-run the failed step manually or delete the half-built user.
- **Single manual license per run** — assigns one SKU per provisioning. For more, use M365 admin center (or rely on group-based licensing, which is the default).
- **Cloud group pagination** — fetches up to 999 cloud groups.
- **DPAPI scope** — the encrypted cert is bound to the user + machine. If a different admin account runs the tool, re-run the wizard to re-encrypt under that account.
- **Dynamic groups** — hidden from the cloud group list (membership is rule-based and can't be modified manually).
- **EXO module** — auto-installed in CurrentUser scope on first use of mail-enabled groups. Requires PowerShell Gallery access.
- **License-processing-service lag** — group-based license assignment can take 5–30 minutes after a user joins a dynamic group. The tool calls `reprocessLicenseAssignment` after setting `usageLocation`, which usually shortcuts this, but there's no SLA.

---

## Logging

All operations are logged to `C:\Logs\UserProvisioning.log`. Passwords are always `[REDACTED]`.

---

## License

MIT
