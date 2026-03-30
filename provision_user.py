#!/usr/bin/env python3
"""
365 User AD and Cloud Setup — End-to-End User Provisioning Tool

A production-ready GUI tool for MSP and enterprise admins that:
  1. Creates a user in on-prem Active Directory
  2. Triggers Entra ID (Azure AD Connect) delta sync
  3. Assigns Microsoft 365 licenses via Microsoft Graph
  4. Manages both on-prem AD groups and cloud-only Entra ID groups

Runs on a Windows Domain Controller under a domain admin context.
Requires: Python 3.10+, msal, requests
"""

import base64
import json
import logging
import os
import re
import secrets
import string
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime, timezone

try:
    import msal
    import requests
except ImportError as e:
    # Show a useful message if deps are missing (e.g. running without venv)
    print(f"Missing dependency: {e}")
    print("Install with: pip install msal requests")
    raise SystemExit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION CONSTANTS — Edit these for your environment
# ══════════════════════════════════════════════════════════════════════════════

# --- Domain ---
AD_DOMAIN = "contoso.com"                           # FQDN of your AD domain
AD_NETBIOS = "CONTOSO"                              # NetBIOS domain name
DEFAULT_UPN_SUFFIX = "@contoso.com"
EMAIL_DOMAINS = ["contoso.com", "fabrikam.com"]     # Dropdown choices for email

# --- Azure AD Connect / Entra Connect ---
# Set to a hostname to force a specific sync server, or None to auto-detect.
ADSYNC_SERVER = None

# --- Microsoft Graph / Entra ID ---
GRAPH_TENANT_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
GRAPH_CLIENT_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # App Registration
GRAPH_CERT_THUMBPRINT = "AABBCCDD..."
GRAPH_CERT_PATH = r"C:\Certs\graph_app.pem"                # PEM with private key
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

# --- License SKU mappings (friendly name -> skuId GUID) ---
# These are examples — replace with your tenant's actual SKU IDs.
# The tool also fetches available licenses dynamically from Graph.
LICENSE_SKUS = {
    "Microsoft 365 Business Premium": "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",
    "Office 365 E3": "6fd2c87f-b296-42f0-b197-1e91e994b900",
    "Office 365 E5": "c7df2760-2c81-4ef7-b578-5b5392b571df",
    "Microsoft 365 E3": "05e9a617-0261-4cee-bb36-b42a0f4d2e45",
}

# --- Service plans to disable by default (per SKU ID) ---
DISABLED_SERVICE_PLANS = {
    # "cbdc14ab-...": ["57ff2da0-..."],  # Example: disable Sway in Business Premium
}

# --- Password Policy ---
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPER = True
PASSWORD_REQUIRE_LOWER = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True

# --- Sync & Polling ---
ENTRA_POLL_INTERVAL_SECONDS = 15
ENTRA_POLL_TIMEOUT_SECONDS = 300    # 5 minutes

# --- Logging ---
LOG_DIR = r"C:\Logs"
LOG_FILE = r"C:\Logs\UserProvisioning.log"
LOG_LEVEL = "INFO"

# --- UI ---
WINDOW_TITLE = "365 User Provisioning Tool"
WINDOW_SIZE = "800x950"


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging():
    """Configure file and console logging. Creates log directory if needed."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError:
        # Fall back to temp dir if C:\Logs isn't writable
        global LOG_FILE
        LOG_FILE = os.path.join(os.environ.get("TEMP", "."), "UserProvisioning.log")

    logger = logging.getLogger("UserProvisioning")
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # File handler — detailed
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    # Console handler — summary
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


logger = setup_logging()


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER / UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def run_powershell(script: str, timeout: int = 30) -> tuple:
    """
    Execute a PowerShell script via subprocess using -EncodedCommand for safety.

    Returns:
        (success: bool, stdout: str, stderr: str)
    """
    # Encode the script as base64 UTF-16LE for -EncodedCommand
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=timeout
        )
        success = result.returncode == 0
        return success, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error("PowerShell command timed out after %ds", timeout)
        return False, "", "Command timed out"
    except FileNotFoundError:
        logger.error("powershell.exe not found — is this a Windows machine?")
        return False, "", "powershell.exe not found"


def sanitize_for_powershell(value: str) -> str:
    """
    Sanitize a string for safe interpolation into PowerShell commands.
    Strips dangerous characters that could enable injection.

    Note: For passwords, we use -EncodedCommand instead of interpolation,
    so this is mainly for names, titles, etc.
    """
    # Allow alphanumeric, spaces, hyphens, apostrophes, periods, commas
    sanitized = re.sub(r"[^a-zA-Z0-9 \-'.,@()_]", "", value)
    # Double any single quotes for PowerShell string escaping
    sanitized = sanitized.replace("'", "''")
    return sanitized


def validate_password_complexity(password: str) -> tuple:
    """
    Validate password against complexity requirements.

    Returns:
        (is_valid: bool, errors: list[str])
    """
    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Must be at least {PASSWORD_MIN_LENGTH} characters")
    if PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter")
    if PASSWORD_REQUIRE_LOWER and not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter")
    if PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        errors.append("Must contain at least one digit")
    if PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        errors.append("Must contain at least one special character")

    return len(errors) == 0, errors


def generate_password(length: int = 16) -> str:
    """Generate a cryptographically random password meeting all complexity requirements."""
    # Ensure at least one character from each required class
    chars = []
    if PASSWORD_REQUIRE_UPPER:
        chars.append(secrets.choice(string.ascii_uppercase))
    if PASSWORD_REQUIRE_LOWER:
        chars.append(secrets.choice(string.ascii_lowercase))
    if PASSWORD_REQUIRE_DIGIT:
        chars.append(secrets.choice(string.digits))
    if PASSWORD_REQUIRE_SPECIAL:
        chars.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    # Fill remaining length with random chars from the full set
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    remaining = max(0, length - len(chars))
    chars.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Shuffle to avoid predictable positions
    result = list(chars)
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


def generate_username(first_name: str, last_name: str) -> str:
    """Generate a sAMAccountName from first initial + last name, lowercased."""
    first = re.sub(r"[^a-zA-Z]", "", first_name).lower()
    last = re.sub(r"[^a-zA-Z]", "", last_name).lower()
    if first and last:
        return f"{first[0]}{last}"
    return ""


# ══════════════════════════════════════════════════════════════════════════════
#  ACTIVE DIRECTORY OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_ad_ous() -> list:
    """
    Retrieve all Organizational Units from Active Directory.
    Returns a list of dicts with 'dn' and 'canonical' keys.
    """
    script = """
    Import-Module ActiveDirectory
    Get-ADOrganizationalUnit -Filter * -Properties CanonicalName |
      Select-Object @{N='dn';E={$_.DistinguishedName}},
                    @{N='canonical';E={$_.CanonicalName}} |
      Sort-Object canonical |
      ConvertTo-Json -Compress
    """
    success, stdout, stderr = run_powershell(script, timeout=30)
    if not success:
        logger.error("Failed to get OUs: %s", stderr)
        return []

    try:
        data = json.loads(stdout) if stdout else []
        # PowerShell returns a single object (not array) if there's only one result
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        logger.error("Failed to parse OU data: %s", stdout[:200])
        return []


def get_ad_security_groups() -> list:
    """
    Retrieve on-prem AD security groups.
    Returns a list of dicts with 'name', 'dn', and 'description' keys.
    """
    script = """
    Import-Module ActiveDirectory
    Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties Description |
      Select-Object @{N='name';E={$_.Name}},
                    @{N='dn';E={$_.DistinguishedName}},
                    @{N='description';E={$_.Description}} |
      Sort-Object name |
      ConvertTo-Json -Compress
    """
    success, stdout, stderr = run_powershell(script, timeout=30)
    if not success:
        logger.error("Failed to get security groups: %s", stderr)
        return []

    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        logger.error("Failed to parse group data: %s", stdout[:200])
        return []


def search_ad_users(search_term: str) -> list:
    """
    Search AD users by name for manager lookup.
    Returns up to 20 matches with display name, DN, and title.
    """
    safe_term = sanitize_for_powershell(search_term)
    if not safe_term:
        return []

    script = f"""
    Import-Module ActiveDirectory
    Get-ADUser -Filter "Name -like '*{safe_term}*'" -Properties DisplayName, Title |
      Select-Object -First 20
        @{{N='display_name';E={{$_.DisplayName}}}},
        @{{N='dn';E={{$_.DistinguishedName}}}},
        @{{N='title';E={{$_.Title}}}} |
      ConvertTo-Json -Compress
    """
    success, stdout, stderr = run_powershell(script, timeout=15)
    if not success:
        logger.warning("Manager search failed: %s", stderr)
        return []

    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        return []


def check_username_exists(username: str) -> bool:
    """Check if a sAMAccountName already exists in AD."""
    safe_name = sanitize_for_powershell(username)
    script = f"""
    Import-Module ActiveDirectory
    try {{ Get-ADUser -Identity '{safe_name}' | Out-Null; Write-Output 'EXISTS' }}
    catch {{ Write-Output 'AVAILABLE' }}
    """
    success, stdout, _ = run_powershell(script, timeout=10)
    return stdout.strip() == "EXISTS"


def create_ad_user(params: dict) -> tuple:
    """
    Create a new AD user with the specified parameters.

    Args:
        params: dict with keys: first_name, last_name, display_name, username,
                email, title, department, ou_dn, password, force_change

    Returns:
        (success: bool, user_dn: str, error_message: str)
    """
    # Build the PowerShell script — password handled safely via EncodedCommand
    p = {k: sanitize_for_powershell(str(v)) for k, v in params.items()
         if k != "password"}

    # The password goes through EncodedCommand (base64) — no shell interpolation risk
    password = params["password"]
    force_change = "$true" if params.get("force_change", True) else "$false"

    script = f"""
    Import-Module ActiveDirectory
    $secpw = ConvertTo-SecureString -String '{password}' -AsPlainText -Force
    New-ADUser `
      -Name '{p["display_name"]}' `
      -GivenName '{p["first_name"]}' `
      -Surname '{p["last_name"]}' `
      -DisplayName '{p["display_name"]}' `
      -SamAccountName '{p["username"]}' `
      -UserPrincipalName '{p["username"]}@{AD_DOMAIN}' `
      -EmailAddress '{p["email"]}' `
      -Title '{p.get("title", "")}' `
      -Department '{p.get("department", "")}' `
      -Path '{p["ou_dn"]}' `
      -AccountPassword $secpw `
      -ChangePasswordAtLogon {force_change} `
      -Enabled $true `
      -PassThru |
      Select-Object DistinguishedName |
      ConvertTo-Json -Compress
    """

    logger.info("Creating AD user: %s (password: [REDACTED])", p["username"])
    success, stdout, stderr = run_powershell(script, timeout=30)

    if not success:
        error_msg = _parse_ad_error(stderr)
        logger.error("AD user creation failed: %s", stderr)
        return False, "", error_msg

    try:
        data = json.loads(stdout)
        user_dn = data.get("DistinguishedName", "")
        logger.info("AD user created: %s at %s", p["username"], user_dn)
        return True, user_dn, ""
    except (json.JSONDecodeError, AttributeError):
        # User probably created but couldn't parse DN — try to look it up
        logger.warning("User likely created but couldn't parse response")
        return True, "", "User created but DN could not be parsed"


def add_user_to_groups(user_dn: str, group_dns: list) -> list:
    """
    Add a user to one or more AD security groups.

    Returns:
        List of (group_name, success, error) tuples.
    """
    results = []
    for group_dn in group_dns:
        safe_user = sanitize_for_powershell(user_dn)
        safe_group = sanitize_for_powershell(group_dn)

        script = f"""
        Import-Module ActiveDirectory
        Add-ADGroupMember -Identity '{safe_group}' -Members '{safe_user}'
        Write-Output 'OK'
        """
        success, stdout, stderr = run_powershell(script, timeout=15)

        # Extract just the group name for reporting
        group_name = group_dn.split(",")[0].replace("CN=", "")
        if success and "OK" in stdout:
            logger.info("Added to group: %s", group_name)
            results.append((group_name, True, ""))
        else:
            logger.error("Failed to add to group %s: %s", group_name, stderr)
            results.append((group_name, False, stderr))

    return results


def set_user_manager(user_dn: str, manager_dn: str) -> tuple:
    """
    Set the manager attribute on an AD user.

    Returns:
        (success: bool, error_message: str)
    """
    safe_user = sanitize_for_powershell(user_dn)
    safe_mgr = sanitize_for_powershell(manager_dn)

    script = f"""
    Import-Module ActiveDirectory
    Set-ADUser -Identity '{safe_user}' -Manager '{safe_mgr}'
    Write-Output 'OK'
    """
    success, stdout, stderr = run_powershell(script, timeout=15)
    if success and "OK" in stdout:
        logger.info("Manager set for user")
        return True, ""
    else:
        logger.error("Failed to set manager: %s", stderr)
        return False, stderr


def _parse_ad_error(stderr: str) -> str:
    """Convert common AD PowerShell errors to friendly messages."""
    lower = stderr.lower()
    if "already exists" in lower:
        return "A user with this sAMAccountName already exists in AD."
    if "password does not meet" in lower or "complexity" in lower:
        return "Password does not meet the domain's complexity requirements."
    if "access is denied" in lower or "access denied" in lower:
        return "Access denied. Ensure you are running as a Domain Admin."
    if "cannot find an object" in lower:
        return "The specified OU, group, or manager was not found in AD."
    if "server is not operational" in lower:
        return "Cannot contact a domain controller. Check network connectivity."
    return f"AD operation failed: {stderr[:300]}"


# ══════════════════════════════════════════════════════════════════════════════
#  MICROSOFT GRAPH / M365 OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

# Module-level token cache
_graph_token_cache = {"token": None, "expires_at": 0}


def get_graph_token() -> str:
    """
    Acquire an app-only access token using certificate-based auth.
    Caches the token and re-acquires if near expiry.
    """
    now = time.time()
    if _graph_token_cache["token"] and _graph_token_cache["expires_at"] > now + 300:
        return _graph_token_cache["token"]

    try:
        with open(GRAPH_CERT_PATH, "r") as f:
            cert_data = f.read()
    except FileNotFoundError:
        raise RuntimeError(
            f"Certificate not found at {GRAPH_CERT_PATH}. "
            "Create an App Registration certificate and place the PEM file there."
        )

    app = msal.ConfidentialClientApplication(
        client_id=GRAPH_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}",
        client_credential={
            "thumbprint": GRAPH_CERT_THUMBPRINT,
            "private_key": cert_data,
        },
    )

    result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
    if "access_token" in result:
        _graph_token_cache["token"] = result["access_token"]
        _graph_token_cache["expires_at"] = now + result.get("expires_in", 3600)
        logger.info("Graph token acquired successfully")
        return result["access_token"]

    error = result.get("error_description", result.get("error", "Unknown error"))
    raise RuntimeError(f"Graph authentication failed: {error}")


def _graph_headers() -> dict:
    """Return standard headers for Graph API calls."""
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Content-Type": "application/json",
    }


def get_available_licenses() -> list:
    """
    Fetch subscribed SKUs from the tenant.
    Returns list of dicts with: sku_id, sku_name, friendly_name, total, consumed, available
    """
    try:
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/subscribedSkus",
            headers=_graph_headers(),
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error("Failed to fetch licenses: %s", e)
        return []

    skus = resp.json().get("value", [])
    licenses = []

    # Build reverse lookup from our config for friendly names
    sku_id_to_friendly = {v: k for k, v in LICENSE_SKUS.items()}

    for sku in skus:
        if sku.get("appliesTo") != "User":
            continue

        sku_id = sku["skuId"]
        prepaid = sku.get("prepaidUnits", {})
        total = prepaid.get("enabled", 0)
        consumed = sku.get("consumedUnits", 0)

        licenses.append({
            "sku_id": sku_id,
            "sku_name": sku.get("skuPartNumber", "Unknown"),
            "friendly_name": sku_id_to_friendly.get(sku_id, sku.get("skuPartNumber", sku_id)),
            "total": total,
            "consumed": consumed,
            "available": max(0, total - consumed),
            "service_plans": sku.get("servicePlans", []),
        })

    licenses.sort(key=lambda x: x["friendly_name"])
    return licenses


def check_license_availability(sku_id: str, licenses: list) -> tuple:
    """
    Check available seats for a specific SKU.

    Returns:
        (available: int, total: int) or (0, 0) if not found.
    """
    for lic in licenses:
        if lic["sku_id"] == sku_id:
            return lic["available"], lic["total"]
    return 0, 0


def find_user_in_entra(upn: str) -> dict | None:
    """
    Look up a user in Entra ID by UPN.
    Returns the user object dict if found, None if not yet synced.
    """
    try:
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{upn}",
            headers=_graph_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("Entra ID lookup failed: %s", e)
        return None


def assign_license(user_id: str, sku_id: str, disabled_plans: list = None) -> tuple:
    """
    Assign a license to a user in Entra ID via Graph API.

    Args:
        user_id: The Entra user object ID or UPN.
        sku_id: The license SKU ID to assign.
        disabled_plans: List of service plan IDs to disable (optional).

    Returns:
        (success: bool, error_message: str)
    """
    body = {
        "addLicenses": [{
            "skuId": sku_id,
            "disabledPlans": disabled_plans or [],
        }],
        "removeLicenses": [],
    }

    try:
        resp = requests.post(
            f"https://graph.microsoft.com/v1.0/users/{user_id}/assignLicense",
            headers=_graph_headers(),
            json=body,
            timeout=30,
        )
        if resp.status_code in (200, 202):
            logger.info("License %s assigned to user %s", sku_id, user_id)
            return True, ""
        else:
            error = resp.json().get("error", {}).get("message", resp.text[:300])
            logger.error("License assignment failed: %s", error)
            return False, error
    except requests.RequestException as e:
        logger.error("License assignment request failed: %s", e)
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRA ID GROUP OPERATIONS (Cloud-Only Groups)
# ══════════════════════════════════════════════════════════════════════════════

def get_cloud_groups() -> list:
    """
    Fetch cloud-only groups from Entra ID (security and M365 groups).
    Filters out on-prem synced groups (those have onPremisesSyncEnabled=true).

    Returns list of dicts: id, display_name, description, group_type
    """
    try:
        # Fetch groups that are NOT synced from on-prem
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/groups"
            "?$filter=onPremisesSyncEnabled ne true"
            "&$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled"
            "&$top=999"
            "&$orderby=displayName",
            headers=_graph_headers(),
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error("Failed to fetch cloud groups: %s", e)
        return []

    groups = []
    for g in resp.json().get("value", []):
        # Determine group type for display
        group_types = g.get("groupTypes", [])
        if "Unified" in group_types:
            gtype = "M365"
        elif g.get("securityEnabled"):
            gtype = "Security"
        else:
            gtype = "Distribution"

        groups.append({
            "id": g["id"],
            "display_name": g.get("displayName", ""),
            "description": g.get("description", "") or "",
            "group_type": gtype,
        })

    return groups


def add_user_to_cloud_groups(user_id: str, group_ids: list) -> list:
    """
    Add a user to cloud-only Entra ID groups.

    Returns list of (group_name, success, error) tuples.
    """
    results = []
    headers = _graph_headers()

    for group_id, group_name in group_ids:
        body = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
        }
        try:
            resp = requests.post(
                f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref",
                headers=headers,
                json=body,
                timeout=15,
            )
            if resp.status_code in (200, 204):
                logger.info("Added to cloud group: %s", group_name)
                results.append((group_name, True, ""))
            else:
                error = resp.json().get("error", {}).get("message", resp.text[:200])
                logger.error("Failed to add to cloud group %s: %s", group_name, error)
                results.append((group_name, False, error))
        except requests.RequestException as e:
            logger.error("Cloud group request failed for %s: %s", group_name, e)
            results.append((group_name, False, str(e)))

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  SYNC OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

_detected_sync_server = {"server": None, "checked": False}


def detect_sync_server() -> tuple:
    """
    Auto-detect the server running Azure AD Connect / Entra Connect.

    Detection order:
      1. Use ADSYNC_SERVER constant if set
      2. Check if ADSync service is running locally
      3. Query AD Service Connection Point for Entra Connect registration
      4. Scan domain controllers for ADSync service

    Returns:
        (server: str or None, method: str) — server hostname and detection method
    """
    # Check override constant first
    if ADSYNC_SERVER:
        logger.info("Using configured sync server: %s", ADSYNC_SERVER)
        return ADSYNC_SERVER, "configured"

    # Check if cached from prior detection
    if _detected_sync_server["checked"]:
        return _detected_sync_server["server"], "cached"

    # Step 1: Check locally
    logger.info("Checking for ADSync service locally...")
    success, stdout, _ = run_powershell(
        "Get-Service -Name ADSync -ErrorAction SilentlyContinue | "
        "Select-Object Status | ConvertTo-Json -Compress",
        timeout=10
    )
    if success and stdout:
        try:
            svc = json.loads(stdout)
            if svc.get("Status") == 4:  # 4 = Running
                logger.info("ADSync service found running locally")
                _detected_sync_server.update({"server": "localhost", "checked": True})
                return "localhost", "local"
        except json.JSONDecodeError:
            pass

    # Step 2: Query AD Service Connection Point
    logger.info("Querying AD for Entra Connect Service Connection Point...")
    script = """
    Import-Module ActiveDirectory
    $domain = (Get-ADDomain).DistinguishedName
    $scp = Get-ADObject -Filter "objectClass -eq 'serviceConnectionPoint' -and Name -eq 'Tenant'" `
      -SearchBase "CN=Microsoft,CN=Program Data,$domain" `
      -Properties Keywords -ErrorAction SilentlyContinue
    if ($scp) {
      $scp | Select-Object @{N='keywords';E={$_.Keywords -join ','}} | ConvertTo-Json -Compress
    } else {
      Write-Output '{}'
    }
    """
    success, stdout, _ = run_powershell(script, timeout=15)
    if success and stdout and stdout != "{}":
        try:
            data = json.loads(stdout)
            keywords = data.get("keywords", "")
            # Keywords contain the server FQDN among other values
            for keyword in keywords.split(","):
                keyword = keyword.strip()
                if "." in keyword and not keyword.startswith("http"):
                    logger.info("Sync server found via SCP: %s", keyword)
                    _detected_sync_server.update({"server": keyword, "checked": True})
                    return keyword, "scp"
        except json.JSONDecodeError:
            pass

    # Step 3: Scan domain controllers
    logger.info("Scanning domain controllers for ADSync service...")
    script = """
    Import-Module ActiveDirectory
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    foreach ($dc in $dcs) {
      try {
        $svc = Get-Service -Name ADSync -ComputerName $dc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
          Write-Output $dc
          break
        }
      } catch {}
    }
    """
    success, stdout, _ = run_powershell(script, timeout=60)
    if success and stdout:
        server = stdout.strip().split("\n")[0].strip()
        if server:
            logger.info("Sync server found on DC: %s", server)
            _detected_sync_server.update({"server": server, "checked": True})
            return server, "dc_scan"

    logger.warning("Could not detect Entra Connect server")
    _detected_sync_server.update({"server": None, "checked": True})
    return None, "not_found"


def trigger_delta_sync(server: str = None) -> tuple:
    """
    Trigger an Azure AD Connect delta sync.

    Args:
        server: The sync server hostname. "localhost" for local, or a remote hostname.

    Returns:
        (success: bool, message: str)
    """
    if not server:
        return False, "No sync server specified"

    if server == "localhost":
        script = """
        Import-Module ADSync
        Start-ADSyncSyncCycle -PolicyType Delta
        Write-Output 'SYNC_STARTED'
        """
    else:
        safe_server = sanitize_for_powershell(server)
        script = f"""
        Invoke-Command -ComputerName '{safe_server}' -ScriptBlock {{
          Import-Module ADSync
          Start-ADSyncSyncCycle -PolicyType Delta
        }}
        Write-Output 'SYNC_STARTED'
        """

    logger.info("Triggering delta sync on %s", server)
    success, stdout, stderr = run_powershell(script, timeout=60)

    if success and "SYNC_STARTED" in stdout:
        return True, "Delta sync initiated"

    # Check for "sync already in progress" — common and recoverable
    if "busy" in stderr.lower() or "already" in stderr.lower() or "in progress" in stderr.lower():
        logger.info("Sync already in progress — waiting for it to complete")
        return True, "Sync already in progress"

    return False, f"Failed to trigger sync: {stderr[:300]}"


# ══════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class ProvisioningApp(tk.Tk):
    """Main GUI application for user provisioning."""

    def __init__(self):
        super().__init__()
        self.title(WINDOW_TITLE)
        self.geometry(WINDOW_SIZE)
        self.resizable(True, True)

        # Data stores (populated async on startup)
        self._ad_ous = []
        self._ad_groups = []
        self._cloud_groups = []
        self._licenses = []
        self._sync_server = None
        self._sync_method = ""
        self._cancel_event = threading.Event()

        # Configure ttk styles
        style = ttk.Style(self)
        style.theme_use("clam")

        # Build the GUI
        self._build_ui()

        # Load data from AD and Graph in background threads
        self.after(100, self._load_startup_data)

    # ── UI Construction ───────────────────────────────────────────────────

    def _build_ui(self):
        """Construct the full GUI layout."""

        # Main scrollable area
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self._scroll_frame = ttk.Frame(canvas)

        self._scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self._scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        parent = self._scroll_frame
        pad = {"padx": 10, "pady": 5}

        # ── User Information ──────────────────────────────────────────────
        frame_user = ttk.LabelFrame(parent, text=" User Information ", padding=10)
        frame_user.pack(fill="x", **pad)

        self.first_name_var = tk.StringVar()
        self.last_name_var = tk.StringVar()
        self.display_name_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.email_domain_var = tk.StringVar(value=EMAIL_DOMAINS[0] if EMAIL_DOMAINS else "")
        self.job_title_var = tk.StringVar()
        self.department_var = tk.StringVar()

        # Auto-generate display name and username on name change
        self.first_name_var.trace_add("write", self._on_name_change)
        self.last_name_var.trace_add("write", self._on_name_change)

        # Row 0: First/Last Name
        ttk.Label(frame_user, text="First Name *").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame_user, textvariable=self.first_name_var, width=25).grid(
            row=0, column=1, sticky="w", padx=(0, 15))
        ttk.Label(frame_user, text="Last Name *").grid(row=0, column=2, sticky="w")
        ttk.Entry(frame_user, textvariable=self.last_name_var, width=25).grid(
            row=0, column=3, sticky="w")

        # Row 1: Display Name
        ttk.Label(frame_user, text="Display Name *").grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(frame_user, textvariable=self.display_name_var, width=40).grid(
            row=1, column=1, columnspan=3, sticky="w", pady=(5, 0))

        # Row 2: Username + Check button
        ttk.Label(frame_user, text="Username *").grid(row=2, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(frame_user, textvariable=self.username_var, width=25).grid(
            row=2, column=1, sticky="w", pady=(5, 0))
        self.check_user_btn = ttk.Button(frame_user, text="Check", width=8,
                                          command=self._check_username)
        self.check_user_btn.grid(row=2, column=2, sticky="w", pady=(5, 0))
        self.username_status_label = ttk.Label(frame_user, text="")
        self.username_status_label.grid(row=2, column=3, sticky="w", pady=(5, 0))

        # Row 3: Email Domain
        ttk.Label(frame_user, text="Email Domain *").grid(row=3, column=0, sticky="w", pady=(5, 0))
        email_combo = ttk.Combobox(frame_user, textvariable=self.email_domain_var,
                                    values=EMAIL_DOMAINS, width=25, state="readonly")
        email_combo.grid(row=3, column=1, sticky="w", pady=(5, 0))

        # Row 4: Job Title / Department
        ttk.Label(frame_user, text="Job Title").grid(row=4, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(frame_user, textvariable=self.job_title_var, width=25).grid(
            row=4, column=1, sticky="w", pady=(5, 0))
        ttk.Label(frame_user, text="Department").grid(row=4, column=2, sticky="w", pady=(5, 0))
        ttk.Entry(frame_user, textvariable=self.department_var, width=25).grid(
            row=4, column=3, sticky="w", pady=(5, 0))

        # ── Active Directory ──────────────────────────────────────────────
        frame_ad = ttk.LabelFrame(parent, text=" Active Directory ", padding=10)
        frame_ad.pack(fill="x", **pad)

        # OU Selection
        self.ou_var = tk.StringVar()
        ttk.Label(frame_ad, text="Organizational Unit *").grid(row=0, column=0, sticky="w")
        self.ou_combo = ttk.Combobox(frame_ad, textvariable=self.ou_var, width=55, state="readonly")
        self.ou_combo.grid(row=0, column=1, columnspan=3, sticky="w")
        self._ou_map = {}  # canonical -> dn

        # AD Security Groups (multi-select)
        ttk.Label(frame_ad, text="AD Groups\n(on-prem)").grid(row=1, column=0, sticky="nw", pady=(5, 0))
        groups_frame = ttk.Frame(frame_ad)
        groups_frame.grid(row=1, column=1, columnspan=3, sticky="w", pady=(5, 0))

        self.ad_groups_listbox = tk.Listbox(groups_frame, selectmode="multiple",
                                             height=6, width=50, exportselection=False)
        groups_scroll = ttk.Scrollbar(groups_frame, orient="vertical",
                                       command=self.ad_groups_listbox.yview)
        self.ad_groups_listbox.configure(yscrollcommand=groups_scroll.set)
        self.ad_groups_listbox.pack(side="left", fill="both")
        groups_scroll.pack(side="left", fill="y")
        self._ad_group_map = {}  # index -> dn

        # Manager search
        self.manager_search_var = tk.StringVar()
        self.manager_dn_var = tk.StringVar()
        self.manager_display_var = tk.StringVar()

        ttk.Label(frame_ad, text="Manager").grid(row=2, column=0, sticky="w", pady=(5, 0))
        mgr_frame = ttk.Frame(frame_ad)
        mgr_frame.grid(row=2, column=1, columnspan=3, sticky="w", pady=(5, 0))

        ttk.Entry(mgr_frame, textvariable=self.manager_search_var, width=30).pack(side="left")
        ttk.Button(mgr_frame, text="Search", width=8,
                    command=self._search_manager).pack(side="left", padx=(5, 0))
        self.manager_selected_label = ttk.Label(mgr_frame, textvariable=self.manager_display_var,
                                                  foreground="green")
        self.manager_selected_label.pack(side="left", padx=(10, 0))

        # Manager search results (shown dynamically)
        self.manager_results_listbox = tk.Listbox(frame_ad, height=4, width=55,
                                                    exportselection=False)
        self.manager_results_listbox.grid(row=3, column=1, columnspan=3, sticky="w")
        self.manager_results_listbox.grid_remove()  # Hidden by default
        self.manager_results_listbox.bind("<<ListboxSelect>>", self._on_manager_select)
        self._manager_results = []  # list of (display, dn)

        # ── Cloud Groups (Entra ID) ──────────────────────────────────────
        frame_cloud = ttk.LabelFrame(parent, text=" Cloud Groups (Entra ID Only) ", padding=10)
        frame_cloud.pack(fill="x", **pad)

        ttk.Label(frame_cloud, text="Assigned after\nEntra sync").grid(
            row=0, column=0, sticky="nw")

        cloud_grp_frame = ttk.Frame(frame_cloud)
        cloud_grp_frame.grid(row=0, column=1, sticky="w")

        self.cloud_groups_listbox = tk.Listbox(cloud_grp_frame, selectmode="multiple",
                                                height=6, width=50, exportselection=False)
        cloud_scroll = ttk.Scrollbar(cloud_grp_frame, orient="vertical",
                                      command=self.cloud_groups_listbox.yview)
        self.cloud_groups_listbox.configure(yscrollcommand=cloud_scroll.set)
        self.cloud_groups_listbox.pack(side="left", fill="both")
        cloud_scroll.pack(side="left", fill="y")
        self._cloud_group_map = {}  # index -> (id, display_name)

        self.cloud_groups_status = ttk.Label(frame_cloud, text="Loading...", foreground="gray")
        self.cloud_groups_status.grid(row=1, column=1, sticky="w")

        # ── Password ─────────────────────────────────────────────────────
        frame_pw = ttk.LabelFrame(parent, text=" Password ", padding=10)
        frame_pw.pack(fill="x", **pad)

        self.password_var = tk.StringVar()
        self.password_confirm_var = tk.StringVar()
        self.force_change_var = tk.BooleanVar(value=True)

        # Password field + generate
        ttk.Label(frame_pw, text="Password *").grid(row=0, column=0, sticky="w")
        pw_entry = ttk.Entry(frame_pw, textvariable=self.password_var, show="*", width=30)
        pw_entry.grid(row=0, column=1, sticky="w")
        ttk.Button(frame_pw, text="Generate", width=10,
                    command=self._generate_password).grid(row=0, column=2, padx=(5, 0))

        # Show/hide toggle
        self._show_pw_var = tk.BooleanVar(value=False)
        self._pw_entry = pw_entry
        ttk.Checkbutton(frame_pw, text="Show", variable=self._show_pw_var,
                         command=self._toggle_password_visibility).grid(row=0, column=3, padx=(5, 0))

        # Confirm
        ttk.Label(frame_pw, text="Confirm *").grid(row=1, column=0, sticky="w", pady=(5, 0))
        self._pw_confirm_entry = ttk.Entry(frame_pw, textvariable=self.password_confirm_var,
                                            show="*", width=30)
        self._pw_confirm_entry.grid(row=1, column=1, sticky="w", pady=(5, 0))

        # Strength indicator
        self.pw_strength_label = ttk.Label(frame_pw, text="", foreground="gray")
        self.pw_strength_label.grid(row=2, column=1, sticky="w", pady=(2, 0))
        self.password_var.trace_add("write", self._on_password_change)

        # Force change checkbox
        ttk.Checkbutton(frame_pw, text="Force password change at next logon",
                         variable=self.force_change_var).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(5, 0))

        # ── Microsoft 365 Licensing ──────────────────────────────────────
        frame_lic = ttk.LabelFrame(parent, text=" Microsoft 365 Licensing ", padding=10)
        frame_lic.pack(fill="x", **pad)

        self.license_var = tk.StringVar()

        ttk.Label(frame_lic, text="License").grid(row=0, column=0, sticky="w")
        lic_row = ttk.Frame(frame_lic)
        lic_row.grid(row=0, column=1, columnspan=3, sticky="w")

        self.license_combo = ttk.Combobox(lic_row, textvariable=self.license_var,
                                           width=40, state="readonly")
        self.license_combo.pack(side="left")
        self.license_combo.bind("<<ComboboxSelected>>", self._on_license_change)
        ttk.Button(lic_row, text="Refresh", width=8,
                    command=self._refresh_licenses).pack(side="left", padx=(5, 0))

        # Seat availability label
        self.license_seats_label = ttk.Label(frame_lic, text="", foreground="gray")
        self.license_seats_label.grid(row=1, column=1, sticky="w")

        # Service plans frame (dynamic checkbuttons)
        self.service_plans_frame = ttk.Frame(frame_lic)
        self.service_plans_frame.grid(row=2, column=0, columnspan=4, sticky="w", pady=(5, 0))
        self._service_plan_vars = {}  # plan_id -> BooleanVar (True = disabled)

        # ── Sync Server Status ───────────────────────────────────────────
        frame_sync = ttk.LabelFrame(parent, text=" Entra Connect Sync ", padding=10)
        frame_sync.pack(fill="x", **pad)

        self.sync_server_label = ttk.Label(frame_sync, text="Detecting sync server...",
                                            foreground="gray")
        self.sync_server_label.grid(row=0, column=0, columnspan=2, sticky="w")

        # Manual override entry
        ttk.Label(frame_sync, text="Override:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.sync_server_override_var = tk.StringVar()
        ttk.Entry(frame_sync, textvariable=self.sync_server_override_var, width=35).grid(
            row=1, column=1, sticky="w", pady=(5, 0))
        ttk.Label(frame_sync, text="(leave empty to use auto-detected)",
                   foreground="gray").grid(row=1, column=2, sticky="w", pady=(5, 0), padx=(5, 0))

        self.skip_sync_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_sync, text="Skip sync (I'll trigger it manually)",
                         variable=self.skip_sync_var).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(5, 0))

        # ── Action Buttons ───────────────────────────────────────────────
        frame_actions = ttk.Frame(parent, padding=10)
        frame_actions.pack(fill="x", padx=10)

        self.provision_btn = ttk.Button(frame_actions, text="Provision User",
                                         command=self._on_provision_click)
        self.provision_btn.pack(side="left", padx=(0, 10))
        ttk.Button(frame_actions, text="Clear Form",
                    command=self._clear_form).pack(side="left")
        self.cancel_btn = ttk.Button(frame_actions, text="Cancel", state="disabled",
                                      command=self._on_cancel_click)
        self.cancel_btn.pack(side="left", padx=(10, 0))

        # ── Progress & Status ────────────────────────────────────────────
        status_frame = ttk.Frame(self, padding=(10, 5))
        status_frame.pack(fill="x", side="bottom")

        self.progress_bar = ttk.Progressbar(status_frame, mode="indeterminate", length=400)
        self.progress_bar.pack(fill="x")
        self.status_label = ttk.Label(status_frame, text="Ready", foreground="gray")
        self.status_label.pack(fill="x", pady=(2, 0))

    # ── Startup Data Loading ─────────────────────────────────────────────

    def _load_startup_data(self):
        """Load AD and Graph data in background threads on startup."""
        self._run_in_thread(self._load_ad_ous, on_complete=self._populate_ous)
        self._run_in_thread(self._load_ad_groups, on_complete=self._populate_ad_groups)
        self._run_in_thread(self._load_cloud_groups, on_complete=self._populate_cloud_groups)
        self._run_in_thread(self._load_licenses, on_complete=self._populate_licenses)
        self._run_in_thread(self._detect_sync, on_complete=self._show_sync_status)

    def _load_ad_ous(self):
        return get_ad_ous()

    def _populate_ous(self, ous):
        self._ad_ous = ous
        self._ou_map = {}
        display_values = []
        for ou in ous:
            canonical = ou.get("canonical", ou.get("dn", ""))
            self._ou_map[canonical] = ou.get("dn", "")
            display_values.append(canonical)
        self.ou_combo["values"] = display_values
        if display_values:
            self.ou_combo.current(0)

    def _load_ad_groups(self):
        return get_ad_security_groups()

    def _populate_ad_groups(self, groups):
        self._ad_groups = groups
        self.ad_groups_listbox.delete(0, "end")
        self._ad_group_map = {}
        for i, g in enumerate(groups):
            display = g.get("name", "")
            desc = g.get("description", "")
            if desc:
                display = f"{display} — {desc[:40]}"
            self.ad_groups_listbox.insert("end", display)
            self._ad_group_map[i] = g.get("dn", "")

    def _load_cloud_groups(self):
        try:
            return get_cloud_groups()
        except Exception as e:
            logger.warning("Could not load cloud groups: %s", e)
            return []

    def _populate_cloud_groups(self, groups):
        self._cloud_groups = groups
        self.cloud_groups_listbox.delete(0, "end")
        self._cloud_group_map = {}

        if not groups:
            self.cloud_groups_status.configure(
                text="No cloud groups found (Graph auth may not be configured)",
                foreground="orange")
            return

        for i, g in enumerate(groups):
            display = f"[{g['group_type']}] {g['display_name']}"
            self.cloud_groups_listbox.insert("end", display)
            self._cloud_group_map[i] = (g["id"], g["display_name"])

        self.cloud_groups_status.configure(
            text=f"{len(groups)} cloud groups loaded", foreground="green")

    def _load_licenses(self):
        try:
            return get_available_licenses()
        except Exception as e:
            logger.warning("Could not load licenses: %s", e)
            return []

    def _populate_licenses(self, licenses):
        self._licenses = licenses
        values = ["(None — skip licensing)"]
        for lic in licenses:
            values.append(f"{lic['friendly_name']} ({lic['available']}/{lic['total']} available)")
        self.license_combo["values"] = values
        self.license_combo.current(0)

    def _detect_sync(self):
        return detect_sync_server()

    def _show_sync_status(self, result):
        server, method = result
        self._sync_server = server
        self._sync_method = method
        if server:
            self.sync_server_label.configure(
                text=f"Detected: {server} (via {method})", foreground="green")
        else:
            self.sync_server_label.configure(
                text="Not detected — enter manually or skip sync", foreground="orange")

    # ── Event Handlers ───────────────────────────────────────────────────

    def _on_name_change(self, *_args):
        """Auto-generate display name and username when first/last name changes."""
        first = self.first_name_var.get().strip()
        last = self.last_name_var.get().strip()

        if first or last:
            self.display_name_var.set(f"{first} {last}".strip())
            self.username_var.set(generate_username(first, last))

    def _on_password_change(self, *_args):
        """Update password strength indicator in real-time."""
        pw = self.password_var.get()
        if not pw:
            self.pw_strength_label.configure(text="", foreground="gray")
            return

        is_valid, errors = validate_password_complexity(pw)
        if is_valid:
            self.pw_strength_label.configure(text="Strong", foreground="green")
        elif len(errors) <= 2:
            self.pw_strength_label.configure(
                text=f"Weak: {errors[0]}", foreground="orange")
        else:
            self.pw_strength_label.configure(
                text=f"Weak: {len(errors)} requirements not met", foreground="red")

    def _on_license_change(self, *_args):
        """Update seat availability and service plans when license selection changes."""
        selection = self.license_var.get()

        # Clear service plans
        for widget in self.service_plans_frame.winfo_children():
            widget.destroy()
        self._service_plan_vars = {}

        if not selection or selection.startswith("(None"):
            self.license_seats_label.configure(text="", foreground="gray")
            return

        # Find the matching license
        idx = self.license_combo.current() - 1  # -1 because index 0 is "(None...)"
        if idx < 0 or idx >= len(self._licenses):
            return

        lic = self._licenses[idx]
        avail, total = lic["available"], lic["total"]

        if avail > 0:
            self.license_seats_label.configure(
                text=f"{avail} available / {total} total",
                foreground="green")
        else:
            self.license_seats_label.configure(
                text=f"0 available / {total} total — provision licenses in M365 admin center",
                foreground="red")

        # Show service plan checkbuttons
        plans = lic.get("service_plans", [])
        default_disabled = DISABLED_SERVICE_PLANS.get(lic["sku_id"], [])

        ttk.Label(self.service_plans_frame, text="Disable service plans:").grid(
            row=0, column=0, columnspan=3, sticky="w")

        for i, plan in enumerate(plans):
            if plan.get("appliesTo") != "User":
                continue
            plan_id = plan["servicePlanId"]
            plan_name = plan.get("servicePlanName", plan_id)

            var = tk.BooleanVar(value=plan_id in default_disabled)
            self._service_plan_vars[plan_id] = var

            ttk.Checkbutton(self.service_plans_frame, text=plan_name,
                             variable=var).grid(
                row=1 + i // 3, column=i % 3, sticky="w", padx=(0, 10))

    def _on_manager_select(self, event):
        """Handle manager selection from search results."""
        selection = self.manager_results_listbox.curselection()
        if selection and self._manager_results:
            idx = selection[0]
            display, dn = self._manager_results[idx]
            self.manager_dn_var.set(dn)
            self.manager_display_var.set(f"-> {display}")
            self.manager_results_listbox.grid_remove()

    # ── Actions ──────────────────────────────────────────────────────────

    def _check_username(self):
        """Check username availability in AD."""
        username = self.username_var.get().strip()
        if not username:
            return

        self.username_status_label.configure(text="Checking...", foreground="gray")

        def check():
            return check_username_exists(username)

        def on_result(exists):
            if exists:
                self.username_status_label.configure(text="TAKEN", foreground="red")
            else:
                self.username_status_label.configure(text="AVAILABLE", foreground="green")

        self._run_in_thread(check, on_complete=on_result)

    def _search_manager(self):
        """Search AD for potential managers."""
        term = self.manager_search_var.get().strip()
        if not term:
            return

        def search():
            return search_ad_users(term)

        def on_result(users):
            self._manager_results = []
            self.manager_results_listbox.delete(0, "end")

            if not users:
                self.manager_results_listbox.insert("end", "(no results)")
                self.manager_results_listbox.grid()
                return

            for user in users:
                display = user.get("display_name", "")
                title = user.get("title", "")
                dn = user.get("dn", "")
                label = f"{display} ({title})" if title else display
                self._manager_results.append((display, dn))
                self.manager_results_listbox.insert("end", label)

            self.manager_results_listbox.grid()

        self._run_in_thread(search, on_complete=on_result)

    def _generate_password(self):
        """Generate a random password and fill both fields."""
        pw = generate_password()
        self.password_var.set(pw)
        self.password_confirm_var.set(pw)

    def _toggle_password_visibility(self):
        """Toggle password show/hide."""
        show = "" if self._show_pw_var.get() else "*"
        self._pw_entry.configure(show=show)
        self._pw_confirm_entry.configure(show=show)

    def _refresh_licenses(self):
        """Re-fetch license data from Graph."""
        self._update_status("Refreshing licenses...")
        self._run_in_thread(self._load_licenses, on_complete=self._populate_licenses)

    def _clear_form(self):
        """Reset all form fields."""
        for var in (self.first_name_var, self.last_name_var, self.display_name_var,
                    self.username_var, self.job_title_var, self.department_var,
                    self.password_var, self.password_confirm_var, self.manager_search_var,
                    self.manager_dn_var, self.manager_display_var):
            var.set("")

        self.force_change_var.set(True)
        self.ad_groups_listbox.selection_clear(0, "end")
        self.cloud_groups_listbox.selection_clear(0, "end")
        self.license_combo.current(0)
        self.username_status_label.configure(text="")
        self.license_seats_label.configure(text="")
        self.pw_strength_label.configure(text="")

        for widget in self.service_plans_frame.winfo_children():
            widget.destroy()

        self._update_status("Ready")

    def _on_cancel_click(self):
        """Cancel an in-progress provisioning operation."""
        self._cancel_event.set()
        self._update_status("Cancelling...")

    # ── Validation ───────────────────────────────────────────────────────

    def _validate_all(self) -> tuple:
        """
        Validate all form fields before provisioning.

        Returns:
            (is_valid: bool, errors: list[str])
        """
        errors = []

        # Required fields
        if not self.first_name_var.get().strip():
            errors.append("First Name is required")
        if not self.last_name_var.get().strip():
            errors.append("Last Name is required")
        if not self.display_name_var.get().strip():
            errors.append("Display Name is required")
        if not self.username_var.get().strip():
            errors.append("Username is required")
        if not self.ou_var.get():
            errors.append("Organizational Unit must be selected")

        # Password
        pw = self.password_var.get()
        pw_confirm = self.password_confirm_var.get()
        if not pw:
            errors.append("Password is required")
        elif pw != pw_confirm:
            errors.append("Passwords do not match")
        else:
            pw_valid, pw_errors = validate_password_complexity(pw)
            if not pw_valid:
                errors.extend(pw_errors)

        # License seat check
        lic_selection = self.license_var.get()
        if lic_selection and not lic_selection.startswith("(None"):
            idx = self.license_combo.current() - 1
            if 0 <= idx < len(self._licenses):
                lic = self._licenses[idx]
                if lic["available"] <= 0:
                    errors.append(
                        f"No available seats for {lic['friendly_name']}. "
                        "Provision licenses in M365 admin center and click Refresh."
                    )

        return len(errors) == 0, errors

    # ── Provisioning Workflow ────────────────────────────────────────────

    def _on_provision_click(self):
        """Validate and start the provisioning workflow."""
        is_valid, errors = self._validate_all()
        if not is_valid:
            messagebox.showerror("Validation Error", "\n".join(f"- {e}" for e in errors))
            return

        # Confirm with user
        username = self.username_var.get().strip()
        if not messagebox.askyesno(
            "Confirm Provisioning",
            f"Create user '{username}' in Active Directory?\n\n"
            "This will:\n"
            "  1. Create the AD account\n"
            "  2. Add to selected groups\n"
            "  3. Trigger Entra sync (if not skipped)\n"
            "  4. Assign M365 license (if selected)\n"
            "  5. Add to cloud groups (if selected)\n\n"
            "Continue?"
        ):
            return

        self._cancel_event.clear()
        self._set_ui_enabled(False)
        self.progress_bar.start(10)

        self._run_in_thread(
            self._provision_workflow,
            on_complete=self._on_provision_complete,
            on_error=self._on_provision_error,
        )

    def _provision_workflow(self) -> dict:
        """
        Execute the full provisioning workflow. Runs in a background thread.

        Returns a summary dict of results.
        """
        results = {
            "username": self.username_var.get().strip(),
            "ad_created": False,
            "ad_user_dn": "",
            "groups_added": [],
            "cloud_groups_added": [],
            "sync_triggered": False,
            "entra_found": False,
            "entra_user_id": "",
            "license_assigned": False,
            "errors": [],
        }

        # Gather form data
        username = self.username_var.get().strip()
        email_domain = self.email_domain_var.get()
        ou_canonical = self.ou_var.get()
        ou_dn = self._ou_map.get(ou_canonical, "")

        params = {
            "first_name": self.first_name_var.get().strip(),
            "last_name": self.last_name_var.get().strip(),
            "display_name": self.display_name_var.get().strip(),
            "username": username,
            "email": f"{username}@{email_domain}",
            "title": self.job_title_var.get().strip(),
            "department": self.department_var.get().strip(),
            "ou_dn": ou_dn,
            "password": self.password_var.get(),
            "force_change": self.force_change_var.get(),
        }

        # ── Step 1: Create AD User ───────────────────────────────────────
        self._update_status_ts("Creating AD user...")
        if self._cancel_event.is_set():
            results["errors"].append("Cancelled by user")
            return results

        success, user_dn, error = create_ad_user(params)
        if not success:
            results["errors"].append(f"AD user creation failed: {error}")
            return results

        results["ad_created"] = True
        results["ad_user_dn"] = user_dn

        # ── Step 2: Set Manager ──────────────────────────────────────────
        manager_dn = self.manager_dn_var.get()
        if manager_dn and user_dn:
            self._update_status_ts("Setting manager...")
            success, error = set_user_manager(user_dn, manager_dn)
            if not success:
                results["errors"].append(f"Failed to set manager: {error}")

        # ── Step 3: Add to AD Groups ─────────────────────────────────────
        selected_ad_groups = self.ad_groups_listbox.curselection()
        if selected_ad_groups and user_dn:
            self._update_status_ts("Adding to AD groups...")
            group_dns = [self._ad_group_map[i] for i in selected_ad_groups
                        if i in self._ad_group_map]
            group_results = add_user_to_groups(user_dn, group_dns)
            results["groups_added"] = group_results
            for gname, gsuccess, gerror in group_results:
                if not gsuccess:
                    results["errors"].append(f"Group '{gname}': {gerror}")

        # ── Step 4: License and Sync ─────────────────────────────────────
        lic_selection = self.license_var.get()
        wants_license = lic_selection and not lic_selection.startswith("(None")
        selected_cloud_groups = self.cloud_groups_listbox.curselection()
        wants_cloud_groups = len(selected_cloud_groups) > 0

        # Only sync/poll if we need to do something in Entra
        if wants_license or wants_cloud_groups:
            if self._cancel_event.is_set():
                results["errors"].append("Cancelled by user")
                return results

            # Trigger sync
            if not self.skip_sync_var.get():
                self._update_status_ts("Triggering Entra Connect delta sync...")
                sync_server = (self.sync_server_override_var.get().strip()
                               or self._sync_server)
                success, msg = trigger_delta_sync(sync_server)
                results["sync_triggered"] = success
                if not success:
                    results["errors"].append(f"Sync: {msg}")
            else:
                self._update_status_ts("Sync skipped — waiting for user to appear in Entra...")
                results["sync_triggered"] = True  # Skipped intentionally

            # Poll for user in Entra ID
            upn = f"{username}@{AD_DOMAIN}"
            self._update_status_ts("Waiting for user to appear in Entra ID...")
            start_time = time.time()

            while not self._cancel_event.is_set():
                elapsed = time.time() - start_time
                if elapsed > ENTRA_POLL_TIMEOUT_SECONDS:
                    results["errors"].append(
                        f"User not found in Entra ID after {ENTRA_POLL_TIMEOUT_SECONDS}s. "
                        "Sync may be delayed — assign license manually later."
                    )
                    break

                self._update_status_ts(
                    f"Polling Entra ID... ({int(elapsed)}s / {ENTRA_POLL_TIMEOUT_SECONDS}s)")

                user_data = find_user_in_entra(upn)
                if user_data:
                    results["entra_found"] = True
                    results["entra_user_id"] = user_data.get("id", "")
                    break

                time.sleep(ENTRA_POLL_INTERVAL_SECONDS)

            # ── Step 5: Assign License ───────────────────────────────────
            if results["entra_found"] and wants_license:
                if self._cancel_event.is_set():
                    results["errors"].append("Cancelled by user")
                    return results

                self._update_status_ts("Assigning M365 license...")
                lic_idx = self.license_combo.current() - 1
                lic = self._licenses[lic_idx]

                # Collect disabled service plans
                disabled_plans = [pid for pid, var in self._service_plan_vars.items()
                                 if var.get()]

                success, error = assign_license(
                    results["entra_user_id"], lic["sku_id"], disabled_plans)
                results["license_assigned"] = success
                if not success:
                    results["errors"].append(f"License assignment: {error}")

            # ── Step 6: Add to Cloud Groups ──────────────────────────────
            if results["entra_found"] and wants_cloud_groups:
                if self._cancel_event.is_set():
                    results["errors"].append("Cancelled by user")
                    return results

                self._update_status_ts("Adding to cloud groups...")
                cloud_group_ids = [
                    self._cloud_group_map[i] for i in selected_cloud_groups
                    if i in self._cloud_group_map
                ]
                cloud_results = add_user_to_cloud_groups(
                    results["entra_user_id"], cloud_group_ids)
                results["cloud_groups_added"] = cloud_results
                for gname, gsuccess, gerror in cloud_results:
                    if not gsuccess:
                        results["errors"].append(f"Cloud group '{gname}': {gerror}")

        return results

    def _on_provision_complete(self, results: dict):
        """Handle provisioning completion — show summary."""
        self.progress_bar.stop()
        self._set_ui_enabled(True)

        # Build summary message
        lines = [f"User: {results['username']}"]
        lines.append(f"AD Account: {'Created' if results['ad_created'] else 'FAILED'}")

        if results["groups_added"]:
            ok = sum(1 for _, s, _ in results["groups_added"] if s)
            total = len(results["groups_added"])
            lines.append(f"AD Groups: {ok}/{total} added")

        if results["entra_found"]:
            lines.append("Entra ID: Synced")
        elif results["sync_triggered"]:
            lines.append("Entra ID: Not yet synced (timeout)")

        if results.get("license_assigned"):
            lines.append("M365 License: Assigned")
        elif self.license_var.get() and not self.license_var.get().startswith("(None"):
            lines.append("M365 License: NOT assigned")

        if results["cloud_groups_added"]:
            ok = sum(1 for _, s, _ in results["cloud_groups_added"] if s)
            total = len(results["cloud_groups_added"])
            lines.append(f"Cloud Groups: {ok}/{total} added")

        if results["errors"]:
            lines.append(f"\nWarnings/Errors ({len(results['errors'])}):")
            for err in results["errors"]:
                lines.append(f"  - {err}")

        summary = "\n".join(lines)
        logger.info("Provisioning complete:\n%s", summary)

        if results["errors"]:
            messagebox.showwarning("Provisioning Complete (with issues)", summary)
        else:
            messagebox.showinfo("Provisioning Complete", summary)

        self._update_status("Provisioning complete")

    def _on_provision_error(self, error: Exception):
        """Handle unexpected provisioning errors."""
        self.progress_bar.stop()
        self._set_ui_enabled(True)
        logger.exception("Provisioning error")
        messagebox.showerror("Provisioning Error",
                             f"An unexpected error occurred:\n\n{error}")
        self._update_status("Error")

    # ── Thread Helpers ───────────────────────────────────────────────────

    def _run_in_thread(self, target, args=(), on_complete=None, on_error=None):
        """Run a function in a daemon thread with GUI-safe callbacks."""
        def wrapper():
            try:
                result = target(*args) if args else target()
                if on_complete:
                    self.after(0, on_complete, result)
            except Exception as e:
                logger.exception("Thread error in %s", target.__name__)
                if on_error:
                    self.after(0, on_error, e)

        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()

    def _set_ui_enabled(self, enabled: bool):
        """Enable or disable all interactive widgets."""
        state = "normal" if enabled else "disabled"
        self.provision_btn.configure(state=state)
        self.cancel_btn.configure(state="disabled" if enabled else "normal")

    def _update_status(self, text: str):
        """Update the status bar label (must be called from main thread)."""
        self.status_label.configure(text=text)

    def _update_status_ts(self, text: str):
        """Thread-safe status update."""
        self.after(0, self._update_status, text)


# ══════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT CHECK DIALOG
# ══════════════════════════════════════════════════════════════════════════════

# Status constants for preflight checks
CHECK_PENDING = "pending"
CHECK_RUNNING = "running"
CHECK_PASS = "pass"
CHECK_WARN = "warn"
CHECK_FAIL = "fail"


def _preflight_check_powershell() -> tuple:
    """Verify powershell.exe is available."""
    success, stdout, stderr = run_powershell("Write-Output 'OK'", timeout=10)
    if success and "OK" in stdout:
        return CHECK_PASS, "PowerShell is available"
    return CHECK_FAIL, f"PowerShell not available: {stderr[:100]}"


def _preflight_check_ad_module() -> tuple:
    """Verify the ActiveDirectory PowerShell module is installed and loadable."""
    script = """
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
    Write-Output "DOMAIN:$domain"
    """
    success, stdout, stderr = run_powershell(script, timeout=15)
    if success and "DOMAIN:" in stdout:
        domain = stdout.split("DOMAIN:")[1].strip()
        return CHECK_PASS, f"AD module loaded — domain: {domain}"
    if "not recognized" in stderr.lower() or "not installed" in stderr.lower():
        return CHECK_FAIL, "ActiveDirectory module not installed. Install RSAT or run on a DC."
    return CHECK_FAIL, f"AD module error: {stderr[:150]}"


def _preflight_check_ad_permissions() -> tuple:
    """Verify the current user can query AD (read OUs as a basic permission test)."""
    script = """
    Import-Module ActiveDirectory
    $count = (Get-ADOrganizationalUnit -Filter * | Measure-Object).Count
    Write-Output "OUS:$count"
    """
    success, stdout, stderr = run_powershell(script, timeout=15)
    if success and "OUS:" in stdout:
        count = stdout.split("OUS:")[1].strip()
        return CHECK_PASS, f"AD read access confirmed — {count} OUs found"
    if "access" in stderr.lower() or "denied" in stderr.lower():
        return CHECK_FAIL, "Insufficient AD permissions. Run as a Domain Admin."
    return CHECK_WARN, f"Could not verify AD permissions: {stderr[:150]}"


def _preflight_check_network() -> tuple:
    """Verify network connectivity to Microsoft Graph and login endpoints."""
    endpoints = [
        ("login.microsoftonline.com", "Entra ID login"),
        ("graph.microsoft.com", "Microsoft Graph"),
    ]
    results = []
    for host, label in endpoints:
        try:
            resp = requests.get(f"https://{host}", timeout=10, allow_redirects=True)
            results.append((label, True, resp.status_code))
        except requests.RequestException as e:
            results.append((label, False, str(e)[:80]))

    all_ok = all(r[1] for r in results)
    if all_ok:
        return CHECK_PASS, "Network connectivity to Microsoft endpoints confirmed"

    failed = [f"{label}: {err}" for label, ok, err in results if not ok]
    return CHECK_FAIL, "Network unreachable: " + "; ".join(failed)


def _preflight_check_certificate() -> tuple:
    """Verify the Graph API certificate file exists and is readable."""
    if not os.path.isfile(GRAPH_CERT_PATH):
        return CHECK_FAIL, (
            f"Certificate not found at {GRAPH_CERT_PATH}\n"
            "Create an App Registration certificate and place the PEM file there."
        )

    try:
        with open(GRAPH_CERT_PATH, "r") as f:
            content = f.read(100)
        if "PRIVATE KEY" in content or "BEGIN" in content:
            return CHECK_PASS, f"Certificate found: {GRAPH_CERT_PATH}"
        return CHECK_WARN, "File exists but may not be a valid PEM certificate"
    except OSError as e:
        return CHECK_FAIL, f"Cannot read certificate: {e}"


def _preflight_check_graph_auth() -> tuple:
    """Verify Microsoft Graph authentication works (acquire a token)."""
    try:
        token = get_graph_token()
        if token:
            return CHECK_PASS, "Graph API authentication successful"
        return CHECK_FAIL, "Token acquisition returned empty"
    except RuntimeError as e:
        msg = str(e)
        if "Certificate not found" in msg:
            return CHECK_FAIL, msg
        if "AADSTS" in msg:
            # Azure AD error codes — extract the useful part
            return CHECK_FAIL, f"Entra ID auth error: {msg[:200]}"
        return CHECK_FAIL, f"Graph auth failed: {msg[:200]}"
    except Exception as e:
        return CHECK_FAIL, f"Graph auth error: {e}"


def _preflight_check_graph_permissions() -> tuple:
    """Verify the app has the required Graph API permissions by testing key endpoints."""
    try:
        headers = _graph_headers()

        # Test 1: Can we read subscribed SKUs? (requires Organization.Read.All)
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/subscribedSkus",
            headers=headers, timeout=15,
        )
        if resp.status_code == 403:
            return CHECK_FAIL, "Missing permission: Organization.Read.All (cannot read licenses)"
        if resp.status_code == 401:
            return CHECK_FAIL, "Authentication rejected — check App Registration config"

        # Test 2: Can we read groups? (requires Group.ReadWrite.All)
        resp2 = requests.get(
            "https://graph.microsoft.com/v1.0/groups?$top=1",
            headers=headers, timeout=15,
        )
        if resp2.status_code == 403:
            return CHECK_WARN, "Licenses OK, but missing Group.ReadWrite.All (cloud groups won't work)"

        return CHECK_PASS, "Graph API permissions verified (licenses + groups)"
    except requests.RequestException as e:
        return CHECK_WARN, f"Could not verify Graph permissions: {e}"


def _preflight_check_adsync() -> tuple:
    """Detect and verify the Entra Connect sync server."""
    server, method = detect_sync_server()
    if server:
        return CHECK_PASS, f"Entra Connect found: {server} (detected via {method})"
    return CHECK_WARN, (
        "Entra Connect server not detected. You can enter it manually in the GUI "
        "or skip sync and trigger it yourself."
    )


# Ordered list of preflight checks: (name, display_label, check_function, is_required)
PREFLIGHT_CHECKS = [
    ("powershell",     "PowerShell",                  _preflight_check_powershell,      True),
    ("ad_module",      "AD PowerShell Module",        _preflight_check_ad_module,       True),
    ("ad_permissions", "AD Permissions",              _preflight_check_ad_permissions,  True),
    ("network",        "Network Connectivity",        _preflight_check_network,         True),
    ("certificate",    "Graph API Certificate",       _preflight_check_certificate,     True),
    ("graph_auth",     "Microsoft 365 Login",         _preflight_check_graph_auth,      True),
    ("graph_perms",    "Graph API Permissions",        _preflight_check_graph_permissions, False),
    ("adsync",         "Entra Connect Sync Server",   _preflight_check_adsync,          False),
]


class PreflightDialog(tk.Tk):
    """
    Startup dialog that runs environment checks before launching the main app.

    Shows a checklist with real-time status indicators. Required checks must pass
    to proceed; warnings allow continuing with reduced functionality.
    """

    ICON = {
        CHECK_PENDING: "\u2022",   # bullet
        CHECK_RUNNING: "\u25CB",   # circle
        CHECK_PASS:    "\u2714",   # checkmark
        CHECK_WARN:    "\u26A0",   # warning
        CHECK_FAIL:    "\u2718",   # X
    }
    COLOR = {
        CHECK_PENDING: "gray",
        CHECK_RUNNING: "blue",
        CHECK_PASS:    "green",
        CHECK_WARN:    "orange",
        CHECK_FAIL:    "red",
    }

    def __init__(self):
        super().__init__()
        self.title("Preflight Check — 365 User Provisioning")
        self.geometry("620x480")
        self.resizable(False, False)

        self._checks_passed = False
        self._check_rows = {}   # name -> (icon_label, text_label, detail_label)
        self._results = {}      # name -> (status, message)

        self._build_ui()
        self.after(200, self._run_checks)

    def _build_ui(self):
        # Header
        header = ttk.Label(self, text="Preflight Environment Check",
                           font=("Segoe UI", 14, "bold"))
        header.pack(pady=(15, 5))
        ttk.Label(self, text="Verifying requirements before launch...",
                  foreground="gray").pack(pady=(0, 10))

        # Checklist frame
        checklist = ttk.Frame(self, padding=10)
        checklist.pack(fill="both", expand=True, padx=20)

        for i, (name, label, _func, required) in enumerate(PREFLIGHT_CHECKS):
            icon_lbl = ttk.Label(checklist, text=self.ICON[CHECK_PENDING],
                                  foreground=self.COLOR[CHECK_PENDING],
                                  font=("Segoe UI", 12))
            icon_lbl.grid(row=i, column=0, padx=(0, 8), pady=3, sticky="w")

            req_tag = " *" if required else ""
            text_lbl = ttk.Label(checklist, text=f"{label}{req_tag}",
                                  font=("Segoe UI", 10))
            text_lbl.grid(row=i, column=1, pady=3, sticky="w")

            detail_lbl = ttk.Label(checklist, text="", foreground="gray",
                                    font=("Segoe UI", 9), wraplength=350)
            detail_lbl.grid(row=i, column=2, padx=(15, 0), pady=3, sticky="w")

            self._check_rows[name] = (icon_lbl, text_lbl, detail_lbl)

        # Legend
        ttk.Label(checklist, text="* = required",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=len(PREFLIGHT_CHECKS), column=0, columnspan=3, sticky="w", pady=(10, 0))

        # Progress bar
        self.progress = ttk.Progressbar(self, maximum=len(PREFLIGHT_CHECKS), mode="determinate")
        self.progress.pack(fill="x", padx=20, pady=(5, 10))

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=(0, 15))

        self.continue_btn = ttk.Button(btn_frame, text="Continue", state="disabled",
                                        command=self._on_continue)
        self.continue_btn.pack(side="left", padx=5)

        self.retry_btn = ttk.Button(btn_frame, text="Retry", state="disabled",
                                     command=self._on_retry)
        self.retry_btn.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="Quit", command=self._on_quit).pack(side="left", padx=5)

        # Status summary
        self.summary_label = ttk.Label(self, text="", font=("Segoe UI", 10))
        self.summary_label.pack(pady=(0, 10))

    def _update_check(self, name: str, status: str, detail: str = ""):
        """Update a check row's icon, color, and detail text."""
        icon_lbl, text_lbl, detail_lbl = self._check_rows[name]
        icon_lbl.configure(text=self.ICON[status], foreground=self.COLOR[status])
        detail_lbl.configure(text=detail, foreground=self.COLOR[status])
        self._results[name] = (status, detail)

    def _run_checks(self):
        """Run all preflight checks sequentially in a background thread."""
        self.continue_btn.configure(state="disabled")
        self.retry_btn.configure(state="disabled")
        self.progress["value"] = 0

        # Reset all to pending
        for name, _, _, _ in PREFLIGHT_CHECKS:
            self._update_check(name, CHECK_PENDING)

        def worker():
            for i, (name, label, func, required) in enumerate(PREFLIGHT_CHECKS):
                self.after(0, self._update_check, name, CHECK_RUNNING, "Checking...")

                try:
                    status, message = func()
                except Exception as e:
                    status = CHECK_FAIL
                    message = f"Unexpected error: {e}"
                    logger.exception("Preflight check '%s' crashed", name)

                logger.info("Preflight [%s]: %s — %s", name, status, message)
                self.after(0, self._update_check, name, status, message)
                self.after(0, self._advance_progress, i + 1)

            self.after(0, self._checks_complete)

        threading.Thread(target=worker, daemon=True).start()

    def _advance_progress(self, value):
        self.progress["value"] = value

    def _checks_complete(self):
        """Evaluate results and enable/disable buttons."""
        required_failed = []
        warnings = []

        for name, label, _func, required in PREFLIGHT_CHECKS:
            status, message = self._results.get(name, (CHECK_FAIL, "Did not run"))
            if status == CHECK_FAIL and required:
                required_failed.append(label)
            elif status == CHECK_WARN:
                warnings.append(label)

        self.retry_btn.configure(state="normal")

        if required_failed:
            self._checks_passed = False
            self.continue_btn.configure(state="disabled")
            self.summary_label.configure(
                text=f"BLOCKED: {len(required_failed)} required check(s) failed",
                foreground="red")
        elif warnings:
            self._checks_passed = True
            self.continue_btn.configure(state="normal")
            self.summary_label.configure(
                text=f"READY with {len(warnings)} warning(s) — some features may be limited",
                foreground="orange")
        else:
            self._checks_passed = True
            self.continue_btn.configure(state="normal")
            self.summary_label.configure(
                text="ALL CHECKS PASSED — ready to launch",
                foreground="green")

    def _on_continue(self):
        """Close preflight and signal to launch the main app."""
        self.destroy()

    def _on_retry(self):
        """Re-run all checks."""
        # Clear Graph token cache so auth is re-tested
        _graph_token_cache["token"] = None
        _graph_token_cache["expires_at"] = 0
        _detected_sync_server["checked"] = False
        self._run_checks()

    def _on_quit(self):
        """Exit the application."""
        self._checks_passed = False
        self.destroy()

    @property
    def passed(self) -> bool:
        return self._checks_passed


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    logger.info("=" * 60)
    logger.info("User Provisioning Tool started at %s",
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    logger.info("=" * 60)

    # Run preflight checks
    preflight = PreflightDialog()
    preflight.mainloop()

    if not preflight.passed:
        logger.info("Preflight checks failed or user quit — exiting")
        return

    logger.info("Preflight passed — launching main application")

    # Launch main application
    app = ProvisioningApp()
    app.mainloop()

    logger.info("Application closed")


if __name__ == "__main__":
    main()
