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

SECURITY MODEL
──────────────
- config.json contains non-secret values (tenant ID, client ID are not secrets
  per Microsoft's own documentation — they are public identifiers).
- The PEM private key is DPAPI-encrypted (Windows Data Protection API),
  bound to the current Windows user account and the local machine's
  master key. A stolen .protected file is useless on another machine
  or under a different user account.
- The app registration in Entra ID should use minimum required
  permissions (User.ReadWrite.All, Directory.ReadWrite.All,
  Organization.Read.All, Group.ReadWrite.All, GroupMember.ReadWrite.All).
- The Graph access token only exists in memory, never written to disk.
- Recommendation: restrict NTFS permissions on config.json and
  .protected files to the service account running this tool.
"""

import base64
import json
import logging
import os
import re
import secrets
import string
import subprocess
import sys
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
#  PATH RESOLUTION & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

def _get_app_dir():
    """Get the directory where the EXE or script lives."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR = _get_app_dir()
CONFIG_PATH = os.path.join(APP_DIR, "config.json")

# Defaults for settings that don't need customer input
DEFAULTS = {
    "password_min_length": 12,
    "password_require_upper": True,
    "password_require_lower": True,
    "password_require_digit": True,
    "password_require_special": True,
    "entra_poll_interval_seconds": 15,
    "entra_poll_timeout_seconds": 300,
    "log_dir": r"C:\Logs",
    "log_file": r"C:\Logs\UserProvisioning.log",
    "log_level": "INFO",
    "disabled_service_plans": {},
    "license_skus": {},
}

# Required keys that must be present in config.json
REQUIRED_CONFIG_KEYS = [
    "ad_domain", "ad_netbios", "email_domains",
    "graph_tenant_id", "graph_client_id",
    "graph_cert_thumbprint", "graph_cert_path",
]

# Graph scopes are constant — not customer-specific
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

# UI constants — not customer-specific
WINDOW_SIZE = "1050x720"


def load_config() -> dict:
    """
    Load configuration from config.json, merging with defaults.

    Returns the merged config dict. If config.json doesn't exist or is
    invalid, returns defaults with empty strings for required keys.
    """
    merged = dict(DEFAULTS)

    if not os.path.isfile(CONFIG_PATH):
        # Return defaults with empty placeholders for required keys
        for key in REQUIRED_CONFIG_KEYS:
            merged.setdefault(key, "" if key != "email_domains" else [])
        return merged

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.getLogger("UserProvisioning").error(
            "Failed to load config.json: %s", e)
        for key in REQUIRED_CONFIG_KEYS:
            merged.setdefault(key, "" if key != "email_domains" else [])
        return merged

    # Merge: user values override defaults
    merged.update(user_cfg)
    return merged


# Load config at module level — used by all functions
cfg = load_config()


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging():
    """Configure file and console logging. Creates log directory if needed."""
    log_dir = cfg.get("log_dir", DEFAULTS["log_dir"])
    log_file = cfg.get("log_file", DEFAULTS["log_file"])
    log_level = cfg.get("log_level", DEFAULTS["log_level"])

    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        # Fall back to temp dir if log dir isn't writable
        log_file = os.path.join(os.environ.get("TEMP", "."), "UserProvisioning.log")

    logger = logging.getLogger("UserProvisioning")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # File handler — detailed
    fh = logging.FileHandler(log_file, encoding="utf-8")
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
#  DPAPI ENCRYPTION (Windows Data Protection API)
# ══════════════════════════════════════════════════════════════════════════════

def dpapi_encrypt_file(plain_path: str, protected_path: str) -> tuple:
    """
    Encrypt a file using Windows DPAPI (CurrentUser scope).

    Reads the plaintext file, encrypts the bytes with DPAPI via PowerShell,
    writes the result as base64 to the .protected file, then deletes the
    plaintext file.

    Returns:
        (success: bool, message: str)
    """
    if not os.path.isfile(plain_path):
        return False, f"Source file not found: {plain_path}"

    # Use PowerShell to encrypt via DPAPI
    # We read the file in PowerShell to avoid shell interpolation issues with
    # PEM content (which contains special characters)
    script = f"""
    Add-Type -AssemblyName System.Security
    $plainBytes = [System.IO.File]::ReadAllBytes('{plain_path}')
    $encBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $b64 = [Convert]::ToBase64String($encBytes)
    Set-Content -Path '{protected_path}' -Value $b64 -Encoding ASCII
    Write-Output 'DPAPI_OK'
    """
    success, stdout, stderr = run_powershell(script, timeout=15)

    if not success or "DPAPI_OK" not in stdout:
        return False, f"DPAPI encryption failed: {stderr[:300]}"

    # Delete the plaintext file
    try:
        os.remove(plain_path)
        logger.info("DPAPI encrypted %s -> %s (plaintext deleted)", plain_path, protected_path)
    except OSError as e:
        logger.warning("Could not delete plaintext file %s: %s", plain_path, e)
        return True, (
            f"Encrypted to {protected_path}, but could not delete plaintext: {e}. "
            "Please delete it manually for security."
        )

    return True, f"Encrypted to {protected_path}"


def dpapi_decrypt_to_memory(protected_path: str) -> str:
    """
    Decrypt a DPAPI-protected file and return contents as a string.

    Never writes plaintext to disk. The decrypted content is returned
    directly from the PowerShell pipeline as a string.

    Returns:
        The decrypted file contents as a string.

    Raises:
        RuntimeError if decryption fails.
    """
    if not os.path.isfile(protected_path):
        raise RuntimeError(f"Protected file not found: {protected_path}")

    # Decrypt and re-encode as base64 for safe transfer through stdout
    # (run_powershell strips trailing whitespace which corrupts PEM content)
    script = f"""
    Add-Type -AssemblyName System.Security
    $b64 = Get-Content -Path '{protected_path}' -Raw
    $encBytes = [Convert]::FromBase64String($b64.Trim())
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encBytes, $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $outB64 = [Convert]::ToBase64String($plainBytes)
    Write-Output $outB64
    """
    success, stdout, stderr = run_powershell(script, timeout=15)

    if not success:
        raise RuntimeError(f"DPAPI decryption failed: {stderr[:300]}")

    # Decode the base64-wrapped plaintext back to the original string
    try:
        plain_bytes = base64.b64decode(stdout.strip())
        return plain_bytes.decode("utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to decode decrypted content: {e}")


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
    # Allow alphanumeric, spaces, hyphens, apostrophes, periods, commas,
    # equals signs (needed for AD distinguished names like OU=Users,DC=domain)
    sanitized = re.sub(r"[^a-zA-Z0-9 \-'.,@()_=]", "", value)
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

    min_len = cfg["password_min_length"]
    if len(password) < min_len:
        errors.append(f"Must be at least {min_len} characters")
    if cfg["password_require_upper"] and not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter")
    if cfg["password_require_lower"] and not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter")
    if cfg["password_require_digit"] and not re.search(r"\d", password):
        errors.append("Must contain at least one digit")
    if cfg["password_require_special"] and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        errors.append("Must contain at least one special character")

    return len(errors) == 0, errors


def generate_password(length: int = 16) -> str:
    """Generate a cryptographically random password meeting all complexity requirements."""
    # Ensure at least one character from each required class
    chars = []
    if cfg["password_require_upper"]:
        chars.append(secrets.choice(string.ascii_uppercase))
    if cfg["password_require_lower"]:
        chars.append(secrets.choice(string.ascii_lowercase))
    if cfg["password_require_digit"]:
        chars.append(secrets.choice(string.digits))
    if cfg["password_require_special"]:
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

def get_ad_upn_suffixes() -> list:
    """
    Retrieve all UPN suffixes configured in the AD forest.
    Returns a list of domain strings (e.g. ["contoso.com", "fabrikam.com"]).
    Includes both the default forest domain and any additional UPN suffixes.
    """
    script = """
    Import-Module ActiveDirectory
    $forest = Get-ADForest
    $suffixes = @($forest.Name)
    $suffixes += $forest.UPNSuffixes
    $suffixes | Sort-Object | ConvertTo-Json -Compress
    """
    success, stdout, stderr = run_powershell(script, timeout=15)
    if not success:
        logger.warning("Could not retrieve UPN suffixes: %s", stderr)
        return []

    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, str):
            data = [data]
        return [s for s in data if s]
    except json.JSONDecodeError:
        logger.warning("Could not parse UPN suffixes: %s", stdout[:200])
        return []


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


def get_ad_groups() -> list:
    """
    Retrieve all on-prem AD groups (Security and Distribution).
    Returns a list of dicts with 'name', 'dn', 'description', and 'category' keys.
    Category is 'Security' or 'Distribution'.
    """
    script = """
    Import-Module ActiveDirectory
    Get-ADGroup -Filter * -Properties Description, GroupCategory |
      Select-Object @{N='name';E={$_.Name}},
                    @{N='dn';E={$_.DistinguishedName}},
                    @{N='description';E={$_.Description}},
                    @{N='category';E={$_.GroupCategory.ToString()}} |
      Sort-Object name |
      ConvertTo-Json -Compress
    """
    success, stdout, stderr = run_powershell(script, timeout=45)
    if not success:
        logger.error("Failed to get AD groups: %s", stderr)
        return []

    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        logger.error("Failed to parse group data: %s", stdout[:200])
        return []


def get_user_ad_groups(sam_account_name: str) -> list:
    """
    Get the list of group DNs that a user is a member of.
    Uses sAMAccountName for reliable lookup (no DN escaping issues).
    Returns a list of group DN strings.
    """
    safe_sam = sanitize_for_powershell(sam_account_name)
    logger.info("Looking up AD groups for sAMAccountName: %s", safe_sam)

    # MemberOf property returns empty under -NoProfile on some DCs.
    # Use Get-ADGroup -Filter to query from the group side instead,
    # which works reliably regardless of profile loading.
    import tempfile
    tmp_dir = tempfile.gettempdir()
    ps1_path = os.path.join(tmp_dir, "get_user_groups.ps1")
    out_path = os.path.join(tmp_dir, "user_groups_result.txt")

    ps1_content = (
        "Import-Module ActiveDirectory\n"
        "$dc = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName\n"
        "$m = (Get-ADUser -Identity '" + safe_sam + "' -Server $dc -Properties MemberOf).MemberOf\n"
        "if ($m -and $m.Count -gt 0) {\n"
        "    $m | ConvertTo-Json -Compress | Out-File -FilePath '" + out_path + "' -Encoding ASCII -Force\n"
        "} else {\n"
        "    '[]' | Out-File -FilePath '" + out_path + "' -Encoding ASCII -Force\n"
        "}\n"
    )
    with open(ps1_path, "w", encoding="ascii") as f:
        f.write(ps1_content)

    try:
        os.remove(out_path)
    except OSError:
        pass

    # Do NOT use -NoProfile — the MemberOf property returns empty without
    # the user's PowerShell profile loaded on some DCs.
    try:
        result = subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass",
             "-File", ps1_path],
            capture_output=True, text=True, timeout=30
        )
        logger.info("AD groups ps1 execution: rc=%d", result.returncode)
    except Exception as e:
        logger.warning("AD groups subprocess failed: %s", e)
        return []
    finally:
        try:
            os.remove(ps1_path)
        except OSError:
            pass

    try:
        with open(out_path, "r", encoding="utf-8-sig") as f:
            content = f.read().strip()
        os.remove(out_path)
    except (OSError, FileNotFoundError) as e:
        logger.warning("Could not read AD groups result file: %s", e)
        return []

    logger.info("AD groups file content (%d chars): %s", len(content), content[:500])

    if not content or content == "null" or content == "[]":
        logger.info("User has no AD group memberships")
        return []

    try:
        data = json.loads(content)
        if data is None:
            return []
        if isinstance(data, str):
            data = [data]
        logger.info("User AD groups found: %d", len(data))
        return data
    except json.JSONDecodeError:
        logger.warning("Could not parse user AD groups: %s", repr(content[:300]))
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
    $term = '*{safe_term}*'
    $users = Get-ADUser -Filter {{
        Name -like $term -or
        DisplayName -like $term -or
        SamAccountName -like $term
    }} -Properties DisplayName, Title |
      Select-Object -First 20
    $users | Select-Object @{{N='display_name';E={{$_.DisplayName}}}}, @{{N='dn';E={{$_.DistinguishedName}}}}, @{{N='title';E={{$_.Title}}}} | ConvertTo-Json -Compress
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

    ad_domain = cfg["ad_domain"]

    script = f"""
    Import-Module ActiveDirectory
    $secpw = ConvertTo-SecureString -String '{password}' -AsPlainText -Force
    New-ADUser `
      -Name '{p["display_name"]}' `
      -GivenName '{p["first_name"]}' `
      -Surname '{p["last_name"]}' `
      -DisplayName '{p["display_name"]}' `
      -SamAccountName '{p["username"]}' `
      -UserPrincipalName '{p["username"]}@{ad_domain}' `
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

    Tries to load the private key in this order:
      1. DPAPI-protected file (.protected extension)
      2. Plain PEM file (fallback for initial setup before encryption)
    """
    now = time.time()
    if _graph_token_cache["token"] and _graph_token_cache["expires_at"] > now + 300:
        return _graph_token_cache["token"]

    cert_path = cfg["graph_cert_path"]
    protected_path = cert_path + ".protected" if not cert_path.endswith(".protected") else cert_path

    # Derive the plain PEM path from the protected path
    if protected_path.endswith(".protected"):
        plain_path = protected_path[:-len(".protected")]
    else:
        plain_path = cert_path

    # Try DPAPI-protected file first
    cert_data = None
    if os.path.isfile(protected_path):
        try:
            cert_data = dpapi_decrypt_to_memory(protected_path)
            logger.info("Loaded certificate via DPAPI decryption")
        except RuntimeError as e:
            logger.warning("DPAPI decryption failed, trying plain PEM: %s", e)

    # Fall back to plain PEM file
    if cert_data is None:
        if os.path.isfile(plain_path):
            try:
                with open(plain_path, "r") as f:
                    cert_data = f.read()
                logger.info("Loaded certificate from plain PEM (not yet DPAPI-encrypted)")
            except OSError as e:
                raise RuntimeError(
                    f"Cannot read certificate at {plain_path}: {e}"
                )
        else:
            raise RuntimeError(
                f"Certificate not found. Looked for:\n"
                f"  - {protected_path} (DPAPI-encrypted)\n"
                f"  - {plain_path} (plain PEM)\n"
                "Run the Setup Wizard or generate a certificate first."
            )

    app = msal.ConfidentialClientApplication(
        client_id=cfg["graph_client_id"],
        authority=f"https://login.microsoftonline.com/{cfg['graph_tenant_id']}",
        client_credential={
            "thumbprint": cfg["graph_cert_thumbprint"],
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
    license_skus = cfg.get("license_skus", {})
    sku_id_to_friendly = {v: k for k, v in license_skus.items()}

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
    Filters out on-prem synced groups client-side (the $filter + $orderby
    combo fails on some tenants).

    Returns list of dicts: id, display_name, description, group_type
    """
    try:
        # Fetch all groups — filter client-side to avoid Graph API
        # issues with $filter + $orderby on some tenants
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/groups"
            "?$select=id,displayName,description,groupTypes,securityEnabled,"
            "mailEnabled,onPremisesSyncEnabled"
            "&$top=999",
            headers=_graph_headers(),
            timeout=30,
        )
        if resp.status_code != 200:
            error_detail = ""
            try:
                error_detail = resp.json().get("error", {}).get("message", "")
            except Exception:
                error_detail = resp.text[:200]
            logger.error("Cloud groups fetch failed (%d): %s",
                         resp.status_code, error_detail)
            return []
    except requests.RequestException as e:
        logger.error("Failed to fetch cloud groups: %s", e)
        return []

    groups = []
    for g in resp.json().get("value", []):
        # Skip on-prem synced groups — only show cloud-only groups
        if g.get("onPremisesSyncEnabled") is True:
            continue

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

    groups.sort(key=lambda x: x["display_name"].lower())
    return groups


def get_user_cloud_groups(user_upn: str) -> list:
    """
    Get the cloud group IDs that a user is a member of.
    Returns a list of group ID strings (cloud-only groups only).
    """
    try:
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_upn}/memberOf"
            "?$select=id,displayName,groupTypes,securityEnabled,onPremisesSyncEnabled"
            "&$top=999",
            headers=_graph_headers(),
            timeout=30,
        )
        if resp.status_code != 200:
            logger.warning("Failed to get user cloud groups: %d", resp.status_code)
            return []
    except requests.RequestException as e:
        logger.warning("Failed to get user cloud groups: %s", e)
        return []

    group_ids = []
    for item in resp.json().get("value", []):
        # Only include cloud-only groups (skip on-prem synced)
        if item.get("@odata.type") == "#microsoft.graph.group":
            if item.get("onPremisesSyncEnabled") is not True:
                group_ids.append(item["id"])
    return group_ids


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
      1. Use configured adsync_server if set
      2. Check if ADSync service is running locally
      3. Query AD Service Connection Point for Entra Connect registration
      4. Scan domain controllers for ADSync service

    Returns:
        (server: str or None, method: str) — server hostname and detection method
    """
    # Check override from config first
    adsync_server = cfg.get("adsync_server")
    if adsync_server:
        logger.info("Using configured sync server: %s", adsync_server)
        return adsync_server, "configured"

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
#  CERTIFICATE GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def _pfx_to_pem(pfx_bytes: bytes, password: str) -> str:
    """
    Convert PFX/PKCS#12 bytes to PEM string (private key + certificate).
    Uses the 'cryptography' library (installed as a dependency of msal).
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption, pkcs12,
    )
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_key_and_certificates,
    )

    private_key, certificate, _ = load_key_and_certificates(
        pfx_bytes, password.encode("utf-8")
    )

    # Export private key as PKCS8 PEM
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("utf-8")

    # Export certificate as PEM
    cert_pem = certificate.public_bytes(Encoding.PEM).decode("utf-8")

    return key_pem + cert_pem


def generate_certificate_on_dc(cert_path: str = None) -> tuple:
    """
    Generate a self-signed certificate on the DC for Graph API authentication.

    Strategy: PowerShell generates the cert and exports as PFX (works on all
    .NET Framework versions). Python converts PFX to PEM using the cryptography
    library (already installed as a dependency of msal). Then DPAPI-encrypts
    the PEM and deletes all plaintext files.

    Args:
        cert_path: Override path for the PEM file. If None, uses cfg["graph_cert_path"].

    Returns:
        (success: bool, thumbprint: str, message: str)
    """
    if cert_path is None:
        cert_path = cfg.get("graph_cert_path", r"C:\Certs\graph_app.pem")

    # If the path ends with .protected, derive the plain PEM path for generation
    if cert_path.endswith(".protected"):
        pem_path = cert_path[:-len(".protected")]
    else:
        pem_path = cert_path

    cert_dir = os.path.dirname(pem_path)
    cer_path = pem_path.replace(".pem", ".cer")
    pfx_path = pem_path.replace(".pem", ".pfx")
    protected_path = pem_path + ".protected"

    # Use a random temp password for PFX export (only lives in memory briefly)
    pfx_password = secrets.token_urlsafe(32)

    script = f"""
    # Create certificate directory
    New-Item -ItemType Directory -Force -Path '{cert_dir}' | Out-Null

    # Generate self-signed certificate (2-year expiry)
    $cert = New-SelfSignedCertificate `
      -Subject 'CN=UserProvisioningTool' `
      -FriendlyName 'User Provisioning Tool - Graph API' `
      -CertStoreLocation 'Cert:\\CurrentUser\\My' `
      -KeyExportPolicy Exportable `
      -KeySpec Signature `
      -KeyLength 2048 `
      -KeyAlgorithm RSA `
      -HashAlgorithm SHA256 `
      -NotAfter (Get-Date).AddYears(2)

    # Export public key as CER (for uploading to Azure)
    Export-Certificate -Cert $cert -FilePath '{cer_path}' -Force | Out-Null

    # Export as PFX with password (works on all .NET Framework versions)
    $pfxPass = ConvertTo-SecureString -String '{pfx_password}' -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath '{pfx_path}' -Password $pfxPass -Force | Out-Null

    # Output thumbprint and paths for the caller
    $result = @{{
      thumbprint = $cert.Thumbprint
      cer_path = '{cer_path}'
      pfx_path = '{pfx_path}'
      expiry = $cert.NotAfter.ToString('yyyy-MM-dd')
      subject = $cert.Subject
    }}
    $result | ConvertTo-Json -Compress
    """

    logger.info("Generating self-signed certificate for Graph API...")
    success, stdout, stderr = run_powershell(script, timeout=30)

    if not success:
        logger.error("Certificate generation failed: %s", stderr)
        return False, "", f"Failed to generate certificate: {stderr[:300]}"

    try:
        data = json.loads(stdout)
        thumbprint = data.get("thumbprint", "")
        logger.info("Certificate generated -- thumbprint: %s", thumbprint)
    except json.JSONDecodeError:
        return False, "", f"Certificate may have been created but could not parse output: {stdout[:200]}"

    # Convert PFX to PEM using Python's cryptography library
    try:
        with open(pfx_path, "rb") as f:
            pfx_bytes = f.read()
        pem_content = _pfx_to_pem(pfx_bytes, pfx_password)

        # Write PEM to disk (will be DPAPI-encrypted and deleted below)
        with open(pem_path, "w", encoding="ascii") as f:
            f.write(pem_content)
        logger.info("PFX converted to PEM successfully")
    except Exception as e:
        logger.error("PFX to PEM conversion failed: %s", e)
        return False, thumbprint, f"Certificate generated (thumbprint: {thumbprint}) but PEM conversion failed: {e}"
    finally:
        # Always delete the PFX file -- it contains the private key
        try:
            os.remove(pfx_path)
        except OSError:
            pass

    # Auto-encrypt the PEM with DPAPI
    encrypt_success, encrypt_msg = dpapi_encrypt_file(pem_path, protected_path)
    if encrypt_success:
        logger.info("PEM auto-encrypted with DPAPI: %s", protected_path)
        encrypt_note = f"  Private key: {protected_path} (DPAPI-encrypted)\n"
    else:
        logger.warning("DPAPI encryption failed: %s", encrypt_msg)
        encrypt_note = (
            f"  Private key: {pem_path} (WARNING: not encrypted)\n"
            f"  DPAPI encryption failed: {encrypt_msg}\n"
        )

    return True, thumbprint, (
        f"Certificate generated successfully!\n\n"
        f"  Thumbprint:  {thumbprint}\n"
        f"{encrypt_note}"
        f"  Public key:  {data.get('cer_path', cer_path)}\n"
        f"  Expires:     {data.get('expiry', 'unknown')}\n\n"
        f"NEXT STEPS:\n"
        f"  1. Upload {cer_path} to your App Registration:\n"
        f"     portal.azure.com > Entra ID > App registrations >\n"
        f"     your app > Certificates & secrets > Upload certificate\n\n"
        f"  2. The thumbprint has been recorded: {thumbprint}\n\n"
        f"  3. Click 'Retry' to re-run preflight checks."
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SETUP WIZARD
# ══════════════════════════════════════════════════════════════════════════════

class SetupWizard(tk.Toplevel):
    """
    First-run setup wizard that collects customer-specific configuration
    and writes config.json. Presented as a multi-page dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.title("Setup Wizard — 365 User Provisioning")
        self.geometry("700x620")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

        self._completed = False
        self._current_page = 0
        self._collected = {}

        # Variables for wizard fields
        self.ad_domain_var = tk.StringVar()
        self.ad_netbios_var = tk.StringVar()
        self.email_domains_var = tk.StringVar()
        self.tenant_id_var = tk.StringVar()
        self.client_id_var = tk.StringVar()
        self.cert_thumbprint_var = tk.StringVar()
        self.cert_path_var = tk.StringVar(value=r"C:\Certs\graph_app.pem.protected")

        self._pages = []
        self._build_ui()
        self._show_page(0)

        # Auto-detect domain in background
        self.after(200, self._auto_detect_domain)

    def _build_ui(self):
        """Build the wizard UI with page container and navigation."""
        # Header
        self._header_label = ttk.Label(
            self, text="", font=("Segoe UI", 13, "bold"))
        self._header_label.pack(pady=(12, 2))

        self._subheader_label = ttk.Label(
            self, text="", foreground="gray", font=("Segoe UI", 9))
        self._subheader_label.pack(pady=(0, 8))

        # Page container
        self._page_frame = ttk.Frame(self, padding=15)
        self._page_frame.pack(fill="both", expand=True)

        # Build all pages (hidden initially)
        self._build_page_domain()
        self._build_page_m365()
        self._build_page_certificate()
        self._build_page_review()

        # Navigation buttons
        nav_frame = ttk.Frame(self, padding=(15, 8))
        nav_frame.pack(fill="x")

        self._back_btn = ttk.Button(nav_frame, text="Back", command=self._go_back)
        self._back_btn.pack(side="left", padx=5)

        self._next_btn = ttk.Button(nav_frame, text="Next", command=self._go_next)
        self._next_btn.pack(side="left", padx=5)

        ttk.Button(nav_frame, text="Cancel", command=self._on_cancel).pack(
            side="right", padx=5)

    def _build_page_domain(self):
        """Page 1: Domain Settings."""
        page = ttk.Frame(self._page_frame)
        self._pages.append(("Domain Settings", "Step 1 of 4", page))

        ttk.Label(page, text="AD Domain FQDN *", font=("Segoe UI", 10)).grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.ad_domain_var, width=40).grid(
            row=1, column=0, sticky="w", pady=(0, 8))
        ttk.Label(page, text="e.g. contoso.com (will be auto-detected if possible)",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=2, column=0, sticky="w", pady=(0, 12))

        ttk.Label(page, text="AD NetBIOS Name *", font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.ad_netbios_var, width=25).grid(
            row=4, column=0, sticky="w", pady=(0, 8))
        ttk.Label(page, text="e.g. CONTOSO (will be auto-detected if possible)",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=5, column=0, sticky="w", pady=(0, 12))

        ttk.Label(page, text="Email Domains (comma-separated) *",
                  font=("Segoe UI", 10)).grid(
            row=6, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.email_domains_var, width=50).grid(
            row=7, column=0, sticky="w", pady=(0, 8))
        ttk.Label(page, text="e.g. contoso.com, fabrikam.com",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=8, column=0, sticky="w")

        self._domain_detect_label = ttk.Label(page, text="", foreground="gray")
        self._domain_detect_label.grid(row=9, column=0, sticky="w", pady=(15, 0))

    def _build_page_m365(self):
        """Page 2: Microsoft 365 / Entra ID settings."""
        page = ttk.Frame(self._page_frame)
        self._pages.append(("Microsoft 365 / Entra ID", "Step 2 of 4", page))

        ttk.Label(page, text="Tenant ID (Directory ID) *",
                  font=("Segoe UI", 10)).grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.tenant_id_var, width=45).grid(
            row=1, column=0, sticky="w", pady=(0, 8))

        ttk.Label(page, text="Client ID (Application ID) *",
                  font=("Segoe UI", 10)).grid(
            row=2, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.client_id_var, width=45).grid(
            row=3, column=0, sticky="w", pady=(0, 12))

        # Instructions panel
        instructions_frame = ttk.LabelFrame(page, text=" How to get these values ",
                                             padding=8)
        instructions_frame.grid(row=4, column=0, sticky="ew", pady=(5, 0))

        instructions = scrolledtext.ScrolledText(
            instructions_frame, wrap="char", font=("Consolas", 8),
            height=12, bg="#1e1e1e", fg="#d4d4d4", relief="flat", state="normal")
        instructions.pack(fill="both", expand=True)

        instructions.insert("1.0", (
            "CREATE AN APP REGISTRATION\n"
            "==========================\n\n"
            "1. Sign in to portal.azure.com as a Global Admin\n"
            "2. Go to: Entra ID > App registrations > New registration\n"
            "3. Name: 'User Provisioning Tool'\n"
            "4. Supported account types: 'This organizational directory only'\n"
            "5. Click Register\n\n"
            "FROM THE OVERVIEW PAGE:\n"
            "  - Application (client) ID  -->  Client ID above\n"
            "  - Directory (tenant) ID    -->  Tenant ID above\n\n"
            "GRANT API PERMISSIONS:\n"
            "  1. API permissions > Add a permission > Microsoft Graph\n"
            "  2. Application permissions > add:\n"
            "     - User.ReadWrite.All\n"
            "     - Directory.ReadWrite.All\n"
            "     - Organization.Read.All\n"
            "     - Group.ReadWrite.All\n"
            "     - GroupMember.ReadWrite.All\n"
            "  3. Click 'Grant admin consent' (requires Global Admin)\n\n"
            "You will upload the certificate in the next step."
        ))
        instructions.configure(state="disabled")

    def _build_page_certificate(self):
        """Page 3: Certificate generation and configuration."""
        page = ttk.Frame(self._page_frame)
        self._pages.append(("Certificate", "Step 3 of 4", page))

        ttk.Label(page, text=(
            "A certificate is needed to authenticate to Microsoft 365.\n"
            "Click 'Generate Certificate' to create one automatically."),
            font=("Segoe UI", 10), wraplength=600, justify="left").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self._gen_cert_wizard_btn = ttk.Button(
            page, text="Generate Certificate", command=self._on_wizard_generate_cert)
        self._gen_cert_wizard_btn.grid(row=1, column=0, sticky="w", pady=(0, 8))

        self._cert_status_label = ttk.Label(page, text="", foreground="gray",
                                             wraplength=600)
        self._cert_status_label.grid(row=2, column=0, columnspan=2, sticky="w",
                                      pady=(0, 12))

        ttk.Label(page, text="Certificate Thumbprint *",
                  font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.cert_thumbprint_var, width=50).grid(
            row=4, column=0, sticky="w", pady=(0, 8))
        ttk.Label(page, text="Auto-filled after generation, or enter manually",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=5, column=0, sticky="w", pady=(0, 12))

        ttk.Label(page, text="Certificate Path",
                  font=("Segoe UI", 10)).grid(
            row=6, column=0, sticky="w", pady=(0, 2))
        ttk.Entry(page, textvariable=self.cert_path_var, width=55).grid(
            row=7, column=0, sticky="w", pady=(0, 8))
        ttk.Label(page, text="Path to the DPAPI-encrypted .pem.protected file",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=8, column=0, sticky="w")

        # Instructions for Azure upload
        ttk.Label(page, text=(
            "\nAfter generating, upload the .cer file to Azure:\n"
            "  portal.azure.com > Entra ID > App registrations >\n"
            "  your app > Certificates & secrets > Upload certificate"),
            foreground="gray", font=("Segoe UI", 9), wraplength=600,
            justify="left").grid(
            row=9, column=0, columnspan=2, sticky="w", pady=(8, 0))

    def _build_page_review(self):
        """Page 4: Review and save."""
        page = ttk.Frame(self._page_frame)
        self._pages.append(("Review & Save", "Step 4 of 4", page))

        ttk.Label(page, text="Review your configuration before saving:",
                  font=("Segoe UI", 10)).grid(
            row=0, column=0, sticky="w", pady=(0, 8))

        self._review_text = scrolledtext.ScrolledText(
            page, wrap="char", font=("Consolas", 9),
            height=16, bg="#1e1e1e", fg="#d4d4d4", relief="flat", state="disabled")
        self._review_text.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        page.rowconfigure(1, weight=1)
        page.columnconfigure(0, weight=1)

        self._save_btn = ttk.Button(page, text="Save Configuration",
                                     command=self._on_save)
        self._save_btn.grid(row=2, column=0, sticky="w", pady=(0, 5))

        self._save_status_label = ttk.Label(page, text="", foreground="gray")
        self._save_status_label.grid(row=3, column=0, sticky="w")

    def _show_page(self, index: int):
        """Display the specified wizard page."""
        # Hide all pages
        for _, _, page_frame in self._pages:
            page_frame.pack_forget()

        self._current_page = index
        title, subtitle, page_frame = self._pages[index]
        self._header_label.configure(text=title)
        self._subheader_label.configure(text=subtitle)
        page_frame.pack(fill="both", expand=True)

        # Update nav button states
        self._back_btn.configure(state="normal" if index > 0 else "disabled")

        if index == len(self._pages) - 1:
            self._next_btn.configure(state="disabled")
            self._populate_review()
        else:
            self._next_btn.configure(state="normal")

    def _go_next(self):
        if self._current_page < len(self._pages) - 1:
            self._show_page(self._current_page + 1)

    def _go_back(self):
        if self._current_page > 0:
            self._show_page(self._current_page - 1)

    def _auto_detect_domain(self):
        """Try to auto-detect AD domain and NetBIOS from the current machine."""
        self._domain_detect_label.configure(text="Detecting domain...",
                                             foreground="blue")

        def detect():
            script = """
            try {
              Import-Module ActiveDirectory -ErrorAction Stop
              $d = Get-ADDomain
              $result = @{
                fqdn = $d.DNSRoot
                netbios = $d.NetBIOSName
              }
              $result | ConvertTo-Json -Compress
            } catch {
              Write-Output '{}'
            }
            """
            return run_powershell(script, timeout=15)

        def on_result(result):
            success, stdout, _ = result
            if success and stdout and stdout != "{}":
                try:
                    data = json.loads(stdout)
                    fqdn = data.get("fqdn", "")
                    netbios = data.get("netbios", "")
                    if fqdn and not self.ad_domain_var.get():
                        self.ad_domain_var.set(fqdn)
                    if netbios and not self.ad_netbios_var.get():
                        self.ad_netbios_var.set(netbios)
                    if fqdn and not self.email_domains_var.get():
                        self.email_domains_var.set(fqdn)
                    self._domain_detect_label.configure(
                        text=f"Auto-detected: {fqdn} ({netbios})",
                        foreground="green")
                    return
                except json.JSONDecodeError:
                    pass
            self._domain_detect_label.configure(
                text="Could not auto-detect domain. Enter values manually.",
                foreground="orange")

        def wrapper():
            try:
                result = detect()
                self.after(0, on_result, result)
            except Exception:
                self.after(0, lambda: self._domain_detect_label.configure(
                    text="Auto-detection failed. Enter values manually.",
                    foreground="orange"))

        threading.Thread(target=wrapper, daemon=True).start()

    def _on_wizard_generate_cert(self):
        """Generate a certificate from the wizard."""
        self._gen_cert_wizard_btn.configure(state="disabled", text="Generating...")
        self._cert_status_label.configure(text="Generating certificate...",
                                           foreground="blue")

        # Derive the PEM path (without .protected) for generation
        cert_path = self.cert_path_var.get().strip()
        if not cert_path:
            cert_path = r"C:\Certs\graph_app.pem.protected"
            self.cert_path_var.set(cert_path)

        def do_gen():
            return generate_certificate_on_dc(cert_path)

        def on_done(result):
            success, thumbprint, message = result
            self._gen_cert_wizard_btn.configure(
                state="normal", text="Generate Certificate")
            if success:
                self.cert_thumbprint_var.set(thumbprint)
                self._cert_status_label.configure(
                    text=f"Certificate generated. Thumbprint: {thumbprint}",
                    foreground="green")
            else:
                self._cert_status_label.configure(
                    text=f"Failed: {message[:200]}", foreground="red")

        def wrapper():
            try:
                result = do_gen()
                self.after(0, on_done, result)
            except Exception as e:
                self.after(0, lambda: self._cert_status_label.configure(
                    text=f"Error: {e}", foreground="red"))
                self.after(0, lambda: self._gen_cert_wizard_btn.configure(
                    state="normal", text="Generate Certificate"))

        threading.Thread(target=wrapper, daemon=True).start()

    def _populate_review(self):
        """Fill the review page with collected values."""
        email_domains = [d.strip() for d in self.email_domains_var.get().split(",")
                         if d.strip()]

        review = (
            f"AD Domain:        {self.ad_domain_var.get()}\n"
            f"AD NetBIOS:       {self.ad_netbios_var.get()}\n"
            f"Email Domains:    {', '.join(email_domains)}\n"
            f"\n"
            f"Tenant ID:        {self.tenant_id_var.get()}\n"
            f"Client ID:        {self.client_id_var.get()}\n"
            f"Cert Thumbprint:  {self.cert_thumbprint_var.get()}\n"
            f"Cert Path:        {self.cert_path_var.get()}\n"
            f"\n"
            f"Config will be saved to:\n"
            f"  {CONFIG_PATH}\n"
            f"\n"
            f"AFTER SAVING:\n"
            f"  1. Upload the .cer file to your App Registration in Azure\n"
            f"  2. Grant admin consent on the API permissions\n"
            f"  3. Re-run the preflight checks"
        )

        self._review_text.configure(state="normal")
        self._review_text.delete("1.0", "end")
        self._review_text.insert("1.0", review)
        self._review_text.configure(state="disabled")

    def _on_save(self):
        """Validate and save config.json."""
        # Validate required fields
        errors = []
        if not self.ad_domain_var.get().strip():
            errors.append("AD Domain is required")
        if not self.ad_netbios_var.get().strip():
            errors.append("AD NetBIOS name is required")
        if not self.email_domains_var.get().strip():
            errors.append("At least one email domain is required")
        if not self.tenant_id_var.get().strip():
            errors.append("Tenant ID is required")
        if not self.client_id_var.get().strip():
            errors.append("Client ID is required")
        if not self.cert_thumbprint_var.get().strip():
            errors.append("Certificate thumbprint is required")

        if errors:
            messagebox.showerror("Validation Error",
                                 "\n".join(f"- {e}" for e in errors))
            return

        email_domains = [d.strip() for d in self.email_domains_var.get().split(",")
                         if d.strip()]

        config_data = {
            "ad_domain": self.ad_domain_var.get().strip(),
            "ad_netbios": self.ad_netbios_var.get().strip(),
            "email_domains": email_domains,
            "adsync_server": None,
            "graph_tenant_id": self.tenant_id_var.get().strip(),
            "graph_client_id": self.client_id_var.get().strip(),
            "graph_cert_thumbprint": self.cert_thumbprint_var.get().strip(),
            "graph_cert_path": self.cert_path_var.get().strip(),
            "password_min_length": DEFAULTS["password_min_length"],
            "password_require_upper": DEFAULTS["password_require_upper"],
            "password_require_lower": DEFAULTS["password_require_lower"],
            "password_require_digit": DEFAULTS["password_require_digit"],
            "password_require_special": DEFAULTS["password_require_special"],
            "entra_poll_interval_seconds": DEFAULTS["entra_poll_interval_seconds"],
            "entra_poll_timeout_seconds": DEFAULTS["entra_poll_timeout_seconds"],
        }

        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2)
            logger.info("config.json saved to %s", CONFIG_PATH)
        except OSError as e:
            messagebox.showerror("Save Error", f"Could not write config.json:\n{e}")
            return

        # Reload config into the global cfg dict
        global cfg
        cfg = load_config()

        self._save_status_label.configure(
            text=f"Saved to {CONFIG_PATH}", foreground="green")
        self._completed = True

        messagebox.showinfo(
            "Configuration Saved",
            f"config.json has been saved.\n\n"
            f"Next steps:\n"
            f"1. Upload the .cer file to your App Registration in Azure\n"
            f"2. Grant admin consent on the API permissions\n"
            f"3. Close this wizard and click 'Retry All Checks'"
        )
        self.destroy()

    def _on_cancel(self):
        self.destroy()

    @property
    def completed(self) -> bool:
        return self._completed


# ══════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class ProvisioningApp(tk.Tk):
    """Main GUI application for user provisioning."""

    def __init__(self):
        super().__init__()
        domain_display = cfg.get("ad_domain", "")
        if domain_display:
            self.title(f"365 User Provisioning \u2014 {domain_display}")
        else:
            self.title("365 User Provisioning Tool")
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

    # -- UI Construction ---------------------------------------------------

    def _build_ui(self):
        """Construct the full GUI layout in a two-column, landscape format."""

        # -- Progress & Status (bottom, always visible) --------------------
        status_frame = ttk.Frame(self, padding=(10, 3))
        status_frame.pack(fill="x", side="bottom")

        self.progress_bar = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress_bar.pack(fill="x")
        self.status_label = ttk.Label(status_frame, text="Ready", foreground="gray")
        self.status_label.pack(fill="x", pady=(2, 0))

        # -- Action Buttons (bottom, above status) -------------------------
        action_frame = ttk.Frame(self, padding=(10, 5))
        action_frame.pack(fill="x", side="bottom")

        self.provision_btn = ttk.Button(action_frame, text="Provision User",
                                         command=self._on_provision_click)
        self.provision_btn.pack(side="left", padx=(0, 10))
        ttk.Button(action_frame, text="Clear Form",
                    command=self._clear_form).pack(side="left")
        self.cancel_btn = ttk.Button(action_frame, text="Cancel", state="disabled",
                                      command=self._on_cancel_click)
        self.cancel_btn.pack(side="left", padx=(10, 0))

        # -- Main two-column layout ----------------------------------------
        main = ttk.Frame(self, padding=5)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(5, 3))
        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="nsew", padx=(3, 5))

        p = {"padx": 0, "pady": 3}
        email_domains = cfg.get("email_domains", [])

        # ===================== LEFT COLUMN ================================

        # -- User Information ----------------------------------------------
        frame_user = ttk.LabelFrame(left, text=" User Information ", padding=8)
        frame_user.pack(fill="x", **p)

        self.first_name_var = tk.StringVar()
        self.last_name_var = tk.StringVar()
        self.display_name_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.email_domain_var = tk.StringVar(
            value=email_domains[0] if email_domains else "")
        self.job_title_var = tk.StringVar()
        self.department_var = tk.StringVar()

        self.first_name_var.trace_add("write", self._on_name_change)
        self.last_name_var.trace_add("write", self._on_name_change)

        r = 0
        ttk.Label(frame_user, text="First Name *").grid(row=r, column=0, sticky="w")
        ttk.Entry(frame_user, textvariable=self.first_name_var, width=20).grid(
            row=r, column=1, sticky="ew", padx=(0, 8))
        ttk.Label(frame_user, text="Last Name *").grid(row=r, column=2, sticky="w")
        ttk.Entry(frame_user, textvariable=self.last_name_var, width=20).grid(
            row=r, column=3, sticky="ew")

        r += 1
        ttk.Label(frame_user, text="Display Name *").grid(row=r, column=0, sticky="w", pady=(3, 0))
        ttk.Entry(frame_user, textvariable=self.display_name_var, width=20).grid(
            row=r, column=1, sticky="ew", pady=(3, 0), padx=(0, 8))
        ttk.Label(frame_user, text="Email *").grid(row=r, column=2, sticky="w", pady=(3, 0))
        self.email_combo = ttk.Combobox(frame_user, textvariable=self.email_domain_var,
                                         values=email_domains, width=17)
        self.email_combo.grid(row=r, column=3, sticky="ew", pady=(3, 0))

        r += 1
        ttk.Label(frame_user, text="Username *").grid(row=r, column=0, sticky="w", pady=(3, 0))
        ttk.Entry(frame_user, textvariable=self.username_var, width=20).grid(
            row=r, column=1, sticky="ew", pady=(3, 0), padx=(0, 8))
        self.check_user_btn = ttk.Button(frame_user, text="Check", width=7,
                                          command=self._check_username)
        self.check_user_btn.grid(row=r, column=2, sticky="w", pady=(3, 0))
        self.username_status_label = ttk.Label(frame_user, text="")
        self.username_status_label.grid(row=r, column=3, sticky="w", pady=(3, 0))

        r += 1
        ttk.Label(frame_user, text="Job Title").grid(row=r, column=0, sticky="w", pady=(3, 0))
        ttk.Entry(frame_user, textvariable=self.job_title_var, width=20).grid(
            row=r, column=1, sticky="ew", pady=(3, 0), padx=(0, 8))
        ttk.Label(frame_user, text="Department").grid(row=r, column=2, sticky="w", pady=(3, 0))
        ttk.Entry(frame_user, textvariable=self.department_var, width=20).grid(
            row=r, column=3, sticky="ew", pady=(3, 0))

        frame_user.columnconfigure(1, weight=1)
        frame_user.columnconfigure(3, weight=1)

        # -- Password ------------------------------------------------------
        frame_pw = ttk.LabelFrame(left, text=" Password ", padding=8)
        frame_pw.pack(fill="x", **p)

        self.password_var = tk.StringVar()
        self.password_confirm_var = tk.StringVar()
        self.force_change_var = tk.BooleanVar(value=True)

        ttk.Label(frame_pw, text="Password *").grid(row=0, column=0, sticky="w")
        pw_entry = ttk.Entry(frame_pw, textvariable=self.password_var, show="*", width=22)
        pw_entry.grid(row=0, column=1, sticky="ew")
        self._show_pw_var = tk.BooleanVar(value=False)
        self._pw_entry = pw_entry
        ttk.Checkbutton(frame_pw, text="Show", variable=self._show_pw_var,
                         command=self._toggle_password_visibility).grid(row=0, column=2, padx=(3, 0))
        ttk.Button(frame_pw, text="Generate", width=8,
                    command=self._generate_password).grid(row=0, column=3, padx=(3, 0))

        ttk.Label(frame_pw, text="Confirm *").grid(row=1, column=0, sticky="w", pady=(3, 0))
        self._pw_confirm_entry = ttk.Entry(frame_pw, textvariable=self.password_confirm_var,
                                            show="*", width=22)
        self._pw_confirm_entry.grid(row=1, column=1, sticky="ew", pady=(3, 0))
        self.pw_strength_label = ttk.Label(frame_pw, text="", foreground="gray")
        self.pw_strength_label.grid(row=1, column=2, columnspan=2, sticky="w", padx=(5, 0), pady=(3, 0))
        self.password_var.trace_add("write", self._on_password_change)

        ttk.Checkbutton(frame_pw, text="Force password change at next logon",
                         variable=self.force_change_var).grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(3, 0))
        frame_pw.columnconfigure(1, weight=1)

        # -- Microsoft 365 Licensing ---------------------------------------
        frame_lic = ttk.LabelFrame(left, text=" Microsoft 365 Licensing ", padding=8)
        frame_lic.pack(fill="x", **p)

        self.license_var = tk.StringVar()
        ttk.Label(frame_lic, text="License").grid(row=0, column=0, sticky="w")
        lic_row = ttk.Frame(frame_lic)
        lic_row.grid(row=0, column=1, sticky="ew")
        self.license_combo = ttk.Combobox(lic_row, textvariable=self.license_var,
                                           width=35, state="readonly")
        self.license_combo.pack(side="left", fill="x", expand=True)
        self.license_combo.bind("<<ComboboxSelected>>", self._on_license_change)
        ttk.Button(lic_row, text="Refresh", width=7,
                    command=self._refresh_licenses).pack(side="left", padx=(3, 0))

        self.license_seats_label = ttk.Label(frame_lic, text="", foreground="gray")
        self.license_seats_label.grid(row=1, column=1, sticky="w")

        self.service_plans_frame = ttk.Frame(frame_lic)
        self.service_plans_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(3, 0))
        self._service_plan_vars = {}
        frame_lic.columnconfigure(1, weight=1)

        # -- Entra Connect Sync --------------------------------------------
        frame_sync = ttk.LabelFrame(left, text=" Entra Connect Sync ", padding=8)
        frame_sync.pack(fill="x", **p)

        self.sync_server_label = ttk.Label(frame_sync, text="Detecting...", foreground="gray")
        self.sync_server_label.grid(row=0, column=0, columnspan=3, sticky="w")

        ttk.Label(frame_sync, text="Override:").grid(row=1, column=0, sticky="w", pady=(3, 0))
        self.sync_server_override_var = tk.StringVar()
        ttk.Entry(frame_sync, textvariable=self.sync_server_override_var, width=25).grid(
            row=1, column=1, sticky="ew", pady=(3, 0))

        self.skip_sync_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_sync, text="Skip sync",
                         variable=self.skip_sync_var).grid(
            row=1, column=2, sticky="w", padx=(8, 0), pady=(3, 0))
        frame_sync.columnconfigure(1, weight=1)

        # ===================== RIGHT COLUMN ===============================

        # -- Copy Groups From Existing User --------------------------------
        frame_copy = ttk.LabelFrame(right, text=" Copy Groups From User ", padding=8)
        frame_copy.pack(fill="x", **p)

        self.copy_user_search_var = tk.StringVar()
        copy_row = ttk.Frame(frame_copy)
        copy_row.pack(fill="x")
        ttk.Entry(copy_row, textvariable=self.copy_user_search_var, width=22).pack(
            side="left", fill="x", expand=True)
        ttk.Button(copy_row, text="Lookup", width=7,
                    command=self._copy_from_user_search).pack(side="left", padx=(3, 0))

        self.copy_user_results = tk.Listbox(frame_copy, height=3, exportselection=False)
        self.copy_user_results.pack(fill="x")
        self.copy_user_results.pack_forget()  # hidden by default
        self.copy_user_results.bind("<<ListboxSelect>>", self._on_copy_user_select)
        self._copy_user_matches = []  # list of (display, dn, upn)

        self.copy_status_label = ttk.Label(frame_copy, text="", foreground="gray")
        self.copy_status_label.pack(anchor="w")

        # -- Active Directory (OU + Groups + Manager) ----------------------
        frame_ad = ttk.LabelFrame(right, text=" Active Directory ", padding=8)
        frame_ad.pack(fill="both", expand=True, **p)

        self.ou_var = tk.StringVar()
        ttk.Label(frame_ad, text="OU *").grid(row=0, column=0, sticky="w")
        self.ou_combo = ttk.Combobox(frame_ad, textvariable=self.ou_var, width=45, state="readonly")
        self.ou_combo.grid(row=0, column=1, columnspan=2, sticky="ew")
        self._ou_map = {}

        # AD Groups filter
        ttk.Label(frame_ad, text="Filter:").grid(row=1, column=0, sticky="w", pady=(3, 0))
        self.ad_group_filter_var = tk.StringVar()
        ttk.Entry(frame_ad, textvariable=self.ad_group_filter_var, width=20).grid(
            row=1, column=1, columnspan=2, sticky="ew", pady=(3, 0))
        self.ad_group_filter_var.trace_add("write", self._on_ad_group_filter)

        # AD Groups tabbed by type
        self.ad_notebook = ttk.Notebook(frame_ad)
        self.ad_notebook.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(3, 0))

        # Security tab
        ad_sec_frame = ttk.Frame(self.ad_notebook)
        self.ad_notebook.add(ad_sec_frame, text="Security")
        self.ad_security_listbox = tk.Listbox(ad_sec_frame, selectmode="multiple",
                                               height=4, exportselection=False)
        ad_sec_scroll = ttk.Scrollbar(ad_sec_frame, orient="vertical",
                                       command=self.ad_security_listbox.yview)
        self.ad_security_listbox.configure(yscrollcommand=ad_sec_scroll.set)
        self.ad_security_listbox.pack(side="left", fill="both", expand=True)
        ad_sec_scroll.pack(side="left", fill="y")

        # Distribution tab
        ad_dist_frame = ttk.Frame(self.ad_notebook)
        self.ad_notebook.add(ad_dist_frame, text="Distribution")
        self.ad_distribution_listbox = tk.Listbox(ad_dist_frame, selectmode="multiple",
                                                    height=4, exportselection=False)
        ad_dist_scroll = ttk.Scrollbar(ad_dist_frame, orient="vertical",
                                        command=self.ad_distribution_listbox.yview)
        self.ad_distribution_listbox.configure(yscrollcommand=ad_dist_scroll.set)
        self.ad_distribution_listbox.pack(side="left", fill="both", expand=True)
        ad_dist_scroll.pack(side="left", fill="y")

        # Group data maps (index -> dn, per tab, per filter state)
        self._ad_security_map = {}
        self._ad_distribution_map = {}
        self._ad_groups_all = []  # full unfiltered list from AD

        # Manager search
        self.manager_search_var = tk.StringVar()
        self.manager_dn_var = tk.StringVar()
        self.manager_display_var = tk.StringVar()

        ttk.Label(frame_ad, text="Manager").grid(row=3, column=0, sticky="w", pady=(3, 0))
        mgr_frame = ttk.Frame(frame_ad)
        mgr_frame.grid(row=3, column=1, columnspan=2, sticky="ew", pady=(3, 0))
        ttk.Entry(mgr_frame, textvariable=self.manager_search_var, width=22).pack(
            side="left", fill="x", expand=True)
        ttk.Button(mgr_frame, text="Search", width=7,
                    command=self._search_manager).pack(side="left", padx=(3, 0))

        self.manager_selected_label = ttk.Label(frame_ad, textvariable=self.manager_display_var,
                                                  foreground="green")
        self.manager_selected_label.grid(row=4, column=1, columnspan=2, sticky="w")

        self.manager_results_listbox = tk.Listbox(frame_ad, height=3, exportselection=False)
        self.manager_results_listbox.grid(row=5, column=1, columnspan=2, sticky="ew")
        self.manager_results_listbox.grid_remove()
        self.manager_results_listbox.bind("<<ListboxSelect>>", self._on_manager_select)
        self._manager_results = []

        frame_ad.columnconfigure(1, weight=1)
        frame_ad.rowconfigure(2, weight=1)

        # -- Cloud Groups (Entra ID) --------------------------------------
        frame_cloud = ttk.LabelFrame(right, text=" Cloud Groups (Entra ID) ", padding=8)
        frame_cloud.pack(fill="both", expand=True, **p)

        # Cloud filter
        filter_row = ttk.Frame(frame_cloud)
        filter_row.pack(fill="x")
        ttk.Label(filter_row, text="Filter:").pack(side="left")
        self.cloud_group_filter_var = tk.StringVar()
        ttk.Entry(filter_row, textvariable=self.cloud_group_filter_var, width=20).pack(
            side="left", fill="x", expand=True, padx=(3, 0))
        self.cloud_group_filter_var.trace_add("write", self._on_cloud_group_filter)

        # Cloud tabbed by type
        self.cloud_notebook = ttk.Notebook(frame_cloud)
        self.cloud_notebook.pack(fill="both", expand=True, pady=(3, 0))

        # Security tab
        cl_sec_frame = ttk.Frame(self.cloud_notebook)
        self.cloud_notebook.add(cl_sec_frame, text="Security")
        self.cloud_security_listbox = tk.Listbox(cl_sec_frame, selectmode="multiple",
                                                   height=4, exportselection=False)
        cl_sec_scroll = ttk.Scrollbar(cl_sec_frame, orient="vertical",
                                       command=self.cloud_security_listbox.yview)
        self.cloud_security_listbox.configure(yscrollcommand=cl_sec_scroll.set)
        self.cloud_security_listbox.pack(side="left", fill="both", expand=True)
        cl_sec_scroll.pack(side="left", fill="y")

        # M365 tab
        cl_m365_frame = ttk.Frame(self.cloud_notebook)
        self.cloud_notebook.add(cl_m365_frame, text="M365")
        self.cloud_m365_listbox = tk.Listbox(cl_m365_frame, selectmode="multiple",
                                               height=4, exportselection=False)
        cl_m365_scroll = ttk.Scrollbar(cl_m365_frame, orient="vertical",
                                        command=self.cloud_m365_listbox.yview)
        self.cloud_m365_listbox.configure(yscrollcommand=cl_m365_scroll.set)
        self.cloud_m365_listbox.pack(side="left", fill="both", expand=True)
        cl_m365_scroll.pack(side="left", fill="y")

        # Distribution tab
        cl_dist_frame = ttk.Frame(self.cloud_notebook)
        self.cloud_notebook.add(cl_dist_frame, text="Distribution")
        self.cloud_distribution_listbox = tk.Listbox(cl_dist_frame, selectmode="multiple",
                                                       height=4, exportselection=False)
        cl_dist_scroll = ttk.Scrollbar(cl_dist_frame, orient="vertical",
                                        command=self.cloud_distribution_listbox.yview)
        self.cloud_distribution_listbox.configure(yscrollcommand=cl_dist_scroll.set)
        self.cloud_distribution_listbox.pack(side="left", fill="both", expand=True)
        cl_dist_scroll.pack(side="left", fill="y")

        # Cloud group data maps
        self._cloud_security_map = {}
        self._cloud_m365_map = {}
        self._cloud_distribution_map = {}
        self._cloud_groups_all = []  # full unfiltered list

        self.cloud_groups_status = ttk.Label(frame_cloud, text="Loading...", foreground="gray")
        self.cloud_groups_status.pack(anchor="w")

    # -- Startup Data Loading ----------------------------------------------

    def _load_startup_data(self):
        """Load AD and Graph data in background threads on startup."""
        self._run_in_thread(self._load_ad_ous, on_complete=self._populate_ous)
        self._run_in_thread(self._load_ad_groups, on_complete=self._populate_ad_groups)
        self._run_in_thread(self._load_upn_suffixes, on_complete=self._populate_email_domains)
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
            # Default to the domain root (shortest canonical path = shallowest OU)
            default_idx = 0
            shortest_len = len(display_values[0])
            for i, val in enumerate(display_values):
                if len(val) < shortest_len:
                    shortest_len = len(val)
                    default_idx = i
            self.ou_combo.current(default_idx)

    def _load_upn_suffixes(self):
        return get_ad_upn_suffixes()

    def _populate_email_domains(self, ad_suffixes):
        """Merge AD UPN suffixes with config email_domains for the dropdown."""
        config_domains = cfg.get("email_domains", [])
        # Combine: config domains first, then any AD suffixes not already listed
        all_domains = list(config_domains)
        for suffix in ad_suffixes:
            if suffix.lower() not in [d.lower() for d in all_domains]:
                all_domains.append(suffix)
        if all_domains:
            self.email_combo["values"] = all_domains
            # Keep current selection if valid, otherwise select first
            if not self.email_domain_var.get() or \
               self.email_domain_var.get() not in all_domains:
                self.email_domain_var.set(all_domains[0])

    def _load_ad_groups(self):
        return get_ad_groups()

    def _populate_ad_groups(self, groups):
        self._ad_groups_all = groups
        self._render_ad_groups()

    def _render_ad_groups(self, filter_text=""):
        """Render AD groups into tabbed listboxes, filtered by search text."""
        ft = filter_text.lower()

        self.ad_security_listbox.delete(0, "end")
        self.ad_distribution_listbox.delete(0, "end")
        self._ad_security_map = {}
        self._ad_distribution_map = {}

        sec_idx = 0
        dist_idx = 0
        for g in self._ad_groups_all:
            name = g.get("name", "")
            desc = g.get("description", "") or ""
            display = f"{name} -- {desc[:40]}" if desc else name

            # Apply filter
            if ft and ft not in name.lower() and ft not in desc.lower():
                continue

            category = g.get("category", "Security")
            if category == "Distribution":
                self.ad_distribution_listbox.insert("end", display)
                self._ad_distribution_map[dist_idx] = g.get("dn", "")
                dist_idx += 1
            else:
                self.ad_security_listbox.insert("end", display)
                self._ad_security_map[sec_idx] = g.get("dn", "")
                sec_idx += 1

    def _load_cloud_groups(self):
        try:
            return get_cloud_groups()
        except Exception as e:
            logger.warning("Could not load cloud groups: %s", e)
            return []

    def _populate_cloud_groups(self, groups):
        self._cloud_groups_all = groups
        if not groups:
            self.cloud_groups_status.configure(
                text="No cloud-only groups found (all groups may be synced from AD)",
                foreground="gray")
            self._render_cloud_groups()
            return

        self._render_cloud_groups()
        self.cloud_groups_status.configure(
            text=f"{len(groups)} cloud groups loaded", foreground="green")

    def _render_cloud_groups(self, filter_text=""):
        """Render cloud groups into tabbed listboxes, filtered by search text."""
        ft = filter_text.lower()

        self.cloud_security_listbox.delete(0, "end")
        self.cloud_m365_listbox.delete(0, "end")
        self.cloud_distribution_listbox.delete(0, "end")
        self._cloud_security_map = {}
        self._cloud_m365_map = {}
        self._cloud_distribution_map = {}

        sec_idx = m365_idx = dist_idx = 0
        for g in self._cloud_groups_all:
            name = g.get("display_name", "")
            desc = g.get("description", "") or ""

            if ft and ft not in name.lower() and ft not in desc.lower():
                continue

            entry = (g["id"], name)
            gtype = g.get("group_type", "Security")

            if gtype == "M365":
                self.cloud_m365_listbox.insert("end", name)
                self._cloud_m365_map[m365_idx] = entry
                m365_idx += 1
            elif gtype == "Distribution":
                self.cloud_distribution_listbox.insert("end", name)
                self._cloud_distribution_map[dist_idx] = entry
                dist_idx += 1
            else:
                self.cloud_security_listbox.insert("end", name)
                self._cloud_security_map[sec_idx] = entry
                sec_idx += 1

    def _load_licenses(self):
        try:
            return get_available_licenses()
        except Exception as e:
            logger.warning("Could not load licenses: %s", e)
            return []

    def _populate_licenses(self, licenses):
        self._licenses = licenses
        values = ["(None \u2014 skip licensing)"]
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
                text="Not detected \u2014 enter manually or skip sync", foreground="orange")

    # -- Event Handlers ----------------------------------------------------

    def _on_ad_group_filter(self, *_args):
        """Re-render AD groups filtered by search text."""
        self._render_ad_groups(self.ad_group_filter_var.get().strip())

    def _on_cloud_group_filter(self, *_args):
        """Re-render cloud groups filtered by search text."""
        self._render_cloud_groups(self.cloud_group_filter_var.get().strip())

    def _copy_from_user_search(self):
        """Search AD for a user to copy groups from."""
        term = self.copy_user_search_var.get().strip()
        if not term:
            return

        def search():
            safe_term = sanitize_for_powershell(term)
            # Search across Name, DisplayName, SamAccountName, and UPN
            script = f"""
            Import-Module ActiveDirectory
            $term = '*{safe_term}*'
            $users = Get-ADUser -Filter {{
                Name -like $term -or
                DisplayName -like $term -or
                SamAccountName -like $term -or
                UserPrincipalName -like $term
            }} -Properties DisplayName, Title, UserPrincipalName |
              Select-Object -First 20
            $users | Select-Object @{{N='display_name';E={{$_.DisplayName}}}}, @{{N='dn';E={{$_.DistinguishedName}}}}, @{{N='sam';E={{$_.SamAccountName}}}}, @{{N='title';E={{$_.Title}}}}, @{{N='upn';E={{$_.UserPrincipalName}}}} | ConvertTo-Json -Compress
            """
            success, stdout, stderr = run_powershell(script, timeout=15)
            if not success:
                return []
            try:
                data = json.loads(stdout) if stdout else []
                if isinstance(data, dict):
                    data = [data]
                return data
            except json.JSONDecodeError:
                return []

        def on_result(users):
            self._copy_user_matches = []
            self.copy_user_results.delete(0, "end")
            if not users:
                self.copy_user_results.insert("end", "(no results)")
                self.copy_user_results.pack(fill="x")
                return
            for u in users:
                display = u.get("display_name", "")
                title = u.get("title", "")
                label = f"{display} ({title})" if title else display
                self._copy_user_matches.append((
                    display,
                    u.get("sam", ""),
                    u.get("upn", ""),
                ))
                self.copy_user_results.insert("end", label)
            self.copy_user_results.pack(fill="x")

        self._run_in_thread(search, on_complete=on_result)

    def _on_copy_user_select(self, event):
        """When a user is selected from copy-from results, fetch and apply their groups."""
        selection = self.copy_user_results.curselection()
        if not selection or not self._copy_user_matches:
            return
        idx = selection[0]
        if idx >= len(self._copy_user_matches):
            return

        display, user_sam, user_upn = self._copy_user_matches[idx]
        self.copy_user_results.pack_forget()
        self.copy_status_label.configure(text=f"Loading groups for {display}...",
                                          foreground="blue")

        def fetch_groups():
            ad_group_dns = get_user_ad_groups(user_sam) if user_sam else []
            cloud_group_ids = get_user_cloud_groups(user_upn) if user_upn else []
            return ad_group_dns, cloud_group_ids

        def on_result(result):
            ad_group_dns, cloud_group_ids = result
            ad_count = self._select_ad_groups_by_dn(ad_group_dns)
            cloud_count = self._select_cloud_groups_by_id(cloud_group_ids)
            self.copy_status_label.configure(
                text=f"Copied {ad_count} AD + {cloud_count} cloud groups from {display}",
                foreground="green")

        self._run_in_thread(fetch_groups, on_complete=on_result)

    def _select_ad_groups_by_dn(self, group_dns: list) -> int:
        """Auto-select AD groups across all tabs by DN. Returns count selected."""
        dn_set = set(d.lower() for d in group_dns)
        logger.info("Matching %d user group DNs against %d security + %d distribution groups",
                     len(dn_set), len(self._ad_security_map), len(self._ad_distribution_map))
        count = 0
        for idx, dn in self._ad_security_map.items():
            if dn.lower() in dn_set:
                self.ad_security_listbox.selection_set(idx)
                count += 1
        for idx, dn in self._ad_distribution_map.items():
            if dn.lower() in dn_set:
                self.ad_distribution_listbox.selection_set(idx)
                count += 1
        if count == 0 and dn_set:
            # Log a sample for debugging
            sample_user_dn = next(iter(dn_set))
            sample_map_dn = next(iter(self._ad_security_map.values()), "(empty)")
            logger.warning("No AD group matches. Sample user group: %s | Sample map entry: %s",
                           sample_user_dn, sample_map_dn)
        return count

    def _select_cloud_groups_by_id(self, group_ids: list) -> int:
        """Auto-select cloud groups across all tabs by ID. Returns count selected."""
        id_set = set(group_ids)
        count = 0
        for idx, (gid, _) in self._cloud_security_map.items():
            if gid in id_set:
                self.cloud_security_listbox.selection_set(idx)
                count += 1
        for idx, (gid, _) in self._cloud_m365_map.items():
            if gid in id_set:
                self.cloud_m365_listbox.selection_set(idx)
                count += 1
        for idx, (gid, _) in self._cloud_distribution_map.items():
            if gid in id_set:
                self.cloud_distribution_listbox.selection_set(idx)
                count += 1
        return count

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
                text=f"0 available / {total} total \u2014 provision licenses in M365 admin center",
                foreground="red")

        # Show service plan checkbuttons
        plans = lic.get("service_plans", [])
        disabled_service_plans = cfg.get("disabled_service_plans", {})
        default_disabled = disabled_service_plans.get(lic["sku_id"], [])

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

    # -- Actions -----------------------------------------------------------

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
        self.ad_security_listbox.selection_clear(0, "end")
        self.ad_distribution_listbox.selection_clear(0, "end")
        self.cloud_security_listbox.selection_clear(0, "end")
        self.cloud_m365_listbox.selection_clear(0, "end")
        self.cloud_distribution_listbox.selection_clear(0, "end")
        self.ad_group_filter_var.set("")
        self.cloud_group_filter_var.set("")
        self.copy_user_search_var.set("")
        self.copy_status_label.configure(text="")
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

    # -- Validation --------------------------------------------------------

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

    # -- Provisioning Workflow ---------------------------------------------

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

        # -- Step 1: Create AD User ----------------------------------------
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

        # -- Step 2: Set Manager -------------------------------------------
        manager_dn = self.manager_dn_var.get()
        if manager_dn and user_dn:
            self._update_status_ts("Setting manager...")
            success, error = set_user_manager(user_dn, manager_dn)
            if not success:
                results["errors"].append(f"Failed to set manager: {error}")

        # -- Step 3: Add to AD Groups (from all tabs) ----------------------
        group_dns = []
        for idx in self.ad_security_listbox.curselection():
            if idx in self._ad_security_map:
                group_dns.append(self._ad_security_map[idx])
        for idx in self.ad_distribution_listbox.curselection():
            if idx in self._ad_distribution_map:
                group_dns.append(self._ad_distribution_map[idx])

        if group_dns and user_dn:
            self._update_status_ts("Adding to AD groups...")
            group_results = add_user_to_groups(user_dn, group_dns)
            results["groups_added"] = group_results
            for gname, gsuccess, gerror in group_results:
                if not gsuccess:
                    results["errors"].append(f"Group '{gname}': {gerror}")

        # -- Step 4: License and Sync --------------------------------------
        lic_selection = self.license_var.get()
        wants_license = lic_selection and not lic_selection.startswith("(None")

        # Gather cloud groups from all tabs
        cloud_group_selections = []
        for idx in self.cloud_security_listbox.curselection():
            if idx in self._cloud_security_map:
                cloud_group_selections.append(self._cloud_security_map[idx])
        for idx in self.cloud_m365_listbox.curselection():
            if idx in self._cloud_m365_map:
                cloud_group_selections.append(self._cloud_m365_map[idx])
        for idx in self.cloud_distribution_listbox.curselection():
            if idx in self._cloud_distribution_map:
                cloud_group_selections.append(self._cloud_distribution_map[idx])
        wants_cloud_groups = len(cloud_group_selections) > 0

        ad_domain = cfg["ad_domain"]
        poll_interval = cfg["entra_poll_interval_seconds"]
        poll_timeout = cfg["entra_poll_timeout_seconds"]

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
                self._update_status_ts("Sync skipped \u2014 waiting for user to appear in Entra...")
                results["sync_triggered"] = True  # Skipped intentionally

            # Poll for user in Entra ID
            upn = f"{username}@{ad_domain}"
            self._update_status_ts("Waiting for user to appear in Entra ID...")
            start_time = time.time()

            while not self._cancel_event.is_set():
                elapsed = time.time() - start_time
                if elapsed > poll_timeout:
                    results["errors"].append(
                        f"User not found in Entra ID after {poll_timeout}s. "
                        "Sync may be delayed \u2014 assign license manually later."
                    )
                    break

                self._update_status_ts(
                    f"Polling Entra ID... ({int(elapsed)}s / {poll_timeout}s)")

                user_data = find_user_in_entra(upn)
                if user_data:
                    results["entra_found"] = True
                    results["entra_user_id"] = user_data.get("id", "")
                    break

                time.sleep(poll_interval)

            # -- Step 5: Assign License ------------------------------------
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

            # -- Step 6: Add to Cloud Groups -------------------------------
            if results["entra_found"] and wants_cloud_groups:
                if self._cancel_event.is_set():
                    results["errors"].append("Cancelled by user")
                    return results

                self._update_status_ts("Adding to cloud groups...")
                cloud_results = add_user_to_cloud_groups(
                    results["entra_user_id"], cloud_group_selections)
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

    # -- Thread Helpers ----------------------------------------------------

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

# -- Remediation instructions for each check ----------------------------------
# These are shown in detail when a check fails or warns. Written for an MSP
# tech deploying this tool to a new customer DC for the first time.

REMEDIATION = {
    "powershell": {
        CHECK_FAIL: (
            "HOW TO FIX: PowerShell Not Available\n"
            "====================================\n"
            "This tool must run on a Windows machine with PowerShell.\n\n"
            "1. This EXE is designed to run on a Windows Domain Controller.\n"
            "2. If you're testing on a non-Windows machine, the tool won't work.\n"
            "3. Ensure powershell.exe is in your system PATH.\n"
            "4. Try opening PowerShell manually to verify it launches."
        ),
    },
    "ad_module": {
        CHECK_FAIL: (
            "HOW TO FIX: Active Directory PowerShell Module\n"
            "==============================================\n"
            "The AD module is required to create users and query the domain.\n\n"
            "If running on a Domain Controller:\n"
            "  - The module should already be installed. Try:\n"
            "    Import-Module ActiveDirectory\n"
            "  - If missing, open Server Manager > Add Roles and Features >\n"
            "    Features > Remote Server Administration Tools >\n"
            "    Role Administration Tools > AD DS and AD LDS Tools >\n"
            "    Active Directory module for Windows PowerShell\n\n"
            "If running on a workstation:\n"
            "  - Install RSAT (Remote Server Administration Tools):\n"
            "    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0\n"
            "  - Restart PowerShell after installing."
        ),
    },
    "ad_permissions": {
        CHECK_FAIL: (
            "HOW TO FIX: AD Permissions\n"
            "==========================\n"
            "The current user cannot query Active Directory.\n\n"
            "1. Right-click the EXE and select 'Run as administrator'\n"
            "2. Ensure you are logged in as a Domain Admin, or an account with\n"
            "   delegated permissions to:\n"
            "   - Create User objects in the target OUs\n"
            "   - Modify group memberships\n"
            "   - Read all OUs and security groups\n\n"
            "3. To check your current user:\n"
            "   whoami /groups | findstr 'Domain Admins'\n\n"
            "4. If using delegated permissions, ensure the Delegation of Control\n"
            "   wizard has granted Create/Delete User Objects on the target OUs."
        ),
    },
    "network": {
        CHECK_FAIL: (
            "HOW TO FIX: Network Connectivity\n"
            "================================\n"
            "The DC must reach Microsoft cloud endpoints over HTTPS (port 443).\n\n"
            "Required endpoints:\n"
            "  - login.microsoftonline.com  (Entra ID authentication)\n"
            "  - graph.microsoft.com        (Microsoft Graph API)\n\n"
            "Troubleshooting:\n"
            "1. Check firewall rules -- port 443 outbound must be open to these hosts\n"
            "2. Check proxy settings -- if the DC uses a web proxy:\n"
            "   netsh winhttp show proxy\n"
            "3. Test manually:\n"
            "   Test-NetConnection login.microsoftonline.com -Port 443\n"
            "   Test-NetConnection graph.microsoft.com -Port 443\n"
            "4. If using a proxy, set the system proxy:\n"
            "   netsh winhttp set proxy proxy-server:port\n"
            "5. DNS resolution -- verify the DC can resolve these hostnames:\n"
            "   Resolve-DnsName login.microsoftonline.com"
        ),
    },
    "certificate": {
        CHECK_FAIL: (
            "HOW TO FIX: Graph API Certificate\n"
            "=================================\n"
            "A certificate is needed so this tool can authenticate to Microsoft 365\n"
            "without storing a password. Each customer needs their own certificate.\n\n"
            "OPTION A -- Generate Certificate (click 'Generate Cert' button below)\n"
            "  The button will create a self-signed certificate automatically,\n"
            "  DPAPI-encrypt the private key, and place it at the expected path.\n"
            "  You'll still need to upload the public key (.cer) to Azure.\n\n"
            "OPTION B -- Run the Setup Wizard (click 'Run Setup Wizard' below)\n"
            "  The wizard will walk you through generating a certificate and\n"
            "  configuring all settings step by step.\n\n"
            "After generating, update config.json with the thumbprint,\n"
            "then click 'Retry' to re-run checks."
        ),
        CHECK_WARN: (
            "WARNING: Certificate File Issue\n"
            "===============================\n"
            "The file exists but may not be a valid PEM certificate or\n"
            "DPAPI-encrypted file.\n\n"
            "Expected formats:\n"
            "  - .pem.protected (DPAPI-encrypted, preferred)\n"
            "  - .pem (plaintext PEM, will work but should be encrypted)\n\n"
            "A valid PEM file should start with:\n"
            "  -----BEGIN PRIVATE KEY-----\n"
            "  or\n"
            "  -----BEGIN RSA PRIVATE KEY-----\n\n"
            "Use the 'Generate Cert' button to create a new valid certificate."
        ),
    },
    "graph_auth": {
        CHECK_FAIL: (
            "HOW TO FIX: Microsoft 365 Login\n"
            "===============================\n"
            "The tool could not authenticate to this customer's Microsoft 365 tenant.\n\n"
            "For each customer, you need an App Registration in THEIR Entra ID tenant.\n\n"
            "  Step 1: Create the App Registration\n"
            "  ------------------------------------\n"
            "  1. Sign in to portal.azure.com as a Global Admin for the customer\n"
            "  2. Go to: Entra ID > App registrations > New registration\n"
            "  3. Name: 'User Provisioning Tool'\n"
            "  4. Supported account types: 'Accounts in this organizational directory only'\n"
            "  5. Click Register\n"
            "  6. On the overview page, copy:\n"
            "     - Application (client) ID  ->  graph_client_id in config.json\n"
            "     - Directory (tenant) ID    ->  graph_tenant_id in config.json\n\n"
            "  Step 2: Upload the Certificate\n"
            "  ------------------------------\n"
            "  1. In the App Registration, go to: Certificates & secrets\n"
            "  2. Click 'Upload certificate'\n"
            "  3. Upload the .cer public key file (from the certificate step)\n"
            "  4. Copy the thumbprint shown -> graph_cert_thumbprint in config.json\n\n"
            "  Step 3: Grant API Permissions\n"
            "  -----------------------------\n"
            "  1. In the App Registration, go to: API permissions\n"
            "  2. Click 'Add a permission' > Microsoft Graph > Application permissions\n"
            "  3. Add these permissions:\n"
            "     - User.ReadWrite.All\n"
            "     - Directory.ReadWrite.All\n"
            "     - Organization.Read.All\n"
            "     - Group.ReadWrite.All\n"
            "     - GroupMember.ReadWrite.All\n"
            "  4. Click 'Grant admin consent for <tenant name>'\n"
            "     (requires Global Admin -- the green checkmarks must appear)\n\n"
            "  Step 4: Update config.json\n"
            "  --------------------------\n"
            f"  Edit {CONFIG_PATH} with the customer's values:\n"
            "    graph_tenant_id: '<Directory (tenant) ID>'\n"
            "    graph_client_id: '<Application (client) ID>'\n"
            "    graph_cert_thumbprint: '<certificate thumbprint>'\n\n"
            "  Or use the 'Run Setup Wizard' button to configure interactively.\n\n"
            "  Then click 'Retry' to re-run checks.\n\n"
            "COMMON ERRORS:\n"
            "  - AADSTS700016: App not found -- wrong Client ID or Tenant ID\n"
            "  - AADSTS700027: Certificate mismatch -- wrong thumbprint or cert not uploaded\n"
            "  - AADSTS7000215: Invalid client secret -- using secret instead of cert\n"
            "  - AADSTS50034: User account doesn't exist -- wrong tenant\n"
            "  - 'could not parse the provided public key' -- certificate format\n"
            "    issue. Re-generate the cert using the Setup Wizard or\n"
            "    Generate Cert button. The PEM must contain both the private\n"
            "    key and certificate (public key) sections."
        ),
    },
    "graph_perms": {
        CHECK_FAIL: (
            "HOW TO FIX: Graph API Permissions\n"
            "=================================\n"
            "Authentication works, but the app is missing required permissions.\n\n"
            "1. Go to: portal.azure.com > Entra ID > App registrations\n"
            "2. Select the 'User Provisioning Tool' app\n"
            "3. Go to: API permissions\n"
            "4. Verify these Application permissions are listed AND have green checkmarks:\n"
            "   - User.ReadWrite.All\n"
            "   - Directory.ReadWrite.All\n"
            "   - Organization.Read.All      (needed for license/SKU queries)\n"
            "   - Group.ReadWrite.All         (needed for cloud group management)\n"
            "   - GroupMember.ReadWrite.All   (needed to add users to cloud groups)\n\n"
            "5. If any are missing, click 'Add a permission' > Microsoft Graph >\n"
            "   Application permissions > search for and add them\n"
            "6. IMPORTANT: Click 'Grant admin consent for <tenant name>'\n"
            "   The status must show green checkmarks, not orange warnings.\n"
            "   This requires Global Admin permissions.\n\n"
            "Then click 'Retry' to re-check."
        ),
        CHECK_WARN: (
            "WARNING: Partial Permissions\n"
            "============================\n"
            "License management works, but cloud group management is not available.\n\n"
            "To enable cloud group assignment, add these permissions to the App Registration:\n"
            "  - Group.ReadWrite.All\n"
            "  - GroupMember.ReadWrite.All\n\n"
            "Then grant admin consent and click 'Retry'.\n\n"
            "You can continue without this -- on-prem AD groups and licensing will still work."
        ),
    },
    "adsync": {
        CHECK_WARN: (
            "INFO: Entra Connect Sync Server\n"
            "===============================\n"
            "The tool couldn't automatically detect where Entra Connect is installed.\n"
            "This is common if the sync agent is on a member server (not a DC).\n\n"
            "You can still use the tool -- in the main window you'll see options to:\n"
            "  - Enter the sync server hostname manually\n"
            "  - Skip sync entirely (and trigger it yourself)\n\n"
            "To find the Entra Connect server:\n"
            "  1. Check Azure Portal > Entra ID > Entra Connect > Connect Sync\n"
            "     The server name is shown under 'Sync server'\n"
            "  2. Or run on each candidate server:\n"
            "     Get-Service ADSync\n\n"
            "If the customer uses Entra Cloud Sync instead of Entra Connect:\n"
            "  - Cloud Sync doesn't have a Start-ADSyncSyncCycle command\n"
            "  - Select 'Skip sync' in the main window -- cloud sync runs automatically\n"
            "    and the tool will poll until the user appears in Entra ID."
        ),
    },
    "config": {
        CHECK_FAIL: (
            "HOW TO FIX: Configuration Not Found\n"
            "===================================\n"
            f"No config.json found at:\n  {CONFIG_PATH}\n\n"
            "This is expected on first run. Click 'Run Setup Wizard' below\n"
            "to create your configuration interactively.\n\n"
            "Alternatively, create config.json manually with these keys:\n\n"
            '  {\n'
            '    "ad_domain": "customer.com",\n'
            '    "ad_netbios": "CUSTOMER",\n'
            '    "email_domains": ["customer.com"],\n'
            '    "adsync_server": null,\n'
            '    "graph_tenant_id": "<tenant-id>",\n'
            '    "graph_client_id": "<client-id>",\n'
            '    "graph_cert_thumbprint": "<thumbprint>",\n'
            '    "graph_cert_path": "C:\\\\Certs\\\\graph_app.pem.protected"\n'
            '  }\n\n'
            f"Save it to: {CONFIG_PATH}\n\n"
            "  HOW TO FIND THESE VALUES:\n"
            "  - portal.azure.com > Entra ID > App registrations > your app > Overview\n"
            "  - Tenant ID = 'Directory (tenant) ID'\n"
            "  - Client ID = 'Application (client) ID'\n"
            "  - Thumbprint = Certificates & secrets > Certificates > Thumbprint column"
        ),
    },
}


def _preflight_check_config() -> tuple:
    """Verify config.json exists, is valid JSON, and has required keys."""
    if not os.path.isfile(CONFIG_PATH):
        return CHECK_FAIL, f"config.json not found at {CONFIG_PATH}"

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return CHECK_FAIL, f"config.json is not valid JSON: {e}"
    except OSError as e:
        return CHECK_FAIL, f"Cannot read config.json: {e}"

    missing = [k for k in REQUIRED_CONFIG_KEYS if not data.get(k)]
    if missing:
        return CHECK_FAIL, f"config.json missing required keys: {', '.join(missing)}"

    return CHECK_PASS, f"Configuration loaded for {data.get('ad_domain', '?')}"


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
        return CHECK_PASS, f"AD module loaded \u2014 domain: {domain}"
    if "not recognized" in stderr.lower() or "not installed" in stderr.lower():
        return CHECK_FAIL, "ActiveDirectory module not installed"
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
        return CHECK_PASS, f"AD read access confirmed \u2014 {count} OUs found"
    if "access" in stderr.lower() or "denied" in stderr.lower():
        return CHECK_FAIL, "Insufficient AD permissions"
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

    failed = [f"{label}" for label, ok, err in results if not ok]
    return CHECK_FAIL, "Unreachable: " + ", ".join(failed)


def _preflight_check_certificate() -> tuple:
    """Verify the Graph API certificate file exists and is readable (plain or DPAPI-encrypted)."""
    cert_path = cfg.get("graph_cert_path", "")
    if not cert_path:
        return CHECK_FAIL, "graph_cert_path not set in config.json"

    # Check for DPAPI-protected file
    protected_path = cert_path + ".protected" if not cert_path.endswith(".protected") else cert_path
    if cert_path.endswith(".protected"):
        plain_path = cert_path[:-len(".protected")]
    else:
        plain_path = cert_path

    if os.path.isfile(protected_path):
        # Try to verify it can be decrypted
        try:
            content = dpapi_decrypt_to_memory(protected_path)
            if "PRIVATE KEY" in content or "BEGIN" in content:
                return CHECK_PASS, f"DPAPI-encrypted certificate found: {protected_path}"
            return CHECK_WARN, "Protected file exists but may not contain a valid PEM certificate"
        except RuntimeError:
            return CHECK_WARN, (
                f"Protected file found at {protected_path} but DPAPI decryption failed. "
                "This can happen if the file was encrypted by a different user account."
            )

    if os.path.isfile(plain_path):
        try:
            with open(plain_path, "r") as f:
                content = f.read(100)
            if "PRIVATE KEY" in content or "BEGIN" in content:
                return CHECK_WARN, (
                    f"Plain PEM found at {plain_path} (not DPAPI-encrypted). "
                    "Consider encrypting it for security."
                )
            return CHECK_WARN, "File exists but may not be a valid PEM certificate"
        except OSError as e:
            return CHECK_FAIL, f"Cannot read certificate: {e}"

    return CHECK_FAIL, f"Certificate not found at {protected_path} or {plain_path}"


def _preflight_check_graph_auth() -> tuple:
    """Verify Microsoft Graph authentication works (acquire a token)."""
    # Skip if config is not loaded
    if not cfg.get("graph_tenant_id") or not cfg.get("graph_client_id"):
        return CHECK_FAIL, "Graph tenant/client IDs not configured in config.json"

    try:
        token = get_graph_token()
        if token:
            return CHECK_PASS, "Graph API authentication successful"
        return CHECK_FAIL, "Token acquisition returned empty"
    except RuntimeError as e:
        msg = str(e)
        if "AADSTS700016" in msg:
            return CHECK_FAIL, "App not found \u2014 wrong Client ID or Tenant ID"
        if "AADSTS700027" in msg:
            return CHECK_FAIL, "Certificate mismatch \u2014 wrong thumbprint or cert not uploaded"
        if "AADSTS" in msg:
            return CHECK_FAIL, f"Entra ID error: {msg[:150]}"
        return CHECK_FAIL, f"Graph auth failed: {msg[:150]}"
    except Exception as e:
        return CHECK_FAIL, f"Graph auth error: {e}"


def _preflight_check_graph_permissions() -> tuple:
    """Verify the app has the required Graph API permissions by testing key endpoints."""
    try:
        headers = _graph_headers()

        resp = requests.get(
            "https://graph.microsoft.com/v1.0/subscribedSkus",
            headers=headers, timeout=15,
        )
        if resp.status_code == 403:
            return CHECK_FAIL, "Missing permission: Organization.Read.All"
        if resp.status_code == 401:
            return CHECK_FAIL, "Authentication rejected"

        resp2 = requests.get(
            "https://graph.microsoft.com/v1.0/groups?$top=1",
            headers=headers, timeout=15,
        )
        if resp2.status_code == 403:
            return CHECK_WARN, "Licenses OK, but cloud groups unavailable (missing Group permissions)"

        return CHECK_PASS, "Graph API permissions verified (licenses + groups)"
    except requests.RequestException as e:
        return CHECK_WARN, f"Could not verify Graph permissions: {e}"


def _preflight_check_adsync() -> tuple:
    """Detect and verify the Entra Connect sync server."""
    server, method = detect_sync_server()
    if server:
        return CHECK_PASS, f"Entra Connect found: {server} (detected via {method})"
    return CHECK_WARN, "Not detected \u2014 enter manually in the main window or skip sync"


# Ordered list of preflight checks: (name, display_label, check_function, is_required)
PREFLIGHT_CHECKS = [
    ("config",         "Configuration",               _preflight_check_config,          True),
    ("powershell",     "PowerShell",                  _preflight_check_powershell,      True),
    ("ad_module",      "AD PowerShell Module",        _preflight_check_ad_module,       True),
    ("ad_permissions", "AD Permissions",              _preflight_check_ad_permissions,  True),
    ("network",        "Network Connectivity",        _preflight_check_network,         True),
    ("certificate",    "Graph API Certificate",       _preflight_check_certificate,     True),
    ("graph_auth",     "Microsoft 365 Login",         _preflight_check_graph_auth,      True),
    ("graph_perms",    "Graph API Permissions",       _preflight_check_graph_permissions, False),
    ("adsync",         "Entra Connect Sync Server",   _preflight_check_adsync,          False),
]


class PreflightDialog(tk.Tk):
    """
    Startup dialog that runs environment checks before launching the main app.

    Shows a checklist with real-time status. Clicking any failed/warning check
    shows detailed step-by-step remediation instructions specific to that issue.
    Required checks must pass to proceed.
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
        self.title("Preflight Check \u2014 365 User Provisioning")
        self.geometry("820x700")
        self.resizable(True, True)

        self._checks_passed = False
        self._check_rows = {}   # name -> (icon_label, text_label, detail_label)
        self._results = {}      # name -> (status, message)

        self._build_ui()
        self.after(200, self._run_checks)

    def _build_ui(self):
        # Header
        header = ttk.Label(self, text="Preflight Environment Check",
                           font=("Segoe UI", 14, "bold"))
        header.pack(pady=(15, 2))
        ttk.Label(self, text="Verifying requirements before launch. "
                  "Click any failed check for setup instructions.",
                  foreground="gray").pack(pady=(0, 10))

        # Top pane: checklist
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(fill="x", padx=15)

        for i, (name, label, _func, required) in enumerate(PREFLIGHT_CHECKS):
            row_frame = ttk.Frame(top_frame)
            row_frame.grid(row=i, column=0, columnspan=3, sticky="ew", pady=1)
            row_frame.columnconfigure(2, weight=1)

            icon_lbl = ttk.Label(row_frame, text=self.ICON[CHECK_PENDING],
                                  foreground=self.COLOR[CHECK_PENDING],
                                  font=("Segoe UI", 12))
            icon_lbl.grid(row=0, column=0, padx=(0, 8), sticky="w")

            req_tag = " *" if required else ""
            text_lbl = ttk.Label(row_frame, text=f"{label}{req_tag}",
                                  font=("Segoe UI", 10), cursor="hand2")
            text_lbl.grid(row=0, column=1, sticky="w")

            detail_lbl = ttk.Label(row_frame, text="", foreground="gray",
                                    font=("Segoe UI", 9), wraplength=420)
            detail_lbl.grid(row=0, column=2, padx=(15, 0), sticky="w")

            # Click handler — show remediation for this check
            for widget in (row_frame, icon_lbl, text_lbl, detail_lbl):
                widget.bind("<Button-1>", lambda e, n=name: self._show_remediation(n))
                widget.configure(cursor="hand2")

            self._check_rows[name] = (icon_lbl, text_lbl, detail_lbl)

        # Legend
        ttk.Label(top_frame, text="* = required  |  Click any check for details",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=len(PREFLIGHT_CHECKS), column=0, columnspan=3, sticky="w", pady=(8, 0))

        # Progress bar
        self.progress = ttk.Progressbar(self, maximum=len(PREFLIGHT_CHECKS), mode="determinate")
        self.progress.pack(fill="x", padx=15, pady=(5, 5))

        # Status summary
        self.summary_label = ttk.Label(self, text="", font=("Segoe UI", 10, "bold"))
        self.summary_label.pack(pady=(0, 5))

        # -- Detail pane (remediation instructions) ------------------------
        detail_frame = ttk.LabelFrame(self, text=" Setup Instructions ", padding=8)
        detail_frame.pack(fill="both", expand=True, padx=15, pady=(0, 5))

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, wrap="char", font=("Consolas", 9),
            state="disabled", height=12, bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#d4d4d4", relief="flat",
        )
        self.detail_text.pack(fill="both", expand=True)

        # Action buttons for the detail pane
        self.detail_btn_frame = ttk.Frame(detail_frame)
        self.detail_btn_frame.pack(fill="x", pady=(5, 0))

        self.gen_cert_btn = ttk.Button(
            self.detail_btn_frame, text="Generate Certificate",
            command=self._on_generate_cert)
        # Hidden by default — shown only when certificate check fails
        self.gen_cert_btn.pack_forget()

        self.setup_wizard_btn = ttk.Button(
            self.detail_btn_frame, text="Run Setup Wizard",
            command=self._on_setup_wizard)
        # Hidden by default — shown when config check fails
        self.setup_wizard_btn.pack_forget()

        self.copy_btn = ttk.Button(
            self.detail_btn_frame, text="Copy to Clipboard",
            command=self._copy_detail_to_clipboard)
        self.copy_btn.pack(side="right")

        # -- Main buttons --------------------------------------------------
        btn_frame = ttk.Frame(self, padding=(15, 5))
        btn_frame.pack(fill="x")

        self.continue_btn = ttk.Button(btn_frame, text="Continue", state="disabled",
                                        command=self._on_continue)
        self.continue_btn.pack(side="left", padx=5)

        self.retry_btn = ttk.Button(btn_frame, text="Retry All Checks", state="disabled",
                                     command=self._on_retry)
        self.retry_btn.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="Quit", command=self._on_quit).pack(side="right", padx=5)

        # Show welcome message in detail pane
        self._set_detail_text(
            "CUSTOMER SETUP CHECKLIST\n"
            "========================\n"
            "For each new customer deployment, you need:\n\n"
            f"  1. Create config.json next to the EXE:\n"
            f"     {CONFIG_PATH}\n"
            "     (Use the 'Run Setup Wizard' button for guided setup)\n\n"
            "  2. Create an App Registration in the customer's Entra ID tenant\n"
            "     (portal.azure.com > Entra ID > App registrations)\n\n"
            "  3. Generate a certificate and upload the public key to the App Registration\n"
            "     (use the 'Generate Certificate' button when that check fails)\n\n"
            "  4. Grant API permissions and admin consent on the App Registration\n\n"
            "  5. Place the EXE + config.json + .pem.protected on the customer's DC\n\n"
            "Checks are running now. Click any failed check for detailed instructions."
        )

    def _set_detail_text(self, text: str, show_cert_btn: bool = False,
                          show_wizard_btn: bool = False):
        """Update the detail/remediation text pane."""
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")
        self.detail_text.see("1.0")

        if show_cert_btn:
            self.gen_cert_btn.pack(side="left", padx=(0, 10))
        else:
            self.gen_cert_btn.pack_forget()

        if show_wizard_btn:
            self.setup_wizard_btn.pack(side="left", padx=(0, 10))
        else:
            self.setup_wizard_btn.pack_forget()

    def _show_remediation(self, check_name: str):
        """Show detailed remediation instructions for a specific check."""
        status, message = self._results.get(check_name, (CHECK_PENDING, ""))

        if status == CHECK_PASS:
            self._set_detail_text(f"PASSED: {message}\n\nNo action needed.")
            return

        # Look up remediation instructions
        check_remediation = REMEDIATION.get(check_name, {})
        instructions = check_remediation.get(status)

        show_cert = (check_name == "certificate" and status in (CHECK_FAIL, CHECK_WARN))
        show_wizard = (check_name == "config" and status == CHECK_FAIL)

        if instructions:
            self._set_detail_text(instructions, show_cert_btn=show_cert,
                                   show_wizard_btn=show_wizard)
        else:
            self._set_detail_text(
                f"Status: {status.upper()}\n"
                f"Detail: {message}\n\n"
                "No specific remediation steps available for this issue.\n"
                "Check the log file for more details.",
                show_wizard_btn=show_wizard
            )

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

                logger.info("Preflight [%s]: %s \u2014 %s", name, status, message)
                self.after(0, self._update_check, name, status, message)
                self.after(0, self._advance_progress, i + 1)

                # If a required check fails, skip dependent checks to save time
                if status == CHECK_FAIL and required:
                    # Mark remaining checks as pending and stop
                    for j in range(i + 1, len(PREFLIGHT_CHECKS)):
                        remaining_name = PREFLIGHT_CHECKS[j][0]
                        self.after(0, self._update_check, remaining_name,
                                   CHECK_PENDING, "Skipped \u2014 fix above issue first")
                    self.after(0, self._advance_progress, len(PREFLIGHT_CHECKS))
                    break

            self.after(0, self._checks_complete)

        threading.Thread(target=worker, daemon=True).start()

    def _advance_progress(self, value):
        self.progress["value"] = value

    def _checks_complete(self):
        """Evaluate results, enable/disable buttons, and auto-show first failure."""
        required_failed = []
        warnings = []
        first_fail_name = None

        for name, label, _func, required in PREFLIGHT_CHECKS:
            status, message = self._results.get(name, (CHECK_PENDING, ""))
            if status == CHECK_FAIL and required:
                required_failed.append(label)
                if first_fail_name is None:
                    first_fail_name = name
            elif status == CHECK_WARN:
                warnings.append(label)

        self.retry_btn.configure(state="normal")

        if required_failed:
            self._checks_passed = False
            self.continue_btn.configure(state="disabled")
            self.summary_label.configure(
                text=f"BLOCKED: {len(required_failed)} required check(s) failed \u2014 see instructions below",
                foreground="red")
            # Auto-show remediation for the first failure
            if first_fail_name:
                self._show_remediation(first_fail_name)
        elif warnings:
            self._checks_passed = True
            self.continue_btn.configure(state="normal")
            self.summary_label.configure(
                text=f"READY with {len(warnings)} warning(s) \u2014 some features may be limited",
                foreground="orange")
        else:
            self._checks_passed = True
            self.continue_btn.configure(state="normal")
            self.summary_label.configure(
                text="ALL CHECKS PASSED \u2014 ready to launch",
                foreground="green")

    def _on_generate_cert(self):
        """Generate a certificate for Graph API auth."""
        self.gen_cert_btn.configure(state="disabled", text="Generating...")

        def do_generate():
            return generate_certificate_on_dc()

        def on_done(result):
            success, thumbprint, message = result
            self.gen_cert_btn.configure(state="normal", text="Generate Certificate")
            self._set_detail_text(message, show_cert_btn=not success)

            if success:
                messagebox.showinfo("Certificate Generated",
                                     f"Certificate created successfully!\n\n"
                                     f"Thumbprint: {thumbprint}\n\n"
                                     "See the instructions panel for next steps.")

        def on_error(e):
            self.gen_cert_btn.configure(state="normal", text="Generate Certificate")
            self._set_detail_text(f"Certificate generation failed:\n{e}")

        # Run in thread to avoid blocking UI
        def wrapper():
            try:
                result = do_generate()
                self.after(0, on_done, result)
            except Exception as e:
                self.after(0, on_error, e)

        threading.Thread(target=wrapper, daemon=True).start()

    def _on_setup_wizard(self):
        """Launch the setup wizard dialog."""
        wizard = SetupWizard(self)
        self.wait_window(wizard)
        if wizard.completed:
            # Reload config and re-run checks
            self._set_detail_text(
                "Configuration saved. Re-running all checks...")
            self._on_retry()

    def _copy_detail_to_clipboard(self):
        """Copy the current detail text to clipboard."""
        self.clipboard_clear()
        text = self.detail_text.get("1.0", "end").strip()
        self.clipboard_append(text)
        self.copy_btn.configure(text="Copied!")
        self.after(2000, lambda: self.copy_btn.configure(text="Copy to Clipboard"))

    def _on_continue(self):
        """Close preflight and signal to launch the main app."""
        self.destroy()

    def _on_retry(self):
        """Re-run all checks."""
        global cfg
        cfg = load_config()
        _graph_token_cache["token"] = None
        _graph_token_cache["expires_at"] = 0
        _detected_sync_server["checked"] = False
        self._set_detail_text("Re-running all checks...")
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
    logger.info("Config path: %s (exists: %s)", CONFIG_PATH, os.path.isfile(CONFIG_PATH))
    logger.info("=" * 60)

    # Run preflight checks
    preflight = PreflightDialog()
    preflight.mainloop()

    if not preflight.passed:
        logger.info("Preflight checks failed or user quit \u2014 exiting")
        return

    logger.info("Preflight passed \u2014 launching main application")

    # Launch main application
    app = ProvisioningApp()
    app.mainloop()

    logger.info("Application closed")


if __name__ == "__main__":
    main()
