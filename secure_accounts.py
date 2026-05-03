#!/usr/bin/env python3
"""
Microsoft Account Security Hardener
------------------------------------
Automates security hardening for multiple Microsoft accounts via the
Microsoft Graph API. For each account the script will:

  1. Revoke all active sign-in sessions (kicks out any unauthorised devices)
  2. Change the account password
  3. Update the security/recovery email address
  4. Remove all registered devices

Usage:
  pip install -r requirements.txt
  python secure_accounts.py

Authentication uses interactive device-code flow — a short code is printed
and you open a browser to enter it. No credentials are stored by this script.

IMPORTANT NOTES:
  - Some operations require permissions that are only available on work/school
    (Azure AD / Entra ID) accounts. Personal accounts (Outlook/Hotmail/Live)
    support session revocation and password change, but the security-email and
    device APIs may return "Forbidden" — that is expected.
  - You need to allow the Microsoft Azure CLI app (public client) the delegated
    permissions below in your tenant, OR register your own Azure AD app and set
    CLIENT_ID accordingly.
"""

import sys
import time
import getpass
import requests
import msal

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Microsoft Azure CLI — a well-known public client ID that works without
# app registration for personal and work Microsoft accounts.
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AUTHORITY = "https://login.microsoftonline.com/common"
GRAPH = "https://graph.microsoft.com/v1.0"

SCOPES = [
    "User.ReadWrite",
    "UserAuthenticationMethod.ReadWrite.All",
    "Directory.AccessAsUser.All",
]

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate(hint: str) -> str | None:
    """
    Authenticate via device-code flow and return an access token.
    The user visits a URL printed on screen and enters the short code shown.
    """
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)

    # Try silent auth first (reuses a cached token for the same account)
    accounts = app.get_accounts(username=hint)
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            print(f"  [+] Reused cached token for {hint}")
            return result["access_token"]

    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        print(f"  [!] Could not start device-code flow: {flow}")
        return None

    print(f"\n  >>> {flow['message']}\n")
    result = app.acquire_token_by_device_flow(flow)

    if "access_token" in result:
        return result["access_token"]

    print(f"  [!] Authentication failed: {result.get('error_description', result)}")
    return None

# ---------------------------------------------------------------------------
# Graph API helpers
# ---------------------------------------------------------------------------

def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def graph_get(token: str, path: str) -> dict:
    r = requests.get(f"{GRAPH}{path}", headers=_headers(token), timeout=30)
    return r.json() if r.ok else {"_error": r.status_code, "_text": r.text}


def graph_post(token: str, path: str, body: dict) -> dict:
    r = requests.post(f"{GRAPH}{path}", headers=_headers(token), json=body, timeout=30)
    if r.status_code == 204:
        return {"_ok": True}
    return r.json() if r.ok else {"_error": r.status_code, "_text": r.text}


def graph_patch(token: str, path: str, body: dict) -> dict:
    r = requests.patch(f"{GRAPH}{path}", headers=_headers(token), json=body, timeout=30)
    if r.status_code == 204:
        return {"_ok": True}
    return r.json() if r.ok else {"_error": r.status_code, "_text": r.text}


def graph_delete(token: str, path: str) -> bool:
    r = requests.delete(f"{GRAPH}{path}", headers=_headers(token), timeout=30)
    return r.status_code in (200, 204)

# ---------------------------------------------------------------------------
# Security operations
# ---------------------------------------------------------------------------

def op_revoke_sessions(token: str) -> bool:
    """Invalidate every active sign-in session for the account."""
    result = graph_post(token, "/me/revokeSignInSessions", {})
    if result.get("_ok") or result.get("value") is True:
        print("  [+] All sign-in sessions revoked.")
        return True
    print(f"  [!] Session revocation failed: {result.get('_text', result)}")
    return False


def op_change_password(token: str, current_pw: str, new_pw: str) -> bool:
    """Change the account password."""
    result = graph_post(token, "/me/changePassword", {
        "currentPassword": current_pw,
        "newPassword": new_pw,
    })
    if result.get("_ok"):
        print("  [+] Password changed.")
        return True
    err = result.get("_text") or result.get("error", {}).get("message", str(result))
    print(f"  [!] Password change failed: {err}")
    return False


def op_update_security_email(token: str, new_email: str) -> bool:
    """
    Update (or add) the security/recovery email address.
    Works reliably on Azure AD accounts; personal accounts may return 403.
    """
    methods = graph_get(token, "/me/authentication/emailMethods")
    if "_error" in methods:
        print(f"  [!] Cannot read email methods (unsupported for this account type): "
              f"{methods.get('_text', '')[:120]}")
        return False

    values = methods.get("value", [])
    if values:
        method_id = values[0]["id"]
        result = graph_patch(
            token,
            f"/me/authentication/emailMethods/{method_id}",
            {"emailAddress": new_email},
        )
        if result.get("_ok") or "emailAddress" in result:
            print(f"  [+] Security email updated → {new_email}")
            return True
        print(f"  [!] Email update failed: {result.get('_text', result)[:120]}")
        return False
    else:
        result = graph_post(
            token,
            "/me/authentication/emailMethods",
            {"emailAddress": new_email},
        )
        if "id" in result:
            print(f"  [+] Security email added → {new_email}")
            return True
        print(f"  [!] Email add failed: {result.get('_text', result)[:120]}")
        return False


def op_remove_devices(token: str) -> int:
    """
    Remove all registered/joined devices from the account.
    Returns count of successfully removed devices.
    """
    devices = graph_get(token, "/me/registeredDevices")
    if "_error" in devices:
        print(f"  [!] Cannot list devices: {devices.get('_text', '')[:120]}")
        return 0

    items = devices.get("value", [])
    if not items:
        print("  [-] No registered devices found.")
        return 0

    removed = 0
    for dev in items:
        dev_id = dev.get("id", "")
        name = dev.get("displayName", "Unknown")
        os_type = dev.get("operatingSystem", "")
        label = f"{name} ({os_type})" if os_type else name

        if graph_delete(token, f"/devices/{dev_id}"):
            print(f"  [+] Removed device: {label}")
            removed += 1
        else:
            print(f"  [-] Could not remove device: {label} "
                  "(may require Azure AD admin rights)")
    return removed


def op_remove_app_passwords(token: str) -> int:
    """Remove legacy app passwords (used with apps that don't support MFA)."""
    result = graph_get(token, "/me/authentication/passwordMethods")
    if "_error" in result:
        return 0

    removed = 0
    for method in result.get("value", []):
        mid = method.get("id", "")
        # The primary password method always exists; skip it
        if mid == "28c10230-6103-485e-b985-444c60001490":
            continue
        if graph_delete(token, f"/me/authentication/passwordMethods/{mid}"):
            print("  [+] Removed legacy app password.")
            removed += 1
    return removed

# ---------------------------------------------------------------------------
# Per-account flow
# ---------------------------------------------------------------------------

def harden_account(
    email: str,
    current_pw: str,
    new_pw: str,
    security_email: str,
) -> dict:
    results = {
        "sessions_revoked": False,
        "password_changed": False,
        "security_email_updated": False,
        "devices_removed": 0,
    }

    print(f"\n{'═' * 62}")
    print(f"  Account: {email}")
    print(f"{'═' * 62}")

    token = authenticate(email)
    if not token:
        print(f"  [!] Skipping — could not authenticate.")
        return results

    print("\n  [1/4] Revoking all active sessions...")
    results["sessions_revoked"] = op_revoke_sessions(token)

    print("\n  [2/4] Changing password...")
    results["password_changed"] = op_change_password(token, current_pw, new_pw)

    print("\n  [3/4] Updating security email...")
    results["security_email_updated"] = op_update_security_email(token, security_email)

    print("\n  [4/4] Removing registered devices...")
    results["devices_removed"] = op_remove_devices(token)

    return results

# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def ask(prompt: str, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("  This field cannot be empty. Please try again.")


def ask_password(prompt: str, min_length: int = 12) -> str:
    while True:
        pw = getpass.getpass(prompt)
        if len(pw) < min_length:
            print(f"  Password must be at least {min_length} characters. Try again.")
            continue
        confirm = getpass.getpass("  Confirm: ")
        if pw != confirm:
            print("  Passwords do not match. Try again.")
            continue
        return pw

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      Microsoft Account Security Hardener                 ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("""
What this script does for EACH account:
  • Revokes ALL active sign-in sessions (kicks out anyone logged in)
  • Changes the password
  • Updates the security / recovery email
  • Removes all registered devices

Authentication: device-code flow — no passwords stored.
""")

    # ── Global new settings ──────────────────────────────────────────────
    print("─── New security settings (applied to every account) ───────\n")
    new_security_email = ask("New security/recovery email address: ")

    print()
    print("New password (min 12 chars, will be applied to every account):")
    new_password = ask_password("  New password: ")

    # ── Account list ─────────────────────────────────────────────────────
    print("\n─── Accounts to harden ─────────────────────────────────────")
    print("Enter each Microsoft account email, one per line.")
    print("Press Enter on an empty line when finished.\n")

    accounts: list[str] = []
    while True:
        email = input(f"  Account {len(accounts) + 1} email (blank to finish): ").strip()
        if not email:
            if not accounts:
                print("  Please enter at least one account.")
                continue
            break
        accounts.append(email)

    # ── Current passwords per account ───────────────────────────────────
    print("\n─── Current passwords ──────────────────────────────────────")
    print("Needed to authorise the password change on each account.\n")

    current_passwords: dict[str, str] = {}
    for email in accounts:
        current_passwords[email] = getpass.getpass(f"  Current password for {email}: ")

    # ── Confirmation ─────────────────────────────────────────────────────
    print(f"\n{'─' * 62}")
    print(f"  Ready to harden {len(accounts)} account(s).")
    print(f"  New security email : {new_security_email}")
    print(f"  New password       : {'*' * len(new_password)}")
    print(f"{'─' * 62}")
    confirm = input("\n  Proceed? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    # ── Process accounts ─────────────────────────────────────────────────
    summary: list[tuple[str, dict]] = []

    for i, email in enumerate(accounts):
        result = harden_account(
            email,
            current_passwords[email],
            new_password,
            new_security_email,
        )
        summary.append((email, result))

        if i < len(accounts) - 1:
            print("\n  Waiting 3 s before next account...")
            time.sleep(3)

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n\n{'═' * 62}")
    print("  SUMMARY")
    print(f"{'═' * 62}")
    print(f"  {'Account':<35} {'Sessions':^8} {'Password':^8} {'Email':^6} {'Devices':^7}")
    print(f"  {'─'*35} {'─'*8} {'─'*8} {'─'*6} {'─'*7}")

    for email, r in summary:
        sessions = "✓" if r["sessions_revoked"] else "✗"
        password = "✓" if r["password_changed"] else "✗"
        email_ok = "✓" if r["security_email_updated"] else "✗"
        devices = str(r["devices_removed"])
        print(f"  {email:<35} {sessions:^8} {password:^8} {email_ok:^6} {devices:^7}")

    print(f"{'═' * 62}\n")
    print("Done. Store your new password in a password manager.")
    print("Recommend enabling an authenticator app (TOTP) for each account.")


if __name__ == "__main__":
    main()
