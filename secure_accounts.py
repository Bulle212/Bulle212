#!/usr/bin/env python3
"""
Microsoft Account Security Hardener
-------------------------------------
For each account you provide an email and the existing recovery code.
The script uses Microsoft's "forgot password" flow to authenticate via
the recovery code (no current password needed), then:

  1. Sets your new password
  2. Signs out of every other session
  3. Updates the security/recovery email
  4. Removes all registered devices
  5. Generates a new recovery code and prints it

Setup:
  pip install playwright
  playwright install chromium
  python secure_accounts.py

The browser window stays visible so you can see what is happening and
step in manually if Microsoft shows a CAPTCHA.
"""

import re
import sys
import time
import getpass

from playwright.sync_api import (
    sync_playwright,
    Browser,
    Page,
    TimeoutError as PWTimeout,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SLOW_MO = 120   # ms between actions — looks more human, reduces bot detection
TIMEOUT  = 15_000  # default element wait (ms)


def log(msg: str) -> None:
    print(f"  {msg}")


def find_and_fill(page: Page, selectors: list[str], value: str, timeout: int = TIMEOUT) -> bool:
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=timeout, state="visible")
            page.fill(sel, value)
            return True
        except PWTimeout:
            continue
    return False


def find_and_click(page: Page, selectors: list[str], timeout: int = TIMEOUT) -> bool:
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=timeout, state="visible")
            page.click(sel)
            return True
        except PWTimeout:
            continue
    return False


def click_text_link(page: Page, texts: list[str], timeout: int = TIMEOUT) -> bool:
    for text in texts:
        try:
            loc = page.get_by_text(text, exact=False).first
            loc.wait_for(timeout=timeout, state="visible")
            loc.click()
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Step 1 — Authenticate via "forgot password + recovery code"
# ---------------------------------------------------------------------------

def authenticate_with_recovery_code(page: Page, email: str, recovery_code: str, new_password: str) -> bool:
    """
    Uses the Microsoft "forgot my password" flow with a recovery code.
    On success the account password is changed to new_password and the
    browser session is authenticated.
    """
    log("Opening Microsoft password reset...")
    page.goto("https://account.live.com/ResetPassword.aspx", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")

    # --- Enter account email ---
    if not find_and_fill(page, ['input[name="iLoginName"]', 'input[type="email"]'], email):
        log("[!] Could not find email field on reset page.")
        return False

    if not find_and_click(page, ['input[id="iSigninName"]', 'input[type="submit"]', '#iNext']):
        page.keyboard.press("Enter")

    page.wait_for_load_state("networkidle")
    time.sleep(1)

    # --- Choose "I have a recovery code" ---
    found_recovery_option = click_text_link(page, [
        "I have a recovery code",
        "Use a recovery code",
        "recovery code",
    ], timeout=8000)

    if not found_recovery_option:
        # Try radio button / input with value containing "recovery"
        found_recovery_option = find_and_click(page, [
            'input[value*="RecoveryCode" i]',
            'input[id*="recovery" i]',
            'label:has-text("recovery")',
        ], timeout=5000)

    if not found_recovery_option:
        log("[!] Could not find the 'recovery code' option. Microsoft may have changed the page layout.")
        log("    Please select the recovery code option manually in the browser.")
        time.sleep(15)  # Give the user time to interact

    page.wait_for_load_state("networkidle")
    time.sleep(1)

    # --- Enter the recovery code ---
    code = recovery_code.strip().replace(" ", "").replace("-", "")
    if not find_and_fill(page, [
        'input[id*="recovery" i]',
        'input[name*="recovery" i]',
        'input[id="iOttText"]',
        'input[type="text"]',
        'input[type="tel"]',
    ], code):
        log("[!] Could not find the recovery code input field.")
        log("    Please enter the code manually in the browser.")
        time.sleep(20)

    if not find_and_click(page, ['input[type="submit"]', 'button[type="submit"]', '#iNext']):
        page.keyboard.press("Enter")

    page.wait_for_load_state("networkidle")
    time.sleep(1)

    # --- Set the new password ---
    # Microsoft shows a "Create a password" or "Reset your password" form
    pw_filled = find_and_fill(page, [
        'input[name="iNewPwd"]',
        'input[id="iNewPwd"]',
        'input[type="password"]',
    ], new_password, timeout=10000)

    if not pw_filled:
        log("[!] Could not find the new-password field.")
        return False

    # Confirm-password field (not always present)
    find_and_fill(page, [
        'input[name="iConfirmPwd"]',
        'input[id="iConfirmPwd"]',
        'input[type="password"]:nth-of-type(2)',
    ], new_password, timeout=3000)

    if not find_and_click(page, ['input[type="submit"]', 'button[type="submit"]', '#iNext']):
        page.keyboard.press("Enter")

    page.wait_for_load_state("networkidle")
    time.sleep(2)

    # --- Verify we reached the account dashboard ---
    if "account.microsoft.com" in page.url or "account.live.com" in page.url:
        log("[+] Authenticated and new password set.")
        return True

    # Sometimes Microsoft redirects to a "You're all set" page
    try:
        page.wait_for_url("**/account.microsoft.com/**", timeout=8000)
        log("[+] Authenticated and new password set.")
        return True
    except PWTimeout:
        pass

    # Navigate manually to the account hub
    page.goto("https://account.microsoft.com", wait_until="networkidle")
    if "account.microsoft.com" in page.url:
        log("[+] Authenticated (redirected to account hub).")
        return True

    log(f"[!] Uncertain state after recovery flow. Current URL: {page.url}")
    return False


# ---------------------------------------------------------------------------
# Step 2 — Sign out of every other session
# ---------------------------------------------------------------------------

def revoke_sessions(page: Page) -> bool:
    try:
        page.goto("https://account.microsoft.com/security", wait_until="networkidle", timeout=20000)

        found = click_text_link(page, [
            "Sign out everywhere",
            "Sign out of all sessions",
            "Sign me out of all",
        ], timeout=8000)

        if not found:
            log("[-] 'Sign out everywhere' button not found on this page.")
            return False

        page.wait_for_load_state("networkidle")

        # Confirm dialog if it appears
        click_text_link(page, ["Sign out", "Yes", "OK", "Confirm"], timeout=5000)
        page.wait_for_load_state("networkidle")

        log("[+] Signed out of all other sessions.")
        return True

    except Exception as e:
        log(f"[!] Session revocation failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Step 3 — Update security/recovery email
# ---------------------------------------------------------------------------

def update_security_email(page: Page, new_email: str) -> bool:
    try:
        page.goto("https://mysignins.microsoft.com/security-info", wait_until="networkidle", timeout=20000)

        # Try clicking "Add method"
        click_text_link(page, ["Add method", "Add sign-in method", "+ Add method"], timeout=6000)
        page.wait_for_load_state("networkidle")

        # Pick "Email" from any dropdown or list that appears
        try:
            page.select_option("select", label="Email")
        except Exception:
            click_text_link(page, ["Email"], timeout=4000)

        click_text_link(page, ["Add", "Next"], timeout=4000)
        page.wait_for_load_state("networkidle")

        # Fill the email address
        if not find_and_fill(page, ['input[type="email"]', 'input[name*="email" i]'], new_email, timeout=6000):
            log("[!] Could not find email address input on security-info page.")
            return False

        if not find_and_click(page, ['button[type="submit"]', 'input[type="submit"]'], timeout=5000):
            page.keyboard.press("Enter")

        page.wait_for_load_state("networkidle")
        log(f"[+] Security email update submitted -> {new_email}")
        log("    Microsoft will send a verification code to that address to confirm.")
        return True

    except Exception as e:
        log(f"[!] Security email update failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Step 4 — Remove all registered devices
# ---------------------------------------------------------------------------

def remove_devices(page: Page) -> int:
    removed = 0
    try:
        page.goto("https://account.microsoft.com/devices", wait_until="networkidle", timeout=20000)

        while True:
            # Look for any visible "Remove device" button
            try:
                btn = page.get_by_role("button", name=re.compile(r"remove\s*(device|this)", re.I)).first
                btn.wait_for(timeout=4000, state="visible")
            except Exception:
                break  # No more remove buttons

            # Try to grab the device name from nearby content
            name = "Unknown"
            try:
                row = btn.locator("xpath=ancestor::*[contains(@class,'device')][1]")
                name = row.locator("h2, h3, [class*='name'], [class*='title']").first.inner_text()
            except Exception:
                pass

            btn.click()
            page.wait_for_load_state("networkidle")

            # Confirm the removal dialog
            click_text_link(page, ["Remove", "Yes", "Confirm", "OK"], timeout=5000)
            page.wait_for_load_state("networkidle")

            log(f"[+] Removed device: {name.strip()}")
            removed += 1
            time.sleep(1)

    except Exception as e:
        log(f"[!] Device removal failed: {e}")

    if removed == 0:
        log("[-] No removable devices found.")

    return removed


# ---------------------------------------------------------------------------
# Step 5 — Generate a new recovery code and return it
# ---------------------------------------------------------------------------

def get_new_recovery_code(page: Page) -> str:
    try:
        page.goto("https://account.microsoft.com/security", wait_until="networkidle", timeout=20000)

        # Open advanced / more security options
        click_text_link(page, [
            "Advanced security options",
            "More security options",
        ], timeout=8000)
        page.wait_for_load_state("networkidle")

        # Find and click the recovery code section
        click_text_link(page, [
            "Get a new code",
            "Generate a new recovery code",
            "Generate new code",
            "Recovery code",
        ], timeout=8000)
        page.wait_for_load_state("networkidle")

        # Confirm generation if a dialog/button appears
        click_text_link(page, [
            "Get a new code",
            "Generate",
            "Yes",
            "OK",
        ], timeout=5000)
        page.wait_for_load_state("networkidle")

        # --- Extract the code from the page ---
        body = page.inner_text("body")

        # Microsoft recovery codes come in a few formats; try them all
        patterns = [
            # 25-char alphanum split by dashes:  ABCDE-FGHIJ-KLMNO-PQRST-UVWXY
            r'\b([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b',
            # 8-digit numeric:  1234-5678
            r'\b(\d{4}-\d{4})\b',
            # 10-char alphanum split:  AB12-CD34-EF56
            r'\b([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})\b',
        ]
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return m.group(1).upper()

        # Try element-level extraction as a fallback
        for sel in [
            '[data-testid*="recovery"]',
            '[class*="recovery-code"]',
            '[aria-label*="recovery code" i]',
            'strong',
            'code',
            'b',
        ]:
            try:
                text = page.locator(sel).first.inner_text(timeout=2000).strip()
                if re.search(r'[A-Z0-9]{4,}', text, re.IGNORECASE):
                    return text
            except Exception:
                continue

        log("[!] Could not auto-extract the new recovery code.")
        log(f"    Please read it from the browser window at: {page.url}")
        return ""

    except Exception as e:
        log(f"[!] Recovery code generation failed: {e}")
        return ""


# ---------------------------------------------------------------------------
# Per-account orchestration
# ---------------------------------------------------------------------------

def harden_account(
    browser: Browser,
    email: str,
    recovery_code: str,
    new_password: str,
    new_security_email: str,
) -> dict:
    result = {
        "email": email,
        "password_set": False,
        "sessions_revoked": False,
        "security_email_updated": False,
        "devices_removed": 0,
        "new_recovery_code": "",
        "error": "",
    }

    print(f"\n{'=' * 62}")
    print(f"  Account : {email}")
    print(f"{'=' * 62}")

    ctx = browser.new_context(
        viewport={"width": 1280, "height": 800},
        # Realistic user-agent to reduce bot detection
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    )
    page = ctx.new_page()

    try:
        # 1. Authenticate + set new password via recovery code
        print("\n  [1/5] Authenticating via recovery code...")
        if not authenticate_with_recovery_code(page, email, recovery_code, new_password):
            result["error"] = "Authentication failed"
            return result
        result["password_set"] = True

        # 2. Sign out of all other sessions
        print("\n  [2/5] Signing out of all other sessions...")
        result["sessions_revoked"] = revoke_sessions(page)

        # 3. Update security / recovery email
        print("\n  [3/5] Updating security email...")
        result["security_email_updated"] = update_security_email(page, new_security_email)

        # 4. Remove registered devices
        print("\n  [4/5] Removing registered devices...")
        result["devices_removed"] = remove_devices(page)

        # 5. Generate new recovery code
        print("\n  [5/5] Generating new recovery code...")
        result["new_recovery_code"] = get_new_recovery_code(page)

    except Exception as e:
        result["error"] = str(e)
        log(f"[!] Unexpected error: {e}")
    finally:
        ctx.close()

    return result


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def ask(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("  Cannot be empty — please try again.")


def ask_password(prompt: str, min_len: int = 12) -> str:
    while True:
        pw = getpass.getpass(prompt)
        if len(pw) < min_len:
            print(f"  Password must be at least {min_len} characters.")
            continue
        if pw != getpass.getpass("  Confirm new password: "):
            print("  Passwords do not match.")
            continue
        return pw


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("Microsoft Account Security Hardener")
    print("=" * 38)
    print("""
For each account you only need:
  - The Microsoft account email
  - The current recovery code (backup code Microsoft gave you)

The script will authenticate via the recovery code, then:
  1. Set your chosen new password
  2. Sign out of every other session
  3. Update the security email
  4. Remove all registered devices
  5. Generate and display a new recovery code

A browser window will open so you can see progress.
If Microsoft shows a CAPTCHA, solve it manually.
""")

    # ── Global settings (applied to every account) ───────────────────────
    print("─── Settings applied to every account ──────────────────────\n")
    new_security_email = ask("New security/recovery email: ")
    print()
    new_password = ask_password("New password (min 12 chars): ")

    # ── Account list ─────────────────────────────────────────────────────
    print("\n─── Accounts to secure ─────────────────────────────────────")
    print("Enter one account per prompt. Leave email blank when done.\n")

    accounts: list[tuple[str, str]] = []
    while True:
        n = len(accounts) + 1
        email = input(f"  Account {n} email  (blank to finish): ").strip()
        if not email:
            if not accounts:
                print("  Enter at least one account.")
                continue
            break
        code = ask(f"  Account {n} recovery code: ")
        accounts.append((email, code))

    # ── Confirmation ─────────────────────────────────────────────────────
    print(f"\n{'─' * 62}")
    print(f"  Accounts to harden  : {len(accounts)}")
    print(f"  New security email  : {new_security_email}")
    print(f"  New password        : {'*' * len(new_password)}")
    print(f"{'─' * 62}")
    if input("\n  Proceed? [y/N] ").strip().lower() != "y":
        print("Aborted.")
        sys.exit(0)

    # ── Run ──────────────────────────────────────────────────────────────
    results = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, slow_mo=SLOW_MO)

        for i, (email, code) in enumerate(accounts):
            r = harden_account(browser, email, code, new_password, new_security_email)
            results.append(r)

            if r["new_recovery_code"]:
                print(f"\n  *** NEW RECOVERY CODE for {email} ***")
                print(f"      {r['new_recovery_code']}")
                print("      Save this somewhere safe — it replaces the old one.\n")

            if i < len(accounts) - 1:
                print("  Waiting 5 s before next account...")
                time.sleep(5)

        browser.close()

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n\n{'=' * 62}")
    print("  SUMMARY")
    print(f"{'=' * 62}")
    col = "{:<33} {:^6} {:^8} {:^7} {:^7} {}"
    print(col.format("Account", "PW", "Session", "Email", "Devices", "New recovery code"))
    print(col.format("-"*33, "-"*6, "-"*8, "-"*7, "-"*7, "-"*20))

    for r in results:
        pw_ok   = "OK" if r["password_set"]           else "FAIL"
        sess    = "OK" if r["sessions_revoked"]        else "FAIL"
        email   = "OK" if r["security_email_updated"]  else "FAIL"
        devs    = str(r["devices_removed"])
        code    = r["new_recovery_code"] or ("ERROR: " + r["error"] if r["error"] else "not found")
        print(col.format(r["email"][:33], pw_ok, sess, email, devs, code))

    print(f"{'=' * 62}\n")
    print("Store all recovery codes in a password manager before closing this window.")


if __name__ == "__main__":
    main()
