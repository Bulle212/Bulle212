#!/usr/bin/env python3
"""
Microsoft Account Security Hardener
Follows the exact recovery flow:
  1. login.live.com → enter email
  2. Forgot password
  3. I don't have any of these
  4. Enter recovery code
  5. Add new security email
  6. Set new password
  7. Capture + print new recovery code
  + Signs out all other sessions and removes devices after login
"""

import re
import sys
import time
import getpass

from playwright.sync_api import sync_playwright, Browser, Page, TimeoutError as PWTimeout

SLOW_MO = 30


def log(msg: str) -> None:
    print(f"  {msg}")


def try_click(page: Page, selectors: list, timeout: int = 8000) -> bool:
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=timeout, state="visible")
            page.click(sel)
            return True
        except PWTimeout:
            continue
    return False


def try_fill(page: Page, selectors: list, value: str, timeout: int = 8000) -> bool:
    for sel in selectors:
        try:
            page.wait_for_selector(sel, timeout=timeout, state="visible")
            page.fill(sel, value)
            return True
        except PWTimeout:
            continue
    return False


def try_click_text(page: Page, texts: list, timeout: int = 8000) -> bool:
    for text in texts:
        try:
            el = page.get_by_text(text, exact=False).first
            el.wait_for(timeout=timeout, state="visible")
            el.click()
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Main recovery flow  (follows the guide step by step)
# ---------------------------------------------------------------------------

def secure_account(page: Page, email: str, recovery_code: str,
                   new_security_email: str, new_password: str) -> str:
    """
    Runs the full recovery flow and returns the new recovery code.
    """

    # ── Step 1-2: Go to reset page and enter email ───────────────────────
    log("Step 1: Opening Microsoft password reset page...")
    page.goto("https://account.live.com/password/reset", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")

    log("Step 2: Entering email address...")
    if not try_fill(page, ['input[name="iLoginName"]', 'input[name="loginfmt"]', 'input[type="email"]'], email):
        log("[!] Could not find email field.")
        return ""

    try_click(page, ['input[type="submit"]', '#idSIButton9', 'button[type="submit"]'])
    page.wait_for_load_state("networkidle")

    # ── Step 3: Click "I don't have this information." ───────────────────
    log("Step 3: Clicking 'I don't have this information.'...")
    found = try_click_text(page, [
        "Jeg har ikke nogen af dem",
        "I don't have this information",
        "I don't have any of these",
        "don't have this information",
        "don't have any",
    ], timeout=8000)
    if not found:
        log("[!] Could not find that button — please click it manually.")
        time.sleep(15)

    page.wait_for_load_state("networkidle")

    # ── Step 4b: Select "recovery code" option if a choice is shown ──────
    # Microsoft may show a list of options — pick the recovery code one
    try_click_text(page, [
        "Gendannelseskode",        # Danish: Recovery code
        "recovery code",
        "Use a recovery code",
        "Brug en gendannelseskode",
    ], timeout=5000)
    page.wait_for_load_state("networkidle")

    # ── Step 5: Enter the recovery code ──────────────────────────────────
    log("Step 5: Entering recovery code...")
    code = recovery_code.strip().replace(" ", "").replace("-", "")
    filled = try_fill(page, [
        'input[name="iOttText"]',
        'input[id="iOttText"]',
        'input[name*="recovery" i]',
        'input[id*="recovery" i]',
        'input[type="text"]',
        'input[type="tel"]',
    ], code)
    if not filled:
        log("[!] Could not find recovery code input — please enter it manually.")
        time.sleep(20)

    try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
    page.wait_for_load_state("networkidle")

    # ── Step 6: Add new security email ───────────────────────────────────
    log("Step 6: Adding new security email...")
    # Microsoft may show a field to add a verification email during recovery
    filled = try_fill(page, [
        'input[type="email"]',
        'input[name*="email" i]',
        'input[id*="email" i]',
    ], new_security_email, timeout=6000)

    if filled:
        try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
        page.wait_for_load_state("networkidle")
        log(f"[+] Security email set to {new_security_email}")
    else:
        log("[-] No email field shown at this step (Microsoft may skip this).")

    # ── Step 7: Set new password ──────────────────────────────────────────
    log("Step 7: Setting new password...")
    filled = try_fill(page, [
        'input[name="iNewPwd"]',
        'input[id="iNewPwd"]',
        'input[type="password"]',
    ], new_password, timeout=10000)

    if not filled:
        log("[!] Could not find password field — please enter it manually.")
        time.sleep(20)
    else:
        # Confirm field if present
        try_fill(page, [
            'input[name="iConfirmPwd"]',
            'input[id="iConfirmPwd"]',
        ], new_password, timeout=3000)

        try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
        page.wait_for_load_state("networkidle")
        log("[+] New password set.")

    # ── Step 8: Capture new recovery code ────────────────────────────────
    log("Step 8: Looking for new recovery code...")
    new_code = extract_recovery_code(page)

    # If not on page yet, navigate to security settings to generate one
    if not new_code:
        new_code = generate_recovery_code(page)

    return new_code


def extract_recovery_code(page: Page) -> str:
    """Try to read a recovery code from the current page."""
    try:
        body = page.inner_text("body")
        patterns = [
            r'\b([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b',
            r'\b(\d{4}-\d{4})\b',
            r'\b([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})\b',
        ]
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return m.group(1).upper()
    except Exception:
        pass
    return ""


def generate_recovery_code(page: Page) -> str:
    """Navigate to security settings and generate a new recovery code."""
    try:
        page.goto("https://account.microsoft.com/security", wait_until="networkidle", timeout=20000)

        try_click_text(page, ["Advanced security options", "More security options"], timeout=8000)
        page.wait_for_load_state("networkidle")

        try_click_text(page, [
            "Get a new code", "Generate a new recovery code",
            "Generate new code", "Recovery code",
        ], timeout=8000)
        page.wait_for_load_state("networkidle")

        try_click_text(page, ["Get a new code", "Generate", "Yes", "OK"], timeout=5000)
        page.wait_for_load_state("networkidle")

        code = extract_recovery_code(page)
        if code:
            return code

        log(f"[-] Could not auto-read recovery code. Please copy it from: {page.url}")
    except Exception as e:
        log(f"[!] Recovery code generation failed: {e}")
    return ""


# ---------------------------------------------------------------------------
# Extra security steps (run after login)
# ---------------------------------------------------------------------------

def revoke_sessions(page: Page) -> bool:
    try:
        page.goto("https://account.microsoft.com/security", wait_until="networkidle", timeout=20000)
        found = try_click_text(page, [
            "Sign out everywhere", "Sign out of all sessions",
        ], timeout=8000)
        if not found:
            log("[-] 'Sign out everywhere' button not found.")
            return False
        page.wait_for_load_state("networkidle")
        try_click_text(page, ["Sign out", "Yes", "OK", "Confirm"], timeout=5000)
        page.wait_for_load_state("networkidle")
        log("[+] Signed out of all other sessions.")
        return True
    except Exception as e:
        log(f"[!] Session revocation failed: {e}")
        return False


def remove_devices(page: Page) -> int:
    removed = 0
    try:
        page.goto("https://account.microsoft.com/devices", wait_until="networkidle", timeout=20000)
        while True:
            try:
                btn = page.get_by_role("button", name=re.compile(r"remove\s*(device|this)", re.I)).first
                btn.wait_for(timeout=4000, state="visible")
            except Exception:
                break
            name = "Unknown"
            try:
                row = btn.locator("xpath=ancestor::*[contains(@class,'device')][1]")
                name = row.locator("h2, h3, [class*='name'], [class*='title']").first.inner_text()
            except Exception:
                pass
            btn.click()
            page.wait_for_load_state("networkidle")
            try_click_text(page, ["Remove", "Yes", "Confirm", "OK"], timeout=5000)
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
# Per-account flow
# ---------------------------------------------------------------------------

def harden_account(browser: Browser, email: str, recovery_code: str,
                   new_password: str, new_security_email: str) -> dict:
    result = {
        "email": email,
        "success": False,
        "sessions_revoked": False,
        "devices_removed": 0,
        "new_recovery_code": "",
    }

    print(f"\n{'=' * 60}")
    print(f"  Account: {email}")
    print(f"{'=' * 60}")

    ctx = browser.new_context(
        viewport={"width": 1280, "height": 800},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    )
    page = ctx.new_page()

    try:
        new_code = secure_account(page, email, recovery_code, new_security_email, new_password)
        result["new_recovery_code"] = new_code
        result["success"] = True

        print("\n  --- Extra security steps ---")
        result["sessions_revoked"] = revoke_sessions(page)
        result["devices_removed"] = remove_devices(page)

    except Exception as e:
        log(f"[!] Unexpected error: {e}")
    finally:
        ctx.close()

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("Microsoft Account Security Hardener")
    print("=" * 38)
    print("""
For each account you need:
  - Microsoft account email
  - Current recovery code

The script will:
  1. Use the recovery code to regain access
  2. Set your new security email
  3. Set your new password
  4. Print your new recovery code
  + Sign out all other sessions
  + Remove all registered devices

The browser window stays open — solve any CAPTCHA manually.
""")

    print("--- Settings for every account ---\n")
    while True:
        new_security_email = input("New security email: ").strip()
        if new_security_email:
            break

    print("  (characters are hidden while you type — this is normal)")
    while True:
        new_password = getpass.getpass("New password (min 12 chars): ")
        if len(new_password) >= 12:
            break
        print("  Must be at least 12 characters.")

    print("\n--- Accounts to secure ---")
    print("Leave email blank when you have entered all accounts.\n")

    accounts: list[tuple[str, str]] = []
    while True:
        n = len(accounts) + 1
        email = input(f"  Account {n} email (blank to finish): ").strip()
        if not email:
            if not accounts:
                print("  Please enter at least one account.")
                continue
            break
        while True:
            code = input(f"  Account {n} recovery code: ").strip()
            if code:
                break
        accounts.append((email, code))

    print(f"\n{'=' * 60}")
    print(f"  Accounts      : {len(accounts)}")
    print(f"  Security email: {new_security_email}")
    print(f"  New password  : {'*' * len(new_password)}")
    print(f"{'=' * 60}")
    if input("\n  Proceed? [y/N] ").strip().lower() != "y":
        print("Aborted.")
        sys.exit(0)

    results = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, slow_mo=SLOW_MO)

        for i, (email, code) in enumerate(accounts):
            r = harden_account(browser, email, code, new_password, new_security_email)
            results.append(r)

            if r["new_recovery_code"]:
                print(f"\n  *** NEW RECOVERY CODE for {email} ***")
                print(f"      {r['new_recovery_code']}")
                print("      Write this down — the old code no longer works.\n")
            else:
                print(f"\n  [!] No recovery code captured for {email}.")
                print("      Check the browser window and write it down manually.\n")

            if i < len(accounts) - 1:
                print("  Waiting 5s before next account...")
                time.sleep(5)

        browser.close()

    print(f"\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    for r in results:
        status   = "OK"   if r["success"]          else "FAILED"
        sessions = "OK"   if r["sessions_revoked"]  else "FAIL"
        devices  = str(r["devices_removed"])
        code     = r["new_recovery_code"] or "not captured"
        print(f"  {r['email']}")
        print(f"    Status: {status}  |  Sessions revoked: {sessions}  |  Devices removed: {devices}")
        print(f"    New recovery code: {code}")
    print(f"{'=' * 60}\n")
    print("Keep your new recovery codes somewhere safe!")


if __name__ == "__main__":
    main()
