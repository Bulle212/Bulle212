#!/usr/bin/env python3
"""
Microsoft Account Security Bot
--------------------------------
A Discord bot that secures Microsoft accounts via the recovery code flow.

Commands:
  /setup    — set the new password and security email (applied to all accounts)
  /add      — add a Microsoft account (email + recovery code) to the queue
  /run      — start securing all queued accounts
  /status   — show what's currently in the queue
  /clear    — clear the queue

All responses are ephemeral (only visible to you).
Results are sent via DM so recovery codes stay private.

Setup:
  1. Go to https://discord.com/developers/applications
  2. Create an application → Bot → copy the token
  3. Enable "applications.commands" scope + "bot" scope when inviting
  4. Paste your token when the script asks, or set DISCORD_TOKEN env variable
  5. pip install -r requirements.txt && playwright install chromium
  6. python bot.py
"""

import os
import re
import asyncio
from dataclasses import dataclass, field

import discord
from discord import app_commands
from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PWTimeout

# ---------------------------------------------------------------------------
# Per-user session
# ---------------------------------------------------------------------------

@dataclass
class Session:
    new_password: str = ""
    new_security_email: str = ""
    accounts: list = field(default_factory=list)  # [(email, recovery_code)]
    running: bool = False

sessions: dict[int, Session] = {}

def get_session(user_id: int) -> Session:
    if user_id not in sessions:
        sessions[user_id] = Session()
    return sessions[user_id]

# ---------------------------------------------------------------------------
# Playwright helpers
# ---------------------------------------------------------------------------

async def try_fill(page: Page, selectors: list, value: str, timeout: int = 5000) -> bool:
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=timeout, state="visible")
            await page.fill(sel, value)
            return True
        except PWTimeout:
            continue
    return False


async def try_click(page: Page, selectors: list, timeout: int = 5000) -> bool:
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, timeout=timeout, state="visible")
            await page.click(sel)
            return True
        except PWTimeout:
            continue
    return False


async def try_click_text(page: Page, texts: list, timeout: int = 5000) -> bool:
    for text in texts:
        try:
            el = page.get_by_text(text, exact=False).first
            await el.wait_for(timeout=timeout, state="visible")
            await el.click()
            return True
        except Exception:
            continue
    return False

# ---------------------------------------------------------------------------
# Recovery flow
# ---------------------------------------------------------------------------

async def secure_account(page: Page, email: str, recovery_code: str,
                          new_security_email: str, new_password: str) -> dict:
    result = {
        "email": email,
        "password_set": False,
        "sessions_revoked": False,
        "security_email_updated": False,
        "devices_removed": 0,
        "new_recovery_code": "",
        "error": "",
    }

    try:
        # Step 1-2: Open reset page and enter email
        await page.goto("https://account.live.com/password/reset", wait_until="domcontentloaded")
        await page.wait_for_load_state("domcontentloaded")

        if not await try_fill(page, ['input[name="iLoginName"]', 'input[name="loginfmt"]', 'input[type="email"]'], email):
            result["error"] = "Could not find email field"
            return result

        await try_click(page, ['input[type="submit"]', '#idSIButton9', 'button[type="submit"]'])
        await page.wait_for_load_state("domcontentloaded")

        # Step 3: "Jeg har ikke nogen af dem" / "I don't have any of these"
        found = await try_click_text(page, [
            "Jeg har ikke nogen af dem",
            "I don't have this information",
            "I don't have any of these",
            "don't have this information",
        ], timeout=8000)
        if not found:
            result["error"] = "Could not find 'I don't have any of these' button"
            return result
        await page.wait_for_load_state("domcontentloaded")

        # Step 4: Select recovery code option if a choice is shown
        await try_click_text(page, [
            "Gendannelseskode",
            "recovery code",
            "Use a recovery code",
            "Brug en gendannelseskode",
        ], timeout=4000)
        await page.wait_for_load_state("domcontentloaded")

        # Step 5: Enter the recovery code
        code = recovery_code.strip().replace(" ", "").replace("-", "")
        if not await try_fill(page, [
            'input[name="iOttText"]',
            'input[id="iOttText"]',
            'input[name*="recovery" i]',
            'input[id*="recovery" i]',
            'input[type="text"]',
            'input[type="tel"]',
        ], code):
            result["error"] = "Could not find recovery code input"
            return result

        await try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
        await page.wait_for_load_state("domcontentloaded")

        # Step 6: Add security email if prompted
        if await try_fill(page, [
            'input[type="email"]',
            'input[name*="email" i]',
            'input[id*="email" i]',
        ], new_security_email, timeout=4000):
            await try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
            await page.wait_for_load_state("domcontentloaded")
            result["security_email_updated"] = True

        # Step 7: Set new password
        if await try_fill(page, [
            'input[name="iNewPwd"]',
            'input[id="iNewPwd"]',
            'input[type="password"]',
        ], new_password, timeout=8000):
            await try_fill(page, ['input[name="iConfirmPwd"]', 'input[id="iConfirmPwd"]'], new_password, timeout=3000)
            await try_click(page, ['input[type="submit"]', 'button[type="submit"]', '#idSIButton9'])
            await page.wait_for_load_state("domcontentloaded")
            result["password_set"] = True

        # Step 8: Capture new recovery code from page
        result["new_recovery_code"] = extract_recovery_code(await page.inner_text("body"))

        # Bonus: revoke sessions
        result["sessions_revoked"] = await revoke_sessions(page)

        # Bonus: remove devices
        result["devices_removed"] = await remove_devices(page)

        # If recovery code not found yet, navigate to security settings
        if not result["new_recovery_code"]:
            result["new_recovery_code"] = await generate_recovery_code(page)

    except Exception as e:
        result["error"] = str(e)

    return result


def extract_recovery_code(body: str) -> str:
    patterns = [
        r'\b([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b',
        r'\b(\d{4}-\d{4})\b',
        r'\b([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})\b',
    ]
    for pattern in patterns:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ""


async def revoke_sessions(page: Page) -> bool:
    try:
        await page.goto("https://account.microsoft.com/security", wait_until="domcontentloaded", timeout=20000)
        found = await try_click_text(page, ["Sign out everywhere", "Sign out of all sessions"], timeout=6000)
        if found:
            await page.wait_for_load_state("domcontentloaded")
            await try_click_text(page, ["Sign out", "Yes", "OK", "Confirm"], timeout=4000)
            return True
    except Exception:
        pass
    return False


async def remove_devices(page: Page) -> int:
    removed = 0
    try:
        await page.goto("https://account.microsoft.com/devices", wait_until="domcontentloaded", timeout=20000)
        while True:
            try:
                btn = page.get_by_role("button", name=re.compile(r"remove\s*(device|this)", re.I)).first
                await btn.wait_for(timeout=3000, state="visible")
                await btn.click()
                await page.wait_for_load_state("domcontentloaded")
                await try_click_text(page, ["Remove", "Yes", "Confirm", "OK"], timeout=4000)
                await page.wait_for_load_state("domcontentloaded")
                removed += 1
            except Exception:
                break
    except Exception:
        pass
    return removed


async def generate_recovery_code(page: Page) -> str:
    try:
        await page.goto("https://account.microsoft.com/security", wait_until="domcontentloaded", timeout=20000)
        await try_click_text(page, ["Advanced security options", "More security options"], timeout=6000)
        await page.wait_for_load_state("domcontentloaded")
        await try_click_text(page, ["Get a new code", "Generate a new recovery code", "Recovery code"], timeout=6000)
        await page.wait_for_load_state("domcontentloaded")
        await try_click_text(page, ["Get a new code", "Generate", "Yes"], timeout=4000)
        await page.wait_for_load_state("domcontentloaded")
        return extract_recovery_code(await page.inner_text("body"))
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# Background processor
# ---------------------------------------------------------------------------

async def process_accounts(user: discord.User, session: Session) -> None:
    results = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)

        for email, recovery_code in list(session.accounts):
            ctx = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = await ctx.new_page()
            result = await secure_account(page, email, recovery_code,
                                          session.new_security_email, session.new_password)
            results.append(result)
            await ctx.close()

        await browser.close()

    session.running = False
    session.accounts.clear()

    # Send results via DM (private — recovery codes stay off the server)
    embed = build_embed(results)
    try:
        await user.send(embed=embed)
    except discord.Forbidden:
        pass  # User has DMs disabled


def build_embed(results: list) -> discord.Embed:
    all_ok = all(r["password_set"] for r in results)
    embed = discord.Embed(
        title="Account Security Results",
        color=discord.Color.green() if all_ok else discord.Color.orange(),
    )

    for r in results:
        lines = [
            f"{'✅' if r['password_set']           else '❌'} Password set",
            f"{'✅' if r['sessions_revoked']        else '❌'} Sessions revoked",
            f"{'✅' if r['security_email_updated']  else '⚠️'} Security email updated",
            f"{'✅' if r['devices_removed'] > 0     else '➖'} Devices removed: {r['devices_removed']}",
            f"🔑 New recovery code: `{r['new_recovery_code'] or 'not captured — check browser'}`",
        ]
        if r["error"]:
            lines.append(f"⚠️ Error: {r['error'][:100]}")

        embed.add_field(name=r["email"], value="\n".join(lines), inline=False)

    embed.set_footer(text="Store your recovery codes somewhere safe.")
    return embed

# ---------------------------------------------------------------------------
# Discord bot
# ---------------------------------------------------------------------------

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


@tree.command(name="setup", description="Set the new password and security email for all accounts")
@app_commands.describe(
    new_password="New password (min 12 chars) — only you can see this",
    security_email="New security/recovery email to set on all accounts",
)
async def cmd_setup(interaction: discord.Interaction, new_password: str, security_email: str):
    await interaction.response.defer(ephemeral=True)

    if len(new_password) < 12:
        await interaction.followup.send("❌ Password must be at least 12 characters.", ephemeral=True)
        return

    s = get_session(interaction.user.id)
    s.new_password = new_password
    s.new_security_email = security_email

    await interaction.followup.send(
        f"✅ Settings saved.\n"
        f"- Security email: `{security_email}`\n"
        f"- Password: `{'*' * len(new_password)}`",
        ephemeral=True,
    )


@tree.command(name="add", description="Add a Microsoft account to the queue")
@app_commands.describe(
    email="Microsoft account email address",
    recovery_code="Current recovery code for this account",
)
async def cmd_add(interaction: discord.Interaction, email: str, recovery_code: str):
    await interaction.response.defer(ephemeral=True)

    s = get_session(interaction.user.id)
    if not s.new_password or not s.new_security_email:
        await interaction.followup.send("❌ Run `/setup` first.", ephemeral=True)
        return
    if s.running:
        await interaction.followup.send("❌ Already running — wait for it to finish.", ephemeral=True)
        return

    s.accounts.append((email, recovery_code))
    await interaction.followup.send(
        f"✅ `{email}` added. Queue: **{len(s.accounts)}** account(s).",
        ephemeral=True,
    )


@tree.command(name="run", description="Start securing all queued accounts")
async def cmd_run(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    s = get_session(interaction.user.id)
    if not s.accounts:
        await interaction.followup.send("❌ Queue is empty. Use `/add` first.", ephemeral=True)
        return
    if s.running:
        await interaction.followup.send("❌ Already running.", ephemeral=True)
        return

    count = len(s.accounts)
    s.running = True
    asyncio.create_task(process_accounts(interaction.user, s))

    await interaction.followup.send(
        f"🔄 Started securing **{count}** account(s).\n"
        f"Results will be sent to you via DM when done.",
        ephemeral=True,
    )


@tree.command(name="status", description="Show what's in your queue")
async def cmd_status(interaction: discord.Interaction):
    s = get_session(interaction.user.id)

    if s.running:
        await interaction.response.send_message("⏳ Currently running...", ephemeral=True)
        return
    if not s.accounts:
        await interaction.response.send_message("Queue is empty.", ephemeral=True)
        return

    lines = [f"`{email}`" for email, _ in s.accounts]
    await interaction.response.send_message(
        f"**Queue — {len(s.accounts)} account(s):**\n" + "\n".join(lines),
        ephemeral=True,
    )


@tree.command(name="clear", description="Clear your account queue")
async def cmd_clear(interaction: discord.Interaction):
    s = get_session(interaction.user.id)
    if s.running:
        await interaction.response.send_message("❌ Can't clear while running.", ephemeral=True)
        return
    count = len(s.accounts)
    s.accounts.clear()
    await interaction.response.send_message(f"🗑️ Cleared {count} account(s).", ephemeral=True)


@client.event
async def on_ready():
    await tree.sync()
    print(f"Bot online: {client.user}  |  Commands synced.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN") or input("Paste your Discord bot token: ").strip()
    if not token:
        print("No token provided. Exiting.")
    else:
        client.run(token)
