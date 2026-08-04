"""Two OTP flows, same underlying mechanics: 6-digit codes, actually emailed.

- Password reset (password_resets table): proves you can get back into an
  account you forgot the password for.
- Sign-up email verification (email_verifications table): proves whoever
  registered actually owns that inbox - something the format + MX-record
  check in email_validate.py deliberately does NOT prove (that only
  confirms the domain exists, not that this person controls a mailbox there).

Both: short-lived, single-use, scoped to one user (looked up by email) so a
6-digit space can't be brute-forced across the whole user base - see
RESET_CODE_MAX_ATTEMPTS / VERIFY_CODE_MAX_ATTEMPTS in config.py for the
per-code guess limit. Delivery goes through services/mailer.py (real SMTP);
if no SMTP provider is configured, routes/api.py falls back to returning the
code directly in the response so local/dev testing still works end-to-end.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..db import execute, query
from . import mailer


def _hash_code(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def _create_otp(table, user_id, expiry_minutes):
    """Issues a fresh 6-digit code in the given table, invalidating any
    earlier unused codes for this user first so only the latest is valid."""
    execute(f"UPDATE {table} SET used_at=datetime('now') "
            f"WHERE user_id=? AND used_at IS NULL", (user_id,))
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    execute(f"INSERT INTO {table} (user_id, token_hash, expires_at) VALUES (?,?,?)",
            (user_id, _hash_code(code), expires_at.isoformat()))
    return code


def _verify_otp(table, user_id, code, max_attempts):
    """Validates a code for a specific user in the given table. Returns
    (ok, error_message). Wrong guesses are counted per-code; too many locks
    that code out early (the user just requests a fresh one) so 6 digits
    can't be brute-forced by spamming the endpoint."""
    row = query(
        f"SELECT * FROM {table} WHERE user_id=? AND used_at IS NULL "
        f"ORDER BY id DESC LIMIT 1", (user_id,), one=True)
    if row is None:
        return False, "That code is invalid or has expired. Request a new one."
    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return False, "That code has expired. Request a new one."
    if row["attempts"] >= max_attempts:
        return False, "Too many incorrect attempts. Request a new code."
    if not secrets.compare_digest(row["token_hash"], _hash_code(code)):
        execute(f"UPDATE {table} SET attempts=attempts+1 WHERE id=?", (row["id"],))
        left = max_attempts - (row["attempts"] + 1)
        if left <= 0:
            return False, "Too many incorrect attempts. Request a new code."
        return False, f"That code isn't right. {left} attempt{'s' if left != 1 else ''} left."
    execute(f"UPDATE {table} SET used_at=datetime('now') WHERE id=?", (row["id"],))
    return True, None


def _send_otp_email(email_addr, code, subject, purpose_line, expiry_minutes):
    text_body = (
        f"{purpose_line}\n\nYour code is: {code}\n\n"
        f"This code expires in {expiry_minutes} minutes and can only be used once.\n\n"
        "If this wasn't you, you can safely ignore this email."
    )
    html_body = f"""
    <div style="font-family:sans-serif;max-width:420px;margin:auto">
      <h2 style="color:#FF5C8A">HealthBuddy</h2>
      <p>{purpose_line}</p>
      <p style="font-size:32px;font-weight:800;letter-spacing:6px;
                background:#f4f4f8;padding:16px 20px;border-radius:12px;
                text-align:center;color:#1C1526">{code}</p>
      <p style="color:#666">This code expires in {expiry_minutes} minutes and can only be used once.</p>
      <p style="color:#999;font-size:13px">If this wasn't you, you can safely ignore this email.</p>
    </div>"""
    return mailer.send_email(email_addr, subject, text_body, html_body)


# ---------- Password reset ----------

def create_reset_code(user_id):
    return _create_otp("password_resets", user_id, current_app.config["RESET_TOKEN_EXPIRY_MINUTES"])


def verify_reset_code(user_id, code):
    return _verify_otp("password_resets", user_id, code, current_app.config["RESET_CODE_MAX_ATTEMPTS"])


def send_password_reset(email_addr, code):
    """Returns True if actually emailed via a configured SMTP provider,
    False otherwise (caller decides whether to fall back to exposing the
    code directly, e.g. in local dev)."""
    minutes = current_app.config["RESET_TOKEN_EXPIRY_MINUTES"]
    sent = _send_otp_email(email_addr, code, "Your HealthBuddy password reset code",
                            "Your password reset code is below.", minutes)
    if not sent:
        current_app.logger.info("[password reset] %s -> code=%s (not emailed - see services/mailer.py)",
                                 email_addr, code)
    return sent


# ---------- Sign-up email verification ----------

def create_verification_code(user_id):
    return _create_otp("email_verifications", user_id, current_app.config["VERIFY_CODE_EXPIRY_MINUTES"])


def verify_verification_code(user_id, code):
    return _verify_otp("email_verifications", user_id, code, current_app.config["VERIFY_CODE_MAX_ATTEMPTS"])


def send_verification_email(email_addr, code):
    """Same return-value contract as send_password_reset - see there."""
    minutes = current_app.config["VERIFY_CODE_EXPIRY_MINUTES"]
    sent = _send_otp_email(email_addr, code, "Verify your email for HealthBuddy",
                            "Welcome to HealthBuddy! Enter this code in the app to verify your email.", minutes)
    if not sent:
        current_app.logger.info("[email verify] %s -> code=%s (not emailed - see services/mailer.py)",
                                 email_addr, code)
    return sent
