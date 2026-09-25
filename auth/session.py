"""Session token management and brute-force lockout for BankGuard authentication."""
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from db.models import get_connection

logger = logging.getLogger(__name__)

SESSION_TTL_MINUTES = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def create_session(user_id: int) -> str:
    """Create a new session token for the given user and persist it with an expiry."""
    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_TTL_MINUTES)

    conn = get_connection()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at.isoformat()),
    )
    conn.commit()
    conn.close()

    logger.info("session_created user_id=%s", user_id)
    return token


def validate_session(token: str) -> Optional[int]:
    """Return the user_id for a valid, unexpired session token, or None if invalid/expired."""
    conn = get_connection()
    row = conn.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if row is None:
        return None

    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        return None

    return row["user_id"]


def invalidate_session(token: str) -> None:
    """Delete a session token, logging the user out."""
    conn = get_connection()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def record_failed_attempt(username: str) -> None:
    """Increment a user's failed-login counter, locking the account after too many failures."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, failed_attempts FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None:
        conn.close()
        return

    new_count = row["failed_attempts"] + 1
    locked_until = None
    if new_count >= MAX_FAILED_ATTEMPTS:
        locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        logger.warning("account_locked username=%s failed_attempts=%s", username, new_count)

    conn.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
        (new_count, locked_until, username),
    )
    conn.commit()
    conn.close()


def reset_failed_attempts(username: str) -> None:
    """Clear a user's failed-login counter and lockout after a successful login."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
        (username,),
    )
    conn.commit()
    conn.close()


def is_locked(username: str) -> bool:
    """Check whether a user's account is currently locked out due to failed attempts."""
    conn = get_connection()
    row = conn.execute(
        "SELECT locked_until FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if row is None or row["locked_until"] is None:
        return False

    return datetime.fromisoformat(row["locked_until"]) > datetime.utcnow()
