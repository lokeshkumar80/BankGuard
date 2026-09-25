"""FastAPI router for BankGuard: login, logout, dashboard alert feed, and transactions."""
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from audit.logger import log_event
from auth.mfa import generate_secret, get_qr_code_base64, verify_otp
from auth.session import (
    create_session,
    invalidate_session,
    is_locked,
    record_failed_attempt,
    reset_failed_attempts,
    validate_session,
)
from db.models import create_user, get_connection, get_user_by_username, verify_password
from encryption.aes import decrypt, encrypt
from fraud.detect import build_feature_vector, is_fraudulent

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="dashboard/templates")

OFF_HOURS_START = 22
OFF_HOURS_END = 8
FAILED_LOGIN_ANOMALY_THRESHOLD = 3


def get_current_user_id(session_token: Optional[str] = Cookie(default=None)) -> Optional[int]:
    """FastAPI dependency that resolves the logged-in user's id from the session cookie."""
    if not session_token:
        return None
    return validate_session(session_token)


def _is_off_hours(hour: int) -> bool:
    """Return True if the given hour falls outside the 8am-10pm normal access window."""
    return hour >= OFF_HOURS_START or hour < OFF_HOURS_END


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request) -> HTMLResponse:
    """Render the registration form."""
    return templates.TemplateResponse(request, "register.html")


@router.post("/register", response_class=HTMLResponse)
def register_submit(request: Request, username: str = Form(...), password: str = Form(...)) -> HTMLResponse:
    """Create a new user account and show their TOTP QR code for MFA enrollment."""
    if get_user_by_username(username) is not None:
        return templates.TemplateResponse(
            request, "register.html", {"error": "Username already exists."}
        )

    secret = generate_secret()
    create_user(username, password, mfa_secret=secret)
    qr_code_b64 = get_qr_code_base64(secret, username)
    log_event("user_registered", json.dumps({"username": username}))

    return templates.TemplateResponse(
        request,
        "register.html",
        {"registered": True, "qr_code_b64": qr_code_b64, "secret": secret},
    )


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    """Render the login form."""
    return templates.TemplateResponse(request, "login.html")


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    otp: str = Form(...),
):
    """Validate credentials + OTP, enforce lockout, flag login anomalies, and start a session."""
    if is_locked(username):
        log_event("login_blocked_lockout", json.dumps({"username": username}))
        return templates.TemplateResponse(
            request, "login.html", {"error": "Account locked. Try again later."}
        )

    user = get_user_by_username(username)
    valid_credentials = user is not None and verify_password(password, user["password_hash"])
    valid_otp = valid_credentials and verify_otp(user["mfa_secret"], otp)

    if not valid_credentials or not valid_otp:
        record_failed_attempt(username)
        log_event("login_failed", json.dumps({"username": username}))

        refreshed = get_user_by_username(username)
        if refreshed is not None and refreshed["failed_attempts"] >= FAILED_LOGIN_ANOMALY_THRESHOLD:
            log_event(
                "multiple_failed_logins",
                json.dumps({"username": username, "failed_attempts": refreshed["failed_attempts"]}),
            )

        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username, password, or OTP."}
        )

    reset_failed_attempts(username)

    current_hour = datetime.now().hour
    if _is_off_hours(current_hour):
        log_event("off_hours_login", json.dumps({"username": username, "hour": current_hour}))

    session_token = create_session(user["id"])
    log_event("login_success", json.dumps({"username": username}))

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="session_token", value=session_token, httponly=True, samesite="lax")
    return response


@router.get("/logout")
def logout(session_token: Optional[str] = Cookie(default=None)) -> RedirectResponse:
    """Invalidate the current session and redirect to the login page."""
    if session_token:
        invalidate_session(session_token)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_token")
    return response


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user_id: Optional[int] = Depends(get_current_user_id)):
    """Render the real-time alert feed and flagged transactions dashboard."""
    if user_id is None:
        return RedirectResponse(url="/login", status_code=303)

    conn = get_connection()
    flagged_rows = conn.execute(
        "SELECT id, amount, merchant, pan_encrypted, timestamp FROM transactions "
        "WHERE is_fraud = 1 ORDER BY id DESC LIMIT 25"
    ).fetchall()
    audit_rows = conn.execute(
        "SELECT timestamp, event, data FROM audit_logs ORDER BY id DESC LIMIT 25"
    ).fetchall()
    conn.close()

    flagged_transactions = []
    for row in flagged_rows:
        try:
            pan_plain = decrypt(row["pan_encrypted"])
            pan_display = f"**** **** **** {pan_plain[-4:]}"
        except Exception:
            pan_display = "N/A"
        flagged_transactions.append(
            {
                "id": row["id"],
                "amount": row["amount"],
                "merchant": row["merchant"],
                "pan": pan_display,
                "timestamp": row["timestamp"],
            }
        )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "flagged_transactions": flagged_transactions,
            "audit_entries": audit_rows,
        },
    )


@router.post("/transactions")
def submit_transaction(
    amount: float = Form(...),
    merchant: str = Form(...),
    pan: str = Form(...),
    user_id: Optional[int] = Depends(get_current_user_id),
):
    """Encrypt PII, score the transaction for fraud, persist it, and audit-log the result."""
    if user_id is None:
        return RedirectResponse(url="/login", status_code=303)

    fraud_flag = is_fraudulent(build_feature_vector(amount))
    pan_encrypted = encrypt(pan)

    conn = get_connection()
    conn.execute(
        """
        INSERT INTO transactions (user_id, amount, merchant, pan_encrypted, is_fraud)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, amount, merchant, pan_encrypted, int(fraud_flag)),
    )
    conn.commit()
    conn.close()

    log_event(
        "transaction_scored",
        json.dumps({"user_id": user_id, "amount": amount, "merchant": merchant, "flagged": fraud_flag}),
    )

    return RedirectResponse(url="/dashboard", status_code=303)
