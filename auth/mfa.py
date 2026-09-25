"""TOTP-based Multi-Factor Authentication (RFC 6238) using pyotp and qrcode."""
import base64
import io

import pyotp
import qrcode

_ISSUER_NAME = "BankGuard"


def generate_secret() -> str:
    """Generate a new random base32 TOTP secret for a user."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Build the otpauth:// provisioning URI for enrolling a user in an authenticator app."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=_ISSUER_NAME)


def get_qr_code_base64(secret: str, username: str) -> str:
    """Generate a base64-encoded PNG QR code for the TOTP enrollment URI."""
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def verify_otp(secret: str, otp: str) -> bool:
    """Verify a user-submitted OTP against their TOTP secret, allowing one time-step drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)
