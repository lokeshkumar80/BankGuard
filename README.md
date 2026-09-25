# BankGuard -- Financial Security Intelligence System

A multi-module financial security system demonstrating core cybersecurity concepts in a
banking context: fraud detection, encrypted PII storage, Multi-Factor Authentication, and
tamper-evident audit logging.

Every module maps to a real-world banking security concern:

| OWASP Top 10 Item | Where covered in BankGuard |
|---|---|
| Broken Authentication | MFA (TOTP), brute-force lockout, session expiry |
| Sensitive Data Exposure | AES-256-GCM encryption on PAN and account numbers |
| Security Logging Failures | SHA-256 hash-chained tamper-evident audit logs |
| Injection | Parameterized SQL queries throughout |
| Security Misconfiguration | `.env` key management, no hardcoded secrets |

## Tech Stack

- **Backend:** Python, FastAPI
- **ML:** scikit-learn (Isolation Forest), pandas, numpy
- **Encryption:** `cryptography` (AES-256-GCM)
- **MFA:** pyotp, qrcode (TOTP / RFC 6238)
- **Hashing:** hashlib (PBKDF2-HMAC-SHA256 for passwords, SHA-256 hash chain for audit logs)
- **Database:** SQLite (raw `sqlite3`, no ORM)
- **Frontend:** HTML/CSS + Jinja2 templates via FastAPI

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env (AES_KEY and SECRET_KEY)
echo "AES_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" >> .env

# (Optional) Train the fraud detection model
# Download creditcard.csv from https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
# and place it in fraud/creditcard.csv
python fraud/train.py

# Run the app
uvicorn main:app --reload
```

Then visit `http://127.0.0.1:8000/register` to create an account and enroll MFA, then
`http://127.0.0.1:8000/login` to sign in and reach the dashboard.

> Note: transaction scoring on the dashboard requires a trained model at
> `fraud/model/model.pkl`. Without one, `POST /transactions` will raise until
> `python fraud/train.py` has been run against a downloaded `creditcard.csv`.

## Project Structure

See [CLAUDE.md](CLAUDE.md) for the full module breakdown and build order.
