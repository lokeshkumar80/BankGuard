# CLAUDE.md -- BankGuard Project Context

## Project Overview

**BankGuard -- Financial Security Intelligence System**
A multi-module financial security system built for demonstrating core cybersecurity
concepts in a banking context. Covers fraud detection, encrypted PII storage,
Multi-Factor Authentication, and tamper-evident audit logging.

**Resume project for ICICI Bank cybersecurity role campus placement.**
Every module maps to a real-world banking security concept -- keep that framing
in code comments and README.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| ML | scikit-learn (Isolation Forest), pandas, numpy |
| Encryption | cryptography library (AES-256-GCM) |
| MFA | pyotp, qrcode |
| Hashing | hashlib (SHA-256) |
| Database | SQLite (via Python sqlite3) |
| Frontend | HTML/CSS + Jinja2 templates (FastAPI) |
| Key Management | python-dotenv (.env file) |

---

## Repo Structure

```
BankGuard/
├── main.py                  # FastAPI app entry point, registers all routers
├── .env                     # AES_KEY, SECRET_KEY -- NEVER commit this
├── .gitignore               # Must include .env, __pycache__, *.db
├── requirements.txt
├── README.md
├── CLAUDE.md                # This file
│
├── auth/
│   ├── __init__.py
│   ├── mfa.py               # TOTP generation, QR code, OTP verification
│   └── session.py           # JWT-like session tokens, expiry, brute-force lockout
│
├── encryption/
│   ├── __init__.py
│   └── aes.py               # AES-256-GCM encrypt() and decrypt() for PII fields
│
├── fraud/
│   ├── __init__.py
│   ├── train.py             # Train Isolation Forest on Kaggle credit card dataset
│   ├── detect.py            # Load saved model, run inference on transaction
│   └── model/               # Saved model artifact (model.pkl) -- gitignored if large
│
├── audit/
│   ├── __init__.py
│   └── logger.py            # SHA-256 hash-chained log writer and chain verifier
│
├── dashboard/
│   ├── __init__.py
│   ├── routes.py            # FastAPI router for dashboard views
│   └── templates/
│       ├── base.html
│       ├── dashboard.html   # Real-time alert feed, flagged transactions
│       └── login.html
│
└── db/
    ├── __init__.py
    └── models.py            # SQLite table setup: users, transactions, audit_logs
```

---

## Module Responsibilities

### `encryption/aes.py`
- AES-256-GCM symmetric encryption
- Functions: `encrypt(plaintext: str) -> str`, `decrypt(ciphertext: str) -> str`
- Key loaded from `.env` via `os.getenv("AES_KEY")`
- Used for: PAN numbers, account numbers, Aadhaar -- any PII before DB write
- Never hardcode the key, never log decrypted values

### `auth/mfa.py`
- TOTP using `pyotp` (RFC 6238)
- Functions: `generate_secret()`, `get_totp_uri(secret, username)`, `verify_otp(secret, otp)`
- QR code generation with `qrcode` library for Google Authenticator enrollment

### `auth/session.py`
- Session token: `secrets.token_hex(32)` stored in DB with expiry timestamp
- Brute-force lockout: track failed attempts per username, lock after 5 failures
- Functions: `create_session(user_id)`, `validate_session(token)`, `record_failed_attempt(username)`

### `fraud/train.py`
- Dataset: Kaggle Credit Card Fraud Detection (creditcard.csv)
- Model: `IsolationForest(contamination=0.001, random_state=42)`
- Save model with `joblib.dump`
- Print precision, recall, F1 on test split after training

### `fraud/detect.py`
- Load saved model with `joblib.load`
- Function: `is_fraudulent(transaction: dict) -> bool`
- Returns True if Isolation Forest flags the transaction as anomaly

### `audit/logger.py`
- Each log entry: `{id, timestamp, event, data, prev_hash, current_hash}`
- `current_hash = SHA-256(prev_hash + timestamp + event + data)`
- Functions: `log_event(event: str, data: str)`, `verify_chain() -> bool`
- Store logs in SQLite audit_logs table

### `db/models.py`
- Tables: `users`, `sessions`, `transactions`, `audit_logs`
- Pure sqlite3, no ORM -- keep it simple and explicit
- Function: `init_db()` called on app startup

### `dashboard/routes.py`
- FastAPI router, Jinja2 templates
- Routes: `/dashboard` (alert feed), `/login`, `/logout`
- Login anomaly checks: multiple failed logins, off-hours access (outside 8am-10pm)

---

## Coding Conventions

- Python 3.10+
- All secrets via `os.getenv()` -- never hardcoded
- Every function has a one-line docstring
- No print statements in production paths -- use Python `logging` module
- Structured logs: `logging.info(json.dumps({...}))`
- All DB queries use parameterized statements -- no f-string SQL
- Functions return typed values -- use type hints throughout
- `.env` in `.gitignore` from day one -- check before every push

---

## Build and Run

```bash
# Install dependencies
pip install fastapi uvicorn cryptography pyotp qrcode scikit-learn \
            pandas numpy python-dotenv joblib

# Freeze
pip freeze > requirements.txt

# Create .env (do this before any other file)
echo "AES_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" >> .env

# Train fraud model (download creditcard.csv from Kaggle first)
python fraud/train.py

# Run the app
uvicorn main:app --reload
```

---

## Build Order

Build modules in this sequence -- each is independently testable before wiring together:

1. `db/models.py` -- init_db(), table creation
2. `encryption/aes.py` -- encrypt/decrypt, test with a PAN string
3. `auth/mfa.py` -- TOTP, test OTP generation and verify
4. `auth/session.py` -- session tokens, brute-force lockout
5. `fraud/train.py` then `fraud/detect.py` -- needs creditcard.csv
6. `audit/logger.py` -- hash chaining, test verify_chain()
7. `main.py` + `dashboard/` -- wire everything together

---

## OWASP Coverage (for interview reference)

| OWASP Top 10 Item | Where covered in BankGuard |
|---|---|
| Broken Authentication | MFA, brute-force lockout, session expiry |
| Sensitive Data Exposure | AES-256-GCM on PAN and account numbers |
| Security Logging Failures | SHA-256 hash-chained tamper-evident audit logs |
| Injection | Parameterized SQL queries throughout |
| Security Misconfiguration | .env key management, no hardcoded secrets |

---

## Dataset

- **Kaggle Credit Card Fraud Detection**
- URL: https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
- File: `creditcard.csv` -- place in `fraud/` directory
- Add `fraud/creditcard.csv` and `fraud/model/*.pkl` to `.gitignore`

---

## What to NOT commit

```gitignore
.env
__pycache__/
*.pyc
*.db
fraud/creditcard.csv
fraud/model/*.pkl
.DS_Store
```
