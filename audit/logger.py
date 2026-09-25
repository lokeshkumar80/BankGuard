"""SHA-256 hash-chained tamper-evident audit log writer and chain verifier."""
import hashlib
import logging
from datetime import datetime

from db.models import get_connection

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _compute_hash(prev_hash: str, timestamp: str, event: str, data: str) -> str:
    """Compute the SHA-256 hash linking a log entry to the previous entry in the chain."""
    payload = f"{prev_hash}{timestamp}{event}{data}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _get_last_hash(conn) -> str:
    """Fetch the current_hash of the most recent audit log entry, or the genesis hash."""
    row = conn.execute(
        "SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["current_hash"] if row else GENESIS_HASH


def log_event(event: str, data: str) -> None:
    """Append a new tamper-evident, hash-chained entry to the audit log."""
    conn = get_connection()
    prev_hash = _get_last_hash(conn)
    timestamp = datetime.utcnow().isoformat()
    current_hash = _compute_hash(prev_hash, timestamp, event, data)

    conn.execute(
        """
        INSERT INTO audit_logs (timestamp, event, data, prev_hash, current_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (timestamp, event, data, prev_hash, current_hash),
    )
    conn.commit()
    conn.close()

    logger.info("audit_event event=%s", event)


def verify_chain() -> bool:
    """Walk the entire audit log and verify every hash link is intact and untampered."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT timestamp, event, data, prev_hash, current_hash FROM audit_logs ORDER BY id ASC"
    ).fetchall()
    conn.close()

    expected_prev_hash = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev_hash:
            logger.error("audit_chain_broken expected_prev=%s got=%s", expected_prev_hash, row["prev_hash"])
            return False

        recomputed_hash = _compute_hash(row["prev_hash"], row["timestamp"], row["event"], row["data"])
        if recomputed_hash != row["current_hash"]:
            logger.error("audit_chain_tampered timestamp=%s event=%s", row["timestamp"], row["event"])
            return False

        expected_prev_hash = row["current_hash"]

    return True
