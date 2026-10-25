"""SQLite storage for the JWKS server's RSA private keys.

Every query uses sqlite3 "?" placeholders so that values are bound by the
driver and never interpolated into the SQL text (prevents SQL injection).
"""
import sqlite3
import time

DB_FILE = "totally_not_my_privateKeys.db"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


def connect(db_file=DB_FILE):
    """Open (creating if needed) the database and ensure the schema exists."""
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.execute(CREATE_TABLE_SQL)
    conn.commit()
    return conn


def insert_key(conn, pem, exp):
    """Store a PEM-encoded private key that expires at unix time `exp`.

    Returns the new key's kid.
    """
    cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, int(exp)))
    conn.commit()
    return cur.lastrowid


def get_key(conn, expired=False, now=None):
    """Return one (kid, pem, exp) row, either expired or still valid.

    Returns None if no matching key exists.
    """
    now = int(time.time()) if now is None else int(now)
    if expired:
        query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
    else:
        query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
    return conn.execute(query, (now,)).fetchone()


def get_valid_keys(conn, now=None):
    """Return all (kid, pem, exp) rows that have not yet expired."""
    now = int(time.time()) if now is None else int(now)
    return conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ?", (now,)
    ).fetchall()
