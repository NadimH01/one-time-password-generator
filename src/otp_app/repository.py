import sqlite3
from pathlib import Path


def connect_database(database_path: Path) -> sqlite3.Connection:

    connection = sqlite3.connect(database_path)

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def create_schema(
    connection: sqlite3.Connection
) -> None:

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY NOT NULL,
            account_name TEXT UNIQUE NOT NULL,
            secret_ciphertext BLOB NOT NULL,
            created_at INTEGER NOT NULL
                CHECK (created_at >= 0)
        );

        CREATE TABLE IF NOT EXISTS verification_state (
            account_id TEXT PRIMARY KEY NOT NULL,
            last_accepted_counter INTEGER NOT NULL DEFAULT -1
                CHECK (last_accepted_counter >= -1),
            failed_attempts INTEGER NOT NULL DEFAULT 0
                CHECK (
                    failed_attempts >= 0
                    AND failed_attempts <= 5
                ),
            locked_until INTEGER NOT NULL DEFAULT 0
                CHECK (locked_until >= 0),

            FOREIGN KEY (account_id)
                REFERENCES accounts(account_id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            event_id INTEGER PRIMARY KEY,
            occurred_at INTEGER NOT NULL
                CHECK (occurred_at >= 0),
            account_id TEXT,
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL,

            FOREIGN KEY (account_id)
                REFERENCES accounts(account_id)
        );

        CREATE TABLE IF NOT EXISTS application_metadata (
            singleton_id INTEGER PRIMARY KEY
                CHECK (singleton_id = 1),
            schema_version INTEGER NOT NULL,
            database_id TEXT UNIQUE NOT NULL,
            key_check_ciphertext BLOB NOT NULL,
            last_seen_unix_s INTEGER NOT NULL
                CHECK (last_seen_unix_s >= 0)
        );
        """
    )


    connection.commit()


def insert_account(
    connection,
    account_id: str,
    account_name: str,
    secret_ciphertext: bytes,
    created_at: int,
) -> None:

    connection.execute(
        """
        INSERT INTO accounts (
            account_id,
            account_name,
            secret_ciphertext,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            account_id,
            account_name,
            secret_ciphertext,
            created_at,
        ),
    )


def insert_initial_verification_state(
    connection,
    account_id: str,
) -> None:

    connection.execute(
        """
        INSERT INTO verification_state (
            account_id,
            last_accepted_counter,
            failed_attempts,
            locked_until
        )
        VALUES (?, -1, 0, 0)
        """,
        (account_id,),
    )


def get_account(
    connection,
    account_id: str,
):

    cursor = connection.execute(
        """
        SELECT
            account_id,
            account_name,
            secret_ciphertext,
            created_at
        FROM accounts
        WHERE account_id = ?
        """,
        (account_id,),
    )

    return cursor.fetchone()


def create_account_record(
    connection,
    account_id: str,
    account_name: str,
    secret_ciphertext: bytes,
    created_at: int,
) -> None:

    try:
        connection.execute("BEGIN")

        insert_account(
            connection,
            account_id,
            account_name,
            secret_ciphertext,
            created_at,
        )

        insert_initial_verification_state(
            connection,
            account_id,
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise


def get_verification_state(
    connection,
    account_id: str,
):
    return connection.execute(
        """
        SELECT
            last_accepted_counter,
            failed_attempts,
            locked_until
        FROM verification_state
        WHERE account_id = ?
        """,
        (account_id,),
    ).fetchone()
def update_verification_state(
    connection,
    account_id: str,
    last_accepted_counter: int,
    failed_attempts: int,
    locked_until: int,
) -> None:

    connection.execute(
        """
        UPDATE verification_state
        SET
            last_accepted_counter = ?,
            failed_attempts = ?,
            locked_until = ?
        WHERE account_id = ?
        """,
        (
            last_accepted_counter,
            failed_attempts,
            locked_until,
            account_id,
        ),
    )


def insert_audit_event(
    connection,
    occurred_at: int,
    account_id: str | None,
    event_type: str,
    outcome: str,
) -> None:

    connection.execute(
        """
        INSERT INTO audit_events (
            occurred_at,
            account_id,
            event_type,
            outcome
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            occurred_at,
            account_id,
            event_type,
            outcome,
        ),
    )
       