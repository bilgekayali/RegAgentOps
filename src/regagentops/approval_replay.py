from __future__ import annotations

import sqlite3
from pathlib import Path


class ApprovalReplayLedger:
    """Append-only, one-time redemption ledger keyed by approval requirement."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = str(database)
        self._connection = sqlite3.connect(self._database, isolation_level=None)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_redemptions (
                requirement_digest TEXT PRIMARY KEY,
                approval_package_digest TEXT NOT NULL UNIQUE,
                institution_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                redeemed_at TEXT NOT NULL
            )
            """
        )

    def close(self) -> None:
        self._connection.close()

    def consume(
        self,
        *,
        approval_package_digest: str,
        institution_id: str,
        requirement_digest: str,
        request_digest: str,
        redeemed_at: str,
    ) -> bool:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                INSERT INTO approval_redemptions (
                    requirement_digest,
                    approval_package_digest,
                    institution_id,
                    request_digest,
                    redeemed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    requirement_digest,
                    approval_package_digest,
                    institution_id,
                    request_digest,
                    redeemed_at,
                ),
            )
            self._connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self._connection.execute("ROLLBACK")
            return False
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def redemption_count(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) FROM approval_redemptions").fetchone()
        return int(row[0]) if row else 0
