import hashlib
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

from .config import DB_FILE


STATUS_PENDING = "Pending"
STATUS_COPYING = "Copying"
STATUS_COPIED = "Copied"
STATUS_VERIFIED = "Verified"
STATUS_SKIPPED = "Skipped"
STATUS_FAILED = "Failed"
STATUS_PARTIAL = "Partially Copied"

DONE_STATUSES = {STATUS_COPIED, STATUS_VERIFIED, STATUS_SKIPPED}
RETRY_STATUSES = {STATUS_PENDING, STATUS_FAILED, STATUS_PARTIAL}


def utc_now():
    return datetime.utcnow().isoformat(timespec="seconds")


def make_job_key(operation, direction, source_path, destination_path):
    raw = f"{operation}|{direction}|{source_path}|{destination_path}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class StateDB:
    def __init__(self, path=DB_FILE):
        self.path = path
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self):
        with self.lock:
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 30000")
            try:
                yield connection
                connection.commit()
            finally:
                connection.close()

    def initialize(self):
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transfer_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_key TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    destination_path TEXT NOT NULL,
                    relative_file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL DEFAULT 0,
                    modified_time REAL NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    copied_bytes INTEGER NOT NULL DEFAULT 0,
                    verified INTEGER NOT NULL DEFAULT 0,
                    checksum TEXT,
                    last_verified_time TEXT,
                    last_error TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_updated TEXT NOT NULL,
                    UNIQUE(job_key, relative_file_path)
                )
                """
            )
            existing_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(transfer_files)").fetchall()
            }
            if "last_verified_time" not in existing_columns:
                connection.execute("ALTER TABLE transfer_files ADD COLUMN last_verified_time TEXT")
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_transfer_files_job_status
                ON transfer_files(job_key, status)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transfer_jobs (
                    job_key TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    destination_path TEXT NOT NULL,
                    last_verification_mode TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
                """
            )

    def upsert_job(self, job_key, operation, direction, source_path, destination_path, verification_mode):
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO transfer_jobs (
                    job_key, operation, direction, source_path, destination_path,
                    last_verification_mode, last_updated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_key) DO UPDATE SET
                    operation = excluded.operation,
                    direction = excluded.direction,
                    source_path = excluded.source_path,
                    destination_path = excluded.destination_path,
                    last_verification_mode = excluded.last_verification_mode,
                    last_updated = excluded.last_updated
                """,
                (
                    job_key,
                    operation,
                    direction,
                    source_path,
                    destination_path,
                    verification_mode,
                    utc_now(),
                ),
            )

    def upsert_file(self, job_key, source_path, destination_path, relative_file_path, file_size, modified_time):
        with self.connect() as connection:
            existing = connection.execute(
                """
                SELECT file_size, modified_time, status, verified
                FROM transfer_files
                WHERE job_key = ? AND relative_file_path = ?
                """,
                (job_key, relative_file_path),
            ).fetchone()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO transfer_files (
                        job_key, source_path, destination_path, relative_file_path,
                        file_size, modified_time, status, copied_bytes,
                        verified, checksum, last_verified_time, last_error, retry_count, last_updated
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, NULL, 0, ?)
                    """,
                    (
                        job_key,
                        source_path,
                        destination_path,
                        relative_file_path,
                        file_size,
                        modified_time,
                        STATUS_PENDING,
                        utc_now(),
                    ),
                )
                return STATUS_PENDING

            same_file = (
                int(existing["file_size"]) == int(file_size)
                and abs(float(existing["modified_time"]) - float(modified_time)) <= 1
            )

            if same_file:
                connection.execute(
                    """
                    UPDATE transfer_files
                    SET source_path = ?, destination_path = ?, last_updated = ?
                    WHERE job_key = ? AND relative_file_path = ?
                    """,
                    (source_path, destination_path, utc_now(), job_key, relative_file_path),
                )
                return existing["status"]

            connection.execute(
                """
                UPDATE transfer_files
                SET source_path = ?, destination_path = ?, file_size = ?, modified_time = ?,
                    status = ?, copied_bytes = 0, verified = 0, checksum = NULL,
                    last_verified_time = NULL, last_error = NULL, retry_count = 0, last_updated = ?
                WHERE job_key = ? AND relative_file_path = ?
                """,
                (
                    source_path,
                    destination_path,
                    file_size,
                    modified_time,
                    STATUS_PENDING,
                    utc_now(),
                    job_key,
                    relative_file_path,
                ),
            )
            return STATUS_PENDING

    def set_status(
        self,
        job_key,
        relative_file_path,
        status,
        copied_bytes=None,
        verified=None,
        checksum=None,
        error=None,
        increment_retry=False,
    ):
        fields = ["status = ?", "last_updated = ?"]
        values = [status, utc_now()]

        if copied_bytes is not None:
            fields.append("copied_bytes = ?")
            values.append(int(copied_bytes))

        if verified is not None:
            fields.append("verified = ?")
            values.append(1 if verified else 0)
            if verified:
                fields.append("last_verified_time = ?")
                values.append(utc_now())

        if checksum is not None:
            fields.append("checksum = ?")
            values.append(checksum)

        if error is not None:
            fields.append("last_error = ?")
            values.append(error)

        if increment_retry:
            fields.append("retry_count = retry_count + 1")

        values.extend([job_key, relative_file_path])

        with self.connect() as connection:
            connection.execute(
                f"""
                UPDATE transfer_files
                SET {', '.join(fields)}
                WHERE job_key = ? AND relative_file_path = ?
                """,
                values,
            )

    def reset_for_force_reverify(self, job_key):
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE transfer_files
                SET status = ?, verified = 0, copied_bytes = 0, checksum = NULL,
                    last_verified_time = NULL, last_error = NULL, last_updated = ?
                WHERE job_key = ?
                """,
                (STATUS_PENDING, utc_now(), job_key),
            )

    def get_counts(self, job_key):
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_files,
                    COALESCE(SUM(file_size), 0) AS total_size,
                    COALESCE(SUM(
                        CASE
                            WHEN status IN ('Copied', 'Verified', 'Skipped') THEN file_size
                            ELSE copied_bytes
                        END
                    ), 0) AS data_done,
                    SUM(CASE WHEN status = 'Copied' THEN 1 ELSE 0 END) AS copied,
                    SUM(CASE WHEN status = 'Verified' THEN 1 ELSE 0 END) AS verified,
                    SUM(CASE WHEN status = 'Skipped' THEN 1 ELSE 0 END) AS skipped,
                    SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN status = 'Partially Copied' THEN 1 ELSE 0 END) AS partial,
                    SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status = 'Copying' THEN 1 ELSE 0 END) AS copying
                FROM transfer_files
                WHERE job_key = ?
                """,
                (job_key,),
            ).fetchone()

        return {key: row[key] or 0 for key in row.keys()}

    def get_row(self, job_key, relative_file_path):
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT relative_file_path, source_path, destination_path, file_size,
                       status, last_error, last_updated
                FROM transfer_files
                WHERE job_key = ? AND relative_file_path = ?
                """,
                (job_key, relative_file_path),
            ).fetchone()

        return dict(row) if row else None

    def recent_rows(self, job_key, limit=5000):
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT relative_file_path, source_path, destination_path, file_size,
                       status, last_error, last_updated
                FROM transfer_files
                WHERE job_key = ?
                ORDER BY last_updated DESC
                LIMIT ?
                """,
                (job_key, limit),
            ).fetchall()

        return [dict(row) for row in rows]

    def iter_retry_rows(self, job_key):
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM transfer_files
                WHERE job_key = ? AND status IN ('Pending', 'Failed', 'Partially Copied')
                ORDER BY relative_file_path
                """,
                (job_key,),
            ).fetchall()

        return [dict(row) for row in rows]
