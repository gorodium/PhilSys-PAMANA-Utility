import hashlib
import posixpath
import socket
import stat
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import paramiko

from .config import (
    CHUNK_SIZE,
    MAX_CHUNK_SIZE_MB,
    MAX_PARALLEL_WORKERS,
    MIN_CHUNK_SIZE_MB,
    PART_SUFFIX,
    VERIFY_FORCE_ALL,
    VERIFY_HASH,
    VERIFY_NONE,
    VERIFY_SIZE_MTIME,
    VERIFY_SIZE_ONLY,
    normalize_remote_path,
)
from .state_db import (
    DONE_STATUSES,
    RETRY_STATUSES,
    STATUS_COPIED,
    STATUS_COPYING,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_VERIFIED,
    make_job_key,
)


class TransferCancelled(Exception):
    pass


def remote_join(base, name):
    if base == "/":
        return "/" + name

    return posixpath.join(base, name)


def relative_join(base, name):
    if not base:
        return name

    return posixpath.join(base, name)


def is_remote_dir(attrs):
    return stat.S_ISDIR(attrs.st_mode)


def is_remote_file(attrs):
    return stat.S_ISREG(attrs.st_mode)


def mtime_matches(source_mtime, destination_mtime):
    return abs(float(source_mtime) - float(destination_mtime)) <= 2


def friendly_error(error):
    text = str(error) or error.__class__.__name__

    if isinstance(error, paramiko.AuthenticationException):
        return "Wrong username or password."
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "Network timeout. Check VPN/NAS connectivity."
    if isinstance(error, (paramiko.SSHException, EOFError, OSError)):
        lowered = text.lower()
        if "permission" in lowered or "denied" in lowered:
            return "Permission denied. Check account access to this folder."
        if "no space" in lowered or "quota" in lowered:
            return "Destination may not have enough storage."
        if "failure" in lowered or "connection" in lowered or "reset" in lowered:
            return "Network interruption or NAS connection failure."

    return text


def bounded_int(value, default, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default

    return max(minimum, min(maximum, number))


class TransferEngine:
    def __init__(self, params, state_db, logger, event_queue, pause_event, cancel_event):
        self.params = params
        self.db = state_db
        self.logger = logger
        self.queue = event_queue
        self.pause_event = pause_event
        self.cancel_event = cancel_event
        self.source_sftp = None
        self.destination_sftp = None
        self.source_ssh = None
        self.destination_ssh = None
        self.destination_cache = {}
        self.cache_lock = threading.RLock()
        self.mkdir_lock = threading.RLock()
        self.counts_lock = threading.Lock()
        self.last_counts_emit = 0
        self.executor = None
        self.futures = set()
        self.futures_lock = threading.Lock()
        self.worker_local = threading.local()
        self.worker_handles = []
        self.worker_handles_lock = threading.Lock()
        self.source_dirs_for_cleanup = []

        chunk_size_mb = bounded_int(
            params.get("chunk_size_mb"),
            CHUNK_SIZE // (1024 * 1024),
            MIN_CHUNK_SIZE_MB,
            MAX_CHUNK_SIZE_MB,
        )
        self.chunk_size = chunk_size_mb * 1024 * 1024
        self.parallel_workers = bounded_int(
            params.get("parallel_workers"),
            1,
            1,
            MAX_PARALLEL_WORKERS,
        )
        if params.get("verify_existing_only"):
            self.parallel_workers = 1
        self.pending_limit = max(self.parallel_workers * 8, 1)

        self.source_path = normalize_remote_path(params["source_path"])
        self.destination_path = normalize_remote_path(params["destination_path"])
        self.job_key = make_job_key(
            params["operation"],
            params["direction"],
            self.source_path,
            self.destination_path,
        )

    def emit(self, event_type, **payload):
        self.queue.put({"type": event_type, **payload})

    def emit_status(self, status, current_file=""):
        self.emit("status", status=status, current_file=current_file)

    def emit_counts(self, force=False):
        with self.counts_lock:
            now = time.monotonic()

            if not force and now - self.last_counts_emit < 0.7:
                return

            self.last_counts_emit = now
        self.emit("counts", counts=self.db.get_counts(self.job_key))

    def emit_row(self, relative_file_path):
        row = self.db.get_row(self.job_key, relative_file_path)

        if row:
            self.emit("row", row=row)

    def wait_if_paused_or_cancelled(self):
        if self.cancel_event.is_set():
            raise TransferCancelled("Transfer cancelled")

        while not self.pause_event.is_set():
            self.emit_status("Paused")
            time.sleep(0.2)

            if self.cancel_event.is_set():
                raise TransferCancelled("Transfer cancelled")

    def force_disconnect(self):
        """Forcefully close all network connections to unblock hanging operations."""
        for handle in (self.source_sftp, self.destination_sftp, self.source_ssh, self.destination_ssh):
            if handle:
                try:
                    handle.close()
                except Exception:
                    pass

        with self.worker_handles_lock:
            for handles in self.worker_handles:
                self.close_handles(handles)

    def connect_sftp(self, config):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )
        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(30)
        return ssh, ssh.open_sftp()

    def mkdir_p(self, sftp, remote_path):
        remote_path = normalize_remote_path(remote_path)

        if remote_path == "/":
            return

        current = ""
        for part in remote_path.strip("/").split("/"):
            current = remote_join(current or "/", part)
            try:
                attrs = sftp.stat(current)
                if not is_remote_dir(attrs):
                    raise RuntimeError(f"Destination path exists but is not a directory: {current}")
            except FileNotFoundError:
                try:
                    sftp.mkdir(current)
                except OSError:
                    attrs = sftp.stat(current)
                    if not is_remote_dir(attrs):
                        raise RuntimeError(f"Destination path exists but is not a directory: {current}")

    def ensure_destination_dir(self, sftp, remote_path):
        with self.mkdir_lock:
            self.mkdir_p(sftp, remote_path)

    def destination_entries(self, remote_dir):
        remote_dir = normalize_remote_path(remote_dir)

        with self.cache_lock:
            cached = self.destination_cache.get(remote_dir)
            if cached is not None:
                return cached

        self.ensure_destination_dir(self.destination_sftp, remote_dir)
        entries = {item.filename: item for item in self.destination_sftp.listdir_attr(remote_dir)}

        with self.cache_lock:
            return self.destination_cache.setdefault(remote_dir, entries)

    def update_destination_cache(self, destination_dir, destination_path, attrs):
        destination_dir = normalize_remote_path(destination_dir)

        with self.cache_lock:
            self.destination_cache.setdefault(destination_dir, {})[posixpath.basename(destination_path)] = attrs

    def remove_stale_partial(self, sftp, part_path):
        try:
            sftp.remove(part_path)
        except FileNotFoundError:
            pass

    def hash_remote_file(self, sftp, path):
        digest = hashlib.sha256()

        with sftp.open(path, "rb") as remote_file:
            while True:
                self.wait_if_paused_or_cancelled()
                chunk = remote_file.read(self.chunk_size)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def verify_destination(self, source_path, destination_path, source_attrs, destination_attrs):
        mode = self.params["verification_mode"]

        if mode == VERIFY_NONE:
            return STATUS_SKIPPED, False, None, "Destination exists; skipped without verification."

        if mode == VERIFY_SIZE_ONLY:
            if int(source_attrs.st_size) == int(destination_attrs.st_size):
                return STATUS_VERIFIED, True, None, None

            return STATUS_PENDING, False, None, "Destination exists but size differs."

        if mode in (VERIFY_SIZE_MTIME, VERIFY_HASH, VERIFY_FORCE_ALL):
            if (
                int(source_attrs.st_size) == int(destination_attrs.st_size)
                and mtime_matches(source_attrs.st_mtime, destination_attrs.st_mtime)
            ):
                return STATUS_VERIFIED, True, None, None

            return STATUS_PENDING, False, None, "Destination exists but size or modified time differs."

        return STATUS_PENDING, False, None, "Unknown verification mode."

    def transfer_file(
        self,
        source_sftp,
        destination_sftp,
        source_path,
        destination_path,
        destination_dir,
        relative_file_path,
        source_attrs,
    ):
        partial_path = destination_path + PART_SUFFIX
        source_digest = hashlib.sha256()
        copied_bytes = 0
        update_threshold = max(self.chunk_size * 4, 1)
        next_update = update_threshold

        self.ensure_destination_dir(destination_sftp, destination_dir)
        self.remove_stale_partial(destination_sftp, partial_path)

        self.db.set_status(
            self.job_key,
            relative_file_path,
            STATUS_COPYING,
            copied_bytes=0,
            verified=False,
            error="",
        )
        self.emit_row(relative_file_path)
        self.emit_status("Copying", relative_file_path)
        self.emit(
            "file_progress",
            relative_file_path=relative_file_path,
            copied_bytes=0,
            file_size=source_attrs.st_size,
        )

        with source_sftp.open(source_path, "rb") as source_file:
            if source_attrs.st_size:
                source_file.prefetch(source_attrs.st_size)

            with destination_sftp.open(partial_path, "wb") as destination_file:
                destination_file.set_pipelined(True)

                while True:
                    self.wait_if_paused_or_cancelled()
                    chunk = source_file.read(self.chunk_size)

                    if not chunk:
                        break

                    destination_file.write(chunk)
                    source_digest.update(chunk)
                    copied_bytes += len(chunk)

                    if copied_bytes >= next_update:
                        self.db.set_status(
                            self.job_key,
                            relative_file_path,
                            STATUS_COPYING,
                            copied_bytes=copied_bytes,
                        )
                        self.emit_counts()
                        self.emit(
                            "file_progress",
                            relative_file_path=relative_file_path,
                            copied_bytes=copied_bytes,
                            file_size=source_attrs.st_size,
                        )
                        next_update += update_threshold

        destination_sftp.rename(partial_path, destination_path)
        destination_sftp.utime(destination_path, (source_attrs.st_mtime, source_attrs.st_mtime))
        destination_attrs = destination_sftp.stat(destination_path)
        self.update_destination_cache(destination_dir, destination_path, destination_attrs)

        if int(destination_attrs.st_size) != int(source_attrs.st_size):
            raise RuntimeError("Destination file size mismatch after copy")

        checksum = source_digest.hexdigest()

        if self.params["verification_mode"] == VERIFY_HASH:
            destination_hash = self.hash_remote_file(destination_sftp, destination_path)

            if destination_hash != checksum:
                raise RuntimeError("Destination hash mismatch after copy")

        self.db.set_status(
            self.job_key,
            relative_file_path,
            STATUS_VERIFIED,
            copied_bytes=source_attrs.st_size,
            verified=True,
            checksum=checksum,
            error="",
        )
        self.emit_row(relative_file_path)
        self.emit(
            "file_progress",
            relative_file_path=relative_file_path,
            copied_bytes=source_attrs.st_size,
            file_size=source_attrs.st_size,
        )

        if self.params["operation"] == "move":
            source_sftp.remove(source_path)

    def should_skip_from_state(self, current_status):
        mode = self.params["verification_mode"]

        if mode == VERIFY_FORCE_ALL:
            return False

        if self.params["retry_failed_only"]:
            return current_status not in RETRY_STATUSES

        if self.params["skip_verified_on_resume"] and current_status in DONE_STATUSES:
            return True

        return False

    def mark_failed(self, relative_file_path, error, increment_retry=True):
        message = friendly_error(error)
        self.db.set_status(
            self.job_key,
            relative_file_path,
            STATUS_FAILED,
            error=message,
            increment_retry=increment_retry,
        )
        self.emit_row(relative_file_path)
        self.emit("error", message=f"{relative_file_path}: {message}")
        self.logger.error("%s failed: %s", relative_file_path, message)
        self.logger.debug(traceback.format_exc())

    def close_handles(self, handles):
        for handle in handles:
            if handle:
                try:
                    handle.close()
                except Exception:
                    pass

    def get_worker_sftps(self):
        handles = getattr(self.worker_local, "handles", None)

        if handles is None:
            source_ssh, source_sftp = self.connect_sftp(self.params["source_config"])
            destination_ssh, destination_sftp = self.connect_sftp(self.params["destination_config"])
            handles = (source_sftp, destination_sftp, source_ssh, destination_ssh)
            self.worker_local.handles = handles

            with self.worker_handles_lock:
                self.worker_handles.append(handles)

        return handles[0], handles[1]

    def reset_worker_sftps(self):
        handles = getattr(self.worker_local, "handles", None)

        if handles is None:
            return

        self.close_handles(handles)
        self.worker_local.handles = None

    def process_transfer_task(self, source_path, destination_path, destination_dir, relative_file_path, source_attrs):
        retry_limit = int(self.params["retry_limit"])

        for attempt in range(retry_limit + 1):
            try:
                self.wait_if_paused_or_cancelled()
                source_sftp, destination_sftp = self.get_worker_sftps()
                self.transfer_file(
                    source_sftp,
                    destination_sftp,
                    source_path,
                    destination_path,
                    destination_dir,
                    relative_file_path,
                    source_attrs,
                )
                self.emit_counts(force=True)
                return
            except TransferCancelled:
                self.db.set_status(
                    self.job_key,
                    relative_file_path,
                    STATUS_PARTIAL,
                    verified=False,
                    error="Transfer cancelled or paused before completion.",
                )
                raise
            except Exception as error:
                self.reset_worker_sftps()

                if attempt >= retry_limit:
                    self.mark_failed(relative_file_path, error)
                    self.emit_counts(force=True)
                    return

                self.logger.warning(
                    "Retrying %s after error on attempt %s: %s",
                    relative_file_path,
                    attempt + 1,
                    friendly_error(error),
                )
                time.sleep(min(2**attempt, 30))

    def collect_completed_transfers(self, wait_for_slot=False):
        while True:
            with self.futures_lock:
                futures = set(self.futures)

            if not futures:
                return

            done = {future for future in futures if future.done()}

            if not done:
                if not wait_for_slot:
                    return

                done, _pending = wait(futures, timeout=0.2, return_when=FIRST_COMPLETED)

            for future in done:
                with self.futures_lock:
                    self.futures.discard(future)

                try:
                    future.result()
                except TransferCancelled:
                    raise
                except Exception as error:
                    self.logger.exception("Unexpected worker failure: %s", friendly_error(error))
                    self.emit("error", message=f"Unexpected worker failure: {friendly_error(error)}")

            if not wait_for_slot:
                return

            with self.futures_lock:
                if len(self.futures) < self.pending_limit:
                    return

            self.wait_if_paused_or_cancelled()

    def wait_for_pending_transfers(self):
        while True:
            self.wait_if_paused_or_cancelled()

            with self.futures_lock:
                futures = set(self.futures)

            if not futures:
                return

            done, _pending = wait(futures, timeout=0.5, return_when=FIRST_COMPLETED)

            if not done:
                self.emit_counts()
                continue

            for future in done:
                with self.futures_lock:
                    self.futures.discard(future)

                try:
                    future.result()
                except TransferCancelled:
                    raise
                except Exception as error:
                    self.logger.exception("Unexpected worker failure: %s", friendly_error(error))
                    self.emit("error", message=f"Unexpected worker failure: {friendly_error(error)}")

            self.emit_counts()

    def submit_transfer(self, source_path, destination_path, destination_dir, relative_file_path, source_attrs):
        if self.executor is None:
            self.process_transfer_task(source_path, destination_path, destination_dir, relative_file_path, source_attrs)
            return

        self.collect_completed_transfers(wait_for_slot=True)
        future = self.executor.submit(
            self.process_transfer_task,
            source_path,
            destination_path,
            destination_dir,
            relative_file_path,
            source_attrs,
        )

        with self.futures_lock:
            self.futures.add(future)

    def cleanup_empty_source_dirs(self):
        if self.params["operation"] != "move":
            return

        for source_dir in sorted(set(self.source_dirs_for_cleanup), key=lambda path: path.count("/"), reverse=True):
            if source_dir == "/":
                continue

            try:
                self.source_sftp.rmdir(source_dir)
            except OSError:
                pass

    def process_file(self, source_path, destination_path, destination_dir, relative_file_path, source_attrs):
        current_status = self.db.upsert_file(
            self.job_key,
            source_path,
            destination_path,
            relative_file_path,
            source_attrs.st_size,
            source_attrs.st_mtime,
        )

        if self.should_skip_from_state(current_status):
            self.emit_counts()
            return

        destination_name = posixpath.basename(destination_path)
        destination_attr = self.destination_entries(destination_dir).get(destination_name)

        if destination_attr is not None:
            if not is_remote_file(destination_attr):
                self.db.set_status(
                    self.job_key,
                    relative_file_path,
                    STATUS_FAILED,
                    error="Destination name exists but is not a file.",
                )
                self.emit_row(relative_file_path)
                self.emit_counts(force=True)
                return

            self.emit_status("Verifying", relative_file_path)
            status, verified, checksum, reason = self.verify_destination(
                source_path,
                destination_path,
                source_attrs,
                destination_attr,
            )

            if status in (STATUS_SKIPPED, STATUS_VERIFIED):
                self.db.set_status(
                    self.job_key,
                    relative_file_path,
                    status,
                    copied_bytes=source_attrs.st_size,
                    verified=verified,
                    checksum=checksum,
                    error=reason or "",
                )
                self.emit_row(relative_file_path)
                self.emit_counts(force=True)
                return

            if self.params["verify_existing_only"]:
                self.db.set_status(
                    self.job_key,
                    relative_file_path,
                    STATUS_PENDING,
                    copied_bytes=0,
                    verified=False,
                    error=reason or "Needs copy.",
                )
                self.emit_row(relative_file_path)
                self.emit_counts(force=True)
                return

        if self.params["verify_existing_only"]:
            self.db.set_status(
                self.job_key,
                relative_file_path,
                STATUS_PENDING,
                copied_bytes=0,
                verified=False,
                error="Destination file missing.",
            )
            self.emit_row(relative_file_path)
            self.emit_counts(force=True)
            return

        if self.executor is not None:
            self.submit_transfer(source_path, destination_path, destination_dir, relative_file_path, source_attrs)
            self.emit_counts()
            return

        retry_limit = int(self.params["retry_limit"])

        for attempt in range(retry_limit + 1):
            try:
                self.transfer_file(
                    self.source_sftp,
                    self.destination_sftp,
                    source_path,
                    destination_path,
                    destination_dir,
                    relative_file_path,
                    source_attrs,
                )
                self.emit_counts(force=True)
                return
            except TransferCancelled:
                self.db.set_status(
                    self.job_key,
                    relative_file_path,
                    STATUS_PARTIAL,
                    verified=False,
                    error="Transfer cancelled or paused before completion.",
                )
                raise
            except Exception as error:
                if attempt >= retry_limit:
                    self.mark_failed(relative_file_path, error)
                    self.emit_counts(force=True)
                    return

                self.logger.warning(
                    "Retrying %s after error on attempt %s: %s",
                    relative_file_path,
                    attempt + 1,
                    friendly_error(error),
                )
                time.sleep(min(2**attempt, 30))

    def scan_directory(self, source_dir, destination_dir, relative_dir=""):
        self.wait_if_paused_or_cancelled()
        self.emit_status("Scanning files", source_dir)
        self.logger.info("Scanning directory %s -> %s", source_dir, destination_dir)

        if self.params["operation"] == "move" and source_dir not in ("/", self.source_path):
            self.source_dirs_for_cleanup.append(source_dir)

        try:
            items = self.source_sftp.listdir_attr(source_dir)
        except Exception as error:
            self.emit("error", message=f"Cannot list source directory {source_dir}: {friendly_error(error)}")
            self.logger.exception("Cannot list source directory %s", source_dir)
            return

        try:
            destination_entries = self.destination_entries(destination_dir)
        except Exception as error:
            self.emit("error", message=f"Cannot list destination directory {destination_dir}: {friendly_error(error)}")
            self.logger.exception("Cannot list destination directory %s", destination_dir)
            return

        for item in items:
            self.wait_if_paused_or_cancelled()
            self.collect_completed_transfers()
            source_path = remote_join(source_dir, item.filename)
            destination_path = remote_join(destination_dir, item.filename)
            relative_path = relative_join(relative_dir, item.filename)

            if is_remote_dir(item):
                destination_item = destination_entries.get(item.filename)

                if destination_item is not None and not is_remote_dir(destination_item):
                    self.emit("error", message=f"Destination blocks directory: {destination_path}")
                    self.logger.error("Destination blocks directory: %s", destination_path)
                    continue

                self.scan_directory(source_path, destination_path, relative_path)
                continue

            if not is_remote_file(item):
                self.logger.info("Skipped non-regular source item: %s", source_path)
                continue

            self.process_file(
                source_path,
                destination_path,
                destination_dir,
                relative_path,
                item,
            )

    def process_retry_rows(self):
        rows = self.db.iter_retry_rows(self.job_key)
        self.emit_status("Retrying failed/pending files")

        for row in rows:
            self.wait_if_paused_or_cancelled()
            relative_path = row["relative_file_path"]
            source_path = row["source_path"]
            destination_path = row["destination_path"]
            destination_dir = posixpath.dirname(destination_path) or "/"

            try:
                source_attrs = self.source_sftp.stat(source_path)
                self.process_file(source_path, destination_path, destination_dir, relative_path, source_attrs)
            except Exception as error:
                self.mark_failed(relative_path, error)

    def run(self):
        self.logger.info("Loaded transfer state from SQLite")
        self.logger.info("Source path: %s", self.source_path)
        self.logger.info("Destination path: %s", self.destination_path)
        self.logger.info("Verification mode: %s", self.params["verification_mode"])
        self.logger.info("Parallel transfers: %s", self.parallel_workers)
        self.logger.info("Chunk size: %s MB", self.chunk_size // (1024 * 1024))

        self.db.upsert_job(
            self.job_key,
            self.params["operation"],
            self.params["direction"],
            self.source_path,
            self.destination_path,
            self.params["verification_mode"],
        )

        if self.params["verification_mode"] == VERIFY_FORCE_ALL:
            self.db.reset_for_force_reverify(self.job_key)

        self.emit("job", job_key=self.job_key)
        self.emit_counts(force=True)

        try:
            self.emit_status("Connecting to source NAS")
            self.source_ssh, self.source_sftp = self.connect_sftp(self.params["source_config"])

            self.emit_status("Connecting to destination NAS")
            self.destination_ssh, self.destination_sftp = self.connect_sftp(self.params["destination_config"])

            if self.parallel_workers > 1:
                self.executor = ThreadPoolExecutor(max_workers=self.parallel_workers, thread_name_prefix="nas-copy")

            if self.params["retry_failed_only"]:
                self.process_retry_rows()
            else:
                self.process_retry_rows()
                self.scan_directory(self.source_path, self.destination_path)

            self.wait_for_pending_transfers()
            self.cleanup_empty_source_dirs()
            self.emit_status("Completed")
            self.emit_counts(force=True)
            self.emit("complete", counts=self.db.get_counts(self.job_key))
        except TransferCancelled:
            self.emit_status("Cancelled")
            self.emit_counts(force=True)
            self.emit("cancelled")
            self.logger.info("Transfer cancelled")
        except Exception as error:
            message = friendly_error(error)
            self.emit_status("Completed with errors")
            self.emit("fatal", message=message)
            self.logger.exception("Fatal transfer error: %s", message)
        finally:
            if self.executor is not None:
                self.executor.shutdown(wait=True, cancel_futures=True)

            for handles in self.worker_handles:
                self.close_handles(handles)

            for handle in (self.source_sftp, self.destination_sftp, self.source_ssh, self.destination_ssh):
                if handle:
                    try:
                        handle.close()
                    except Exception:
                        pass
