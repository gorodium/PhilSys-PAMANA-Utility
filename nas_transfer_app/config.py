import json
import os
import sys
from pathlib import Path


APP_NAME = "NAS_Transfer_Files"
APP_DISPLAY_NAME = "PhilSys PAMANA Utility"
APP_SUBTITLE = "An unofficial PhilSys Packet, Matrix, and NAS Utility"
SFTP_PORT = 2222
PART_SUFFIX = ".partial"
DEFAULT_CHUNK_SIZE_MB = 4
MIN_CHUNK_SIZE_MB = 1
MAX_CHUNK_SIZE_MB = 16
CHUNK_SIZE = DEFAULT_CHUNK_SIZE_MB * 1024 * 1024
DEFAULT_PARALLEL_WORKERS = 4
MAX_PARALLEL_WORKERS = 4
DEFAULT_RETRY_LIMIT = 2

NAS_ENDPOINTS = {
    "NAS1": {
        "name": "NAS1",
        "host": "upload.philsys.gov.ph",
        "port": SFTP_PORT,
    },
    "NAS2": {
        "name": "NAS2",
        "host": "172.16.35.100",
        "port": SFTP_PORT,
    },
}

VERIFY_NONE = "None"
VERIFY_SIZE_ONLY = "Size only"
VERIFY_SIZE_MTIME = "Size + modified time"
VERIFY_HASH_AFTER_COPY = "Hash after copy"
VERIFY_FORCE_ALL = "Force Reverify All"

VERIFY_QUICK = VERIFY_SIZE_MTIME
VERIFY_HASH = VERIFY_HASH_AFTER_COPY
VERIFY_FAILED_PENDING = "Verify Only Failed/Pending"

VERIFY_MODES = [
    VERIFY_NONE,
    VERIFY_SIZE_ONLY,
    VERIFY_SIZE_MTIME,
    VERIFY_HASH_AFTER_COPY,
    VERIFY_FORCE_ALL,
]

LEGACY_VERIFY_MODE_MAP = {
    "Quick Check": VERIFY_SIZE_MTIME,
    "Full Hash Check": VERIFY_HASH_AFTER_COPY,
    "Verify Only Failed/Pending": VERIFY_SIZE_MTIME,
}

DEFAULT_PACKET_ROOT = "/"
DEFAULT_MATRIX_DESTINATION_ROOT = "/Misamis Oriental/ePhilID TRN Concerns/"
MATRIX_BACKEND_PHRASE = "Due to ongoing backend restoration--"

OLD_MATRIX_ENDPOINTS = {
    "matrix_endpoint_assigned_tickets": "/api/tickets?assignee={user_name}",
    "matrix_endpoint_ticket_comments": "/api/tickets/{ticket_id}/comments",
    "matrix_endpoint_update_assignee": "/api/tickets/{ticket_id}/assignee",
    "matrix_endpoint_update_due_date": "/api/tickets/{ticket_id}/due-date",
    "matrix_endpoint_post_comment": "/api/tickets/{ticket_id}/comments",
}

REDMINE_MATRIX_ENDPOINTS = {
    "matrix_endpoint_assigned_tickets": "/issues.json?assigned_to_id=me&status_id=open",
    "matrix_endpoint_ticket_comments": "/issues/{ticket_id}.json?include=journals",
    "matrix_endpoint_update_assignee": "/issues/{ticket_id}.json",
    "matrix_endpoint_update_due_date": "/issues/{ticket_id}.json",
    "matrix_endpoint_post_comment": "/issues/{ticket_id}.json",
}


def install_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path(__file__).resolve().parent.parent


def resource_path(relative_path):
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative_path

    return Path(__file__).resolve().parent.parent / relative_path


def data_dir():
    local_app_data = os.environ.get("LOCALAPPDATA")

    if local_app_data:
        return Path(local_app_data) / APP_NAME

    return Path.home() / "AppData" / "Local" / APP_NAME


APP_DIR = install_dir()
DATA_DIR = data_dir()
CONFIG_FILE = DATA_DIR / "nas_transfer_settings.json"
DB_FILE = DATA_DIR / "transfer_state.db"
LOG_DIR = DATA_DIR / "logs"


DEFAULT_SETTINGS = {
    "direction": "NAS1_TO_NAS2",
    "operation": "copy",
    "source_path": "/",
    "destination_path": "/",
    "source_username": "",
    "destination_username": "",
    "source_save_credentials": False,
    "destination_save_credentials": False,
    "nas1_username": "",
    "nas2_username": "",
    "nas1_save_credentials": False,
    "nas2_save_credentials": False,
    "verification_mode": VERIFY_QUICK,
    "skip_verified_on_resume": True,
    "retry_limit": DEFAULT_RETRY_LIMIT,
    "parallel_workers": DEFAULT_PARALLEL_WORKERS,
    "chunk_size_mb": DEFAULT_CHUNK_SIZE_MB,
    "packet_search_root": DEFAULT_PACKET_ROOT,
    "packet_target_nas": "NAS1",
    "packet_target_folder": DEFAULT_MATRIX_DESTINATION_ROOT,
    "theme": "System",
    "accent_color": "#0f7c91",
    "province_profiles": [],
    "packet_province_profile_id": "",
    "matrix_province_profile_id": "",
    "matrix_api_base_url": "https://matrix.philsys.gov.ph",
    "matrix_user_full_name": "",
    "matrix_ticket_numbers": "",
    "matrix_destination_root": DEFAULT_MATRIX_DESTINATION_ROOT,
    "matrix_save_token": False,
    "matrix_verify_ssl": True,
    "matrix_api_style": "redmine",
    **REDMINE_MATRIX_ENDPOINTS,
    "encrypted_credentials": {},
}


def load_settings():
    if not CONFIG_FILE.exists():
        return DEFAULT_SETTINGS.copy()

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            loaded = json.load(file)
    except (OSError, json.JSONDecodeError):
        return DEFAULT_SETTINGS.copy()

    settings = DEFAULT_SETTINGS.copy()
    settings.update({key: value for key, value in loaded.items() if key in settings})
    for key, old_endpoint in OLD_MATRIX_ENDPOINTS.items():
        if settings.get(key) in ("", old_endpoint):
            settings[key] = REDMINE_MATRIX_ENDPOINTS[key]
    if not settings.get("matrix_api_style"):
        settings["matrix_api_style"] = "redmine"
    settings["verification_mode"] = LEGACY_VERIFY_MODE_MAP.get(
        settings.get("verification_mode"),
        settings.get("verification_mode"),
    )
    return settings


def save_settings(settings):
    safe_settings = DEFAULT_SETTINGS.copy()
    safe_settings.update({key: value for key, value in settings.items() if key in safe_settings})
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(safe_settings, indent=2), encoding="utf-8")


def normalize_remote_path(path):
    value = (path or "/").strip().replace("\\", "/")

    if not value:
        value = "/"

    if not value.startswith("/"):
        value = "/" + value

    parts = []

    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)

    return "/" + "/".join(parts) if parts else "/"


def direction_endpoints(direction):
    if direction == "NAS2_TO_NAS1":
        return NAS_ENDPOINTS["NAS2"], NAS_ENDPOINTS["NAS1"]

    return NAS_ENDPOINTS["NAS1"], NAS_ENDPOINTS["NAS2"]


def endpoint_by_name(name):
    return NAS_ENDPOINTS[name]
