import csv
import re
from dataclasses import dataclass
from functools import lru_cache
from io import StringIO

from .config import DEFAULT_MATRIX_DESTINATION_ROOT, MATRIX_BACKEND_PHRASE, normalize_remote_path, resource_path


PACKET_SPLIT_RE = re.compile(r"[\s,;]+")
PACKET_ID_RE = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._-]{4,}\b")
MACHINE_CODE_MAP_PATH = resource_path("data/machine_code_map.tsv")


@dataclass
class PacketSearchResult:
    packet_id: str
    packet_name: str
    found_location: str
    nas_source: str
    size: int
    modified_time: float
    status: str = "Found"
    profile: str = ""
    error: str = ""


def parse_packet_input(text):
    values = []
    seen = set()

    for part in PACKET_SPLIT_RE.split(text or ""):
        packet_id = part.strip()
        if not packet_id:
            continue
        key = packet_id.casefold()
        if key in seen:
            continue
        seen.add(key)
        values.append(packet_id)

    return values


def extract_packet_ids(text):
    values = []
    seen = set()

    for match in PACKET_ID_RE.findall(text or ""):
        key = match.casefold()
        if key in seen:
            continue
        seen.add(key)
        values.append(match)

    return values


def packet_machine_code(packet_id):
    value = re.sub(r"\D", "", str(packet_id or ""))
    if len(value) < 10:
        return ""
    return value[5:10]


@lru_cache(maxsize=1)
def machine_code_map():
    mapping = {}
    try:
        lines = MACHINE_CODE_MAP_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return mapping

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        code, folder = parts[0].strip(), parts[1].strip()
        if code and folder:
            mapping[code] = folder
    return mapping


def machine_folder_for_packet(packet_id):
    code = packet_machine_code(packet_id)
    if not code:
        return ""
    return machine_code_map().get(code, "")


def is_backend_restoration_comment(text):
    return "due to ongoing backend restoration" in (text or "").casefold()


def build_ticket_folder(ticket_number, root=DEFAULT_MATRIX_DESTINATION_ROOT):
    ticket = str(ticket_number or "").strip().strip("/")
    if not ticket:
        raise ValueError("Ticket number is required.")

    return normalize_remote_path(f"{normalize_remote_path(root)}/{ticket}")


def packet_results_to_csv(results):
    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "Packet ID",
            "Packet name",
            "NAS source",
            "Province/Profile",
            "Found location",
            "Size",
            "Last modified",
            "Status",
            "Error/Notes",
        ]
    )

    for result in results:
        writer.writerow(
            [
                result.packet_id,
                result.packet_name,
                result.nas_source,
                result.profile,
                result.found_location,
                result.size,
                result.modified_time,
                result.status,
                result.error,
            ]
        )

    return output.getvalue()
