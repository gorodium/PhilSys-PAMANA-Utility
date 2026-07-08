import json
import ssl
from dataclasses import dataclass, field
from datetime import date, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .packet_tools import build_ticket_folder, extract_packet_ids, is_backend_restoration_comment


class MatrixApiError(RuntimeError):
    pass


class MatrixCertificateError(MatrixApiError):
    pass


@dataclass
class MatrixCommentMatch:
    ticket_id: str
    ticket_number: str
    comment_id: str
    comment_author: str
    comment_author_id: str
    comment_text: str
    packet_ids: list[str]
    destination_folder: str
    planned_due_date: str
    status: str = "Ready"
    found_packets: list = field(default_factory=list)
    error: str = ""
    packet_copied: bool = False
    ticket_commented: bool = False


def safe_token_preview(token):
    if not token:
        return ""
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"


def ticket_value(ticket, *keys, default=""):
    for key in keys:
        value = ticket.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def comment_value(comment, *keys, default=""):
    for key in keys:
        value = comment.get(key)
        if isinstance(value, dict):
            value = value.get("name") or value.get("login") or value.get("id")
        if value not in (None, ""):
            return str(value)
    return default


def nested_value(data, *keys, default=""):
    value = data
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    if value in (None, ""):
        return default
    return str(value)


def extract_matrix_packet_ids(text):
    packet_ids = []
    for value in extract_restoration_packet_ids(text):
        letters_digits = "".join(ch for ch in value if ch.isalnum())
        has_digit = any(ch.isdigit() for ch in value)
        if not has_digit:
            continue
        if len(letters_digits) < 6:
            continue
        packet_ids.append(value)
    return packet_ids


def is_trn_like(value):
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return len(digits) >= 20


def extract_restoration_packet_ids(text):
    values = []
    seen = set()
    lines = str(text or "").splitlines()

    for index, line in enumerate(lines):
        if not is_backend_restoration_comment(line):
            continue

        phrase_index = line.casefold().find("due to ongoing backend restoration")
        before_phrase = line[:phrase_index] if phrase_index >= 0 else line
        candidates = [value for value in extract_packet_ids(before_phrase) if is_trn_like(value)]

        if not candidates and index > 0:
            previous_line = lines[index - 1].strip()
            candidates = [value for value in extract_packet_ids(previous_line) if is_trn_like(value)]

        if not candidates:
            candidates = [value for value in extract_packet_ids(line) if is_trn_like(value)]

        for value in candidates:
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            values.append(value)

    return values


class MatrixApiClient:
    def __init__(self, base_url, token, endpoints, timeout=30, verify_ssl=True, api_style="redmine"):
        self.base_url = (base_url or "").rstrip("/") + "/"
        self.token = token or ""
        self.endpoints = endpoints
        self.timeout = timeout
        self.verify_ssl = bool(verify_ssl)
        self.api_style = (api_style or "redmine").strip().lower()
        self.ssl_context = None if self.verify_ssl else ssl._create_unverified_context()

    def _format_endpoint(self, endpoint_key, **values):
        template = self.endpoints.get(endpoint_key, "")
        if not template:
            raise MatrixApiError(f"Missing Matrix endpoint setting: {endpoint_key}")

        escaped = {key: quote(str(value), safe="") for key, value in values.items()}
        return template.format(**escaped)

    def _add_query_params(self, endpoint, params):
        split = urlsplit(endpoint)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        query.update({key: str(value) for key, value in params.items()})
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))

    def _request(self, method, endpoint, payload=None):
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        data = None
        headers = {"Accept": "application/json"}

        if self.token and self.api_style == "redmine":
            headers["X-Redmine-API-Key"] = self.token
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                body = response.read().decode("utf-8")
        except HTTPError as error:
            safe = error.read().decode("utf-8", errors="replace")[:500]
            raise MatrixApiError(f"Matrix API {method} {endpoint} failed with status {error.code}: {safe}") from error
        except URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise MatrixCertificateError(
                    "Matrix API certificate verification failed. "
                    "Retrying with internal/self-signed certificate mode may be required for this server."
                ) from error
            raise MatrixApiError(f"Matrix API connection failed for {endpoint}: {error.reason}") from error

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise MatrixApiError(f"Matrix API returned non-JSON data for {endpoint}.") from error

    def test_connection(self):
        return self.get_assigned_tickets("__connection_test__")

    def get_assigned_tickets(self, user_name):
        endpoint = self._format_endpoint("assigned_tickets", user_name=user_name)
        if self.api_style == "redmine":
            issues = []
            limit = 100
            offset = 0

            while True:
                data = self._request("GET", self._add_query_params(endpoint, {"limit": limit, "offset": offset}))
                page = data if isinstance(data, list) else data.get("issues") or []
                issues.extend(page)

                if isinstance(data, list):
                    if len(page) < limit:
                        break
                else:
                    total = int(data.get("total_count") or len(issues))
                    if len(issues) >= total or len(page) < limit:
                        break

                offset += len(page) or limit

            return issues

        data = self._request("GET", endpoint)
        if isinstance(data, list):
            return data
        return data.get("issues") or data.get("tickets") or data.get("data") or data.get("results") or []

    def get_ticket_comments(self, ticket_id):
        endpoint = self._format_endpoint("ticket_comments", ticket_id=ticket_id)
        data = self._request("GET", endpoint)
        if isinstance(data, list):
            return data
        issue = data.get("issue")
        if isinstance(issue, dict):
            comments = []
            description = issue.get("description")
            if description:
                comments.append(
                    {
                        "id": "description",
                        "user": issue.get("author") or {},
                        "notes": description,
                    }
                )
            comments.extend(issue.get("journals") or issue.get("comments") or [])
            return comments
        return data.get("comments") or data.get("data") or data.get("results") or []

    def update_assignee(self, ticket_id, new_assignee):
        endpoint = self._format_endpoint("update_assignee", ticket_id=ticket_id)
        if self.api_style == "redmine":
            try:
                assignee_id = int(str(new_assignee).strip())
            except (TypeError, ValueError) as error:
                raise MatrixApiError("Redmine Matrix updates require the comment author's numeric user ID.") from error
            return self._request("PUT", endpoint, {"issue": {"assigned_to_id": assignee_id}})
        return self._request("PATCH", endpoint, {"assignee": new_assignee})

    def update_due_date(self, ticket_id, due_date):
        endpoint = self._format_endpoint("update_due_date", ticket_id=ticket_id)
        if self.api_style == "redmine":
            return self._request("PUT", endpoint, {"issue": {"due_date": due_date}})
        return self._request("PATCH", endpoint, {"due_date": due_date})

    def post_comment(self, ticket_id, message):
        endpoint = self._format_endpoint("post_comment", ticket_id=ticket_id)
        if self.api_style == "redmine":
            return self._request("PUT", endpoint, {"issue": {"notes": message}})
        return self._request("POST", endpoint, {"body": message, "comment": message})


def build_matrix_matches(tickets, comments_by_ticket, destination_root):
    matches = []
    due_date = (date.today() + timedelta(days=3)).isoformat()

    for ticket in tickets:
        ticket_id = ticket_value(ticket, "id", "ticket_id", "key", "number")
        ticket_number = ticket_value(ticket, "number", "ticket_number", "key", "id")
        if not ticket_id or not ticket_number:
            continue

        ticket_comments = comments_by_ticket.get(ticket_id, [])
        is_already_executed = any(
            "Packet(s) uploaded in this directory" in comment_value(c, "notes", "body", "text", "comment", "content")
            for c in ticket_comments
        )

        for comment in ticket_comments:
            text = comment_value(comment, "notes", "body", "text", "comment", "content")
            if not is_backend_restoration_comment(text):
                continue

            author = comment_value(comment, "author", "created_by", "user", "name")
            author_id = nested_value(comment, "user", "id")
            packet_ids = extract_matrix_packet_ids(text)
            destination_folder = build_ticket_folder(ticket_number, destination_root)
            status = "Already Executed" if is_already_executed else "Pending"
            error = ""

            if not author:
                status = "Manual review"
                error = "Comment author could not be identified."
            elif not packet_ids:
                status = "Manual review"
                error = "No packet identifier was found in the matching comment."

            matches.append(
                MatrixCommentMatch(
                    ticket_id=ticket_id,
                    ticket_number=ticket_number,
                    comment_id=comment_value(comment, "id", "comment_id"),
                    comment_author=author,
                    comment_author_id=author_id,
                    comment_text=text,
                    packet_ids=packet_ids,
                    destination_folder=destination_folder,
                    planned_due_date=due_date,
                    status=status,
                    error=error,
                )
            )

    return matches
