import tempfile
import unittest
from pathlib import Path

from nas_transfer_app.config import VERIFY_FORCE_ALL
from nas_transfer_app.matrix_api import MatrixApiClient, build_matrix_matches, extract_matrix_packet_ids
from nas_transfer_app.packet_tools import (
    build_ticket_folder,
    is_backend_restoration_comment,
    machine_folder_for_packet,
    packet_machine_code,
    parse_packet_input,
)
from nas_transfer_app.state_db import DONE_STATUSES, STATUS_PENDING, STATUS_VERIFIED, StateDB, make_job_key
from nas_transfer_app.transfer_engine import TransferEngine


class CoreLogicTests(unittest.TestCase):
    def test_multi_packet_input_parsing(self):
        self.assertEqual(
            parse_packet_input("ABC123, DEF456\nGHI789 ABC123"),
            ["ABC123", "DEF456", "GHI789"],
        )

    def test_matrix_comment_detection(self):
        self.assertTrue(is_backend_restoration_comment("Please check. Due to ongoing backend restoration-- packet 12345"))
        self.assertTrue(is_backend_restoration_comment("7430023250262920210811020911 - Due to ongoing backend restoration, we advise you"))
        self.assertFalse(is_backend_restoration_comment("Normal ticket update"))

    def test_matrix_packet_id_extraction_filters_normal_words(self):
        text = (
            "Hello kindly check the status of below ephilid/s\n"
            "71315249660963320250602054653 - Ready to download\n"
            "73500267490133520260112085706 - Ready to download\n"
            "74300217880238620260328025311 - Due to ongoing backend restoration, we advise you to locate the physical packet of this TRN to complete the generation of ePhilID.\n"
            "74300217880239820260330010005 - Ready to download"
        )
        self.assertEqual(
            extract_matrix_packet_ids(text),
            ["74300217880238620260328025311"],
        )

    def test_packet_machine_code_maps_to_nas_folder(self):
        self.assertEqual(packet_machine_code("7430023250262920210811020911"), "23250")
        self.assertEqual(machine_folder_for_packet("7430023250262920210811020911"), "PRO-LPT-90772")

    def test_ticket_destination_path(self):
        self.assertEqual(
            build_ticket_folder("625042"),
            "/Misamis Oriental/ePhilID TRN Concerns/625042",
        )

    def test_resume_skip_logic_keeps_verified_done(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = StateDB(Path(temp_dir) / "state.db")
            job_key = make_job_key("copy", "NAS1_TO_NAS2", "/", "/")
            db.upsert_job(job_key, "copy", "NAS1_TO_NAS2", "/", "/", "Size + modified time")
            db.upsert_file(job_key, "/source.zip", "/source.zip", "source.zip", 100, 123)
            db.set_status(job_key, "source.zip", STATUS_VERIFIED, copied_bytes=100, verified=True)

            params = {
                "operation": "copy",
                "direction": "NAS1_TO_NAS2",
                "source_path": "/",
                "destination_path": "/",
                "verification_mode": "Size + modified time",
                "skip_verified_on_resume": True,
                "retry_failed_only": False,
                "verify_existing_only": False,
                "parallel_workers": 1,
                "chunk_size_mb": 1,
            }
            engine = TransferEngine(params, db, None, None, None, None)
            self.assertTrue(engine.should_skip_from_state(STATUS_VERIFIED))
            params["verification_mode"] = VERIFY_FORCE_ALL
            engine = TransferEngine(params, db, None, None, None, None)
            self.assertFalse(engine.should_skip_from_state(STATUS_VERIFIED))
            self.assertIn(STATUS_VERIFIED, DONE_STATUSES)
            self.assertEqual(db.get_row(job_key, "source.zip")["status"], STATUS_VERIFIED)

    def test_matrix_match_building(self):
        tickets = [{"id": "1", "number": "625042"}]
        comments = {
            "1": [
                {
                    "id": "c1",
                    "author": "Maria Santos",
                    "body": "7430023250262920210811020911 - Due to ongoing backend restoration-- packet is needed",
                }
            ]
        }
        matches = build_matrix_matches(tickets, comments, "/Misamis Oriental/ePhilID TRN Concerns/")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].ticket_number, "625042")
        self.assertEqual(matches[0].comment_author, "Maria Santos")
        self.assertEqual(matches[0].destination_folder, "/Misamis Oriental/ePhilID TRN Concerns/625042")
        self.assertEqual(matches[0].packet_ids, ["7430023250262920210811020911"])

    def test_redmine_issue_journals_build_matrix_matches(self):
        tickets = [{"id": 625042, "subject": "Backend restoration"}]
        comments = {
            "625042": [
                {
                    "id": 9,
                    "user": {"id": 422, "name": "MISAMISOR.macabale"},
                    "notes": "7430023250262920210811020911 - Due to ongoing backend restoration, kindly upload the packet",
                }
            ]
        }
        matches = build_matrix_matches(tickets, comments, "/Misamis Oriental/ePhilID TRN Concerns/")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].ticket_id, "625042")
        self.assertEqual(matches[0].comment_author, "MISAMISOR.macabale")
        self.assertEqual(matches[0].comment_author_id, "422")
        self.assertIn("7430023250262920210811020911", matches[0].packet_ids)

    def test_redmine_client_parses_issues_and_journals(self):
        class FakeRedmineClient(MatrixApiClient):
            def _request(self, method, endpoint, payload=None):
                if endpoint == "/issues.json?assigned_to_id=me&status_id=open&limit=100&offset=0":
                    return {"issues": [{"id": 625042}]}
                if endpoint == "/issues/625042.json?include=journals":
                    return {
                        "issue": {
                            "author": {"id": 7, "name": "Reporter"},
                            "description": "description text",
                            "journals": [{"id": 1, "notes": "test"}],
                        }
                    }
                return {}

        client = FakeRedmineClient(
            "https://matrix.philsys.gov.ph",
            "token",
            {
                "assigned_tickets": "/issues.json?assigned_to_id=me&status_id=open",
                "ticket_comments": "/issues/{ticket_id}.json?include=journals",
            },
            api_style="redmine",
        )
        self.assertEqual(client.get_assigned_tickets("me"), [{"id": 625042}])
        self.assertEqual(
            client.get_ticket_comments("625042"),
            [
                {"id": "description", "user": {"id": 7, "name": "Reporter"}, "notes": "description text"},
                {"id": 1, "notes": "test"},
            ],
        )

    def test_redmine_client_paginates_assigned_issues(self):
        class FakePagedRedmineClient(MatrixApiClient):
            def _request(self, method, endpoint, payload=None):
                if endpoint.endswith("offset=0"):
                    return {"total_count": 101, "issues": [{"id": index} for index in range(100)]}
                if endpoint.endswith("offset=100"):
                    return {"total_count": 101, "issues": [{"id": 628945}]}
                return {"total_count": 101, "issues": []}

        client = FakePagedRedmineClient(
            "https://matrix.philsys.gov.ph",
            "token",
            {"assigned_tickets": "/issues.json?assigned_to_id=me&status_id=open"},
            api_style="redmine",
        )
        tickets = client.get_assigned_tickets("me")
        self.assertEqual(len(tickets), 101)
        self.assertEqual(tickets[-1]["id"], 628945)

    def test_matrix_client_can_allow_internal_self_signed_certificate(self):
        client = MatrixApiClient(
            "https://matrix.philsys.gov.ph",
            "token",
            {"assigned_tickets": "/api/tickets?assignee={user_name}"},
            verify_ssl=False,
            api_style="generic",
        )
        self.assertFalse(client.verify_ssl)
        self.assertIsNotNone(client.ssl_context)


if __name__ == "__main__":
    unittest.main()
