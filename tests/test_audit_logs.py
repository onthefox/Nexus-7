"""
Sanity tests for the audit-log.json fixtures added in this PR under the
audit-<timestamp>/ directories. These are sample Shannon pentest-agent audit
trails; this test validates their structural integrity (valid JSON, expected
keys/types) so that regressions in the audit log format are caught early.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The specific audit directories added by this PR.
AUDIT_DIRS = [
    "audit-1784353143",
    "audit-1784353218",
    "audit-1784353612",
    "audit-1784353622",
    "audit-1784353645",
]

EXPECTED_ACTIONS = [
    "preflight_passed",
    "pre_recon_start",
    "recon_start",
    "vuln_analysis_start",
    "exploitation_start",
    "reporting_start",
]


def _load_audit_log(audit_dir: str) -> dict:
    path = os.path.join(REPO_ROOT, audit_dir, "audit-log.json")
    with open(path, "r") as f:
        return json.load(f)


class TestAuditLogFixtures:
    def test_all_expected_audit_dirs_exist(self):
        for audit_dir in AUDIT_DIRS:
            path = os.path.join(REPO_ROOT, audit_dir, "audit-log.json")
            assert os.path.isfile(path), f"Missing audit log: {path}"

    def test_audit_logs_are_valid_json(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            assert isinstance(data, dict)

    def test_session_id_matches_directory_name(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            assert data["session_id"] == audit_dir

    def test_metrics_structure(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            metrics = data["metrics"]
            assert "total_events" in metrics
            assert "agents" in metrics
            assert "shannon" in metrics["agents"]
            assert metrics["agents"]["shannon"]["events"] == metrics["total_events"]

    def test_events_have_expected_sequence(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            actions = [event["action"] for event in data["events"]]
            assert actions == EXPECTED_ACTIONS

    def test_all_events_report_success(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            for event in data["events"]:
                assert event["success"] is True
                assert event["error"] == ""

    def test_preflight_event_has_check_metadata(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            preflight_event = data["events"][0]
            assert preflight_event["action"] == "preflight_passed"
            checks = preflight_event["metadata"]["checks"]
            assert checks == {"target": True, "config": True, "credentials": True}

    def test_events_are_chronologically_ordered(self):
        for audit_dir in AUDIT_DIRS:
            data = _load_audit_log(audit_dir)
            timestamps = [event["timestamp"] for event in data["events"]]
            assert timestamps == sorted(timestamps)