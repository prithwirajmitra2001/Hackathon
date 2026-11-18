import os
from datetime import date

import pytest

os.environ.setdefault("SOCPILOT_EMBEDDER", "hashing")   # tests run offline, no model download

from socpilot.alert_parser import parse_alert  # noqa: E402
from socpilot.kb import KnowledgeBase  # noqa: E402
from socpilot.loader import load_playbooks, load_sample_alerts  # noqa: E402
from socpilot.pipeline import analyze, eval_rule  # noqa: E402
from socpilot.ticket import generate_ticket  # noqa: E402

TODAY = date(2026, 11, 18)
EXPECTED = {
    "alert_ransom_wazuh.json": ("Ransomware", "PB-RANS", "P1"),
    "alert_phish_sentinel.json": ("Phishing", "PB-PHISH", "P1"),
    "alert_credstuff_sentinel.json": ("Credential Stuffing", "PB-CRED", "P2"),
    "alert_s3_guardduty.json": ("Cloud Storage Exposure", "PB-S3", "P1"),
}


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase()


def test_playbooks_have_unique_step_ids():
    ids = [s.id for pb in load_playbooks().values() for s in pb.steps]
    assert len(ids) == len(set(ids)) and len(load_playbooks()) == 5


@pytest.mark.parametrize("name", EXPECTED)
def test_each_sample_alert(kb, name):
    cat, pb, sev = EXPECTED[name]
    a = analyze(load_sample_alerts()[name], kb, None, TODAY)
    assert a.alert.category == cat
    assert a.playbook.id == pb
    assert a.severity == sev
    assert all(i.step_id.startswith(pb + "-") for i in a.checklist.items)   # every line cites the playbook


def test_iocs_and_cve_priority(kb):
    a = analyze(load_sample_alerts()["alert_ransom_wazuh.json"], kb, None, TODAY)
    assert "198.51.100.23" in a.alert.entities["ips"]
    assert "10.20.4.18" not in a.alert.entities["ips"]          # internal IP never goes to a block list
    assert a.cves[0].cve_id == "CVE-2023-4966" and a.cves[0].priority == "P1"


def test_gaps(kb):
    rans = analyze(load_sample_alerts()["alert_ransom_wazuh.json"], kb, None, TODAY)
    kinds = {g["kind"] for g in rans.gaps}
    assert "CVE action not covered" in kinds and "Playbook overdue for review" in kinds
    phish = analyze(load_sample_alerts()["alert_phish_sentinel.json"], kb, None, TODAY)
    assert phish.gaps == []


def test_no_match_means_no_procedure(kb):
    assert analyze({"msg": "printer out of paper"}, kb).playbook is None


def test_validator_drops_uncited_lines(kb):
    class FakeLLM:
        label = "fake"

        def complete_json(self, prompt, max_tokens=0):
            return {"checklist": [{"step_id": "PB-RANS-3.1", "text": "Isolate the hosts."},
                                  {"step_id": "PB-XYZ-9.9", "text": "Pay the ransom."}],
                    "omitted": [], "outside_sop": ["Call the attackers"]}
    a = analyze(load_sample_alerts()["alert_ransom_wazuh.json"], kb, FakeLLM(), TODAY)
    assert [d["text"] for d in a.checklist.dropped] == ["Pay the ransom."]
    assert a.checklist.outside_sop == ["Call the attackers"]
    assert any(i.note.startswith("restored") for i in a.checklist.items)   # SOP steps the model skipped come back


def test_ticket_has_required_sections(kb):
    a = analyze(load_sample_alerts()["alert_s3_guardduty.json"], kb, None, TODAY)
    t = generate_ticket(a, {"PB-S3-3.2": {"state": "approved", "at": "2026-11-18T09:00:00Z"}}, "INC-T")
    for section in ("## Timeline", "## Root cause", "## Containment and recovery actions", "[x]"):
        assert section in t


def test_rule_eval():
    assert eval_rule("a and (b or c)", {"a": True, "c": True})
    assert not eval_rule("a and b", {"a": True, "b": None})
