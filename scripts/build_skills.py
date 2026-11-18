"""Regenerate one Agent Skill (skills/pb-*/SKILL.md) per playbook. Run after editing a playbook:
    python scripts/build_skills.py
The playbook Markdown stays the source of truth; the skill tells an agent how to use it."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from socpilot.kb import generic_text  # noqa: E402
from socpilot.loader import ROOT, load_playbooks  # noqa: E402

SLUG = {"PB-PHISH": "pb-phishing", "PB-RANS": "pb-ransomware", "PB-CRED": "pb-credential-stuffing",
        "PB-DDOS": "pb-ddos", "PB-S3": "pb-public-s3-bucket"}

for pb in load_playbooks().values():
    slug = SLUG.get(pb.id, pb.id.lower())
    first = next(s for s in pb.steps if s.section_no == "3")
    lines = [
        "---", f"name: {slug}",
        f"description: Approved {pb.title.lower()} SOP ({pb.id} v{pb.version}). Use when an alert matches "
        + ", ".join(f'"{f}"' for f in pb.finding_types[:3]) + f" or MITRE ATT&CK {', '.join(pb.attack)}. Returns cited steps only.",
        "---", "", f"# {pb.title} ({pb.id})", "",
        f"Source of truth: `playbooks/{pb.id}.md` · owner: {pb.owner} · approved by {pb.approved_by} · last review {pb.last_review}.", "",
        "## When to use", f"- {pb.overview}", f"- Finding types: {'; '.join(pb.finding_types)}", f"- ATT&CK: {', '.join(pb.attack)}", "",
        "## How to use",
        "1. Answer each triage question from alert fields. If a field is missing, answer \"unknown\"; do not guess.",
        "2. Pick severity with the first rule that is true, top to bottom.",
        "3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.",
        "4. Replace each `{placeholder}` with the real indicator values from the alert.",
        f"5. Cite every line by step ID, e.g. `{first.id}`. Never add a step that is not listed below.",
        "6. Sections 3 and 4 are actions: mark them \"awaiting approval\". Sections 2 and 5 are tasks.",
        "7. If an indicator or a KEV required action has no step, report it as a playbook gap.", "",
        "## Triage questions", *[f"- {t['question']} (fact: `{t['fact']}`)" for t in pb.triage], "",
        "## Severity", *[f"- **{s['level']}**: {s['when']}  (rule: `{s['rule']}`)" for s in pb.severity], "",
        "## Steps"]
    section = None
    for s in pb.steps:
        if s.section_no != section:
            section = s.section_no
            lines += ["", f"### {s.section_no}. {s.section}" + ("  (needs approval)" if s.is_action else "")]
        extra = []
        if s.condition:
            extra.append(f"only if `{s.condition}`")
        if s.needs:
            extra.append("needs " + ", ".join(s.needs))
        lines.append(f"- `{s.id}` {s.text}" + (f"  _({'; '.join(extra)})_" if extra else ""))
    lines += ["", "## Regulatory", pb.regulatory, ""]
    out = ROOT / "skills" / slug / "SKILL.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", out.relative_to(ROOT))
