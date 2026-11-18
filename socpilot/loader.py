"""Load playbooks (Markdown + YAML front matter), the CVE feed and sample alerts."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK_DIR = ROOT / "playbooks"
DATA_DIR = ROOT / "data"

STEP_RE = re.compile(r"^- \*\*(PB-[A-Z0-9]+-\d+\.\d+)\*\*\s+(.*?)\s*(?:<!--(.*?)-->)?\s*$")
SECTION_RE = re.compile(r"^## (\d+)\. (.+)$")


@dataclass
class Step:
    id: str
    playbook_id: str
    section_no: str
    section: str
    text: str                      # may contain {placeholders}
    needs: list[str] = field(default_factory=list)
    condition: str | None = None   # fact that must be true ("if:")
    tags: list[str] = field(default_factory=list)

    @property
    def is_action(self) -> bool:
        """Contain (3) and Eradicate & Recover (4) steps change systems, so they need approval."""
        return self.section_no in ("3", "4")


@dataclass
class Playbook:
    id: str
    title: str
    version: str
    status: str
    owner: str
    approved_by: str
    last_review: str
    review_interval_days: int
    attack: list[str]
    finding_types: list[str]
    severity: list[dict]
    triage: list[dict]
    regulatory: str
    overview: str
    steps: list[Step]
    path: Path
    markdown: str

    def step(self, step_id: str) -> Step | None:
        return next((s for s in self.steps if s.id == step_id), None)


def _parse_meta(raw: str | None) -> dict:
    meta: dict = {}
    if not raw:
        return meta
    for part in raw.split("|"):
        if ":" in part:
            k, v = part.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta


def load_playbook(path: Path) -> Playbook:
    text = path.read_text(encoding="utf-8")
    _, front, body = text.split("---", 2)
    fm = yaml.safe_load(front)
    steps: list[Step] = []
    section_no, section = "", ""
    overview_lines: list[str] = []
    for line in body.splitlines():
        m = SECTION_RE.match(line)
        if m:
            section_no, section = m.group(1), m.group(2).strip()
            continue
        m = STEP_RE.match(line)
        if m:
            meta = _parse_meta(m.group(3))
            steps.append(Step(
                id=m.group(1), playbook_id=fm["id"], section_no=section_no, section=section, text=m.group(2).strip(),
                needs=[x.strip() for x in meta.get("needs", "").split(",") if x.strip()],
                condition=meta.get("if") or None,
                tags=[x.strip() for x in meta.get("tags", "").split(",") if x.strip()],
            ))
        elif section_no == "1" and line.strip() and not line.startswith(("#", "|", "-", "**", ">")):
            overview_lines.append(line.strip())
    return Playbook(
        id=fm["id"], title=fm["title"], version=str(fm["version"]), status=fm["status"], owner=fm["owner"],
        approved_by=fm["approved_by"], last_review=str(fm["last_review"]),
        review_interval_days=int(fm.get("review_interval_days", 180)), attack=list(fm["attack"]),
        finding_types=list(fm["finding_types"]), severity=list(fm["severity"]), triage=list(fm["triage"]),
        regulatory=fm.get("regulatory", ""), overview=" ".join(overview_lines), steps=steps, path=path, markdown=text,
    )


def load_playbooks(directory: Path = PLAYBOOK_DIR) -> dict[str, Playbook]:
    pbs = [load_playbook(p) for p in sorted(directory.glob("PB-*.md"))]
    return {pb.id: pb for pb in pbs}


def load_cve_feed(path: Path = DATA_DIR / "cve_feed.json") -> dict:
    feed = json.loads(path.read_text(encoding="utf-8"))
    feed["by_id"] = {r["cve_id"]: r for r in feed["records"]}
    return feed


def load_sample_alerts(directory: Path = DATA_DIR / "alerts") -> dict[str, dict]:
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))}
