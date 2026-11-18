"""Run the pipeline in the terminal:  python cli.py data/alerts/alert_ransom_wazuh.json [--approve-all]"""
import argparse
import json
from datetime import datetime, timezone

from socpilot.kb import KnowledgeBase
from socpilot.llm import get_llm
from socpilot.pipeline import analyze
from socpilot.ticket import generate_ticket

p = argparse.ArgumentParser()
p.add_argument("alert", help="path to an alert JSON file")
p.add_argument("--approve-all", action="store_true", help="approve every action before writing the ticket")
args = p.parse_args()

kb, llm = KnowledgeBase(), get_llm()
a = analyze(json.load(open(args.alert, encoding="utf-8")), kb, llm)
print(f"Knowledge base: {kb.stats}\nLLM: {llm.label if llm else 'offline'}\n")
print(f"Alert: {a.alert.title}\nAttack type: {a.alert.category} · {', '.join(a.alert.attack_labels)}")
print("IoCs:", {k: v for k, v in a.alert.entities.items() if v})
for c in a.cves:
    print(f"CVE {c.cve_id}: {c.priority} ({c.reason})")
if not a.playbook:
    raise SystemExit("No approved procedure matches this alert: escalate to Tier 2.")
print(f"Playbook: {a.playbook.id} · severity {a.severity} ({a.severity_reason})\n")
for i in a.checklist.items:
    print(f"  [{'ACTION' if i.is_action else 'task  '}] {i.text}  <{i.step_id}>")
for d in a.checklist.dropped:
    print(f"  [DROPPED] {d['text']}  ({d['why']})")
print("\nGaps:" + ("" if a.gaps else " none"))
for g in a.gaps:
    print(f"  - {g['kind']}: {g['detail']}")
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
dec = {i.step_id: {"state": "approved", "at": now} for i in a.checklist.items if i.is_action} if args.approve_all else {}
print("\n" + generate_ticket(a, dec, "INC-CLI-0001", llm))
