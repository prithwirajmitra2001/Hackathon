"""Thin LLM wrapper. Uses Anthropic or OpenAI if a key is set; otherwise returns None (offline mode)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

AGENTS_MD = (Path(__file__).resolve().parent.parent / "AGENTS.md")


def system_prompt() -> str:
    rules = AGENTS_MD.read_text(encoding="utf-8") if AGENTS_MD.exists() else ""
    return ("You are the SOC Runbook Copilot. Follow these project rules exactly.\n\n" + rules +
            "\n\nAlways answer with one JSON object and nothing else.")


class LLM:
    def __init__(self, provider: str, model: str, client):
        self.provider, self.model, self.client = provider, model, client

    @property
    def label(self) -> str:
        return f"{self.provider} · {self.model}"

    def complete_json(self, user: str, max_tokens: int = 2000) -> dict:
        if self.provider == "anthropic":
            msg = self.client.messages.create(model=self.model, max_tokens=max_tokens, system=system_prompt(),
                                              messages=[{"role": "user", "content": user}])
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        else:
            resp = self.client.chat.completions.create(model=self.model, max_tokens=max_tokens,
                                                       response_format={"type": "json_object"},
                                                       messages=[{"role": "system", "content": system_prompt()},
                                                                 {"role": "user", "content": user}])
            text = resp.choices[0].message.content or ""
        return parse_json(text)


def parse_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m.group(0))


def get_llm() -> LLM | None:
    if os.getenv("SOCPILOT_OFFLINE") == "1":
        return None
    if os.getenv("ANTHROPIC_API_KEY"):
        import anthropic
        return LLM("anthropic", os.getenv("SOCPILOT_MODEL", "claude-sonnet-5-5"), anthropic.Anthropic())
    if os.getenv("OPENAI_API_KEY"):
        import openai
        return LLM("openai", os.getenv("SOCPILOT_MODEL", "gpt-4.1-mini"), openai.OpenAI())
    return None
