"""Core analysis for hearsay.

A trace is a list of events (JSONL). Each event has:
  step     int (optional, defaults to line order)
  agent    name of the agent that produced it ("user" for the human)
  type     "user" | "message" | "tool_call" | "tool_result"
  content  text (for tool_call, may be an object of arguments)
  tool     tool name (tool_call / tool_result, optional)

The idea: a concrete fact (number, path, URL, version, CVE, hash, quoted
identifier) that an agent states should trace back to something that agent
actually observed, i.e. a tool result it received or the user's own words.
When it only traces back to another agent's message, it is hearsay. When
nobody in the chain ever observed it, it is a rumor that someone made up.
When a hearsay or rumor fact then flows into a tool call, an action was taken
on unverified information.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

ATOM_PATTERNS = [
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("url", re.compile(r"https?://[^\s<>\"')\]]+")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("hash", re.compile(r"\b[0-9a-f]{7,64}\b")),
    ("version", re.compile(r"\bv?\d+\.\d+(?:\.\d+)+(?:[-+][\w.]+)?\b")),
    ("path", re.compile(r"(?:(?<=\s)|^|(?<=[`'\"(]))(?:~|\.{1,2})?/?(?:[\w.-]+/)+[\w.-]+")),
    ("code", re.compile(r"`([^`\n]{2,80})`")),
    ("number", re.compile(r"(?<![\w.])-?\d+(?:[.,]\d+)*(?:\s?(?:%|ms|s|MB|GB|KB|x))?(?!\w)(?!\.\d)")),
]

# numbers too generic to count as a claim
TRIVIAL_NUMBERS = {str(i) for i in range(0, 11)}


@dataclass
class Event:
    idx: int
    step: int
    agent: str
    type: str
    text: str
    tool: str | None = None


@dataclass
class Finding:
    kind: str          # hearsay | rumor | acted-on-hearsay | acted-on-rumor
    severity: str      # low | medium | high
    step: int
    agent: str
    atom: str
    atom_type: str
    chain: list = field(default_factory=list)   # [(step, agent)] of earlier mentions
    origin: str | None = None                   # where it was first observed, if anywhere
    note: str = ""


def _norm(atom: str, kind: str) -> str:
    a = atom.strip().rstrip(".,;:")
    if kind == "number":
        a = a.replace(",", "").replace(" ", "")
    if kind in ("url",):
        a = a.rstrip("/")
    return a.lower()


def extract_atoms(text: str, min_number: int = 11) -> dict[str, str]:
    """Return {normalized_atom: atom_type} for concrete facts in text."""
    out: dict[str, str] = {}
    taken: list[tuple[int, int]] = []

    def overlaps(s, e):
        return any(s < te and ts < e for ts, te in taken)

    for kind, pat in ATOM_PATTERNS:
        for m in pat.finditer(text):
            if kind == "code":
                s, e = m.span(1)
                raw = m.group(1)
            else:
                s, e = m.span()
                raw = m.group(0)
            if overlaps(s, e) and kind != "code":
                continue
            if kind == "hash" and not re.search(r"[a-f]", raw):
                continue  # pure digits are numbers, not hashes
            if kind == "hash" and not re.search(r"\d", raw):
                continue  # plain words like 'deadbeef'-less english
            if kind == "number":
                digits = re.sub(r"[^\d.]", "", raw)
                try:
                    if float(digits.replace(",", "")) < min_number and not re.search(r"[%a-zA-Z.]", raw):
                        continue
                except ValueError:
                    continue
                if raw.strip() in TRIVIAL_NUMBERS:
                    continue
            if kind == "path" and "/" not in raw:
                continue
            n = _norm(raw, kind)
            if len(n) < 2:
                continue
            out.setdefault(n, kind)
            taken.append((s, e))
    return out


def _text_of(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return json.dumps(content, sort_keys=True)


def load_trace(lines: Iterable[str]) -> list[Event]:
    events = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        obj = json.loads(line)
        typ = obj.get("type", "message")
        agent = obj.get("agent") or ("user" if typ == "user" else "agent")
        events.append(Event(
            idx=len(events),
            step=int(obj.get("step", len(events) + 1)),
            agent=agent,
            type=typ,
            text=_text_of(obj.get("content", obj.get("args"))),
            tool=obj.get("tool"),
        ))
    events.sort(key=lambda e: (e.step, e.idx))
    return events


def analyze(events: list[Event], shared_results: bool = False, min_number: int = 11) -> list[Finding]:
    observed: dict[str, dict[str, int]] = {}  # agent -> atom -> step first observed
    user_atoms: dict[str, int] = {}
    said: dict[str, list[tuple[int, str]]] = {}  # atom -> [(step, agent)] in messages
    status: dict[tuple[str, str], tuple[str, Finding | None]] = {}  # (agent, atom) -> label
    findings: list[Finding] = []

    def seen_by(agent: str, atom: str) -> bool:
        if atom in user_atoms:
            return True
        if shared_results:
            return any(atom in obs for obs in observed.values())
        return atom in observed.get(agent, {})

    def origin_of(atom: str) -> str | None:
        if atom in user_atoms:
            return f"user@{user_atoms[atom]}"
        best = None
        for ag, obs in observed.items():
            if atom in obs and (best is None or obs[atom] < best[1]):
                best = (ag, obs[atom])
        return f"tool_result:{best[0]}@{best[1]}" if best else None

    for ev in events:
        atoms = extract_atoms(ev.text, min_number=min_number)
        if ev.type == "user":
            for a in atoms:
                user_atoms.setdefault(a, ev.step)
            continue
        if ev.type == "tool_result":
            obs = observed.setdefault(ev.agent, {})
            for a in atoms:
                obs.setdefault(a, ev.step)
            continue
        if ev.type == "message":
            for a, kind in atoms.items():
                prior = said.get(a, [])
                others = [(s, ag) for s, ag in prior if ag != ev.agent]
                if seen_by(ev.agent, a):
                    status[(ev.agent, a)] = ("grounded", None)
                elif (ev.agent, a) in status:
                    pass  # repeating itself; keep first label
                elif others:
                    org = origin_of(a)
                    f = Finding(
                        kind="hearsay", severity="low" if org else "medium",
                        step=ev.step, agent=ev.agent, atom=a, atom_type=kind,
                        chain=[{"step": s, "agent": ag} for s, ag in prior], origin=org,
                        note=("relayed from another agent; observed by "
                              + org.split(":", 1)[-1] if org else
                              "relayed from another agent; nobody ever observed it"),
                    )
                    findings.append(f)
                    status[(ev.agent, a)] = ("hearsay" if org else "rumor-relay", f)
                else:
                    org = origin_of(a)
                    if org is None:
                        f = Finding(
                            kind="rumor", severity="medium", step=ev.step, agent=ev.agent,
                            atom=a, atom_type=kind, origin=None,
                            note="first stated here with no tool result or user message behind it",
                        )
                        findings.append(f)
                        status[(ev.agent, a)] = ("rumor", f)
                    else:
                        f = Finding(
                            kind="hearsay", severity="low", step=ev.step, agent=ev.agent,
                            atom=a, atom_type=kind, origin=org,
                            note="known from another agent's tool result this agent never saw",
                        )
                        findings.append(f)
                        status[(ev.agent, a)] = ("hearsay", f)
                said.setdefault(a, []).append((ev.step, ev.agent))
            continue
        if ev.type == "tool_call":
            for a, kind in atoms.items():
                if seen_by(ev.agent, a):
                    continue
                label, src = status.get((ev.agent, a), (None, None))
                prior = said.get(a, [])
                if label is None:
                    others = [(s, ag) for s, ag in prior if ag != ev.agent]
                    if not others:
                        continue  # agent's own fresh argument; out of scope
                    label = "hearsay" if origin_of(a) else "rumor-relay"
                if label == "grounded":
                    continue
                unverified = label in ("rumor", "rumor-relay")
                findings.append(Finding(
                    kind="acted-on-rumor" if unverified else "acted-on-hearsay",
                    severity="high" if unverified else "medium",
                    step=ev.step, agent=ev.agent, atom=a, atom_type=kind,
                    chain=[{"step": s, "agent": ag} for s, ag in prior],
                    origin=origin_of(a),
                    note=(f"passed to tool {ev.tool or '?'} without this agent ever observing it"),
                ))
    return findings


SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


def summarize(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.kind] = counts.get(f.kind, 0) + 1
    return counts


def to_json(findings: list[Finding]) -> str:
    return json.dumps({"summary": summarize(findings), "findings": [asdict(f) for f in findings]}, indent=2)


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "hearsay: every concrete fact traces back to something its speaker observed.\n"
    lines = []
    for f in findings:
        chain = " <- ".join(f"{c['agent']}@{c['step']}" for c in reversed(f.chain)) if f.chain else "-"
        lines.append(f"[{f.severity.upper():6}] step {f.step} {f.agent}: {f.kind} {f.atom_type} '{f.atom}'")
        lines.append(f"         chain: {chain} | origin: {f.origin or 'none'}")
        lines.append(f"         {f.note}")
    s = summarize(findings)
    lines.append("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(s.items())))
    return "\n".join(lines) + "\n"


def to_md(findings: list[Finding]) -> str:
    out = ["| step | agent | kind | severity | fact | origin |", "|---|---|---|---|---|---|"]
    for f in findings:
        out.append(f"| {f.step} | {f.agent} | {f.kind} | {f.severity} | `{f.atom}` | {f.origin or 'none'} |")
    return "\n".join(out) + "\n"
