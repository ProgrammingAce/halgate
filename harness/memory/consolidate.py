"""Background consolidation pass (the "dream").

Triggered by the harness when the dirty counter crosses thresholds. Rules:
- pinned facts survive verbatim (re-injected if the LLM drops them)
- provenance is carried forward; confidence cannot rise above source caps
- near-duplicate collapse (same subject, sim >= dup_similarity)
- facts with no matching prior become source="reflected", confidence <= 0.6
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from ..config import MemoryConfig
from ..errors import HarnessError
from .store import MemoryStore

CONSOLIDATION_PROMPT = (
    "Consolidate these memory facts for a security-research agent. "
    "Merge near-duplicates, remove stale ephemeral findings (things phrased "
    "as 'currently X'), prune attitude-language, and keep ALL pinned facts "
    "verbatim (they are marked with [PIN]). "
    "Return ONLY JSON: {\"memories\": [{\"text\":..., \"category\":..., "
    "\"subject\":..., \"confidence\":...}], "
    "\"episode\": \"one-sentence session summary\"}"
)

_VALID_CATEGORIES = {"vulnerability", "target_arch", "credential",
                     "mitigation", "scope", "tool_note", "insight", "session"}
_VALID_SUBJECTS = {"target", "self"}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def extract_json(text: str) -> dict:
    """Tolerant JSON extraction from LLM prose."""
    if not text:
        raise HarnessError("empty consolidation response")
    text = text.strip()
    candidates: list[str] = []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        candidates.append(fenced.group(1))
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
    for cand in candidates:
        try:
            data = json.loads(cand)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            continue
    raise HarnessError("no valid JSON in consolidation response")


def build_consolidation_prompt(current: list[dict]) -> str:
    render = "\n".join(
        f"[{'PIN ' if e.get('pinned') else ''}{{{e.get('category')}}}] "
        f"(id={e.get('id')}, conf={e.get('confidence')}, "
        f"src={e.get('source')}) {e.get('text')}"
        for e in current)
    return f"{CONSOLIDATION_PROMPT}\n\nFACTS:\n{render}"


async def run_consolidation(store: MemoryStore, llm_client,
                            config: MemoryConfig) -> tuple[bool, int]:
    current = store.read_long_term()
    if not current:
        return True, 0
    completion = await llm_client.complete(
        [{"role": "user", "content": build_consolidation_prompt(current)}])
    data = extract_json(completion.content)
    proposed = data.get("memories") or []
    if not isinstance(proposed, list):
        raise HarnessError("consolidation JSON missing 'memories' list")

    by_prior_id = {e["id"]: e for e in current if e.get("id")}
    pinned_prior = [e for e in current if e.get("pinned")]

    # 1) match proposals to priors (None => synthesized fact)
    used_priors: set[str] = set()
    resolved: list[tuple[dict, dict | None]] = []
    for p in proposed:
        if not isinstance(p, dict) or not str(p.get("text", "")).strip():
            continue
        prior = None
        for e in current:
            if e["id"] in used_priors:
                continue
            if store._text_similarity(str(p.get("text", "")),
                                      e.get("text", "")) \
                    >= min(config.dup_similarity, 0.5):
                prior = e
                break
        if prior is not None:
            used_priors.add(prior["id"])
        resolved.append((p, prior))

    # 2) invariant: pinned facts survive verbatim (re-inject if dropped)
    kept_texts = {str(p.get("text", "")).strip() for p, _ in resolved}
    for e in pinned_prior:
        if str(e.get("text", "")).strip() not in kept_texts:
            resolved.append(({"text": e["text"],
                              "category": e.get("category"),
                              "subject": e.get("subject", "target"),
                              "pinned": True,  # internal marker (stripped later)
                              "_force_prior": e["id"]}, e))

    # force-match re-injected pinned facts to their prior
    final: list[tuple[dict, dict | None]] = []
    for p, prior in resolved:
        force = p.pop("_force_prior", None)
        if force is not None:
            prior = by_prior_id.get(force, prior)
        p.pop("pinned", None)  # pinning comes from provenance, never LLM
        final.append((p, prior))

    # 3) near-dup collapse: pinned wins, then higher confidence, then length
    collapsed: list[tuple[dict, dict | None]] = []
    for p, prior in final:
        merged = False
        for i, (q, qprior) in enumerate(collapsed):
            subj_p = (prior or p).get("subject", "target")
            subj_q = (qprior or q).get("subject", "target")
            if subj_p != subj_q:
                continue
            if store._text_similarity(str(p.get("text", "")),
                                      str(q.get("text", ""))) \
                    >= config.dup_similarity:
                def rank(item):
                    d, pr = item
                    base = pr if pr is not None else d
                    return (bool(base.get("pinned")),
                            float(base.get("confidence", 0.5)),
                            len(str(base.get("text", ""))))
                if rank((p, prior)) >= rank((q, qprior)):
                    collapsed[i] = (p, prior)
                merged = True
                break
        if not merged:
            collapsed.append((p, prior))

    # 4) build the consolidated entries (provenance carried forward)
    new_entries: list[dict] = []
    for p, prior in collapsed:
        text = str(p.get("text", "")).strip()[:config.max_text_chars]
        if not text:
            continue
        source = prior.get("source", "inferred") if prior is not None \
            else "reflected"
        if source == "reflected":
            confidence = min(0.6, float(p.get("confidence", 0.5) or 0.5))
        else:
            confidence = store.resolve_confidence(
                p.get("confidence"), source)
            if prior is not None:
                # cannot raise confidence above the prior's
                confidence = min(confidence,
                                 float(prior.get("confidence", 0.5)))
        category = p.get("category") or \
            (prior.get("category") if prior is not None else "insight")
        if category not in _VALID_CATEGORIES:
            category = "insight"
        subject = p.get("subject") or \
            (prior.get("subject") if prior is not None else "target")
        if subject not in _VALID_SUBJECTS:
            subject = "target"
        entry = {
            "id": store._mem_id(text, subject),
            "ts": _now_iso(),
            "first_seen": prior.get("first_seen", _now_iso())
            if prior is not None else _now_iso(),
            "last_confirmed": None,
            "category": category,
            "subject": subject,
            "text": text,
            "confidence": confidence,
            "source": source,
            "importance": (prior or {}).get("importance", 5),
            "pinned": bool((prior or {}).get("pinned")),
            "related_ids": [prior["id"]] if prior is not None else [],
        }
        if not any(e["id"] == entry["id"] for e in new_entries):
            new_entries.append(entry)

    # 5) backup this instance's shard, then write the consolidated set
    shard = store._shard("long_term")
    backup = store._dir / f"long_term.{store._instance}.bak.jsonl"
    if shard.exists():
        backup.write_text(shard.read_text())
    store._rewrite("long_term", new_entries)

    # 6) tombstone priors that vanished; lift tombstones for kept ids
    kept_ids = {e["id"] for e in new_entries}
    for e in new_entries:
        if e["id"] in by_prior_id:
            continue  # same id: preserved
    dropped = set(by_prior_id) - kept_ids
    if dropped:
        store._add_tombstone(dropped)
    store._remove_tombstone(kept_ids)

    # 7) short-term trim + episode
    store.trim_short_term(5)
    episode = data.get("episode")
    if isinstance(episode, str) and episode.strip():
        store._append("episodes", {"ts": _now_iso(),
                                   "text": episode.strip()[:500]})
    return True, len(new_entries)
