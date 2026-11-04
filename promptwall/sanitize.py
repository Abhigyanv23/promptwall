"""Turn scanned content into text that is safer to hand to an LLM.

What sanitizing does:
  1. Uses only the *visible* text - hidden spans, comments and attributes are
     dropped entirely (a human reading the page never saw them either).
  2. Strips invisible Unicode (zero-width, bidi controls, tag characters).
  3. Redacts the sentences/windows that trigger a rule (MEDIUM+) or the ML
     classifier, replacing each with a visible marker so the agent knows
     something was removed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ml import MAX_CHUNK_CHARS
from .models import Severity

REDACTION = "[promptwall: removed suspected injected instruction]"
_UNIT_SPLIT = re.compile(r"((?<=[.!?])[ \t]+|\n+)")


@dataclass
class Sanitized:
    text: str
    removed: list[str] = field(default_factory=list)


def _flagged(scanner, text: str) -> bool:
    from .scanner import normalize_for_matching

    for f in scanner.scan_text(text, "sanitize"):
        if f.severity != Severity.LOW:
            return True
    clf = scanner.classifier
    if clf is not None:
        probs = clf.predict_proba([normalize_for_matching(text)])
        if probs and probs[0] >= clf.threshold:
            return True
    return False


def sanitize_text(text: str, scanner) -> Sanitized:
    from .scanner import normalize

    text = normalize(text)
    pieces = _UNIT_SPLIT.split(text)
    units = pieces[0::2]
    seps = pieces[1::2] + [""]

    # Greedy windows over unit indices (same packing idea as ml.chunk_text).
    windows: list[list[int]] = []
    cur: list[int] = []
    length = 0
    for i, u in enumerate(units):
        if cur and length + len(u) + 1 > MAX_CHUNK_CHARS:
            windows.append(cur)
            cur, length = [], 0
        cur.append(i)
        length += len(u) + 1
    if cur:
        windows.append(cur)

    redact: set[int] = set()
    for wi, win in enumerate(windows):
        joined = " ".join(units[i] for i in win if units[i].strip())
        if not joined or not _flagged(scanner, joined):
            continue
        # Remove the WHOLE window, not just the sentence that triggered. The
        # trigger is often the wrapper ("Ignore your previous instructions.")
        # while the actual goal sits in the next sentence - removing only the
        # trigger leaked the goal in benchmark run 2.
        redact.update(win)
        # A trigger in the last sentence of a window means the payload likely
        # continues into the next window: take its first sentence too.
        last = max(i for i in win if units[i].strip())
        if wi + 1 < len(windows) and _flagged(scanner, units[last]):
            redact.add(windows[wi + 1][0])

    out: list[str] = []
    removed: list[str] = []
    last_redacted = False
    for i, (u, sep) in enumerate(zip(units, seps)):
        if i in redact:
            if u.strip():
                removed.append(u.strip())
            if not last_redacted:
                out.append(REDACTION + (sep if "\n" in sep else " "))
            last_redacted = True
        else:
            out.append(u + sep)
            last_redacted = last_redacted and not u.strip()
    return Sanitized("".join(out).strip(), removed)