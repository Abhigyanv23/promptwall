"""Every benchmark input, generated in one place.

run_benchmark.py (promptwall) and baselines.py (Prompt Guard 2, ProtectAI) both
iterate these, so every detector is scored on byte-identical inputs.
"""
from __future__ import annotations

import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import sources  # noqa: E402
from deliveries import _HOMO, DELIVERIES, inject  # noqa: E402
from hard_negatives import HARD_NEGATIVES  # noqa: E402
from promptwall.scanner import normalize  # noqa: E402


def squash(s: str) -> str:
    return " ".join(normalize(s).lower().split())


@dataclass
class AttackPage:
    delivery: str
    wrapper: str
    goal_source: str
    host: str
    page: str
    marker: str        # first 50 chars of the goal, as an agent would see it
    payload: str

    @property
    def groups(self) -> dict[str, str]:
        w = self.wrapper
        return {
            "attack pages by delivery": self.delivery,
            "attack pages by wrapper": ("seen: " if w in sources.TRAIN_WRAPPERS
                                        else "held-out: ") + w,
            "attack pages by goal source":
                f"{self.goal_source} ({'plain goal' if w == 'plain' else 'wrapped'})",
        }


def benign_pages() -> list[tuple[str, str]]:
    """(name, html) of the 63 untouched test pages."""
    return sources.readability_pages()["test"]


def hard_negative_pages() -> list[tuple[str, str]]:
    return list(HARD_NEGATIVES.items())


def attack_pages(clean_hosts: list[tuple[str, str]]) -> Iterator[AttackPage]:
    """161 test goals x 6 wrappers x 2 pages, delivery and host assigned round-robin."""
    deliveries = list(DELIVERIES)
    k = 0
    for g in sources.test_goals():
        for w in sources.WRAPPERS:
            payload = sources.wrap(w, g.text)
            for _ in range(2):
                dname = deliveries[k % len(deliveries)]
                hname, host = clean_hosts[k % len(clean_hosts)]
                goal_seen = g.text.translate(_HOMO) if dname == "homoglyph_visible" else g.text
                yield AttackPage(dname, w, g.source, hname,
                                 inject(host, DELIVERIES[dname](payload), k),
                                 squash(goal_seen)[:50], payload)
                k += 1


def text_attacks() -> Iterator[tuple[str, str]]:
    """(group, text): real tool outputs with embedded attacks + direct attacks."""
    rng = random.Random(7)
    resp = sources.injecagent_tool_responses()
    for setting in ("base", "enhanced"):
        pool = [t for s, t in resp if s == setting]
        for t in rng.sample(pool, 300):
            yield f"InjecAgent tool output ({setting})", t
    for g in sources.test_tensortrust():
        yield "Tensor Trust direct attacks (held-out half)", g.text


def text_benign() -> Iterator[tuple[str, str]]:
    for kind, t in sources.bipia_contexts("test"):
        yield f"BIPIA {kind}s (benign)", t