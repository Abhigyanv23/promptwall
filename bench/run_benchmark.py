"""Run the promptwall benchmark and write bench/results/{results.json,RESULTS.md,misses.csv}.

    bash bench/fetch_sources.sh        # once
    python bench/train_classifier.py   # once (or use the shipped model)
    python bench/run_benchmark.py

Detectors compared, all on identical inputs:
  keyword_baseline  - substring list over the page's text (what most tutorials do)
  rules             - promptwall rules only
  ml                - promptwall classifier only (any chunk >= threshold)
  combined          - promptwall as shipped (rules + ML -> allow/sanitize/block)

Two kinds of metric:
  flagged / blocked - did the detector raise an alert?
  reached LLM       - did the attack text survive into what the agent would read?
                      This is the security outcome. Hidden content is dropped by
                      promptwall even when nothing is flagged.
"""
from __future__ import annotations

import csv
import json
import random
import re
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import sources  # noqa: E402
from deliveries import _HOMO, DELIVERIES, EXPECTED_GAPS, inject  # noqa: E402
from hard_negatives import HARD_NEGATIVES  # noqa: E402
from promptwall.models import ScanResult  # noqa: E402
from promptwall.sanitize import sanitize_text  # noqa: E402
from promptwall.scanner import Scanner, normalize  # noqa: E402

OUT = Path(__file__).parent / "results"
RNG = random.Random(7)
DETECTORS = ["keyword_baseline", "rules", "ml", "combined"]
REACH = ["no_defence", "keyword_baseline", "promptwall"]

KEYWORDS = ["ignore previous instructions", "ignore all previous instructions",
            "ignore your previous instructions", "disregard previous instructions",
            "disregard all previous", "ignore the above", "system prompt", "you are now",
            "developer mode", "jailbreak"]


def squash(s: str) -> str:
    return " ".join(normalize(s).lower().split())


def keyword_hit(text: str) -> bool:
    t = squash(text)
    return any(k in t for k in KEYWORDS)


def html_text(html: str) -> str:
    """What a naive agent reads: all text nodes, hidden or not (scripts excluded)."""
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style"]):
        t.decompose()
    return soup.get_text(" ")


def scan(scanner: Scanner, content: str, is_html: bool):
    t0 = time.perf_counter()
    res = scanner.scan_html(content) if is_html else scanner.scan_plain(content)
    if res.verdict == "sanitize":
        safe = sanitize_text(res.visible_text, scanner).text
    elif res.verdict == "allow":
        safe = normalize(res.visible_text)
    else:
        safe = ""
    ms = (time.perf_counter() - t0) * 1000   # = Firewall.inspect() cost
    raw = html_text(content) if is_html else content
    rules_res = ScanResult(findings=[f for f in res.findings if not f.rule_id.startswith("ml.")])
    ml = [f for f in res.findings if f.rule_id.startswith("ml.")]
    verdicts = {
        "keyword_baseline": "block" if keyword_hit(raw) else "allow",
        "rules": rules_res.verdict,
        "ml": ("block" if any(f.severity.value == "high" for f in ml) else
               "sanitize" if ml else "allow"),
        "combined": res.verdict,
    }
    return verdicts, ms, raw, safe, res


class Tally:
    def __init__(self):
        self.n = defaultdict(int)
        self.flag = defaultdict(lambda: defaultdict(int))
        self.block = defaultdict(lambda: defaultdict(int))
        self.reach = defaultdict(lambda: defaultdict(int))
        self.has_reach = False

    def add(self, group: str, verdicts: dict, reached: dict | None = None):
        self.n[group] += 1
        for d, v in verdicts.items():
            self.flag[group][d] += v != "allow"
            self.block[group][d] += v == "block"
        if reached:
            self.has_reach = True
            for d, r in reached.items():
                self.reach[group][d] += r

    def rows(self):
        for g, n in self.n.items():
            row = {"group": g, "n": n,
                   "flagged": {d: self.flag[g][d] / n for d in DETECTORS},
                   "blocked": {d: self.block[g][d] / n for d in DETECTORS}}
            if self.has_reach:
                row["reached_llm"] = {d: self.reach[g][d] / n for d in REACH}
            yield row


def main():
    OUT.mkdir(exist_ok=True)
    scanner = Scanner()
    assert scanner.classifier is not None, "train the classifier first"
    test_pages = sources.readability_pages()["test"]
    goals = sources.test_goals()
    latencies: list[float] = []
    misses: list[dict] = []

    # ---------------- B. benign pages (first: also picks clean hosts) ----------------
    benign = Tally()
    false_pos: list[dict] = []
    clean_hosts = []
    for name, html in test_pages:
        v, ms, _, _, res = scan(scanner, html, True)
        latencies.append(ms)
        benign.add("readability test pages (real sites)", v)
        if all(x == "allow" for x in v.values()):
            clean_hosts.append((name, html))
        if v["combined"] != "allow":
            false_pos.append({"page": name, "verdict": v["combined"],
                              "findings": [f"{f.rule_id}@{f.location}: {f.snippet[:90]}"
                                           for f in res.findings if f.severity.value != "low"
                                           or f.rule_id != "hidden.content_present"]})
    hard = Tally()
    for name, html in HARD_NEGATIVES.items():
        v, *_ = scan(scanner, html, True)
        hard.add("hand-written hard negatives", v)
        if v["combined"] != "allow":
            false_pos.append({"page": "hard:" + name, "verdict": v["combined"], "findings": []})

    # ---------------- A. attack pages ----------------
    by_delivery, by_wrapper, by_source = Tally(), Tally(), Tally()
    deliveries = list(DELIVERIES)
    k = 0
    for g in goals:
        for w in sources.WRAPPERS:
            payload = sources.wrap(w, g.text)
            for _ in range(2):
                dname = deliveries[k % len(deliveries)]
                hname, host = clean_hosts[k % len(clean_hosts)]
                page = inject(host, DELIVERIES[dname](payload), k)
                v, ms, raw, safe, _ = scan(scanner, page, True)
                latencies.append(ms)
                # Marker = first 50 chars of the goal, as the agent would see it.
                goal_seen = g.text.translate(_HOMO) if dname == "homoglyph_visible" else g.text
                marker = squash(goal_seen)[:50]
                in_raw = marker in squash(raw)
                reached = {"no_defence": in_raw,
                           "keyword_baseline": in_raw and v["keyword_baseline"] == "allow",
                           "promptwall": marker in squash(safe)}
                by_delivery.add(dname, v, reached)
                by_wrapper.add(("seen: " if w in sources.TRAIN_WRAPPERS else "held-out: ") + w,
                               v, reached)
                by_source.add(f"{g.source} ({'plain goal' if w == 'plain' else 'wrapped'})",
                              v, reached)
                if v["combined"] == "allow":
                    misses.append({"set": "attack_page", "delivery": dname, "wrapper": w,
                                   "goal_source": g.source, "host": hname,
                                   "reached_llm": reached["promptwall"],
                                   "payload": " ".join(payload.split())[:300]})
                k += 1
    n_attack_pages = k

    # ---------------- C. text-level (tool outputs, direct attacks) ----------------
    text_atk, text_ben = Tally(), Tally()
    resp = sources.injecagent_tool_responses()
    for setting in ("base", "enhanced"):
        pool = [t for s, t in resp if s == setting]
        for t in RNG.sample(pool, 300):
            v, *_ = scan(scanner, t, False)
            text_atk.add(f"InjecAgent tool output ({setting})", v)
            if v["combined"] == "allow":
                misses.append({"set": f"injecagent_{setting}", "payload": t[:300]})
    for g in sources.test_tensortrust():
        v, *_ = scan(scanner, g.text, False)
        text_atk.add("Tensor Trust direct attacks (held-out half)", v)
        if v["combined"] == "allow":
            misses.append({"set": "tensortrust", "payload": " ".join(g.text.split())[:300]})
    for kind, t in sources.bipia_contexts("test"):
        v, *_ = scan(scanner, t, False)
        text_ben.add(f"BIPIA {kind}s (benign)", v)

    # ---------------- write results ----------------
    lat = sorted(latencies)
    summary = {
        "n_attack_pages": n_attack_pages, "n_benign_pages": len(test_pages),
        "n_clean_hosts": len(clean_hosts),
        "latency_ms": {"p50": round(statistics.median(lat), 1),
                       "p95": round(lat[int(0.95 * len(lat))], 1),
                       "max": round(lat[-1], 1)},
        "classifier": scanner.classifier.meta | {"threshold": scanner.classifier.threshold,
                                                 "high_threshold": scanner.classifier.high_threshold},
    }
    tables = {"attack pages by delivery": by_delivery, "attack pages by wrapper": by_wrapper,
              "attack pages by goal source": by_source, "text-level attacks": text_atk,
              "benign pages": benign, "benign text": text_ben, "hard negatives": hard}
    data = {"summary": summary,
            "tables": {t: list(tab.rows()) for t, tab in tables.items()},
            "false_positives": false_pos}
    (OUT / "results.json").write_text(json.dumps(data, indent=2))
    with (OUT / "misses.csv").open("w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=["set", "delivery", "wrapper", "goal_source",
                                            "host", "reached_llm", "payload"])
        wr.writeheader()
        wr.writerows(misses)
    (OUT / "RESULTS.md").write_text(render_md(data))
    print(render_md(data))


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def render_md(data: dict) -> str:
    s = data["summary"]
    lines = ["# promptwall benchmark results", "",
             f"- Attack pages: {s['n_attack_pages']}, built on {s['n_clean_hosts']} real test "
             f"pages that every detector allows (so any flag is caused by the payload)",
             f"- Benign real-world test pages: {s['n_benign_pages']}",
             f"- Latency per page (rules + ML + sanitize, 1 CPU core): p50 "
             f"{s['latency_ms']['p50']} ms, p95 {s['latency_ms']['p95']} ms", "",
             "**flagged** = sanitize or block. **blocked** = block. "
             "**reached LLM** = the attack text survived into what the agent reads "
             "(lower is better). For benign rows, flagged = false positive.", ""]
    for title, rows in data["tables"].items():
        has_reach = rows and "reached_llm" in rows[0]
        head = "| group | n | keyword | rules | ML | **combined** flagged | combined blocked |"
        sep = "|---|---|---|---|---|---|---|"
        if has_reach:
            head += " reached LLM: no defence | keyword | **promptwall** |"
            sep += "---|---|---|"
        lines += [f"## {title}", "", head, sep]
        for r in sorted(rows, key=lambda r: -r["flagged"]["combined"]):
            f, b = r["flagged"], r["blocked"]
            gap = " ⚠️ expected gap" if r["group"] in EXPECTED_GAPS else ""
            line = (f"| {r['group']}{gap} | {r['n']} | {pct(f['keyword_baseline'])} | "
                    f"{pct(f['rules'])} | {pct(f['ml'])} | **{pct(f['combined'])}** | "
                    f"{pct(b['combined'])} |")
            if has_reach:
                rl = r["reached_llm"]
                line += (f" {pct(rl['no_defence'])} | {pct(rl['keyword_baseline'])} | "
                         f"**{pct(rl['promptwall'])}** |")
            lines.append(line)
        lines.append("")
    if data["false_positives"]:
        lines += ["## False positives (combined)", ""]
        for fp in data["false_positives"]:
            lines.append(f"- `{fp['page']}` → {fp['verdict']}")
            for x in fp["findings"][:4]:
                lines.append(f"  - {x}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()