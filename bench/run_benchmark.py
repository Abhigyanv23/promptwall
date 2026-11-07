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
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import cases  # noqa: E402
from cases import squash  # noqa: E402
from deliveries import EXPECTED_GAPS  # noqa: E402
from promptwall.models import ScanResult  # noqa: E402
from promptwall.sanitize import sanitize_text  # noqa: E402
from promptwall.scanner import Scanner, normalize  # noqa: E402

OUT = Path(__file__).parent / "results"
DETECTORS = ["keyword_baseline", "rules", "ml", "combined"]
REACH = ["no_defence", "keyword_baseline", "promptwall"]

KEYWORDS = ["ignore previous instructions", "ignore all previous instructions",
            "ignore your previous instructions", "disregard previous instructions",
            "disregard all previous", "ignore the above", "system prompt", "you are now",
            "developer mode", "jailbreak"]


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


def build_scanner(args) -> Scanner:
    if args.classifier == "tfidf":
        return Scanner()                      # the bundled TF-IDF model, as shipped
    from promptwall.ml import InjectionClassifier
    from promptwall.transformer_ml import TransformerClassifier
    if not args.model:
        sys.exit("--classifier transformer needs --model (a model directory or HF repo id)")
    # A Hugging Face repo id is exactly "owner/name". Anything else is a local path,
    # and a missing local path would otherwise surface as a confusing 401 from the Hub.
    looks_like_repo_id = (args.model.count("/") == 1 and not Path(args.model).is_absolute()
                          and not args.model.startswith(("models/", "./", "../")))
    if not Path(args.model).exists() and not looks_like_repo_id:
        sys.exit(f"model directory not found: {args.model} (did training finish? "
                 "run bench/train_transformer.py first)")
    prefilter = InjectionClassifier.load_default() if args.cascade else None
    return Scanner(classifier=TransformerClassifier(
        args.model, device=args.device, prefilter=prefilter,
        prefilter_threshold=args.cascade_threshold))


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--classifier", choices=["tfidf", "transformer"], default="tfidf")
    ap.add_argument("--model", help="transformer model directory or Hugging Face repo id")
    ap.add_argument("--device", default=None, help="cpu or cuda (default: cuda if available)")
    ap.add_argument("--cascade", action="store_true",
                    help="transformer only on chunks the TF-IDF model scores >= --cascade-threshold")
    ap.add_argument("--cascade-threshold", type=float, default=0.02)
    ap.add_argument("--tag", default="",
                    help="suffix for output files (default for a transformer run: 'transformer')")
    args = ap.parse_args(argv)
    if args.classifier == "transformer" and not args.tag:
        args.tag = "transformer_cascade" if args.cascade else "transformer"
    suffix = f"_{args.tag}" if args.tag else ""

    # Windows consoles default to cp1252, which cannot print the report's symbols.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    OUT.mkdir(exist_ok=True)
    scanner = build_scanner(args)
    assert scanner.classifier is not None, "train the classifier first"
    test_pages = cases.benign_pages()
    # A tagged run (another classifier) is compared case for case with the main
    # run, so it reuses the main run's host pages instead of picking its own.
    reference_hosts = None
    if suffix:
        ref = OUT / "results.json"
        if not ref.exists():
            sys.exit("run the default benchmark first (python bench/run_benchmark.py)")
        reference_hosts = json.loads(ref.read_text(encoding="utf-8"))["summary"]["clean_hosts"]
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
    for name, html in cases.hard_negative_pages():
        v, *_ = scan(scanner, html, True)
        hard.add("hand-written hard negatives", v)
        if v["combined"] != "allow":
            false_pos.append({"page": "hard:" + name, "verdict": v["combined"], "findings": []})

    # ---------------- A. attack pages ----------------
    by_delivery, by_wrapper, by_source = Tally(), Tally(), Tally()
    tallies = {"attack pages by delivery": by_delivery, "attack pages by wrapper": by_wrapper,
               "attack pages by goal source": by_source}
    per_case: list[dict] = []
    n_attack_pages = 0
    dropped_hosts: list[str] = []
    attack_hosts = clean_hosts
    if reference_hosts is not None:
        pages_by_name = dict(test_pages)
        own_clean = {name for name, _ in clean_hosts}
        dropped_hosts = sorted(h for h in reference_hosts if h not in own_clean)
        attack_hosts = [(h, pages_by_name[h]) for h in reference_hosts]
    for i, c in enumerate(cases.attack_pages(attack_hosts)):
        if c.host in dropped_hosts:
            continue   # this classifier flags the host page on its own: unfair to count
        v, ms, raw, safe, _ = scan(scanner, c.page, True)
        latencies.append(ms)
        in_raw = c.marker in squash(raw)
        reached = {"no_defence": in_raw,
                   "keyword_baseline": in_raw and v["keyword_baseline"] == "allow",
                   "promptwall": c.marker in squash(safe)}
        for table, group in c.groups.items():
            tallies[table].add(group, v, reached)
        per_case.append({"i": i, "host": c.host, "groups": c.groups,
                         "flagged": v["combined"] != "allow", "blocked": v["combined"] == "block",
                         "reached": reached["promptwall"], "reached_no_defence": in_raw})
        if v["combined"] == "allow":
            misses.append({"set": "attack_page", "delivery": c.delivery, "wrapper": c.wrapper,
                           "goal_source": c.goal_source, "host": c.host,
                           "reached_llm": reached["promptwall"],
                           "payload": " ".join(c.payload.split())[:300]})
        n_attack_pages += 1
        if n_attack_pages % 200 == 0:
            print(f"  attack page {n_attack_pages}...", file=sys.stderr, flush=True)

    # ---------------- C. text-level (tool outputs, direct attacks) ----------------
    text_atk, text_ben = Tally(), Tally()
    for i, (group, t) in enumerate(cases.text_attacks()):
        v, *_ = scan(scanner, t, False)
        text_atk.add(group, v)
        per_case.append({"i": f"text-{i}", "groups": {"text-level attacks": group},
                         "flagged": v["combined"] != "allow", "blocked": v["combined"] == "block"})
        if v["combined"] == "allow":
            misses.append({"set": group, "payload": " ".join(t.split())[:300]})
    for i, (group, t) in enumerate(cases.text_benign()):
        v, *_ = scan(scanner, t, False)
        text_ben.add(group, v)
        per_case.append({"i": f"benign-text-{i}", "groups": {"benign text": group},
                         "flagged": v["combined"] != "allow", "blocked": v["combined"] == "block"})

    # ---------------- write results ----------------
    lat = sorted(latencies)
    summary = {
        "n_attack_pages": n_attack_pages, "n_benign_pages": len(test_pages),
        "n_clean_hosts": len(attack_hosts) - len(dropped_hosts),
        "clean_hosts": [name for name, _ in attack_hosts if name not in dropped_hosts],
        "hosts_dropped_vs_main_run": dropped_hosts,
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
    stats = getattr(scanner.classifier, "stats", None)
    if stats:
        summary["classifier_stats"] = stats
    (OUT / f"results{suffix}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    # One line per case: lets baselines.py compare on exactly the same subset.
    (OUT / f"per_case{suffix}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in per_case) + "\n", encoding="utf-8")
    with (OUT / f"misses{suffix}.csv").open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["set", "delivery", "wrapper", "goal_source",
                                            "host", "reached_llm", "payload"])
        wr.writeheader()
        wr.writerows(misses)
    md = render_md(data)
    if suffix:
        md = md.replace("# promptwall benchmark results",
                        f"# promptwall benchmark results: {args.tag} "
                        f"({summary['classifier'].get('model', args.classifier)})\n\n"
                        f"- Same attack pages as the main run; host pages this classifier flags "
                        f"on its own are dropped: {len(dropped_hosts)} {dropped_hosts}", 1)
    (OUT / f"RESULTS{suffix}.md").write_text(md, encoding="utf-8")
    print(md)


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