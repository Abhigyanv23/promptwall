"""Score a neural prompt-injection classifier on the SAME cases as promptwall.

    pip install transformers torch sentencepiece
    python bench/baselines.py --model protectai          # ungated, Apache-2.0
    python bench/baselines.py --model promptguard2-86m   # gated: request access + `hf auth login`
    python bench/baselines.py --model promptguard2-22m --limit 200   # quick partial run

Run bench/run_benchmark.py first: this script reads its results.json (which host
pages were used) and per_case.jsonl (promptwall's verdict on each case), so the
comparison is case-for-case on identical inputs.

How the baseline is applied (the way you'd deploy a string classifier):
  input  = the page's extracted text, as a plain-text agent reads it
  window = 512 tokens with overlap (both model cards cap input at 512 tokens;
           Meta's card says to split longer text and scan every segment)
  score  = max P(malicious) over the windows; flagged if >= --threshold
  if flagged, the page is assumed withheld (so the attack does not reach the LLM)

Fairness: host pages the baseline itself flags are dropped from the attack
comparison for BOTH detectors, so neither gets credit for a host false positive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import cases  # noqa: E402
from cases import squash  # noqa: E402
from run_benchmark import html_text  # noqa: E402

RESULTS = Path(__file__).parent / "results"
MODELS = {
    "protectai": "protectai/deberta-v3-base-prompt-injection-v2",
    "promptguard2-86m": "meta-llama/Llama-Prompt-Guard-2-86M",
    "promptguard2-22m": "meta-llama/Llama-Prompt-Guard-2-22M",
}


# ---------------------------------------------------------------- detectors

class HFDetector:
    """Any Hugging Face sequence classifier with a benign / attack label."""

    def __init__(self, model_id: str, device: str = "cpu", batch_size: int = 16,
                 window: int = 512):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        # A smaller window dilutes a short payload less with surrounding page text
        # (sensitivity check: --window 128). 2 tokens are reserved for specials.
        self.WINDOW = max(16, min(window, 512) - 2)
        self.STRIDE = max(1, self.WINDOW - max(8, self.WINDOW // 8))
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id).to(device).eval()
        self.device, self.batch_size = device, batch_size
        labels = {i: str(l).upper() for i, l in self.model.config.id2label.items()}
        hits = [i for i, l in labels.items() if any(k in l for k in ("MAL", "INJ", "JAIL"))]
        # Both cards: index 1 = attack. Prefer the label name when it says so.
        self.attack_idx = hits[0] if hits else 1
        print(f"labels={labels} -> attack index {self.attack_idx}")
        self._cache: dict[str, float] = {}

    WINDOW, STRIDE = 510, 446   # 510 tokens + 2 special tokens = 512; 64-token overlap

    def _windows(self, text: str) -> list[str]:
        # Manual windowing over token ids: works with slow and fast tokenizers alike.
        ids = self.tok(text, add_special_tokens=False, truncation=False,
                       verbose=False)["input_ids"]
        if len(ids) <= self.WINDOW:
            return [text]
        starts, i = [], 0
        while True:                      # step until a window reaches the last token
            starts.append(i)
            if i + self.WINDOW >= len(ids):
                break
            i += self.STRIDE
        return [self.tok.decode(ids[s:s + self.WINDOW], skip_special_tokens=True)
                for s in starts]

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        wins = self._windows(text)
        todo = [w for w in wins if self._key(w) not in self._cache]
        for i in range(0, len(todo), self.batch_size):
            batch = todo[i:i + self.batch_size]
            enc = self.tok(batch, truncation=True, max_length=512, padding=True,
                           return_tensors="pt").to(self.device)
            with self.torch.no_grad():
                probs = self.torch.softmax(self.model(**enc).logits, dim=-1)[:, self.attack_idx]
            for w, p in zip(batch, probs.tolist()):
                self._cache[self._key(w)] = p
        return max(self._cache[self._key(w)] for w in wins)

    @staticmethod
    def _key(w: str) -> str:
        return hashlib.sha1(w.encode()).hexdigest()


class StubDetector:
    """No-download stand-in used to test this script's plumbing (--model stub)."""

    def score(self, text: str) -> float:
        t = squash(text)
        return 0.99 if ("ignore" in t and "instruction" in t) or "important message" in t else 0.01


# ---------------------------------------------------------------- tally

class Counts:
    def __init__(self):
        self.n = defaultdict(int)
        self.c = defaultdict(lambda: defaultdict(int))

    def add(self, table: str, group: str, **flags: bool):
        key = (table, group)
        self.n[key] += 1
        for name, v in flags.items():
            self.c[key][name] += bool(v)

    def rows(self, table: str) -> list[dict]:
        return [{"group": g, "n": n, **{k: v / n for k, v in self.c[(t, g)].items()}}
                for (t, g), n in self.n.items() if t == table]


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


# ---------------------------------------------------------------- main

def main(argv=None):
    # Windows consoles default to cp1252, which cannot print the report's symbols.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True,
                    help=f"{', '.join(MODELS)}, stub, or any Hugging Face model id")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--device", default="cpu", help="cpu or cuda")
    ap.add_argument("--limit", type=int, default=0, help="score only the first N attack pages")
    ap.add_argument("--window", type=int, default=512,
                    help="tokens per window (default 512 = model max; try 128 as a sensitivity check)")
    args = ap.parse_args(argv)

    res_path = RESULTS / "results.json"
    pc_path = RESULTS / "per_case.jsonl"
    if not (res_path.exists() and pc_path.exists()):
        sys.exit("Run bench/run_benchmark.py first (needs results.json and per_case.jsonl).")
    results = json.loads(res_path.read_text(encoding="utf-8"))
    per_case = [json.loads(line) for line in pc_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    pw_attack = [r for r in per_case if isinstance(r["i"], int)]
    pw_text = {r["i"]: r for r in per_case if not isinstance(r["i"], int)}

    name = args.model
    model_id = MODELS.get(name, name)
    det = (StubDetector() if name == "stub"
           else HFDetector(model_id, args.device, window=args.window))
    tag = name.replace("/", "_") + ("" if args.window == 512 else f"_w{args.window}")
    thr = args.threshold

    def flagged(text: str) -> tuple[bool, float]:
        t0 = time.perf_counter()
        s = det.score(text)
        return s >= thr, (time.perf_counter() - t0) * 1000

    counts = Counts()
    latencies: list[float] = []

    # Benign pages -> false-positive rate; also decides which hosts are fair to use.
    pages = dict(cases.benign_pages())
    host_fp: dict[str, bool] = {}
    for pname, html in pages.items():
        f, ms = flagged(html_text(html))
        latencies.append(ms)
        host_fp[pname] = f
        counts.add("benign pages", "readability test pages (real sites)", baseline=f)
    for pname, html in cases.hard_negative_pages():
        f, _ = flagged(html_text(html))
        counts.add("hard negatives", "hand-written hard negatives", baseline=f)

    # Attack pages, rebuilt from the same host list and checked against per_case.
    clean_hosts = [(h, pages[h]) for h in results["summary"]["clean_hosts"]]
    skipped = 0
    for i, c in enumerate(cases.attack_pages(clean_hosts)):
        if args.limit and i >= args.limit:
            break
        pw = pw_attack[i]
        assert pw["host"] == c.host and pw["groups"] == c.groups, \
            "case mismatch: re-run bench/run_benchmark.py"
        if host_fp[c.host]:
            skipped += 1     # baseline already flags this host page - unfair to count
            continue
        raw = html_text(c.page)
        f, ms = flagged(raw)
        latencies.append(ms)
        base_reached = (c.marker in squash(raw)) and not f
        for table, group in c.groups.items():
            counts.add(table, group, baseline=f, promptwall=pw["flagged"],
                       baseline_reached=base_reached, promptwall_reached=pw["reached"],
                       no_defence_reached=pw["reached_no_defence"])
        if i % 100 == 0:
            print(f"  attack page {i}...", flush=True)

    # Text-level cases (tool outputs, direct attacks, benign emails/tables).
    for prefix, gen, table in (("text", cases.text_attacks, "text-level attacks"),
                               ("benign-text", cases.text_benign, "benign text")):
        for i, (group, t) in enumerate(gen()):
            f, _ = flagged(t)
            counts.add(table, group, baseline=f, promptwall=pw_text[f"{prefix}-{i}"]["flagged"])

    # ---------------- write
    lat = sorted(latencies)
    tables = {t: counts.rows(t) for t in
              ["attack pages by delivery", "attack pages by wrapper",
               "attack pages by goal source", "text-level attacks", "benign pages",
               "benign text", "hard negatives"]}
    # promptwall's false-positive rates on the same benign pages, from its own run.
    for t in ("benign pages", "hard negatives"):
        pw_rows = {r["group"]: r["flagged"]["combined"] for r in results["tables"][t]}
        for r in tables[t]:
            r["promptwall"] = pw_rows.get(r["group"], float("nan"))
    out = {
        "model": model_id, "threshold": thr, "window": args.window, "limit": args.limit,
        "hosts_excluded_as_baseline_false_positives": sorted(h for h, f in host_fp.items()
                                                              if f and h in results["summary"]["clean_hosts"]),
        "attack_pages_skipped": skipped,
        "latency_ms": {"p50": round(statistics.median(lat), 1),
                       "p95": round(lat[int(0.95 * len(lat))], 1)},
        "promptwall_latency_ms": results["summary"]["latency_ms"],
        "tables": tables,
    }
    (RESULTS / f"baseline_{tag}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    md = render(out)
    (RESULTS / f"BASELINE_{tag}.md").write_text(md, encoding="utf-8")
    print(md)


def render(o: dict) -> str:
    lines = [f"# Baseline: `{o['model']}` vs promptwall", "",
             f"- Threshold {o['threshold']}; input = extracted page text in "
             f"{o.get('window', 512)}-token windows, "
             f"score = max over windows",
             f"- Latency per page: baseline p50 {o['latency_ms']['p50']} ms, "
             f"p95 {o['latency_ms']['p95']} ms | promptwall p50 "
             f"{o['promptwall_latency_ms']['p50']} ms, p95 {o['promptwall_latency_ms']['p95']} ms",
             f"- Host pages the baseline flags on their own (dropped from the attack comparison "
             f"for both): {len(o['hosts_excluded_as_baseline_false_positives'])} "
             f"({o['attack_pages_skipped']} attack pages skipped)"]
    if o["limit"]:
        lines.append(f"- PARTIAL RUN: first {o['limit']} attack pages only")
    lines.append("")
    for table, rows in o["tables"].items():
        if not rows:
            continue
        attack_pages = "promptwall_reached" in rows[0]
        both = "promptwall" in rows[0]
        head = "| group | n | baseline flagged |"
        sep = "|---|---|---|"
        if both:
            head += " promptwall flagged |"
            sep += "---|"
        if attack_pages:
            head += " reached LLM: no defence | baseline | promptwall |"
            sep += "---|---|---|"
        lines += [f"## {table}", "", head, sep]
        for r in sorted(rows, key=lambda r: -r["baseline"]):
            line = f"| {r['group']} | {r['n']} | {pct(r['baseline'])} |"
            if both:
                line += f" {pct(r['promptwall'])} |"
            if attack_pages:
                line += (f" {pct(r['no_defence_reached'])} | {pct(r['baseline_reached'])} | "
                         f"{pct(r['promptwall_reached'])} |")
            lines.append(line)
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()