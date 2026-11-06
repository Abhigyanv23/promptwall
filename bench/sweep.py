"""Threshold sweep for a baseline: its whole ROC curve, not one operating point.

    python bench/baselines.py --model promptguard2-86m   # writes scores_<tag>.jsonl
    python bench/sweep.py --model promptguard2-86m

A detector run at one threshold gives one (false-positive rate, detection) point.
Comparing two single points only proves something when one beats the other on
BOTH. When it doesn't, sweep the baseline's threshold and ask the fair question:
at the same false-positive rate as promptwall, how much does the baseline catch?

Fairness rule (same as baselines.py), applied at every threshold: attack pages
built on a host page the baseline flags by itself at that threshold are left
out for both detectors, and promptwall is scored on the same remaining pages.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).parent / "results"
THRESHOLDS = [0.9, 0.7, 0.5, 0.3, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005, 0.002, 0.001,
              0.0005, 0.0002, 0.0001]


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def point(thr: float, benign: dict[str, float], attacks: list[dict], pw: dict[int, dict]) -> dict:
    flagged_hosts = {h for h, s in benign.items() if s >= thr}
    kept = [a for a in attacks if a["host"] not in flagged_hosts]
    n = len(kept)
    if n == 0:
        return {"threshold": thr, "benign_fpr": len(flagged_hosts) / len(benign), "n_attack": 0}
    base_flag = sum(a["score"] >= thr for a in kept) / n
    base_reach = sum(a["marker_in_raw"] and a["score"] < thr for a in kept) / n
    pw_flag = sum(pw[a["i"]]["flagged"] for a in kept) / n
    pw_reach = sum(pw[a["i"]]["reached"] for a in kept) / n
    return {"threshold": thr, "benign_fpr": len(flagged_hosts) / len(benign),
            "n_attack": n, "baseline_flagged": base_flag, "baseline_reached": base_reach,
            "promptwall_flagged": pw_flag, "promptwall_reached": pw_reach}


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="the tag baselines.py used, e.g. promptguard2-86m")
    args = ap.parse_args(argv)

    path = RESULTS / f"scores_{args.model}.jsonl"
    if not path.exists():
        sys.exit(f"{path} not found: re-run bench/baselines.py --model {args.model} "
                 "(older versions did not save scores)")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    benign = {r["host"]: r["score"] for r in rows if r["kind"] == "benign_page"}
    attacks = [r for r in rows if r["kind"] == "attack_page"]
    per_case = [json.loads(line) for line in
                (RESULTS / "per_case.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    pw = {r["i"]: r for r in per_case if isinstance(r["i"], int)}
    pw_results = json.loads((RESULTS / "results.json").read_text(encoding="utf-8"))
    pw_fpr = pw_results["tables"]["benign pages"][0]["flagged"]["combined"]

    # Every distinct benign score is a threshold where the FPR changes; add the grid.
    cuts = sorted(set(THRESHOLDS) | {s + 1e-9 for s in benign.values()}, reverse=True)
    pts = [point(t, benign, attacks, pw) for t in cuts]
    pts = [p for p in pts if p["n_attack"]]

    # The fair comparison: the baseline's best detection at FPR <= promptwall's.
    at_pw = [p for p in pts if p["benign_fpr"] <= pw_fpr + 1e-9]
    best = max(at_pw, key=lambda p: p["baseline_flagged"]) if at_pw else None

    lines = [f"# Threshold sweep: `{args.model}`", "",
             f"- Benign real pages: {len(benign)}; attack pages scored: {len(attacks)}",
             f"- promptwall's false-positive rate on the same benign pages: {pct(pw_fpr)}", ""]
    if best:
        lines += ["## At promptwall's false-positive rate", "",
                  f"Best baseline threshold with benign FPR <= {pct(pw_fpr)}: "
                  f"**{best['threshold']:.6g}** (benign FPR {pct(best['benign_fpr'])}).", "",
                  "| | baseline | promptwall (same pages) |", "|---|---|---|",
                  f"| Attack pages flagged (n={best['n_attack']}) | {pct(best['baseline_flagged'])} | "
                  f"{pct(best['promptwall_flagged'])} |",
                  f"| Attack text reaching the LLM | {pct(best['baseline_reached'])} | "
                  f"{pct(best['promptwall_reached'])} |", ""]
    lines += ["## Full sweep (grid points only)", "",
              "| threshold | benign pages flagged | attack pages kept | baseline flagged | "
              "promptwall flagged | baseline reached LLM | promptwall reached LLM |",
              "|---|---|---|---|---|---|---|"]
    for p in pts:
        if p["threshold"] in THRESHOLDS:
            lines.append(f"| {p['threshold']:g} | {pct(p['benign_fpr'])} | {p['n_attack']} | "
                         f"{pct(p['baseline_flagged'])} | {pct(p['promptwall_flagged'])} | "
                         f"{pct(p['baseline_reached'])} | {pct(p['promptwall_reached'])} |")
    md = "\n".join(lines) + "\n"
    (RESULTS / f"SWEEP_{args.model}.md").write_text(md, encoding="utf-8")
    (RESULTS / f"sweep_{args.model}.json").write_text(
        json.dumps({"promptwall_fpr": pw_fpr, "best_at_promptwall_fpr": best, "points": pts},
                   indent=2), encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()