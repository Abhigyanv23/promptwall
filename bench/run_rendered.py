"""Phase 4 benchmark: promptwall in RENDERED mode (headless Chromium).

    python bench/run_benchmark.py     # static run first (defines the host pages)
    python bench/run_rendered.py      # ~20 min on 1 core; writes *_rendered files

Runs the same 1,932 attack pages as the static benchmark, plus a Phase 4 set of
322 pages hidden by an EXTERNAL stylesheet (scored in both modes). "No defence"
here means an agent that reads the rendered page's innerText, which is what a
browser-based agent sees: it includes JavaScript-added text and excludes text
hidden by CSS. Page network requests are blocked; the benchmark's "external"
stylesheet is served locally by the renderer.
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
import cases  # noqa: E402
from cases import squash  # noqa: E402
from deliveries import EXTERNAL_CSS_BODY, EXTERNAL_CSS_URL  # noqa: E402
from run_benchmark import DETECTORS, Tally, html_text, keyword_hit, render_md  # noqa: E402
from run_benchmark import scan as scan_static  # noqa: E402
from promptwall.extract import extract_html  # noqa: E402
from promptwall.models import Finding, ScanResult, Severity  # noqa: E402
from promptwall.render import Renderer, RenderError  # noqa: E402
from promptwall.sanitize import sanitize_text  # noqa: E402
from promptwall.scanner import Scanner, normalize  # noqa: E402

OUT = Path(__file__).parent / "results"


def scan_rendered(scanner: Scanner, renderer: Renderer, html: str):
    t0 = time.perf_counter()
    failed = False
    try:
        ext = renderer.extract(html)
        raw = ext.inner_text
    except RenderError:
        ext, raw, failed = extract_html(html), html_text(html), True
    res = scanner.scan_extraction(ext)
    if failed:
        res.findings.append(Finding("render.failed", "operational", Severity.LOW, "page", ""))
    if res.verdict == "sanitize":
        safe = sanitize_text(res.visible_text, scanner).text
    elif res.verdict == "allow":
        safe = normalize(res.visible_text)
    else:
        safe = ""
    ms = (time.perf_counter() - t0) * 1000
    rules_res = ScanResult(findings=[f for f in res.findings if not f.rule_id.startswith("ml.")])
    ml = [f for f in res.findings if f.rule_id.startswith("ml.")]
    verdicts = {
        "keyword_baseline": "block" if keyword_hit(raw) else "allow",
        "rules": rules_res.verdict,
        "ml": ("block" if any(f.severity.value == "high" for f in ml) else
               "sanitize" if ml else "allow"),
        "combined": res.verdict,
    }
    return verdicts, ms, raw, safe, res, failed


def reached(c, v, raw, safe) -> dict:
    in_raw = c.marker in squash(raw)
    return {"no_defence": in_raw,
            "keyword_baseline": in_raw and v["keyword_baseline"] == "allow",
            "promptwall": c.marker in squash(safe)}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    static = json.loads((OUT / "results.json").read_text(encoding="utf-8"))
    pages = dict(cases.benign_pages())
    scanner = Scanner()
    assert scanner.classifier is not None, "train the classifier first"
    renderer = Renderer(routes={EXTERNAL_CSS_URL: (EXTERNAL_CSS_BODY, "text/css")})
    latencies: list[float] = []
    misses: list[dict] = []
    failures = 0

    try:
        # ---- benign pages: false positives, and which hosts stay usable
        benign = Tally()
        false_pos, host_flagged = [], {}
        for name, html in pages.items():
            v, ms, _, _, res, failed = scan_rendered(scanner, renderer, html)
            latencies.append(ms)
            failures += failed
            benign.add("readability test pages (real sites)", v)
            host_flagged[name] = any(x != "allow" for x in v.values())
            if v["combined"] != "allow":
                false_pos.append({"page": name, "verdict": v["combined"],
                                  "findings": [f"{f.rule_id}@{f.location}: {f.snippet[:90]}"
                                               for f in res.findings
                                               if f.rule_id != "hidden.content_present"]})
        hard = Tally()
        for name, html in cases.hard_negative_pages():
            v, *_ = scan_rendered(scanner, renderer, html)
            hard.add("hand-written hard negatives", v)

        # Same host list as the static run, minus hosts rendered mode flags on its own.
        static_hosts = [(h, pages[h]) for h in static["summary"]["clean_hosts"]]
        dropped = sorted(h for h, _ in static_hosts if host_flagged[h])

        # ---- the 1,932 original attack pages
        by_delivery, by_wrapper, by_source = Tally(), Tally(), Tally()
        tallies = {"attack pages by delivery": by_delivery, "attack pages by wrapper": by_wrapper,
                   "attack pages by goal source": by_source}
        n_attack = skipped = 0
        for i, c in enumerate(cases.attack_pages(static_hosts)):
            if c.host in dropped:
                skipped += 1
                continue
            v, ms, raw, safe, _, failed = scan_rendered(scanner, renderer, c.page)
            latencies.append(ms)
            failures += failed
            r = reached(c, v, raw, safe)
            for table, group in c.groups.items():
                tallies[table].add(group, v, r)
            if v["combined"] == "allow":
                misses.append({"set": "attack_page", "delivery": c.delivery, "wrapper": c.wrapper,
                               "goal_source": c.goal_source, "host": c.host,
                               "reached_llm": r["promptwall"],
                               "payload": " ".join(c.payload.split())[:300]})
            n_attack += 1
            if i % 200 == 0:
                print(f"  attack page {i}...", flush=True)

        # ---- Phase 4 set: external-stylesheet hiding, static vs rendered
        ext_css = Tally()
        for c in cases.external_css_pages(static_hosts):
            if c.host in dropped:
                continue
            v, _, raw, safe, _ = scan_static(scanner, c.page, True)
            ext_css.add("external stylesheet, static mode", v, reached(c, v, raw, safe))
            v, ms, raw, safe, _, failed = scan_rendered(scanner, renderer, c.page)
            failures += failed
            ext_css.add("external stylesheet, rendered mode", v, reached(c, v, raw, safe))
    finally:
        renderer.close()

    lat = sorted(latencies)
    summary = {
        "mode": "rendered", "n_attack_pages": n_attack, "n_benign_pages": len(pages),
        "n_clean_hosts": len(static_hosts) - len(dropped),
        "hosts_dropped_rendered_false_positive": dropped,
        "attack_pages_skipped": skipped, "render_failures": failures,
        "latency_ms": {"p50": round(statistics.median(lat), 1),
                       "p95": round(lat[int(0.95 * len(lat))], 1),
                       "max": round(lat[-1], 1)},
    }
    tables = {"attack pages by delivery": by_delivery, "attack pages by wrapper": by_wrapper,
              "attack pages by goal source": by_source,
              "Phase 4: external-stylesheet hiding": ext_css,
              "benign pages": benign, "hard negatives": hard}
    data = {"summary": summary, "tables": {t: list(tab.rows()) for t, tab in tables.items()},
            "false_positives": false_pos}
    (OUT / "results_rendered.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    with (OUT / "misses_rendered.csv").open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["set", "delivery", "wrapper", "goal_source",
                                            "host", "reached_llm", "payload"])
        wr.writeheader()
        wr.writerows(misses)
    md = render_md(data).replace(
        "# promptwall benchmark results",
        "# promptwall benchmark results: RENDERED mode (headless Chromium)\n\n"
        f"- No defence = an agent reading the rendered page's innerText. Hosts dropped because "
        f"rendered mode flags them on their own: {len(dropped)} ({skipped} attack pages skipped). "
        f"Render failures (fell back to static): {failures}.", 1).replace(
        " ⚠️ expected gap", " (a static-mode gap; scanned here)")
    (OUT / "RESULTS_rendered.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()