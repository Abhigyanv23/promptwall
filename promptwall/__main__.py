import argparse
import json
import sys
from pathlib import Path

from .firewall import Firewall
from .scanner import Scanner


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="promptwall",
                                description="Scan HTML or text for prompt-injection attempts.")
    p.add_argument("path", help="File to scan, or - for stdin")
    p.add_argument("--text", action="store_true", help="Treat input as plain text, not HTML")
    p.add_argument("--no-ml", action="store_true", help="Rules only (skip the ML classifier)")
    p.add_argument("--log", metavar="FILE", help="Append non-allowed results to a JSONL log")
    p.add_argument("--show-text", action="store_true",
                   help="Include the sanitized text that would be passed to the LLM")
    args = p.parse_args(argv)

    if args.path == "-":
        data = sys.stdin.read()
    else:
        data = Path(args.path).read_text(encoding="utf-8", errors="replace")

    scanner = Scanner(classifier=None) if args.no_ml else Scanner()
    fw = Firewall(scanner, log_path=args.log)
    d = fw.inspect(data, content_type="text" if args.text else "html",
                   source=None if args.path == "-" else args.path)
    out = d.to_dict()
    if not args.show_text:
        out.pop("safe_text")
    out["ml_enabled"] = scanner.classifier is not None
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 1 if d.verdict == "block" else 0


if __name__ == "__main__":
    sys.exit(main())