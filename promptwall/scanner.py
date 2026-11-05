from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import replace

from . import unicode_checks as uc
from .confusables import fold_mixed_script
from .extract import extract_html
from .models import Finding, ScanResult, Severity
from .patterns import RULES, Rule

_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ESCALATE = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.HIGH,
}
# Used for content that is merely hidden (menus, modals, comments, attributes).
# Real sites hide a LOT legitimately, so weak (LOW) signals are not escalated
# there - run 1 of the benchmark showed that caused most rule false positives.
_ESCALATE_HIDDEN = {
    Severity.LOW: Severity.LOW,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.HIGH,
}
_AUTO = object()


# Several mixed-script words (Latin + Cyrillic/Greek inside one word) is the
# signature of a homoglyph attack; one or two can be a brand name or a typo.
MIXED_SCRIPT_THRESHOLD = 3


def normalize(text: str) -> str:
    """Strip invisible chars, then NFKC (folds full-width / compatibility letters).

    This is also what the LLM receives, so it must not change real text.
    """
    return unicodedata.normalize("NFKC", uc.strip_invisible(text))


def normalize_for_matching(text: str) -> str:
    """normalize() + homoglyph folding. For detection only - never shown to the LLM."""
    return fold_mixed_script(normalize(text))[0]


def _snippet(text: str, m: re.Match, pad: int = 40) -> str:
    s = text[max(0, m.start() - pad): m.end() + pad]
    return " ".join(s.split())[:200]


def _try_b64(s: str) -> str | None:
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text) / max(len(text), 1)
    return text if printable > 0.9 else None


class Scanner:
    """Rules + (optional) ML classifier.

    classifier: "auto" (default) loads the bundled model if scikit-learn is
    installed; None disables ML; or pass an InjectionClassifier instance.
    renderer: a promptwall.render.Renderer to extract text from a real browser
    (catches external-CSS hiding and JavaScript-added text); None = static mode.
    """

    def __init__(self, rules: list[Rule] | None = None, zero_width_threshold: int = 10,
                 classifier=_AUTO, renderer=None):
        self.rules = rules if rules is not None else RULES
        self.zero_width_threshold = zero_width_threshold
        self.renderer = renderer   # promptwall.render.Renderer for rendered mode, or None
        if classifier is _AUTO:
            from .ml import InjectionClassifier
            classifier = InjectionClassifier.load_default()
        self.classifier = classifier

    # ---------------- rules ----------------

    def scan_text(self, text: str, location: str = "text", _depth: int = 0) -> list[Finding]:
        findings: list[Finding] = []
        counts = uc.invisible_counts(text)

        if counts["tag"]:
            decoded = uc.decode_tag_smuggling(text)
            findings.append(Finding("unicode.tag_smuggling", "obfuscation",
                                    Severity.MEDIUM, location, decoded[:200]))
            if _depth == 0 and decoded:
                for f in self.scan_text(decoded, location, _depth + 1):
                    findings.append(replace(f, severity=Severity.HIGH,
                                            location=f"{location}+tag-decoded"))
                findings.extend(self._ml_findings(decoded, f"{location}+tag-decoded",
                                                  escalate=True))
        if counts["bidi"]:
            findings.append(Finding("unicode.bidi_control", "obfuscation", Severity.LOW,
                                    location, f"{counts['bidi']} bidi control char(s)"))
        if counts["zero_width"] >= self.zero_width_threshold:
            findings.append(Finding("unicode.zero_width_flood", "obfuscation", Severity.LOW,
                                    location, f"{counts['zero_width']} zero-width char(s)"))

        clean, mixed = fold_mixed_script(normalize(text))
        if mixed >= MIXED_SCRIPT_THRESHOLD:
            findings.append(Finding("unicode.mixed_script_words", "obfuscation", Severity.MEDIUM,
                                    location, f"{mixed} word(s) mixing Latin with Cyrillic/Greek"))
        for rule in self.rules:
            m = rule.pattern.search(clean)
            if m:
                findings.append(Finding(rule.id, rule.category, rule.severity,
                                        location, _snippet(clean, m)))

        if _depth == 0:
            for m in _B64.finditer(clean):
                decoded = _try_b64(m.group())
                if decoded and (self.scan_text(decoded, location, _depth + 1)
                                or self._ml_findings(decoded, location)):
                    findings.append(Finding("obfuscation.base64_payload", "obfuscation",
                                            Severity.HIGH, location, decoded[:200]))
        return findings

    # ---------------- ML ----------------

    def _ml_batch(self, items: list[tuple[str, str]], escalate: bool = False) -> list[Finding]:
        """items: (text, location). One model call for all of them."""
        if self.classifier is None:
            return []
        items = [(t, loc) for t, loc in items if t and t.strip()]
        if not items:
            return []
        clf = self.classifier
        out = []
        scored = clf.score_many([normalize_for_matching(t) for t, _ in items])
        for (_, loc), chunks in zip(items, scored):
            for cs in chunks:
                if cs.prob < clf.threshold:
                    continue
                sev = Severity.HIGH if cs.prob >= clf.high_threshold else Severity.MEDIUM
                if escalate:
                    sev = _ESCALATE[sev]
                out.append(Finding("ml.classifier", "ml", sev, loc,
                                   f"p={cs.prob:.2f} | {cs.text[:180]}"))
        return out

    def _ml_findings(self, text: str, location: str, escalate: bool = False) -> list[Finding]:
        return self._ml_batch([(text, location)], escalate)

    # ---------------- entry points ----------------

    def scan_html(self, html: str) -> ScanResult:
        """Scan HTML. Uses the browser when a renderer is set, else static extraction."""
        if self.renderer is None:
            return self.scan_extraction(extract_html(html))
        from .render import RenderError
        try:
            return self.scan_extraction(self.renderer.extract(html))
        except RenderError as e:
            # Never let a page through unscanned: fall back to static extraction.
            result = self.scan_extraction(extract_html(html))
            result.findings.append(Finding("render.failed", "operational", Severity.LOW,
                                           "page", str(e)[:200]))
            return result

    def scan_url(self, url: str) -> ScanResult:
        """Render a live URL (needs a renderer with allow_network=True)."""
        if self.renderer is None:
            raise ValueError("scan_url needs a renderer: Scanner(renderer=Renderer(allow_network=True))")
        return self.scan_extraction(self.renderer.extract(url=url))

    def scan_extraction(self, ext) -> ScanResult:
        """Core scan over an Extraction (static or rendered)."""
        result = ScanResult(visible_text=ext.visible_text, hidden_spans=ext.hidden_spans)
        result.findings.extend(self.scan_text(ext.visible_text, "visible"))

        concealed = 0
        for span in ext.hidden_spans:
            if not span.reason.startswith("attr:"):
                concealed += 1
            for f in self.scan_text(span.text, span.reason):
                result.findings.append(replace(f, severity=_ESCALATE_HIDDEN[f.severity]))
        # ML is NOT escalated for hidden spans: hidden text never reaches the LLM
        # through Firewall (it is dropped), so a MEDIUM here is for alerting only.
        result.findings.extend(self._ml_batch(
            [(ext.visible_text, "visible")] + [(s.text, s.reason) for s in ext.hidden_spans]))

        if concealed:
            result.findings.append(Finding("hidden.content_present", "concealment", Severity.LOW,
                                           "page", f"{concealed} hidden text span(s)"))
        return result

    def scan_plain(self, text: str) -> ScanResult:
        findings = self.scan_text(text, "text") + self._ml_findings(text, "text")
        return ScanResult(findings=findings, visible_text=text)