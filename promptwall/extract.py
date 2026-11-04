"""Split an HTML page into visible text and hidden/non-rendered text spans.

Reads inline styles and simple class/id rules from <style> blocks in the page.
Hiding via external stylesheets or JS needs a rendered DOM (getComputedStyle) -
that comes in Phase 4 (Playwright).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup
from bs4.element import Comment, Declaration, Doctype, NavigableString, ProcessingInstruction, Tag

from .models import HiddenSpan

TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder")
MIN_ATTR_LEN = 15
HIDDEN_CLASSES = {"sr-only", "visually-hidden", "screen-reader-text", "hidden", "d-none", "invisible"}
BLOCK_TAGS = {
    "p", "div", "li", "ul", "ol", "br", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "td", "th",
    "section", "article", "header", "footer", "nav", "main", "aside", "blockquote", "pre",
    "table", "form", "title",
}

# Applied to the style attribute with all whitespace removed, lower-cased.
_STYLE_RULES = [
    ("display-none", re.compile(r"display:none")),
    ("visibility-hidden", re.compile(r"visibility:(hidden|collapse)")),
    ("opacity-0", re.compile(r"(^|;)opacity:0*(\.0+)?(;|$|!)")),
    ("font-size-0", re.compile(r"font-size:0*(\.0+)?(px|em|rem|pt|%)?(;|$|!)")),
    ("off-screen", re.compile(r"(left|top|right|text-indent|margin-left|margin-top):-\d{3,}")),
    ("clipped", re.compile(r"clip(-path)?:(rect\(0|inset\(50%|circle\(0)")),
    ("transparent-text", re.compile(r"(^|;)color:(transparent|rgba\([^)]*,0(\.0+)?\))")),
]
_ZERO_SIZE = re.compile(r"(^|;)(max-)?(height|width):0(px)?(;|$|!)")

_COLOR_ALIASES = {
    "#fff": "white", "#ffffff": "white", "rgb(255,255,255)": "white",
    "#000": "black", "#000000": "black", "rgb(0,0,0)": "black",
}


@dataclass
class Extraction:
    visible_text: str
    hidden_spans: list[HiddenSpan] = field(default_factory=list)


_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_CSS_RULE = re.compile(r"([^{}@]+)\{([^{}]*)\}")
_SIMPLE_SELECTOR = re.compile(r"^[a-z0-9_-]*([.#])([a-z0-9_-]+)$", re.I)
_SR_ONLY_CLASSES = {"sr-only", "visually-hidden", "screen-reader-text"}


def _declarations_hide(decl: str) -> str | None:
    d = re.sub(r"\s+", "", decl).lower()
    for name, rx in _STYLE_RULES:
        if rx.search(d):
            return name
    return None


def _stylesheet_hidden(soup: BeautifulSoup) -> tuple[dict[str, str], dict[str, str]]:
    """Return {class: reason}, {id: reason} for simple selectors that hide content.

    Handles `.x`, `#x`, `div.x` (and comma lists of them), including rules
    inside @media blocks. Descendant/compound selectors are skipped - matching
    them properly needs a real CSS engine.
    """
    classes: dict[str, str] = {}
    ids: dict[str, str] = {}
    for st in soup.find_all("style"):
        css = _CSS_COMMENT.sub("", st.get_text())
        for selectors, decl in _CSS_RULE.findall(css):
            how = _declarations_hide(decl)
            if not how:
                continue
            for sel in selectors.split(","):
                m = _SIMPLE_SELECTOR.match(sel.strip())
                if not m:
                    continue
                target = classes if m.group(1) == "." else ids
                target[m.group(2).lower()] = how
    return classes, ids


def _css_value(style: str, prop: str) -> str | None:
    m = re.search(rf"(?:^|;){re.escape(prop)}:([^;!]+)", style)
    return m.group(1) if m else None


def _color(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    return _COLOR_ALIASES.get(v, v)


def _hidden_reason(tag: Tag, sheet_classes: dict[str, str] | None = None,
                   sheet_ids: dict[str, str] | None = None) -> str | None:
    if tag.has_attr("hidden"):
        return "attr-hidden"
    if str(tag.get("aria-hidden", "")).lower() == "true":
        return "aria-hidden"
    style = re.sub(r"\s+", "", str(tag.get("style", ""))).lower()
    if style:
        for name, rx in _STYLE_RULES:
            if rx.search(style):
                return f"css:{name}"
        if _ZERO_SIZE.search(style) and "overflow:hidden" in style:
            return "css:zero-size"
        fg = _color(_css_value(style, "color"))
        bg = _color(_css_value(style, "background-color") or _css_value(style, "background"))
        if fg and bg and fg == bg:
            return "css:same-color"
    classes = {c.lower() for c in (tag.get("class") or [])}
    hit = classes & HIDDEN_CLASSES
    if hit:
        return f"class:{sorted(hit)[0]}"
    if sheet_classes:
        for c in sorted(classes):
            if c in sheet_classes and c not in _SR_ONLY_CLASSES:
                return f"stylesheet:{sheet_classes[c]}"
    if sheet_ids:
        tid = str(tag.get("id", "")).lower()
        if tid and tid in sheet_ids:
            return f"stylesheet:{sheet_ids[tid]}"
    return None


def _collect_attrs(tag: Tag, out: list[HiddenSpan]) -> None:
    for attr in TEXT_ATTRS:
        v = tag.get(attr)
        if isinstance(v, str) and len(v.strip()) >= MIN_ATTR_LEN:
            out.append(HiddenSpan(f"attr:{attr}", v.strip()))
    for k, v in tag.attrs.items():
        if k.startswith("data-") and isinstance(v, str) and len(v.strip()) >= MIN_ATTR_LEN:
            out.append(HiddenSpan(f"attr:{k}", v.strip()))
    if tag.name == "meta":
        v = tag.get("content")
        if isinstance(v, str) and len(v.strip()) >= MIN_ATTR_LEN:
            out.append(HiddenSpan("attr:meta-content", v.strip()))
    if tag.name == "input" and str(tag.get("type", "")).lower() == "hidden":
        v = tag.get("value")
        if isinstance(v, str) and v.strip():
            out.append(HiddenSpan("input-hidden-value", v.strip()))


def extract_html(html: str) -> Extraction:
    soup = BeautifulSoup(html, "html.parser")
    sheet_classes, sheet_ids = _stylesheet_hidden(soup)
    for t in soup(["script", "style", "noscript", "template"]):
        t.decompose()

    visible: list[str] = []
    hidden: list[HiddenSpan] = []

    def walk(node) -> None:
        for child in node.children:
            if isinstance(child, Comment):
                text = child.strip()
                if text:
                    hidden.append(HiddenSpan("html-comment", text))
                continue
            if isinstance(child, (Doctype, Declaration, ProcessingInstruction)):
                continue
            if isinstance(child, NavigableString):
                text = " ".join(child.split())
                if text:
                    visible.append(text)
                continue
            if not isinstance(child, Tag):
                continue

            reason = _hidden_reason(child, sheet_classes, sheet_ids)
            if reason:
                # Whole hidden subtree becomes ONE span, so instructions split
                # across inline tags (<b>, <span>) still match patterns.
                text = " ".join(child.get_text(" ").split())
                if text:
                    hidden.append(HiddenSpan(reason, text))
                for t in [child, *child.find_all(True)]:
                    _collect_attrs(t, hidden)
                for c in child.find_all(string=lambda s: isinstance(s, Comment)):
                    if c.strip():
                        hidden.append(HiddenSpan("html-comment", c.strip()))
                continue

            _collect_attrs(child, hidden)
            if child.name in BLOCK_TAGS:
                visible.append("\n")
            walk(child)
            if child.name in BLOCK_TAGS:
                visible.append("\n")

    walk(soup)
    visible_text = re.sub(r"[ \t]*\n[ \t\n]*", "\n", " ".join(visible)).strip()
    return Extraction(visible_text, hidden)