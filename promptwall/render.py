"""Rendered mode: extract visible vs hidden text from a real browser.

The static extractor (extract.py) reads inline styles and <style> blocks. It
cannot see:
  - text hidden by an EXTERNAL stylesheet (the .css file is never fetched), and
  - text that JavaScript adds after the page loads (scripts are not run).
Rendered mode loads the page in headless Chromium (via Playwright), lets its
scripts and stylesheets run, then asks the browser for each text node's
*computed* style and on-screen box. The result is the same Extraction shape the
static extractor returns, so detection, sanitizing and logging are unchanged.

Safety: the page's own scripts run, so network access is BLOCKED by default
(nothing the page requests leaves the machine). Pass allow_network=True to
scan live URLs, or `routes` to serve specific URLs locally (used by the
benchmark to serve an "external" stylesheet). Downloads and service workers
are disabled. Not covered: shadow DOM, iframes, and text injected later than
`settle_ms` after load (e.g. setTimeout(..., 10000)).

    pip install "promptwall-agent[render]" && playwright install chromium
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from .extract import MIN_ATTR_LEN, TEXT_ATTRS, Extraction
from .models import HiddenSpan

# Runs inside the page. Returns {title, visible: [...], hidden: [{reason, text}], innerText}.
_WALKER_JS = r"""
(cfg) => {
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD']);
  const csCache = new Map(), reasonCache = new Map(), bgCache = new Map();
  const cs = el => { let c = csCache.get(el); if (!c) { c = getComputedStyle(el); csCache.set(el, c); } return c; };
  const rgba = s => {
    const m = /rgba?\(([^)]+)\)/.exec(s || '');
    if (!m) return null;
    const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  const lum = c => {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
  };
  // Background actually behind an element: first ancestor with an opaque-ish colour, else white.
  const bgOf = el => {
    if (!el) return [255, 255, 255, 1];
    if (bgCache.has(el)) return bgCache.get(el);
    const c = rgba(cs(el).backgroundColor);
    const r = (c && c[3] > 0.5) ? c : bgOf(el.parentElement);
    bgCache.set(el, r);
    return r;
  };
  // Hidden reason set on this element itself (inherited by its descendants).
  const ownReason = el => {
    const c = cs(el);
    if (c.display === 'none') return 'display-none';
    if (c.visibility === 'hidden' || c.visibility === 'collapse') return 'visibility-hidden';
    if (parseFloat(c.opacity) < 0.05) return 'opacity-0';
    if (c.contentVisibility === 'hidden') return 'content-visibility';
    if (c.clipPath && /inset\(\s*50%|circle\(\s*0/.test(c.clipPath)) return 'clipped';
    if (c.clip && /^rect\(0(px)?[ ,]+0(px)?[ ,]+0(px)?[ ,]+0(px)?\)/.test(c.clip)) return 'clipped';
    if (/^matrix\(0, 0, 0, 0/.test(c.transform)) return 'scaled-0';
    const inline = c.display.startsWith('inline') || c.display === 'contents';
    if (!inline && c.overflow !== 'visible' && (el.clientWidth <= 1 || el.clientHeight <= 1)) return 'zero-size';
    return null;
  };
  const reasonFor = el => {
    if (!el || el === document.documentElement) return null;
    if (reasonCache.has(el)) return reasonCache.get(el);
    const r = ownReason(el) || reasonFor(el.parentElement);
    reasonCache.set(el, r);
    return r;
  };
  const docW = Math.max(document.documentElement.scrollWidth, innerWidth);
  const docH = Math.max(document.documentElement.scrollHeight, innerHeight);
  // Text-level checks: things a parent can look fine for but the glyphs are not seeable.
  const textReason = (node, el) => {
    const c = cs(el);
    if (parseFloat(c.fontSize) < 1) return 'font-size-0';
    const fg = rgba(c.color);
    if (fg && fg[3] < 0.05) return 'transparent-text';
    if (fg) {
      const bg = bgOf(el), a = lum(fg), b = lum(bg);
      const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      if (ratio < 1.15) return 'same-color';
    }
    const range = document.createRange();
    range.selectNodeContents(node);
    const r = range.getBoundingClientRect();
    if (r.width < 1 && r.height < 1) return 'zero-size';
    const x = r.left + scrollX, y = r.top + scrollY;
    if (x + r.width < 0 || y + r.height < 0 || x > docW + 50 || y > docH + 50) return 'off-screen';
    return null;
  };
  const blockOf = el => {
    while (el && el !== document.body) {
      const d = cs(el).display;
      if (!d.startsWith('inline') && d !== 'contents') return el;
      el = el.parentElement;
    }
    return document.body;
  };
  const inSkip = el => { for (; el; el = el.parentElement) if (SKIP.has(el.tagName)) return true; return false; };

  const visible = [], hidden = [];
  let lastBlock = null, lastHidden = null, lastHiddenBlock = null;
  const root = document.body || document.documentElement;
  const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
  for (let n = tw.nextNode(); n; n = tw.nextNode()) {
    if (n.nodeType === Node.COMMENT_NODE) {
      const t = n.data.trim();
      if (t) hidden.push({reason: 'html-comment', text: t});
      lastHidden = null;
      continue;
    }
    const text = n.data.replace(/\s+/g, ' ');
    if (!text.trim()) continue;
    const el = n.parentElement;
    if (!el || inSkip(el)) continue;
    const reason = reasonFor(el) || textReason(n, el);
    if (reason) {
      // Merge consecutive hidden runs with the same reason, so an instruction split
      // across <b>/<span> tags still reads as one sentence.
      const hb = blockOf(el);
      if (lastHidden && lastHidden.reason === reason)
        lastHidden.text += (hb === lastHiddenBlock ? '' : ' ') + text;   // new block: keep a space
      else { lastHidden = {reason, text}; hidden.push(lastHidden); }
      lastHiddenBlock = hb;
      continue;
    }
    lastHidden = null;
    const b = blockOf(el);
    if (b !== lastBlock) { visible.push('\n'); lastBlock = b; }
    visible.push(text);
  }
  // Attribute text (never rendered as page text) - same attributes as static mode.
  for (const el of document.querySelectorAll('*')) {
    for (const a of cfg.textAttrs) {
      const v = el.getAttribute(a);
      if (v && v.trim().length >= cfg.minAttr) hidden.push({reason: 'attr:' + a, text: v.trim()});
    }
    for (const a of el.getAttributeNames()) {
      if (a.startsWith('data-')) {
        const v = el.getAttribute(a);
        if (v && v.trim().length >= cfg.minAttr) hidden.push({reason: 'attr:' + a, text: v.trim()});
      }
    }
    if (el.tagName === 'META') {
      const v = el.getAttribute('content');
      if (v && v.trim().length >= cfg.minAttr) hidden.push({reason: 'attr:meta-content', text: v.trim()});
    }
    if (el.tagName === 'INPUT' && (el.getAttribute('type') || '').toLowerCase() === 'hidden') {
      const v = el.getAttribute('value');
      if (v && v.trim()) hidden.push({reason: 'input-hidden-value', text: v.trim()});
    }
  }
  for (const h of hidden) h.text = h.text.trim();
  return {title: document.title || '', visible, hidden: hidden.filter(h => h.text),
          innerText: document.body ? document.body.innerText : ''};
}
"""


class RenderError(RuntimeError):
    """The page could not be rendered (timeout, crash, browser missing)."""


# Playwright's sync API allows ONE running instance per thread, so every Renderer
# in this thread shares one browser process (each page still gets its own fresh,
# isolated context). Reference-counted: the browser stops with the last Renderer.
_SHARED = threading.local()


def _acquire_browser():
    st = _SHARED.__dict__
    if st.get("browser") is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise RenderError("rendered mode needs Playwright: pip install playwright && "
                              "playwright install chromium") from e
        pw = None
        try:
            pw = sync_playwright().start()
            st["browser"] = pw.chromium.launch(headless=True)
            st["pw"], st["refs"] = pw, 0
        except Exception as e:  # noqa: BLE001 - browser missing, sandbox issues...
            if pw is not None:
                pw.stop()
            raise RenderError(f"could not start Chromium ({e}). "
                              "Try: playwright install chromium") from e
    st["refs"] += 1
    return st["browser"]


def _release_browser():
    st = _SHARED.__dict__
    if st.get("browser") is None:
        return
    st["refs"] -= 1
    if st["refs"] <= 0:
        for closer in (st["browser"].close, st["pw"].stop):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass
        st["browser"] = st["pw"] = None
        st["refs"] = 0


@dataclass
class RenderedExtraction(Extraction):
    inner_text: str = ""            # what a rendered-DOM agent reading innerText would see
    blocked_requests: list[str] = field(default_factory=list)


class Renderer:
    """Reusable headless-Chromium renderer. Not thread-safe: one per thread.

    allow_network: let the page fetch subresources (and allow url= navigation).
    routes: {exact URL: (body, content_type)} served locally, even with network off.
    settle_ms: extra wait after `load` for scripts that inject text slightly later.
    """

    def __init__(self, *, allow_network: bool = False,
                 routes: dict[str, tuple[str, str]] | None = None,
                 timeout_ms: int = 15000, settle_ms: int = 300,
                 viewport: tuple[int, int] = (1280, 800)):
        self.allow_network = allow_network
        self.routes = routes or {}
        self.timeout_ms = timeout_ms
        self.settle_ms = settle_ms
        self.viewport = viewport
        self._browser = None

    # -- lifecycle
    def _ensure(self):
        if self._browser is None:
            self._browser = _acquire_browser()

    def close(self):
        if self._browser is not None:
            self._browser = None
            _release_browser()

    def __enter__(self):
        self._ensure()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- extraction
    def extract(self, html: str | None = None, *, url: str | None = None) -> RenderedExtraction:
        if (html is None) == (url is None):
            raise ValueError("pass exactly one of html or url")
        if url is not None and not self.allow_network:
            raise ValueError("url= needs allow_network=True")
        self._ensure()
        blocked: list[str] = []
        # A fresh context per page: no cookies or storage shared between pages.
        ctx = self._browser.new_context(
            java_script_enabled=True, accept_downloads=False, service_workers="block",
            viewport={"width": self.viewport[0], "height": self.viewport[1]})
        try:
            def handle(route):
                u = route.request.url
                if u in self.routes:
                    body, ctype = self.routes[u]
                    return route.fulfill(status=200, body=body, content_type=ctype)
                if u.startswith(("data:", "about:", "blob:")) or self.allow_network:
                    return route.continue_()
                blocked.append(u)
                return route.abort()

            ctx.route("**/*", handle)
            page = ctx.new_page()
            page.set_default_timeout(self.timeout_ms)
            try:
                if url is not None:
                    page.goto(url, wait_until="load")
                else:
                    page.set_content(html, wait_until="load")
                if self.settle_ms:
                    page.wait_for_timeout(self.settle_ms)
                data = page.evaluate(_WALKER_JS, {"textAttrs": list(TEXT_ATTRS),
                                                  "minAttr": MIN_ATTR_LEN})
            except Exception as e:  # noqa: BLE001 - timeouts, crashed pages
                raise RenderError(f"render failed: {type(e).__name__}: {e}") from e
        finally:
            ctx.close()

        parts = ([data["title"], "\n"] if data["title"] else []) + data["visible"]
        visible = re.sub(r"[ \t]*\n[ \t\n]*", "\n", "".join(parts)).strip()
        visible = re.sub(r"[ \t]{2,}", " ", visible)
        hidden = [HiddenSpan("rendered:" + h["reason"] if not h["reason"].startswith(("attr:", "html-comment", "input-hidden"))
                             else h["reason"], h["text"]) for h in data["hidden"]]
        return RenderedExtraction(visible, hidden, inner_text=data["innerText"],
                                  blocked_requests=blocked)