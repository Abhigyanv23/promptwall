"""HTML for the Streamlit demo's results, built from core.analyze() output.

Kept apart from streamlit_app.py so it can be tested without Streamlit. Every
piece of page content goes through html.escape: the demo displays text taken
from arbitrary, possibly hostile pages.
"""
from __future__ import annotations

from html import escape

from promptwall.models import BLOCK_THRESHOLD, SANITIZE_THRESHOLD
from promptwall.scanner import normalize

RULES = {
    "override.ignore_previous": "Tells the agent to ignore its instructions",
    "override.new_instructions": "Gives the agent new instructions",
    "exfil.sensitive_data": "Asks for passwords, keys or personal data",
    "exfil.markdown_image": "Leaks data through an image link",
    "action.navigate_or_run": "Pushes the agent to open a link or run something",
    "target.addresses_agent": "Speaks directly to an AI agent",
    "secrecy.hide_from_user": "Asks the agent to keep something from the user",
    "role.chat_template_token": "Contains chat-template control tokens",
    "role.fake_system_label": "Pretends to be a system message",
    "role.persona_switch": "Tries to change the agent's persona",
    "unicode.tag_smuggling": "Hides text in invisible Unicode tag characters",
    "unicode.zero_width_flood": "Uses many zero-width characters",
    "unicode.bidi_control": "Uses text-direction control characters",
    "unicode.mixed_script_words": "Mixes look-alike letters from other alphabets",
    "ml.classifier": "The classifier reads it as an injected instruction",
    "hidden.content_present": "The page contains text hidden from readers",
    "render.failed": "The browser render failed, so the page was scanned statically",
}

HIDING = {
    "css:display-none": "display: none",
    "css:visibility-hidden": "visibility: hidden",
    "css:opacity-zero": "opacity: 0",
    "css:zero-size": "font size or box of zero",
    "css:same-color": "text the same colour as its background",
    "css:offscreen": "positioned off the screen",
    "aria-hidden": "aria-hidden",
    "html-comment": "an HTML comment",
    "input-hidden-value": "a hidden form field",
    "attr:alt": "image alt text",
    "attr:title": "a tooltip (title)",
    "attr:aria-label": "an aria-label",
    "attr:meta-content": "a meta tag",
}

VERDICT = {
    "block": ("Blocked", "The agent gets a notice instead of this page."),
    "sanitize": ("Sanitized", "Suspicious passages were cut out before the agent reads it."),
    "allow": ("Allowed", "Nothing here is aimed at an agent. It reads the visible text."),
}


def describe_hiding(reason: str) -> str:
    if reason in HIDING:
        return HIDING[reason]
    if reason.startswith("stylesheet:"):
        return "a <style> rule (" + reason.split(":", 1)[1].replace("-", " ") + ")"
    if reason.startswith("attr:"):
        return "the " + reason[5:] + " attribute"
    return reason


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def verdict_html(r: dict) -> str:
    title, line = VERDICT[r["verdict"]]
    risk = max(0.0, min(1.0, r["risk"]))
    lo, hi = r.get("sanitize_at", SANITIZE_THRESHOLD), r.get("block_at", BLOCK_THRESHOLD)
    counts = [plural(len(r["findings"]), "finding"), plural(len(r["hidden"]), "hidden passage"),
              plural(len(r["removed"]), "sentence") + " removed"]
    ml = "" if r["ml_enabled"] else '<p class="pw-note">Classifier unavailable: rules only.</p>'
    return f"""
<section class="pw-verdict pw-{r['verdict']}" aria-label="Verdict">
  <div class="pw-verdict-head">
    <h2>{title}</h2>
    <p>{line}</p>
  </div>
  <div class="pw-meter" role="img"
       aria-label="Risk {risk:.2f}. Sanitize from {lo:g}, block from {hi:g}.">
    <div class="pw-meter-track">
      <span class="pw-zone pw-zone-allow" style="width:{lo * 100:.0f}%"></span>
      <span class="pw-zone pw-zone-sanitize"
            style="width:{(hi - lo) * 100:.0f}%"></span>
      <span class="pw-zone pw-zone-block" style="width:{(1 - hi) * 100:.0f}%"></span>
      <span class="pw-needle" style="left:{risk * 100:.1f}%"></span>
    </div>
    <div class="pw-meter-scale">
      <span>Risk {risk:.2f}</span>
      <span>sanitize from {lo:g}, block from {hi:g}</span>
    </div>
  </div>
  <p class="pw-counts">{", ".join(counts)}, checked in {r['latency_ms']} ms.</p>
  {ml}
</section>"""


def human_view_html(r: dict) -> str:
    """What a person sees, then what was hidden from them, marked up."""
    paras = [p for p in r["visible_text"].split("\n") if p.strip()] or ["(no visible text)"]
    cut = {t.strip() for t in r["removed"]}

    def line(p: str) -> str:
        # A line the sanitizer removed is struck through, so the cut is visible in place.
        if normalize(p).strip() in cut:
            return f'<p class="pw-cut" title="Removed before the agent reads it">{escape(p)}</p>'
        return f"<p>{escape(p)}</p>"

    body = "".join(line(p) for p in paras[:400])
    if len(paras) > 400:
        body += f'<p class="pw-note">…and {len(paras) - 400} more lines.</p>'
    hidden = "".join(
        f'<div class="pw-hidden"><span class="pw-hidden-how">Hidden by '
        f'{escape(describe_hiding(reason))}</span><p>{escape(text)}</p></div>'
        for reason, text in r["hidden"][:200])
    if hidden:
        hidden = ('<h4>Hidden from people, but present in the page</h4>' + hidden)
    return ('<div class="pw-panel pw-human"><h3>What a person sees</h3>'
            f'<div class="pw-scroll" tabindex="0" aria-label="What a person sees">{body}{hidden}</div></div>')


def agent_view_html(r: dict) -> str:
    return ('<div class="pw-panel pw-agent"><h3>What the agent receives</h3>'
            '<div class="pw-scroll" tabindex="0" aria-label="What the agent receives">'
            f'<pre>{escape(r["llm_input"])}</pre></div></div>')


def findings_html(r: dict) -> str:
    if not r["findings"]:
        return '<p class="pw-empty">No rule or classifier fired on this input.</p>'
    rows = "".join(
        f'<tr><td><span class="pw-sev pw-sev-{escape(sev)}">{escape(sev)}</span></td>'
        f'<td><strong>{escape(RULES.get(rule, rule))}</strong><br><code>{escape(rule)}</code></td>'
        f'<td>{escape(describe_hiding(where) if where not in ("visible", "page", "text") else where)}</td>'
        f'<td class="pw-snip">{escape(snip)}</td></tr>'
        for rule, sev, where, snip in r["findings"])
    return ('<div class="pw-table-wrap"><table class="pw-findings"><thead><tr>'
            '<th>Severity</th><th>What it found</th><th>Where</th><th>Text</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>')


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@400;500;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --pw-paper: #F3F5F7;
  --pw-sheet: #FFFFFF;
  --pw-ink: #1B2430;
  --pw-muted: #5B6676;
  --pw-rule: #D5DBE3;
  --pw-blue: #2747D6;
  --pw-block: #B42318;
  --pw-block-tint: #FDECEA;
  --pw-sanitize: #A15C07;
  --pw-sanitize-tint: #FEF3E2;
  --pw-allow: #1D7A55;
  --pw-allow-tint: #E6F4EE;
  --pw-hatch: rgba(161, 92, 7, 0.16);
}

/* Text only. Streamlit draws its icons with a ligature font (Material Symbols):
   overriding the font on those spans prints their names, e.g. "_arrow_right". */
.stApp, .stMarkdown, .stTextInput input, .stTextArea textarea, .stButton button,
[data-testid="stWidgetLabel"], [data-testid="stExpander"] summary p, .stSlider, .stPills {
  font-family: 'Schibsted Grotesk', system-ui, sans-serif;
}
[data-testid="stIconMaterial"], .material-symbols-rounded {
  font-family: 'Material Symbols Rounded' !important;
}
.stTextArea textarea, .pw-agent pre, .pw-findings code {
  font-family: 'IBM Plex Mono', ui-monospace, monospace !important;
}
[data-testid="stHeader"] { background: transparent; }
.block-container { max-width: 1180px; padding-top: 2.5rem; }

.pw-hero { margin: 0 0 1.75rem; max-width: 52rem; }
.pw-hero h1 {
  font-size: clamp(2.4rem, 5vw, 3.6rem); line-height: 1.02; font-weight: 800;
  letter-spacing: -0.03em; margin: 0 0 0.75rem; color: var(--pw-ink); padding: 0;
}
.pw-hero h1 .pw-strike {
  text-decoration: line-through; text-decoration-color: var(--pw-block);
  text-decoration-thickness: 0.12em; color: var(--pw-muted);
}
.pw-hero p { font-size: 1.08rem; line-height: 1.55; color: var(--pw-muted); margin: 0; }
.pw-hero a { color: var(--pw-blue); }

.pw-verdict {
  border-left: 6px solid var(--pw-tone); background: var(--pw-tint);
  padding: 1.25rem 1.5rem; border-radius: 4px; margin: 0.5rem 0 1.5rem;
}
.pw-block { --pw-tone: var(--pw-block); --pw-tint: var(--pw-block-tint); }
.pw-sanitize { --pw-tone: var(--pw-sanitize); --pw-tint: var(--pw-sanitize-tint); }
.pw-allow { --pw-tone: var(--pw-allow); --pw-tint: var(--pw-allow-tint); }
.pw-verdict-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.25rem 1rem; }
.pw-verdict h2 {
  font-size: 2.6rem; font-weight: 800; letter-spacing: -0.03em; line-height: 1;
  color: var(--pw-tone); margin: 0; padding: 0;
}
.pw-verdict-head p { margin: 0; font-size: 1.05rem; color: var(--pw-ink); }
.pw-meter { margin: 1.1rem 0 0.6rem; max-width: 34rem; }
.pw-meter-track { position: relative; display: flex; height: 10px; border-radius: 5px; overflow: visible; }
.pw-zone { height: 100%; opacity: 0.35; }
.pw-zone-allow { background: var(--pw-allow); border-radius: 5px 0 0 5px; }
.pw-zone-sanitize { background: var(--pw-sanitize); }
.pw-zone-block { background: var(--pw-block); border-radius: 0 5px 5px 0; }
.pw-needle {
  position: absolute; top: -5px; width: 4px; height: 20px; margin-left: -2px;
  background: var(--pw-ink); border-radius: 2px;
}
.pw-meter-scale {
  display: flex; justify-content: space-between; gap: 1rem; margin-top: 0.45rem;
  font-size: 0.85rem; color: var(--pw-muted);
}
.pw-meter-scale span:first-child { color: var(--pw-ink); font-weight: 700; }
.pw-counts { margin: 0; color: var(--pw-muted); font-size: 0.95rem; }
.pw-note, .pw-empty { color: var(--pw-muted); font-size: 0.95rem; }

.pw-panel {
  background: var(--pw-sheet); border: 1px solid var(--pw-rule); border-radius: 6px;
  padding: 1.1rem 1.25rem; overflow-wrap: anywhere;
}
.pw-panel h3 { font-size: 1.05rem; font-weight: 700; margin: 0 0 0.75rem; padding: 0; color: var(--pw-ink); }
.pw-panel h4 { font-size: 0.95rem; font-weight: 700; margin: 1.25rem 0 0.5rem; padding: 0; color: var(--pw-sanitize); }
.pw-human p { margin: 0 0 0.6rem; line-height: 1.6; max-width: 70ch; }
.pw-human p.pw-cut {
  text-decoration: line-through; text-decoration-color: var(--pw-block);
  text-decoration-thickness: 2px; color: var(--pw-muted);
}
.pw-hidden {
  margin: 0 0 0.6rem; padding: 0.6rem 0.8rem; border: 1px dashed var(--pw-sanitize);
  border-radius: 4px;
  background: repeating-linear-gradient(-45deg, var(--pw-hatch) 0 6px, transparent 6px 12px);
}
.pw-hidden p { margin: 0.25rem 0 0; font-size: 0.95rem; }
.pw-hidden-how { font-size: 0.85rem; font-weight: 700; color: var(--pw-sanitize); }
/* Both views scroll inside a fixed height, so a long page doesn't push the findings
   far down. The heading stays put; tabindex lets keyboard users scroll them too. */
.pw-scroll {
  max-height: 28rem; overflow-y: auto; padding-right: 0.5rem;
  scrollbar-width: thin; scrollbar-color: #AEB7C4 transparent;
}
.pw-scroll::-webkit-scrollbar { width: 8px; }
.pw-scroll::-webkit-scrollbar-thumb { background: #AEB7C4; border-radius: 4px; }
.pw-scroll:focus-visible { outline: 2px solid var(--pw-blue); outline-offset: 2px; }
.pw-agent pre {
  white-space: pre-wrap; margin: 0; font-size: 0.86rem; line-height: 1.55;
  background: #EEF1F5; color: var(--pw-ink); padding: 0.9rem 1rem; border-radius: 4px;
}

.pw-table-wrap { overflow-x: auto; }
.pw-findings { width: 100%; border-collapse: collapse; font-size: 0.93rem; }
.pw-findings th {
  text-align: left; font-weight: 700; color: var(--pw-muted); font-size: 0.85rem;
  border-bottom: 2px solid var(--pw-rule); padding: 0.5rem 0.75rem 0.5rem 0;
}
.pw-findings td { border-bottom: 1px solid var(--pw-rule); padding: 0.65rem 0.75rem 0.65rem 0; vertical-align: top; }
.pw-findings code { font-size: 0.78rem; color: var(--pw-muted); background: none; padding: 0; }
.pw-snip { color: var(--pw-muted); max-width: 28rem; }
.pw-sev { font-weight: 700; white-space: nowrap; }
.pw-sev::before { content: ""; display: inline-block; width: 0.6em; height: 0.6em; border-radius: 50%; margin-right: 0.4em; background: currentColor; }
.pw-sev-high { color: var(--pw-block); }
.pw-sev-medium { color: var(--pw-sanitize); }
.pw-sev-low { color: var(--pw-muted); }

.pw-foot { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--pw-rule); color: var(--pw-muted); font-size: 0.9rem; }
.pw-foot a { color: var(--pw-blue); }

@media (max-width: 640px) {
  .pw-verdict h2 { font-size: 2rem; }
  .pw-meter-scale { flex-direction: column; gap: 0.1rem; }
  .pw-findings thead { display: none; }
  .pw-findings tr { display: block; border-bottom: 1px solid var(--pw-rule); padding: 0.6rem 0; }
  .pw-findings td { display: block; border: 0; padding: 0.15rem 0; }
}
</style>
"""

HERO = """
<header class="pw-hero">
  <h1>Your agent reads <span class="pw-strike">everything</span> what you would.</h1>
  <p>Web pages can hide instructions for AI agents in text people never see. promptwall finds
  them, cuts them out, and hands the agent only what a person would read. Pick an example or
  paste a page.</p>
</header>
"""

FOOT = """
<footer class="pw-foot">
  Static mode: external stylesheets and text added by JavaScript are not seen here (the
  package's rendered mode handles those). Benchmark, misses and code on
  <a href="https://github.com/Abhigyanv23/promptwall">GitHub</a>.
</footer>
"""