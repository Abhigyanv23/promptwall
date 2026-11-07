"""promptwall live demo (Gradio). Runs on a Hugging Face Space or locally:

    pip install gradio requests -e .
    python demo/app.py            # then open http://127.0.0.1:7860
"""
from __future__ import annotations

import gradio as gr

import core

INTRO = """# promptwall: a prompt-injection firewall for browsing agents
Paste a web page (or fetch one by URL) and see what an AI agent would receive after
promptwall has checked it: the verdict, what was found, what was hidden from human readers,
and the cleaned text. [Code, benchmark and limits on GitHub](https://github.com/Abhigyanv23/promptwall).

Static mode only: styles from external CSS files and text added by JavaScript are not seen
here (the package's rendered mode handles those)."""


def run(content: str, as_text: bool):
    try:
        r = core.analyze(content, as_text=as_text)
    except ValueError as e:
        return f"**{e}**", [], [], "", ""
    removed = "\n".join(f"- {t}" for t in r["removed"]) or "(nothing redacted)"
    return (core.summary_markdown(r), r["findings"], r["hidden"], r["llm_input"],
            removed)


def fetch(url: str):
    try:
        return core.fetch_url(url), ""
    except core.FetchError as e:
        return gr.update(), f"**{e}**"


with gr.Blocks(title="promptwall demo") as demo:
    gr.Markdown(INTRO)
    with gr.Row():
        with gr.Column(scale=3):
            with gr.Row():
                url = gr.Textbox(label="Fetch a public URL (optional)",
                                 placeholder="https://example.com/article", scale=4)
                fetch_btn = gr.Button("Fetch", scale=1)
            fetch_msg = gr.Markdown()
            content = gr.Textbox(label="HTML or text to check", lines=14, max_lines=30,
                                 value=core.EXAMPLES["Hidden instruction (display:none)"])
            as_text = gr.Checkbox(label="Treat as plain text (tool output, email) instead of HTML")
            check_btn = gr.Button("Check it", variant="primary")
            gr.Examples(examples=[[html] for html in core.EXAMPLES.values()],
                        example_labels=list(core.EXAMPLES), inputs=[content],
                        label="Examples")
        with gr.Column(scale=4):
            summary = gr.Markdown()
            with gr.Tab("Findings"):
                findings = gr.Dataframe(headers=["rule", "severity", "where", "snippet"],
                                        wrap=True, interactive=False)
            with gr.Tab("Hidden from humans"):
                hidden = gr.Dataframe(headers=["how it was hidden", "text"], wrap=True,
                                      interactive=False)
            with gr.Tab("What the LLM receives"):
                llm_input = gr.Textbox(label="Fenced as untrusted data (spotlighting)",
                                       lines=14, max_lines=30)
            with gr.Tab("Redacted"):
                removed = gr.Markdown()

    outputs = [summary, findings, hidden, llm_input, removed]
    check_btn.click(run, [content, as_text], outputs)
    fetch_btn.click(fetch, [url], [content, fetch_msg]).then(run, [content, as_text], outputs)
    demo.load(run, [content, as_text], outputs)

if __name__ == "__main__":
    demo.queue(default_concurrency_limit=4).launch()