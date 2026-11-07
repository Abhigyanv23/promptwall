"""promptwall live demo (Streamlit). Deploys free on Streamlit Community Cloud:
share.streamlit.io -> Create app -> this repo, branch main, file demo/streamlit_app.py.

Locally:
    pip install streamlit requests -e .
    streamlit run demo/streamlit_app.py
"""
from __future__ import annotations

import streamlit as st

import core

st.set_page_config(page_title="promptwall demo", layout="wide")

st.title("promptwall: a prompt-injection firewall for browsing agents")
st.markdown(
    "Paste a web page (or fetch one by URL) and see what an AI agent would receive after "
    "promptwall has checked it: the verdict, what was found, what was hidden from human "
    "readers, and the cleaned text. "
    "[Code, benchmark and limits on GitHub](https://github.com/Abhigyanv23/promptwall).  \n"
    "*Static mode only: styles from external CSS files and text added by JavaScript are not "
    "seen here (the package's rendered mode handles those).*")

FIRST_EXAMPLE = next(iter(core.EXAMPLES))
if "content" not in st.session_state:
    st.session_state.content = core.EXAMPLES[FIRST_EXAMPLE]
    st.session_state.fetch_error = ""


def load_example():
    st.session_state.content = core.EXAMPLES[st.session_state.example]
    st.session_state.fetch_error = ""


def fetch():
    try:
        st.session_state.content = core.fetch_url(st.session_state.url)
        st.session_state.fetch_error = ""
    except core.FetchError as e:
        st.session_state.fetch_error = str(e)


@st.cache_resource
def warm_up():
    core.firewall()          # load the classifier once per server, not per visitor
    return True


warm_up()
left, right = st.columns([3, 4], gap="large")

with left:
    st.selectbox("Examples", list(core.EXAMPLES), key="example", on_change=load_example)
    url_col, btn_col = st.columns([4, 1], vertical_alignment="bottom")
    url_col.text_input("Fetch a public URL (optional)", key="url",
                       placeholder="https://example.com/article")
    btn_col.button("Fetch", on_click=fetch, width="stretch")
    if st.session_state.fetch_error:
        st.error(st.session_state.fetch_error)
    st.text_area("HTML or text to check", key="content", height=360)
    as_text = st.checkbox("Treat as plain text (tool output, email) instead of HTML")

with right:
    try:
        r = core.analyze(st.session_state.content, as_text=as_text)
    except ValueError as e:
        st.info(str(e))
        st.stop()

    st.markdown(core.summary_markdown(r))
    findings, hidden, llm, removed = st.tabs(
        ["Findings", "Hidden from humans", "What the LLM receives", "Redacted"])
    with findings:
        if r["findings"]:
            st.dataframe([dict(zip(["rule", "severity", "where", "snippet"], row))
                          for row in r["findings"]], width="stretch", hide_index=True)
        else:
            st.write("No findings.")
    with hidden:
        if r["hidden"]:
            st.dataframe([dict(zip(["how it was hidden", "text"], row)) for row in r["hidden"]],
                         width="stretch", hide_index=True)
        else:
            st.write("Nothing on this page is hidden from a human reader.")
    with llm:
        st.caption("Fenced as untrusted data (spotlighting), so the model treats it as data.")
        st.code(r["llm_input"], language=None, wrap_lines=True)
    with removed:
        if r["removed"]:
            st.markdown("\n".join(f"- {t}" for t in r["removed"]))
        else:
            st.write("Nothing redacted.")