"""promptwall live demo (Streamlit). Deploys free on Streamlit Community Cloud:
share.streamlit.io -> Create app -> this repo, branch main, file demo/streamlit_app.py.

Locally (from the repo root, so .streamlit/config.toml applies the theme):
    pip install streamlit requests -e .
    streamlit run demo/streamlit_app.py
"""
from __future__ import annotations

import streamlit as st

import core
import view

st.set_page_config(page_title="promptwall: see what your agent reads", layout="wide")
st.markdown(view.CSS, unsafe_allow_html=True)
st.markdown(view.HERO, unsafe_allow_html=True)

EXAMPLE_NAMES = list(core.EXAMPLES)
if "content" not in st.session_state:
    st.session_state.content = core.EXAMPLES[EXAMPLE_NAMES[0]]
    st.session_state.example = EXAMPLE_NAMES[0]
    st.session_state.fetch_error = ""


def load_example():
    name = st.session_state.example
    if name:                                  # clicking the selected pill again clears it
        st.session_state.content = core.EXAMPLES[name]
    st.session_state.fetch_error = ""


def fetch():
    try:
        st.session_state.content = core.fetch_url(st.session_state.url)
        st.session_state.example = None
        st.session_state.fetch_error = ""
    except core.FetchError as e:
        st.session_state.fetch_error = str(e)


def edited():
    st.session_state.example = None           # the text no longer matches an example


@st.cache_resource
def warm_up():
    core.firewall()                           # load the classifier once per server
    return True


warm_up()

st.pills("Examples", EXAMPLE_NAMES, key="example", on_change=load_example)

url_col, btn_col = st.columns([5, 1], vertical_alignment="bottom")
url_col.text_input("Or check a live page", key="url",
                   placeholder="https://example.com/article")
btn_col.button("Check page", on_click=fetch, width="stretch")
if st.session_state.fetch_error:
    st.error(st.session_state.fetch_error)

with st.expander("Page source (paste your own HTML or text here)"):
    st.text_area("Page source", key="content", height=300, on_change=edited,
                 label_visibility="collapsed")
    as_text = st.toggle("This is plain text (a tool result or email), not HTML")

try:
    r = core.analyze(st.session_state.content, as_text=as_text)
except ValueError:
    st.info("The page source is empty. Pick an example or paste a page to check it.")
    st.stop()

st.markdown(view.verdict_html(r), unsafe_allow_html=True)

human, agent = st.columns(2, gap="medium")
human.markdown(view.human_view_html(r), unsafe_allow_html=True)
agent.markdown(view.agent_view_html(r), unsafe_allow_html=True)

st.markdown("### Why")
st.markdown(view.findings_html(r), unsafe_allow_html=True)

st.markdown(view.FOOT, unsafe_allow_html=True)