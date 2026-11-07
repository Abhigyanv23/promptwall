# promptwall demo

Paste a web page, or fetch one by URL, and see what a browsing agent would receive after
[promptwall](https://github.com/Abhigyanv23/promptwall) has checked it:

- the verdict;
- the findings;
- the text hidden from human readers;
- the cleaned, fenced text that is passed to the LLM.

The demo runs promptwall's static mode with the shipped TF-IDF classifier. Its URL fetcher only
reaches public http(s) sites, re-checks every redirect, and stops at 10 seconds or 2 MB.

| File | What it is |
|---|---|
| `core.py` | The analysis and the safe URL fetcher. It has no UI code, so it is tested in `tests/test_demo.py` |
| `streamlit_app.py` | Streamlit UI, used for the free hosted demo |
| `app.py` | The same demo in Gradio, for running locally |
| `requirements.txt` | What Streamlit Community Cloud installs |

## Deploy free on Streamlit Community Cloud

1. Sign in at <https://share.streamlit.io> with GitHub.
2. Click **Create app** → "Deploy a public app from GitHub".
3. Fill in the form:
   - Repository: `Abhigyanv23/promptwall`
   - Branch: `main`
   - Main file path: `demo/streamlit_app.py`
4. Under **Advanced settings**, choose Python **3.12**.
5. Click **Deploy**. The first build takes a few minutes.

The app sleeps after 12 hours without visitors, and the next visitor wakes it.

## Run locally

```bash
pip install streamlit requests -e .
streamlit run demo/streamlit_app.py

# or the Gradio version
pip install gradio requests -e .
python demo/app.py
```