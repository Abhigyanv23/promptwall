---
title: promptwall
emoji: 🧱
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: 6.30.0
python_version: "3.12"
app_file: app.py
pinned: false
license: mit
short_description: Prompt-injection firewall for browsing agents - live demo
---

# promptwall demo

Paste a web page or fetch one by URL, and see what a browsing agent would receive after
[promptwall](https://github.com/Abhigyanv23/promptwall) has checked it: the verdict, the
findings, the text hidden from human readers, and the cleaned, fenced text passed to the LLM.

The demo runs promptwall's static mode with the shipped TF-IDF classifier. Its URL fetcher only
reaches public http(s) sites, re-checks every redirect, and stops at 10 seconds or 2 MB.