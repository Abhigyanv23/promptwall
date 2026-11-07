"""The demo's logic (demo/core.py): example verdicts and the URL fetcher's SSRF guard.

No network: name resolution is replaced by a stub.
"""
import socket
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1] / "demo"
if not (DEMO / "core.py").exists():           # e.g. tests run from the sdist
    pytest.skip("demo/ not present", allow_module_level=True)
sys.path.insert(0, str(DEMO))
import core  # noqa: E402

EXPECTED = {
    "Hidden instruction (display:none)": "block",
    "White-on-white text": "block",
    "Visible instruction in a blog post": "sanitize",
    "Homoglyphs (Cyrillic letters)": "block",
    "HTML comment (not flagged, still stripped)": "allow",
    "Ordinary page (should allow)": "allow",
}


@pytest.mark.parametrize("name", list(EXPECTED))
def test_examples_give_the_verdict_their_label_promises(name):
    assert core.analyze(core.EXAMPLES[name])["verdict"] == EXPECTED[name]


def test_hidden_comment_never_reaches_the_llm_even_unflagged():
    r = core.analyze(core.EXAMPLES["HTML comment (not flagged, still stripped)"])
    assert r["hidden"] and "disregard" not in r["llm_input"]


def test_empty_input_is_a_friendly_error():
    with pytest.raises(ValueError):
        core.analyze("   ")


def fake_resolve(ip):
    def getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 443))]
    return getaddrinfo


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                                "172.16.0.1", "0.0.0.0", "100.64.0.1"])
def test_private_and_metadata_addresses_are_refused(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolve(ip))
    with pytest.raises(core.FetchError, match="private or reserved"):
        core._check_public("http://innocent-looking.example/")


def test_ipv6_loopback_is_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0))])
    with pytest.raises(core.FetchError):
        core._check_public("http://[::1]/")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x",
                                 "gopher://example.com/"])
def test_only_http_and_https(url):
    with pytest.raises(core.FetchError, match="Only http"):
        core._check_public(url)


def test_public_address_is_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolve("93.184.215.14"))
    core._check_public("https://example.com/")      # no exception


def test_redirect_to_a_private_address_is_refused(monkeypatch):
    """A public page that redirects to the metadata service must not be followed."""
    requests = pytest.importorskip("requests")
    addresses = {"public.example": "93.184.215.14", "169.254.169.254": "169.254.169.254"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addresses[host], 80))])

    class Redirect:
        is_redirect, status_code = True, 302
        headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

        def close(self):
            pass

    fetched = []
    monkeypatch.setattr(requests, "get", lambda url, **k: fetched.append(url) or Redirect())
    with pytest.raises(core.FetchError, match="private or reserved"):
        core.fetch_url("http://public.example/")
    assert fetched == ["http://public.example/"]      # the private URL was never requested