import types

import requests

from site_inspector import inspect_website


def test_inspect_website_without_url_marks_irrelevant():
    result = inspect_website(None)
    assert result["cookies"]["reason"] == "no_website"
    assert result["cookies"]["enabled"] is False


def test_inspect_website_detects_cookies(monkeypatch):
    jar = requests.cookies.RequestsCookieJar()
    jar.set("sessionid", "abc", domain=".example.com", secure=True, rest={"HttpOnly": True})
    fake_response = types.SimpleNamespace(
        status_code=200,
        url="https://example.com/",
        cookies=jar,
        headers={"Set-Cookie": "sessionid=abc"},
        text="<html><body>Cookie banner present.</body></html>",
    )

    def fake_get(url, headers, timeout):  # noqa: ARG001
        return fake_response

    monkeypatch.setattr("site_inspector.requests.get", fake_get)
    result = inspect_website("example.com")
    assert result["reachable"] is True
    assert result["cookies"]["enabled"] is True
    assert result["cookies"]["details"][0]["name"] == "sessionid"
    assert result["cookies"]["banner_detected"] is True
