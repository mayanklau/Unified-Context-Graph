"""The web console, driven in a real browser.

These tests start the application on a local port, load the demonstration estate
into a fresh tenant and click through every section. They are skipped when no
Chromium is available; run them with ``pytest -m ui``.

Set ``SECGRAPH_TEST_CHROMIUM`` to a Chromium executable to use one that
Playwright did not install itself.
"""

from __future__ import annotations

import os
import shutil
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.ui

playwright_api = pytest.importorskip("playwright.sync_api")

PASSWORD = "Console-Check-2026!"  # noqa: S105 - a test credential
SECTIONS = ["overview", "explore", "paths", "priorities", "memory", "data", "admin", "model"]


def _chromium_path() -> str | None:
    explicit = os.environ.get("SECGRAPH_TEST_CHROMIUM")
    if explicit:
        return explicit
    for candidate in ("/opt/pw-browsers/chromium", shutil.which("chromium"), shutil.which("chromium-browser")):
        if candidate and Path(candidate).exists():
            return candidate
    return None


@pytest.fixture(scope="module")
def browser() -> Iterator[object]:
    with playwright_api.sync_playwright() as p:
        try:
            instance = p.chromium.launch()
        except Exception:
            path = _chromium_path()
            if not path:
                pytest.skip("no Chromium available for the console tests")
            try:
                instance = p.chromium.launch(executable_path=path)
            except Exception as exc:  # pragma: no cover - depends on the machine
                pytest.skip(f"Chromium could not be started: {exc}")
        yield instance
        instance.close()


@pytest.fixture(scope="module")
def console(ctx) -> Iterator[dict[str, str]]:
    """The app on a real socket, with the demo estate in its own tenant."""
    import uvicorn

    from secgraph.api.app import create_app
    from secgraph.demo.loader import seed_demo
    from secgraph.governance.rbac import Principal

    tenant = "ui-" + uuid.uuid4().hex[:10]
    suffix = uuid.uuid4().hex[:6]
    users = {"admin": f"ui-admin-{suffix}", "viewer": f"ui-viewer-{suffix}"}
    seed_demo(
        ctx, tenant, Principal.build(id="user:ui-test", name="ui-test", kind="user", tenant_id=tenant, roles=["admin"])
    )
    for role, username in users.items():
        ctx.auth.create_user(tenant, "user:ui-test", username=username, password=PASSWORD, roles=[role])

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(context=ctx), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:  # pragma: no cover
            raise RuntimeError("the console server did not start")
        time.sleep(0.05)
    yield {"url": f"http://127.0.0.1:{port}", "tenant": tenant, **users}
    server.should_exit = True
    thread.join(timeout=10)


class Session:
    """One browser page plus everything that went wrong on it."""

    def __init__(self, browser, base: str, **context_options: object):
        self.base = base
        self.context = browser.new_context(**context_options)
        self.page = self.context.new_page()
        self.problems: list[str] = []
        self.page.on("pageerror", lambda error: self.problems.append(f"script error: {error}"))
        self.page.on(
            "console",
            lambda message: (
                self.problems.append(f"console {message.type}: {message.text}")
                if message.type in ("error", "warning")
                else None
            ),
        )

    def login(self, username: str) -> None:
        self.page.goto(self.base + "/")
        self.page.wait_for_selector("#login:not([hidden])")
        self.page.fill("input[name=username]", username)
        self.page.fill("input[name=password]", PASSWORD)
        self.page.click("#login-form button[type=submit]")
        self.page.wait_for_selector("#shell:not([hidden])")

    def open(self, section: str) -> str:
        self.page.click(f'#nav a[href="#/{section}"]')
        return self.wait(section)

    def wait(self, section: str) -> str:
        self.page.wait_for_function(
            "section => { const m = document.querySelector('#main');"
            " return m.dataset.section === section && m.getAttribute('aria-busy') === 'false'"
            " && !m.querySelector('.spinner'); }",
            arg=section,
        )
        return self.page.inner_text("#main")

    def assert_clean(self) -> None:
        """No script errors, and no value that was printed instead of rendered."""
        text = self.page.inner_text("body")
        for leak in ("[object ", "undefined", "NaN"):
            assert leak not in text, f"the page shows {leak!r}"
        assert "null" not in text.split(), "the page shows 'null'"
        assert self.problems == []

    def close(self) -> None:
        self.context.close()


def test_every_section_renders_without_errors(browser, console):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["admin"])
    assert session.page.eval_on_selector_all("#nav a", "els => els.map(e => e.getAttribute('href'))") == [
        f"#/{name}" for name in SECTIONS
    ]
    text = {}
    for name in SECTIONS:
        text[name] = session.open(name)
        session.assert_clean()
    assert "Crown jewels at risk" in text["overview"] and "ad-dc-01" in text["overview"]
    assert "web-portal-01" in text["explore"]
    assert "External attacker" in text["paths"] and "this path" in text["paths"]
    assert "CVE-" in text["priorities"] and "Choke points" in text["priorities"] and "Contained" in text["priorities"]
    assert "Log4Shell" in text["memory"]
    assert "assets_csv" in text["data"]
    assert "Create an API key" in text["admin"]
    assert "internet_exposed_asset" in text["model"]
    assert session.problems == []
    session.close()


def test_explore_entity_tabs_and_graph(browser, console):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["admin"])
    session.open("explore")
    page = session.page
    page.fill("input[type=search]", "web-portal-01")
    page.click("#main form button[type=submit]")
    page.click('tr.clickable:has-text("web-portal-01")')
    page.wait_for_selector(".graph svg .vertex")
    assert page.locator(".graph svg .vertex").count() >= 3
    page.wait_for_selector(".legend .type")
    assert "q=web-portal-01" in page.url  # the search survives opening a result
    assert page.input_value("#main input[type=search]") == "web-portal-01"
    session.assert_clean()
    for tab, expected in (
        ("Exposure", "Compromise probability"),
        ("Details", "hostname"),
        ("Relationships", "HAS_FINDING"),
        ("History", "current"),
        ("Context pack", "web-portal-01"),
    ):
        page.click(f'.tabs button:has-text("{tab}")')
        page.wait_for_function("expected => document.querySelector('#main').innerText.includes(expected)", arg=expected)
        session.assert_clean()
    session.close()


def test_overview_links_filter_the_explorer(browser, console):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["admin"])
    session.open("overview")
    page = session.page
    page.click('#main a[href="#/explore?type=BusinessService"]')
    session.wait("explore")
    types = page.eval_on_selector_all("#main tr.clickable td:nth-child(2)", "els => els.map(e => e.innerText.trim())")
    assert types and set(types) == {"BusinessService"}
    session.assert_clean()
    session.close()


def test_untrusted_names_are_rendered_as_text(browser, console, ctx):
    """A scanner can put anything in a title. It must never become markup."""
    from secgraph.ingest.canonical import IngestRequest

    hostile = '<img src=x onerror="window.pwned=1">'
    ctx.ingest.ingest(
        console["tenant"],
        "user:ui-test",
        IngestRequest(
            source="scanner",
            nodes=[
                {"type": "Asset", "identifiers": {"hostname": "xss-probe-01"}, "properties": {"name": hostile}},
            ],
        ),
    )
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["admin"])
    session.open("explore")
    page = session.page
    page.fill("input[type=search]", "xss-probe-01")
    page.click("#main form button[type=submit]")
    row = page.locator("tr.clickable", has_text="onerror")
    row.wait_for()
    row.click()
    page.wait_for_selector(".graph svg .vertex")
    assert page.locator("#main img").count() == 0
    assert page.evaluate("window.pwned") is None
    assert session.problems == []
    session.close()


def test_viewer_sees_only_what_the_role_allows(browser, console):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["viewer"])
    links = session.page.eval_on_selector_all("#nav a", "els => els.map(e => e.getAttribute('href'))")
    assert links == ["#/overview", "#/explore", "#/model"]
    text = session.open("overview")
    assert "Entities" in text and "Crown jewels at risk" not in text
    # a hand-typed address for a section the role cannot use falls back to the first allowed one
    session.page.goto(console["url"] + "/#/admin")
    session.page.wait_for_function("() => location.hash === '#/overview'")
    assert session.problems == []
    session.close()


def test_wrong_password_api_key_login_and_sign_out(browser, console, ctx):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    page = session.page
    page.goto(console["url"] + "/")
    page.fill("input[name=username]", console["admin"])
    page.fill("input[name=password]", "not-the-password")
    page.click("#login-form button[type=submit]")
    page.wait_for_selector("#login-error:not([hidden])")
    assert page.is_hidden("#shell")

    key = ctx.auth.create_api_key(
        console["tenant"],
        "user:ui-test",
        name="console test",
        roles=["analyst"],
        kind="service",
        known_node_types=set(ctx.ontology.node_types),
    )["api_key"]
    page.click('button[data-mode="key"]')
    page.fill("input[name=apikey]", key)
    page.click("#login-form button[type=submit]")
    page.wait_for_selector("#shell:not([hidden])")
    assert "analyst" in page.inner_text("#whoami")
    page.click("#logout")
    page.wait_for_selector("#login:not([hidden])")
    assert page.evaluate("sessionStorage.length") == 0
    # the failed sign-in is the only thing the browser may have complained about
    assert [p for p in session.problems if "401" not in p] == []
    session.close()


def test_admin_can_create_a_key_and_add_a_note(browser, console):
    session = Session(browser, console["url"], viewport={"width": 1360, "height": 860})
    session.login(console["admin"])
    page = session.page
    session.open("admin")
    page.fill('#main input[name="name"]', "triage agent")
    page.click('#main button:has-text("Create key")')
    page.wait_for_selector("#main pre:has-text('sg_')")
    assert "triage agent" in page.inner_text("#main")

    session.open("memory")
    title = "Console note " + uuid.uuid4().hex[:6]
    page.fill('#main input[name="title"]', title)
    page.fill('#main textarea[name="body"]', "Written from the console test.")
    page.click('#main button:has-text("Add note")')
    page.wait_for_function("title => document.querySelector('#main').innerText.includes(title)", arg=title)
    assert session.problems == []
    session.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_narrow_screens_do_not_scroll_sideways(browser, console, scheme):
    session = Session(browser, console["url"], viewport={"width": 390, "height": 800}, color_scheme=scheme)
    session.login(console["admin"])
    for name in SECTIONS:
        session.open(name)
        overflow = session.page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        assert overflow <= 1, f"{name} scrolls sideways by {overflow}px"
    assert session.problems == []
    session.close()
