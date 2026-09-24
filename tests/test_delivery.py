"""Regression gates for the static UI contract and reproducible distribution."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re

import pytest

from main import THEATER_STEPS
from scripts.init_env import initialize

ROOT = Path(__file__).resolve().parents[1]


class PageContract(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.scripts = []
        self.inline_scripts = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "script":
            if "src" in attrs:
                self.scripts.append(attrs["src"])
            else:
                self.inline_scripts += 1


@pytest.mark.parametrize("page", ["index", "sessions", "session", "attack", "profiles"])
def test_pages_have_unique_ids_and_local_external_scripts(page):
    parser = PageContract()
    html = (ROOT / "static" / f"{page}.html").read_text()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids))
    assert parser.inline_scripts == 0
    assert parser.scripts == ["/static/app.js", f"/static/pages/{page}.js"]
    for script in parser.scripts:
        assert (ROOT / script.lstrip("/")).is_file()
    assert 'data-pref-theme' not in html


def test_no_native_prompt_or_confirm_remains():
    for source in (ROOT / "static").rglob("*.js"):
        assert not re.search(r"window\.(prompt|confirm)\(", source.read_text())


def test_demo_fixture_matches_theater():
    data = json.loads((ROOT / "tests/data/demo_sequence.json").read_text())
    assert data["commands"] == [command for command, _ in THEATER_STEPS]


def test_initial_config_is_offline_and_does_not_overwrite(tmp_path):
    (tmp_path / ".env.example").write_text((ROOT / ".env.example").read_text())
    target = initialize(tmp_path)
    original = target.read_text()
    assert "DASHSCOPE_API_KEY=\n" in original
    assert "DASHSCOPE_BASE_URL=\n" in original
    assert "NEO4J_PASSWORD=please_change_me" not in original
    with pytest.raises(FileExistsError):
        initialize(tmp_path)
    assert target.read_text() == original


def test_overview_omits_decorative_instruction_copy():
    shared = (ROOT/'static/app.js').read_text()
    overview = (ROOT/'static/index.html').read_text()
    assert 'ASTHONEY · 第 14 组 · 本机 SSH 实验' not in shared
    assert '实线为预置资产，虚线为即时合成资产' not in overview
    assert 'resetDemoBtn' in overview
