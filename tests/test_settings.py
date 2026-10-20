import json

import pytest

from putty_lib.settings import DEFAULT_COMMAND_RULES, SettingsStore


def test_defaults_seed_and_persistence(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path, seed={"max_concurrent": 3})
    assert store.current.max_concurrent == 3
    assert store.current.command_rules == DEFAULT_COMMAND_RULES
    store.update({"allowed_hosts": [" web01 ", "", "*.lan"], "strip_ansi": False})
    saved = json.loads(path.read_text())
    assert saved["allowed_hosts"] == ["web01", "*.lan"] and saved["strip_ansi"] is False
    # settings.json wins over the config.toml seed on the next start
    again = SettingsStore(path, seed={"max_concurrent": 7, "strip_ansi": True})
    assert again.current.max_concurrent == 3 and again.current.strip_ansi is False


@pytest.mark.parametrize("changes", [
    {"approval_mode": "sometimes"},
    {"max_output_chars": 10},
    {"strip_ansi": "yes"},
    {"command_rules": [{"pattern": "(unclosed", "action": "ask"}]},
    {"command_rules": [{"pattern": "rm", "action": "allow"}]},
    {"allowed_hosts": "web01"},
    {"no_such_setting": 1},
])
def test_invalid_changes_are_rejected(tmp_path, changes):
    store = SettingsStore(tmp_path / "s.json")
    with pytest.raises(ValueError):
        store.update(changes)
    assert not (tmp_path / "s.json").exists()


def test_listener_and_mutate(tmp_path):
    store = SettingsStore(tmp_path / "s.json")
    seen = []
    store.on_change(lambda s: seen.append(s.allowed_hosts[:]))
    store.mutate(lambda s: s.allowed_hosts.append("db01"))
    assert seen == [["db01"]]


def test_corrupt_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("{not json")
    assert SettingsStore(path).current.approval_mode == "risky"


def test_version_has_changelog_entry():
    from pathlib import Path

    from putty_lib import __version__

    changelog = (Path(__file__).resolve().parent.parent / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {__version__}\n" in changelog


def test_version_format_is_calver():
    import re

    from putty_lib import __version__

    year, month, rev = re.fullmatch(r"(\d{4})\.(\d{2})\.(\d{3})", __version__).groups()
    assert 1 <= int(month) <= 12 and int(rev) >= 1
