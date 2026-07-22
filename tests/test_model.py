"""Core tests for plugin discovery, conversion, and dataset execution."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import orjson
from Registry.Registry import RegBin

from reg2es.models.Reg2es import (
    Reg2es,
    _normalize_value,
    detect_hive_type,
    discover_plugins,
    plugin_matches_hive,
    plugin_result_to_document,
    resolve_plugin_names,
)
from reg2es.plugins import BasePlugin, PluginResult
from tests.regrippy.reg_mock import RegistryKeyMock, RegistryValueMock


def _runner(plugin_name, plugin, *, chunk_size=100, error_policy="raise"):
    runner = Reg2es.__new__(Reg2es)
    runner.input_paths = [Path("/host/SYSTEM")]
    runner.chunk_size = chunk_size
    runner.error_policy = error_policy
    runner.plugins = [(plugin_name, plugin)]
    return runner


def test_plugin_discovery_and_selection() -> None:
    discovered = discover_plugins()
    names = [name for name, _plugin in discovered]
    assert names == sorted(names)

    selected = resolve_plugin_names(["services", "run"], discovered)
    assert [name for name, _plugin in selected] == ["services", "run"]

    with pytest.raises(ValueError, match="Unknown plugin"):
        resolve_plugin_names(["missing"], discovered)


def test_hive_detection_prefers_parser_and_uses_safe_fallback() -> None:
    registry = MagicMock()
    registry.hive_type.return_value.value = "software"
    assert detect_hive_type(registry, Path("renamed.bin")) == "SOFTWARE"

    registry.hive_type.side_effect = ValueError("unknown")
    assert detect_hive_type(registry, Path("SYSTEM.LOG1")) == "SYSTEM"
    assert detect_hive_type(registry, Path("sample.bin")) == "UNKNOWN"


@pytest.mark.parametrize(
    ("declared", "hive", "expected"),
    [
        ("ALL", "SYSTEM", True),
        ("SOFTWARE", "software", True),
        (["SOFTWARE", "SAM"], "SAM", True),
        (["SOFTWARE", "SAM"], "SYSTEM", False),
    ],
)
def test_plugin_hive_matching(declared, hive, expected) -> None:
    plugin = type("Plugin", (BasePlugin,), {"__REGHIVE__": declared})
    assert plugin_matches_hive(plugin, hive) is expected


def test_normalize_nested_plugin_data_without_stringifying_objects() -> None:
    class Action:
        def __init__(self):
            self.runas = "SYSTEM"
            self.cmd = "cmd.exe"

    value = {
        "binary": b"\xde\xad",
        "when": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "action": Action(),
        "items": (b"\x01", {"ok": True}),
    }
    normalized = _normalize_value(value)
    assert normalized["binary"] == "dead"
    assert normalized["when"] == "2024-01-01T00:00:00+00:00"
    assert normalized["action"] == {"runas": "SYSTEM", "cmd": "cmd.exe"}
    assert normalized["items"] == ["01", {"ok": True}]

    with pytest.raises(TypeError, match="Unsupported value type"):
        _normalize_value(object())


def test_plugin_result_conversion_is_ecs_shaped_and_lossless() -> None:
    key = RegistryKeyMock.build("Control\\Test")
    value = RegistryValueMock("Payload", b"\xde\xad", RegBin)
    result = PluginResult(key=key, value=value)
    result.custom = {
        "nested": {"raw": b"\x00\x01"},
        "label": "端末一号",
    }

    document = plugin_result_to_document(
        result,
        "example",
        "SYSTEM",
        "/host/SYSTEM",
    )

    assert document["event"]["action"] == "example"
    assert document["registry"]["value"] == "Payload"
    assert document["registry"]["data"] == {
        "type": result.value_type,
        "bytes": 2,
        "strings": ["dead"],
    }
    assert document["reg2es"]["value_data"] == "dead"
    assert document["reg2es"]["custom"]["nested"]["raw"] == "0001"
    payload = orjson.dumps(document)
    assert "端末一号".encode() in payload
    assert orjson.loads(payload)["reg2es"]["custom"]["label"] == "端末一号"
    assert document["log"]["file"]["path"] == "/host/SYSTEM"


def test_runner_validates_configuration() -> None:
    with pytest.raises(ValueError, match="error_policy"):
        Reg2es([], error_policy="ignore")
    with pytest.raises(ValueError, match="chunk_size"):
        Reg2es([], chunk_size=0)


def test_error_policy_continue_logs_and_raise_propagates(caplog) -> None:
    class FailingPlugin(BasePlugin):
        __REGHIVE__ = "ALL"

        def run(self):
            raise RuntimeError("broken plugin")
            yield  # pragma: no cover - makes this a generator

    def dataset():
        return {"SYSTEM": [(Path("/host/SYSTEM"), MagicMock())]}

    continuing = _runner("failing", FailingPlugin, error_policy="continue")
    with (
        patch(
            "reg2es.models.Reg2es._build_hive_dataset",
            side_effect=lambda _paths: dataset(),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert list(continuing.gen_records()) == []
    assert "failing" in caplog.text

    raising = _runner("failing", FailingPlugin, error_policy="raise")
    with (
        patch(
            "reg2es.models.Reg2es._build_hive_dataset",
            side_effect=lambda _paths: dataset(),
        ),
        pytest.raises(RuntimeError, match="broken plugin"),
    ):
        list(raising.gen_records())


def test_records_are_chunked_once_with_final_remainder() -> None:
    class ResultsPlugin(BasePlugin):
        __REGHIVE__ = "ALL"

        def run(self):
            for index in range(5):
                result = PluginResult()
                result.custom = {"index": index}
                yield result

    runner = _runner("results", ResultsPlugin, chunk_size=2)
    dataset = {"SYSTEM": [(Path("/host/SYSTEM"), MagicMock())]}
    with patch(
        "reg2es.models.Reg2es._build_hive_dataset",
        return_value=dataset,
    ):
        chunks = list(runner.gen_records())

    assert [len(chunk) for chunk in chunks] == [2, 2, 1]
    assert [
        document["reg2es"]["custom"]["index"] for chunk in chunks for document in chunk
    ] == list(range(5))
    assert dataset == {}


def test_declared_hive_order_and_state_are_isolated_between_datasets(
    monkeypatch,
) -> None:
    from reg2es.plugins.localgroups import Plugin as LocalGroups

    calls = []

    def fake_run(self):
        marker = self.reg.marker
        calls.append((marker, self.hive_name))
        if self.hive_name == "SOFTWARE":
            self.user_profile_list.append(marker)
            return
        result = PluginResult()
        result.custom = {"profiles": list(self.user_profile_list)}
        yield result

    monkeypatch.setattr(LocalGroups, "run", fake_run)
    monkeypatch.setattr(LocalGroups, "user_profile_list", ["stale"])

    def dataset(marker):
        software = MagicMock(marker=marker)
        sam = MagicMock(marker=marker)
        return {
            "SAM": [(Path(f"/{marker}/SAM"), sam)],
            "SOFTWARE": [(Path(f"/{marker}/SOFTWARE"), software)],
        }

    runner = _runner("localgroups", LocalGroups)
    with patch(
        "reg2es.models.Reg2es._build_hive_dataset",
        side_effect=[dataset("first"), dataset("second")],
    ):
        first = list(runner.gen_records())
        second = list(runner.gen_records())

    assert calls == [
        ("first", "SOFTWARE"),
        ("first", "SAM"),
        ("second", "SOFTWARE"),
        ("second", "SAM"),
    ]
    assert first[0][0]["reg2es"]["custom"]["profiles"] == ["first"]
    assert second[0][0]["reg2es"]["custom"]["profiles"] == ["second"]


def test_closing_partial_generator_releases_dataset() -> None:
    class ResultsPlugin(BasePlugin):
        __REGHIVE__ = "ALL"

        def run(self):
            yield PluginResult()
            yield PluginResult()

    dataset = {"SYSTEM": [(Path("/host/SYSTEM"), MagicMock())]}
    runner = _runner("results", ResultsPlugin, chunk_size=1)
    with patch(
        "reg2es.models.Reg2es._build_hive_dataset",
        return_value=dataset,
    ):
        records = runner.gen_records()
        next(records)
        records.close()

    assert dataset == {}
