"""Core tests for plugin discovery, conversion, and dataset execution."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import orjson
from Registry import Registry
from Registry.Registry import RegBin

from reg2es.models.Reg2es import (
    Reg2es,
    RegistryRecoveryError,
    _build_hive_dataset,
    _close_parsers,
    _normalize_value,
    _prepare_registry_hive,
    detect_hive_type,
    discover_plugins,
    is_transaction_log,
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


def _fake_registry(**attrs):
    values = {
        "_reg2es_recovery": None,
        "_reg2es_temporary_path": None,
        **attrs,
    }
    return SimpleNamespace(**values)


def test_plugin_discovery_and_selection() -> None:
    discovered = discover_plugins()
    names = [name for name, _plugin in discovered]
    assert names == sorted(names)

    selected = resolve_plugin_names(["services", "run"], discovered)
    assert [name for name, _plugin in selected] == ["services", "run"]

    defaults = resolve_plugin_names(None, discovered)
    assert "regtime" not in [name for name, _plugin in defaults]
    assert [name for name, _plugin in resolve_plugin_names(["regtime"], discovered)] == [
        "regtime"
    ]

    with pytest.raises(ValueError, match="Unknown plugin"):
        resolve_plugin_names(["missing"], discovered)


def test_hive_detection_prefers_parser_and_uses_safe_fallback() -> None:
    registry = MagicMock()
    registry.hive_type.return_value.value = "software"
    assert detect_hive_type(registry, Path("renamed.bin")) == "SOFTWARE"

    registry.hive_type.side_effect = ValueError("unknown")
    assert detect_hive_type(registry, Path("SYSTEM.LOG1")) == "UNKNOWN"
    assert detect_hive_type(registry, Path("sample.bin")) == "UNKNOWN"


@pytest.mark.parametrize(
    "name",
    ["SYSTEM.LOG", "SYSTEM.LOG1", "SYSTEM.log2", "user.dat.LoG1"],
)
def test_transaction_logs_are_recognized_case_insensitively(name) -> None:
    assert is_transaction_log(Path(name))


def test_clean_hive_ignores_stale_logs(tmp_path, monkeypatch) -> None:
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"clean evidence")
    (tmp_path / "SYSTEM.LOG1").write_bytes(b"invalid stale log")
    monkeypatch.setattr(
        "reg2es.models.Reg2es._primary_recovery_required", lambda _path: False
    )

    parser_path, recovery = _prepare_registry_hive(hive)

    assert parser_path == hive
    assert recovery is None
    assert hive.read_bytes() == b"clean evidence"


def test_dirty_hive_without_logs_fails_explicitly(tmp_path, monkeypatch) -> None:
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"dirty evidence")
    monkeypatch.setattr(
        "reg2es.models.Reg2es._primary_recovery_required", lambda _path: True
    )

    with pytest.raises(RegistryRecoveryError, match="dirty.*no .LOG1/.LOG2"):
        _prepare_registry_hive(hive)


def test_single_log_recovery_uses_temp_copy_and_preserves_source(
    tmp_path, monkeypatch
) -> None:
    hive = tmp_path / "SYSTEM"
    original = b"dirty evidence"
    hive.write_bytes(original)
    log1 = tmp_path / "SYSTEM.LOG1"
    log1.write_bytes(b"log one")

    monkeypatch.setattr(
        "reg2es.models.Reg2es._primary_recovery_required",
        lambda path: path == hive,
    )

    class FakeLog:
        def __init__(self, primary, log_path):
            self.primary = primary
            self.path = Path(log_path)

        def is_eligible_log(self):
            return True

        def recover_hive(self):
            self.primary.seek(0)
            self.primary.write(b"recovered")
            return 7

    monkeypatch.setattr("reg2es.models.Reg2es.RegistryLog.RegistryLog", FakeLog)

    recovered_path, recovery = _prepare_registry_hive(hive)
    try:
        assert recovery == {
            "applied": True,
            "method": "python-registry.RegistryLog",
            "logs": [str(log1.resolve())],
        }
        assert recovered_path != hive
        assert recovered_path.read_bytes().startswith(b"recovered")
        assert hive.read_bytes() == original
    finally:
        recovered_path.unlink(missing_ok=True)


def test_dual_log_recovery_uses_sequence_order_and_preserves_source(
    tmp_path, monkeypatch
) -> None:
    hive = tmp_path / "SYSTEM"
    original = b"dirty evidence"
    hive.write_bytes(original)
    log1 = tmp_path / "SYSTEM.LOG1"
    log2 = tmp_path / "SYSTEM.LOG2"
    log1.write_bytes(b"log one")
    log2.write_bytes(b"log two")
    calls = []

    monkeypatch.setattr(
        "reg2es.models.Reg2es._primary_recovery_required",
        lambda path: path == hive,
    )

    class FakeLog:
        def __init__(self, primary, log_path):
            self.primary = primary
            self.path = Path(log_path)
            self.sequence = 20 if self.path == log1 else 10

        def is_eligible_log(self):
            return True

        def is_starting_log(self, other):
            return self.sequence < other.sequence

        def recover_hive(self):
            calls.append(("start", self.path.name))
            self.primary.seek(0)
            self.primary.write(b"recovered")
            return self.sequence

        def reload_primary_regf(self):
            calls.append(("reload", self.path.name))

        def recover_hive_continue(self, expected_sequence):
            calls.append(("continue", self.path.name, expected_sequence))
            return self.sequence

    monkeypatch.setattr("reg2es.models.Reg2es.RegistryLog.RegistryLog", FakeLog)

    recovered_path, recovery = _prepare_registry_hive(hive)
    try:
        assert calls == [
            ("start", "SYSTEM.LOG2"),
            ("reload", "SYSTEM.LOG1"),
            ("continue", "SYSTEM.LOG1", 11),
        ]
        assert recovery == {
            "applied": True,
            "method": "python-registry.RegistryLog",
            "logs": [str(log2.resolve()), str(log1.resolve())],
        }
        assert recovered_path != hive
        assert recovered_path.read_bytes().startswith(b"recovered")
        assert hive.read_bytes() == original
    finally:
        recovered_path.unlink(missing_ok=True)


def test_unsupported_old_log_advises_external_recovery_and_cleans_temp(
    tmp_path, monkeypatch
) -> None:
    from Registry import RegistryParse

    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"dirty evidence")
    (tmp_path / "SYSTEM.LOG1").write_bytes(b"old log")
    monkeypatch.setattr(
        "reg2es.models.Reg2es._primary_recovery_required", lambda _path: True
    )

    real_named_temporary_file = __import__("tempfile").NamedTemporaryFile

    def temporary_in_test_dir(**kwargs):
        return real_named_temporary_file(dir=tmp_path, **kwargs)

    monkeypatch.setattr(
        "reg2es.models.Reg2es.tempfile.NamedTemporaryFile", temporary_in_test_dir
    )

    def reject_old_log(_primary, _log_path):
        raise RegistryParse.NotSupportedException("Old transaction log")

    monkeypatch.setattr(
        "reg2es.models.Reg2es.RegistryLog.RegistryLog", reject_old_log
    )

    with pytest.raises(RegistryRecoveryError, match=r"rla\.exe"):
        _prepare_registry_hive(hive)

    assert list(tmp_path.glob("reg2es-recovered-*.hive")) == []
    assert hive.read_bytes() == b"dirty evidence"


def test_dataset_excludes_logs_and_removes_recovered_temp(tmp_path, monkeypatch) -> None:
    hive = tmp_path / "SYSTEM"
    transaction_log = tmp_path / "SYSTEM.LOG1"
    recovered = tmp_path / "recovered.hive"
    hive.write_bytes(b"regf")
    for path in (transaction_log, recovered):
        path.write_bytes(b"data")
    registry = MagicMock()

    prepare = MagicMock(
        return_value=(recovered, {"applied": True, "logs": [str(transaction_log)]})
    )
    monkeypatch.setattr("reg2es.models.Reg2es._prepare_registry_hive", prepare)
    monkeypatch.setattr(
        "reg2es.models.Reg2es.Registry.Registry", lambda _path: registry
    )
    monkeypatch.setattr(
        "reg2es.models.Reg2es.detect_hive_type", lambda _reg, _path: "SYSTEM"
    )

    dataset = _build_hive_dataset([transaction_log, hive])
    assert prepare.call_args_list == [((hive,),)]
    assert dataset["SYSTEM"][0][0] == hive

    _close_parsers(dataset)
    assert not recovered.exists()
    assert hive.exists()
    assert transaction_log.exists()


def test_dataset_rejects_transaction_logs_without_primary(tmp_path) -> None:
    transaction_log = tmp_path / "SYSTEM.LOG1"
    transaction_log.write_bytes(b"log")

    with pytest.raises(RegistryRecoveryError, match="No primary registry hive"):
        _build_hive_dataset([transaction_log])


def test_recovery_metadata_is_added_to_documents() -> None:
    class ResultsPlugin(BasePlugin):
        __REGHIVE__ = "SYSTEM"

        def run(self):
            result = PluginResult()
            result.custom = {"ok": True}
            yield result

    recovery = {
        "applied": True,
        "method": "python-registry.RegistryLog",
        "logs": ["/host/SYSTEM.LOG1"],
    }
    runner = _runner("results", ResultsPlugin)
    dataset = {
        "SYSTEM": [
            (
                Path("/host/SYSTEM"),
                _fake_registry(_reg2es_recovery=recovery),
            )
        ]
    }
    with patch(
        "reg2es.models.Reg2es._build_hive_dataset",
        return_value=dataset,
    ):
        chunks = list(runner.gen_records())

    assert chunks[0][0]["log"]["file"]["path"] == str(
        Path("/host/SYSTEM").resolve()
    )
    assert chunks[0][0]["reg2es"]["recovery"] == recovery


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
    assert document["registry"]["hive"] == "HKLM"
    assert document["registry"]["key"] == "SYSTEM\\Control\\Test"
    assert document["registry"]["path"] == "HKLM\\SYSTEM\\Control\\Test"
    assert document["registry"]["value"] == "Payload"
    assert document["registry"]["data"] == {
        "type": result.value_type,
        "bytes": 2,
    }
    assert document["reg2es"]["value_data"] == "dead"
    assert document["reg2es"]["custom"]["nested"]["raw"] == "0001"
    payload = orjson.dumps(document)
    assert "端末一号".encode() in payload
    assert orjson.loads(payload)["reg2es"]["custom"]["label"] == "端末一号"
    assert document["log"]["file"]["path"] == str(Path("/host/SYSTEM").resolve())
    assert document["reg2es"]["source"] == {
        "hive": "SYSTEM",
        "key_path": "\\ROOT\\Control\\Test",
    }


def test_recentdocs_promotes_decoded_name_to_ecs_file_field() -> None:
    result = PluginResult()
    result.path = "ROOT\\Software\\Microsoft\\Windows\\RecentDocs"
    result.custom = {"docname": "report.pdf"}

    document = plugin_result_to_document(
        result,
        "recentdocs",
        "NTUSER.DAT",
        "/host/NTUSER.DAT",
    )

    assert document["file"] == {"name": "report.pdf"}


def test_ecs_document_omits_unknown_timestamp() -> None:
    result = PluginResult()
    result.path = "ROOT\\Software\\Example"

    document = plugin_result_to_document(
        result,
        "example",
        "NTUSER.DAT",
        "/host/NTUSER.DAT",
    )

    assert "@timestamp" not in document
    assert document["registry"] == {
        "hive": "HKCU",
        "key": "Software\\Example",
        "path": "HKCU\\Software\\Example",
    }


def test_missing_plugin_key_is_not_logged() -> None:
    reg = MagicMock()
    reg.open.side_effect = Registry.RegistryKeyNotFoundException("missing")
    plugin_logger = MagicMock()
    plugin = BasePlugin(reg, plugin_logger, "SYSTEM", "/host/SYSTEM")

    assert plugin.open_key("Control\\Missing") is None
    plugin_logger.assert_not_called()


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
        return {"SYSTEM": [(Path("/host/SYSTEM"), _fake_registry())]}

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
    dataset = {"SYSTEM": [(Path("/host/SYSTEM"), _fake_registry())]}
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
        software = _fake_registry(marker=marker)
        sam = _fake_registry(marker=marker)
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

    dataset = {"SYSTEM": [(Path("/host/SYSTEM"), _fake_registry())]}
    runner = _runner("results", ResultsPlugin, chunk_size=1)
    with patch(
        "reg2es.models.Reg2es._build_hive_dataset",
        return_value=dataset,
    ):
        records = runner.gen_records()
        next(records)
        records.close()

    assert dataset == {}
