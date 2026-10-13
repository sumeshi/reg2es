"""Focused contracts for bounded exports and safe output paths."""
import importlib
import json
from pathlib import Path
import sys

import pytest

from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter
from reg2es.models.Reg2es import plugin_result_to_document
from reg2es.plugins.base import PluginResult
from datetime import datetime, timezone


@pytest.mark.parametrize("output_format", ["jsonl", "ndjson"])
def test_cli_default_output_uses_line_format_suffix(tmp_path, monkeypatch, output_format):
    module = importlib.import_module("reg2es.views.Reg2jsonView")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf")
    captured = {}

    class Presenter:
        failed_records = 0
        errors = []
        successful_records = 0

        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export_json(self):
            pass

    monkeypatch.setattr(module, "Reg2jsonPresenter", Presenter)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["reg2json", str(source), "--format", output_format],
    )
    module.Reg2jsonView().run()
    assert Path(captured["output_path"]).name == "SYSTEM.jsonl"


@pytest.mark.parametrize("output_format", ["jsonl", "ndjson"])
@pytest.mark.parametrize("records", [[], [{"text": "端末\nnext"}, {"n": 2}]])
def test_jsonl_streams_chunks_without_list_api(tmp_path, monkeypatch, output_format, records):
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    state = []

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            try:
                for record in records:
                    yield [record]
            finally:
                state.append("generator closed")

        def close(self):
            state.append("parser closed")

    monkeypatch.setattr(module, "Reg2es", Runner)
    monkeypatch.chdir(tmp_path)
    presenter = Reg2jsonPresenter("SYSTEM", is_quiet=True, output_format=output_format)
    monkeypatch.setattr(presenter, "reg2json", lambda: pytest.fail("materialized records"))
    paths = presenter.export_json()
    assert paths == [tmp_path / "SYSTEM.jsonl"]
    payload = paths[0].read_bytes()
    assert payload == b"".join((json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for r in records)
    assert state == ["generator closed", "parser closed"]


@pytest.mark.parametrize("offset", [0, 9, -5])
def test_json_and_jsonl_preserve_the_same_generated_record_schema(
    tmp_path, monkeypatch, offset
):
    from datetime import timedelta

    result = PluginResult()
    result.mtime = 100
    original = datetime(2015, 10, 30, 7, 24, 57, 814133, tzinfo=timezone.utc).astimezone(
        timezone(timedelta(hours=offset))
    )
    result.custom = {"original_event_time": original}
    result.set_event_time(
        original,
        source="test.artifact_time",
        meaning="test_event",
        precision="microseconds",
        raw="raw-time",
    )
    record = plugin_result_to_document(
        result,
        "example",
        "SYSTEM",
        "/evidence/SYSTEM",
        ["registry", "host-01"],
    )

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield [record]

        def close(self):
            pass

    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    monkeypatch.setattr(module, "Reg2es", Runner)
    exported = {}
    for output_format in ("json", "jsonl"):
        output = tmp_path / f"records.{output_format}"
        presenter = Reg2jsonPresenter(
            "SYSTEM",
            output_path=str(output),
            is_quiet=True,
            output_format=output_format,
            additional_tags=["registry", "host-01"],
        )
        payload = presenter.export_json()[0].read_bytes()
        parsed = json.loads(payload)
        exported[output_format] = parsed[0] if output_format == "json" else parsed

    assert exported["json"] == exported["jsonl"] == record
    assert exported["json"]["event"] == {
        "provider": "registry",
        "module": "windows",
        "dataset": "windows.registry",
        "kind": "event",
        "category": ["registry"],
        "type": ["info"],
        "action": "example",
    }
    assert exported["json"]["tags"] == ["registry", "host-01"]
    assert exported["json"]["@timestamp"] == "2015-10-30T07:24:57.814133Z"
    assert exported["json"]["reg2es"]["custom"]["original_event_time"] == (
        original.isoformat().replace("+00:00", "Z")
    )
    assert exported["json"]["reg2es"]["timestamp"] == {
        "source": "test.artifact_time",
        "meaning": "test_event",
        "fallback_reason": None,
        "precision": "microseconds",
        "raw": "raw-time",
    }


@pytest.mark.parametrize("command", ["Reg2json", "Reg2es"])
def test_cli_tags_are_parsed_and_forwarded(monkeypatch, tmp_path, command):
    module = importlib.import_module(f"reg2es.views.{command}View")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf")
    captured = {}

    class Presenter:
        failed_records = 0
        errors = []
        successful_records = 0

        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export_json(self):
            pass

        def bulk_import(self):
            return 0, []

    attribute = "Reg2jsonPresenter" if command == "Reg2json" else "Reg2esPresenter"
    monkeypatch.setattr(module, attribute, Presenter)
    monkeypatch.setattr(
        sys,
        "argv",
        [command.lower(), str(source), "--tags", "registry, host-01,,case-42,host-01"],
    )
    getattr(module, command + "View")().run()

    assert captured["additional_tags"] == ["registry", "host-01", "case-42", "host-01"]

@pytest.mark.parametrize("command", ["Reg2es", "Reg2json"])
def test_cli_processes_valid_deduplicated_hive_and_reports_bad_inputs_even_quiet(
    tmp_path, monkeypatch, capsys, command
):
    module = importlib.import_module(f"reg2es.views.{command}View")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf valid")
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    missing = tmp_path / "missing"
    captured = {}

    class Presenter:
        successful_records = 1
        failed_records = 0
        errors = []

        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.errors = kwargs.get("input_diagnostics", [])
            self.failed_records = len(self.errors)

        def export_json(self):
            return []

        def bulk_import(self):
            return 1, []

    attribute = "Reg2jsonPresenter" if command == "Reg2json" else "Reg2esPresenter"
    monkeypatch.setattr(module, attribute, Presenter)
    monkeypatch.setattr(
        sys,
        "argv",
        [command.lower(), str(source), str(source), str(missing), str(empty), "--quiet"],
    )

    with pytest.raises(SystemExit) as exited:
        module.entry_point()

    assert exited.value.code == 1
    assert captured["input_paths"] == [source.resolve() if command == "Reg2es" else str(source.resolve())]
    captured_output = capsys.readouterr()
    assert "does not exist" in captured_output.err.lower()
    assert "not a registry hive" in captured_output.err.lower()
    assert "2 input failures; 0 extraction failures" in captured_output.err
    assert captured_output.out == ""

@pytest.mark.parametrize("command", ["Reg2es", "Reg2json"])
def test_cli_reports_output_or_es_failure_without_traceback(
    tmp_path, monkeypatch, capsys, command
):
    module = importlib.import_module(f"reg2es.views.{command}View")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf valid")

    class Presenter:
        def __init__(self, **kwargs):
            pass

        def export_json(self):
            raise OSError("cannot write output")

        def bulk_import(self):
            raise RuntimeError("Elasticsearch unavailable")

    attribute = "Reg2jsonPresenter" if command == "Reg2json" else "Reg2esPresenter"
    monkeypatch.setattr(module, attribute, Presenter)
    monkeypatch.setattr(sys, "argv", [command.lower(), str(source), "--quiet"])

    with pytest.raises(SystemExit) as exited:
        module.entry_point()

    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert ("cannot write output" if command == "Reg2json" else "Elasticsearch unavailable") in captured.err
    assert captured.out == ""

@pytest.mark.parametrize("command", ["Reg2es", "Reg2json"])
def test_cli_keeps_argparse_usage_errors_at_status_two(monkeypatch, capsys, command):
    module = importlib.import_module(f"reg2es.views.{command}View")
    monkeypatch.setattr(sys, "argv", [command.lower(), "--size", "0"])

    with pytest.raises(SystemExit) as exited:
        module.entry_point()

    assert exited.value.code == 2
    assert "must be greater than zero" in capsys.readouterr().err
