"""Focused contracts for bounded exports and safe output paths."""
import importlib
import json
from pathlib import Path
import sys

import pytest

from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter


@pytest.mark.parametrize("output_format", ["jsonl", "ndjson"])
def test_cli_default_output_uses_line_format_suffix(tmp_path, monkeypatch, output_format):
    module = importlib.import_module("reg2es.views.Reg2jsonView")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf")
    captured = {}

    class Presenter:
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
