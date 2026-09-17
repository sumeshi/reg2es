"""Shared output validation and CLI contract."""
import importlib
import pytest
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter

@pytest.mark.parametrize("output_format", ["json", "jsonl", "ndjson"])
@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_output_preserves_input(tmp_path, output_format, alias):
    source = tmp_path / "input"
    source.write_bytes(b"evidence")
    destination = source
    if alias != "same":
        destination = tmp_path / "alias"
        if alias == "symlink":
            destination.symlink_to(source)
        else:
            destination.hardlink_to(source)
    with pytest.raises(ValueError):
        Reg2jsonPresenter(source, str(destination), output_format=output_format).export_json()
    assert source.read_bytes() == b"evidence"

@pytest.mark.parametrize("output_format", ["jsonl", "ndjson"])
def test_split_jsonl(tmp_path, monkeypatch, output_format):
    import json
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    documents = [
        {"id": 1, "reg2es": {"plugin": {"name": "services"}}},
        {"id": 2, "reg2es": {"plugin": {"name": "compname"}}},
        {"id": 3, "reg2es": {"plugin": {"name": "services"}}},
    ]
    class Runner:
        def __init__(self, **kwargs):
            pass
        def gen_records(self):
            for document in documents:
                yield [document]
        def close(self):
            pass
    monkeypatch.setattr(module, "Reg2es", Runner)
    presenter = Reg2jsonPresenter(tmp_path / "input", str(tmp_path / "out"),
                                  split=True, output_format=output_format)
    paths = presenter.export_json()
    assert [p.name for p in paths] == ["services.jsonl", "compname.jsonl"]
    assert [json.loads(line)["id"] for line in paths[0].read_bytes().splitlines()] == [1, 3]



@pytest.mark.parametrize("command", ["Reg2json", "Reg2es"])
@pytest.mark.parametrize("size", ["0", "-1"])
def test_cli_rejects_nonpositive_size(monkeypatch, command, size):
    module = importlib.import_module(f"reg2es.views.{command}View")
    monkeypatch.setattr("sys.argv", [command.lower(), "input", "--size", size])
    with pytest.raises(SystemExit) as exited:
        getattr(module, command + "View")()
    assert exited.value.code == 2

def test_invalid_format_rejected(tmp_path):
    with pytest.raises(ValueError):
        Reg2jsonPresenter(tmp_path / "input", "", output_format="csv")

@pytest.mark.parametrize("output_format", ["jsonl", "ndjson"])
def test_cli_accepts_format(monkeypatch, output_format):
    module = importlib.import_module("reg2es.views.Reg2jsonView")
    monkeypatch.setattr("sys.argv", ["reg2json", "input", "--format", output_format])
    view = module.Reg2jsonView()
    assert view.args.format == output_format
