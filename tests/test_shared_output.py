"""Shared output validation and CLI contract."""
import importlib
import os
import pytest
from reg2es.models.Reg2es import collect_registry_hives
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


@pytest.mark.parametrize("output_format", ["json", "jsonl", "ndjson"])
@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_split_output_preserves_every_input(tmp_path, monkeypatch, output_format, alias):
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    output = tmp_path / "out"
    output.mkdir()
    suffix = ".json" if output_format == "json" else ".jsonl"
    destination = output / f"services{suffix}"
    first_input = tmp_path / "SYSTEM"
    first_input.write_bytes(b"first evidence")
    source = destination if alias == "same" else tmp_path / "second hive"
    source.write_bytes(b"second evidence")
    if alias == "symlink":
        destination.symlink_to(source)
    elif alias == "hardlink":
        destination.hardlink_to(source)
    earlier_output = output / f"compname{suffix}"
    earlier_output.write_bytes(b"previous export")

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield [
                {"reg2es": {"plugin": {"name": "compname"}}},
                {"reg2es": {"plugin": {"name": "services"}}},
            ]

        def close(self):
            pass

    monkeypatch.setattr(module, "Reg2es", Runner)
    presenter = Reg2jsonPresenter(
        [first_input, source], str(output), split=True, output_format=output_format,
        is_quiet=True,
    )
    with pytest.raises(ValueError, match="different files"):
        presenter.export_json()
    assert first_input.read_bytes() == b"first evidence"
    assert source.read_bytes() == b"second evidence"
    assert earlier_output.read_bytes() == b"previous export"
    assert not list(output.glob(".*.tmp"))


@pytest.mark.parametrize("output_format", ["json", "jsonl", "ndjson"])
@pytest.mark.parametrize("split", [False, True])
def test_failed_extraction_keeps_existing_output(tmp_path, monkeypatch, output_format, split):
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    suffix = ".json" if output_format == "json" else ".jsonl"
    destination = tmp_path / f"services{suffix}"
    destination.write_bytes(b"previous export")

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield [{"reg2es": {"plugin": {"name": "services"}}}]
            raise ValueError("fatal extraction error")

        def close(self):
            pass

    monkeypatch.setattr(module, "Reg2es", Runner)
    presenter = Reg2jsonPresenter(
        tmp_path / "SYSTEM", str(tmp_path if split else destination),
        split=split, output_format=output_format, is_quiet=True,
    )
    with pytest.raises(ValueError, match="fatal extraction error"):
        presenter.export_json()
    assert destination.read_bytes() == b"previous export"
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("output_format", ["json", "jsonl", "ndjson"])
def test_later_directory_destination_preserves_all_exports(tmp_path, output_format):
    suffix = ".json" if output_format == "json" else ".jsonl"
    earlier = tmp_path / f"compname{suffix}"
    earlier.write_bytes(b"previous export")
    (tmp_path / f"services{suffix}").mkdir()
    presenter = Reg2jsonPresenter(
        tmp_path / "SYSTEM", str(tmp_path), split=True, output_format=output_format,
    )
    with pytest.raises(ValueError, match="regular file"):
        presenter.export_json()
    assert earlier.read_bytes() == b"previous export"
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX file permissions")
@pytest.mark.parametrize("output_format", ["json", "jsonl"])
@pytest.mark.parametrize("split", [False, True])
def test_export_preserves_existing_mode(
    tmp_path, monkeypatch, output_format, split
):
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    suffix = ".json" if output_format == "json" else ".jsonl"
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    destination = output_dir / f"services{suffix}"
    destination.write_bytes(b"previous export")
    destination.chmod(0o664)

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield [{"reg2es": {"plugin": {"name": "services"}}}]

        def close(self):
            pass

    monkeypatch.setattr(module, "Reg2es", Runner)
    presenter = Reg2jsonPresenter(
        tmp_path / "SYSTEM",
        str(output_dir if split else destination),
        split=split,
        output_format=output_format,
        is_quiet=True,
    )
    presenter.export_json()

    assert destination.exists()
    assert destination.stat().st_mode & 0o777 == 0o664
    assert destination.read_bytes() != b"previous export"


def test_split_cli_guards_all_discovered_inputs(tmp_path, monkeypatch):
    from reg2es.views.Reg2jsonView import entry_point

    directory = tmp_path / "inputs"
    directory.mkdir()
    source = directory / "services.json"
    source.write_bytes(b"regf synthetic hive")
    earlier = directory / "compname.json"
    earlier.write_bytes(b"previous export")
    monkeypatch.setattr("sys.argv", [
        "reg2json", str(directory), "--split", "-o", str(directory),
    ])
    with pytest.raises(SystemExit) as exited:
        entry_point()
    assert exited.value.code == 1
    assert source.read_bytes() == b"regf synthetic hive"
    assert earlier.read_bytes() == b"previous export"


def test_split_export_rejects_unreadable_input_directory(tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf synthetic hive")
    hidden = tmp_path / "locked"
    hidden.mkdir()
    destination = hidden / "services.json"
    destination.write_bytes(b"existing evidence")
    hidden_hive = hidden / "SYSTEM"
    hidden_hive.write_bytes(b"regf synthetic hive")
    hidden.chmod(0o300)

    try:
        if os.access(hidden, os.R_OK):
            pytest.skip("filesystem permissions are bypassed")

        for source, expected in [(tmp_path, hive), (hidden_hive, hidden_hive)]:
            input_files, errors, _, protected = collect_registry_hives([source])
            assert input_files == [expected.resolve()]
            protected_directory = source.parent if source == hidden_hive else source
            assert protected_directory.resolve() in protected
            assert any(error["source_file"] == str(hidden.resolve()) for error in errors)

            presenter = Reg2jsonPresenter(
                input_files,
                str(hidden),
                split=True,
                protected_input_paths=protected,
            )
            with pytest.raises(ValueError, match="inside an input directory"):
                presenter.export_json()
            assert destination.read_bytes() == b"existing evidence"
    finally:
        hidden.chmod(0o700)


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
@pytest.mark.parametrize(
    ("input_kind", "split"),
    [("nonhive", False), ("transaction-log", True)],
)
def test_cli_output_guard_protects_rejected_inputs(
    tmp_path, monkeypatch, capsys, output_format, input_kind, split
):
    from reg2es.views.Reg2jsonView import entry_point

    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf synthetic hive")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    suffix = ".json" if output_format == "json" else ".jsonl"

    if input_kind == "nonhive":
        protected = tmp_path / "invalid.dat"
        protected.write_bytes(b"non-hive sentinel")
        output = protected
        args = [str(hive), str(protected)]
    else:
        protected = tmp_path / "SYSTEM.LOG1"
        protected.write_bytes(b"transaction-log sentinel")
        output = output_dir / f"services{suffix}"
        output.hardlink_to(protected)
        args = [str(hive), str(protected)]

    output_argument = output_dir if split else output
    argv = [
        "reg2json", *args, "--format", output_format, "-o", str(output_argument)
    ]
    if split:
        argv.append("--split")
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exited:
        entry_point()

    assert exited.value.code == 1
    assert protected.read_bytes() in (
        b"non-hive sentinel",
        b"transaction-log sentinel",
    )
    assert "Input and output must be different files" in capsys.readouterr().err
    if input_kind == "transaction-log":
        assert output.samefile(protected)

@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_cli_zero_record_partial_keeps_existing_output(
    tmp_path, monkeypatch, capsys, output_format
):
    module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf synthetic hive")
    suffix = ".json" if output_format == "json" else ".jsonl"
    output = tmp_path / f"existing{suffix}"
    output.write_bytes(b"previous output")

    class Runner:
        successful_records = 0
        failed_records = 1
        errors = [{
            "hive_path": str(source.resolve()),
            "error": "ValueError: corrupt hive",
        }]

        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield from ()

        def close(self):
            pass

    monkeypatch.setattr(module, "Reg2es", Runner)
    monkeypatch.setattr(
        "sys.argv",
        ["reg2json", str(source), "-o", str(output), "--format", output_format, "--quiet"],
    )

    with pytest.raises(SystemExit) as exited:
        from reg2es.views.Reg2jsonView import entry_point

        entry_point()

    assert exited.value.code == 1
    assert output.read_bytes() == b"previous output"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(source.resolve()) in captured.err
    assert "corrupt hive" in captured.err
    assert "Partial extraction:" in captured.err

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
