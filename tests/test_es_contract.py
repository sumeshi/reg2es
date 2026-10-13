import importlib
from pathlib import Path
from unittest.mock import MagicMock
import pytest

@pytest.mark.parametrize("failure", ["partial", "transport"])
def test_bulk_failures_propagate_and_close(monkeypatch, failure):
    module = importlib.import_module("reg2es.presenters.Reg2esPresenter")
    presenter = module.Reg2esPresenter(Path("input"), is_quiet=True)
    state = []
    def chunks():
        try:
            yield [{"id": 1}]
            pytest.fail("continued after failed batch")
        finally:
            state.append("closed")
    monkeypatch.setattr(presenter, "reg2es", chunks)
    client = MagicMock()
    if failure == "partial":
        client.bulk_indice.return_value = (
            0,
            [{"index": {"_id": "bad-id", "status": 400,
                        "error": {"type": "mapper_parsing_exception",
                                  "reason": "field type conflict"}}}],
        )
    else:
        client.bulk_indice.side_effect = RuntimeError("transport failed")
    monkeypatch.setattr(module, "ElasticsearchUtils", lambda **kwargs: client)
    with pytest.raises(RuntimeError) as error:
        presenter.bulk_import()
    if failure == "partial":
        assert "bad-id" in str(error.value)
        assert "field type conflict" in str(error.value)
    client.close.assert_called_once()
    assert state == ["closed"]

def test_public_reg2es_raises_partial_error_and_preserves_es_failures(monkeypatch):
    import reg2es

    diagnostics = [{"hive_path": "bad.hive", "error": "ValueError: corrupt"}]

    class PartialPresenter:
        failed_records = 1
        successful_records = 2
        errors = diagnostics

        def __init__(self, **kwargs):
            pass

        def bulk_import(self):
            return 2, []

    monkeypatch.setattr("reg2es.presenters.Reg2esPresenter.Reg2esPresenter", PartialPresenter)
    with pytest.raises(reg2es.PartialExtractionError) as error:
        reg2es.reg2es("good.hive")
    assert error.value.records is None
    assert error.value.diagnostics == [{
        **diagnostics[0], "source_file": "bad.hive",
    }]
    assert str(error.value) == "Partial extraction: 1 failure(s); output is incomplete."

    class FailingPresenter(PartialPresenter):
        failed_records = 0

        def bulk_import(self):
            raise RuntimeError("Elasticsearch unavailable")

    monkeypatch.setattr("reg2es.presenters.Reg2esPresenter.Reg2esPresenter", FailingPresenter)
    with pytest.raises(RuntimeError, match="Elasticsearch unavailable"):
        reg2es.reg2es("good.hive")


def test_cli_passes_tls_options(tmp_path, monkeypatch):
    module = importlib.import_module("reg2es.views.Reg2esView")
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf" + b"\0" * 4096)
    client = MagicMock()
    client.return_value.bulk_import.return_value = (0, [])
    client.return_value.failed_records = 0
    monkeypatch.setattr(module, "Reg2esPresenter", client)
    monkeypatch.setattr("sys.argv", ["reg2es", str(source), "--ca-certs", "ca.pem", "--no-verify-certs"])
    module.Reg2esView().run()
    assert client.call_args.kwargs["ca_certs"] == "ca.pem"
    assert client.call_args.kwargs["verify_certs"] is False

def test_tls_options(monkeypatch):
    module = importlib.import_module("reg2es.models.ElasticsearchUtils")
    client = MagicMock()
    monkeypatch.setattr(module, "Elasticsearch", client)
    module.ElasticsearchUtils("localhost", 9200, "https", "user", "", ca_certs="ca.pem")
    assert client.call_args.kwargs["verify_certs"] is True
    assert client.call_args.kwargs["ca_certs"] == "ca.pem"
    assert client.call_args.kwargs["basic_auth"] == ("user", "")
