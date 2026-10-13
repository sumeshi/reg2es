"""Chunk sizes are validated before any parsing or Elasticsearch work."""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from reg2es.models.Reg2es import Reg2es
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter

INVALID_SIZES = [0, -1, True, 1.5, "2", None]


@pytest.mark.parametrize("chunk_size", INVALID_SIZES)
def test_model_rejects_invalid_chunk_size(chunk_size):
    with pytest.raises(ValueError, match="chunk_size"):
        Reg2es([], chunk_size=chunk_size)


@pytest.mark.parametrize(
    ("presenter", "chunk_size"),
    [(Reg2esPresenter, 0), (Reg2jsonPresenter, 1.5)],
)
def test_presenter_rejects_invalid_chunk_size_before_side_effects(
    monkeypatch, tmp_path, presenter, chunk_size
):
    module_name = presenter.__module__
    if presenter is Reg2esPresenter:
        module = __import__(module_name, fromlist=["ElasticsearchUtils"])
        client_factory = MagicMock()
        monkeypatch.setattr(module, "ElasticsearchUtils", client_factory)
        with pytest.raises(ValueError, match="chunk_size"):
            presenter(
                [tmp_path / "SYSTEM"], chunk_size=chunk_size
            ).bulk_import()
        client_factory.assert_not_called()
    else:
        source = tmp_path / "SYSTEM"
        monkeypatch.setattr(
            Path,
            "resolve",
            lambda *args, **kwargs: pytest.fail(
                "resolved input before validation"
            ),
        )
        with pytest.raises(ValueError, match="chunk_size"):
            presenter(source, chunk_size=chunk_size)


@pytest.mark.parametrize("chunk_size", INVALID_SIZES)
@pytest.mark.parametrize("api", ["reg2es", "reg2json"])
def test_public_apis_validate_before_resolving_input_paths(
    monkeypatch, chunk_size, api
):
    import reg2es

    monkeypatch.setattr(
        reg2es,
        "_normalize_paths",
        lambda _paths: pytest.fail("resolved input before validation"),
    )
    with pytest.raises(ValueError, match="chunk_size"):
        getattr(reg2es, api)("SYSTEM", chunk_size=chunk_size)


def test_valid_chunk_size_is_accepted():
    assert Reg2es([], chunk_size=1).chunk_size == 1
