# coding: utf-8
from itertools import chain
from pathlib import Path
from typing import List, Optional, Sequence

from reg2es.models.Reg2es import Reg2es

PathInput = str | Path | Sequence[str | Path]


def _normalize_paths(input_paths: PathInput) -> List[Path]:
    """Normalize a single path or path sequence without iterating strings."""
    if isinstance(input_paths, (str, Path)):
        values = [input_paths]
    else:
        values = list(input_paths)
    if not values:
        raise ValueError("At least one registry hive path is required.")
    return [Path(value).resolve() for value in values]


def reg2es(
    input_paths: PathInput,
    host: str = "localhost",
    port: int = 9200,
    index: str = "reg2es",
    scheme: str = "http",
    pipeline: str = "",
    login: str = "",
    pwd: str = "",
    chunk_size: int = 500,
    plugin_names: Optional[List[str]] = None,
    additional_tags: Optional[List[str]] = None,
    verify_certs: bool = True,
) -> None:
    """Fast import of Windows NT Registry(REGF) into Elasticsearch.

    Args:
        input_paths: Paths to registry hive files.
        host: Elasticsearch host address.
        port: Elasticsearch port number.
        index: Name of the index to create.
        scheme: Elasticsearch address scheme.
        pipeline: Elasticsearch Ingest Pipeline.
        login: Elasticsearch login.
        pwd: Elasticsearch password.
        chunk_size: Number of documents per bulk request.
        plugin_names: Plugin names to run (None for the default-enabled set).
        additional_tags: Extra tags for each record.
        verify_certs: Whether to verify TLS certificates.
    """
    from reg2es.presenters.Reg2esPresenter import Reg2esPresenter

    paths = _normalize_paths(input_paths)

    Reg2esPresenter(
        input_paths=paths,
        host=host,
        port=int(port),
        index=index,
        scheme=scheme,
        pipeline=pipeline,
        login=login,
        pwd=pwd,
        is_quiet=True,
        chunk_size=chunk_size,
        plugin_names=plugin_names,
        additional_tags=additional_tags,
        verify_certs=verify_certs,
    ).bulk_import()


def reg2json(
    input_paths: PathInput,
    chunk_size: int = 500,
    plugin_names: Optional[List[str]] = None,
    additional_tags: Optional[List[str]] = None,
) -> List[dict]:
    """Convert Windows NT Registry to list of ECS-formatted dicts.

    Args:
        input_paths: Input registry hive files.
        chunk_size: Internal chunk size for processing.
        plugin_names: Plugin names to run (None for the default-enabled set).
        additional_tags: Extra tags for each record.

    Returns:
        List of registry records in ECS format.
    """
    paths = _normalize_paths(input_paths)

    r = Reg2es(
        input_paths=paths,
        plugin_names=plugin_names,
        chunk_size=chunk_size,
        additional_tags=additional_tags,
    )
    try:
        records: List[dict] = list(chain.from_iterable(r.gen_records()))
    finally:
        r.close()

    return records
