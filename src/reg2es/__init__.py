# coding: utf-8
from typing import List
from pathlib import Path

from reg2es.models.Reg2es import Reg2es
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter


# for use via python-script!

def reg2es(
    input_path: str,
    host: str = "localhost",
    port: int = 9200,
    index: str = "reg2es",
    scheme: str = "http",
    pipeline: str = "",
    login: str = "",
    pwd: str = "",
    multiprocess: bool = False,
    chunk_size: int = 500
) -> None:
    """Fast import of Windows NT Registry(REGF) into Elasticsearch.
    Args:
        input_path (str):
            Windows NT Registries to import into Elasticsearch.

        host (str, optional):
            Elasticsearch host address. Defaults to "localhost".

        port (int, optional):
            Elasticsearch port number. Defaults to 9200.

        index (str, optional):
            Name of the index to create. Defaults to "reg2es".

        scheme (str, optional):
            Elasticsearch address scheme. Defaults to "http".

        pipeline (str, optional):
            Elasticsearch Ingest Pipeline. Defaults to "".

        login (str, optional):
            Elasticsearch login to connect into.

        pwd (str, optional):
            Elasticsearch password associated with the login provided.

        multiprocess (bool, optional):
            Flag to run multiprocessing.

        chunk_size (int, optional):
            Size of the chunk to be processed for each process.
    """

    mp = Reg2esPresenter(
        input_path=Path(input_path),
        host=host,
        port=int(port),
        index=index,
        scheme=scheme,
        pipeline=pipeline,
        login=login,
        pwd=pwd,
        is_quiet=True,
        multiprocess=multiprocess,
        chunk_size=int(chunk_size),
    ).bulk_import()


def reg2json(filepath: str, multiprocess: bool = False, chunk_size: int = 500) -> List[dict]:
    """Convert Windows NT Registry to List[dict].

    Args:
        filepath (str): Input Registry file.
        multiprocess (bool): Flag to run multiprocessing.
        chunk_size (int): Size of the chunk to be processed for each process.

    Note:
        Since the content of the file is loaded into memory at once,
        it requires the same amount of memory as the file to be loaded.
    """
    reg = Reg2es(Path(filepath).resolve())
    records: List[dict] = sum(list(reg.gen_records(multiprocess=multiprocess, chunk_size=chunk_size)), list())

    return records
