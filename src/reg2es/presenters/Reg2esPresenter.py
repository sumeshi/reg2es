# coding: utf-8
from pathlib import Path
from typing import Callable, Generator, List, Optional, Sequence

from tqdm import tqdm

from reg2es.models.Reg2es import Reg2es
from reg2es.models.ElasticsearchUtils import ElasticsearchUtils


class Reg2esPresenter:
    def __init__(
        self,
        input_paths: Sequence[Path] | Path,
        host: str = "localhost",
        port: int = 9200,
        index: str = "reg2es",
        scheme: str = "http",
        pipeline: str = "",
        login: str = "",
        pwd: str = "",
        is_quiet: bool = False,
        chunk_size: int = 500,
        plugin_names: Optional[List[str]] = None,
        additional_tags: Optional[List[str]] = None,
        verify_certs: bool = True,
        logger: Optional[Callable[[str, bool], None]] = None,
    ):
        self.input_paths = (
            [input_paths] if isinstance(input_paths, Path) else list(input_paths)
        )
        if not self.input_paths:
            raise ValueError("at least one registry path is required")
        self.host = host
        self.port = port
        self.index = index
        self.scheme = scheme
        self.pipeline = pipeline
        self.login = login
        self.pwd = pwd
        self.is_quiet = is_quiet
        self.chunk_size = chunk_size
        self.plugin_names = plugin_names
        self.additional_tags = additional_tags
        self.verify_certs = verify_certs
        self.logger = logger

    def reg2es(self) -> Generator[List[dict], None, None]:
        """Yield chunks of documents from all inputs / plugins.

        Follows the same pattern as Evtx2esPresenter.evtx2es().
        """
        r = Reg2es(
            input_paths=self.input_paths,
            plugin_names=self.plugin_names,
            chunk_size=self.chunk_size,
            additional_tags=self.additional_tags,
        )
        try:
            gen = r.gen_records()
            yield from gen if self.is_quiet else tqdm(gen)
        finally:
            r.close()

    def bulk_import(self) -> tuple[int, list]:
        es = ElasticsearchUtils(
            hostname=self.host,
            port=self.port,
            scheme=self.scheme,
            login=self.login,
            pwd=self.pwd,
            verify_certs=self.verify_certs,
        )

        total_success = 0
        total_failed: list = []
        batch_count = 0

        for records in self.reg2es():
            try:
                success, failed = es.bulk_indice(records, self.index, self.pipeline)
                total_success += success
                if failed:
                    total_failed.extend(failed)
                batch_count += 1
            except Exception:
                if self.logger:
                    self.logger("Error occurred during bulk indexing", self.is_quiet)
                raise

        if self.logger:
            self.logger(
                f"Bulk import completed: {batch_count} batches processed",
                self.is_quiet,
            )
            self.logger(
                f"Successfully indexed: {total_success} documents",
                self.is_quiet,
            )
            if total_failed:
                self.logger(
                    f"Failed to index: {len(total_failed)} documents",
                    self.is_quiet,
                )
                for failure in total_failed[:3]:
                    self.logger(f"Error: {failure}", self.is_quiet)

        if total_failed:
            raise RuntimeError(
                f"Elasticsearch failed to index {len(total_failed)} document(s)"
            )

        return total_success, total_failed
