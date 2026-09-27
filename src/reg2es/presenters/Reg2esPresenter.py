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
        ca_certs: str | None = None,
        logger: Optional[Callable[[str, bool], None]] = None,
    ):
        self.input_paths = (
            [input_paths] if isinstance(input_paths, Path) else list(input_paths)
        )
        if not self.input_paths:
            raise ValueError("At least one registry hive path is required.")
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
        self.ca_certs = ca_certs
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
            hostname=self.host, port=self.port, scheme=self.scheme,
            login=self.login, pwd=self.pwd, verify_certs=self.verify_certs,
            ca_certs=self.ca_certs,
        )
        chunks = None
        total_success = 0
        batch_count = 0
        try:
            chunks = self.reg2es()
            for records in chunks:
                success, failed = es.bulk_indice(records, self.index, self.pipeline)
                total_success += success
                batch_count += 1
                if failed:
                    details = []
                    for item in failed[:3]:
                        for operation, result in item.items():
                            if not isinstance(result, dict):
                                continue
                            error = result.get("error", {})
                            if not isinstance(error, dict):
                                error = {"reason": str(error)}
                            details.append(
                                f"{operation} id={result.get('_id', '?')} "
                                f"status={result.get('status', '?')} "
                                f"{error.get('type', 'error')}: "
                                f"{str(error.get('reason', 'unknown'))[:500]}"
                            )
                    raise RuntimeError(
                        f"Elasticsearch failed to index {len(failed)} document(s); "
                        f"{total_success} indexed before stopping. "
                        + "; ".join(details)
                    )
        finally:
            try:
                close = getattr(chunks, "close", None)
                if close is not None:
                    close()
            finally:
                es.close()
        if self.logger:
            self.logger(
                f"Bulk import completed: {batch_count} batches processed",
                self.is_quiet,
            )
            self.logger(f"Successfully indexed: {total_success} documents", self.is_quiet)
        return total_success, []
