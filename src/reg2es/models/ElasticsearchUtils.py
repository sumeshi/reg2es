# coding: utf-8
from hashlib import sha1
from typing import Iterable, Tuple

import orjson
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


class ElasticsearchUtils:
    def __init__(
        self, hostname: str, port: int, scheme: str, login: str, pwd: str,
        verify_certs: bool = True, ca_certs: str | None = None,
    ) -> None:
        kwargs = {
            "hosts": [f"{scheme}://{hostname}:{port}"],
            "verify_certs": verify_certs,
        }
        if login:
            kwargs["basic_auth"] = (login, pwd)
        if ca_certs is not None:
            kwargs["ca_certs"] = ca_certs
        self.es = Elasticsearch(**kwargs)

    def close(self) -> None:
        self.es.close()

    def calc_hash(self, record: dict) -> str:
        return sha1(orjson.dumps(record, option=orjson.OPT_SORT_KEYS)).hexdigest()

    def bulk_indice(
        self,
        records: Iterable[dict],
        index_name: str,
        pipeline: str = "",
    ) -> Tuple[int, list]:
        """Bulk index documents into Elasticsearch.

        Args:
            records: List of document dicts.
            index_name: Target index name.
            pipeline: Ingest pipeline name (empty string to skip).

        Returns:
            Tuple of (success_count, failed_list).
        """

        def actions():
            for record in records:
                event = {
                    "_id": self.calc_hash(record),
                    "_index": index_name,
                    "_source": record,
                }
                if pipeline:
                    event["pipeline"] = pipeline
                yield event

        try:
            success, failed = bulk(
                self.es, actions(), raise_on_error=False, stats_only=False
            )
            return (success, failed)
        except Exception as e:
            raise Exception(f"Bulk indexing error: {e}") from e
