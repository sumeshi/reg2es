# coding: utf-8
from hashlib import sha1
from typing import List, Tuple

import orjson
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


class ElasticsearchUtils:
    def __init__(
        self,
        hostname: str,
        port: int,
        scheme: str,
        login: str,
        pwd: str,
        verify_certs: bool = True,
    ) -> None:
        kwargs = {
            "hosts": [f"{scheme}://{hostname}:{port}"],
            "verify_certs": verify_certs,
        }
        if login:
            kwargs["basic_auth"] = (login, pwd)
        self.es = Elasticsearch(**kwargs)

    def calc_hash(self, record: dict) -> str:
        return sha1(orjson.dumps(record, option=orjson.OPT_SORT_KEYS)).hexdigest()

    def bulk_indice(
        self,
        records: List[dict],
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
        events = []
        for record in records:
            event = {
                "_id": self.calc_hash(record),
                "_index": index_name,
                "_source": record,
            }
            if pipeline:
                event["pipeline"] = pipeline
            events.append(event)

        try:
            success, failed = bulk(
                self.es, events, raise_on_error=False, stats_only=False
            )
            return (success, failed)
        except Exception as e:
            raise Exception(f"Bulk indexing error: {e}") from e
