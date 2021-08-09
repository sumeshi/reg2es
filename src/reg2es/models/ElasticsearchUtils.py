# coding: utf-8
from typing import List
from hashlib import sha1

from elasticsearch import Elasticsearch, exceptions, client
from elasticsearch.helpers import bulk

import orjson


class ElasticsearchUtils(object):
    def __init__(self, hostname: str, port: int, scheme: str, login: str, pwd: str) -> None:
        if login == "":
            self.es = Elasticsearch(host=hostname, port=port, scheme=scheme, verify_certs=False)
        else:
            self.es = Elasticsearch(host=hostname, port=port, scheme=scheme, verify_certs=False, http_auth=(login, pwd))

    def calc_hash(self, record: dict) -> str:
        """Calculate hash value from record.

        Args:
            record (dict): Registry record.

        Returns:
            str: Hash value
        """
        return sha1(orjson.dumps(record, option=orjson.OPT_SORT_KEYS)).hexdigest()

    def bulk_indice(self, records: List[dict], index_name: str, pipeline: str, fields_limit: int = 10000) -> None:
        """Bulk indices the documents into Elasticsearch.

        Args:
            records (List[dict]): List of each records read from Registry files.
            index_name (str): Target Elasticsearch Index.
            pipeline (str): Target Elasticsearch Ingest Pipeline
        """
        for record in [records]:
            try:
                self.es.index(index=index_name, id=self.calc_hash(record), body=record)
            except exceptions.RequestError:
                ic = client.IndicesClient(self.es)
                ic.put_settings({"index.mapping.total_fields.limit": fields_limit})
                self.es.index(index=index_name, id=self.calc_hash(record), body=record)

