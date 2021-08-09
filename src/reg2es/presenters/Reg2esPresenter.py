# coding: utf-8
import traceback
from typing import List
from pathlib import Path

import orjson
from tqdm import tqdm

from reg2es.models.Reg2es import Reg2es
from reg2es.models.ElasticsearchUtils import ElasticsearchUtils


class Reg2esPresenter(object):

    def __init__(
        self,
        input_path: Path,
        host: str = "localhost",
        port: int = 9200,
        index: str = "reg2es",
        scheme: str = "http",
        pipeline: str = "",
        login: str = "",
        pwd: str = "",
        is_quiet: bool = False,
        fields_limit: int = 10000,
    ):
        self.input_path = input_path
        self.host = host
        self.port = port
        self.index = index
        self.scheme = scheme
        self.pipeline = pipeline
        self.login = login
        self.pwd = pwd
        self.is_quiet = is_quiet
        self.fields_limit = fields_limit

    def reg2es(self) -> List[dict]:
        r = Reg2es(self.input_path)
        generator = r.gen_records() if self.is_quiet else tqdm(r.gen_records())

        buffer: List[dict] = generator
        return buffer

    def bulk_import(self):
        es = ElasticsearchUtils(
            hostname=self.host,
            port=self.port,
            scheme=self.scheme,
            login=self.login,
            pwd=self.pwd
        )

        for records in self.reg2es():
            try:
                es.bulk_indice(records, self.index, self.pipeline, self.fields_limit)
            except Exception:
                traceback.print_exc()
