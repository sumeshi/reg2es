# coding: utf-8
from itertools import chain
from pathlib import Path
from typing import List

import orjson
from tqdm import tqdm

from reg2es.models.Reg2es import Reg2es


class Reg2jsonPresenter(object):

    def __init__(
        self,
        input_path: str,
        output_path: str,
        is_quiet: bool = False,
    ):
        self.input_path = Path(input_path).resolve()
        self.output_path = output_path if output_path else Path(self.input_path).with_suffix('.json')
        self.is_quiet = is_quiet

    def reg2json(self) -> List[dict]:
        r = Reg2es(self.input_path)
        generator = r.gen_records() if self.is_quiet else tqdm(r.gen_records())

        buffer: List[dict] = list(generator)
        return buffer[0]

    def export_json(self):
        self.output_path.write_text(
            orjson.dumps(self.reg2json(), option=orjson.OPT_INDENT_2).decode("utf-8")
        )
