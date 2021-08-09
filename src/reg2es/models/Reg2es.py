# coding: utf-8
from itertools import chain
from pathlib import Path
from typing import List, Generator, Iterable, Optional
from itertools import islice

import orjson
import pyregf


def decode_data(data_type: int, data: bytes) -> str:
    enum = {
        0: lambda x: x.hex(),
        1: lambda x: x.decode('utf-16').rstrip('\u0000'),
        2: lambda x: x.decode('utf-16').rstrip('\u0000'),
        3: lambda x: x.hex(),
        4: lambda x: int.from_bytes(x, 'little'),
        5: lambda x: int.from_bytes(x, 'big'),
        6: lambda x: x.decode('utf-16').rstrip('\u0000'),
        7: lambda x: x.decode('utf-16').rstrip('\u0000').split(' '),
        8: lambda x: x.hex(),
        9: lambda x: x.hex(),
        10: lambda x: x.hex(),
        11: lambda x: int.from_bytes(x, 'little'),
    }

    try:
        result = enum[data_type](data)
    except Exception:
        if data:
            result = data.hex()
        else:
            result = None
    
    return result


def get_data_type_identifier(data_type: int) -> Optional[str]:
    enum = {
        0: 'REG_NONE',
        1: 'REG_SZ',
        2: 'REG_EXPAND_SZ',
        3: 'REG_BINARY',
        4: 'REG_DWORD',
        5: 'REG_DWORD_BIG_ENDIAN',
        6: 'REG_LINK',
        7: 'REG_MULTI_SZ',
        8: 'REG_RESOURCE_LIST',
        9: 'REG_FULL_RESOURCE_DESCRIPTOR',
        10: 'REG_RESOURCE_REQUIREMENTS_LIST',
        11: 'REG_QWORD',
    }
    return enum.get(data_type, None)


def get_all_hives(reg: pyregf.key) -> dict:

    subtree = dict()
    if reg.sub_keys:
        for r in reg.sub_keys:
            subtree[r.get_name().lstrip('.')] = {**{"meta": {"last_written_time": r.get_last_written_time().isoformat()}}, **get_all_hives(r)}
    
    values = {
            v.get_name().lstrip('.') if v.get_name() else "_": {
                "type": v.get_type(),
                "identifier": get_data_type_identifier(v.get_type()),
                "size": v.get_data_size(),
                "data": decode_data(v.get_type(), v.get_data()),
            } for v in reg.values
        }
    
    if subtree and values:
        return {**subtree, **values}
    elif subtree:
        return subtree
    elif values:
        return values
    else:
        return {}


class Reg2es(object):
    def __init__(self, input_path: Path) -> None:
        self.path = input_path
        self.reg_file = pyregf.file()
        self.reg_file.open_file_object(self.path.open('rb'))

    def gen_records(self) -> Generator:
        """Generates the formatted Registry records chunks.

        Yields:
            Generator: Yields dict.
        """
        root_key = self.reg_file.get_root_key()
        hives = {root_key.get_name(): get_all_hives(root_key)}

        yield hives
