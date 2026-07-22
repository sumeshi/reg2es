# coding: utf-8
from itertools import chain
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import orjson
from tqdm import tqdm

from reg2es.models.Reg2es import Reg2es


class Reg2jsonPresenter:
    def __init__(
        self,
        input_paths: Sequence[str | Path] | str | Path,
        output_path: str = "",
        is_quiet: bool = False,
        chunk_size: int = 500,
        plugin_names: Optional[List[str]] = None,
        additional_tags: Optional[List[str]] = None,
        split: bool = False,
    ):
        values = (
            [input_paths] if isinstance(input_paths, (str, Path)) else list(input_paths)
        )
        if not values:
            raise ValueError("at least one registry path is required")
        self.input_paths = [Path(path).resolve() for path in values]
        self.output_path = (
            Path(output_path).resolve()
            if output_path
            else (
                Path.cwd() if split else Path.cwd() / f"{self.input_paths[0].name}.json"
            )
        )
        self.is_quiet = is_quiet
        self.chunk_size = chunk_size
        self.plugin_names = plugin_names
        self.additional_tags = additional_tags
        self.split = split

    def reg2json(self) -> List[dict]:
        r = Reg2es(
            input_paths=self.input_paths,
            plugin_names=self.plugin_names,
            chunk_size=self.chunk_size,
            additional_tags=self.additional_tags,
        )
        try:
            generator = r.gen_records()
            buffer: List[dict] = list(
                chain.from_iterable(generator if self.is_quiet else tqdm(generator))
            )
            return buffer
        finally:
            r.close()

    def export_json(self) -> List[Path]:
        documents = self.reg2json()
        if not self.split:
            self._write_json(self.output_path, documents)
            return [self.output_path]

        output_directory = self.output_path
        output_directory.mkdir(parents=True, exist_ok=True)
        by_plugin: Dict[str, List[dict]] = {}
        for document in documents:
            plugin_name = document.get("reg2es", {}).get("plugin", {}).get("name")
            if isinstance(plugin_name, str) and plugin_name:
                by_plugin.setdefault(plugin_name, []).append(document)

        output_paths: List[Path] = []
        for plugin_name, plugin_documents in by_plugin.items():
            output_path = output_directory / f"{plugin_name}.json"
            self._write_json(output_path, plugin_documents)
            output_paths.append(output_path)
        return output_paths

    @staticmethod
    def _write_json(path: Path, documents: List[dict]) -> None:
        path.write_text(
            orjson.dumps(documents, option=orjson.OPT_INDENT_2).decode("utf-8"),
            encoding="utf-8",
        )
