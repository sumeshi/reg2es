# coding: utf-8
from contextlib import closing, ExitStack
from itertools import chain
import os
from pathlib import Path
import stat
import tempfile
from typing import Dict, List, Optional, Sequence

import orjson
from tqdm import tqdm

from reg2es.models.Reg2es import (
    PartialExtractionError,
    Reg2es,
    discover_plugins,
    resolve_plugin_names,
    validate_chunk_size,
)


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
        output_format: str = "json",
        protected_input_paths: Sequence[str | Path] = (),
        input_diagnostics: Sequence[dict] = (),
    ):
        validate_chunk_size(chunk_size)
        values = (
            [input_paths] if isinstance(input_paths, (str, Path)) else list(input_paths)
        )
        if not values:
            raise ValueError("At least one registry hive path is required.")
        if output_format not in ("json", "jsonl", "ndjson"):
            raise ValueError(f"Invalid output format: {output_format}")
        self.output_format = output_format
        suffix = ".json" if output_format == "json" else ".jsonl"
        self.input_paths = [Path(path).resolve() for path in values]
        self.protected_input_paths = [
            Path(path).resolve() for path in protected_input_paths
        ]
        self.input_diagnostics = list(input_diagnostics)
        self.output_path = (
            Path(output_path)
            if output_path
            else (
                Path.cwd() if split else Path.cwd() / f"{self.input_paths[0].name}{suffix}"
            )
        )
        self.is_quiet = is_quiet
        self.chunk_size = chunk_size
        self.plugin_names = plugin_names
        self.additional_tags = additional_tags
        self.split = split
        self.successful_records = 0
        self.failed_records = 0
        self.errors = []

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
            self._capture_result(r)
            r.close()

    def export_json(self) -> List[Path]:
        candidates = (
            [
                self._plugin_path(name)
                for name, _ in resolve_plugin_names(
                    self.plugin_names, discover_plugins()
                )
            ]
            if self.split
            else [self.output_path]
        )
        for path in candidates:
            self._check_output_path(path)
        if self.split:
            self.output_path.mkdir(parents=True, exist_ok=True)
        staged: Dict[Path, Path] = {}
        try:
            if self.output_format != "json":
                self._export_jsonl(staged)
            else:
                documents = self.reg2json()
                if not self.split:
                    self._write_json(self.output_path, documents, staged)
                else:
                    by_plugin: Dict[str, List[dict]] = {}
                    for document in documents:
                        name = (
                            document.get("reg2es", {})
                            .get("plugin", {})
                            .get("name")
                        )
                        if isinstance(name, str) and name:
                            by_plugin.setdefault(name, []).append(document)
                    for name, plugin_documents in by_plugin.items():
                        self._write_json(
                            self._plugin_path(name), plugin_documents, staged
                        )
            # Validate the entire set before publishing any file.
            for path in staged:
                self._check_output_path(path)
            if self.failed_records and self.successful_records == 0:
                raise PartialExtractionError(self.errors)
            for path, temporary in staged.items():
                if os.name == "posix" and path.exists():
                    temporary.chmod(stat.S_IMODE(path.stat().st_mode))
                temporary.replace(path)
            return list(staged)
        finally:
            for temporary in staged.values():
                temporary.unlink(missing_ok=True)

    def _export_jsonl(self, staged: Dict[Path, Path]) -> None:
        runner = Reg2es(
            input_paths=self.input_paths,
            plugin_names=self.plugin_names,
            chunk_size=self.chunk_size,
            additional_tags=self.additional_tags,
        )
        try:
            with closing(runner.gen_records()) as chunks, ExitStack() as stack:
                progress = chunks if self.is_quiet else stack.enter_context(tqdm(chunks))
                if not self.split:
                    temporary = self._stage_path(self.output_path, staged)
                    output = stack.enter_context(temporary.open("wb"))
                    for chunk in progress:
                        for record in chunk:
                            output.write(orjson.dumps(record) + b"\n")
                    return
                for chunk in progress:
                    for record in chunk:
                        name = (
                            record.get("reg2es", {})
                            .get("plugin", {})
                            .get("name")
                        )
                        if not isinstance(name, str) or not name:
                            continue
                        path = self._plugin_path(name)
                        temporary = self._stage_path(path, staged)
                        # Only one file handle is open, even for many plugins.
                        with temporary.open("ab") as output:
                            output.write(orjson.dumps(record) + b"\n")
        finally:
            self._capture_result(runner)
            runner.close()

    def _capture_result(self, runner: Reg2es) -> None:
        self.successful_records = getattr(runner, "successful_records", 0)
        self.errors = [*self.input_diagnostics, *getattr(runner, "errors", [])]
        self.failed_records = len(self.errors)

    def _plugin_path(self, name: str) -> Path:
        if not name.isidentifier():
            raise ValueError("Invalid plugin output name")
        suffix = ".json" if self.output_format == "json" else ".jsonl"
        return self.output_path / f"{name}{suffix}"

    def _stage_path(self, path: Path, staged: Dict[Path, Path]) -> Path:
        self._check_output_path(path)
        if path not in staged:
            with tempfile.NamedTemporaryFile(
                dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False
            ) as temporary:
                staged[path] = Path(temporary.name)
        return staged[path]

    def _check_output_path(self, path: Path) -> None:
        output_path = path.resolve()
        for source in [*self.input_paths, *self.protected_input_paths]:
            if output_path == source or (
                path.exists() and source.exists() and path.samefile(source)
            ):
                raise ValueError(
                    "Input and output must be different files; "
                    "they must not refer to the same file."
                )
            if source.is_dir() and output_path.is_relative_to(source):
                raise ValueError("Output files must not be written inside an input directory.")
        if path.is_symlink():
            raise ValueError("The output path must not be a symbolic link.")
        if path.exists() and not path.is_file():
            raise ValueError("The output path must be a regular file.")

    def _write_json(
        self, path: Path, documents: List[dict], staged: Dict[Path, Path]
    ) -> None:
        self._stage_path(path, staged).write_text(
            orjson.dumps(documents, option=orjson.OPT_INDENT_2).decode("utf-8"),
            encoding="utf-8",
        )
