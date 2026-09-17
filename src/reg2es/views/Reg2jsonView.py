# coding: utf-8
from pathlib import Path
from typing import List, Optional

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter
from reg2es.models.Reg2es import is_transaction_log, looks_like_registry_hive


class Reg2jsonView(BaseView):
    def __init__(self):
        super().__init__()
        self.define_options()
        self.args = self.parser.parse_args()

    def define_options(self):
        self.parser.add_argument(
            "--format", choices=("json", "jsonl", "ndjson"), default="json",
            help=(
                "Output format (default: json). "
                "JSONL/NDJSON writes one record per line."
            ),
        )
        self.parser.add_argument(
            "reg_files",
            nargs="*",
            type=str,
            help="Input Windows NT Registry hives or directories containing them.",
        )
        self.parser.add_argument(
            "--output-file",
            "-o",
            type=str,
            default="",
            help=(
                "Output file path. With --split, this is the output "
                "directory. Defaults to <first_input>.json, or the current "
                "directory with --split."
            ),
        )
        self.parser.add_argument(
            "--split",
            action="store_true",
            help="Write one JSON or JSONL file per plugin that produced results.",
        )

    def __collect_input_files(self, reg_files: List[str]) -> List[Path]:
        """Collect all input paths, expanding directories."""
        paths: List[Path] = []
        for reg_file in reg_files:
            p = Path(reg_file)
            if p.is_dir():
                paths.extend(
                    f
                    for f in p.rglob("*")
                    if (
                        f.is_file()
                        and not is_transaction_log(f)
                        and looks_like_registry_hive(f)
                    )
                )
            elif p.is_file():
                if is_transaction_log(p):
                    self.log(
                        f"Warning: {reg_file} is a registry transaction log; "
                        "it will be applied automatically with its primary hive "
                        "and will not be processed separately.",
                        self.args.quiet,
                    )
                elif not looks_like_registry_hive(p):
                    self.log(
                        f"Warning: {reg_file} is not a registry hive; skipping.",
                        self.args.quiet,
                    )
                else:
                    paths.append(p)
            else:
                self.log(
                    f"Warning: {reg_file} does not exist; skipping.",
                    self.args.quiet,
                )
        return paths

    def run(self):
        if self.list_plugins():
            return
        if not self.args.reg_files:
            self.parser.error("At least one registry hive or directory is required.")

        input_files = self.__collect_input_files(self.args.reg_files)

        if not input_files:
            self.parser.error("No readable registry hives found.")

        self.log(f"Converting {len(input_files)} hive(s)...", self.args.quiet)

        plugins: Optional[List[str]] = getattr(self.args, "plugins", None)

        if self.args.split:
            output_file = self.args.output_file or Path.cwd()
        else:
            output_file = self.args.output_file or self.__default_output_path(
                self.args.reg_files,
                input_files,
                self.args.format,
            )

        Reg2jsonPresenter(
            input_paths=[str(p) for p in input_files],
            output_path=str(output_file),
            is_quiet=self.args.quiet,
            chunk_size=self.args.size,
            plugin_names=plugins,
            additional_tags=self.parse_tags(),
            split=self.args.split,
            output_format=self.args.format,
        ).export_json()

        self.log("Conversion completed successfully.", self.args.quiet)

    def __default_output_path(
        self, reg_files: List[str], input_files: List[Path], output_format: str = "json"
    ) -> Path:
        """Pick a safe default JSON path that never lands inside an input dir.

        Writing the export inside a scanned directory pollutes the inputs and
        gets re-ingested on the next run, so a single directory argument is
        named after that directory and written to the current directory.
        """
        suffix = ".json" if output_format == "json" else ".jsonl"
        if len(reg_files) == 1 and Path(reg_files[0]).is_dir():
            directory = Path(reg_files[0]).resolve()
            candidate = Path.cwd() / f"{directory.name}{suffix}"
            if candidate.resolve().parent == directory:
                return directory.parent / f"{directory.name}{suffix}"
            return candidate
        return Path.cwd() / f"{input_files[0].name}{suffix}"


def entry_point():
    Reg2jsonView().run()


if __name__ == "__main__":
    entry_point()
