# coding: utf-8
from pathlib import Path
from typing import List, Optional

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter
from reg2es.models.Reg2es import is_transaction_log


class Reg2jsonView(BaseView):
    def __init__(self):
        super().__init__()
        self.define_options()
        self.args = self.parser.parse_args()

    def define_options(self):
        self.parser.add_argument(
            "reg_files",
            nargs="*",
            type=str,
            help="Windows NT Registry files or directories containing them.",
        )
        self.parser.add_argument(
            "--output-file",
            "-o",
            type=str,
            default="",
            help="JSON file path to output. Defaults to <first_input>.json.",
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
                    if f.is_file() and not is_transaction_log(f)
                )
            elif p.is_file():
                if is_transaction_log(p):
                    self.log(
                        f"Warning: {reg_file} is a registry transaction log; "
                        "it will be auto-applied with its primary hive and is "
                        "not processed as a standalone hive.",
                        self.args.quiet,
                    )
                else:
                    paths.append(p)
            else:
                self.log(
                    f"Warning: {reg_file} does not exist, skipping.",
                    self.args.quiet,
                )
        return paths

    def run(self):
        if self.list_plugins():
            return
        if not self.args.reg_files:
            self.parser.error("at least one registry file or directory is required")

        input_files = self.__collect_input_files(self.args.reg_files)

        if not input_files:
            self.parser.error("no readable input files found")

        self.log(f"Converting {len(input_files)} file(s).", self.args.quiet)

        plugins: Optional[List[str]] = getattr(self.args, "plugins", None)

        Reg2jsonPresenter(
            input_paths=[str(p) for p in input_files],
            output_path=self.args.output_file,
            is_quiet=self.args.quiet,
            chunk_size=self.args.size,
            plugin_names=plugins,
            additional_tags=self.parse_tags(),
        ).export_json()

        self.log("Converted.", self.args.quiet)


def entry_point():
    Reg2jsonView().run()


if __name__ == "__main__":
    entry_point()
