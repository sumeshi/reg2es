# coding: utf-8
from pathlib import Path
from typing import List, Optional

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter
from reg2es.models.Reg2es import is_transaction_log, looks_like_registry_hive


class Reg2esView(BaseView):
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
            "--host", default="localhost", help="Elasticsearch host"
        )
        self.parser.add_argument(
            "--port", default=9200, type=int, help="Elasticsearch port number"
        )
        self.parser.add_argument("--index", default="reg2es", help="Index name")
        self.parser.add_argument(
            "--scheme", default="http", help="Scheme to use (http, https)"
        )
        self.parser.add_argument(
            "--pipeline", default="", help="Ingest pipeline to use"
        )
        self.parser.add_argument(
            "--login", default="", help="Login for Elasticsearch authentication"
        )
        self.parser.add_argument(
            "--pwd", default="", help="Password for Elasticsearch authentication"
        )
        self.parser.add_argument(
            "--no-verify-certs",
            action="store_true",
            help="Disable TLS certificate verification for Elasticsearch.",
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
                        "it will be auto-applied with its primary hive and is "
                        "not processed as a standalone hive.",
                        self.args.quiet,
                    )
                elif not looks_like_registry_hive(p):
                    self.log(
                        f"Warning: {reg_file} is not a registry hive, skipping.",
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

        self.log(
            f"Processing {len(input_files)} file(s) as 1 dataset.", self.args.quiet
        )

        verify_certs = not getattr(self.args, "no_verify_certs", False)
        plugins: Optional[List[str]] = getattr(self.args, "plugins", None)

        Reg2esPresenter(
            input_paths=input_files,
            host=self.args.host,
            port=self.args.port,
            index=self.args.index,
            scheme=self.args.scheme,
            pipeline=self.args.pipeline,
            login=self.args.login,
            pwd=self.args.pwd,
            is_quiet=self.args.quiet,
            chunk_size=self.args.size,
            plugin_names=plugins,
            additional_tags=self.parse_tags(),
            verify_certs=verify_certs,
            logger=self.log,
        ).bulk_import()

        self.log("Import completed.", self.args.quiet)


def entry_point():
    Reg2esView().run()


if __name__ == "__main__":
    entry_point()
