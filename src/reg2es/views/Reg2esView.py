# coding: utf-8
from typing import List, Optional
import sys

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter
from reg2es.models.Reg2es import collect_registry_hives


class Reg2esView(BaseView):
    def __init__(self):
        super().__init__()
        self.define_options()
        self.args = self.parser.parse_args()

    def define_options(self):
        self.parser.add_argument(
            "--ca-certs",
            default=None,
            help="Path to a CA certificate bundle for TLS verification.",
        )
        self.parser.add_argument(
            "reg_files",
            nargs="*",
            type=str,
            help="Input Windows NT Registry hives or directories containing them.",
        )
        self.parser.add_argument(
            "--host", default="localhost", help="Elasticsearch host."
        )
        self.parser.add_argument(
            "--port", default=9200, type=int, help="Elasticsearch port."
        )
        self.parser.add_argument(
            "--index", default="reg2es", help="Elasticsearch index name."
        )
        self.parser.add_argument(
            "--scheme", default="http", help="Connection scheme (http or https)."
        )
        self.parser.add_argument(
            "--pipeline", default="", help="Elasticsearch ingest pipeline to use."
        )
        self.parser.add_argument(
            "--login",
            default="",
            help="Username for Elasticsearch authentication.",
        )
        self.parser.add_argument(
            "--pwd",
            default="",
            help="Password for Elasticsearch authentication.",
        )
        self.parser.add_argument(
            "--no-verify-certs",
            action="store_true",
            help="Disable TLS certificate verification.",
        )

    def run(self):
        if self.list_plugins():
            return
        if not self.args.reg_files:
            self.parser.error("At least one registry hive or directory is required.")

        input_files, input_errors, notices, _protected_inputs = collect_registry_hives(
            self.args.reg_files
        )
        self.report_input_issues(input_errors, notices)

        if not input_files:
            self.parser.exit(1, "No readable registry hives found.\n")

        self.log(
            f"Processing {len(input_files)} hive(s) as a single dataset.",
            self.args.quiet,
        )

        verify_certs = not getattr(self.args, "no_verify_certs", False)
        plugins: Optional[List[str]] = getattr(self.args, "plugins", None)

        presenter = Reg2esPresenter(
            input_paths=input_files,
            host=self.args.host,
            ca_certs=self.args.ca_certs,
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
        )
        total_success, _ = presenter.bulk_import()
        self.report_extraction_errors(presenter.errors)
        if input_errors or presenter.failed_records:
            self.parser.exit(
                1,
                f"Partial extraction: {total_success} records indexed; "
                f"{len(input_errors)} input failures; "
                f"{presenter.failed_records} extraction failures.\n",
            )

        self.log("Import completed successfully.", self.args.quiet)


def entry_point():
    try:
        BaseView.run_entry_point(Reg2esView)
    except Exception as exc:
        print(f"reg2es: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    entry_point()
