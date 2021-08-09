# coding: utf-8
from typing import List
from pathlib import Path

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2esPresenter import Reg2esPresenter 


class Reg2esView(BaseView):

    def __init__(self):
        super().__init__()
        self.define_options()
        self.args = self.parser.parse_args()

    def define_options(self):
        self.parser.add_argument(
            "reg_files",
            nargs="+",
            type=str,
            help="Windows NT Registry or directories containing them.",
        )

        self.parser.add_argument("--host", default="localhost", help="ElasticSearch host")
        self.parser.add_argument("--port", default=9200, help="ElasticSearch port number")
        self.parser.add_argument("--index", default="reg2es", help="Index name")
        self.parser.add_argument("--scheme", default="http", help="Scheme to use (http, https)")
        self.parser.add_argument("--pipeline", default="", help="Ingest pipeline to use")
        self.parser.add_argument("--login", default="", help="Login to use to connect to Elastic database")
        self.parser.add_argument("--pwd", default="", help="Password associated with the login")
        self.parser.add_argument("--fields-limit", default=10000, help="index.mapping.total_fields.limit settings")
    
    def __list_reg_files(self, reg_files: List[str]) -> List[Path]:
        # TODO: verify filename
        reg_path_list = list()
        for reg_file in reg_files:
            if Path(reg_file).is_dir():
                reg_path_list.extend(Path(reg_file).glob("**/*"))
            else:
                reg_path_list.append(Path(reg_file))

        return reg_path_list

    def run(self):
        view = Reg2esView()
        reg_files = self.__list_reg_files(self.args.reg_files)

        for reg_file in reg_files:
            view.log(f"Currently Importing {reg_file}.", self.args.quiet)

            # TODO: verify filename before processing
            try:
                Reg2esPresenter(
                    input_path=reg_file,
                    host=self.args.host,
                    port=int(self.args.port),
                    index=self.args.index,
                    scheme=self.args.scheme,
                    pipeline=self.args.pipeline,
                    login=self.args.login,
                    pwd=self.args.pwd,
                    is_quiet=self.args.quiet,
                    fields_limit=self.args.fields_limit
                ).bulk_import()
            except Exception as e:
                print('ImportError: ', reg_file)
                print(e)

        view.log("Import completed.", self.args.quiet)


def entry_point():
    Reg2esView().run()


if __name__ == "__main__":
    entry_point()
