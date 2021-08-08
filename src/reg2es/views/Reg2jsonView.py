# coding: utf-8
from multiprocessing import cpu_count

from reg2es.views.BaseView import BaseView
from reg2es.presenters.Reg2jsonPresenter import Reg2jsonPresenter


class Reg2jsonView(BaseView):

    def __init__(self):
        super().__init__()
        self.define_options()
        self.args = self.parser.parse_args()

    def define_options(self):
        self.parser.add_argument("reg_file", type=str, help="Windows NT Registry(REGF) file to input.")
        self.parser.add_argument("--output-file", "-o", type=str, default="", help="json file path to output.")

    def run(self):
        view = Reg2jsonView()
        view.log(f"Converting {self.args.reg_file}.", self.args.quiet)

        if self.args.multiprocess:
            view.log(f"Multi-Process: {cpu_count()}", self.args.quiet)

        Reg2jsonPresenter(
            input_path=self.args.reg_file,
            output_path=self.args.output_file,
            is_quiet=self.args.quiet,
            multiprocess=self.args.multiprocess,
            chunk_size=self.args.size,
        ).export_json()

        view.log("Converted.", self.args.quiet)


def entry_point():
    Reg2jsonView().run()


if __name__ == "__main__":
    entry_point()
