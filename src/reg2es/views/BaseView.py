# coding: utf-8
import argparse
from abc import ABCMeta, abstractmethod
from typing import List, Optional

from reg2es.__about__ import __version__
from reg2es.models.Reg2es import discover_plugins


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


class BaseView(metaclass=ABCMeta):
    def __init__(self):
        self.parser = argparse.ArgumentParser(allow_abbrev=False)
        self.__define_common_options()

    def __define_common_options(self):
        plugin_names = [name for name, _plugin in discover_plugins()]
        self.parser.add_argument(
            "--version", "-v", action="version", version=__version__
        )
        self.parser.add_argument(
            "--quiet",
            "-q",
            action="store_true",
            help="Suppress standard output.",
        )
        self.parser.add_argument(
            "--size",
            "-s",
            type=positive_int,
            default=500,
            help="Chunk size for batch processing (default: 500).",
        )
        self.parser.add_argument(
            "--tags",
            default="",
            help=(
                "Comma-separated tags to add to each record "
                "(e.g., hostname, case-id)."
            ),
        )
        self.parser.add_argument(
            "--plugin",
            action="append",
            dest="plugins",
            default=None,
            choices=plugin_names,
            help=(
                "Plugin name to run (repeatable). Omit to run compatible, "
                "default-enabled plugins."
            ),
        )
        self.parser.add_argument(
            "--list-plugins",
            action="store_true",
            help="List bundled plugins and exit.",
        )

    @abstractmethod
    def define_options(self):
        pass

    def log(self, message: str, is_quiet: bool):
        if not is_quiet:
            print(message)

    def parse_tags(self) -> Optional[List[str]]:
        """Parse the common comma-separated tag option."""
        if not self.args.tags:
            return None
        tags = [tag.strip() for tag in self.args.tags.split(",")]
        return [tag for tag in tags if tag]

    def list_plugins(self) -> bool:
        """Print the deterministic plugin inventory when requested."""
        if not self.args.list_plugins:
            return False
        for name, plugin in discover_plugins():
            description = (plugin.__doc__ or "").strip()
            print(f"{name}: {description}")
        return True
