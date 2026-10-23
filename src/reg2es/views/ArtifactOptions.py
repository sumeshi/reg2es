"""Registry dataset and plugin options layered on the common CLI."""

import sys

from ..models.Reg2es import discover_plugins


class ArtifactOptions:
    supports_multiprocessing = False

    def _define_artifact_options(self):
        plugin_names = [name for name, _plugin in discover_plugins()]
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

    def report_input_issues(self, errors, notices=()):
        for message in notices:
            print(f"Warning: {message}", file=sys.stderr)
        for message in errors:
            print(
                f"Error: {message.get('source_file', 'registry input')}: "
                f"{message.get('error', 'input skipped')}",
                file=sys.stderr,
            )

    def report_extraction_errors(self, errors):
        for error in errors:
            path = error.get("source_file", error.get("hive_path", "registry input"))
            message = error.get("error", "extraction failed")
            print(f"Error: {path}: {message}", file=sys.stderr)

    def list_plugins(self) -> bool:
        """Print the deterministic plugin inventory when requested."""
        if not self.args.list_plugins:
            return False
        for name, plugin in discover_plugins():
            description = (plugin.__doc__ or "").strip()
            print(f"{name}: {description}")
        return True
