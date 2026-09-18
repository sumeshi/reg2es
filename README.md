# reg2es

[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/reg2es)](https://pypi.org/project/reg2es/)

![reg2es logo](https://gist.githubusercontent.com/sumeshi/c2f430d352ae763273faadf9616a29e5/raw/bd51b2539d8bb639d4f630ef13639706bed1f905/reg2es.svg)

A command-line tool and Python library for extracting forensic artifacts from
Windows NT Registry (REGF) hives and importing them into Elasticsearch.

The 38 bundled plugins are based on
[airbus-cert/regrippy](https://github.com/airbus-cert/regrippy). `reg2es` runs
standalone and does not require the `regrippy` package at runtime. Both
`reg2es` and `reg2json` use the same plugin runner and emit the same
ECS-oriented documents.


## Usage

**reg2es** can be used as a standalone command-line tool or integrated directly into your Python scripts.

```bash
reg2es SYSTEM SOFTWARE SAM
reg2json NTUSER.DAT -o artifacts.json
```

```python
from reg2es import reg2es

reg2es(["SYSTEM", "SOFTWARE", "SAM"])
```


### Arguments

Multiple inputs passed in one invocation form one registry dataset. This lets
plugins such as `localgroups` enrich SAM results using SOFTWARE data, regardless
of the order of input paths.

```bash
reg2es SAM SOFTWARE
```

reg2es can recursively process all registry files under a specified directory:

```bash
tree .
regfiles/
  ├── NTUSER.DAT
  ├── NTUSER.MAN
  ├── SAM
  └── subdirectory/
    ├── SOFTWARE
    └── subsubdirectory/
      ├── SYSTEM
      └── UsrClass.dat

reg2es /regfiles/ # Recursively collects hives as one dataset.
```

Directory scans process REGF hive files only. Registry transaction logs and
unrelated files are not treated as standalone hives.


### Common options

- `--plugin NAME`: run one plugin; repeat to select several. By default,
  compatible, default-enabled plugins run. The exhaustive `regtime` plugin is
  opt-in.
- `--list-plugins`: print the 38 bundled plugins and exit.
- `--size N`: set the generation and indexing chunk size (default: 500).
- `--tags tag1,tag2`: add tags to every document.
- `--quiet`: suppress progress output.

`reg2es` also accepts Elasticsearch connection options including
`--host`, `--port`, `--index`, `--scheme`, `--pipeline`, `--login`, `--pwd`,
`--ca-certs`, and `--no-verify-certs`. TLS verification is enabled by default;
use `--ca-certs /path/to/ca.pem` for a private CA bundle. Run `reg2es --help`
or `reg2json --help` for the full current interface.


### Examples

When using from the command line:

```bash
reg2es SYSTEM --plugin services --host localhost --index registry-artifacts
```

When using from a Python script:

```py
reg2es(
    ["SYSTEM", "SOFTWARE"],
    host="localhost",
    index="registry-artifacts",
    plugin_names=["services", "systeminfo"],
    additional_tags=["host-01", "case-42"],
)
```

With Elasticsearch authentication:

```bash
reg2es SYSTEM --login elastic --pwd '******'
```


## Appendix

### reg2json

**reg2es** also includes `reg2json`, a command-line tool for converting Windows NT Registry into JSON files. :sushi: :sushi: :sushi:

```bash
reg2json NTUSER.DAT --plugin userassist -o artifacts.json
```

`reg2json` also supports line-delimited output. `--format jsonl` (or `ndjson`)
writes one record per line without holding the entire dataset in memory. When
no output path is specified, the default extension is `.jsonl`:

```bash
reg2json NTUSER.DAT --plugin userassist --format jsonl -o artifacts.jsonl
```

Use `--split` to write one output file per plugin that produced results. With
the default JSON format, each file contains a JSON array. With `--format jsonl`
or `--format ndjson`, each file contains one JSON object per line. The `-o`
option names the output directory (the current directory is used by default):

```bash
reg2json collected-hives/ --split -o artifacts/
```

For example, the command above produces files such as
`artifacts/antivirus.json`, `artifacts/services.json`, and
`artifacts/userassist.json`. Plugins with no results do not produce an empty
file.

The exhaustive `regtime` timeline is excluded from the default plugin set
because it emits one record for every registry key. Run it explicitly when
needed:

```bash
reg2json collected-hives/ --plugin regtime -o regtime.json
```

You can also convert registry files directly into a Python `list[dict]`:

```python
from reg2es import reg2json

result: list[dict] = reg2json(
    ["SOFTWARE", "SAM"],
    plugin_names=["localgroups"],
    additional_tags=["host-01"],
)
```


## Output Format Example

Each plugin result becomes one ECS-oriented document. Standard `event`,
`registry`, `log.file`, `tags`, and `@timestamp` fields describe the artifact.
Lossless plugin-specific data and the original offline-hive location are kept
under `reg2es`.

Binary registry values report their size in `registry.data.bytes`; their raw
hex is preserved once in `reg2es.value_data`. Parsed fields remain under
`reg2es.custom`, and RecentDocs names are also exposed as ECS `file.name`.

```json
{
  "@timestamp": "2015-10-30T07:24:57.814133+00:00",
  "event": {
    "kind": "event",
    "category": ["registry"],
    "type": ["info"],
    "action": "compname"
  },
  "registry": {
    "hive": "HKLM",
    "key": "SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName",
    "path": "HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName",
    "value": "ComputerName",
    "data": {
      "type": "RegSZ",
      "strings": ["DESKTOP-EXAMPLE"]
    }
  },
  "log": {
    "file": {"path": "/evidence/SYSTEM"}
  },
  "tags": ["registry", "host-01"],
  "reg2es": {
    "plugin": {"name": "compname"},
    "source": {
      "hive": "SYSTEM",
      "key_path": "ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName"
    },
    "value_data": "DESKTOP-EXAMPLE"
  }
}
```


## Installation

### From PyPI

```bash
$ pip install reg2es
```

### With uv

```bash
$ uv add reg2es
```

### From GitHub Releases

Standalone binaries built with Nuitka are available from GitHub Releases for systems without a Python environment.

```bash
$ chmod +x ./reg2es
$ ./reg2es {{options...}}
```

```powershell
> reg2es.exe {{options...}}
```


## Contributing

The source code for **reg2es** is hosted on GitHub: https://github.com/sumeshi/reg2es.
Please report issues and feature requests. :sushi: :sushi: :sushi:


## License

Standalone release ZIPs include `LICENSES.txt` with the project, bundled plugin,
runtime dependency and build Python license notices. Keep it with the executables
when redistributing them. The collector excludes development-only dependencies.

**reg2es** is released under the [MIT](LICENSE) License.

### Third-Party Notices

This product includes code derived from [regrippy](https://github.com/airbus-cert/regrippy)
v2.0.3 by Airbus CERT, licensed under Apache License 2.0.

- Repository: <https://github.com/airbus-cert/regrippy>
- Vendored components:
  - `src/reg2es/plugins/base.py` — BasePlugin, PluginResult, mactime
  - `src/reg2es/plugins/*.py` — 38 registry analysis plugins
  - `src/reg2es/plugins/shimcache.py` — Shim Cache plugin with its parser
    (original copyright: Andrew Davis, Mandiant 2012)
- Modifications: import paths changed from `regrippy` to `reg2es.plugins` and
  the formerly separate Shim Cache parser was integrated into its plugin.
  Unused upstream CLI display helpers were removed; artifact extraction logic
  remains unchanged.
- Full license text: [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)

We gratefully thank the maintainers and contributors of regrippy,
python-registry, and the other open-source projects that make reg2es possible.
