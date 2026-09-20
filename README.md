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

When a plugin can parse the time represented by its record, that UTC-aware time
is used for `@timestamp`. Otherwise the registry key's LastWrite is used, with
the legacy `btime` value as a final fallback. The original LastWrite and other
MACB values remain under `reg2es.timestamps` and `reg2es.timestamp_iso`; the
selection and its meaning are recorded in `reg2es.timestamp` (`source`,
`meaning`, `precision`, and `fallback_reason`). Unknown, malformed, sentinel,
or timezone-free values are retained as raw/custom data and fall back to
LastWrite instead of being guessed as UTC. A missing valid time omits
`@timestamp` rather than using the current time. FILETIME conversion uses
integer arithmetic; `datetime` output is microsecond precision and the raw
100-nanosecond value is retained when available.

Artifact times are currently used for UserAssist execution, shutdown and OS
installation records, ShimCache target-file modification, TypedURLsTime,
Office TrustRecords macro enabling, Scheduled Task DynamicInfo, SAM local-user
last login, and installed KB packages. TeamViewer startup and uninstall dates
remain raw fallback candidates when their format or meaning is not confirmed.

SAM local-user times currently support the verified 80-byte, revision-3 `F`
layout. Short records, other layouts, and RID mismatches retain their raw data
and use LastWrite with an explicit reason. KB installation-time halves are
retained independently when either value is missing.

ShimCache preserves every Windows 8/10 entry. Legacy-format deduplication uses
the original FILETIME and other parsed evidence, so entries differing within
the same second remain distinct. Raw ShimCache time/size fields use decimal
strings to preserve unsigned values without Elasticsearch integer overflow.

### Per-plugin `@timestamp` source

`key.last_write` / `registry_key_modified` means the plugin has no confirmed
intrinsic time for its record and falls back to the registry key LastWrite.

| Plugin | Hive(s) | `@timestamp` source | Meaning | Precision |
| --- | --- | --- | --- | --- |
| `antivirus` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `auditpol` | SECURITY | `key.last_write` | `registry_key_modified` | — |
| `compname` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `env` | SYSTEM, SOFTWARE, NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `filedialogmru` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `gpo` | SOFTWARE, NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `kb` | SOFTWARE | `InstallTimeHigh/InstallTimeLow` | `kb_installation` | `microseconds` |
| `kb` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `keyboard` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `lastloggedon` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `lastshutdown` | SYSTEM | `ShutdownTime` | `shutdown` | `microseconds` |
| `lastshutdown` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `localgroups` | SOFTWARE, SAM | `key.last_write` | `registry_key_modified` | — |
| `localusers` | SAM | `SAM.Users.F.last_login` | `user_last_login` | `microseconds` |
| `localusers` | SAM | `key.last_write` | `registry_key_modified` | — |
| `mndmru` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `mstscmru` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `office_macros` | NTUSER.DAT | `TrustRecords.ts_enabled` | `office_document_macros_enabled` | `minute` |
| `office_macros` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `portproxy` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `printer_history` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `printer_ports` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `proxy` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `putty` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `rdphint` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `recentdocs` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `regtime` | ALL | `key.last_write` | `registry_key_modified` | — |
| `run` | NTUSER.DAT, SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `runmru` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `services` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `shimcache` | SYSTEM | `ShimCache.file_mtime` | `target_file_modified` | `microseconds` |
| `shimcache` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `srum` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `sysinternals` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `systeminfo` | SYSTEM | `ShutdownTime` | `shutdown` | `microseconds` |
| `systeminfo` | SOFTWARE | `InstallDate` | `os_installation` | `seconds` |
| `systeminfo` | SYSTEM, SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `tasks` | SOFTWARE | `TaskCache.DynamicInfo.last_start` | `scheduled_task_last_run` | `microseconds` |
| `tasks` | SOFTWARE | `TaskCache.DynamicInfo.created` | `scheduled_task_created` | `microseconds` |
| `tasks` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `teamviewer` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `timezone` | SYSTEM | `key.last_write` | `registry_key_modified` | — |
| `typedurls` | NTUSER.DAT | `TypedURLsTime` | `url_typed` | `microseconds` |
| `typedurls` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `uninstall` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `userassist` | NTUSER.DAT | `UAObject.last_exec` | `program_execution` | `microseconds` |
| `userassist` | NTUSER.DAT | `key.last_write` | `registry_key_modified` | — |
| `usersids` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |
| `version` | SOFTWARE | `key.last_write` | `registry_key_modified` | — |

The `fallback_reason` field explains why a row used `key.last_write` (for
example `intrinsic_time_unavailable`, `invalid_shutdowntime_filetime`, or
`typedurls_time_missing`).

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
  - Timestamp selection and artifact-time parsing in bundled plugins are
    reg2es changes; upstream LastWrite values remain preserved as provenance.
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
