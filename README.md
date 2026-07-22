# reg2es

[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/reg2es)](https://pypi.org/project/reg2es/)

![reg2es logo](https://gist.githubusercontent.com/sumeshi/c2f430d352ae763273faadf9616a29e5/raw/bd51b2539d8bb639d4f630ef13639706bed1f905/reg2es.svg)

A command-line tool and Python library for parsing Windows NT Registry (REGF) and importing the results into Elasticsearch.

**reg2es** leverages the [regrippy](https://github.com/airbus-cert/regrippy) framework for flexible and extensible registry parsing.


## Usage

**reg2es** can be used as a standalone command-line tool or integrated directly into your Python scripts.

```bash
$ reg2es /path/to/your/file.DAT
```

```python
from reg2es import reg2es

reg2es('/path/to/your/file.DAT')
```


### Arguments

**reg2es** can process multiple files at once:

```bash
$ reg2es NTUSER.DAT SYSTEM SAM
```

reg2es can recursively process all registry files under a specified directory:

```bash
$ tree .
regfiles/
  ├── NTUSER.DAT
  ├── NTUSER.MAN
  ├── SAM
  └── subdirectory/
    ├── SOFTWARE
    └── subsubdirectory/
      ├── SYSTEM
      └── UsrClass.dat

$ reg2es /regfiles/ # This recursively processes all registry files.
```


### Options

```
--version, -v

--help, -h

--quiet, -q
  Suppress standard output
  (default: False)

--host:
  Elasticsearch host address (default: localhost)

--port:
  Elasticsearch port number (default: 9200)

--index:
  Destination index name (default: reg2es)

--scheme:
  Protocol scheme to use (http or https) (default: http)

--pipeline:
  Elasticsearch Ingest Pipeline to use (default: )

--login:
  Username for Elasticsearch authentication

--pwd:
  Password for Elasticsearch authentication

--fields-limit:
  index.mapping.total_fields.limit settings (default: 10000)
```


### Examples

When using from the command line:

```bash
$ reg2es /path/to/your/file.DAT --host=localhost --port=9200 --index=foobar
```

When using from a Python script:

```py
reg2es('/path/to/your/file.DAT', host='localhost', port=9200, index='foobar')
```

With credentials for Elastic Security:

```bash
$ reg2es /path/to/your/file.DAT --host=localhost --port=9200 --index=foobar --login=elastic --pwd=******
```


## Appendix

### reg2json

**reg2es** also includes `reg2json`, a command-line tool for converting Windows NT Registry into JSON files. :sushi: :sushi: :sushi:

```bash
$ reg2json /path/to/your/file.DAT /path/to/output/target.json
```

You can also convert registry files directly into a Python `dict` object:

```python
from reg2es import reg2json

result: dict = reg2json('/path/to/your/file.DAT')
```


## Output Format Example

```json
{
  "ROOT": {
    "AppEvents": {
      "meta": {
        "last_written_time": "2015-10-30T07:24:57.814133"
      },
      "EventLabels": {
        "meta": {
          "last_written_time": "2015-10-30T07:25:51.735838"
        },
        "Default": {
          "meta": {
            "last_written_time": "2015-10-30T07:24:57.861009"
          },
          "_": {
            "type": 1,
            "identifier": "REG_SZ",
            "size": 26,
            "data": "Default Beep"
          }
        }
      }
    }
  }
}
```


## Known Issues

```
elasticsearch.exceptions.RequestError: RequestError(400, 'illegal_argument_exception', 'Limit of total fields [1000] in index [reg2es] has been exceeded')
```

Windows NT Registry has a large number of elements per document and is caught in the initial value of the limit.
Therefore, please use the `--fields-limit` (default: 10000) option to remove the limit.

```bash
$ reg2es --fields-limit 10000 NTUSER.DAT
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

Released under the [MIT](LICENSE) License.

Powered by [regrippy](https://github.com/airbus-cert/regrippy).
