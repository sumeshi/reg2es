# reg2es

[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![PyPI version](https://badge.fury.io/py/reg2es.svg)](https://badge.fury.io/py/reg2es)
[![Python Versions](https://img.shields.io/pypi/pyversions/reg2es.svg)](https://pypi.org/project/reg2es/)

![reg2es logo](https://gist.githubusercontent.com/sumeshi/c2f430d352ae763273faadf9616a29e5/raw/bd51b2539d8bb639d4f630ef13639706bed1f905/reg2es.svg)

A library for fast import of Windows NT Registry(REGF) into Elasticsearch.  
reg2es uses C library [libregf](https://github.com/libyal/libregf).


## Usage

When using from the commandline interface:

```bash
$ reg2es /path/to/your/file.DAT
```

When using from the python-script:

```python
from reg2es import reg2es

if __name__ == '__main__':
  filepath = '/path/to/your/file.DAT'
  reg2es(filepath)
```

### Arguments

reg2es supports importing from multiple files.

```bash
$ reg2es NTUSER.DAT SYSTEM SAM
```

Also, possible to import recursively from a specific directory.

Note: In this case, the filename will not be checked, please check for unnecessary files before execute.

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

$ reg2es /regfiles/ # The Path is recursively expanded to file1~6.reg.
```

### Options

```
--version, -v

--help, -h

--quiet, -q
  Flag to suppress standard output
  (default: False)

--host:
  ElasticSearch host address
  (default: localhost)

--port:
  ElasticSearch port number
  (default: 9200)

--index:
  Index name of Import destination
  (default: reg2es)

--scheme:
  Scheme to use (http, or https)
  (default: http)

--pipeline
  Elasticsearch Ingest Pipeline to use
  (default: )

--login:
  The login to use if Elastic Security is enable
  (default: )

--pwd:
  The password linked to the login provided
  (default: )

--fields-limit
  index.mapping.total_fields.limit settings
  (default: 10000)
```

### Examples

When using from the commandline interface:

```
$ reg2es /path/to/your/file.dat --host=localhost --port=9200 --index=foobar
```

When using from the python-script:

```py
if __name__ == '__main__':
    reg2es('/path/to/your/file.dat', host=localhost, port=9200, index='foobar')
```

With the Amazon Elasticsearch Serivce (ES):

```
$ reg2es /path/to/your/file.dat --host=example.us-east-1.es.amazonaws.com --port=443 --scheme=https --index=foobar
```

With credentials for Elastic Security:

```
$ reg2es /path/to/your/file.dat --host=localhost --port=9200 --index=foobar --login=elastic --pwd=******
```

Note: The current version does not verify the certificate.


## Appendix

### Reg2json

Extra feature. :sushi: :sushi: :sushi:

Convert from Windows NT Registry(REGF) to json file.

```bash
$ reg2json /path/to/your/file.DAT /path/to/output/target.json
```

Convert from Windows NT Registry(REGF) to Python dict object.

```python
from reg2es import reg2json

if __name__ == '__main__':
  filepath = '/path/to/your/file.DAT'
  result: dict = reg2json(filepath)
```

## Output Format

The structures is not well optimized for searchable with Elasticsearch. I'm waiting for your PR!!

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
          },
          "DispFileName": {
            "type": 1,
            "identifier": "REG_SZ",
            "size": 34,
            "data": "@mmres.dll,-5824"
          }
        },
        "ActivatingDocument": {
          "meta": {
            "last_written_time": "2015-10-30T07:24:57.861009"
          },
          "_": {
            "type": 1,
            "identifier": "REG_SZ",
            "size": 40,
            "data": "Complete Navigation"
          },
          "DispFileName": {
            "type": 1,
            "identifier": "REG_SZ",
            "size": 40,
            "data": "@ieframe.dll,-10321"
          }
        }
        ...
      }
    }
  }
}
```

## Installation

### via PyPI
```
$ pip install reg2es
```

## Known Issues

```
elasticsearch.exceptions.RequestError: RequestError(400, 'illegal_argument_exception', 'Limit of total fields [1000] in index [reg2es] has been exceeded')
```

Windows NT Registry has a large number of elements per document and is caught in the initial value of the limit.
Therefore, please use the --fields-limit(default: 10000) option to remove the limit.

```
$ reg2es --fields-limit 10000 NTUSER.DAT
```

## Contributing

[CONTRIBUTING](https://github.com/sumeshi/reg2es/blob/master/CONTRIBUTING.md)

The source code for reg2es is hosted at GitHub, and you may download, fork, and review it from this repository(https://github.com/sumeshi/reg2es).
Please report issues and feature requests. :sushi: :sushi: :sushi:

## License

reg2es is released under the [MIT](https://github.com/sumeshi/reg2es/blob/master/LICENSE) License.

Powered by [libregf](https://github.com/libyal/libregf).
