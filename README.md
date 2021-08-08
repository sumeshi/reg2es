# reg2es

[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![PyPI version](https://badge.fury.io/py/reg2es.svg)](https://badge.fury.io/py/reg2es)
[![Python Versions](https://img.shields.io/pypi/pyversions/reg2es.svg)](https://pypi.org/project/reg2es/)
[![DockerHub Status](https://shields.io/docker/cloud/build/sumeshi/reg2es)](https://hub.docker.com/r/sumeshi/reg2es)

![reg2es logo](https://gist.githubusercontent.com/sumeshi/c2f430d352ae763273faadf9616a29e5/raw/bd51b2539d8bb639d4f630ef13639706bed1f905/reg2es.svg)

A library for fast import of Windows NT Registry(REGF) into Elasticsearch.  
reg2es uses C library [libregf](https://github.com/libyal/libregf).


## Usage

When using from the commandline interface:

```bash
$ reg2es /path/to/your/file.reg
```

When using from the python-script:

```python
from reg2es import reg2es

if __name__ == '__main__':
  filepath = '/path/to/your/file.reg'
  reg2es(filepath)
```

### Arguments

reg2es supports importing from multiple files.

```bash
$ reg2es file1.reg file2.reg file3.reg
```

Also, possible to import recursively from a specific directory.

```bash
$ tree .
regfiles/
  ├── file1.reg
  ├── file2.reg
  ├── file3.reg
  └── subdirectory/
    ├── file4.reg
    └── subsubdirectory/
      ├── file5.reg
      └── file6.reg

$ reg2es /regfiles/ # The Path is recursively expanded to file1~6.reg.
```

### Options

```
--version, -v

--help, -h

--quiet, -q
  Flag to suppress standard output
  (default: False)

--multiprocess, -m:
  Flag to run multiprocessing (fast!)
  (default: False)

--size:
  Size of the chunk to be processed for each process
  (default: 500)

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
```

### Examples

When using from the commandline interface:

```
$ reg2es /path/to/your/file.reg --host=localhost --port=9200 --index=foobar --size=500
```

When using from the python-script:

```py
if __name__ == '__main__':
    reg2es('/path/to/your/file.reg', host=localhost, port=9200, index='foobar', size=500)
```

With the Amazon Elasticsearch Serivce (ES):

```
$ reg2es /path/to/your/file.reg --host=example.us-east-1.es.amazonaws.com --port=443 --scheme=https --index=foobar
```

With credentials for Elastic Security:

```
$ reg2es /path/to/your/file.reg --host=localhost --port=9200 --index=foobar --login=elastic --pwd=******
```

Note: The current version does not verify the certificate.


## Appendix

### Reg2json

Extra feature. :sushi: :sushi: :sushi:

Convert from Windows NT Registry(REGF) to json file.

```bash
$ reg2json /path/to/your/file.reg /path/to/output/target.json
```

Convert from Windows NT Registry(REGF) to Python List[dict] object.

```python
from reg2es import reg2json

if __name__ == '__main__':
  filepath = '/path/to/your/file.reg'
  result: List[dict] = reg2json(filepath)
```

## Installation

### via PyPI
```
$ pip install reg2es
```

### via DockerHub
```
$ docker pull sumeshi/reg2es:latest
```

## Run with Docker
https://hub.docker.com/r/sumeshi/reg2es


## reg2es
```bash
# "host.docker.internal" is only available in mac and windows environments.
# For linux, use the --add-host option.
$ docker run -t --rm -v $(pwd):/app/work sumeshi/reg2es:latest reg2es /app/work/Security.reg --host=host.docker.internal
```

## reg2json
```bash
$ docker run -t --rm -v $(pwd):/app/work sumeshi/reg2es:latest reg2es /app/work/Security.reg /app/work/out.json
```

Do not use the "latest" image if at all possible.  
The "latest" image is not a released version, but is built from the contents of the master branch.

## Contributing

[CONTRIBUTING](https://github.com/sumeshi/reg2es/blob/master/CONTRIBUTING.md)

The source code for reg2es is hosted at GitHub, and you may download, fork, and review it from this repository(https://github.com/sumeshi/reg2es).
Please report issues and feature requests. :sushi: :sushi: :sushi:

## License

reg2es is released under the [MIT](https://github.com/sumeshi/reg2es/blob/master/LICENSE) License.

Powered by [libregf](https://github.com/libyal/libregf).