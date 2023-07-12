FCS Simple Endpoint
===================

<!-- START: BADGES -->
[![](https://img.shields.io/badge/%20code%20style-black-000000)](https://github.com/psf/black)
[![](https://img.shields.io/badge/%20imports-isort-%231674b1)](https://pycqa.github.io/isort/)
[![](https://img.shields.io/badge/linting-flake8-yellowgreen)](https://github.com/PyCQA/flake8)  
[![](https://img.shields.io/badge/%20doc%20style-sphinx-0a507a.svg)](https://www.sphinx-doc.org/en/master/usage/index.html)
[![](https://img.shields.io/badge/%20doc%20style-google-3666d6.svg)](https://google.github.io/styleguide/pyguide.html#s3.8-comments-and-docstrings)  
[![fcs-simple-endpoint @ PyPI](https://img.shields.io/pypi/v/fcs-simple-endpoint)](https://pypi.python.org/pypi/fcs-simple-endpoint)
[![](https://img.shields.io/github/last-commit/Querela/fcs-simple-endpoint-python)](https://github.com/Querela/fcs-simple-endpoint-python/commits/main)
[![Documentation Status](https://readthedocs.org/projects/fcs-simple-endpoint-python/badge/?version=latest)](https://fcs-simple-endpoint-python.readthedocs.io/en/latest/?badge=latest)
<!-- END: BADGES -->

- Based on [Java](https://github.com/clarin-eric/fcs-simple-endpoint/) implementation  
  _git commit: `47d1335288d27e860564fb878463f6b467ef7216`_
- Differences:
   - a bit more pythonic (naming, interfaces, enums etc.)


## Installation

```bash
# from github/source
python3 -m pip install 'fcs-simple-endpoint @ git+https://github.com/Querela/fcs-simple-endpoint-python.git'

# (locally) built package
python3 -m pip install dist/fcs_simple_endpoint-<version>-py2.py3-none-any.whl
# or
python3 -m pip install dist/fcs-simple-endpoint-<version>.tar.gz

# for local development
python3 -m pip install -e .
```

In `setup.cfg`:
```ini
[options]
install_requires =
    fcs-simple-endpoint @ git+https://github.com/Querela/fcs-simple-endpoint-python.git
```


## Build source/binary distribution

```bash
python3 -m pip install build
python3 -m build
```


## Development

* Uses `pytest` (with coverage, clarity and randomly plugins).

```bash
python3 -m pip install -e .[test]

pytest
```

Run style checks:
```bash
# general style checks
python3 -m pip install -e .[style]

black --check .
flake8 . --show-source --statistics
isort --check --diff .
mypy .

# building the package and check metadata
python3 -m pip install -e .[build]

python3 -m build
twine check --strict dist/*

# build documentation and check links ...
python3 -m pip install -e .[docs]

sphinx-build -b html docs dist/docs
sphinx-build -b linkcheck docs dist/docs
```


## Build documentation

```bash
python3 -m pip install -r ./docs/requirements.txt
# or 
python3 -m pip install -e .[docs]

sphinx-build -b html docs dist/docs
sphinx-build -b linkcheck docs dist/docs
```


## See also

- [clarin-eric/fcs-sru-server](https://github.com/clarin-eric/fcs-sru-server/)
- [clarin-eric/fcs-simple-endpoint](https://github.com/clarin-eric/fcs-simple-endpoint/)
