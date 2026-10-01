#!/bin/bash
set -eu
cd /home/saulofilho/dev/pessoal/secscan-python
echo "=== CWD ==="
pwd

echo "=== STEP 1: PyPI name check ==="
curl -sI https://pypi.org/pypi/secscan/json | head -n 20

echo "=== STEP 2: Credentials (yes/no only) ==="
if [ -f "$HOME/.pypirc" ]; then
  echo "HOME/.pypirc: yes"
else
  echo "HOME/.pypirc: no"
fi
if [ -n "${TWINE_PASSWORD:-}" ]; then
  echo "TWINE_PASSWORD: yes"
else
  echo "TWINE_PASSWORD: no"
fi
if [ -n "${PYPI_API_TOKEN:-}" ]; then
  echo "PYPI_API_TOKEN: yes"
else
  echo "PYPI_API_TOKEN: no"
fi
if [ -n "${TWINE_USERNAME:-}" ]; then
  echo "TWINE_USERNAME: yes"
else
  echo "TWINE_USERNAME: no"
fi

# Stop if nothing is configured and stdin is not a TTY (cannot prompt)
if [ ! -f "$HOME/.pypirc" ] && [ -z "${TWINE_PASSWORD:-}" ] && [ -z "${PYPI_API_TOKEN:-}" ]; then
  if [ ! -t 0 ]; then
    echo "STOP: no ~/.pypirc, TWINE_PASSWORD, or PYPI_API_TOKEN, and stdin is not interactive."
    exit 2
  fi
fi

echo "=== STEP 3: Install build tools ==="
python3 -m pip install --user -q build twine

echo "=== STEP 4: Tests ==="
PYTHONPATH=src python3 -m unittest discover -s tests -q
echo "TESTS_EXIT:$?"

echo "=== STEP 5: Clean/rebuild ==="
rm -rf dist build *.egg-info src/*.egg-info
python3 -m build
echo "=== dist ==="
ls -la dist

echo "=== STEP 6: twine check ==="
python3 -m twine check dist/*

echo "=== STEP 7: twine upload ==="
if [ -n "${PYPI_API_TOKEN:-}" ] && [ -z "${TWINE_PASSWORD:-}" ]; then
  export TWINE_USERNAME="__token__"
  export TWINE_PASSWORD="$PYPI_API_TOKEN"
fi
if [ -f "$HOME/.pypirc" ] || [ -n "${TWINE_PASSWORD:-}" ]; then
  python3 -m twine upload dist/*
else
  echo "STOP: upload needs credentials and none are configured."
  exit 2
fi

echo "=== STEP 8: Verify ==="
sleep 15
curl -sI https://pypi.org/pypi/secscan/json | head -n 20
echo "=== DONE ==="
