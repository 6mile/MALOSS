#!/bin/bash

WORKDIR=/Users/paulmccarty_1/projects/maloss

echo "Testing remote github javascript repo. This should have one malicious package."
python3 $WORKDIR/maloss.py -r https://github.com/NiftyBank/niftybank-app/blob/master/package.json

echo "Testing remote gitlab javascript repo. This should have zero malicious package."
python3 $WORKDIR/maloss.py -r https://gitlab.com/gitlab-com/gl-infra/ci-images/-/raw/packagecloud-v1.6.2/package.json

echo "Testing remote github repo. This should have zero malicious package."
python3 $WORKDIR/maloss.py -r https://github.com/bndr/pipreqs/blob/master/pyproject.toml

echo "Testing local clean package.json..."
python3 $WORKDIR/maloss.py $WORKDIR/tests/clean/package.json

echo "Testing local malicious package.json..."
python3 $WORKDIR/maloss.py $WORKDIR/tests/malicious/package.json

echo "Testing local malicious package-lock.json..."
python3 $WORKDIR/maloss.py $WORKDIR/tests/malicious/package-lock.json

echo "Testing local malicious requirements.txt..."
python3 $WORKDIR/maloss.py $WORKDIR/tests/malicious/requirements.txt

echo "Testing local malicious pyproject.toml..."
python3 $WORKDIR/maloss.py $WORKDIR/tests/malicious/pyproject.toml
