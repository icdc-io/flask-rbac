#!/bin/bash
# before running this script, make sure you have set the password in keyring
# set the password using: keyring set testpypi __token__ <password>

# Clean up previous builds
rm -rf dist/ build/ *.egg-info/

# Build the package
python -m build

# Retrieve the password from keyring
TOKEN=$(keyring get testpypi __token__)

# Upload to TestPyPI using twine and the retrieved password
python -m twine upload --repository testpypi dist/* -u __token__ -p $TOKEN --non-interactive  --verbose

# Optional: Print success message
if [ $? -eq 0 ]; then
    echo "Successfully uploaded flask-rbac-icdc to TestPyPI"
    echo "You can install it using:"
    echo "pip install --index-url https://test.pypi.org/simple/ flask-rbac-icdc"
else
    echo "Upload failed"
fi