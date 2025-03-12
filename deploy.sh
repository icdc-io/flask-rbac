#!/bin/bash
# before running this script, make sure you have set the password in keyring
# set the password using: keyring set testpypi __token__ <password>

# Activate the virtual environment
source venv/bin/activate

# Run unit tests
# pytest tests -v
python -m unittest ./tests/test_rbac.py -v
if [ $? -ne 0 ]; then
    echo "Unit tests failed"
    exit 1
else
    echo "Unit tests passed"
fi

# Create documentation
rm -rf docs/output
sphinx-apidoc -o ./docs/source ./flask_rbac_icdc
sphinx-build -b html docs/source docs/output

# Clean up previous builds
echo "Cleaning up previous builds..."
rm -rf dist/ build/ *.egg-info/

# Build the package
echo "Building the package..."
python -m build

# Retrieve the password from keyring
TOKEN=$(keyring get testpypi __token__)

# Upload to TestPyPI using twine and the retrieved password
echo "Uploading to TestPyPI..."
python -m twine upload --repository testpypi dist/* -u __token__ -p $TOKEN --non-interactive  --verbose

# Optional: Print success message
if [ $? -eq 0 ]; then
    echo "Successfully uploaded flask-rbac-icdc to TestPyPI"
    echo "You can install it using:"
    echo "pip install --index-url https://test.pypi.org/simple/ flask-rbac-icdc"
else
    echo "Upload failed"
fi