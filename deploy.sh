#!/bin/bash
# before running this script, make sure you have set the password in keyring
# set the password using: keyring set testpypi __token__ <password>

# Activate the virtual environment
source venv/bin/activate

# Run unit tests
# pytest tests -v
echo "==============================================="
echo "Running unit tests..."
echo "==============================================="
python -m unittest ./tests/test_rbac.py -v
if [ $? -ne 0 ]; then
    echo "Unit tests failed"
    exit 1
else
    echo "Unit tests passed"
fi

# Create documentation
echo "==============================================="
echo "Creating documentation..."
echo "==============================================="
sphinx-build -E -a -b html docs/source docs/build
if [ $? -ne 0 ]; then
    echo "Error: Documentation failed"
else
    echo "Documentation created successfuly"
    # Commit and push the documentation
    cd docs/build
    git add .
    git commit -m "Update documentation"
    git push origin main
    cd ../..
    echo "Documentation pushed to GitHub"
fi
# Clean up previous builds
echo "==============================================="
echo "Cleaning up previous builds..."
echo "==============================================="
rm -rf dist/ build/ *.egg-info/

# Build the package
echo "Building the package..."
python -m build

# Ask user to choose the repository
echo "==============================================="
echo "Choose the repository to upload to:"
echo "1) TestPyPI (test.pypi.org)"
echo "2) PyPI (pypi.org)"
read -p "Enter the number of your choice: " choice

if [ "$choice" -eq 1 ]; then
    REPOSITORY="testpypi"
    INDEX_URL="https://test.pypi.org/simple/"
elif [ "$choice" -eq 2 ]; then
    REPOSITORY="pypi"
    INDEX_URL="https://pypi.org/simple/"
else
    echo "Invalid choice"
    exit 1
fi

# Retrieve the password from keyring
TOKEN=$(keyring get $REPOSITORY __token__)

# Upload to TestPyPI using twine and the retrieved password
echo "==============================================="
echo "Uploading to $REPOSITORY..."
echo "==============================================="
python -m twine upload --repository $REPOSITORY dist/* -u __token__ -p $TOKEN --non-interactive  --verbose

# Optional: Print success message
if [ $? -eq 0 ]; then
    echo "Successfully uploaded flask-rbac-icdc to $REPOSITORY"
    echo "You can install it using:"
    echo "pip install --index-url $INDEX_URL flask-rbac-icdc"
else
    echo "Upload failed"
fi