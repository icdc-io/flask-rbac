# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys

sys.path.insert(0, os.path.abspath("../.."))  # Ensure library is accessible
# Sphinx extensions
extensions = [
    "sphinx.ext.autodoc",  # Generate docs from docstrings
    "sphinx.ext.napoleon",  # Support Google/NumPy docstrings
    "sphinx.ext.viewcode",  # Add source code links
    "sphinx.ext.intersphinx",  # Cross-link external docs
    "sphinx_autodoc_typehints",  # Show type hints
]

# Theme
html_theme = "sphinx_rtd_theme"  # Read the Docs theme

project = "flask_rbac_icdc"
copyright = "2025, ICDC Vitali Starastsenka"
author = "Vitali Starastsenka"
release = "0.1.3"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

templates_path = ["_templates"]
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "venv",
    "requirements.txt",
    "README.md",
    "docs/source/conf.py",
    ".pytest_cache",
    "__pycache__",
    "*.pyc",
]

language = "python"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_static_path = ["_static"]

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
}
