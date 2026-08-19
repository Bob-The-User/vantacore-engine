"""Sphinx configuration for VantaCore Engine API reference."""

project = "VantaCore Engine"
extensions = ["sphinx.ext.autodoc", "sphinx_autodoc_typehints"]
html_theme = "alabaster"
autodoc_typehints = "description"
