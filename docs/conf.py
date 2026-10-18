# Configuration file for the Sphinx documentation builder.
# crystal-tpm2-tss: Native Crystal TPM 2.0 Software Stack

project = 'crystal-tpm2-tss'
copyright = '2026, Rénich Bon Ćirić (Copyleft)'
author = 'Rénich Bon Ćirić'
release = '0.4.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.todo',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'build', 'technical/api', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = []
html_title = 'Crystal TPM2-TSS Documentation'
html_show_sourcelink = False
