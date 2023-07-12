import os

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.coverage",
    "sphinx.ext.extlinks",
    "sphinx.ext.ifconfig",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "myst_parser",
]
source_suffix = [".rst", ".md"]
master_doc = "index"
project = "FCS SRU Simple Endpoint"
year = "2023"
author = "Erik Körner"
copyright = "{0}, {1}".format(year, author)
version = release = "0.1"

pygments_style = "trac"
templates_path = ["."]
extlinks = {}

# on_rtd is whether we are on readthedocs.org
on_rtd = os.environ.get("READTHEDOCS", None) == "True"

if not on_rtd:  # only set the theme if we're building docs locally
    html_theme = "sphinx_rtd_theme"

html_use_smartypants = True
html_last_updated_fmt = "%b %d, %Y"
html_split_index = False
html_sidebars = {
    "**": ["searchbox.html", "globaltoc.html", "sourcelink.html"],
}
html_short_title = "%s-%s" % (project, version)

autoclass_content = "both"
autodoc_member_order = "bysource"

napoleon_google_docstring = True
# napoleon_numpy_docstring = False
napoleon_use_ivar = True
napoleon_use_rtype = False
napoleon_use_param = False

linkcheck_ignore = [
    # xml namespace links (ContentHandler)
    r"^http://xml\.org/sax/features/.+",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "fcs-sru-server": ("https://fcs-sru-server-python.readthedocs.io/en/latest/", None),
    "fcs-ql-parser": ("https://fcs-ql-python.readthedocs.io/en/latest/", None),
    "werkzeug": ("https://werkzeug.palletsprojects.com/en/2.2.x/", None),  # latest?
    "PyJWT": ("https://pyjwt.readthedocs.io/en/stable/", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
}
