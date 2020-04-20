#!/usr/bin/python3 -W default
import warnings
import distutils.sysconfig
import os
import sys

from setuptools import setup
from distutils.core import Extension


warnings.simplefilter('default')

long_description = """\
Embeds the Python 3 interpreter into PAM \
so PAM modules can be written in Python"""

classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
    "Natural Language :: English",
    "Operating System :: Unix",
    "Programming Language :: C",
    "Programming Language :: Python3",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Systems Administration :: Authentication/Directory"]

if "Py_DEBUG" not in os.environ:
    Py_DEBUG = []
else:
    Py_DEBUG = [('Py_DEBUG', 1)]

libpython_so = distutils.sysconfig.get_config_var('INSTSONAME')
ext_modules = [
    Extension(
        "pam_python",
        sources=["pam_python.c"],
        include_dirs=['/usr/local/lib/'],
        library_dirs=[],
        define_macros=[('LIBPYTHON_SO', '"' + libpython_so + '"')] + Py_DEBUG,
        libraries=["pam", "python%d.%dm" % sys.version_info[:2]],
    ),
]

setup(
    name="pam_python",
    version="1.1.0",
    description="Enabled PAM Modules to be written in Python",
    keywords="pam,embed,authentication,security",
    platforms="Unix",
    long_description=long_description,
    author="James Boylan",
    author_email="ogre@boylan.net",
    url="https://github.com/Ralnoc/pam-python",
    license="AGPL-3.0",
    classifiers=classifiers,
    ext_modules=ext_modules,
)
