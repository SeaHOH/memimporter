#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""setup script for memimport.
"""

import os
import sys
import glob
import platform

from importlib import machinery

if sys.argv != ['setup.py', 'sdist']:

    if platform.system() != "Windows":
        raise RuntimeError("This package requires Windows")

    if sys.version_info < (3, 6):
        raise RuntimeError("This package requires Python 3.6 or later")

############################################################################

from setuptools import setup

from setuptools.extension import Extension

############################################################################

macros = [
    ("_CRT_SECURE_NO_WARNINGS", "1"),
    ("Py_LIMITED_API", "0x03060000"),
    ("STANDALONE", "1")
]

extra_compile_args = [
    "-IC:\\Program Files\\Microsoft SDKs\\Windows\\v7.0\\Include",
    "-IC:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include",
    "-IC:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.10586.0\\ucrt",
    "/DSTANDALONE"
]
extra_link_args = []


if 0:
    # enable this to debug a release build
    extra_compile_args.append("/Od")
    extra_compile_args.append("/Z7")
    extra_link_args.append("/DEBUG")
    macros.append(("VERBOSE", "1"))

_memimporter = Extension(
    "_memimporter",
    sources=glob.glob("source/*.c"),
    libraries=["user32", "shell32"],
    define_macros=macros,
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
)

if __name__ == "__main__":
    from tools import fixupver
    fixupver.fix_up("memimport.py")

    setup(
        name="memimport",
        version=fixupver.version,
        description="Helps import Python extensions from memory, e.g. extensions from Zip files or Web.",
        keywords="memory importer zip loader",
        long_description=open("README.md").read(),
        long_description_content_type="text/markdown",
        author="Thomas Heller <theller@ctypes.org>, Alberto Sottile <alby128@gmail.com>",
        maintainer="SeaHOH",
        maintainer_email="seahoh@gmail.com",
        url="http://github.com/SeaHOH/memimport",
        project_urls={
            "Tracker": "http://github.com/SeaHOH/memimport/issues"
        },
        license="MIT/X11 OR (MPL 2.0)",
        license_files=[
            "LICENSE.txt",
            "MIT-License.txt",
            "MPL2-License.txt",
        ],
        setup_requires=["wheel"],
        platforms="Windows",
        python_requires=">=3.6, <3.12",

        classifiers=[
            "Development Status :: 4 - Beta",
            "Environment :: Console",
            "License :: OSI Approved :: MIT License",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
            "Operating System :: Microsoft :: Windows",
            "Programming Language :: C",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: Implementation :: CPython",
            "Topic :: Software Development",
            "Topic :: Software Development :: Libraries",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "Topic :: System :: Software Distribution",
            "Topic :: Utilities",
        ],

        ext_modules=[_memimporter],
        py_modules=["memimport", "zipextimporter"],
    )
