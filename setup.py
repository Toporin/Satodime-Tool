#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import importlib.util
import argparse
import subprocess

from setuptools import setup, find_packages
from setuptools.command.install import install

MIN_PYTHON_VERSION = "3.6.1"
_min_python_version_tuple = tuple(map(int, (MIN_PYTHON_VERSION.split("."))))

# todo: check actual minimum version required...
if sys.version_info[:3] < _min_python_version_tuple:
    sys.exit("Error: SatodimeTool requires Python version >= %s..." % MIN_PYTHON_VERSION)

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'SatodimeTool/version.py')
version_module = version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

setup(
    name="SatodimeTool",
    version=version.SATODIMETOOL_VERSION,
    python_requires='>={}'.format(MIN_PYTHON_VERSION),
    install_requires=requirements,
    packages=['SatodimeTool'],
    package_dir={
        'SatodimeTool': 'SatodimeTool'
    },
    package_data={
        'SatodimeTool': ['*.ini', '*.png', '*.ico', 'help/*.txt'],
    },

    scripts=['SatodimeTool/satodime_tool.py'],
    description="Utility to set up and use a Satodime",
    author="Toporin",
    author_email="support@satochip.io",
    license="GNU Lesser General Public License v3 (LGPLv3)",
    url='https://github.com/Toporin/SatodimeTool',
    project_urls={
        'Github': 'https://github.com/Toporin',
        'Webshop': 'https://satochip.io/',
        'Telegram': 'https://t.me/Satochip',
        'Twitter': 'https://twitter.com/satochipwallet',
        'Source': 'https://github.com/Toporin/SatodimeTool',
        'Tracker': 'https://github.com/Toporin/SatodimeTool/issues',
    },
    long_description="""Utility to set up and use a Satodime""",
)
