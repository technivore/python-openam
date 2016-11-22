#!/usr/bin/env python

# $Revision $

from distutils.core import setup, Command
import os

# Get version from pkg index
from openam import __version__, __author_name__, __author_email__


class CleanCommand(Command):
    description = "cleans up non-package files. (dist, build, etc.)"
    user_options = []

    def initialize_options(self):
        self.files = None

    def finalize_options(self):
        self.files = './build ./dist ./MANIFEST ./*.pyc examples/*.pyc ./*.egg-info'

    def run(self):
        print 'Cleaning: %s' % self.files
        os.system('rm -rf ' + self.files)

long_desc = """
Python interface for OpenAM.
"""

setup(
    name='python-openam',
    version=__version__,
    author=__author_name__,
    author_email=__author_email__,
    license='MIT',
    py_modules=['openam'],
    url='https://github.com/technivore/python-openam/',
    description='Python OpenAM interface',
    long_description=long_desc,
    scripts=[],
    cmdclass={
        'clean': CleanCommand,
    }
)
