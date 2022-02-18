import os

import setuptools
from setuptools import setup, Extension


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


ssl_workaround = Extension('pykdeconnect.ssl_workaround',
                           sources=['src/ssl_workaround.c'],
                           include_dirs=['include'],
                           libraries=["ssl"])


setup(
    name="pykdeconnect",
    version="0.0.1",
    author="Adrian Freund",
    author_email="git@freundtech.com",
    description=("A python implementation of the kdeconnect protocol"),
    license="MIT",
    keywords="kde connect",
    url="https://github.com/freundTech/pykdeconnect",
    packages=setuptools.find_packages(),
    ext_modules=[ssl_workaround],
    long_description=read('README.rst'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
)
