import sys
import warnings

from setuptools import setup, Extension
from setuptools.dist import Distribution

# ccompiler isn't ported to setuptools yet
with warnings.catch_warnings():
    from distutils.ccompiler import new_compiler


# Function taken from cryptography under the BSD license
def compiler_type():
    """
    Gets the compiler type from distutils. On Windows with MSVC it will be
    "msvc". On macOS and linux it is "unix".
    """
    dist = Distribution()
    dist.parse_config_files()
    cmd = dist.get_command_obj("build")
    cmd.ensure_finalized()
    compiler = new_compiler(compiler=cmd.compiler)
    return compiler.compiler_type


if sys.platform == "win32" and compiler_type() == "msvc":
    ssl_lib = "libssl"
else:
    ssl_lib = "ssl"


setup(
    ext_modules=[
        Extension('pykdeconnect.ssl_workaround',
                  sources=['src/ssl_workaround.c'],
                  include_dirs=['include'],
                  libraries=[ssl_lib])
    ]
)
