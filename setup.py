from setuptools import setup, Extension

setup(
    ext_modules=[
        Extension('pykdeconnect.ssl_workaround',
                  sources=['src/ssl_workaround.c'],
                  include_dirs=['include'],
                  libraries=["ssl"])
    ]
)
