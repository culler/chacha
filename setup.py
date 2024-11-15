from setuptools import setup
from distutils.extension import Extension
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        Extension(
            'chacha._chacha', ['src/_chacha/_chacha.pyx'],
            extra_compile_args=['-Wno-unreachable-code'],
            language='c',
        ),
    ),
)
