from setuptools import setup
from distutils.extension import Extension
import sys, os

have_chacha_pyx = os.path.exists('src/_chacha/_chacha.pyx')
have_chacha_c = os.path.exists('src/_chacha/_chacha.c')

compiler_options = []
if sys.platform != 'win32':
    compiler_options.append('-Wno-unreachable-code')
if sys.platform == 'darwin':
    compiler_options.append('-mmacosx-version-min=10.9')

try:
    from Cython.Build import cythonize
except ImportError:
    if not have_chacha_c:
        print('You must install Cython to build this chafe package.')
        sys.exit(1)
    sdist = True

if not have_chacha_pyx:
    extension = [
        Extension(
            'chacha._chacha', ['src/_chacha/_chacha.c'],
            extra_compile_args=compiler_options,
            language='c')
    ]
else:
    extension = cythonize(
        Extension(
            'chacha._chacha', ['src/_chacha/_chacha.pyx'],
            extra_compile_args=compiler_options,
            language='c'),
    )
setup(ext_modules=extension)
