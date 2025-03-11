from setuptools import setup, Extension
from Cython.Build import cythonize

ext_modules = [
    Extension(
        "dtls",
        ["dtls.pyx"],
        libraries=["ssl"],
    )
]

setup(
    ext_modules=cythonize(ext_modules)
)