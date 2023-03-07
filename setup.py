from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.0.9'
DESCRIPTION = 'A quantum proof (post-quantum) implementation of the NTRU algorithm'

# Setting up
setup(
    name="pq_ntru",
    version=VERSION,
    url="https://github.com/protdos/pq-ntru",
    author="CodingLive | ProtDos",
    author_email="<rootcode@duck.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=['numpy', 'sympy'],
    keywords=['python', "python3", "post-quantum", "ntru", "quantum-proof", "crypto", "cryptography", "lattice", "svp", "numpy", "sympy"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
