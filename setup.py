from setuptools import setup, find_packages

long_description = open("README.md").read()

setup(
    name="tesla_bluetooth",
    version="0.2.0",
    description="Python interface for connecting to Tesla vehicles directly using the BLE API",
    readme="README.md",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Teslemetry/python-tesla-bluetooth",
    author="Brett Adams, Kaeden Brinkman, Lex Nastin, Kevin Dewald",
    author_email="admin@teslemetry.com",
    license="BSD 2-clause",
    packages=find_packages(exclude=["test", "example"]),
    install_requires=["simplepyble", "cryptography", "protobuf"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
    ],
)
