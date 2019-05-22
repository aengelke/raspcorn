#!/usr/bin/python3

from setuptools import setup

setup(
    name="Raspcorn",
    version="0.1",
    packages=[
        "raspcorn"
    ],
    install_requires=[
        "unicorn >= 1.0",
        "pyelftools >= 0.25",
    ],

    include_package_data=True,
)
