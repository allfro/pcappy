#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='pcappy',
    author='Nadeem Douba',
    version='0.3',
    author_email='ndouba@gmail.com',
    description='Pure Python wrapper for PCAP library.',
    license='GPL',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf' ] # list of resources
    },
    install_requires=[
        # Name of packages required for easy_install
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)