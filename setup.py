"""Install ``vault`` as an importable package."""

from setuptools import setup, find_packages


setup(
    name='arxiv-vault',
    version='0.0.2',
    packages=['arxiv.vault'],
    zip_safe=False,
    install_requires=[
        'hvac==0.8.2'
    ]
)
