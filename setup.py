"""Install ``vault`` as an importable package."""

from setuptools import setup, find_packages


setup(
    name='arxiv-vault',
    version='0.0.7',
    packages=[f'arxiv.{package}' for package in find_packages('arxiv')],
    zip_safe=False,
    install_requires=[
        'hvac==0.8.2'
    ]
)
