from setuptools import setup

setup(
    name='yaml-validators',
    version='1.0.0',
    py_modules=[
        'yaml_router',
        'kubernetes_validator',
        'helm_validator',
    ],
    install_requires=['ruamel.yaml>=0.17.0'],
)