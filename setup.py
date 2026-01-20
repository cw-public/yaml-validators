from setuptools import setup

setup(
    name='yaml-validators',
    version='1.0.0',
    py_modules=[
        'yaml_router',
        'kubernetes_validator',
        'helm_validator',
    ],
    install_requires=[
        'ruamel.yaml>=0.17.0',
        'yamllint>=1.32',
        ],
    entry_points={
        'console_scripts': [
            'yaml-router=yaml_router:main',
        ],
    },
)