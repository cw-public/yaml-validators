from setuptools import setup, find_packages

setup(
    name="yaml-validators",
    version="2.0.0",
    description="Unified YAML validators for Helm, Kubernetes, and Ansible",
    author="Your Name",
    python_requires=">=3.8",
    py_modules=[
        "yaml_router",
        "unified_validator",
        "helm_trimmer",
        "shared_constants",
    ],
    install_requires=[
        "ruamel.yaml>=0.17",
        "yamllint>=1.26",
    ],
    entry_points={
        "console_scripts": [
            "yaml-router=yaml_router:main",
            "unified-validator=unified_validator:main",
        ],
    },
)