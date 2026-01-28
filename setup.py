from setuptools import setup, find_packages

setup(
    name="yaml-validators",
    version="1.0.0",
    description="YAML validators for Helm, Kubernetes, and Ansible",
    author="Artur",
    python_requires=">=3.8",
    py_modules=[
        "yaml_router",
        "kubernetes_validator", 
        "helm_validator",
        "shared_constants",  # <-- WICHTIG: Hier hinzufügen!
    ],
    install_requires=[
        "ruamel.yaml>=0.17",
        "yamllint>=1.26",
    ],
    entry_points={
        "console_scripts": [
            "yaml-router=yaml_router:main",
            "k8s-validator=kubernetes_validator:main",
            "helm-validator=helm_validator:main",
        ],
    },
)