from setuptools import setup, find_packages

setup(
    name="dependency-auditor",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "dependency_auditor": ["templates/*.html"],
    },
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "requests>=2.28",
        "pip-requirements-parser>=32.0",
        "node-semver>=0.2.0",
        "lxml>=4.9",
        "networkx>=3.1",
        "jinja2>=3.1",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "dep-audit=dependency_auditor.cli:cli",
        ],
    },
    python_requires=">=3.11",
)
