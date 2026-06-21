import json
from pathlib import Path

from dependency_auditor.parsers.python_parser import Dependency


def parse_package_json(filepath: str) -> list:
    path = Path(filepath)
    if not path.is_file():
        return []

    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    deps: list[Dependency] = []
    source = str(path)

    sections = [
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", True),
        ("optionalDependencies", False),
    ]

    for section_key, is_dev in sections:
        section = data.get(section_key)
        if not section or not isinstance(section, dict):
            continue
        for name, version_spec in section.items():
            deps.append(Dependency(
                name=name,
                version_spec=version_spec if version_spec else "*",
                ecosystem="npm",
                source_file=source,
                is_dev=is_dev,
            ))

    return deps


def parse(file_path: str) -> list:
    path = Path(file_path)
    name = path.name.lower()

    if name == "package.json":
        return parse_package_json(file_path)

    return []
