import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from pip_requirements_parser import RequirementsFile


@dataclass
class Dependency:
    name: str
    version_spec: str
    ecosystem: str = "pypi"
    source_file: str = ""
    is_dev: bool = False
    dependencies: list[str] = field(default_factory=list)


def parse_requirements_txt(file_path: str) -> list[Dependency]:
    path = Path(file_path)
    if not path.is_file():
        return []

    deps: list[Dependency] = []
    parsed = RequirementsFile.from_file(str(path))

    for req in parsed.requirements:
        if req.name is None:
            continue

        name = req.name
        specifier = str(req.specifier) if req.specifier else "*"
        extras = ""
        if req.extras:
            extras = "[" + ",".join(sorted(req.extras)) + "]"

        deps.append(Dependency(
            name=name,
            version_spec=extras + specifier if extras else specifier,
            source_file=str(path),
        ))

    return deps


def _parse_pep508_spec(spec: str) -> tuple[str, str]:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)", spec.strip())
    if not match:
        return spec, "*"
    name = match.group(1)
    version_part = match.group(2).strip()
    return name, version_part if version_part else "*"


def _parse_poetry_section(
    deps_dict: dict,
    source_file: str,
    is_dev: bool = False,
) -> list[Dependency]:
    result: list[Dependency] = []
    for name, value in deps_dict.items():
        if name == "python":
            continue

        if isinstance(value, str):
            version_spec = value if value else "*"
        elif isinstance(value, dict):
            version_spec = value.get("version", "*")
            if not version_spec:
                version_spec = "*"
            if value.get("optional", False):
                continue
        else:
            version_spec = "*"

        result.append(Dependency(
            name=name,
            version_spec=version_spec,
            source_file=source_file,
            is_dev=is_dev,
        ))

    return result


def _parse_project_section(
    dep_list: list[str],
    source_file: str,
    is_dev: bool = False,
) -> list[Dependency]:
    result: list[Dependency] = []
    for spec in dep_list:
        name, version_spec = _parse_pep508_spec(spec)
        if name:
            result.append(Dependency(
                name=name,
                version_spec=version_spec,
                source_file=source_file,
                is_dev=is_dev,
            ))
    return result


def parse_pyproject_toml(file_path: str) -> list[Dependency]:
    path = Path(file_path)
    if not path.is_file():
        return []

    if tomllib is None:
        return []

    with open(path, "rb") as f:
        data = tomllib.load(f)

    deps: list[Dependency] = []
    source = str(path)

    project = data.get("project", {})
    project_deps = project.get("dependencies", [])
    if project_deps:
        deps.extend(_parse_project_section(project_deps, source))

    optional_deps = project.get("optional-dependencies", {})
    for group_name, group_deps in optional_deps.items():
        is_dev = group_name.lower() in ("dev", "test", "testing", "development")
        deps.extend(_parse_project_section(group_deps, source, is_dev=is_dev))

    poetry = data.get("tool", {}).get("poetry", {})
    poetry_deps = poetry.get("dependencies", {})
    if poetry_deps:
        deps.extend(_parse_poetry_section(poetry_deps, source))

    poetry_dev_deps = poetry.get("group", {})
    for group_name, group_data in poetry_dev_deps.items():
        group_dep_dict = group_data.get("dependencies", {})
        is_dev = group_name != "main"
        deps.extend(_parse_poetry_section(group_dep_dict, source, is_dev=is_dev))

    poetry_dev_old = poetry.get("dev-dependencies", {})
    if poetry_dev_old:
        deps.extend(_parse_poetry_section(poetry_dev_old, source, is_dev=True))

    return deps


def parse(file_path: str) -> list[Dependency]:
    path = Path(file_path)
    name = path.name.lower()

    if name == "requirements.txt" or name.endswith(".txt"):
        return parse_requirements_txt(file_path)
    if name == "pyproject.toml":
        return parse_pyproject_toml(file_path)

    return []
