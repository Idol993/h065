import json
import re
from pathlib import Path

from dependency_auditor.parsers.python_parser import Dependency


def parse_pipfile_lock(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    if not path.is_file():
        return []

    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)

    deps: list[Dependency] = []
    source = str(path)

    for section_key, is_dev in (("default", False), ("develop", True)):
        section = data.get(section_key, {})
        for name, info in section.items():
            if not isinstance(info, dict):
                continue
            version_raw = info.get("version", "")
            version = version_raw.lstrip("=") if version_raw else "*"
            deps.append(Dependency(
                name=name,
                version_spec=version,
                ecosystem="pypi",
                source_file=source,
                is_dev=is_dev,
            ))

    return deps


def parse_package_lock(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    if not path.is_file():
        return []

    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)

    deps: list[Dependency] = []
    source = str(path)
    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 2:
        packages = data.get("packages", {})
        for pkg_path, info in packages.items():
            if not pkg_path or pkg_path == "":
                continue
            if not isinstance(info, dict):
                continue
            name = pkg_path.split("node_modules/")[-1]
            if not name:
                continue
            version = info.get("version", "*")
            is_dev = info.get("dev", False)
            deps.append(Dependency(
                name=name,
                version_spec=version,
                ecosystem="npm",
                source_file=source,
                is_dev=is_dev,
            ))
    else:
        dependencies = data.get("dependencies", {})
        for name, info in dependencies.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "*")
            is_dev = info.get("dev", False)
            deps.append(Dependency(
                name=name,
                version_spec=version,
                ecosystem="npm",
                source_file=source,
                is_dev=is_dev,
            ))

    return deps


def parse_yarn_lock(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    if not path.is_file():
        return []

    text = path.read_text(encoding="utf-8")
    source = str(path)
    deps: list[Dependency] = []

    entry_pattern = re.compile(
        r'^"(?P<full>[^"]+)":\s*$',
        re.MULTILINE,
    )
    version_pattern = re.compile(
        r'^\s+version\s+"(?P<version>[^"]+)"',
        re.MULTILINE,
    )

    entries = list(entry_pattern.finditer(text))
    for i, match in enumerate(entries):
        full = match.group("full")
        block_start = match.end()
        block_end = entries[i + 1].start() if i + 1 < len(entries) else len(text)
        block = text[block_start:block_end]

        version_match = version_pattern.search(block)
        if not version_match:
            continue
        version = version_match.group("version")

        names = re.findall(r'"([^@]+)@', full)
        name = names[0] if names else full.split("@")[0]

        deps.append(Dependency(
            name=name,
            version_spec=version,
            ecosystem="npm",
            source_file=source,
        ))

    return deps


def parse(filepath: str) -> list[Dependency]:
    name = Path(filepath).name.lower()
    if name == "pipfile.lock":
        return parse_pipfile_lock(filepath)
    if name == "package-lock.json":
        return parse_package_lock(filepath)
    if name == "yarn.lock":
        return parse_yarn_lock(filepath)
    return []
