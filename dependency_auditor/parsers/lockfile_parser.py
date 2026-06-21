import json
import re
from pathlib import Path

from dependency_auditor.parsers.python_parser import Dependency


def _extract_dep_names(deps_dict: dict) -> list[str]:
    names = []
    if deps_dict and isinstance(deps_dict, dict):
        for name in deps_dict.keys():
            names.append(name)
    return names


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
            sub_deps = _extract_dep_names(info.get("dependencies", {}))
            deps.append(Dependency(
                name=name,
                version_spec=version,
                ecosystem="pypi",
                source_file=source,
                is_dev=is_dev,
                dependencies=sub_deps,
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

    name_to_deps: dict[str, list[str]] = {}

    if lockfile_version >= 2:
        packages = data.get("packages", {})
        name_to_info: dict[str, dict] = {}
        for pkg_path, info in packages.items():
            if not pkg_path or pkg_path == "":
                continue
            if not isinstance(info, dict):
                continue
            name = pkg_path.split("node_modules/")[-1]
            if not name:
                continue
            name_to_info[name] = info

        for name, info in name_to_info.items():
            sub_deps = _extract_dep_names(info.get("dependencies", {}))
            if not sub_deps:
                sub_deps = _extract_dep_names(info.get("requires", {}))
            name_to_deps[name] = sub_deps

        for name, info in name_to_info.items():
            version = info.get("version", "*")
            is_dev = info.get("dev", False)
            license_field = info.get("license")
            dep = Dependency(
                name=name,
                version_spec=version,
                ecosystem="npm",
                source_file=source,
                is_dev=is_dev,
                dependencies=name_to_deps.get(name, []),
            )
            if license_field:
                dep._lock_licenses = [license_field] if isinstance(license_field, str) else list(license_field)
            deps.append(dep)
    else:
        name_to_info: dict[str, dict] = {}
        dependencies = data.get("dependencies", {})
        for name, info in dependencies.items():
            if not isinstance(info, dict):
                continue
            name_to_info[name] = info

        for name, info in name_to_info.items():
            sub_deps = _extract_dep_names(info.get("requires", {}))
            name_to_deps[name] = sub_deps

        for name, info in name_to_info.items():
            version = info.get("version", "*")
            is_dev = info.get("dev", False)
            license_field = info.get("license")
            dep = Dependency(
                name=name,
                version_spec=version,
                ecosystem="npm",
                source_file=source,
                is_dev=is_dev,
                dependencies=name_to_deps.get(name, []),
            )
            if license_field:
                dep._lock_licenses = [license_field] if isinstance(license_field, str) else list(license_field)
            deps.append(dep)

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
    deps_start_pattern = re.compile(
        r'^\s+dependencies:\s*$',
        re.MULTILINE,
    )
    dep_entry_pattern = re.compile(
        r'^\s+("[^"]+"|\S+)\s+"[^"]+"',
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

        sub_deps: list[str] = []
        deps_match = deps_start_pattern.search(block)
        if deps_match:
            dep_lines_start = deps_match.end()
            dep_block = text[dep_lines_start:block_end]
            for dep_match in dep_entry_pattern.finditer(dep_block):
                dep_str = dep_match.group(1).strip('"')
                dep_name = dep_str.split("@")[0]
                sub_deps.append(dep_name)

        deps.append(Dependency(
            name=name,
            version_spec=version,
            ecosystem="npm",
            source_file=source,
            dependencies=sub_deps,
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
