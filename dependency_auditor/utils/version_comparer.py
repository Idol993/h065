import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class VersionConstraint:
    operator: str
    version: tuple


@dataclass
class VersionRange:
    constraints: list


def parse_version(version_str: str) -> tuple:
    parts = re.split(r'[.\-]', version_str.strip())
    result = []
    for part in parts:
        match = re.match(r'(\d+)', part)
        if match:
            result.append(int(match.group(1)))
        else:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result[:3])


def version_to_str(version: tuple) -> str:
    return '.'.join(str(p) for p in version)


def compare_versions(v1: tuple, v2: tuple) -> int:
    for a, b in zip(v1, v2):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(v1) < len(v2):
        return -1
    if len(v1) > len(v2):
        return 1
    return 0


def satisfies_constraint(version: tuple, constraint: VersionConstraint) -> bool:
    cmp = compare_versions(version, constraint.version)
    if constraint.operator == '==':
        return cmp == 0
    elif constraint.operator == '!=':
        return cmp != 0
    elif constraint.operator == '>=':
        return cmp >= 0
    elif constraint.operator == '<=':
        return cmp <= 0
    elif constraint.operator == '>':
        return cmp > 0
    elif constraint.operator == '<':
        return cmp < 0
    elif constraint.operator == '~=':
        prefix = constraint.version[:-1]
        next_version = prefix[:-1] + (prefix[-1] + 1,)
        return compare_versions(version, constraint.version) >= 0 and compare_versions(version, next_version) < 0
    elif constraint.operator == '^=':
        if constraint.version[0] > 0:
            next_major = (constraint.version[0] + 1, 0, 0)
        elif constraint.version[1] > 0:
            next_minor = (constraint.version[0], constraint.version[1] + 1, 0)
            return compare_versions(version, constraint.version) >= 0 and compare_versions(version, next_minor) < 0
        else:
            next_patch = (constraint.version[0], constraint.version[1], constraint.version[2] + 1)
            return compare_versions(version, constraint.version) >= 0 and compare_versions(version, next_patch) < 0
        return compare_versions(version, constraint.version) >= 0 and compare_versions(version, next_major) < 0
    return False


def parse_version_range(spec: str) -> Optional[VersionRange]:
    if not spec or not spec.strip():
        return None

    spec = spec.strip()
    constraints = []

    if spec.startswith('~'):
        ver = parse_version(spec[1:])
        constraints.append(VersionConstraint('~=', ver))
    elif spec.startswith('^'):
        ver = parse_version(spec[1:])
        constraints.append(VersionConstraint('^=', ver))
    else:
        pattern = r'(>=|<=|!=|==|>|<)([\d][\d.\-]*)'
        matches = re.findall(pattern, spec)
        if matches:
            for op, ver_str in matches:
                constraints.append(VersionConstraint(op, parse_version(ver_str)))
        else:
            ver = parse_version(spec)
            constraints.append(VersionConstraint('==', ver))

    if not constraints:
        return None
    return VersionRange(constraints)


def version_satisfies_range(version: tuple, version_range: VersionRange) -> bool:
    return all(satisfies_constraint(version, c) for c in version_range.constraints)


def lowest_version_in_range(version_range: VersionRange) -> Optional[tuple]:
    min_version = None
    for constraint in version_range.constraints:
        if constraint.operator in ('>=', '==', '~=','^='):
            if min_version is None or compare_versions(constraint.version, min_version) > 0:
                min_version = constraint.version
    return min_version
