import re
from pathlib import Path

from lxml import etree

from dependency_auditor.parsers.python_parser import Dependency

_MAVEN_NS = "http://maven.apache.org/POM/4.0.0"
_NS = {"m": _MAVEN_NS}

_GRADLE_DEP_RE = re.compile(
    r"""(?x)
    (\w+(?:\s*\([^)]*\))?)   # configuration: implementation, testImplementation('...'), api, etc.
    \s+
    ['"]                      # opening quote
    ([^'"]+)                  # coordinate string
    ['"]                      # closing quote
    """
)


def _resolve_property(version: str, properties: dict[str, str]) -> str:
    if version and version.startswith("${") and version.endswith("}"):
        key = version[2:-1]
        return properties.get(key, version)
    return version


def parse_pom_xml(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    if not path.is_file():
        return []

    try:
        tree = etree.parse(str(path))
    except etree.XMLSyntaxError:
        return []

    root = tree.getroot()
    source = str(path)

    properties: dict[str, str] = {}
    props_el = root.find("m:properties", _NS)
    if props_el is not None:
        for child in props_el:
            tag = etree.QName(child.tag).localname if "}" in child.tag else child.tag
            properties[tag] = child.text or ""

    managed_versions: dict[str, str] = {}
    dm = root.find("m:dependencyManagement", _NS)
    if dm is not None:
        deps_el = dm.find("m:dependencies", _NS)
        if deps_el is not None:
            for dep in deps_el.findall("m:dependency", _NS):
                g = dep.findtext("m:groupId", default="", namespaces=_NS).strip()
                a = dep.findtext("m:artifactId", default="", namespaces=_NS).strip()
                v = dep.findtext("m:version", default="", namespaces=_NS).strip()
                if g and a:
                    managed_versions[f"{g}:{a}"] = _resolve_property(v, properties)

    deps: list[Dependency] = []
    for parent in root.findall("m:dependencies", _NS):
        for dep in parent.findall("m:dependency", _NS):
            g = dep.findtext("m:groupId", default="", namespaces=_NS).strip()
            a = dep.findtext("m:artifactId", default="", namespaces=_NS).strip()
            v = dep.findtext("m:version", default="", namespaces=_NS).strip()

            if not g or not a:
                continue

            coordinate = f"{g}:{a}"

            if v:
                v = _resolve_property(v, properties)
            else:
                v = managed_versions.get(coordinate, "*")

            if not v:
                v = "*"

            scope = dep.findtext("m:scope", default="", namespaces=_NS).strip()
            is_dev = scope in ("test", "provided")

            deps.append(Dependency(
                name=coordinate,
                version_spec=v,
                ecosystem="maven",
                source_file=source,
                is_dev=is_dev,
            ))

    return deps


def parse_build_gradle(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    if not path.is_file():
        return []

    source = str(path)
    content = path.read_text(encoding="utf-8")

    deps: list[Dependency] = []

    for match in _GRADLE_DEP_RE.finditer(content):
        config = match.group(1).strip().split("(")[0].strip()
        coord = match.group(2).strip()

        parts = coord.split(":")
        if len(parts) < 2:
            continue

        group = parts[0]
        artifact = parts[1]
        version = parts[2] if len(parts) >= 3 else "*"

        is_dev = config.startswith("test") or config in ("testRuntimeOnly", "testCompileOnly")

        deps.append(Dependency(
            name=f"{group}:{artifact}",
            version_spec=version if version else "*",
            ecosystem="maven",
            source_file=source,
            is_dev=is_dev,
        ))

    return deps


def parse(filepath: str) -> list[Dependency]:
    path = Path(filepath)
    name = path.name.lower()

    if name == "pom.xml":
        return parse_pom_xml(filepath)
    if name == "build.gradle":
        return parse_build_gradle(filepath)

    return []
