import os
from typing import Any, Optional

import yaml


DEFAULT_CONFIG = {
    "ignore_packages": [],
    "ignore_cves": [],
    "severity_threshold": "low",
    "license_threshold": "high",
    "fail_on_high_vulnerability": True,
    "fail_on_circular_dependency": True,
    "fail_on_copyleft_license": True,
    "max_depth": 5,
    "oss_index_url": "https://ossindex.sonatype.org/api/v3/component-report",
    "pypi_api_url": "https://pypi.org/pypi",
    "npm_api_url": "https://registry.npmjs.org",
    "maven_api_url": "https://search.maven.org/solrsearch/select",
}


class ConfigLoader:
    def __init__(self, config_path: Optional[str] = None):
        self._config = DEFAULT_CONFIG.copy()
        if config_path and os.path.isfile(config_path):
            self._load(config_path)
        else:
            for candidate in [".dep-audit.yml", ".dep-audit.yaml", "dep-audit.yml", "dep-audit.yaml"]:
                if os.path.isfile(candidate):
                    self._load(candidate)
                    break

    def _load(self, path: str):
        with open(path, 'r', encoding='utf-8') as f:
            user_config = yaml.safe_load(f)
        if user_config and isinstance(user_config, dict):
            self._config.update(user_config)

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    @property
    def ignore_packages(self) -> list:
        return self._config.get("ignore_packages", [])

    @property
    def ignore_cves(self) -> list:
        return self._config.get("ignore_cves", [])

    @property
    def fail_on_high_vulnerability(self) -> bool:
        return self._config.get("fail_on_high_vulnerability", True)

    @property
    def fail_on_circular_dependency(self) -> bool:
        return self._config.get("fail_on_circular_dependency", True)

    @property
    def fail_on_copyleft_license(self) -> bool:
        return self._config.get("fail_on_copyleft_license", True)

    @property
    def max_depth(self) -> int:
        return self._config.get("max_depth", 5)

    @property
    def oss_index_url(self) -> str:
        return self._config.get("oss_index_url", DEFAULT_CONFIG["oss_index_url"])

    @property
    def pypi_api_url(self) -> str:
        return self._config.get("pypi_api_url", DEFAULT_CONFIG["pypi_api_url"])

    @property
    def npm_api_url(self) -> str:
        return self._config.get("npm_api_url", DEFAULT_CONFIG["npm_api_url"])

    @property
    def maven_api_url(self) -> str:
        return self._config.get("maven_api_url", DEFAULT_CONFIG["maven_api_url"])
