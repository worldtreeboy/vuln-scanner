"""Configuration file support for Vibehunter scanners.

Loads .vibehunter.yml from the project root (or specified path) and provides
custom sources, sinks, sanitizers, path exclusions, and suppression settings.

Config format example:

    sources:
      java:
        - "getCustomInput"
      php:
        - "$customGlobal"
      js:
        - "getUntrustedData"

    sinks:
      java:
        sql: ["customQuery", "rawExecute"]
        command: ["shellRun"]
      php:
        sql: ["customDbExec"]

    sanitizers:
      java:
        universal: ["MySanitizer.clean"]
        sql: ["MyEscaper.escapeSQL"]
      php:
        universal: ["customSanitize"]

    exclude_paths:
      - "vendor/"
      - "test/"
      - "**/*_test.java"

    suppression_keyword: "nosec"
    min_confidence: "HIGH"
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class VibehunterConfig:
    """Parsed configuration from .vibehunter.yml."""
    custom_sources: Dict[str, List[str]] = field(default_factory=dict)
    custom_sinks: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    custom_sanitizers: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    exclude_paths: List[str] = field(default_factory=list)
    suppression_keyword: str = "nosec"
    min_confidence: str = "HIGH"

    def get_sources(self, language: str) -> List[str]:
        """Get custom sources for a given language."""
        return self.custom_sources.get(language, [])

    def get_sinks(self, language: str, category: str = None) -> List[str]:
        """Get custom sinks for a given language and optional category."""
        lang_sinks = self.custom_sinks.get(language, {})
        if category:
            return lang_sinks.get(category, [])
        # Return all sinks flattened
        result = []
        for sinks in lang_sinks.values():
            result.extend(sinks)
        return result

    def get_sanitizers(self, language: str, category: str = None) -> List[str]:
        """Get custom sanitizers for a given language and optional category."""
        lang_sans = self.custom_sanitizers.get(language, {})
        if category:
            return lang_sans.get(category, [])
        result = []
        for sans in lang_sans.values():
            result.extend(sans)
        return result

    def should_exclude(self, file_path: str) -> bool:
        """Check if a file path matches any exclusion pattern."""
        import fnmatch
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
            # Also check if any path component matches
            if pattern.endswith('/') and pattern.rstrip('/') in file_path.split(os.sep):
                return True
        return False


def load_config(target_path: str, config_path: str = None) -> Optional[VibehunterConfig]:
    """Load Vibehunter configuration.

    Args:
        target_path: The scan target path (used to find .vibehunter.yml)
        config_path: Explicit config path (overrides auto-discovery)

    Returns:
        VibehunterConfig if found, None otherwise.
    """
    if not HAS_YAML:
        return None

    if config_path:
        if os.path.isfile(config_path):
            return _parse_config(config_path)
        return None

    # Walk up from target_path to find .vibehunter.yml
    search_dir = os.path.abspath(target_path)
    if os.path.isfile(search_dir):
        search_dir = os.path.dirname(search_dir)

    while True:
        candidate = os.path.join(search_dir, '.vibehunter.yml')
        if os.path.isfile(candidate):
            return _parse_config(candidate)
        # Also check .vibehunter.yaml
        candidate = os.path.join(search_dir, '.vibehunter.yaml')
        if os.path.isfile(candidate):
            return _parse_config(candidate)
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break  # Reached filesystem root
        search_dir = parent

    return None


def _parse_config(config_path: str) -> VibehunterConfig:
    """Parse a .vibehunter.yml file into a VibehunterConfig."""
    with open(config_path, 'r') as f:
        data = yaml.safe_load(f) or {}

    config = VibehunterConfig()

    # Parse sources
    sources = data.get('sources', {})
    if isinstance(sources, dict):
        for lang, items in sources.items():
            if isinstance(items, list):
                config.custom_sources[lang] = [str(s) for s in items]

    # Parse sinks
    sinks = data.get('sinks', {})
    if isinstance(sinks, dict):
        for lang, categories in sinks.items():
            if isinstance(categories, dict):
                config.custom_sinks[lang] = {}
                for cat, items in categories.items():
                    if isinstance(items, list):
                        config.custom_sinks[lang][cat] = [str(s) for s in items]

    # Parse sanitizers
    sanitizers = data.get('sanitizers', {})
    if isinstance(sanitizers, dict):
        for lang, categories in sanitizers.items():
            if isinstance(categories, dict):
                config.custom_sanitizers[lang] = {}
                for cat, items in categories.items():
                    if isinstance(items, list):
                        config.custom_sanitizers[lang][cat] = [str(s) for s in items]

    # Parse exclude_paths
    exclude = data.get('exclude_paths', [])
    if isinstance(exclude, list):
        config.exclude_paths = [str(p) for p in exclude]

    # Parse simple settings
    config.suppression_keyword = str(data.get('suppression_keyword', 'nosec'))
    config.min_confidence = str(data.get('min_confidence', 'HIGH'))

    return config
