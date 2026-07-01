from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Type

from .models import Finding, ScanContext
from .request_engine import RequestEngine


class DetectorPlugin(ABC):
    """Base class for all detector plugins."""

    name = "base"

    @abstractmethod
    def run(self, context: ScanContext, engine: RequestEngine) -> List[Finding]:
        """Execute vulnerability checks and return findings."""


class DetectorRegistry:
    """Simple plugin registry for detector discovery and execution."""

    def __init__(self) -> None:
        self._plugins: Dict[str, Type[DetectorPlugin]] = {}

    def register(self, plugin_cls: Type[DetectorPlugin]) -> None:
        self._plugins[plugin_cls.name] = plugin_cls

    def create_all(self) -> List[DetectorPlugin]:
        return [plugin_cls() for plugin_cls in self._plugins.values()]

    def names(self) -> List[str]:
        return sorted(self._plugins.keys())
