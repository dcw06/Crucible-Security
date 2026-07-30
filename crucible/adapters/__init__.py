"""Platform adapters for Crucible application targets."""

from .desktop import DesktopArtifactAdapter
from .web import WebAppAdapter

__all__ = ["DesktopArtifactAdapter", "WebAppAdapter"]
