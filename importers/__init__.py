"""MBCP importers (SPEC §4): distribution wedge, not conformance evidence.

Each importer attaches a sensitivity marker and defaults
``consent.exportable = false`` when the source has no consent field.
"""

from . import chatgpt, hermes
from ._common import ImportFormatError

__all__ = ["chatgpt", "hermes", "ImportFormatError"]
