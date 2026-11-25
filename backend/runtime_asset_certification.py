"""Compatibility alias to the single, import-safe release verifier."""
import sys as _sys

from dc_release_gate import runtime_asset_certification as _implementation

_sys.modules[__name__] = _implementation
