"""Maps `InventorySourceKind` to its adapter module.

Each adapter module is a set of two functions, `test_connection()` and
`fetch()`, matching `ApiAdapter` structurally — mypy checks a module
against a `Protocol` the same way it checks a class, so no wrapper class is
needed here.
"""

from __future__ import annotations

from ...core.models.enums import InventorySourceKind
from . import azure_arm, desktop_central, ms_graph
from .base import ApiAdapter

_ADAPTERS: dict[InventorySourceKind, ApiAdapter] = {
    InventorySourceKind.API_DESKTOP_CENTRAL: desktop_central,
    InventorySourceKind.API_AZURE_ARM: azure_arm,
    InventorySourceKind.API_MS_GRAPH: ms_graph,
}


def adapter_for(kind: InventorySourceKind) -> ApiAdapter:
    adapter = _ADAPTERS.get(kind)
    if adapter is None:
        raise ValueError(f"No adapter registered for {kind.value}")
    return adapter
