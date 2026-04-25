"""
Aegis state modules — centralized in-memory state for hybrid real+simulated checks.

Each state module follows the same pattern:
  - REAL probes update `real_*` fields
  - SIMULATED incidents update `sim_*` fields (overlay)
  - The "effective" status reported to dashboards = sim overlay if active, else real

This lets us safely simulate incidents without touching actual services.
"""
from .service_state import service_state
from .auth_state import auth_state
from .cert_state import cert_state
from .network_state import network_state
from .infra_state import infra_state

__all__ = [
    "service_state",
    "auth_state",
    "cert_state",
    "network_state",
    "infra_state",
]
