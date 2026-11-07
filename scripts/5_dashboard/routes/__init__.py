"""
scripts/5_dashboard/routes/__init__.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Modular Flask Route Blueprints Package (Layer 4)
-----------------------------------------------------------------------------
"""

from .events_bp import events_bp
from .defense_bp import defense_bp
from .fleet_bp import fleet_bp
from .governance_bp import governance_bp
from .soc_siem_bp import soc_siem_bp
from .demo_bp import demo_bp

__all__ = [
    "events_bp",
    "defense_bp",
    "fleet_bp",
    "governance_bp",
    "soc_siem_bp",
    "demo_bp",
]

