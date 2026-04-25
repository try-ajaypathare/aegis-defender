"""
Aegis attack registry — categorized simulations across infrastructure layers.

Categories:
  - performance     : CPU/RAM/disk/network resource pressure
  - service         : crash/degrade/latency on monitored services (Apache/MySQL/etc.)
  - security        : auth-related and intrusion patterns (Phase 2)
  - network         : connectivity/DNS/gateway failures (Phase 3)
  - infra           : backup/NTP/hardware (Phase 4)

All attacks are PURE SIMULATION. They register impact with the SimulationEngine
or set state-overlay flags; no real resources are consumed and no real services
are stopped.
"""
from __future__ import annotations

from typing import Type

from attacker.base_attack import BaseAttack

# Phase 1 — performance (existing 10) + service crash (NEW)
from attacker.attacks.cpu_spike import CPUSpike
from attacker.attacks.ram_flood import RAMFlood
from attacker.attacks.disk_fill import DiskFill
from attacker.attacks.traffic_flood import TrafficFlood
from attacker.attacks.combo import ComboAttack
from attacker.attacks.fork_bomb import ForkBomb
from attacker.attacks.slow_creep import SlowCreep
from attacker.attacks.memory_leak import MemoryLeak
from attacker.attacks.cryptomining_sim import CryptominingSim
from attacker.attacks.ransomware_sim import RansomwareSim
from attacker.attacks.service_crash import ServiceCrashAttack

# Phase 2 — security
from attacker.attacks.ssh_brute_force import SSHBruteForce
from attacker.attacks.cert_expire import CertExpire
from attacker.attacks.port_expose import PortExpose

# Phase 3 — network
from attacker.attacks.dns_blackhole import DNSBlackhole
from attacker.attacks.gateway_drop import GatewayDrop

# Phase 4 — infra
from attacker.attacks.backup_fail import BackupFail
from attacker.attacks.ntp_drift import NTPDrift
from attacker.attacks.hardware_warning import HardwareWarning


#
# Curated demo registry — 15 attacks across 5 infra-defender pillars.
# Removed: combo, fork_bomb, slow_creep, cryptomining_sim
#   (low demo value / redundant with cpu_spike + ransomware_sim).
# These classes are still importable above so the historical attacks/ folder
# stays intact, but they don't appear in the attacker UI.
#
REGISTRY: dict[str, Type[BaseAttack]] = {
    # ─────── Performance (resource pressure) ───────
    "cpu_spike":        CPUSpike,
    "ram_flood":        RAMFlood,
    "disk_fill":        DiskFill,
    "memory_leak":      MemoryLeak,

    # ─────── Service (Phase 1) ───────
    "service_crash":    ServiceCrashAttack,

    # ─────── Security (Phase 2 + repositioned ransomware) ───────
    "ssh_brute_force":  SSHBruteForce,
    "cert_expire":      CertExpire,
    "port_expose":      PortExpose,
    "ransomware_sim":   RansomwareSim,

    # ─────── Network (Phase 3 + DDoS from old traffic_flood) ───────
    "traffic_flood":    TrafficFlood,
    "dns_blackhole":    DNSBlackhole,
    "gateway_drop":     GatewayDrop,

    # ─────── Infrastructure (Phase 4) ───────
    "backup_fail":      BackupFail,
    "ntp_drift":        NTPDrift,
    "hardware_warning": HardwareWarning,
}


def get_attack_list() -> list[dict]:
    return [
        {
            "type": key,
            "name": cls.name,
            "category": cls.category,
            "description": cls.description,
        }
        for key, cls in REGISTRY.items()
    ]
