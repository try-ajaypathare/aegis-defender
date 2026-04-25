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


REGISTRY: dict[str, Type[BaseAttack]] = {
    # ─────── Performance (resource pressure) ───────
    "cpu_spike":        CPUSpike,
    "ram_flood":        RAMFlood,
    "disk_fill":        DiskFill,
    "traffic_flood":    TrafficFlood,
    "combo":            ComboAttack,
    "fork_bomb":        ForkBomb,
    "slow_creep":       SlowCreep,
    "memory_leak":      MemoryLeak,
    "cryptomining_sim": CryptominingSim,
    "ransomware_sim":   RansomwareSim,

    # ─────── Service (NEW — Phase 1) ───────
    "service_crash":    ServiceCrashAttack,
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
