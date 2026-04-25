"""
Aegis — Self-Healing Infrastructure Defender
Main entry point.

Starts:
  - Monitor thread (collects performance metrics)
  - Defender orchestrator (subscribes to events → AI+rules+actions)
  - Security watchers (process genealogy, network, registry, file integrity, USB)
  - Aegis check threads (service health, security audit, network probe, infra audit)
  - Defender API server (port 8000)
  - Attacker API server (port 8001)
  - Kill-switch hotkey listener (Ctrl+Shift+Q)

Run:
    python main.py

Stop:
    Ctrl+C
"""
from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path

# Make sure our package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

from attacker.api import create_app as create_attacker_app  # noqa: E402
from attacker.safety_guard import guard  # noqa: E402
from defender.api import create_app as create_defender_app  # noqa: E402
from defender.checks import (  # noqa: E402
    InfraAuditCheck,
    NetworkProbeCheck,
    SecurityAuditCheck,
    ServiceHealthCheck,
)
from defender.monitor import Monitor  # noqa: E402
from defender.orchestrator import DefenderOrchestrator, auto_retrain_loop  # noqa: E402
from defender.security.file_integrity import FileIntegrityMonitor  # noqa: E402
from defender.security.network_watcher import NetworkWatcher  # noqa: E402
from defender.security.process_genealogy import ProcessGenealogyWatcher  # noqa: E402
from defender.security.registry_watcher import RegistryWatcher  # noqa: E402
from defender.security.usb_monitor import USBMonitor  # noqa: E402
from shared.config_loader import get_config  # noqa: E402
from shared.logger import get_logger  # noqa: E402
from shared.state import (  # noqa: E402
    auth_state, cert_state, infra_state, network_state, service_state,
)
from shared.windows_helper import is_admin  # noqa: E402
from storage import database as db  # noqa: E402

log = get_logger("aegis")


BANNER = r"""
    _              _
   / \   ___  __ _(_)___
  / _ \ / _ \/ _` | / __|
 / ___ \  __/ (_| | \__ \
/_/   \_\___|\__, |_|___/
             |___/
 Self-Healing Infrastructure Defender
"""


class AegisApp:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.orchestrator: DefenderOrchestrator | None = None
        self.monitor: Monitor | None = None
        self.threads: list[threading.Thread] = []
        self._servers: list = []
        self._checks: list = []

    def initialize(self) -> None:
        print(BANNER)
        log.info(f"Starting Aegis v{self.cfg.app.version} ({self.cfg.app.environment})")
        log.info(f"Admin privileges: {is_admin()}")

        # DB
        db.initialize()
        log.info("Database initialized")

        # Pre-seed state singletons
        service_state.register_from_config(self.cfg.services.monitored)
        cert_state.register_from_config(self.cfg.security_audit.cert_check.monitored_domains)
        network_state.register_link("internet", self.cfg.network_health.internet_targets[0])
        network_state.register_link("gateway", self.cfg.network_health.gateway_ip)
        network_state.register_link("dns", self.cfg.network_health.dns_test_domains[0])
        network_state.register_ports(
            self.cfg.security_audit.port_audit.expected_open_ports,
            self.cfg.security_audit.port_audit.forbidden_ports,
        )
        infra_state.initialize_baseline(self.cfg)
        log.info(f"State seeded: {len(self.cfg.services.monitored)} services, "
                 f"{len(self.cfg.security_audit.cert_check.monitored_domains)} certs, "
                 f"{len(self.cfg.security_audit.port_audit.expected_open_ports)} ports")

        # Defender
        self.orchestrator = DefenderOrchestrator()
        self.orchestrator.register_with_bus()

        # Monitor (producer)
        self.monitor = Monitor()

        # Safety guard hotkey
        guard.start_hotkey_listener()

    def start_threads(self) -> None:
        assert self.monitor is not None

        # Monitor thread (legacy CPU/RAM/disk/network)
        t_mon = threading.Thread(target=self.monitor.start, daemon=True, name="monitor")
        t_mon.start()
        self.threads.append(t_mon)

        # Aegis NEW periodic checks
        if self.cfg.services.enabled:
            chk = ServiceHealthCheck()
            self._checks.append(chk)
            t = threading.Thread(target=chk.start, daemon=True, name="check-services")
            t.start()
            self.threads.append(t)

        if self.cfg.security_audit.enabled:
            chk = SecurityAuditCheck()
            self._checks.append(chk)
            t = threading.Thread(target=chk.start, daemon=True, name="check-security")
            t.start()
            self.threads.append(t)

        if self.cfg.network_health.enabled:
            chk = NetworkProbeCheck()
            self._checks.append(chk)
            t = threading.Thread(target=chk.start, daemon=True, name="check-network")
            t.start()
            self.threads.append(t)

        if self.cfg.infra_health.enabled:
            chk = InfraAuditCheck()
            self._checks.append(chk)
            t = threading.Thread(target=chk.start, daemon=True, name="check-infra")
            t.start()
            self.threads.append(t)

        # Legacy security watchers
        if self.cfg.security.process_genealogy:
            pg = ProcessGenealogyWatcher()
            t = threading.Thread(target=pg.start, daemon=True, name="proc-genealogy")
            t.start()
            self.threads.append(t)

        if self.cfg.security.network_watcher:
            nw = NetworkWatcher()
            t = threading.Thread(target=nw.start, daemon=True, name="network-watcher")
            t.start()
            self.threads.append(t)

        if self.cfg.security.file_integrity:
            fi = FileIntegrityMonitor()
            t = threading.Thread(target=fi.start, daemon=True, name="file-integrity")
            t.start()
            self.threads.append(t)

        if self.cfg.security.registry_watcher:
            rw = RegistryWatcher()
            t = threading.Thread(target=rw.start, daemon=True, name="registry-watcher")
            t.start()
            self.threads.append(t)

        if self.cfg.security.usb_monitor:
            usb = USBMonitor()
            t = threading.Thread(target=usb.start, daemon=True, name="usb-monitor")
            t.start()
            self.threads.append(t)

        # Auto-retrain loop
        if self.cfg.ai.enabled and self.orchestrator is not None:
            t_retrain = threading.Thread(
                target=auto_retrain_loop,
                args=(self.orchestrator.predictor, self.cfg.ai.auto_retrain_hours),
                daemon=True,
                name="auto-retrain",
            )
            t_retrain.start()
            self.threads.append(t_retrain)

    def start_servers(self) -> None:
        assert self.orchestrator is not None

        defender_app = create_defender_app(predictor=self.orchestrator.predictor, orchestrator=self.orchestrator)
        attacker_app = create_attacker_app()

        host = self.cfg.dashboards.host

        def run_defender() -> None:
            config = uvicorn.Config(
                defender_app, host=host, port=self.cfg.dashboards.defender_port,
                log_level="warning", access_log=False,
            )
            server = uvicorn.Server(config)
            self._servers.append(server)
            server.run()

        def run_attacker() -> None:
            config = uvicorn.Config(
                attacker_app, host=host, port=self.cfg.dashboards.attacker_port,
                log_level="warning", access_log=False,
            )
            server = uvicorn.Server(config)
            self._servers.append(server)
            server.run()

        t1 = threading.Thread(target=run_defender, daemon=True, name="defender-api")
        t2 = threading.Thread(target=run_attacker, daemon=True, name="attacker-api")
        t1.start()
        t2.start()
        self.threads.extend([t1, t2])

        log.info(f"[DEFENDER] http://{host}:{self.cfg.dashboards.defender_port}")
        log.info(f"[ATTACKER] http://{host}:{self.cfg.dashboards.attacker_port}")

    def shutdown(self) -> None:
        log.info("Shutting down...")
        if self.monitor:
            self.monitor.stop()
        for chk in self._checks:
            try:
                chk.stop()
            except Exception:
                pass
        guard.stop_all("shutdown")
        for server in self._servers:
            try:
                server.should_exit = True
            except Exception:
                pass

    def run(self) -> None:
        self.initialize()
        self.start_threads()
        self.start_servers()

        # Give servers a moment
        time.sleep(1)
        log.info("[OK] Aegis running. Press Ctrl+C to stop.")

        def handle_sigint(signum, frame):
            self.shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_sigint)

        # Main loop — just sleep
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()


if __name__ == "__main__":
    app = AegisApp()
    app.run()
