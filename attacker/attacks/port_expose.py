"""
Port expose attack — leaks a forbidden port (Telnet/SMB/C2/etc.) so the
security audit can detect "this port shouldn't be open".
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import network_state


log = get_logger("attack.port_expose")


PORT_HINTS = {
    23:    ("telnet",          "Telnet daemon — should never be open in 2025"),
    135:   ("rpc-locator",     "Windows RPC — typically blocked at edge"),
    445:   ("smb",             "SMB — exploited by WannaCry, EternalBlue"),
    4444:  ("metasploit",      "Common reverse-shell / Metasploit handler port"),
    5555:  ("adb",             "Android Debug Bridge — security risk"),
    6667:  ("irc",             "IRC — frequently used for C2"),
    14444: ("monero",          "Monero crypto-mining pool port"),
}


class PortExpose(BaseAttack):
    name = "port_expose"
    category = "security"
    description = "Open a forbidden port (Telnet/SMB/C2). Triggers port-audit alert."

    DEFAULTS = {
        "port": 4444,
        "process": "unknown.exe",
        "duration": 180,
    }

    def _run(self) -> None:
        port = int(self.params.get("port", self.DEFAULTS["port"]))
        process = self.params.get("process", self.DEFAULTS["process"])

        ok = network_state.inject_port_open(port, process=process)
        if not ok:
            self.stop(stopped_by="overlay_failed")
            return

        hint_name, hint_desc = PORT_HINTS.get(port, ("unknown", "Port not in catalog"))
        bus.publish("event", {
            "category": "security",
            "level": "CRITICAL",
            "message": f"Forbidden port {port} ({hint_name}) opened by {process}",
            "source": self.name,
            "port": port,
            "process": process,
        })
        log.info(f"[SIM] Port {port} ({hint_name}) opened by {process}")

        while self.is_running and self._check_safety():
            time.sleep(1)
