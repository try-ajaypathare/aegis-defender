"""
Config loader for Aegis.
Parses config.yaml into a typed Pydantic model.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


class AppSettings(BaseModel):
    name: str = "Aegis"
    version: str = "1.0.0"
    environment: str = "development"
    log_level: str = "INFO"


class MonitoringSettings(BaseModel):
    interval_seconds: int = 5
    retention_days: int = 30
    warmup_samples: int = 3


class ThresholdRule(BaseModel):
    warning: float
    critical: float
    sustained_seconds: int = 0


class NetworkThresholds(BaseModel):
    connection_warning: int = 100
    connection_critical: int = 300


class ProcessThresholds(BaseModel):
    warning: int = 300
    critical: int = 500


class SimpleThreshold(BaseModel):
    warning: float
    critical: float


class ThresholdsSettings(BaseModel):
    cpu: ThresholdRule
    memory: ThresholdRule
    disk: ThresholdRule
    processes: ProcessThresholds
    network: NetworkThresholds
    # NEW thresholds
    service_latency_ms: SimpleThreshold = SimpleThreshold(warning=500, critical=1500)
    auth_failures_per_minute: SimpleThreshold = SimpleThreshold(warning=10, critical=30)
    cert_days_to_expiry: SimpleThreshold = SimpleThreshold(warning=30, critical=7)


class ActionsSettings(BaseModel):
    auto_kill_enabled: bool = True
    auto_clear_temp: bool = True
    kill_confirmation_required: bool = False
    cooldown_seconds: int = 30
    ai_advisor_enabled: bool = True
    ai_verify_after_action: bool = True


class AISettings(BaseModel):
    enabled: bool = True
    engine: str = "isolation_forest"
    auto_retrain_hours: int = 72
    min_samples_for_training: int = 1000
    anomaly_threshold: float = 0.7
    contamination: float = 0.05
    use_shap_explanations: bool = True


class SecuritySettings(BaseModel):
    process_genealogy: bool = True
    network_watcher: bool = True
    file_integrity: bool = True
    registry_watcher: bool = True
    usb_monitor: bool = True
    watched_folders: list[str] = Field(default_factory=list)
    suspicious_ports: list[int] = Field(default_factory=list)
    suspicious_chains: list[list[str]] = Field(default_factory=list)


# ─────────── NEW SECTIONS ─────────── #

class MonitoredService(BaseModel):
    id: str
    name: str
    type: str               # "http" | "tcp"
    probe_url: Optional[str] = None
    host: Optional[str] = None
    port: int
    timeout_seconds: float = 2.0
    restart_command: Optional[str] = None
    simulated_only: bool = False


class ServicesSettings(BaseModel):
    enabled: bool = True
    probe_interval_seconds: int = 5
    monitored: list[MonitoredService] = Field(default_factory=list)


class SSHBruteForceConfig(BaseModel):
    track_window_minutes: int = 5
    block_threshold_failures: int = 5
    block_duration_minutes: int = 15


class CertCheckConfig(BaseModel):
    monitored_domains: list[str] = Field(default_factory=list)


class PortAuditConfig(BaseModel):
    expected_open_ports: list[int] = Field(default_factory=list)
    forbidden_ports: list[int] = Field(default_factory=list)


class SecurityAuditSettings(BaseModel):
    enabled: bool = True
    audit_interval_seconds: int = 5
    ssh_brute_force: SSHBruteForceConfig = SSHBruteForceConfig()
    cert_check: CertCheckConfig = CertCheckConfig()
    port_audit: PortAuditConfig = PortAuditConfig()


class NetworkHealthSettings(BaseModel):
    enabled: bool = True
    probe_interval_seconds: int = 10
    gateway_ip: str = "192.168.1.1"
    internet_targets: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    dns_test_domains: list[str] = Field(default_factory=lambda: ["google.com", "cloudflare.com"])


class BackupConfig(BaseModel):
    expected_interval_hours: int = 24


class NTPConfig(BaseModel):
    max_drift_seconds: float = 5.0


class OSUpdatesConfig(BaseModel):
    warn_pending_count: int = 5


class InfraHealthSettings(BaseModel):
    enabled: bool = True
    audit_interval_seconds: int = 30
    backup: BackupConfig = BackupConfig()
    ntp: NTPConfig = NTPConfig()
    os_updates: OSUpdatesConfig = OSUpdatesConfig()


# ─────────── EXISTING ─────────── #

class DashboardsSettings(BaseModel):
    defender_port: int = 8000
    attacker_port: int = 8001
    host: str = "127.0.0.1"
    auth_enabled: bool = False
    auth_token: str = "change-me"


class AttacksSettings(BaseModel):
    max_duration_seconds: int = 300
    max_ram_mb: int = 2000
    max_disk_mb: int = 1000
    max_cpu_cores: int = 4
    max_threads: int = 500
    max_sockets: int = 500
    max_file_handles: int = 500
    max_processes_fork_bomb: int = 30
    kill_switch_hotkey: str = "ctrl+shift+q"
    workspace_folder: str = "attacker/attack_workspace"


class TelegramSettings(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


class DiscordSettings(BaseModel):
    enabled: bool = False
    webhook_url: str = ""


class EmailSettings(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    recipients: list[str] = Field(default_factory=list)


class NotificationsSettings(BaseModel):
    windows_toast: bool = True
    console_output: bool = True
    log_file: str = "logs/aegis.log"
    telegram: TelegramSettings = TelegramSettings()
    discord: DiscordSettings = DiscordSettings()
    email: EmailSettings = EmailSettings()


class FeedbackSettings(BaseModel):
    enabled: bool = True
    min_feedback_for_retrain: int = 20


class AegisConfig(BaseModel):
    app: AppSettings
    monitoring: MonitoringSettings
    thresholds: ThresholdsSettings
    actions: ActionsSettings
    safety_list: list[str] = Field(default_factory=list)
    ai: AISettings
    security: SecuritySettings
    services: ServicesSettings = ServicesSettings()
    security_audit: SecurityAuditSettings = SecurityAuditSettings()
    network_health: NetworkHealthSettings = NetworkHealthSettings()
    infra_health: InfraHealthSettings = InfraHealthSettings()
    dashboards: DashboardsSettings
    attacks: AttacksSettings
    notifications: NotificationsSettings
    feedback: FeedbackSettings


# Backwards-compat alias (some old code references ArgusConfig)
ArgusConfig = AegisConfig


_cached: AegisConfig | None = None


def load_config(force_reload: bool = False) -> AegisConfig:
    global _cached
    if _cached is not None and not force_reload:
        return _cached

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    _cached = AegisConfig(**raw)
    return _cached


def get_config() -> AegisConfig:
    return load_config()
