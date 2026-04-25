# Aegis — Self-Healing Infrastructure Defender

A multi-pillar **infrastructure SOC dashboard** that detects incidents across
services, security, network, and system layers — and **auto-heals them** in
three intelligent defense modes (AUTO / HYBRID / AI).

Built around a real LLM agent (NVIDIA DeepSeek / Llama / Gemini) backed by a
deterministic decision engine and 28-action remediation catalog. Designed to
*visibly demonstrate* the full incident lifecycle:
**detect → analyze → decide → execute → verify**.

> **Pure simulation.** No real services are stopped, no real network changes
> are made, no real attacks are launched. Aegis maintains an in-memory state
> overlay that attackers flip into incident states and defenders heal back —
> safe to demo on any machine, with optional real-probe integration when
> XAMPP / Apache / MySQL are running locally.

![Architecture](https://img.shields.io/badge/architecture-event--driven-cyan)
![Modes](https://img.shields.io/badge/modes-AUTO%20|%20HYBRID%20|%20AI-amber)
![Attacks](https://img.shields.io/badge/curated%20attacks-15-success)
![Actions](https://img.shields.io/badge/remediation%20actions-28-success)

---

## ✨ What makes Aegis different

- **4 infrastructure pillars** (Services, Security, Network, Infrastructure)
  monitored simultaneously — not just CPU/RAM/disk
- **15 curated incident scenarios** across all 5 demo-friendly categories
- **28 remediation actions** including `restart_service`, `rotate_cert`,
  `block_ip`, `restart_uplink`, `sync_ntp`, `clear_hw_warning`, `retry_backup`,
  etc.
- **3 working defense modes** (AUTO/HYBRID/AI) — every mode actually solves
  every incident, not just CPU/RAM
- **Visible reaction window** (3-4.5s) so the user sees `RED → DECIDE → GREEN`
  on screen, not invisible sub-second auto-healing
- **Live Decision Flow panel** showing every step (DETECT → ANALYZE → DECIDE →
  EXECUTE → VERIFY) with risk score, reasoning, rejected alternatives
- **Hybrid real + simulated probes** — real Apache/MySQL/gateway/DNS pings when
  available, synthetic baseline when not

---

## 🏛️ The 4 Pillars

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AEGIS DEFENDER DASHBOARD                          │
├──────────────────┬──────────────────┬──────────────────┬─────────────────┤
│   SERVICES       │     SECURITY     │     NETWORK      │  INFRASTRUCTURE │
│   3/4 up         │     0 active     │    3/3 healthy   │      OK         │
│   apache mysql   │  4 IPs blocked   │  uplink · DNS    │ backup · NTP    │
│   redis app      │  certs · ports   │   gateway        │ updates · HW    │
└──────────────────┴──────────────────┴──────────────────┴─────────────────┘
```

| Pillar | What it monitors | Auto-heal actions |
|--------|------------------|-------------------|
| **Services** | Apache / MySQL / Redis / App health, latency | `restart_service` |
| **Security** | SSH brute force, SSL certs, port audit, ransomware | `block_ip_aegis`, `rotate_cert`, `close_port` |
| **Network** | Internet uplink, gateway, DNS resolver | `restart_uplink`, `restart_dns` |
| **Infrastructure** | Backup, NTP drift, OS updates, hardware (SMART/temp/PSU) | `retry_backup`, `sync_ntp`, `clear_hw_warning` |

---

## 🛡️ The 3 Defense Modes

| Mode | Decision-maker | Reaction time | Use case |
|------|----------------|---------------|----------|
| **AUTO** | Pure rule engine + DecisionEngine | 3.0s visible delay | Fast deterministic response, zero LLM cost |
| **HYBRID** | Rules + AI investigation + state-verify | 4.5s visible delay | Default — rules act, AI confirms heal worked |
| **AI** | LLM picks every action via 6-stage Live Solver | 3.0s + multi-step pipeline | Maximum reasoning, demo-grade visibility |

The **same DecisionEngine** services all modes — actions are unified. The
difference is purely in *who* decides and *how visibly* the reasoning unfolds.

---

## 📜 Curated Attacks (15)

| Category | Attacks |
|----------|---------|
| 🚀 **Performance** | `cpu_spike`, `ram_flood`, `disk_fill` |
| 🖥️ **Service Health** | `service_crash` (Apache/MySQL/Redis/App, mode=crash/degrade/latency) |
| 🔒 **Security** | `ssh_brute_force`, `cert_expire`, `port_expose`, `ransomware_sim` |
| 🌐 **Network** | `traffic_flood` (DDoS), `dns_blackhole`, `gateway_drop` |
| 🗄️ **Infrastructure** | `backup_fail`, `ntp_drift`, `hardware_warning` |

Each attack respects firewall realism — e.g., `ssh_brute_force` honors
defender IP blocks (no more events from blocked source). When AUTO mode
blocks the attacker IP, the attack visibly *contains* itself within seconds.

---

## 🛠️ The 28-Action Remediation Catalog

```
Tier 0 OBSERVE       none, log_only, alert, increase_monitoring, clear_temp,
                     notify_soc

Tier 1 LIMIT         throttle_cpu, throttle_network, rate_limit_source,
                     require_challenge

Tier 2 CONTAIN       sandbox_process, block_network, quarantine_files

Tier 3 SUSPEND       suspend_process, block_ip_temporary

Tier 4 TERMINATE     kill_process, kill_and_capture, block_ip_permanent,
                     rollback_changes

Tier 6 AEGIS HEAL    restart_service, rotate_cert, close_port,
                     block_ip_aegis, retry_backup, sync_ntp,
                     restart_uplink, restart_dns, clear_hw_warning,
                     page_oncall
```

The Tier 6 actions are unique to Aegis — they *heal* infrastructure rather
than just contain threats.

---

## 🏗️ Architecture

```
                  ┌─────────────────────────────────────┐
   Attacker UI ──▶│  attacker/api.py  (FastAPI :8001)   │
                  │   ├─ 15 attacks (performance/svc/   │
                  │   │   security/network/infra)       │
                  │   └─ safety_guard (kill switch)     │
                  └─────────────────────────────────────┘
                                 │ flips state-overlay flags
                                 ▼
                  ┌─────────────────────────────────────┐
                  │  shared/state/  (in-memory)         │
                  │   ├─ service_state  (apache, mysql) │
                  │   ├─ auth_state     (auth log + IPs)│
                  │   ├─ cert_state     (SSL lifecycle) │
                  │   ├─ network_state  (links + ports) │
                  │   └─ infra_state    (backup/ntp/hw) │
                  └─────────────────────────────────────┘
                                 │ status changes
                                 ▼
                  ┌─────────────────────────────────────┐
                  │  defender/checks/  (4 thread loops) │
                  │   ├─ service_health  (every 5s)     │
                  │   ├─ security_audit  (every 5s)     │
                  │   ├─ network_probe   (every 10s)    │
                  │   └─ infra_audit     (every 30s)    │
                  └─────────────────────────────────────┘
                                 │ publishes "event"
                                 ▼
                  ┌─────────────────────────────────────┐
                  │  defender/orchestrator.py           │
                  │   handle_aegis_event(event)         │
                  │   ├─ AUTO   : DecisionEngine →      │
                  │   │           +3.0s delay → execute │
                  │   ├─ HYBRID : same + verify state   │
                  │   └─ AI     : LLM Live Solver +     │
                  │               DecisionEngine        │
                  └─────────────────────────────────────┘
                                 │
                ┌────────────────┼────────────────────┐
                ▼                ▼                    ▼
      ┌─────────────────┐  ┌─────────────┐  ┌──────────────────┐
      │ DecisionEngine  │  │ ai/         │  │ executor.py      │
      │ category-based  │  │  ├─ live_   │  │ 28 action        │
      │ direct mapping  │  │  │  solver  │  │ handlers         │
      │ + risk score    │  │  ├─ advisor │  │ → mutates state  │
      └─────────────────┘  │  └─ invest. │  └──────────────────┘
                           └─────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────────────┐
                  │  Defender Dashboard (HTML/CSS/JS)   │
                  │   ├─ 4 Pillar KPI hero cards        │
                  │   ├─ Live Solutions Banner          │
                  │   ├─ Live Decision Flow (5 steps)   │
                  │   ├─ Infrastructure Health (16      │
                  │   │   tiles, real-time)             │
                  │   ├─ Authentication Activity feed   │
                  │   ├─ AI Live Solve panel            │
                  │   └─ Compact metrics strip (CPU/    │
                  │       RAM/disk demoted to footer)   │
                  └─────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- A free NVIDIA API key from [build.nvidia.com](https://build.nvidia.com)
  (or Gemini key from [aistudio.google.com](https://aistudio.google.com))
- *Optional:* XAMPP for real Apache + MySQL probes (otherwise services run
  in pure simulation)

### Setup

```bash
# 1. Clone
git clone https://github.com/try-ajaypathare/aegis-defender.git
cd aegis-defender

# 2. (Optional) virtualenv
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up your AI key
copy .env.example .env          # Windows
# cp .env.example .env          # Linux/Mac
# Edit .env and fill in NVIDIA_API_KEY

# 5. Run
python main.py
# (or double-click run.bat on Windows)
```

Open the dashboards:
- 🛡️ **Defender** : http://127.0.0.1:8000
- ⚔️ **Attacker** : http://127.0.0.1:8001

---

## 🎮 Demo Flow

1. Open the Defender dashboard — all 4 pillars **GREEN** baseline.
2. Switch defense mode to **AUTO** in the topnav.
3. Open Attacker in another tab.
4. Pick an attack — e.g. *Service Health → service_crash → Heavy → Start*.
5. Watch the Defender:
   - **0–3 seconds:** Apache tile turns **RED** with "SIM" badge,
     Services pillar pulses critical, Live Decision Flow panel animates
     DETECT → ANALYZE → DECIDE steps.
   - **At 3 seconds:** Solutions banner flashes "Restarted service",
     toast notification appears, Apache tile turns **GREEN**, restart
     count increments.
   - **In HYBRID/AI mode:** an additional VERIFY step confirms the heal
     actually worked.
6. Try other attacks: `ssh_brute_force` (auto-blocks attacker IP after 8
   seconds), `cert_expire` (rotates the certificate), `gateway_drop`
   (restarts the uplink), `port_expose` (closes the forbidden port).

The full demo loop takes ~30 seconds per incident — clearly visible from
attack to heal.

---

## 📡 Selected API Endpoints

```
# Pillar state
GET  /api/services                       list all services + health
POST /api/services/{id}/restart          manual heal
GET  /api/security/auth_events           failed logins + IP threats
POST /api/security/block_ip              { ip, duration_minutes }
GET  /api/security/certs                 SSL cert lifecycle
POST /api/security/certs/{domain}/rotate manual rotation
GET  /api/security/ports                 port audit
POST /api/security/ports/{port}/close    close forbidden port
GET  /api/network                        link health (uplink/dns/gateway)
GET  /api/infra                          backup/ntp/updates/hardware
POST /api/infra/backup/retry             manual backup retry
POST /api/infra/ntp/sync                 manual NTP sync

# Defense mode
GET  /api/defender/mode
POST /api/defender/mode                  { mode: "auto|hybrid|ai" }
GET  /api/defender/offenders
GET  /api/defender/action_catalog
POST /api/defender/demo_reset

# AI
POST /api/ai/solve                       run Live Solver
POST /api/ai/investigate                 multi-step investigation
GET  /api/ai/llm/status

# Attacks (port 8001)
GET  /api/attacks/list
POST /api/attacks/{type}/start
POST /api/attacks/stop_all
```

---

## 📁 Project Layout

```
aegis/
├── main.py                       # entrypoint
├── config.yaml                   # thresholds, services, certs, ports
├── requirements.txt
├── run.bat                       # Windows launcher
├── .env.example                  # template for AI keys
│
├── ai/                           # LLM integrations
│   ├── advisor.py                #   single-shot helpers
│   ├── investigator.py           #   multi-step agent (18 tools)
│   ├── live_solver.py            #   6-stage demo pipeline
│   ├── llm_client.py             #   provider fallback + cache
│   └── ...
│
├── attacker/
│   ├── api.py                    # :8001 server
│   ├── attacks/                  # 15 curated attacks
│   ├── safety_guard.py           # Ctrl+Shift+Q kill switch
│   └── base_attack.py
│
├── defender/
│   ├── api.py                    # :8000 server + WebSocket
│   ├── orchestrator.py           # 3-mode decision flow + reaction delay
│   ├── decision_engine.py        # 28 actions, risk scoring, Aegis routing
│   ├── defense_mode.py           # AUTO/HYBRID/AI state machine
│   ├── executor.py               # 28 action handlers
│   ├── rules_engine.py           # baseline-aware delta detection
│   ├── monitor.py                # synthetic baseline + sim overlay
│   ├── checks/                   # 4 periodic checks (service/security/
│   │                             #   network/infra)
│   └── security/                 # process/network/file watchers
│
├── shared/
│   ├── state/                    # 5 in-memory state modules
│   ├── simulation.py             # core simulation engine
│   ├── fake_baseline.py          # healthy-server metrics
│   ├── event_bus.py              # in-process pub/sub
│   ├── config_loader.py          # Pydantic schema
│   └── notifier.py
│
├── storage/
│   ├── database.py               # SQLite (auto-created)
│   ├── persistence.py            # JSON state for mode/trust
│   └── schema.sql
│
└── ui/
    ├── defender.html             # main dashboard (4 pillars + flow)
    ├── attacker.html             # attack console (5 categories)
    ├── icons.svg                 # 48 inline Lucide-style icons
    ├── css/styles.css            # cyan/amber theme
    └── js/                       # defender.js, attacker.js, charts.js
```

---

## 🎨 Visual Identity

Aegis uses a **Guardian Cyan + Amber** palette to differentiate from generic
SOC tools:

- Primary accent: `#06b6d4` (cyan-500)
- Secondary accent: `#f59e0b` (amber)
- Surface tones: cooler/bluer (`#060a14` canvas, `#0c1422` panels)
- Brand mark: **"Æ"** ligature in cyan gradient with shield-shaped border-radius
- Animations: critical-pulse on red pillars, scale-in on Solutions banner,
  green tile-heal flash on auto-recovery

---

## ⚠️ Safety

This project is a *simulation*. The attack catalog never touches real
hardware, real services, real networks, or real users. The underlying classes
are illustrative — do not extend them to harm systems you don't own.

**Real APIs called by this project:**
- NVIDIA Build (LLM inference)
- Google AI Studio (LLM inference, fallback)
- *Optional:* localhost Apache (HTTP probe), localhost MySQL (TCP probe),
  default gateway ping, public DNS resolution

No other outbound network connections.

---

## 📜 License

MIT
