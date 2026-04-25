# Argus — AI-Driven Self-Healing Server Defender

A simulation-based security operations dashboard that demonstrates **multi-tier
intelligent defense** against synthetic attacks. Built around a real LLM agent
(NVIDIA DeepSeek / Llama / Gemini) that thinks step-by-step and picks responses
from an 18-action catalog.

> **Pure simulation.** No real CPU, RAM, disk, network, or processes are stressed.
> Attacks register their *claimed* impact in a simulation engine; the monitor
> overlays it on a healthy-server baseline so dashboards look real without
> touching hardware.

---

## ✨ Highlights

- **3 defense modes** (toggle in topnav):
  - `AUTO` — pure rule engine, deterministic, zero LLM cost
  - `HYBRID` — rules + AI verify + auto-investigation (default)
  - `AI` — LLM picks every action, with engine guardrails
- **Multi-tier action catalog** (18 actions across 5 tiers):
  observe → limit → contain → suspend → terminate
- **Risk scoring engine** combining severity, confidence, reputation, repeat-offender
  history, time-of-day, and metric-delta
- **AI Live Solve** — demo-grade six-stage pipeline (DETECT → ANALYZE → DECIDE →
  EXECUTE → VERIFY → REPORT) with live WebSocket streaming
- **AI Investigator** — multi-step agent loop with 8 tools (inspect_metric,
  inspect_offender, try_throttle, etc.) the LLM calls iteratively
- **WAF simulation** — 9 fake request patterns (SQL injection, XSS, path
  traversal, credential stuffing, DDoS, …) classified and acted on by AI
- **Repeat-offender tracking** with automatic escalation
- **Trust system** for whitelisted processes/IPs
- **10 simulated attacks**: cpu_spike, ram_flood, disk_fill, traffic_flood,
  combo, fork_bomb, slow_creep, memory_leak, cryptomining_sim, ransomware_sim
- **Persistent state** — defense mode + trust list survive restarts
- **Demo Reset** — one-click clean slate
- **AI usage tracker** with soft-cap to protect free-tier API quota

---

## 🏗️ Architecture

```
                   ┌─────────────────────────────────────┐
  Attacker UI ──▶  │  attacker/api.py (FastAPI :8001)    │
                   │     ├ attacks/ (10 simulations)     │
                   │     └ safety_guard (kill switch)    │
                   └─────────────────────────────────────┘
                                  │ registers impact
                                  ▼
                   ┌─────────────────────────────────────┐
                   │  shared/simulation.py engine        │
                   │     (no real resources consumed)    │
                   └─────────────────────────────────────┘
                                  ▲ overlay
                                  │
                   ┌─────────────────────────────────────┐
                   │  defender/monitor.py                │
                   │     fake_baseline + sim overlay     │
                   └─────────────────────────────────────┘
                                  │ publishes metric
                                  ▼
                   ┌─────────────────────────────────────┐
                   │  defender/orchestrator.py           │
                   │     branches by DefenseMode         │
                   │     AUTO  → DecisionEngine          │
                   │     HYBRID→ DecisionEngine + AI verify
                   │     AI    → ai_advisor + Live Solver│
                   └─────────────────────────────────────┘
                                  │
                ┌─────────────────┼──────────────────────┐
                ▼                 ▼                      ▼
   ┌──────────────────┐ ┌────────────────┐   ┌─────────────────┐
   │  rules_engine    │ │ DecisionEngine │   │ ai/             │
   │  (baseline + delta)│ │ + Executor    │   │  ├ llm_client   │
   └──────────────────┘ └────────────────┘   │  ├ advisor      │
                                              │  ├ investigator │
                                              │  └ live_solver  │
                                              └─────────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────────────┐
                   │  defender/api.py (FastAPI :8000)    │
                   │     REST + WebSocket streaming      │
                   └─────────────────────────────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────────────┐
                   │  Defender Dashboard (HTML/CSS/JS)    │
                   │     - Live metric cards              │
                   │     - AI Live Solve panel            │
                   │     - Decision Engine panel          │
                   │     - Attack Detection Timeline      │
                   │     - Investigation history          │
                   │     - WAF live request feed          │
                   └─────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- A free NVIDIA API key from https://build.nvidia.com (or Gemini key from
  https://aistudio.google.com)

### Setup

```bash
# 1. Clone
git clone https://github.com/<your-username>/argus.git
cd argus

# 2. (Optional) virtualenv
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up your AI key
copy .env.example .env          # Windows
# cp .env.example .env          # Linux/Mac
# Edit .env and fill in NVIDIA_API_KEY

# 5. Run
python main.py
```

Open the dashboards:
- 🛡️ **Defender** : http://127.0.0.1:8000
- 🎯 **Attacker** : http://127.0.0.1:8001

---

## 🎮 How to Demo

1. Open the Defender dashboard
2. Wait ~25 seconds for baseline learning
3. Switch defense mode toggle to **AI**
4. Open the Attacker tab in another window
5. Pick an attack (e.g. *cpu_spike → Heavy → Start*)
6. Watch the Defender:
   - **AI Live Solve** panel auto-runs 6 stages over ~20 seconds
   - **Attack Detection Timeline** entry transitions `active` → `resolved`
   - Decision Engine shows risk score + reasoning chain
   - Final report is written by the LLM

Or click **Solve with AI** to manually trigger the live solver on demand.

---

## 🧠 AI Modes Explained

| Mode | Decisions made by | LLM calls | Speed | Cost |
|------|-------------------|-----------|-------|------|
| **AUTO** | Rule engine only | 0 | Fastest | Free |
| **HYBRID** | Rules + LLM verify | 1–2 per threat | Fast | Low |
| **AI** | LLM picks every action via Live Solver | 3–4 per threat | Slower | Medium |

You can switch any time from the topnav segmented control.

---

## 🛡️ Action Catalog (18 actions, 5 tiers)

| Tier | Actions |
|------|---------|
| **0 OBSERVE** | `log_only`, `alert`, `increase_monitoring`, `clear_temp` |
| **1 LIMIT** | `throttle_cpu`, `throttle_network`, `rate_limit_source`, `require_challenge` |
| **2 CONTAIN** | `sandbox_process`, `block_network`, `quarantine_files` |
| **3 SUSPEND** | `suspend_process`, `block_ip_temporary` |
| **4 TERMINATE** | `kill_process`, `kill_and_capture`, `block_ip_permanent`, `rollback_changes` |

Click *Action Catalog* in the Decision Engine panel to see the full list with
descriptions in the dashboard.

---

## 🌐 WAF / Live Request Feed

Generates fake HTTP requests in 9 patterns and pipes them through the AI:

- `credential_stuffing`, `sql_injection`, `path_traversal`, `xss`,
  `recon_scanner`, `ddos_volumetric`, `api_scraping`, `normal_browse`, `normal_api`

The LLM classifies each, the Decision Engine assigns risk + tier, and the
appropriate action runs — same engine that handles process attacks.

---

## 📡 API Endpoints (selection)

```
GET  /api/metrics/current
GET  /api/metrics/history?hours=1
GET  /api/events?limit=50
GET  /api/actions?limit=20
GET  /api/stats/summary
GET  /api/stats/baseline
GET  /api/stats/detection

POST /api/defender/mode             # body: {"mode": "auto|hybrid|ai"}
GET  /api/defender/mode
GET  /api/defender/offenders
GET  /api/defender/action_catalog
GET  /api/defender/trust
POST /api/defender/demo_reset

POST /api/ai/solve                  # run AI Live Solver
POST /api/ai/investigate            # multi-step investigation
POST /api/ai/explain
POST /api/ai/analyze
POST /api/ai/chat                   # body: {"message": "..."}
GET  /api/ai/usage
GET  /api/ai/llm/status
GET  /api/ai/investigations

GET  /api/waf/patterns
POST /api/waf/send                  # body: {"pattern": "...", "count": 1}

POST /api/attacks/{type}/start      # via :8001
POST /api/attacks/stop_all
GET  /api/attacks/active
```

---

## 📁 Project Layout

```
argus/
├── main.py                     # entrypoint
├── config.yaml                 # thresholds, modes, ports
├── requirements.txt
├── .env.example                # template for AI keys
│
├── ai/                         # LLM integrations
│   ├── advisor.py              #   single-shot helpers
│   ├── investigator.py         #   multi-step agent loop
│   ├── live_solver.py          #   6-stage demo pipeline
│   ├── llm_client.py           #   provider fallback + cache
│   ├── json_extract.py         #   robust JSON parsing
│   ├── predictor.py            #   anomaly detection
│   └── trainer.py
│
├── attacker/
│   ├── api.py                  # :8001 server
│   ├── attacks/                # 10 simulated attacks
│   ├── fake_requests.py        # WAF request generator
│   ├── safety_guard.py         # kill switch
│   └── base_attack.py
│
├── defender/
│   ├── api.py                  # :8000 server
│   ├── orchestrator.py         # mode-aware decision flow
│   ├── decision_engine.py      # risk scoring + action picking
│   ├── defense_mode.py         # AUTO/HYBRID/AI state
│   ├── executor.py             # 18-action implementations
│   ├── rules_engine.py         # baseline-aware delta detection
│   ├── monitor.py              # fake-baseline + sim overlay
│   ├── system_info.py          # synthetic server identity
│   └── security/               # process/network/file watchers
│
├── shared/
│   ├── simulation.py           # core simulation engine
│   ├── fake_baseline.py        # healthy-server metrics
│   ├── event_bus.py            # pub/sub
│   ├── notifier.py             # toast / Telegram / Discord / email
│   └── config_loader.py
│
├── storage/
│   ├── database.py             # SQLite (auto-created)
│   ├── persistence.py          # JSON state for mode/trust
│   └── schema.sql
│
└── ui/
    ├── defender.html           # main dashboard
    ├── attacker.html           # attack console
    ├── icons.svg               # 48 inline Lucide-style icons
    ├── css/styles.css          # dark + light themes
    └── js/                     # defender.js, attacker.js, charts.js, theme.js
```

---

## ⚠️ Safety

This project is a *simulation*. Do not use the attack catalog against systems
you don't own — even though Argus's attacks are fully synthetic and never
touch real resources, the underlying classes are illustrative and could be
extended to do harm if modified.

**Real APIs called by this project:**
- NVIDIA Build (LLM inference)
- Google AI Studio (LLM inference, fallback only if configured)

No other outbound network connections.

---

## 📜 License

MIT
