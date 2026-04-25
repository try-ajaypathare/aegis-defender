"""
Verify SIMULATION MODE: attacks only move server metrics (fake),
real psutil metrics stay stable (real system untouched).
"""
import psutil
import requests
import time


def real_metrics():
    psutil.cpu_percent(interval=None); time.sleep(0.3)
    vm = psutil.virtual_memory()
    return {
        "cpu_real": round(psutil.cpu_percent(interval=0.3), 1),
        "mem_real": round(vm.percent, 1),
        "mem_real_gb": round(vm.used / 1024 ** 3, 2),
    }


def server_metrics():
    r = requests.get("http://127.0.0.1:8000/api/metrics/current", timeout=5)
    m = r.json()
    return {
        "cpu_server": m.get("cpu_percent", 0),
        "mem_server": m.get("memory_percent", 0),
        "mem_server_gb": m.get("memory_used_gb", 0),
        "simulation_active": m.get("simulation_active", False),
        "simulation_count": m.get("simulation_count", 0),
    }


def start(name, params):
    return requests.post(f"http://127.0.0.1:8001/api/attacks/{name}/start", json=params, timeout=5).ok


def stop_all():
    try:
        requests.post("http://127.0.0.1:8001/api/attacks/stop_all", timeout=5)
    except Exception:
        pass


def measure_attack(name, params, label):
    print(f"\n=== {label}: {name} ===")
    stop_all(); time.sleep(3)

    r_before = real_metrics()
    s_before = server_metrics()
    print(f"  BEFORE:  real CPU={r_before['cpu_real']}%  server CPU={s_before['cpu_server']}%")
    print(f"           real MEM={r_before['mem_real']}% ({r_before['mem_real_gb']}GB)  server MEM={s_before['mem_server']}%")

    start(name, params)
    time.sleep(8)  # let simulation + ramp take effect

    r_during = real_metrics()
    s_during = server_metrics()
    print(f"  DURING:  real CPU={r_during['cpu_real']}%  server CPU={s_during['cpu_server']}%  <- server should be HIGHER")
    print(f"           real MEM={r_during['mem_real']}% ({r_during['mem_real_gb']}GB)  server MEM={s_during['mem_server']}%")
    print(f"           sim_active={s_during['simulation_active']}  sim_count={s_during['simulation_count']}")

    stop_all()
    time.sleep(2)

    # Verdicts
    real_cpu_delta = abs(r_during["cpu_real"] - r_before["cpu_real"])
    real_mem_delta = abs(r_during["mem_real_gb"] - r_before["mem_real_gb"])
    server_cpu_delta = s_during["cpu_server"] - s_before["cpu_server"]
    server_mem_delta = s_during["mem_server"] - s_before["mem_server"]

    print()
    print(f"  [REAL SYSTEM DELTA] CPU: {real_cpu_delta:+.1f}%  MEM: {real_mem_delta:+.2f}GB")
    print(f"  [SERVER METRIC DELTA]  CPU: {server_cpu_delta:+.1f}%  MEM: {server_mem_delta:+.1f}%")

    # Safety: real system should move less than 15% due to our activity (not the attack)
    real_safe = real_cpu_delta < 25 and real_mem_delta < 0.5
    server_visible = server_cpu_delta > 3 or server_mem_delta > 3

    print(f"  [VERDICT] real system safe: {'YES' if real_safe else 'NO (may have real impact!)'}")
    print(f"  [VERDICT] server metrics responded: {'YES' if server_visible else 'NO'}")
    return real_safe, server_visible


if __name__ == "__main__":
    print("=" * 72)
    print("  SIMULATION MODE VERIFICATION")
    print("=" * 72)
    print("  Real system metrics should NOT change significantly.")
    print("  Server/dashboard metrics SHOULD move dramatically.")
    print("=" * 72)

    cases = [
        ("cpu_spike",    {"cores": 4, "duration": 15},  "CPU attack"),
        ("ram_flood",    {"size_mb": 1500, "duration": 15}, "RAM attack"),
        ("fork_bomb",    {"count": 20, "duration": 15}, "Process flood"),
        ("cryptomining_sim", {"cores": 3, "duration": 15}, "Crypto miner"),
        ("combo",        {"intensity": "high", "duration": 15}, "Combo heavy"),
    ]

    results = []
    for name, params, label in cases:
        safe, visible = measure_attack(name, params, label)
        results.append((name, safe, visible))

    stop_all()

    print()
    print("=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  {'Attack':25} {'Real safe':12} {'Server visible'}")
    for name, safe, visible in results:
        print(f"  {name:25} {'[OK]' if safe else '[UNSAFE]':12} {'[OK]' if visible else '[WEAK]'}")
    all_safe = all(safe for _, safe, _ in results)
    all_visible = all(visible for _, _, visible in results)
    print()
    print(f"  REAL SYSTEM SAFETY: {'PASSED' if all_safe else 'FAILED'}")
    print(f"  SIMULATION VISIBILITY: {'PASSED' if all_visible else 'PARTIAL'}")
    print("=" * 72)
