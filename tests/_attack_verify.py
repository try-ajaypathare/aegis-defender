"""Verify each attack actually moves system metrics (measured via psutil directly)."""
import psutil
import requests
import time


def snap():
    vm = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\")
    except Exception:
        disk = psutil.disk_usage("/")
    return {
        "cpu": round(psutil.cpu_percent(interval=0.3), 1),
        "mem": round(vm.percent, 1),
        "mem_gb": round(vm.used / 1024 ** 3, 2),
        "disk": round(disk.percent, 1),
        "procs": len(psutil.pids()),
    }


def attack(name, params):
    return requests.post(f"http://127.0.0.1:8001/api/attacks/{name}/start", json=params, timeout=8).ok


def stop_all():
    try:
        requests.post("http://127.0.0.1:8001/api/attacks/stop_all", timeout=8)
    except Exception:
        pass


def test(name, params, wait, metric, min_delta):
    stop_all()
    time.sleep(4)
    base = snap()
    if not attack(name, params):
        return "START_FAILED"
    time.sleep(1)
    peak = dict(base)
    for _ in range(wait):
        time.sleep(1)
        s = snap()
        for k in peak:
            peak[k] = max(peak[k], s[k])
    stop_all()
    delta = peak[metric] - base[metric]
    status = "WORKING" if delta >= min_delta else "WEAK"
    print(f"  {status:8} {name:20}  {metric}: {base[metric]:6.1f} -> {peak[metric]:6.1f}  (+{delta:+5.1f})")
    return status


if __name__ == "__main__":
    print("=" * 72)
    print("  ATTACK IMPACT VERIFICATION (psutil direct)")
    print("=" * 72)

    cases = [
        ("cpu_spike",        {"cores": 4, "duration": 15},  10, "cpu", 15),
        ("ram_flood",        {"size_mb": 1200, "duration": 20}, 12, "mem", 6),
        ("memory_leak",      {"leak_rate_mb_per_sec": 40, "duration": 18}, 12, "mem", 4),
        ("fork_bomb",        {"count": 20, "duration": 15}, 8, "procs", 5),
        ("cryptomining_sim", {"cores": 2, "duration": 15}, 10, "cpu", 12),
        ("slow_creep",       {"duration": 25}, 20, "cpu", 8),
    ]

    results = []
    for args in cases:
        results.append(test(*args))

    stop_all()

    passed = sum(1 for r in results if r == "WORKING")
    print()
    print("-" * 72)
    print(f"  RESULT: {passed}/{len(results)} attacks show measurable impact")
    print("=" * 72)
