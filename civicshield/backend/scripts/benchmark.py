"""CivicShield benchmark harness (per Optimization Pack §5).

Seeds the DB, then times key endpoints over N iterations and prints
P50/P95 + mean. Same script is used before/after optimization so the
comparison is apples-to-apples.
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

N = 5


def timeit(label, fn):
    samples = []
    out = None
    for _ in range(N):
        t0 = time.perf_counter()
        out = fn()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    p50 = samples[len(samples) // 2]
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    print(f"{label:28s} mean={statistics.mean(samples):8.1f}ms p50={p50:8.1f}ms p95={p95:8.1f}ms")
    return out


def main():
    seed()
    client = TestClient(app)
    timeit("GET /api/health", lambda: client.get("/api/health"))
    timeit("GET /api/assets", lambda: client.get("/api/assets"))
    timeit("GET /api/findings", lambda: client.get("/api/findings"))
    timeit("POST /api/assessments/run", lambda: client.post("/api/assessments/run"))
    run_id = client.get("/api/assessments").json()[-1]["id"]
    timeit("GET /api/assessments/{id}", lambda: client.get(f"/api/assessments/{run_id}"))
    timeit("GET export csv", lambda: client.get(f"/api/assessments/{run_id}/export", params={"format": "csv"}))
    timeit("POST /api/recovery/runs", lambda: client.post("/api/recovery/runs", json={"scenario_id": "app-loss"}))


if __name__ == "__main__":
    main()
