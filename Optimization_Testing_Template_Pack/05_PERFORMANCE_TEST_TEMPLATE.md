# Performance Test Template

## 1. Workload Definition

| Parameter | Value |
|---|---:|
| Concurrent users | |
| Requests/sec | |
| Events/sec | |
| Payload size | |
| Test duration | |
| Ramp-up | |
| Ramp-down | |

## 2. Test Types

### Baseline
Stable workload used as the comparison point.

### Load
Expected normal and peak workload.

### Stress
Increase workload until the safe operating limit is reached.

### Spike
Rapid workload increase/decrease.

### Soak
Long-duration workload to expose leaks/degradation.

## 3. Metrics

| Metric | Target | Baseline | Optimized | Delta | Pass |
|---|---:|---:|---:|---:|---|
| P50 latency | | | | | |
| P95 latency | | | | | |
| P99 latency | | | | | |
| Throughput | | | | | |
| Error rate | | | | | |
| CPU peak | | | | | |
| Memory peak | | | | | |
| Disk latency | | | | | |
| DB latency | | | | | |

## 4. Test Integrity

- [ ] Same build/config for before/after comparison.
- [ ] Same workload profile.
- [ ] Representative test data.
- [ ] Warm/cold cache state documented.
- [ ] Background workloads documented.
- [ ] Infrastructure contention documented.
- [ ] Timestamp + commit ID stored.

## 5. Result

### Baseline
- Throughput: ______
- P95: ______
- P99: ______
- Error rate: ______
- CPU: ______
- RAM: ______

### Optimized
- Throughput: ______
- P95: ______
- P99: ______
- Error rate: ______
- CPU: ______
- RAM: ______

### Change
- Throughput: ______ %
- P95: ______ %
- P99: ______ %
- Error rate: ______ %
- CPU: ______ %
- RAM: ______ %

## 6. Pass Rule

PASS only when functional, security and reliability tests pass and all performance/resource budgets are satisfied without unacceptable regression.
