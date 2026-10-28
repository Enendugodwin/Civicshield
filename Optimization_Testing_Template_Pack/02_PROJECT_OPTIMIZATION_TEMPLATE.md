# Project Optimization Template

## 1. Project Profile

| Field | Value |
|---|---|
| Project | |
| Version | |
| Repository | |
| Language | |
| Framework | |
| Runtime | |
| Deployment | VM / Container / Serverless / Agent |
| Main workload | |
| Expected users | |
| Requests/sec | |
| Events/sec | |
| Data volume | |
| Availability target | |

## 2. Architecture Bottleneck Review

- [ ] CPU-heavy operations
- [ ] Memory-heavy operations
- [ ] Disk I/O
- [ ] Network/API calls
- [ ] Database queries
- [ ] Queue/backlog
- [ ] Serialization/deserialization
- [ ] Authentication/authorization
- [ ] External dependencies
- [ ] Excessive logging
- [ ] Polling
- [ ] Lock/contention
- [ ] Startup/cold-start work

## 3. Application Optimization

### I/O
- [ ] Batch operations where safe.
- [ ] Stream large data.
- [ ] Reduce filesystem operations.
- [ ] Reuse connections.
- [ ] Avoid unnecessary serialization.
- [ ] Use async/non-blocking I/O where appropriate.

### Database
- [ ] Identify slow queries.
- [ ] Review execution plans.
- [ ] Remove N+1 patterns.
- [ ] Tune indexes from evidence.
- [ ] Limit returned rows/columns.
- [ ] Use bounded connection pools.
- [ ] Batch safe writes.
- [ ] Review locks/contention.
- [ ] Configure timeouts.

### Network/API
- [ ] Reuse connections.
- [ ] Configure connection/read/write timeouts.
- [ ] Use bounded retries.
- [ ] Use exponential backoff.
- [ ] Avoid unsafe blind retries.
- [ ] Minimize payloads.
- [ ] Cache safe repetitive calls.

### Concurrency
- [ ] Bound worker/thread/process counts.
- [ ] Prevent unbounded queues.
- [ ] Add backpressure.
- [ ] Minimize shared-state contention.
- [ ] Test race/deadlock conditions.

### Caching

| Cache | Data | TTL | Max Size | Invalidation | Hit Rate |
|---|---|---:|---:|---|---:|
| | | | | | |

## 4. Observability

Required metrics:
- Requests/sec
- Error rate
- P50/P95/P99 latency
- CPU
- Memory
- DB latency
- External dependency latency
- Queue depth
- Runtime/GC pauses where applicable

Required telemetry:
- [ ] Structured logs
- [ ] Correlation/request ID
- [ ] Metrics
- [ ] Health endpoint
- [ ] Readiness/liveness where applicable
- [ ] Tracing where useful

## 5. Performance Budget

| Metric | Budget | Baseline | Current | Pass? |
|---|---:|---:|---:|---|
| P50 latency | | | | |
| P95 latency | | | | |
| P99 latency | | | | |
| Throughput | | | | |
| Error rate | | | | |
| CPU | | | | |
| Memory | | | | |
| DB latency | | | | |

## 6. Optimization Loop

1. Capture baseline.
2. Profile.
3. Rank bottlenecks.
4. Make the smallest useful change.
5. Run unit/integration/functional tests.
6. Run security tests.
7. Run performance tests.
8. Compare against baseline.
9. Keep/rework/revert.
10. Record evidence.

## 7. Release Gates

- [ ] Functional tests pass.
- [ ] Regression tests pass.
- [ ] Security tests pass.
- [ ] Performance budget met.
- [ ] Resource budget met.
- [ ] Reliability tests pass.
- [ ] Rollback validated.
