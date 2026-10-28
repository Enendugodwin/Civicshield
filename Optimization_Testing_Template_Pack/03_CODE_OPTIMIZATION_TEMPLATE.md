# Code Optimization Template

## 1. Scope

| Field | Value |
|---|---|
| Repository | |
| Branch | |
| Commit | |
| Module / Function | |
| Language | |
| Runtime | |
| Goal | |

## 2. Profiling Evidence

| Area | Finding | Tool | Evidence |
|---|---|---|---|
| CPU | | | |
| Memory | | | |
| Allocations | | | |
| I/O | | | |
| Database | | | |
| Network | | | |
| Locks/contention | | | |
| Startup | | | |

## 3. Algorithm / Data Structure

- [ ] Review time complexity.
- [ ] Review space complexity.
- [ ] Remove duplicate work.
- [ ] Avoid unnecessary sorting.
- [ ] Use suitable maps/sets/indexes.
- [ ] Reduce avoidable nested loops.
- [ ] Precompute reusable results when justified.
- [ ] Avoid repeated parsing/conversion.

## 4. Memory

- [ ] Check leaks.
- [ ] Avoid retaining unused objects.
- [ ] Avoid unnecessary copies.
- [ ] Stream large datasets.
- [ ] Bound caches.
- [ ] Reuse expensive resources safely.
- [ ] Check collection growth.

## 5. I/O

- [ ] Batch DB/filesystem operations.
- [ ] Reduce network round trips.
- [ ] Reuse connections.
- [ ] Avoid blocking I/O in latency-critical paths.
- [ ] Configure timeouts.
- [ ] Compress only when trade-off is favorable.

## 6. Concurrency

- [ ] Bound concurrency.
- [ ] Avoid deadlocks.
- [ ] Check race conditions.
- [ ] Minimize critical sections.
- [ ] Bound queues.
- [ ] Validate worker/thread counts with benchmarks.

## 7. Security Preservation

- [ ] No hard-coded secrets.
- [ ] No sensitive information in logs.
- [ ] Input validation preserved.
- [ ] Authorization preserved.
- [ ] TLS validation preserved.
- [ ] Timeouts preserved.
- [ ] Retries remain bounded.
- [ ] Dependencies checked.

## 8. Optimization Record

| Issue | Evidence | Change | Before | After | Regression? | Decision |
|---|---|---|---:|---:|---|---|
| | | | | | | |

## 9. Definition of Done

- [ ] Benchmark reproducible.
- [ ] Functional behavior preserved/intentionally changed.
- [ ] Performance improvement measured.
- [ ] Resource impact checked.
- [ ] Tests added or updated.
- [ ] Security checks pass.
- [ ] Code reviewed.
