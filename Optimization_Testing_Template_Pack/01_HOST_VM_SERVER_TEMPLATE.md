# Host / VM / Server Optimization Template

## 1. System Profile

| Field | Value |
|---|---|
| Asset / Hostname | |
| Environment | DEV / TEST / UAT / PROD |
| Physical / VM / Cloud | |
| Hypervisor | VMware / Hyper-V / KVM / Other |
| OS / Version | |
| Workload | |
| Owner | |
| Date | |
| Build / Image version | |

## 2. Resource Baseline

| Metric | Baseline | Target | Tool | Result |
|---|---:|---:|---|---|
| CPU average % | | | | |
| CPU peak % | | | | |
| VM CPU Ready / Steal % | | | | |
| RAM average % | | | | |
| RAM peak % | | | | |
| Swap/Page pressure | | | | |
| Disk latency ms | | | | |
| Disk IOPS | | | | |
| Disk throughput MB/s | | | | |
| Network latency ms | | | | |
| Network throughput | | | | |
| Packet loss % | | | | |
| Process count | | | | |
| Startup time | | | | |
| Application P95 ms | | | | |
| Application P99 ms | | | | |

## 3. CPU Optimization

- [ ] Remove unnecessary services/processes.
- [ ] Check host CPU contention.
- [ ] Check VM CPU Ready / steal time.
- [ ] Avoid excessive vCPU allocation.
- [ ] Align application worker/thread count with available CPU.
- [ ] Profile CPU-heavy processes.
- [ ] Check interrupt/driver issues where relevant.

## 4. Memory Optimization

- [ ] Size RAM from observed workload.
- [ ] Check swap/page pressure.
- [ ] Check memory leaks.
- [ ] Bound caches.
- [ ] Tune runtime heap where applicable.
- [ ] Check VM ballooning/compression.
- [ ] Check host memory pressure.

## 5. Storage Optimization

- [ ] Identify read/write-heavy workloads.
- [ ] Use SSD/NVMe for latency-sensitive workloads.
- [ ] Check disk latency and queue depth.
- [ ] Check datastore/storage contention.
- [ ] Separate high-write logs/data/temp workloads where beneficial.
- [ ] Configure log rotation/retention.
- [ ] Check free capacity and inode capacity (Linux).
- [ ] Benchmark before/after changes.

## 6. Network Optimization

- [ ] Verify NIC/virtual NIC driver.
- [ ] Verify link speed/duplex.
- [ ] Check packet loss and retransmits.
- [ ] Verify MTU consistency.
- [ ] Measure DNS resolution time.
- [ ] Remove unused interfaces.
- [ ] Measure end-to-end application latency.

## 7. OS Optimization

### Linux
- [ ] Remove unnecessary services.
- [ ] Verify time synchronization.
- [ ] Review file-descriptor/process limits.
- [ ] Configure log rotation.
- [ ] Review filesystem configuration.
- [ ] Review kernel parameters only when workload evidence supports it.
- [ ] Apply security updates.

### Windows Server
- [ ] Remove unnecessary roles/features.
- [ ] Review service startup types.
- [ ] Review power/performance plan.
- [ ] Review page-file behavior.
- [ ] Configure event-log retention.
- [ ] Apply OS/driver/security updates.
- [ ] Endpoint-security exclusions only through approved change control.

## 8. VM Optimization

- [ ] VM integration tools current.
- [ ] Correct virtual hardware.
- [ ] Check CPU/RAM overcommit.
- [ ] Check datastore latency.
- [ ] Check host contention.
- [ ] Review NUMA for large VMs.
- [ ] Remove unnecessary virtual devices.
- [ ] Keep snapshots controlled.

## 9. Host/System Tests

### Capacity
- [ ] CPU pressure
- [ ] Memory pressure
- [ ] Disk I/O
- [ ] Network throughput

### Reliability
- [ ] Reboot recovery
- [ ] Service restart
- [ ] Temporary network loss
- [ ] Database/dependency outage
- [ ] Disk-full behavior
- [ ] High CPU behavior
- [ ] Low-memory behavior
- [ ] Restore/rollback test

## 10. Acceptance Criteria

| Gate | Limit |
|---|---:|
| CPU peak | <= ____ % |
| Memory peak | <= ____ % |
| Disk latency | <= ____ ms |
| Packet loss | <= ____ % |
| P95 latency | <= ____ ms |
| P99 latency | <= ____ ms |
| Error rate | <= ____ % |
| Recovery time | <= ____ sec |
