# ExecGuard results: cloud-build-container, 20261007T030825Z

| Item | Outcome |
|---|---|
| Host | Ubuntu 24.04.5 LTS, kernel 6.18.44-fc-v77 |
| Enforcement mode (check-env) | FANOTIFY_FALLBACK |
| Build from clean | OK in 1.2s, 0 warning(s) |
| Daemon | failed to start (see daemon.log) |
| Tests: unit | PASS (63 / 63 passed, 0 failed) |
| Tests: functional | SKIP (daemon not reachable / kernel lacks BPF-LSM) |
| Tests: security | SKIP (daemon not reachable / kernel lacks BPF-LSM) |
| Tests: bypass | SKIP (daemon not reachable / kernel lacks BPF-LSM) |
| Benchmark | skipped (no reachable daemon) |

## Files

- `bpf-sections.txt`
- `build-artifacts.txt`
- `build.log`
- `check-env.log`
- `daemon.log`
- `system.txt`
- `tests/bypass.log`
- `tests/functional.log`
- `tests/security.log`
- `tests/summary.log`
- `tests/unit.log`
