# data/

Inputs consumed by ExecGuard, its tests, and its evidence pipeline. Nothing in
this directory is generated; captured outputs live in `results/`.

| Path | Contents | Used by |
|---|---|---|
| `policies/demo.conf` | The default policy shipped in `src/config/execguard.conf` (protects the demo sandbox). | `src/scripts/demo.sh`, installation |
| `policies/audit-rollout.conf` | System-wide scope in `MODE audit`: logs what would be blocked without blocking it. | First stage of a rollout on a test VM |
| `policies/system-enforce.conf` | The same scope in `MODE enforce`, with `dpkg`/`apt` trusted. | Second stage of a rollout |
| `policies/empty-but-valid.conf` | Comments and blank lines only. Must validate. | Unit tests |
| `policies/invalid/*.conf` | Four deliberately malformed policies (unknown directive, bad mode, missing argument, bad `DENY` selector). Each must be rejected. | Unit tests |
| `policies/fixtures.conf.in` | Template policy over `fixtures/sandbox`; `@FIXTURES@` is substituted at test time. | Unit tests |
| `fixtures/sandbox/` | Small file tree exercising glob expansion and executable detection. See `fixtures/README.md`. | Unit tests |
| `test-cases/attack-matrix.csv` | Catalogue of all 29 kernel-enforcement test cases: technique, command, syscalls, LSM hook, expected decision and audit reason. | Kernel test suites, report |
| `schemas/audit-event.schema.json` | JSON Schema for one line of `audit.jsonl`. | Log consumers, dashboard |
| `schemas/baseline-entry.schema.json` | JSON Schema for one line of `baseline.jsonl`. | Integrity tooling |
| `schemas/enums.csv` | Numeric values of `eg_op`, `eg_decision`, `eg_reason` and how each is rendered in the log. | Log consumers |

## Using a policy

```sh
# Validate any policy without installing it.
EG_CONFIG=data/policies/audit-rollout.conf ./build/execguard policy validate

# Install one as the active policy on a test VM.
sudo install -m 0640 data/policies/audit-rollout.conf /etc/execguard/execguard.conf
sudo egctl reload
```

Protecting `/usr/bin/*` on a machine you depend on is not recommended. Use a
disposable VM and start with `audit-rollout.conf`.
