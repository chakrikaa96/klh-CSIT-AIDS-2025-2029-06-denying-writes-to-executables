# fixtures/sandbox

A minimal tree used by `src/tests/unit/` to verify policy glob expansion and
the executable-detection rule in `eg_is_executable()`. The test copies this
tree to a temporary directory and sets file modes explicitly, so results do not
depend on how the repository was checked out.

| File | Mode set by test | Content | Executable per `eg_is_executable()`? |
|---|---|---|---|
| `bin/app` | 0755 | `#!/bin/sh` script | Yes (execute bit) |
| `bin/tool.sh` | 0644 | `#!/bin/sh` script | Yes (shebang) |
| `bin/elf-noexec` | 0644 | Begins with ELF magic `\x7fELF` | Yes (ELF magic) |
| `lib/readme.txt` | 0644 | Plain text | No |

With `policies/fixtures.conf.in`, the expected protected set is exactly the
three files under `bin/`; `lib/readme.txt` and the non-existent `bin/missing`
must be excluded.
