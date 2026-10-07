# reports/

| File | Contents |
|---|---|
| `ExecGuard_Project_Report.md` | Project report source: problem, background, comparison with existing approaches, design, implementation, verification, defects found, OS-concept mapping, limitations, future work, references |
| `ExecGuard_Project_Report.pdf` | The same report, A4, 13 pages |

The review material submitted earlier (`OSSP_Abstract.pdf`,
`OSSP_Project_PPT_Review 1.pdf`) stays at the repository root.

## Keeping the report current

Section 6.2 quotes the Level 1 run in `results/`. After the BPF-LSM VM run
(`sudo RESULTS_LABEL=vm make results`), add its functional, security and bypass
outcomes and the benchmark figures to Section 6.3 and 6.4 from that run's
`summary.md` and `benchmark.log`, then regenerate the PDF:

```sh
# Requires pandoc and a Chromium/Chrome binary.
awk 'n>=2 {print; next} /^---$/ {n++}' reports/ExecGuard_Project_Report.md > /tmp/body.md
pandoc /tmp/body.md -s -t html5 --metadata pagetitle="ExecGuard Project Report" -o /tmp/report.html
chromium --headless --no-pdf-header-footer --print-to-pdf=reports/ExecGuard_Project_Report.pdf /tmp/report.html
```
