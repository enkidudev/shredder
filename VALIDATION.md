# Validation - 1.1.1

Date: 2026-10-31. Platform: Linux. Python: 3.12.14.
Base repository: enkidudev/shredder, commit 4cc6faf (v0.1.0).

## Executed successfully

- 54/54 automated tests with ResourceWarning treated as an error:
  `python -W error::ResourceWarning -m unittest discover -s tests -q`.
- Python syntax compilation of shredder.py, shredder_rules.py and shredder_rustscan.py.
- `git diff --check`.
- Wheel build through pip, using the locally installed setuptools backend without build isolation or dependency downloads.
- Wheel installation into a clean virtual environment without optional dependencies.
- Installed command reports version 1.1.1 and displays the hybrid discovery options in CLI help.
- Installed command, invoked outside the source checkout, generates an offline report from synthetic Nmap XML with exit 0.
- Bundled example JSON rules load successfully.

The tests include real subprocesses producing synthetic Nmap XML, a failed-stage/retry/resume workflow, recovery from truncated XML and grepable output, hash/flag invalidation, interrupted-stage recovery, offline scope filtering without DNS/process calls, rule positives/negatives, duplicate suppression, scope rejection, display modes and report escaping.

The local HTTP integration tests use real loopback servers. They verify pinned Host headers, no redirect following, duplicate-header retention, fixed extra-path collection, body storage, cache reuse and concurrent endpoint requests. A barrier requires two endpoints to run together rather than relying on a fragile timing threshold.

## Hybrid discovery verification

The RustScan adapter was checked against upstream commit 9379033 (Cargo version 2.4.1), including explicit CLI flags, accessible `Open IP:PORT` events, summary format and disabled-script behavior. It uses `--no-config --accessible --scripts none`, without `--greppable`.

New regression cases verify IPv4/IPv6 output, rejected addresses/ports/noise, explicit port filtering, range/list translation, no implicit backend fallback, legacy v1.1.0 resume defaults, and continued Nmap UDP discovery. A real child process cannot finish until a test callback observes its first port in the flushed journal and terminal output. This proves streaming behavior of the adapter without presenting the child as a real RustScan binary.

The simulated hybrid pipeline tests an initial nonzero RustScan exit, retained discoveries, Nmap enumeration on the selected ports, discovery retry on resume, cached Nmap reuse, and subsequent completed discovery reuse. Independent cases cover timeouts, Ctrl+C recovery, hash invalidation, duplicate events and unsupported zero-exit output remaining partial.

## Explicit limits

No external target was scanned. Neither RustScan nor Nmap is installed in this workspace, so actual RustScan/Nmap/NSE execution and relative scan-speed improvements have not been benchmarked. Generated XML is marked synthetic in test source; it is not presented as a recorded lab scan.

Not exercised here: live DNS/dnspython fallback, HTTPS/SNI, WinRM, optional Rich rendering, UDP packet capture, Windows/macOS runtime behavior or hosted GitHub Actions. The inherited CI matrix remains configured but has not been run here. A known lab host should be used for live comparison against manual Nmap output before relying on a release in an engagement.

Nmap partial-result recovery can retain only complete elements or available grepable records. RustScan recovery retains accepted events already flushed to its journal. A resumed incomplete stage starts a fresh stage attempt; it does not resume Nmap at an exact packet position. Earlier attempts remain preserved. DNS probes are rerun. HTTP/DNS probe errors are recorded but do not change scanner-stage exit status.

The source branch is prepared locally; no GitHub push, tag or public release was performed.
