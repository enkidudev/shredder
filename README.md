# Shredder

Portable Nmap enumeration with preserved evidence and an offline investigation queue.
**Version 1.1.1. Python 3.10+. External Nmap required for online scans.**

## Install or update

From this project folder on Parrot/Debian:

```bash
pipx install --force '.[pretty,dns]'
shredder --version
shredder --doctor
```

If pipx is missing, install it with `sudo apt install pipx`, run `pipx ensurepath`, and open a new terminal. If Nmap is missing, install it separately with `sudo apt install nmap`. Nmap is never bundled or installed automatically. Rich and dnspython are optional; the core and offline imports run without them.

Alternatively, `./install.sh` links the source checkout into `~/.local/bin/shredder`. Keep the whole project folder in place because the entry point imports `shredder_rules.py` and `shredder_rustscan.py`. Include `~/.local/bin` in PATH. For macOS/Windows, install Python, Nmap and pipx, then use the same pipx command (`py -m pipx` on Windows). Cross-platform runtime testing remains pending.

## Start

```bash
shredder 10.129.1.10 -o ~/engagements/target
shredder target.htb --profile quick --codec -o ./evidence
shredder 10.129.1.10 --web-extras --all-findings -o ./evidence
shredder 10.129.1.10 --quiet -o ./evidence
shredder 10.129.1.10 --plain -o ./evidence
```

Without `-o`, interactive sessions ask where to save. Noninteractive runs require `-o`. Each new run gets its own timestamped directory; timestamps in evidence are UTC.

Default coverage is all TCP ports, TCP connect (`-sT -Pn -n`) and `-T4`. The targeted and custom NSE stages use `--version-light`; the initial fingerprint stage retains normal version detection. This reduces repeated version-probe work, rather than eliminating all repeat probing. HTTP endpoints run concurrently (four workers by default), with sequential bounded requests per endpoint. Hosts and Nmap stages remain sequential.

```bash
shredder 10.129.1.10 --min-rate 1000 --max-retries 1 --host-timeout 300 -o ./evidence
shredder 10.129.1.10 --web-workers 8 -o ./evidence
shredder -iL targets.txt --exclude 10.129.1.5 --exclude 10.129.2.0/24 -o ./evidence
shredder 10.129.1.0/28 --plan -o ./evidence
```

Rate/retry overrides are optional; Nmap chooses them when omitted. Verify Ligolo-ng routing before scanning a pivoted host. Shredder does not create tunnels or change routes. UDP (`--profile full-udp`) still needs appropriate privileges and transport support. `open|filtered` is preserved as uncertain and is never promoted to confirmed open.

CIDRs must be network-aligned: `10.129.1.5/24` is rejected rather than silently expanded. Hostnames are resolved once and pinned. Discovered names and redirect destinations never join the scan queue.

## RustScan discovery with live ports

```bash
shredder 10.129.1.10 --discovery rustscan --codec -o ./evidence
shredder 10.129.1.10 --discovery rustscan --profile quick -o ./evidence
shredder 10.129.1.10 --discovery rustscan --ports 22,80,443,8000-8100 -o ./evidence
shredder 10.129.1.10 --discovery rustscan --rustscan-batch 4500 --rustscan-timeout 1500 --rustscan-tries 1 -o ./evidence
```

RustScan is a separately installed optional dependency; Nmap remains required for online enumeration. `--rustscan /path/to/rustscan` selects its executable. `--doctor --discovery rustscan` checks both executables. Nmap remains the default TCP discovery backend until live port-coverage comparisons are complete. RustScan does not replace the Nmap UDP stage in `full-udp` runs.

The adapter passes a single frozen IP, ignores RustScan user configuration with `--no-config`, selects accessible output, and disables its scripting with `--scripts none`. It deliberately does not use greppable mode, which suppresses live discovery lines. Shredder then starts its own Nmap fingerprint/default/targeted NSE stages on the discovered ports, saving the usual Nmap XML and command records. Nmap timing/rate switches govern Nmap stages; RustScan uses its separate batch/timeout/tries settings. RustScan timeouts are milliseconds; Shredder's stage timeout is seconds.

```text
  Discovered 22/tcp on 10.129.1.10 | 1 TCP ports found
  Discovered 80/tcp on 10.129.1.10 | 2 TCP ports found
```

Each distinct, in-scope TCP port is displayed as its line is received and immediately appended/flushed to `<host>/01_tcp_discovery.ports.jsonl`. Duplicate ports, other target addresses, invalid ports and ports outside an explicit `--ports` selection are ignored for handoff; raw output is retained. Quiet mode suppresses the display, not the journal. Full summaries update at stage boundaries, not on every individual port, to avoid rewriting large reports repeatedly. Buffering inside an external RustScan build can affect when its output arrives.

A completed discovery requires a successful process exit and a recognized, consistent final result (or its explicit zero-port diagnostic). Failed, timed-out or interrupted discovery retains known ports and stays partial. After a failed/timed-out sweep Shredder can still enumerate the known ports; Ctrl+C stops the workflow and saves them for resume. A later resume reruns incomplete discovery into a new attempt and reuses valid completed Nmap stages when their port/flag selection is unchanged. Successful RustScan discovery is reused only if its command and saved port/journal/log hashes match.

The `quick` profile uses RustScan's top-1000 selection, which is not promised to be identical to Nmap's installed service-frequency database. Full mode explicitly scans 1-65535. Explicit port ranges are translated to a single range or a literal list. Extremely fragmented lists beyond the portable command-length bound require `--discovery nmap`. No automatic switch to another backend occurs if RustScan is missing or fails.

Reference behavior was checked against [RustScan upstream source](https://github.com/bee-san/RustScan) at commit `9379033` (Cargo version 2.4.1). Real RustScan/Nmap execution and speed gains remain unverified here; this release tests the adapter with synthetic child processes.

## Check this first

The default terminal shows at most five leads per host. Each has an observation, a priority explanation, a next check and an evidence file. All matching leads and source references are saved in JSON, Markdown and offline HTML, regardless of terminal mode.

```text
[CODEC] Boss! Look what we got here.

01  CHECK FIRST | Anonymous FTP login accepted [21/tcp]
    Observed   ftp-anon reports anonymous login accepted.
    Priority   Authentication succeeded without supplied credentials;
               checking file access is a direct next step.
    Next move  List accessible files and inspect readable configurations/backups.
               Login alone does not prove file readability.
    Evidence   127.0.0.1/04_service_enumeration.xml -> ftp-anon
    Status     Observation recorded; follow-up unverified.
```

| Mode | Behavior |
|---|---|
| Default | Brief Codec introduction when leads match, progress, services and top five leads per host |
| `--codec` | Additional dialogue at start, host, resume and finish milestones |
| `--quiet` | Errors/warnings and final result path; saved evidence is unaffected |
| `--plain` | Plain text without styling or dialogue; lead details remain |
| `--all-findings` | Display every lead; independent of display mode |
| `--verbose` | Print scanner commands and live output; quiet takes precedence |

Priorities mean investigation order, not CVSS or vulnerability severity. A rule may confirm an observed login result or disclosed path, while exploitation, readable files and related impact remain unverified. Banners alone never produce automatic CVE findings. Unsupported conditions produce no lead, not a claim of safety. Duplicate rule hits are grouped by endpoint, with evidence references retained. See [the rulebook](docs/RULEBOOK.md).

## Web and service coverage

HTTP collects `/` and `/robots.txt`. `--web-extras` adds `/sitemap.xml`, `/.git/HEAD` and `/.well-known/security.txt`. No discovered paths or redirects are followed automatically. Each response is bounded to 128 KiB of body. Original headers, including repeated Set-Cookie fields, are preserved. HTTPS accepts self-signed certificates for evidence collection; this is not certificate trust validation. Legacy TLS compatibility and automatic scheme fallback are not included in v1.1.

Supplied hostnames retain Host/SNI while sockets connect only to the frozen scoped IP. Default Host ports are omitted. Body captures stay in per-endpoint JSON; consolidated results reference their paths and hashes rather than embedding copies. Completed successful HTTP captures are reused on resume; failed endpoints are retried into new files.

Detected services route targeted scripts; port numbers are fallback clues when the service is unknown, tcpwrapped, or only a table guess. Nmap's NSE portrules still decide which checks execute.

| Service | Checks |
|---|---|
| FTP | System information and anonymous access |
| SMB | Protocols, signing, time, OS discovery, share enumeration |
| LDAP | RootDSE and bounded anonymous search |
| RPC/NFS | RPC registration and export listings |
| DNS | NSID, recursion; explicit zone enables AXFR and directed records |
| SSH | Keys, algorithms, optional supported authentication methods |
| SMTP/RDP | Commands, NTLM information, encryption where applicable |
| WinRM | NTLM information with `/wsman` argument |
| Databases | Available MySQL/MSSQL/MongoDB/Redis NSE metadata; other protocols remain fingerprints |
| TLS | Certificate information through NSE |

```bash
shredder 10.129.1.10 --domain target.htb --ssh-user enkidu -o ./evidence
shredder target.htb --script smb-enum-users --script-args-file ./arguments.txt -o ./evidence
shredder target.htb --skip-enum -o ./evidence
shredder target.htb --no-default-scripts -o ./evidence
```

`--skip-enum` omits targeted NSE/direct web/DNS checks. Custom literal NSE scripts remain explicit and run separately. The default category excludes `http-title` because that script follows redirects. Other NSE scripts retain their native auxiliary network behavior; Shredder is not a network sandbox. Missing bundled scripts are reported and skipped; missing explicitly requested scripts stop the scan.

## Partial results and resume

```bash
# Supply the timestamped run directory, not its parent or an XML file.
shredder --resume ./evidence/20261031-223100-abc123 --codec
```

Successful scan stages are reused only when their XML hash and requested flags still match the checkpoint. Incomplete, failed, changed or missing stages are rerun; old files remain and new attempts receive `_attempt02`, `_attempt03`, etc. Saved addresses and scan options are reused without hostname re-resolution. Only display switches and executable paths (`--nmap`, `--rustscan`) may change during resume. The custom rule snapshot is retained in the run.

Checkpoint state is written after each scan stage. Complete port/script elements can be recovered from truncated XML; sibling `.gnmap` output supplies a further port fallback. On Ctrl+C the active scan is terminated, available evidence is recovered, and an interrupted report is saved. HTTP work already running can take its bounded request time to stop.

This resumes Shredder's workflow by rerunning incomplete stages. It does not continue an Nmap process at its exact prior packet position. The local run directory and its JSON state must be trusted. Resume supports v1.1.0/v1.1.1 online scan runs, not v0.1 directories, offline imports or plans. DNS probes are repeated on resume into separate evidence files.

## Import existing Nmap XML

```bash
# Offline interpretation. No Nmap executable or DNS resolution required.
shredder --import-xml scan.xml --import-only -o ./review

# Filter an offline import to an IP or network.
shredder 10.129.1.10 --import-xml scan.xml --import-only -o ./review

# Seed an online run. Explicit targets still define scan scope.
shredder 10.129.1.10 --import-xml scan.xml -o ./evidence

# Deliberately rely on imported port coverage, skipping discovery.
shredder 10.129.1.10 --import-xml scan.xml --skip-discovery -o ./evidence
```

Repeat `--import-xml` for several files. Raw XML and available sibling grepable files are copied into the run. An arbitrary XML file supplies evidence, not a checkpoint or scope authorization. Online discovery still runs unless `--skip-discovery` is explicitly selected. Incomplete imported scans do not establish full port coverage. Offline imports do not fetch web pages; they interpret supplied NSE evidence. Offline filtering accepts IP/CIDR inputs, not hostname resolution. The default 256-host ceiling still applies.

## Evidence and exits

| File | Purpose |
|---|---|
| `plan.json` | Frozen scope, original options and runtime/rule-engine provenance |
| `commands.json` | Commands, times, exit codes and failures, including earlier attempts |
| `checkpoints.json` | Stage completion, backend, requested flags/command, evidence paths and hashes |
| `<host>/*discovery*.ports.jsonl` | Live, append-only RustScan TCP discovery events |
| `<host>/*discovery*.ports.json` | Aggregated RustScan results and partial/completed status |
| `rules.json` | Snapshot of additional custom rules |
| `results.json` | Services, scripts, web metadata, DNS records and all ranked leads |
| `SUMMARY.md` / `SUMMARY.html` | Professional summaries; no Codec dialogue |
| `SHA256.json` | Chunked hashes of saved run files |
| `<host>/*.xml/.nmap/.gnmap/.log` | Raw scanner evidence and stdout/stderr logs |
| `<host>/http_*.json` | HTTP bodies and complete response headers |
| `import_*.xml/.gnmap` | Preserved imported evidence |

Terminal control characters and bidi overrides are stripped for display; Markdown and HTML escape remote content. Raw evidence remains intact and can contain credentials/cookies, so keep engagement outputs private. The code does not automatically redact raw evidence.

Exit codes: `0` completed/planned/offline import, `1` partial scan, `2` invalid input/dependency, `130` interrupted. Completed orchestration is not proof every service was fully enumerated. HTTP/DNS errors remain explicit in saved responses and do not themselves change the scanner-stage exit code.

## Development

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
python -m py_compile shredder.py shredder_rules.py shredder_rustscan.py
```

See [VALIDATION.md](VALIDATION.md) for executed checks and limits, and [CHANGELOG.md](CHANGELOG.md) for release changes. No exploit execution, credential spraying, authenticated database workflows or automatic vhost/directory wordlist scans are included.

MIT license applies to Shredder. Nmap remains a separately installed dependency under its own license.
