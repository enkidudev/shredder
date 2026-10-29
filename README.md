# Shredder

Portable Python enumeration assistant for boxes and authorized engagements. Give it an IP, hostname, target list, or CIDR. It discovers ports, fingerprints services, runs default and targeted Nmap scripts, performs direct web checks, and preserves labeled evidence.

**Version 0.1.0 — initial implementation.** Python 3.10+. Designed for Linux, macOS and Windows. Local verification used Linux, real child-process tests, simulated Nmap scan output and a local HTTP server. Live Nmap scans, Windows and macOS execution are not yet verified. The included GitHub Actions matrix is ready for future CI; it has not run here.

## Install as a global command

**Required runtime dependencies:** Python 3.10+ and an existing [Nmap](https://nmap.org/download.html) installation (including its standard NSE scripts). Nmap is an external dependency, not bundled or installed by Shredder. Most penetration-testing distributions already include Nmap; install it only if it is missing. Nmap must be on `PATH`, or pass `--nmap` with its executable path. `pipx` is recommended for installing the `shredder` command globally for your user.

On Parrot/Debian, from the extracted project folder:

```bash
sudo apt update
sudo apt install pipx
command -v nmap >/dev/null || sudo apt install nmap
pipx ensurepath
pipx install '.[pretty,dns]'
```

Open a new terminal, then check the command:

```bash
command -v shredder
shredder --doctor
```

Now you can run `shredder TARGET` from any working directory. To update after changing the project, run `pipx install --force '.[pretty,dns]'` from its folder.

On macOS, install Nmap and pipx, then run `pipx install '.[pretty,dns]'` from the project folder. On Windows, install Nmap and Npcap, install pipx with `py -m pip install --user pipx`, then run `py -m pipx ensurepath` and `py -m pipx install '.[pretty,dns]'` from the project folder. Start a new terminal and use `shredder --doctor` to verify PATH and Nmap.

`rich` adds styled tables and color. `dnspython` adds directed DNS record queries. Both are optional: Python + external Nmap runs the core. Missing optional enhancements are reported; nothing is installed automatically.

## Terminal output and save location

Normal runs show short stage progress, completion times, service tables and web observations. Full Nmap banners, commands, timing messages and script dumps are saved to files. Add `--verbose` (or `-v`) to print the full stream as well. Failed stages show the last eight output lines and the full log path.

When `--output` / `-o` is omitted, an interactive run asks:

```text
Where should scan logs be saved? [./results]:
```

Enter a folder path, or press Enter for `./results`. Paths containing spaces and `~` are supported. The selected folder receives a new timestamped run folder. The prompt checks writability before starting scans. For scripts or redirected input, supply `-o PATH` explicitly.

```bash
shredder 10.129.118.240 --profile quick
shredder 10.129.118.240 --profile quick -o ~/engagements/trick
shredder 10.129.118.240 --profile quick --verbose
```

## Start

```bash
shredder 10.129.1.10
shredder target.htb --domain target.htb
shredder                         # interactive target/profile prompts
```

The default `full` profile scans TCP ports 1–65535 using TCP connect scanning, then fingerprints confirmed open ports and runs scripts. Normal Nmap timing (`T3`) is used, with no forced minimum packet rate. Hosts run sequentially to keep the output readable. This is an orchestration tool, not a new high-speed scanning engine.

```bash
# Quicker first pass: top 1,000 TCP ports
shredder 10.129.1.10 --profile quick

# All TCP plus top 100 UDP ports; requires root/admin and Nmap packet capture support
sudo .venv/bin/shredder 10.129.1.10 --profile full-udp

# Specific TCP ports, additional installed scripts
shredder target.htb --ports 21,22,53,80,443,445 --script smb-enum-users

# Exact DNS zone for record queries and AXFR attempt against discovered DNS services
shredder 10.129.1.10 --domain target.htb

# Authentication methods for an explicitly supplied SSH username
shredder target.htb --ssh-user enkidu

# Read scope from a file; omit specified targets
shredder -iL targets.txt --exclude 10.129.1.5 --exclude 10.129.2.0/24

# Review resolved target scope without scanning (hostname resolution still uses DNS)
shredder 10.129.1.0/28 --plan

# Discovery + fingerprint/default scripts, without targeted enumeration
shredder target.htb --skip-enum

# Turn off default NSE scripts, preserving targeted enumeration
shredder target.htb --no-default-scripts

# Custom output parent and timing
shredder target.htb -o engagement-alpha --timing 4 --timeout 1800
```

`targets.txt` accepts one IP, hostname or CIDR per line, with `#` comments. A domain resolving to several addresses includes every returned address in the explicit target plan. Targets are deduplicated and pinned to those addresses for the run. A default ceiling of 256 hosts prevents accidental huge expansions; `--max-hosts` changes it.

Use `--help` for all options. For Windows, substitute `.\.venv\Scripts\python.exe` for `python` if you have not activated the environment.

## Automatic coverage

| Service | Checks |
|---|---|
| HTTP/HTTPS | Direct `/` and `/robots.txt` requests, status, headers, title, Location, basic technology clues; bounded response capture; TLS certificate through NSE |
| SMB | Protocols, signing mode, time, OS discovery, anonymous/guest share enumeration as supported by NSE |
| DNS | Service ID and recursion checks; explicit `--domain` enables SOA/NS/A/AAAA/MX/TXT through dnspython and AXFR through NSE |
| FTP | Service/system information, anonymous access and directory listing when available |
| SSH | Version, host keys, algorithm list; supported authentication methods when `--ssh-user` is supplied |
| LDAP/LDAPS | RootDSE and bounded anonymous search (Nmap's default object limit) |
| RPC/NFS | RPC service registration and exported filesystem listings |
| Databases | Version/service probes; NSE metadata for MySQL, MSSQL, MongoDB and Redis; PostgreSQL/Oracle remain fingerprint-only |
| SMTP | Advertised commands and available NTLM information |
| RDP/WinRM | Security/NTLM information when supported |
| Other | Preserve Nmap service fingerprints and default-script findings |

A service's detected name routes the checks, so recognized services on unusual ports are included. Known port numbers are fallback clues; they are not proof of a service. NSE scripts still apply their own service rules and may not emit a finding. No output from a script means no reported result, not a verified absence of a problem.

The tool checks the local NSE index before targeted checks. Missing scripts are skipped and named in the report; a missing explicitly requested custom script stops the run before scanning. There are no additional service-specific executables to install in this version.

The default NSE category runs with **`http-title` excluded** because that script follows redirects. The direct web probe replaces its title check and records redirects without following them. Other NSE scripts retain their native behavior; the tool never adds discovered names to its target queue, but it is not a network sandbox for NSE. Custom scripts can have their own network behavior.

If multiple explicitly supplied hostnames resolve to the same IP, the direct web probe tries each supplied hostname with its original Host header and TLS SNI. Extra names found in certificates, script output, DNS answers or redirect locations stay in evidence for review. To scan one, add it as an explicit target in another run.

HTTPS collection accepts self-signed certificates to collect lab evidence; it does not certify trust or validate the certificate chain. Direct web responses can contain cookies or other sensitive values, and saved NSE output can contain credentials.

UDP `open|filtered` stays distinct from confirmed `open`. Fingerprint/default/targeted script stages use confirmed open ports; a UDP service that remains uncertain can therefore need manual follow-up. Nmap can generate an empty or failed fingerprint result on unsupported protocols, which is retained and marked partial.

## Custom NSE arguments

Use installed, literal NSE names with `--script name1,name2`; repeat the option as needed. Paths, wildcard categories, Boolean expressions and `+` forced execution are intentionally not exposed in this first interface. Extra scripts run in a separately labeled stage over the confirmed open ports.

For scripts needing arguments, put Nmap's argument syntax in a local file and pass:

```bash
shredder target.htb --script smb-enum-users --script-args-file /path/to/local-arguments.txt
```

The file is passed to all enabled NSE stages. Its contents are not copied into the command ledger, though scripts can print secrets in their results. `--domain` and `--ssh-user` supply their specific arguments during the targeted stage. Review exact argument names in the relevant [NSE documentation](https://nmap.org/nsedoc/).

## Evidence

Each invocation creates a new timestamped directory. Results are never overwritten across runs.

| File | Purpose |
|---|---|
| `plan.json` | Explicit inputs, frozen addresses and options |
| `commands.json` | Exact subprocess argument arrays, start/finish times, exit codes and errors |
| `results.json` | Combined services, states, script evidence, web observations, DNS records |
| `SUMMARY.md` | Readable notes and service tables |
| `SUMMARY.html` | Offline, escaped, dark-themed summary; no external scripts or assets |
| `SHA256.json` | SHA-256 hashes of saved run files after a completed, partial or interrupted scan |
| `<host>/01_tcp_discovery.*` | Discovery raw Nmap/XML/grepable output plus live-output log |
| `<host>/03_fingerprint_defaults.*` | Service/version/default-script evidence |
| `<host>/04_service_enumeration.*` | Targeted NSE evidence |
| `<host>/05_custom_scripts.*` | Optional extra-script evidence |
| `<host>/http_<port>_<index>.json` | HTTP metadata and up to 128 KiB of body per requested path |
| `<host>/dns_<port>_<protocol>.json` | Directed DNS records, errors, or missing-dependency notice |

`02_udp_discovery.*` is present for the UDP profile. The raw Nmap XML retains structured script details; combined results retain both script text and XML fragments. Normal output shows stage progress and the service table. With --verbose, findings are also printed as Nmap emits them. Raw files remain available for full detail. Remote terminal control characters are stripped for display; report HTML escapes remote content.

A stage timeout or nonzero scanner exit makes the run `partial`. `Ctrl+C` stops the active subprocess, keeps finished stages and available partial files, and produces an `interrupted` summary. There is no automatic resume yet. Timestamps inside evidence are UTC; the run folder uses the machine's local time.

Exit codes: `0` complete/planned, `1` partial scan, `2` input/dependency error, `130` interrupted. A `complete` run means orchestration finished; it does not assert every service was enumerated successfully. Individual HTTP/DNS failures remain in the evidence. Hashes detect file changes, but are not signatures or independent integrity attestation.

## Pivoted targets

TCP uses `-sT -Pn -n`, which is suitable for reachable routed targets such as those reached through Ligolo-ng. Set up and verify the route first. Shredder does not create tunnels, manage Ligolo sessions, change routes or require a particular pivot product. UDP behavior depends on the actual tunnel and privileges; verify it separately.

## Before relying on it

Run a quick scan against a known lab host, compare ports/services against a manual Nmap run, open the saved summary and verify the raw XML. Then test the full profile and interruption on your own environment. Exam use also depends on the applicable exam tool rules.

This first release does not include directory/vhost wordlist scans, recursive SMB downloads, authenticated database enumeration workflows, exploit execution, password spraying, automatic installation, pause/resume, or concurrent host scheduling. Those can be added as explicit modules after validating this baseline.

## Development and publication

```bash
python -m unittest discover -s tests -v
python -m py_compile shredder.py
```

The tests cover scope parsing and exclusions, option injection rejection, IPv6 input, evidence fidelity, uncertain UDP states, script routing, HTML escaping, terminal sanitization, child-process timeouts and exit codes, a simulated end-to-end Nmap run, and a real local HTTP server confirming Host handling and no redirect following. They do not substitute for live NSE, TLS, DNS, packet-capture or platform testing.

`results/`, virtual environments and common evidence extensions are excluded by `.gitignore`. If you choose another output directory, exclude it too. Do not publish engagement evidence or credential argument files. Shredder is distributed under the [MIT License](LICENSE). The license applies to Shredder source and does not relicense or redistribute Nmap, which remains a separate external dependency.

The MIT license permits use, modification and redistribution provided that the copyright and permission notices are preserved. Nmap remains a separate dependency and is not redistributed in this package.

## References

- [Nmap scan states](https://nmap.org/book/man-port-scanning-basics.html)
- [Port coverage](https://nmap.org/book/man-port-specification.html)
- [NSE selection and default-category behavior](https://nmap.org/book/man-nse.html)
- [Nmap output formats](https://nmap.org/book/man-output.html)
- [http-title redirect behavior](https://nmap.org/nsedoc/scripts/http-title.html)
- [DNS zone transfer arguments](https://nmap.org/nsedoc/scripts/dns-zone-transfer.html)
- [LDAP search limits](https://nmap.org/nsedoc/scripts/ldap-search.html)
- [SSH authentication-method check](https://nmap.org/nsedoc/scripts/ssh-auth-methods.html)
