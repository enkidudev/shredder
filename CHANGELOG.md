# Changelog

## 1.1.1 - 2026-10-31

- Add optional RustScan TCP discovery via `--discovery rustscan`; Nmap remains the default and still runs all fingerprint/NSE and UDP stages.
- Display accepted open TCP ports immediately and flush each discovery into an append-only JSONL journal.
- Pin RustScan to frozen IPs, ignore user configuration, disable RustScan scripts, validate output addresses/ports and deduplicate events.
- Preserve partial discoveries on timeouts, nonzero exits and interrupts; retain all attempt files and validate completed discovery checkpoints with hashes.
- Add explicit RustScan binary, batch-size, timeout and retry controls; retain Nmap XML and rulebook processing after handoff.
- Preserve saved custom executable paths on resume and support earlier v1.1.0 state with new option defaults.
- Add subprocess-based streaming and hybrid-pipeline regressions; no real RustScan/Nmap benchmark is claimed.

## 1.1.0 - 2026-10-31

- Add an offline rule engine with ten built-in lead types, source links, explicit observation/follow-up status, deterministic priorities and explanations.
- Add default, quiet, plain and full Codec display behavior; retain professional saved reports and all findings.
- Add optional literal JSON rules without modifying core code.
- Add checkpoint-based stage resume, truncated XML/grepable recovery, preserved retry attempts, and scoped Nmap XML import including an offline mode.
- Add bounded concurrent HTTP endpoints, optional fixed web extras, duplicate-header preservation, default Host-port handling, and body hashes/file references in consolidated results.
- Default to T4; expose packet rate, retransmission and host timeout controls; use light version probes during targeted/custom stages.
- Reject host/mask scope widening, honor detected services over port guesses, escape remote Markdown, strip C1/bidi display controls and hash files in chunks.
- Add DNS UDP-to-TCP fallback and WinRM /wsman script argument.
- Expand regression tests, installation instructions and evidence documentation.

Version jumps from 0.1.0 to 1.1.0 follow the requested release name. This is not a claim that every recommendation in the improvement-plan PDF is implemented. Legacy TLS fallback, automatic domain-driven DNS queries, a full service-plugin refactor, broad new protocol coverage and live multi-service CI remain deferred.

## 0.1.0 - 2026-10-29

- Initial port discovery, service enumeration, direct HTTP/robots checks and evidence reports.
