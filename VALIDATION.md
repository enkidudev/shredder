# Validation — 0.1.0

Date: 2026-10-29
Environment: Linux, Python 3.12.14 (original verification) and Python 3.13.5 (GitHub release packaging).

Passed: 19/19 automated tests on Linux/Python 3.13.5 (`python -W error::ResourceWarning -m unittest discover -s tests -v`) and Python syntax compilation. The previous Linux/Python 3.12.14 verification also passed all 19 tests, CLI help, target-plan creation, and missing-Nmap dependency reporting. The timeout test was adjusted to start its child Python process with `-S` to avoid unrelated site-packages startup overhead exceeding the one-second test timeout.

The integration test launches real Python subprocesses acting as Nmap and supplies simulated XML. The HTTP test uses a real local HTTP server and verifies that redirect destinations are not requested and the supplied Host header is retained. No external target was scanned.

Not yet verified: actual Nmap/NSE execution, UDP packet capture, HTTPS/SNI handshakes, live DNS record queries, Windows/macOS execution, optional Rich rendering, or the hosted CI workflow. These require environment testing before relying on functionality in an engagement; they are not prerequisites to publishing the source code. The project depends on a separately installed Nmap; it does not bundle Nmap.

Implementation scope: port discovery, version fingerprints, default NSE category excluding redirect-following http-title, service-specific NSE, direct HTTP/robots collection, optional explicit-zone DNS records, custom named NSE, and evidence reports. Deeper wordlist scans and authenticated database workflows remain future modules.

Output update: added checks for interactive save selection, explicit output bypass, noninteractive output requirement, and quiet versus verbose display while preserving raw log contents.

Release packaging: MIT `LICENSE` added, SPDX `license = "MIT"` and `license-files` metadata set in `pyproject.toml`, and README updated with external Nmap dependency and license terms. GitHub Actions has not been run in GitHub.
