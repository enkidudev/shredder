"""RustScan discovery adapter. No scripts, hostname resolution or implicit scope."""
from __future__ import annotations

import ipaddress
import re


def selected_ports(spec):
    if not spec:
        return None
    result = set()
    for block in spec.split(','):
        bounds = [int(x) for x in block.split('-')]
        result.update(range(bounds[0], bounds[-1] + 1))
    return result


def discovery_command(args, address):
    """Use explicit CLI options; ignore user configuration and disable scripting."""
    address = str(ipaddress.ip_address(address))
    command = [args.rustscan, '--no-config', '--accessible', '--scripts', 'none',
               '--addresses', address, '--batch-size', str(args.rustscan_batch),
               '--timeout', str(args.rustscan_timeout), '--tries', str(args.rustscan_tries)]
    ports = selected_ports(args.ports)
    if ports:
        low, high = min(ports), max(ports)
        if len(ports) == high - low + 1:
            command += ['--range', f'{low}-{high}']
        else:
            value = ','.join(map(str, sorted(ports)))
            if len(value) > 24000:
                raise ValueError('Fragmented port list is too long for portable RustScan invocation; use --discovery nmap.')
            command += ['--ports', value]
    elif args.profile == 'quick':
        command += ['--top']
    else:
        command += ['--range', '1-65535']
    return command


def parse_event(line, address, allowed=None):
    """Return (ports, final-summary, no-open-message) for one scoped output line."""
    expected = ipaddress.ip_address(address)

    def same_ip(value):
        try:
            return ipaddress.ip_address(value.strip('[]')) == expected
        except ValueError:
            return False

    def valid(values):
        return all(1 <= p <= 65535 and (allowed is None or p in allowed) for p in values)

    match = re.fullmatch(r'Open\s+(\[?[^\s]+\]?):([0-9]{1,5})\s*', line.strip())
    if match and same_ip(match[1]):
        port = int(match[2])
        return ([port], False, False) if valid([port]) else ([], False, False)
    match = re.fullmatch(r'\s*(\S+)\s*->\s*\[([\d,\s]*)\]\s*', line)
    if match and same_ip(match[1]):
        tokens = match[2].strip()
        if not tokens:
            return [], True, False
        if not re.fullmatch(r'[0-9]{1,5}(?:\s*,\s*[0-9]{1,5})*', tokens):
            return [], False, False
        ports = list(map(int, re.split(r'\s*,\s*', tokens)))
        return (ports, True, False) if valid(ports) else ([], False, False)
    # RustScan reports zero discoveries with a diagnostic, not an empty summary.
    match = re.search(r"Looks like I didn't find any open ports for (\S+?)\.(?:\s|$)", line)
    return [], False, bool(match and same_ip(match[1]))


def port_record(number, source):
    return {'port': number, 'protocol': 'tcp', 'state': 'open', 'service': 'unknown',
            'version': '', 'tunnel': '', 'fingerprint': {}, 'discovery_source': source}
