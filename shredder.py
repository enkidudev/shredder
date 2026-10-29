#!/usr/bin/env python3
"""Shredder: portable enumeration orchestration; Python 3.10+, external Nmap."""
from __future__ import annotations

import argparse
import ctypes
from collections import deque
import hashlib
import html
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

VERSION = '0.1.0'
SCRIPTS = {
    'smb': ['smb-protocols', 'smb2-security-mode', 'smb2-time', 'smb-os-discovery', 'smb-enum-shares'],
    'dns': ['dns-nsid', 'dns-recursion'],
    'ftp': ['ftp-anon', 'ftp-syst'],
    'ssh': ['ssh-hostkey', 'ssh2-enum-algos'],
    'ldap': ['ldap-rootdse', 'ldap-search'],
    'rpc': ['rpcinfo', 'nfs-showmount'],
    'database': ['mysql-info', 'ms-sql-info', 'mongodb-info', 'redis-info'],
    'smtp': ['smtp-commands', 'smtp-ntlm-info'],
    'rdp': ['rdp-ntlm-info', 'rdp-enum-encryption'],
    'winrm': ['http-ntlm-info'],
    'tls': ['ssl-cert'],
}
# http-title follows redirects. A direct HTTP probe below replaces it.
DEFAULT_EXPRESSION = '(default and not http-title)'
ANSI = re.compile(r'\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]')


def clean(value):
    return ANSI.sub('', str(value))


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    temporary.replace(path)


class UI:
    def __init__(self, plain=False):
        self.console = None
        if not plain:
            try:
                from rich.console import Console
                self.console = Console(highlight=False)
            except ImportError:
                pass

    def say(self, value, style=None):
        value = clean(value)
        if self.console:
            self.console.print(value, markup=False, style=style)
        else:
            print(value, flush=True)

    def table(self, ports):
        if self.console:
            from rich.table import Table
            table = Table(title='Discovered services', header_style='bold cyan', expand=True)
            for name in ('Port', 'State', 'Service', 'Version'):
                table.add_column(name)
            for p in ports:
                table.add_row(f"{p['port']}/{p['protocol']}", p['state'], clean(p['service']), clean(p['version']))
            self.console.print(table)
        else:
            for p in ports:
                self.say(f"{p['port']:>5}/{p['protocol']}  {p['state']:<14} {p['service']:<18} {p['version']}")


def normalize_target(value):
    value = value.strip()
    if not value or value.startswith('-') or any(c.isspace() for c in value):
        raise ValueError(f'Invalid target: {value!r}')
    if '/' in value:
        return str(ipaddress.ip_network(value, strict=False))
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        pass
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')):
        raise ValueError(f'Use an IP or hostname, without a URL or port: {value!r}')
    return value


def resolve_targets(entries, limit, exclusions):
    """Freeze user-supplied names to addresses once; never expand discovered names."""
    excluded = []
    for entry in exclusions:
        target = normalize_target(entry)
        if '/' in target:
            excluded.append(ipaddress.ip_network(target))
        else:
            try:
                excluded.append(ipaddress.ip_network(target))
            except ValueError:
                excluded.extend(ipaddress.ip_network(x[4][0]) for x in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM))
    hosts = {}
    for entry in entries:
        target = normalize_target(entry)
        if '/' in target:
            net = ipaddress.ip_network(target)
            if net.num_addresses > limit + 2:
                raise ValueError(f'{target} exceeds --max-hosts {limit}; split the range or explicitly raise the limit.')
            addresses = [str(a) for a in net.hosts()]
        else:
            try:
                addresses = [str(ipaddress.ip_address(target))]
            except ValueError:
                addresses = sorted({x[4][0] for x in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)})
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if any(ip.version == net.version and ip in net for net in excluded):
                continue
            item = hosts.setdefault(address, {'address': address, 'inputs': []})
            if target not in item['inputs']:
                item['inputs'].append(target)
            if len(hosts) > limit:
                raise ValueError(f'Too many targets; --max-hosts is {limit}.')
    if not hosts:
        raise ValueError('No targets remain after exclusions.')
    return list(hosts.values())


def parse_xml(path, expected_address):
    root = ET.parse(path).getroot()
    ports, scripts, names = [], [], []
    for host in root.findall('host'):
        if expected_address not in [a.get('addr') for a in host.findall('address')]:
            continue
        names.extend(h.get('name') for h in host.findall('hostnames/hostname') if h.get('name'))
        for node in host.findall('ports/port'):
            state = node.find('state')
            service = node.find('service')
            attrs = service.attrib if service is not None else {}
            port = {'port': int(node.get('portid')), 'protocol': node.get('protocol'),
                    'state': state.get('state', 'unknown') if state is not None else 'unknown',
                    'service': attrs.get('name', 'unknown'), 'tunnel': attrs.get('tunnel', ''),
                    'version': ' '.join(attrs[k] for k in ('product', 'version', 'extrainfo') if attrs.get(k)),
                    'fingerprint': attrs}
            ports.append(port)
            for script in node.findall('script'):
                scripts.append({'port': port['port'], 'protocol': port['protocol'],
                                'id': script.get('id'), 'output': script.get('output', ''),
                                'xml': ET.tostring(script, encoding='unicode')})
        for script in host.findall('hostscript/script'):
            scripts.append({'port': None, 'protocol': None, 'id': script.get('id'),
                            'output': script.get('output', ''), 'xml': ET.tostring(script, encoding='unicode')})
    return {'ports': ports, 'scripts': scripts, 'discovered_names': names,
            'finished': root.find('runstats/finished').attrib if root.find('runstats/finished') is not None else {}}


def families(port):
    n, s = port['port'], port['service'].lower()
    result = set()
    if 'http' in s or n in {80, 443, 8000, 8080, 8443, 5985, 5986}:
        result.add('http')
    if 'microsoft-ds' in s or 'netbios-ssn' in s or n in {139, 445}: result.add('smb')
    if s == 'domain' or n == 53: result.add('dns')
    if s in {'ftp', 'ftps'} or n == 21: result.add('ftp')
    if s == 'ssh' or n == 22: result.add('ssh')
    if 'ldap' in s or n in {389, 636, 3268, 3269}: result.add('ldap')
    if s in {'rpcbind', 'nfs'} or n in {111, 2049}: result.add('rpc')
    if any(x in s for x in ('mysql', 'ms-sql', 'postgres', 'mongodb', 'redis', 'oracle')) or n in {1433, 1521, 3306, 5432, 6379, 27017}:
        result.add('database')
    if 'smtp' in s or n in {25, 465, 587}: result.add('smtp')
    if s == 'ms-wbt-server' or n == 3389: result.add('rdp')
    if n in {5985, 5986}: result.add('winrm')
    if port['tunnel'] == 'ssl' or n in {443, 465, 636, 8443, 5986, 3269}: result.add('tls')
    return result


def elevated():
    if os.name == 'nt':
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def tcp_flags(args, target):
    return ['-n', '-Pn', '-sT', '-T' + args.timing, '--stats-every', '10s'] + (['-6'] if ':' in target else [])


def port_spec(ports):
    return ','.join(f"{proto[0].upper()}:" + ','.join(str(p['port']) for p in ports if p['protocol'] == proto)
                    for proto in ('tcp', 'udp') if any(p['protocol'] == proto for p in ports))


class Runner:
    def __init__(self, args, directory, ui):
        self.args, self.directory, self.ui = args, directory, ui
        self.commands = []
        self.partial = False
        self.failures = 0

    def save(self):
        write_json(self.directory / 'commands.json', self.commands)

    def run(self, command, stem):
        label = stem.name.split('_', 1)[-1].replace('_', ' ').capitalize()
        verbose = self.args.verbose
        self.ui.say('\n' + label + '…', 'cyan')
        if verbose:
            self.ui.say('> ' + subprocess.list2cmdline(command), 'cyan')
        tail = deque(maxlen=8)
        status = None
        if not verbose and self.ui.console and self.ui.console.is_terminal:
            status = self.ui.console.status(label + '…', spinner='dots')
            status.start()
        record = {'argv': command, 'started': now(), 'status': 'running', 'log': str(stem.relative_to(self.directory)) + '.log'}
        self.commands.append(record)
        self.save()
        proc = None
        thread = None
        started = time.monotonic()
        heartbeat = started
        try:
            with stem.with_suffix('.log').open('w', encoding='utf-8') as log:
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding='utf-8', errors='replace', bufsize=1)
                lines = queue.Queue()
                def reader():
                    try:
                        for line in proc.stdout: lines.put(line)
                    finally:
                        lines.put(None)
                thread = threading.Thread(target=reader, daemon=True)
                thread.start()
                while True:
                    elapsed = time.monotonic() - started
                    if status:
                        status.update(f'{label}… {int(elapsed)}s elapsed')
                    elif not verbose and time.monotonic() - heartbeat >= 60:
                        self.ui.say(f'  Still running ({int(elapsed)}s elapsed)…', 'dim')
                        heartbeat = time.monotonic()
                    if time.monotonic() - started > self.args.timeout:
                        raise TimeoutError(f'Stage exceeded {self.args.timeout}s.')
                    try:
                        line = lines.get(timeout=0.2)
                    except queue.Empty:
                        if proc.poll() is not None and not thread.is_alive(): break
                        continue
                    if line is None: break
                    log.write(line)
                    log.flush()
                    tail.append(line.rstrip())
                    if verbose:
                        self.ui.say(line.rstrip())
                code = proc.wait(timeout=max(0.1, self.args.timeout - (time.monotonic() - started)))
                record.update(returncode=code, status='complete' if code == 0 else 'failed')
                if code:
                    self.partial = True
                    self.failures += 1
        except KeyboardInterrupt:
            record['status'] = 'interrupted'
            self.partial = True
            self.failures += 1
            raise
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            record.update(status='failed', error=str(exc))
            self.partial = True
            self.failures += 1
            self.ui.say(str(exc), 'yellow')
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if thread:
                thread.join(timeout=1)
            if proc and proc.stdout:
                proc.stdout.close()
            if status:
                status.stop()
            record['finished'] = now()
            self.save()
            self.ui.say(f"  {record['status'].capitalize()} ({time.monotonic() - started:.1f}s)",
                        'green' if record['status'] == 'complete' else 'yellow')
            if record['status'] == 'failed' and not verbose:
                for line in tail:
                    self.ui.say('  ' + line, 'yellow')
                self.ui.say(f'  Full log: {stem.with_suffix(".log")}')
        return record['status'] == 'complete'

    def scan(self, host, directory, label, flags):
        stem = directory / label
        command = [self.args.nmap] + flags + ['-oA', str(stem), host['address']]
        success = self.run(command, stem)
        path = stem.with_suffix('.xml')
        if path.exists():
            try:
                parsed = parse_xml(path, host['address'])
                if parsed['finished'].get('exit') == 'error':
                    self.partial = True
                    self.failures += 1
                return parsed
            except (ET.ParseError, ValueError) as exc:
                self.ui.say(f'Incomplete XML for {label}: {exc}; raw output retained.', 'yellow')
        self.partial = True
        self.failures += 1
        return {'ports': [], 'scripts': [], 'discovered_names': [], 'finished': {}, 'failed': not success}


def http_probe(address, hostname, port):
    """Pin socket to the approved IP, preserve Host/SNI, never follow redirects."""
    secure = port['tunnel'] == 'ssl' or port['port'] in {443, 8443, 5986}
    records = []
    for path in ('/', '/robots.txt'):
        conn = http.client.HTTPConnection(address, port['port'], timeout=8)
        try:
            conn.connect()
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn.sock = context.wrap_socket(conn.sock, server_hostname=hostname)
            host_header = f'[{hostname}]' if ':' in hostname else hostname
            conn.request('GET', path, headers={'Host': f"{host_header}:{port['port']}",
                                              'User-Agent': f'Shredder/{VERSION}', 'Accept-Encoding': 'identity'})
            response = conn.getresponse()
            body = response.read(131073)
            text = body[:131072].decode('utf-8', errors='replace')
            title = re.search(r'<title\b[^>]*>(.*?)</title>', text, re.I | re.S)
            clues = [name for name, pattern in {'WordPress': r'wp-content|wp-includes',
                     'Drupal': r'Drupal|sites/default/files', 'Joomla': r'com_content|Joomla',
                     'ASP.NET': r'__VIEWSTATE|ASP.NET', 'Next.js': r'__NEXT_DATA__|/_next/'}.items()
                     if re.search(pattern, text, re.I)]
            records.append({'path': path, 'status': response.status, 'headers': dict(response.getheaders()),
                            'title': html.unescape(re.sub(r'\s+', ' ', title.group(1))).strip() if title else '',
                            'technology_clues': clues, 'location': response.getheader('Location'),
                            'redirect_followed': False, 'body_truncated': len(body) > 131072,
                            'body': text, 'tls_certificate_verified': False if secure else None})
        except (OSError, http.client.HTTPException) as exc:
            records.append({'path': path, 'error': str(exc)})
        finally:
            conn.close()
    return records


def dns_probe(address, port, zone):
    """Explicit-zone DNS queries, sent only to the approved target DNS service."""
    try:
        import dns.message
        import dns.query
        import dns.rdatatype
    except ImportError:
        return [{'skipped': 'DNS record queries require dnspython; AXFR via NSE remains available.'}]
    records = []
    for kind in ('SOA', 'NS', 'A', 'AAAA', 'MX', 'TXT'):
        try:
            query = dns.message.make_query(zone, kind)
            response = (dns.query.tcp if port['protocol'] == 'tcp' else dns.query.udp)(
                query, address, port=port['port'], timeout=4)
            records.append({'type': kind, 'rcode': response.rcode(),
                            'answers': [r.to_text() for r in response.answer]})
        except Exception as exc:
            records.append({'type': kind, 'error': str(exc)})
    return records


def choose_scripts(ports, zone=None):
    groups = set().union(*(families(p) for p in ports)) if ports else set()
    scripts = sorted({s for group in groups for s in SCRIPTS.get(group, [])})
    if 'dns' in groups and zone:
        scripts.append('dns-zone-transfer')
    return scripts


def supported_scripts(nmap, requested, ui):
    """Query the local NSE index without contacting a target; skip missing scripts."""
    if not requested: return [], []
    try:
        command = [nmap, '--script-help', ','.join(requested), '-oX', '-']
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
        # Missing script names may abort the entire query. Retry separately only then.
        root = ET.fromstring(result.stdout)
        available = {s.get('filename', '').replace('\\', '/').rsplit('/', 1)[-1].removesuffix('.nse')
                     for s in root.findall('.//script')}
        found = [s for s in requested if s in available]
        if result.returncode == 0 and len(found) == len(requested): return found, []
    except (OSError, ET.ParseError, subprocess.TimeoutExpired):
        pass
    found, missing = [], []
    for script in requested:
        try:
            result = subprocess.run([nmap, '--script-help', script], capture_output=True,
                                    text=True, encoding='utf-8', errors='replace', timeout=10)
            (found if result.returncode == 0 and re.search(r'(?m)^' + re.escape(script) + r'\s*$', result.stdout) else missing).append(script)
        except (OSError, subprocess.TimeoutExpired):
            missing.append(script)
    if missing: ui.say('Unavailable NSE scripts (skipped): ' + ', '.join(missing), 'yellow')
    return found, missing


def merge_results(data, result, stage):
    for port in result['ports']:
        existing = next((p for p in data['ports'] if (p['port'], p['protocol']) == (port['port'], port['protocol'])), None)
        if existing:
            if port['service'] == 'unknown' and existing['service'] != 'unknown':
                port['service'], port['version'], port['tunnel'], port['fingerprint'] = existing['service'], existing['version'], existing['tunnel'], existing['fingerprint']
            existing.update(port)
        else: data['ports'].append(port)
    data['scripts'].extend(dict(s, stage=stage) for s in result['scripts'])
    data['discovered_names'] = sorted(set(data['discovered_names'] + result['discovered_names']))


def render_report(directory, report):
    write_json(directory / 'results.json', report)
    content = ['# Shredder engagement summary', '', f"Started: {report['started']}",
               f"Status: {report['status']}", '',
               'New names and redirect locations are evidence only; they are never added to the target queue.', '']
    if report.get('missing_scripts'):
        content += ['Unavailable NSE scripts (skipped): ' + ', '.join(report['missing_scripts']), '']
    for host in report['hosts']:
        content += [f"## {host['address']}", '', f"Inputs: {', '.join(host['inputs'])}", '',
                    f"Status: {host.get('status', 'pending')}", '', '| Port | State | Service | Version |', '|---|---|---|---|']
        for p in sorted(host['ports'], key=lambda p: (p['protocol'], p['port'])):
            fields = [f"{p['port']}/{p['protocol']}", p['state'], p['service'], p['version']]
            content.append('| ' + ' | '.join(clean(f).replace('|', '\\|').replace('\n', ' ') for f in fields) + ' |')
        content += ['', '### Script findings', '']
        for script in host['scripts']:
            content += [f"**{clean(script['id'])} — {script['port'] or 'host'} ({script['stage']})**", '']
            content.extend('    ' + line for line in clean(script['output']).splitlines())
            content.append('')
        for web in host['http']:
            for item in web['responses']:
                content += [f"HTTP {web['port']} {item['path']}: {item.get('status', item.get('error'))}", '',
                            '    ' + clean(item.get('title', '')), '']
                if item.get('location'): content += ['Redirect recorded: ' + clean(item['location']), '']
        for dns_result in host.get('dns', []):
            content += ['DNS records:', ''] + ['    ' + clean(json.dumps(item)) for item in dns_result] + ['']
        if host['discovered_names']: content += ['Names for review: ' + ', '.join(map(clean, host['discovered_names'])), '']
        if host.get('notes'): content += ['Notes: ' + '; '.join(map(clean, host['notes'])), '']
    markdown = '\n'.join(content)
    (directory / 'SUMMARY.md').write_text(markdown, encoding='utf-8')
    # Escape everything sourced from remote systems. Offline HTML has no scripts/assets.
    page = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
    page += '<title>Shredder results</title><style>body{background:#11141d;color:#e1e6ef;font:15px/1.7 system-ui;max-width:1100px;margin:40px auto;padding:20px}h1{color:#67e8cf}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#191f2c;padding:24px;border:1px solid #394153;border-radius:12px}</style>'
    page += '<h1>SHREDDER / Engagement evidence</h1><p>Raw scans and structured results accompany this summary.</p><pre>' + html.escape(markdown) + '</pre></html>'
    (directory / 'SUMMARY.html').write_text(page, encoding='utf-8')


def positive(value):
    number = int(value)
    if number < 1: raise argparse.ArgumentTypeError('Must be a positive integer.')
    return number


def ports_value(value):
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', value):
        raise argparse.ArgumentTypeError('Use port numbers/ranges, e.g. 22,80,443,8000-8100.')
    for block in value.split(','):
        pair = list(map(int, block.split('-')))
        if any(p < 1 or p > 65535 for p in pair) or pair[0] > pair[-1]:
            raise argparse.ArgumentTypeError('Ports must be ordered ranges within 1–65535.')
    return value


def parser():
    p = argparse.ArgumentParser(description='Shredder — port discovery, service enumeration and organized evidence.',
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('targets', nargs='*', help='IP, hostname or CIDR; repeat to add explicitly scoped targets')
    p.add_argument('-iL', '--targets-file', type=Path, help='One IP/hostname/CIDR per line; # comments accepted')
    p.add_argument('--exclude', action='append', default=[], help='Exclude IP, hostname or CIDR; repeatable')
    p.add_argument('--profile', choices=['quick', 'full', 'full-udp'], default='full', help='1000 TCP; all TCP; all TCP + top UDP')
    p.add_argument('--ports', type=ports_value, help='Override TCP discovery ports')
    p.add_argument('--udp-top', type=positive, default=100, help='UDP ports for full-udp profile')
    p.add_argument('--timing', choices=['2', '3', '4'], default='3')
    p.add_argument('--timeout', type=positive, default=3600, help='Maximum seconds per external scan stage')
    p.add_argument('--script-timeout', type=positive, default=60, help='Maximum seconds per NSE script')
    p.add_argument('--max-hosts', type=positive, default=256)
    p.add_argument('--script', action='append', default=[], help='Extra literal NSE names, comma-separated; repeatable')
    p.add_argument('--script-args-file', type=Path, help='Nmap script arguments file (may contain credentials)')
    p.add_argument('--domain', help='Explicit DNS zone to query through discovered target DNS services')
    p.add_argument('--ssh-user', help='Explicit username for SSH supported-authentication-method check')
    p.add_argument('--skip-enum', action='store_true', help='Run discovery and default scripts only')
    p.add_argument('--no-default-scripts', action='store_true')
    p.add_argument('-o', '--output', type=Path, help='Save directory; prompts when omitted (Enter uses ./results)')
    p.add_argument('-v', '--verbose', action='store_true', help='Show full live scanner output and commands')
    p.add_argument('--nmap', default='nmap', help='Nmap executable name or path')
    p.add_argument('--plain', action='store_true', help='Disable optional Rich styling')
    p.add_argument('--plan', action='store_true', help='Resolve inputs and save plan, without scanning')
    p.add_argument('--doctor', action='store_true', help='Check local dependencies without scanning')
    p.add_argument('--version', action='version', version=VERSION)
    return p


def choose_output(output, ui):
    if output is not None:
        return output.expanduser()
    if not sys.stdin.isatty():
        raise ValueError('Supply --output PATH when running without an interactive terminal.')
    while True:
        entered = input('Where should scan logs be saved? [./results]: ').strip()
        if len(entered) >= 2 and entered[0] == entered[-1] and entered[0] in "\"'":
            entered = entered[1:-1]
        path = Path(entered or 'results').expanduser()
        try:
            path.mkdir(parents=True, exist_ok=True)
            import tempfile
            with tempfile.TemporaryFile(dir=path):
                pass
            return path
        except OSError as exc:
            ui.say(f'Cannot save there: {exc}. Choose another directory.', 'yellow')


def main(argv=None):
    args = parser().parse_args(argv)
    ui = UI(args.plain)
    ui.say(f'SHREDDER {VERSION} / DISCOVER · ENUMERATE · RECORD', 'bold cyan')
    if args.doctor:
        executable = shutil.which(args.nmap)
        ui.say(f'Python: {sys.version.split()[0]} | OS: {sys.platform} | Elevated: {elevated()}')
        ui.say(f'Nmap: {executable or "MISSING — install from https://nmap.org/download.html"}')
        ui.say('Rich: available' if ui.console else 'Rich styling: disabled/unavailable; plain output works')
        return 0 if executable else 2
    try:
        entries = list(args.targets)
        if args.targets_file:
            entries += [s for line in args.targets_file.read_text(encoding='utf-8').splitlines()
                        if (s := line.split('#', 1)[0].strip())]
        if not entries:
            if not sys.stdin.isatty(): raise ValueError('Supply a target or --targets-file.')
            entries = input('Target IP / hostname / CIDR (space-separated): ').split()
            answer = input('Profile [full / quick / full-udp] (full): ').strip()
            if answer:
                if answer not in {'full', 'quick', 'full-udp'}: raise ValueError('Unknown profile.')
                args.profile = answer
        if args.udp_top > 65535: raise ValueError('--udp-top cannot exceed 65535.')
        if args.script_args_file and not args.script_args_file.is_file(): raise ValueError('Script arguments file not found.')
        custom = [s.strip().removesuffix('.nse') for group in args.script for s in group.split(',')]
        if any(not re.fullmatch(r'[A-Za-z0-9_-]+', s) for s in custom):
            raise ValueError('--script accepts literal installed NSE script names, not paths or expressions.')
        if args.ssh_user and not re.fullmatch(r'[A-Za-z0-9_.@\\-]+', args.ssh_user):
            raise ValueError('Unsupported characters in --ssh-user.')
        if args.domain:
            args.domain = normalize_target(args.domain)
            if '/' in args.domain: raise ValueError('--domain must be a DNS zone, not a network.')
            try: ipaddress.ip_address(args.domain)
            except ValueError: pass
            else: raise ValueError('--domain must be a DNS zone, not an IP.')
        hosts = resolve_targets(entries, args.max_hosts, args.exclude)
        if not args.plan:
            if not shutil.which(args.nmap): raise ValueError('Nmap missing. Run --doctor; installation instructions are in README.md.')
            if args.profile == 'full-udp' and not elevated():
                raise ValueError('UDP requires administrator/root privileges. Use full/quick or rerun elevated.')
        args.output = choose_output(args.output, ui)
        directory = args.output.resolve() / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(3).hex())
        directory.mkdir(parents=True, mode=0o700)
        report = {'version': VERSION, 'started': now(), 'status': 'planned' if args.plan else 'running',
                  'profile': args.profile, 'notes': ['Discovery names never expand the target queue.',
                  'Default NSE category excludes http-title; direct web probe records redirects without following.',
                  'NSE scripts themselves can perform auxiliary network interactions; scope is not a network firewall.'],
                  'hosts': [dict(h, status='pending', ports=[], scripts=[], http=[], discovered_names=[], notes=[]) for h in hosts]}
        write_json(directory / 'plan.json', {'targets': hosts, 'options': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}})
        render_report(directory, report)
        ui.say(f'Targets: {len(hosts)} | Profile: {args.profile} | Evidence: {directory}', 'cyan')
        if args.plan:
            for host in hosts: ui.say(host['address'] + ' ← ' + ', '.join(host['inputs']))
            return 0
        runner = Runner(args, directory, ui)
        requested = sorted({s for group in SCRIPTS.values() for s in group} |
                           {'dns-zone-transfer'} | ({'ssh-auth-methods'} if args.ssh_user else set()) | set(custom))
        available, missing = supported_scripts(args.nmap, requested, ui)
        if set(custom) & set(missing):
            report['status'] = 'failed'
            render_report(directory, report)
            raise ValueError('A requested custom script is unavailable: ' + ', '.join(set(custom) & set(missing)))
        report['missing_scripts'] = missing
        script_args = ['--script-timeout', f'{args.script_timeout}s']
        if args.script_args_file: script_args += ['--script-args-file', str(args.script_args_file.resolve())]
        try:
            for host in report['hosts']:
                hostdir = directory / host['address'].replace(':', '_')
                hostdir.mkdir(mode=0o700)
                host['status'] = 'running'
                failures_before = runner.failures
                ui.say('\n══ ' + host['address'] + ' ══', 'bold magenta')
                base = tcp_flags(args, host['address'])
                discovery = ['-p', args.ports] if args.ports else (['--top-ports', '1000'] if args.profile == 'quick' else ['-p-'])
                merge_results(host, runner.scan(host, hostdir, '01_tcp_discovery', base + discovery), 'tcp_discovery')
                if args.profile == 'full-udp':
                    udp = [s for s in base if s != '-sT'] + ['-sU', '-sV', '--top-ports', str(args.udp_top)]
                    merge_results(host, runner.scan(host, hostdir, '02_udp_discovery', udp), 'udp_discovery')
                opened = [p for p in host['ports'] if p['state'] == 'open']
                if opened:
                    protocols = {p['protocol'] for p in opened}
                    transport = [s for s in base if s != '-sT'] + (['-sT'] if 'tcp' in protocols else []) + (['-sU'] if 'udp' in protocols else [])
                    flags = transport + ['-p', port_spec(opened), '-sV']
                    if not args.no_default_scripts: flags += ['--script', DEFAULT_EXPRESSION] + script_args
                    merge_results(host, runner.scan(host, hostdir, '03_fingerprint_defaults', flags), 'fingerprint_defaults')
                    opened = [p for p in host['ports'] if p['state'] == 'open']
                    ui.table(opened)
                    if not args.skip_enum:
                        selected = choose_scripts(opened, args.domain)
                        if args.ssh_user and any('ssh' in families(p) for p in opened): selected.append('ssh-auth-methods')
                        selected = [s for s in selected if s in available]
                        extra_args = []
                        if args.domain: extra_args.append('dns-zone-transfer.domain=' + args.domain)
                        if args.ssh_user:
                            if not re.fullmatch(r'[A-Za-z0-9_.@\\-]+', args.ssh_user): raise ValueError('Unsupported characters in --ssh-user.')
                            extra_args.append('ssh.user=' + args.ssh_user)
                        if selected:
                            flags = transport + ['-p', port_spec(opened), '-sV', '--script', ','.join(selected)] + script_args
                            if extra_args: flags += ['--script-args', ','.join(extra_args)]
                            merge_results(host, runner.scan(host, hostdir, '04_service_enumeration', flags), 'service_enumeration')
                        hostnames = [s for s in host['inputs'] if '/' not in s and not is_ip(s)] or [host['address']]
                        for port in opened:
                            if port['protocol'] == 'tcp' and 'http' in families(port):
                                ui.say(f"Web baseline: {port['port']}/tcp (redirects recorded)", 'cyan')
                                for index, hostname in enumerate(hostnames):
                                    responses = http_probe(host['address'], hostname, port)
                                    host['http'].append({'port': port['port'], 'hostname': hostname, 'responses': responses})
                                    write_json(hostdir / f"http_{port['port']}_{index}.json", responses)
                                    for item in responses: ui.say(f"  {hostname}{item['path']}: {item.get('status', item.get('error'))} {item.get('title', '')} {item.get('location') or ''}")
                        if args.domain:
                            for port in opened:
                                if 'dns' in families(port):
                                    records = dns_probe(host['address'], port, args.domain)
                                    write_json(hostdir / f"dns_{port['port']}_{port['protocol']}.json", records)
                                    host.setdefault('dns', []).append(records)
                                    if args.verbose:
                                        for item in records: ui.say('  DNS ' + str(item))
                                    else:
                                        ui.say(f'  DNS: {len(records)} record query results saved.')
                        if any('dns' in families(p) for p in opened) and not args.domain:
                            host['notes'].append('DNS zone transfer skipped: supply --domain with the exact zone.')
                        if any(p['port'] in {1521, 5432} or any(x in p['service'] for x in ('postgres', 'oracle')) for p in opened):
                            host['notes'].append('PostgreSQL/Oracle: version/authentication response only; authenticated database enumeration remains manual.')
                    if custom:
                        flags = transport + ['-p', port_spec(opened), '-sV', '--script', ','.join(custom)] + script_args
                        merge_results(host, runner.scan(host, hostdir, '05_custom_scripts', flags), 'custom_scripts')
                else:
                    host['notes'].append('No confirmed open ports; review discovery output. UDP open|filtered remains uncertain.')
                ui.say(f"  {len(host['scripts'])} NSE results saved. Full findings: SUMMARY.html", 'cyan')
                host['status'] = 'partial' if runner.failures > failures_before else 'complete'
                render_report(directory, report)
        except KeyboardInterrupt:
            report['status'] = 'interrupted'
            for item in report['hosts']:
                if item['status'] == 'running': item['status'] = 'interrupted'
            ui.say('Interrupted. Completed evidence and raw partial output retained.', 'yellow')
            return 130
        except Exception:
            runner.partial = True
            for item in report['hosts']:
                if item['status'] == 'running': item['status'] = 'failed'
            raise
        finally:
            if report['status'] != 'interrupted': report['status'] = 'partial' if runner.partial else 'complete'
            report['finished'] = now()
            render_report(directory, report)
            hashes = {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(directory.rglob('*')) if p.is_file() and p.name != 'SHA256.json'}
            write_json(directory / 'SHA256.json', hashes)
            ui.say(f"\n{report['status'].upper()} / {directory / 'SUMMARY.html'}", 'bold cyan')
        return 1 if runner.partial else 0
    except (KeyboardInterrupt, EOFError):
        ui.say('Cancelled before scanning.', 'yellow')
        return 130
    except (ValueError, OSError) as exc:
        ui.say(f'Error: {exc}', 'red')
        return 2


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == '__main__':
    raise SystemExit(main())
