#!/usr/bin/env python3
"""Shredder: portable enumeration orchestration; Python 3.10+, external Nmap."""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from shredder_rules import load_rules, rank_leads
from shredder_rustscan import discovery_command, parse_event, port_record, selected_ports

VERSION = '1.1.1'
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
    return re.sub(r'[\x80-\x9f\u202a-\u202e\u2066-\u2069]', '', ANSI.sub('', str(value)))


def md(value):
    """Remote text must not introduce Markdown, HTML, table cells, or links."""
    value = html.escape(clean(value), quote=False)
    return re.sub(r'([\\`*_{}\[\]()#+.!|>-])', r'\\\1', value).replace('\r', ' ').replace('\n', ' ')


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    temporary.replace(path)


class UI:
    def __init__(self, plain=False, quiet=False, codec=False):
        self.console = None
        self.quiet, self.codec, self.plain = quiet, codec, plain
        if not plain:
            try:
                from rich.console import Console
                self.console = Console(highlight=False)
            except ImportError:
                pass

    def say(self, value, style=None, *, essential=False):
        if self.quiet and not essential and style not in {'yellow', 'red'}:
            return
        value = clean(value)
        if self.console:
            self.console.print(value, markup=False, style=style)
        else:
            print(value, flush=True)

    def table(self, ports):
        if self.quiet:
            return
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

    def chatter(self, event):
        if self.codec and not self.plain:
            lines = {'start': 'Codec online. Recon first, Boss.',
                     'resume': 'Kept you waiting, huh? Picking up the trail.',
                     'host': 'New sector. Let\'s see what answers.',
                     'finish': 'Evidence secured. Your move, Boss.'}
            self.say('[CODEC] ' + lines[event], 'cyan')

    def leads(self, host, show_all=False):
        if self.quiet:
            return
        leads = host.get('leads', [])
        if not leads:
            self.say('No rulebook leads matched. Review the raw evidence; this does not establish absence of issues.')
            return
        if not self.plain:
            self.say('\n[CODEC] Boss! Look what we got here.', 'bold cyan')
        else:
            self.say('\nCheck this first', 'bold cyan')
        selected = leads if show_all else leads[:5]
        for index, lead in enumerate(selected, 1):
            self.say(f"\n{index:02}  {lead['priority'].upper().replace('-', ' ')} | {lead['title']} [{lead['endpoint']}]", 'bold cyan')
            for label, value in [('Observed', lead['observation']), ('Priority', lead['why_priority']),
                                 ('Next move', lead['next_check']), ('Evidence', lead['evidence'][0]['source'])]:
                self.say(f'    {label:<10} {value}')
            self.say('    Status     Observation recorded; follow-up unverified.', 'dim')
        if len(leads) > len(selected):
            self.say(f'\n{len(leads) - len(selected)} more leads saved. Use --all-findings to display all.')


def normalize_target(value):
    value = value.strip()
    if not value or value.startswith('-') or any(c.isspace() for c in value):
        raise ValueError(f'Invalid target: {value!r}')
    if '/' in value:
        return str(ipaddress.ip_network(value, strict=True))
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
                excluded.extend(ipaddress.ip_network(x) for x in resolve_name(target))
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
                addresses = resolve_name(target)
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


def resolve_name(target):
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise ValueError(f'Cannot resolve target {target!r}: {exc}') from exc


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
            'finished': (finished.attrib if (finished := root.find('runstats/finished')) is not None else {})}


def read_scan(path, address):
    """Recover completed hosts/ports from interrupted XML, then grepable output."""
    try:
        parsed = parse_xml(path, address)
        parsed['partial'] = parsed['finished'].get('exit') != 'success'
        return parsed
    except (ET.ParseError, OSError, ValueError):
        pass
    # iterparse emits completed elements before a truncated tail. Do not invent
    # closing tags or treat the recovered fragment as a completed discovery scan.
    result = {'ports': [], 'scripts': [], 'discovered_names': [], 'finished': {}, 'partial': True}
    try:
        current, matched = None, False
        for event, element in ET.iterparse(path, events=('start', 'end')):
            if event == 'start' and element.tag == 'host':
                current, matched = element, False
            elif event == 'end' and element.tag == 'address' and current is not None:
                matched = matched or element.get('addr') == address
            elif event == 'end' and element.tag == 'port' and matched:
                # Parse a standalone completed port with the same canonical parser.
                state, service = element.find('state'), element.find('service')
                attrs = dict(service.attrib) if service is not None else {}
                item = {'port': int(element.get('portid')), 'protocol': element.get('protocol'),
                        'state': state.get('state', 'unknown') if state is not None else 'unknown',
                        'service': attrs.get('name', 'unknown'), 'tunnel': attrs.get('tunnel', ''),
                        'version': ' '.join(attrs[k] for k in ('product', 'version', 'extrainfo') if attrs.get(k)),
                        'fingerprint': attrs}
                result['ports'].append(item)
                result['scripts'].extend({'port': item['port'], 'protocol': item['protocol'],
                                         'id': s.get('id'), 'output': s.get('output', ''),
                                         'xml': ET.tostring(s, encoding='unicode')}
                                        for s in element.findall('script'))
            elif event == 'end' and element.tag == 'hostname' and matched and element.get('name'):
                result['discovered_names'].append(element.get('name'))
            elif event == 'end' and element.tag == 'hostscript' and matched:
                result['scripts'].extend({'port': None, 'protocol': None, 'id': s.get('id'),
                                         'output': s.get('output', ''), 'xml': ET.tostring(s, encoding='unicode')}
                                        for s in element.findall('script'))
            elif event == 'end' and element.tag == 'host':
                current, matched = None, False
                element.clear()
    except (ET.ParseError, OSError, ValueError):
        pass
    known = {(p['port'], p['protocol']) for p in result['ports']}
    grepable = path.with_suffix('.gnmap')
    if grepable.exists():
        for line in grepable.read_text(encoding='utf-8', errors='replace').splitlines():
            match = re.match(r'^Host:\s+(\S+)\s+.*?\tPorts:\s*(.*)', line)
            if not match or match.group(1) != address:
                continue
            for record in match.group(2).split(', '):
                fields = record.split('/')
                if len(fields) < 7 or not fields[0].isdigit() or fields[2] not in {'tcp', 'udp'}:
                    continue
                number = int(fields[0])
                if not 1 <= number <= 65535 or (number, fields[2]) in known:
                    continue
                result['ports'].append({'port': number, 'state': fields[1], 'protocol': fields[2],
                                        'service': fields[4] or 'unknown', 'version': fields[6],
                                        'tunnel': '', 'fingerprint': {}})
                known.add((number, fields[2]))
    return result


def families(port):
    n, s = port['port'], port.get('service', 'unknown').lower()
    # Nmap's table guess is not service detection. A probed service always wins.
    fallback = s in {'', 'unknown', 'tcpwrapped'} or port.get('fingerprint', {}).get('method') == 'table'
    if not fallback:
        n = -1
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
    if n in {5985, 5986} or ('http' in result and port['port'] in {5985, 5986}): result.add('winrm')
    if port.get('tunnel') == 'ssl' or s in {'https', 'ldaps', 'ftps', 'smtps'} or n in {443, 465, 636, 8443, 5986, 3269}: result.add('tls')
    return result


def elevated():
    if os.name == 'nt':
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def tcp_flags(args, target):
    flags = ['-n', '-Pn', '-sT', '-T' + args.timing, '--stats-every', '10s'] + (['-6'] if ':' in target else [])
    for option in ('min_rate', 'max_retries', 'host_timeout'):
        value = getattr(args, option, None)
        if value is not None:
            flags += ['--' + option.replace('_', '-'), str(value) + ('s' if option == 'host_timeout' else '')]
    return flags


def port_spec(ports):
    return ','.join(f"{proto[0].upper()}:" + ','.join(str(p['port']) for p in ports if p['protocol'] == proto)
                    for proto in ('tcp', 'udp') if any(p['protocol'] == proto for p in ports))


class Runner:
    def __init__(self, args, directory, ui):
        self.args, self.directory, self.ui = args, directory, ui
        self.commands = json.loads((directory / 'commands.json').read_text()) if (directory / 'commands.json').exists() else []
        self.checkpoints = json.loads((directory / 'checkpoints.json').read_text()) if (directory / 'checkpoints.json').exists() else {}
        self.on_stage = None
        self.partial = False
        self.failures = 0

    def save(self):
        write_json(self.directory / 'commands.json', self.commands)
        write_json(self.directory / 'checkpoints.json', self.checkpoints)

    def run(self, command, stem, on_line=None):
        label = stem.name.split('_', 1)[-1].replace('_', ' ').capitalize()
        verbose = self.args.verbose
        self.ui.say('\n' + label + '…', 'cyan')
        if verbose:
            self.ui.say('> ' + subprocess.list2cmdline(command), 'cyan')
        tail = deque(maxlen=8)
        status = None
        if not verbose and not self.ui.quiet and self.ui.console and self.ui.console.is_terminal:
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
                    if on_line:
                        on_line(clean(line.rstrip()))
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
        key = f"{host['address']}/{label}"
        cached = self.checkpoints.get(key)
        if cached and cached.get('status') == 'complete' and cached.get('flags') == flags:
            path = self.directory / cached['xml']
            if path.exists() and file_hash(path) == cached.get('sha256'):
                self.ui.say(f'Reusing completed stage: {label}', 'dim')
                result = read_scan(path, host['address'])
                for script in result['scripts']:
                    script['source'] = cached['xml']
                merge_results(host, result, label.split('_', 1)[-1])
                if self.on_stage:
                    self.on_stage()
                return result
        stem = directory / label
        attempt = 1
        while any(stem.with_suffix(suffix).exists() for suffix in ('.xml', '.nmap', '.gnmap', '.log')):
            attempt += 1
            stem = directory / f'{label}_attempt{attempt:02}'
        command = [self.args.nmap] + flags + ['-oA', str(stem), host['address']]
        path = stem.with_suffix('.xml')
        success, interrupted = False, False
        try:
            success = self.run(command, stem)
        except KeyboardInterrupt:
            interrupted = True
        parsed = read_scan(path, host['address'])
        source = str(path.relative_to(self.directory))
        for script in parsed['scripts']:
            script['source'] = source
        if not success or parsed.get('partial'):
            self.partial = True
            self.failures += 1
            self.ui.say(f'{label}: partial scan; recovered {len(parsed["ports"])} port records. Raw files retained.', 'yellow')
        self.checkpoints[key] = {'status': 'complete' if success and not parsed.get('partial') else 'partial',
                                 'flags': flags, 'xml': source, 'sha256': file_hash(path) if path.exists() else None}
        self.save()
        merge_results(host, parsed, label.split('_', 1)[-1])
        if self.on_stage:
            self.on_stage()
        if interrupted:
            raise KeyboardInterrupt
        return parsed

    def discover_rustscan(self, host, directory):
        """Stream scoped TCP discoveries into an append-only, flushed journal."""
        label = '01_tcp_discovery'
        key = f"{host['address']}/{label}"
        command = discovery_command(self.args, host['address'])
        allowed = selected_ports(self.args.ports)
        cached = self.checkpoints.get(key, {})
        if cached.get('backend') == 'rustscan' and cached.get('status') == 'complete' and cached.get('argv') == command:
            paths = {name: self.directory / cached[name] for name in ('ports_file', 'journal', 'log')}
            if all(p.is_file() and file_hash(p) == cached.get('hashes', {}).get(name) for name, p in paths.items()):
                saved = json.loads(paths['ports_file'].read_text(encoding='utf-8'))
                merge_results(host, saved, 'tcp_discovery')
                host['discovery'] = {'backend': 'rustscan', 'status': 'complete', 'source': cached['journal']}
                self.ui.say('Reusing completed RustScan discovery.', 'dim')
                if self.on_stage: self.on_stage()
                return saved
        attempt, stem = 1, directory / label
        while any(directory.glob(stem.name + '.*')):
            attempt += 1
            stem = directory / f'{label}_attempt{attempt:02}'
        journal_path, ports_path = stem.with_suffix('.ports.jsonl'), stem.with_suffix('.ports.json')
        source = str(journal_path.relative_to(self.directory))
        found, final_ports, empty_message = set(), None, False
        host['discovery'] = {'backend': 'rustscan', 'status': 'running', 'source': source}
        if self.on_stage: self.on_stage()
        interrupted, success = False, False
        with journal_path.open('w', encoding='utf-8') as journal:
            def accept(line):
                nonlocal final_ports, empty_message
                ports, summary, empty = parse_event(line, host['address'], allowed)
                if summary: final_ports = set(ports)
                empty_message = empty_message or empty
                for number in ports:
                    if number in found:
                        continue
                    journal.write(json.dumps({'observed': now(), 'address': host['address'],
                                               'port': number, 'protocol': 'tcp', 'state': 'open'}) + '\n')
                    journal.flush()
                    found.add(number)
                    merge_results(host, {'ports': [port_record(number, source)], 'scripts': [], 'discovered_names': []}, 'tcp_discovery')
                    self.ui.say(f"  Discovered {number}/tcp on {host['address']} | {len(found)} TCP ports found", 'cyan')
            try:
                success = self.run(command, stem, on_line=accept)
            except KeyboardInterrupt:
                interrupted = True
        # A zero exit alone is insufficient: recognize the scoped final result.
        complete = success and ((final_ports is not None and final_ports == found)
                                or (not found and empty_message))
        status = 'complete' if complete else 'partial'
        result = {'ports': [port_record(p, source) for p in sorted(found)], 'scripts': [],
                  'discovered_names': [], 'partial': not complete, 'backend': 'rustscan'}
        write_json(ports_path, result)
        evidence = {'ports_file': str(ports_path.relative_to(self.directory)), 'journal': source,
                    'log': str(stem.with_suffix('.log').relative_to(self.directory))}
        self.checkpoints[key] = {'backend': 'rustscan', 'status': status, 'argv': command, **evidence,
                                 'hashes': {name: file_hash(self.directory / value) for name, value in evidence.items()
                                            if (self.directory / value).is_file()}}
        host['discovery']['status'] = status
        if not complete:
            self.partial = True
            self.failures += 1
            self.ui.say(f'RustScan discovery incomplete; {len(found)} confirmed TCP ports retained. Port coverage remains incomplete.', 'yellow')
        self.save()
        if self.on_stage: self.on_stage()
        if interrupted: raise KeyboardInterrupt
        return result


def http_probe(address, hostname, port, extras=False):
    """Pin socket to the approved IP, preserve Host/SNI, never follow redirects."""
    secure = 'tls' in families(port)
    records = []
    paths = ('/', '/robots.txt') + (('/sitemap.xml', '/.git/HEAD', '/.well-known/security.txt') if extras else ())
    for path in paths:
        conn = http.client.HTTPConnection(address, port['port'], timeout=8)
        try:
            conn.connect()
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn.sock = context.wrap_socket(conn.sock, server_hostname=hostname)
            host_header = f'[{hostname}]' if ':' in hostname else hostname
            if port['port'] != (443 if secure else 80):
                host_header += f":{port['port']}"
            conn.request('GET', path, headers={'Host': host_header,
                                              'User-Agent': f'Shredder/{VERSION}', 'Accept-Encoding': 'identity'})
            response = conn.getresponse()
            body = response.read(131073)
            text = body[:131072].decode('utf-8', errors='replace')
            title = re.search(r'<title\b[^>]*>(.*?)</title>', text, re.I | re.S)
            clues = [name for name, pattern in {'WordPress': r'wp-content|wp-includes',
                     'Drupal': r'Drupal|sites/default/files', 'Joomla': r'com_content|Joomla',
                     'ASP.NET': r'__VIEWSTATE|ASP.NET', 'Next.js': r'__NEXT_DATA__|/_next/'}.items()
                     if re.search(pattern, text, re.I)]
            records.append({'path': path, 'status': response.status, 'headers': response.getheaders(),
                            'title': html.unescape(re.sub(r'\s+', ' ', title.group(1))).strip() if title else '',
                            'technology_clues': clues, 'location': response.getheader('Location'),
                            'redirect_followed': False, 'body_truncated': len(body) > 131072,
                            'body': text, 'body_sha256': hashlib.sha256(body[:131072]).hexdigest(),
                            'body_bytes': len(body[:131072]),
                            'tls_certificate_verified': False if secure else None})
        except (OSError, http.client.HTTPException) as exc:
            records.append({'path': path, 'error': str(exc)})
        finally:
            conn.close()
    return records


def collect_web(host, opened, hostdir, args, ui, checkpoint):
    """Parallel independent endpoints; one worker owns both requests for an endpoint."""
    hostnames = [s for s in host['inputs'] if '/' not in s and not is_ip(s)] or [host['address']]
    jobs = []
    for port in opened:
        if port['protocol'] != 'tcp' or 'http' not in families(port):
            continue
        for index, hostname in enumerate(hostnames):
            path = hostdir / f"http_{port['port']}_{index}.json"
            existing = next((w for w in host['http'] if w['port'] == port['port'] and w['hostname'] == hostname), None)
            if existing:
                saved = hostdir.parent / existing.get('source', '')
                if saved.is_file() and existing.get('sha256') == file_hash(saved) and all('error' not in r for r in existing['responses']):
                    continue
            jobs.append((port, hostname, index))
    if not jobs:
        return
    executor = ThreadPoolExecutor(max_workers=args.web_workers)
    futures = {executor.submit(http_probe, host['address'], name, port, args.web_extras): (port, name, index)
               for port, name, index in jobs}
    try:
        for future in as_completed(futures):
            port, hostname, index = futures[future]
            responses = future.result()
            path = hostdir / f"http_{port['port']}_{index}.json"
            # Preserve failed/partial attempts instead of overwriting the evidence.
            attempt = 1
            while path.exists():
                attempt += 1
                path = hostdir / f"http_{port['port']}_{index}_attempt{attempt:02}.json"
            write_json(path, responses)
            compact = [{k: v for k, v in item.items() if k != 'body'} for item in responses]
            host['http'] = [w for w in host['http'] if (w['port'], w['hostname']) != (port['port'], hostname)]
            host['http'].append({'port': port['port'], 'hostname': hostname, 'responses': compact,
                                 'source': f'{hostdir.name}/{path.name}', 'sha256': file_hash(path)})
            host['http'].sort(key=lambda w: (w['port'], w['hostname']))
            # Derive leads before removing bodies from the consolidated report.
            for response in compact:
                response['body_file'] = f'{hostdir.name}/{path.name}'
            ui.say(f"  Web {hostname}:{port['port']}: {len(responses)} responses saved.")
            checkpoint()
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)


def dns_probe(address, port, zone):
    """Explicit-zone DNS queries, sent only to the approved target DNS service."""
    try:
        import dns.message
        import dns.query
        import dns.exception
    except ImportError:
        return [{'skipped': 'DNS record queries require dnspython; AXFR via NSE remains available.'}]
    records = []
    for kind in ('SOA', 'NS', 'A', 'AAAA', 'MX', 'TXT'):
        try:
            query = dns.message.make_query(zone, kind)
            if port['protocol'] == 'tcp':
                response = dns.query.tcp(query, address, port=port['port'], timeout=4)
            else:
                response, _ = dns.query.udp_with_fallback(query, address, port=port['port'], timeout=4)
            records.append({'type': kind, 'rcode': response.rcode(),
                            'answers': [r.to_text() for r in response.answer]})
        except (dns.exception.DNSException, OSError, ValueError) as exc:
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
            if ((port['service'] == 'unknown' or port.get('fingerprint', {}).get('method') == 'table')
                    and existing['service'] != 'unknown' and existing.get('fingerprint', {}).get('method') != 'table'):
                port['service'], port['version'], port['tunnel'], port['fingerprint'] = existing['service'], existing['version'], existing['tunnel'], existing['fingerprint']
            existing.update(port)
        else: data['ports'].append(port)
    for script in result['scripts']:
        record = dict(script, stage=stage)
        key = (script['id'], script['port'], script['protocol'], stage)
        existing = next((s for s in data['scripts'] if (s['id'], s['port'], s['protocol'], s['stage']) == key), None)
        if existing is not None:
            existing.update(record)
        else:
            data['scripts'].append(record)
    data['discovered_names'] = sorted(set(data['discovered_names'] + result['discovered_names']))


def update_leads(directory, report, rules):
    for host in report['hosts']:
        web_records = []
        for web in host['http']:
            hydrated = dict(web)
            path = (directory / web.get('source', '')).resolve()
            if directory.resolve() in path.parents and path.is_file():
                hydrated['responses'] = json.loads(path.read_text(encoding='utf-8'))
            web_records.append(hydrated)
        host['leads'] = rank_leads(dict(host, http=web_records), rules)


def import_addresses(paths):
    addresses = set()
    for path in paths:
        try:
            for event, element in ET.iterparse(path, events=('end',)):
                if element.tag == 'address' and element.get('addrtype') in {None, 'ipv4', 'ipv6'} and is_ip(element.get('addr', '')):
                    addresses.add(str(ipaddress.ip_address(element.get('addr'))))
                elif element.tag == 'host':
                    element.clear()
        except ET.ParseError:
            pass  # Complete address elements before truncation are still usable.
    if not addresses:
        raise ValueError('No IPv4/IPv6 hosts found in the supplied Nmap XML.')
    return sorted(addresses)


def import_scans(paths, directory, report):
    for index, original in enumerate(paths, 1):
        path = directory / f'import_{index:02}.xml'
        shutil.copyfile(original, path)
        if original.with_suffix('.gnmap').is_file():
            shutil.copyfile(original.with_suffix('.gnmap'), path.with_suffix('.gnmap'))
        for host in report['hosts']:
            result = read_scan(path, host['address'])
            for script in result['scripts']:
                script['source'] = path.name
            merge_results(host, result, f'import_{index:02}')
            if result.get('partial'):
                host['notes'].append(f'{path.name}: imported scan is partial; port coverage is incomplete.')
        report.setdefault('imports', []).append({'source': str(original.resolve()), 'copy': path.name,
                                                 'sha256': file_hash(path)})


def save_hashes(directory):
    hashes = {str(p.relative_to(directory)): file_hash(p)
              for p in sorted(directory.rglob('*')) if p.is_file() and p.name != 'SHA256.json'}
    write_json(directory / 'SHA256.json', hashes)


def render_report(directory, report):
    write_json(directory / 'results.json', report)
    content = ['# Shredder engagement summary', '', f"Started: {report['started']}",
               f"Status: {report['status']}", '',
               'New names and redirect locations are evidence only; they are never added to the target queue.', '']
    if report.get('missing_scripts'):
        content += ['Unavailable NSE scripts (skipped): ' + ', '.join(report['missing_scripts']), '']
    for host in report['hosts']:
        content += [f"## {md(host['address'])}", '', f"Inputs: {', '.join(map(md, host['inputs']))}", '',
                    f"Status: {md(host.get('status', 'pending'))}", '']
        if host.get('discovery'):
            content += [f"TCP discovery: {md(host['discovery']['backend'])}, {md(host['discovery']['status'])}", '']
        content += ['### Investigation queue', '']
        for index, lead in enumerate(host.get('leads', []), 1):
            content += [f"{index}. **{md(lead['priority'])}: {md(lead['title'])}** ({md(lead['endpoint'])})", '',
                        'Observed: ' + md(lead['observation']), '',
                        'Why this priority: ' + md(lead['why_priority']), '',
                        'Next check (unverified): ' + md(lead['next_check']), '',
                        'Evidence: ' + '; '.join(md(e['source']) for e in lead['evidence']), '',
                        'References: ' + ', '.join(md(x) for x in lead['references']), '']
        content += ['| Port | State | Service | Version |', '|---|---|---|---|']
        for p in sorted(host['ports'], key=lambda p: (p['protocol'], p['port'])):
            fields = [f"{p['port']}/{p['protocol']}", p['state'], p['service'], p['version']]
            content.append('| ' + ' | '.join(md(f) for f in fields) + ' |')
        content += ['', '### Script findings', '']
        for script in host['scripts']:
            content += [f"**{md(script['id'])} / {script['port'] or 'host'} ({md(script['stage'])})**", '']
            content.extend('    ' + line for line in clean(script['output']).splitlines())
            content.append('')
        for web in host['http']:
            for item in web['responses']:
                content += [f"HTTP {web['port']} {md(item['path'])}: {md(item.get('status', item.get('error')))}", '',
                            '    ' + clean(item.get('title', '')), '']
                if item.get('location'): content += ['Redirect recorded: ' + md(item['location']), '']
        for dns_result in host.get('dns', []):
            content += ['DNS records:', ''] + ['    ' + clean(json.dumps(item)) for item in dns_result] + ['']
        if host['discovered_names']: content += ['Names for review: ' + ', '.join(map(md, host['discovered_names'])), '']
        if host.get('notes'): content += ['Notes: ' + '; '.join(map(md, host['notes'])), '']
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
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter, allow_abbrev=False)
    p.add_argument('targets', nargs='*', help='IP, hostname or CIDR; repeat to add explicitly scoped targets')
    p.add_argument('-iL', '--targets-file', type=Path, help='One IP/hostname/CIDR per line; # comments accepted')
    p.add_argument('--exclude', action='append', default=[], help='Exclude IP, hostname or CIDR; repeatable')
    p.add_argument('--profile', choices=['quick', 'full', 'full-udp'], default='full', help='1000 TCP; all TCP; all TCP + top UDP')
    p.add_argument('--ports', type=ports_value, help='Override TCP discovery ports')
    p.add_argument('--discovery', choices=['nmap', 'rustscan'], default='nmap', help='TCP discovery backend; Nmap still performs service/NSE enumeration')
    p.add_argument('--rustscan', default='rustscan', help='RustScan executable name or path')
    p.add_argument('--rustscan-batch', type=positive, default=4500, help='Concurrent RustScan sockets')
    p.add_argument('--rustscan-timeout', type=positive, default=1500, help='RustScan connection timeout in milliseconds')
    p.add_argument('--rustscan-tries', type=positive, default=1, help='RustScan connection attempts per port (1-255)')
    p.add_argument('--udp-top', type=positive, default=100, help='UDP ports for full-udp profile')
    p.add_argument('--timing', '-T', choices=['2', '3', '4'], default='4')
    p.add_argument('--min-rate', type=positive, help='Nmap minimum packet rate; unset by default')
    p.add_argument('--max-retries', type=int, help='Nmap retransmission cap, including 0')
    p.add_argument('--host-timeout', type=positive, help='Nmap per-host timeout in seconds')
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
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--quiet', '-q', action='store_true', help='Only errors/warnings and the final summary')
    mode.add_argument('--codec', action='store_true', help='Extra Codec dialogue at milestones')
    p.add_argument('--all-findings', action='store_true', help='Display the full investigation queue instead of the top five per host')
    p.add_argument('--rules', type=Path, action='append', default=[], help='Additional local JSON rules; repeatable')
    p.add_argument('--web-workers', type=positive, default=4, help='Concurrent HTTP endpoints (maximum 32)')
    p.add_argument('--web-extras', action='store_true', help='Also collect sitemap.xml, .git/HEAD and security.txt; no crawling')
    p.add_argument('--resume', type=Path, help='Resume a saved v1.1 run directory with its original scan options')
    p.add_argument('--import-xml', type=Path, action='append', default=[], help='Seed evidence from Nmap XML; repeatable')
    p.add_argument('--import-only', action='store_true', help='Build an offline report from XML, without DNS resolution or scans')
    p.add_argument('--skip-discovery', action='store_true', help='Explicitly use imported port coverage instead of new discovery')
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
    ui = UI(args.plain, args.quiet, args.codec)
    ui.say(f'SHREDDER {VERSION} / DISCOVER · ENUMERATE · RECORD', 'bold cyan')
    if args.doctor:
        executable = shutil.which(args.nmap)
        ui.say(f'Python: {sys.version.split()[0]} | OS: {sys.platform} | Elevated: {elevated()}', essential=True)
        ui.say(f'Nmap: {executable or "MISSING - install from https://nmap.org/download.html"}', essential=True)
        rustscan = shutil.which(args.rustscan)
        ui.say(f'RustScan: {rustscan or "not installed (optional for Nmap discovery)"}', essential=True)
        return 0 if executable and (args.discovery != 'rustscan' or rustscan) else 2
    try:
        if args.resume:
            allowed = {'resume', 'plain', 'quiet', 'codec', 'verbose', 'all_findings', 'nmap', 'rustscan'}
            defaults = vars(parser().parse_args([]))
            if any(value != defaults[key] for key, value in vars(args).items() if key not in allowed):
                raise ValueError('--resume uses the saved scan options; only display options and executable paths may be changed.')
            directory = args.resume.expanduser().resolve()
            plan = json.loads((directory / 'plan.json').read_text(encoding='utf-8'))
            report = json.loads((directory / 'results.json').read_text(encoding='utf-8'))
            if report.get('version') not in {'1.1.0', VERSION} or report.get('status') in {'planned', 'imported'}:
                raise ValueError('Resume requires a v1.1 scan run, not an offline import or plan.')
            display = {key: getattr(args, key) for key in allowed}
            for key in ('nmap', 'rustscan'):
                if display[key] == defaults[key]: display.pop(key)
            saved = dict(defaults)
            saved.update(plan['options'])
            saved.update(display)
            args = argparse.Namespace(**saved)
            for key in ('output', 'script_args_file'):
                if getattr(args, key, None): setattr(args, key, Path(getattr(args, key)))
            # Frozen addresses are authoritative: never re-resolve hostnames on resume.
            hosts = plan['targets']
            if [h['address'] for h in hosts] != [h['address'] for h in report['hosts']]:
                raise ValueError('Saved target plan and report disagree.')
            for host in hosts:
                ipaddress.ip_address(host['address'])
            rules = load_rules([directory / 'rules.json'])
            report['status'] = 'running'
            report.setdefault('resumptions', []).append(now())
            ui.chatter('resume')
        else:
            if args.import_only and not args.import_xml:
                raise ValueError('--import-only requires --import-xml FILE.')
            if args.skip_discovery and not args.import_xml:
                raise ValueError('--skip-discovery requires --import-xml FILE.')
            if args.import_only and args.plan:
                raise ValueError('--import-only and --plan are separate offline modes.')
            rules = load_rules(args.rules)
            entries = list(args.targets)
            if args.targets_file:
                entries += [s for line in args.targets_file.read_text(encoding='utf-8').splitlines()
                            if (s := line.split('#', 1)[0].strip())]
            if args.import_only:
                candidates = import_addresses(args.import_xml)
                if any(not is_ip(x) and '/' not in x for x in entries + args.exclude):
                    raise ValueError('Offline import filters accept only IPs/CIDRs, without hostname resolution.')
                hosts = resolve_targets(entries or candidates, args.max_hosts, args.exclude)
                hosts = [h for h in hosts if h['address'] in candidates]
                if not hosts: raise ValueError('No imported hosts match the selected scope.')
            else:
                if not entries:
                    if not sys.stdin.isatty():
                        raise ValueError('Supply a target or --targets-file. XML import never authorizes new scan targets.')
                    entries = input('Target IP / hostname / CIDR (space-separated): ').split()
                    answer = input('Profile [full / quick / full-udp] (full): ').strip()
                    if answer:
                        if answer not in {'full', 'quick', 'full-udp'}: raise ValueError('Unknown profile.')
                        args.profile = answer
                hosts = resolve_targets(entries, args.max_hosts, args.exclude)
            args.output = choose_output(args.output, ui)
            directory = args.output.resolve() / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(3).hex())
            directory.mkdir(parents=True, mode=0o700)
            report = {'version': VERSION, 'started': now(), 'status': 'planned' if args.plan else 'running',
                      'profile': args.profile, 'notes': ['Discovery names never expand the target queue.',
                      'Investigation priorities are triage, not vulnerability severities.',
                      'Observations are recorded evidence; suggested follow-up checks remain unverified.'],
                      'hosts': [dict(h, status='pending', ports=[], scripts=[], http=[], discovered_names=[], notes=[]) for h in hosts]}
            write_json(directory / 'rules.json', rules)
            write_json(directory / 'plan.json', {
                'targets': hosts,
                'provenance': {'shredder': VERSION, 'python': sys.version, 'platform': sys.platform,
                               'rule_engine_sha256': file_hash(Path(__file__).with_name('shredder_rules.py'))},
                'options': {k: [str(x) for x in v] if isinstance(v, list) else str(v) if isinstance(v, Path) else v
                            for k, v in vars(args).items()}})
            if args.import_xml and not args.plan:
                import_scans(args.import_xml, directory, report)
            ui.chatter('start')
        def checkpoint():
            update_leads(directory, report, rules)
            render_report(directory, report)
        checkpoint()
        ui.say(f'Targets: {len(hosts)} | Profile: {args.profile} | Evidence: {directory}', 'cyan')
        if args.plan:
            for host in hosts: ui.say(host['address'] + ' <- ' + ', '.join(host['inputs']))
            ui.say(f'PLANNED / {directory / "SUMMARY.html"}', essential=True)
            return 0
        if args.import_only:
            report['status'] = 'imported'
            report['finished'] = now()
            for host in report['hosts']:
                host['status'] = 'imported'
                ui.leads(host, args.all_findings)
            checkpoint()
            save_hashes(directory)
            ui.say(f'IMPORTED (offline) / {directory / "SUMMARY.html"}', essential=True)
            return 0
        if args.skip_discovery and args.profile == 'full-udp':
            raise ValueError('--skip-discovery cannot be combined with --profile full-udp; imported coverage is explicit.')
        if args.web_workers > 32: raise ValueError('--web-workers cannot exceed 32.')
        if args.rustscan_batch > 65535: raise ValueError('--rustscan-batch cannot exceed 65535.')
        if args.rustscan_tries > 255: raise ValueError('--rustscan-tries cannot exceed 255.')
        if args.rustscan_timeout > 4294967295: raise ValueError('--rustscan-timeout exceeds RustScan integer range.')
        if args.max_retries is not None and not 0 <= args.max_retries <= 100:
            raise ValueError('--max-retries must be between 0 and 100.')
        if args.udp_top > 65535: raise ValueError('--udp-top cannot exceed 65535.')
        if args.script_args_file and not args.script_args_file.is_file(): raise ValueError('Script arguments file not found.')
        custom = [s.strip().removesuffix('.nse') for group in args.script for s in group.split(',')]
        if any(not re.fullmatch(r'[A-Za-z0-9_-]+', s) for s in custom):
            raise ValueError('--script accepts literal installed NSE script names, not paths or expressions.')
        if args.ssh_user and not re.fullmatch(r'[A-Za-z0-9_.@\\-]+', args.ssh_user):
            raise ValueError('Unsupported characters in --ssh-user.')
        if args.domain:
            args.domain = normalize_target(args.domain)
            if '/' in args.domain or is_ip(args.domain): raise ValueError('--domain must be a DNS zone.')
        if not shutil.which(args.nmap): raise ValueError('Nmap missing. Run --doctor; installation instructions are in README.md.')
        if args.discovery == 'rustscan' and not args.skip_discovery:
            if not shutil.which(args.rustscan):
                raise ValueError('RustScan missing. Install RustScan or select --discovery nmap; Nmap remains required for enumeration.')
            discovery_command(args, hosts[0]['address'])  # Validate portable port arguments before scanning.
        if args.profile == 'full-udp' and not elevated():
            raise ValueError('UDP requires administrator/root privileges. Use full/quick or rerun elevated.')
        runner = Runner(args, directory, ui)
        runner.on_stage = checkpoint
        requested = sorted({s for group in SCRIPTS.values() for s in group} |
                           {'dns-zone-transfer'} | ({'ssh-auth-methods'} if args.ssh_user else set()) | set(custom))
        available, missing = supported_scripts(args.nmap, requested, ui)
        if set(custom) & set(missing):
            report['status'] = 'failed'
            checkpoint()
            raise ValueError('A requested custom script is unavailable: ' + ', '.join(sorted(set(custom) & set(missing))))
        report['missing_scripts'] = missing
        script_args = ['--script-timeout', f'{args.script_timeout}s']
        if args.script_args_file: script_args += ['--script-args-file', str(args.script_args_file.resolve())]
        try:
            for host in report['hosts']:
                hostdir = directory / host['address'].replace(':', '_')
                hostdir.mkdir(mode=0o700, exist_ok=True)
                host['status'] = 'running'
                failures_before = runner.failures
                ui.chatter('host')
                ui.say('\n== ' + host['address'] + ' ==', 'bold magenta')
                base = tcp_flags(args, host['address'])
                if not args.skip_discovery:
                    if args.discovery == 'rustscan':
                        runner.discover_rustscan(host, hostdir)
                    else:
                        discovery = ['-p', args.ports] if args.ports else (['--top-ports', '1000'] if args.profile == 'quick' else ['-p-'])
                        runner.scan(host, hostdir, '01_tcp_discovery', base + discovery)
                    if args.profile == 'full-udp':
                        udp = [s for s in base if s != '-sT'] + ['-sU', '-sV', '--top-ports', str(args.udp_top)]
                        runner.scan(host, hostdir, '02_udp_discovery', udp)
                opened = [p for p in host['ports'] if p['state'] == 'open']
                if opened:
                    protocols = {p['protocol'] for p in opened}
                    transport = [s for s in base if s != '-sT'] + (['-sT'] if 'tcp' in protocols else []) + (['-sU'] if 'udp' in protocols else [])
                    flags = transport + ['-p', port_spec(opened), '-sV']
                    if not args.no_default_scripts: flags += ['--script', DEFAULT_EXPRESSION] + script_args
                    runner.scan(host, hostdir, '03_fingerprint_defaults', flags)
                    opened = [p for p in host['ports'] if p['state'] == 'open']
                    ui.table(opened)
                    if not args.skip_enum and opened:
                        selected = choose_scripts(opened, args.domain)
                        if args.ssh_user and any('ssh' in families(p) for p in opened): selected.append('ssh-auth-methods')
                        selected = [s for s in selected if s in available]
                        extra_args = []
                        if args.domain: extra_args.append('dns-zone-transfer.domain=' + args.domain)
                        if args.ssh_user: extra_args.append('ssh.user=' + args.ssh_user)
                        if any('winrm' in families(p) for p in opened):
                            extra_args.append('http-ntlm-info.root=/wsman')
                        if selected:
                            flags = transport + ['-p', port_spec(opened), '-sV', '--version-light', '--script', ','.join(selected)] + script_args
                            if extra_args: flags += ['--script-args', ','.join(extra_args)]
                            runner.scan(host, hostdir, '04_service_enumeration', flags)
                        collect_web(host, opened, hostdir, args, ui, checkpoint)
                        if args.domain:
                            # DNS probes are bounded and cheap. Re-run on resume, preserving prior records.
                            for port in opened:
                                if 'dns' in families(port):
                                    records = dns_probe(host['address'], port, args.domain)
                                    path = hostdir / f"dns_{port['port']}_{port['protocol']}_{len(host.get('dns', [])):03}.json"
                                    write_json(path, records)
                                    host.setdefault('dns', []).append(records)
                                    checkpoint()
                        if any('dns' in families(p) for p in opened) and not args.domain:
                            note = 'DNS zone transfer skipped: supply --domain with the exact zone.'
                            if note not in host['notes']: host['notes'].append(note)
                    if custom and opened:
                        flags = transport + ['-p', port_spec(opened), '-sV', '--version-light', '--script', ','.join(custom)] + script_args
                        runner.scan(host, hostdir, '05_custom_scripts', flags)
                else:
                    note = 'No confirmed open ports; review discovery output. UDP open|filtered remains uncertain.'
                    if note not in host['notes']: host['notes'].append(note)
                host['status'] = 'partial' if runner.failures > failures_before else 'complete'
                checkpoint()
                ui.leads(host, args.all_findings)
        except KeyboardInterrupt:
            report['status'] = 'interrupted'
            for item in report['hosts']:
                if item['status'] == 'running': item['status'] = 'interrupted'
            ui.say('Interrupted. Evidence retained; use --resume with this run directory.', 'yellow')
            return 130
        except Exception:
            runner.partial = True
            for item in report['hosts']:
                if item['status'] == 'running': item['status'] = 'failed'
            raise
        finally:
            if report['status'] != 'interrupted': report['status'] = 'partial' if runner.partial else 'complete'
            report['finished'] = now()
            checkpoint()
            save_hashes(directory)
            ui.chatter('finish')
            ui.say(f"\n{report['status'].upper()} / {directory / 'SUMMARY.html'}", essential=True)
        return 1 if runner.partial else 0
    except (KeyboardInterrupt, EOFError):
        ui.say('Cancelled before scanning.', 'yellow')
        return 130
    except (ValueError, OSError, KeyError, TypeError) as exc:
        if 'report' in locals() and report.get('status') == 'running':
            report['status'] = 'failed'
            report['error'] = str(exc)
            render_report(directory, report)
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
