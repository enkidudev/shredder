"""Synthetic regression cases. No target-specific or external scans."""
import contextlib
import http.server
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import shredder as b
from shredder_rules import load_rules, rank_leads
from test_shredder import XML


def host():
    return {'address': '127.0.0.1', 'inputs': ['127.0.0.1'], 'ports': [],
            'scripts': [], 'http': [], 'discovered_names': [], 'notes': []}


def script(sid, output, stage='service_enumeration', port=None):
    return {'id': sid, 'output': output, 'stage': stage, 'port': port, 'protocol': 'tcp' if port else None}


class RuleTests(unittest.TestCase):
    def test_positive_and_negative_evidence_and_ranking(self):
        h = host()
        h['scripts'] = [script('ftp-anon', 'Anonymous FTP login allowed (FTP code 230)', port=21),
                        script('smb2-security-mode', '\n  3.1.1:\n    Message signing enabled but not required'),
                        script('nfs-showmount', '/home 192.0.2.0/24'),
                        script('ldap-rootdse', 'defaultNamingContext: DC=example,DC=local')]
        leads = rank_leads(h)
        self.assertEqual(leads[0]['rule'], 'ftp-anon')
        self.assertEqual(len(leads), 4)
        self.assertTrue(all(x['observation_status'] == 'observed' and x['follow_up_status'] == 'unverified' for x in leads))
        self.assertTrue(all(x['why_priority'] and x['references'] and x['evidence'] for x in leads))
        h['scripts'] = [script('ftp-anon', 'Anonymous FTP login not allowed'),
                        script('smb2-security-mode', 'Message signing enabled and required'),
                        script('nfs-showmount', 'ERROR: no exports')]
        self.assertEqual(rank_leads(h), [])

    def test_port_and_version_alone_are_not_findings(self):
        h = host()
        h['ports'] = [{'port': 445, 'service': 'microsoft-ds', 'version': 'ancient version'}]
        self.assertEqual(rank_leads(h), [])

    def test_duplicate_scripts_group_with_evidence(self):
        h = host()
        h['scripts'] = [script('ftp-anon', 'Anonymous FTP login allowed', stage=stage, port=21)
                        for stage in ('fingerprint_defaults', 'service_enumeration')]
        leads = rank_leads(h)
        self.assertEqual(len(leads), 1)
        self.assertEqual(len(leads[0]['evidence']), 2)

    def test_web_patterns_need_status_and_content(self):
        h = host()
        responses = [{'path': '/robots.txt', 'status': 200, 'body': 'User-agent: *\nDisallow: /backup/\nDisallow: /'},
                     {'path': '/.git/HEAD', 'status': 200, 'body': '<title>Generic login</title>'},
                     {'path': '/', 'status': 302, 'location': 'http://outside.invalid/admin', 'body': ''}]
        h['http'] = [{'hostname': 'approved.invalid', 'port': 80, 'responses': responses}]
        leads = rank_leads(h)
        self.assertEqual({x['rule'] for x in leads}, {'robots-paths', 'redirect'})
        responses[0]['status'] = 403
        responses[1]['body'] = 'ref: refs/heads/main\n'
        self.assertEqual({x['rule'] for x in rank_leads(h)}, {'git-head', 'redirect'})

    def test_custom_rules_are_literal_validated_and_no_code(self):
        rule = {'id': 'local-test', 'script_id': 'custom-info', 'contains': 'literal.*text',
                'title': 'Local lead', 'priority': 'follow-up', 'why': 'Reason',
                'next_check': 'Inspect response', 'references': ['https://example.com/docs']}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'rules.json'
            path.write_text(json.dumps([rule]))
            rules = load_rules([path])
            h = host()
            h['scripts'] = [script('custom-info', 'literalZZtext')]
            self.assertEqual(rank_leads(h, rules), [])
            h['scripts'][0]['output'] = 'literal.*text'
            self.assertEqual(rank_leads(h, rules)[0]['origin'], 'custom')
            for invalid in [dict(rule, id='ftp-anon'), dict(rule, references=['javascript:alert(1)']),
                            dict(rule, priority='critical'), dict(rule, code='exec()')]:
                path.write_text(json.dumps([invalid]))
                with self.assertRaises(ValueError): load_rules([path])

    def test_matching_pages_are_a_follow_up_not_a_default_vhost_claim(self):
        h = host()
        h['http'] = [{'hostname': name, 'port': 80, 'responses': [{'path': '/', 'status': 200, 'body': 'same'}]}
                     for name in ('one.invalid', 'two.invalid')]
        lead = rank_leads(h)[0]
        self.assertEqual(lead['rule'], 'matching-pages')
        self.assertEqual(lead['priority'], 'follow-up')
        self.assertIn('hypothesis', lead['why_priority'])


class RecoveryTests(unittest.TestCase):
    def test_full_resume_workflow_reuses_discovery_and_retries_failed_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'fake.py'
            fake.write_text('''import pathlib, sys
args = sys.argv[1:]
if '--script-help' in args:
    names = args[args.index('--script-help')+1].split(',')
    print('<nmaprun>' + ''.join('<script filename="'+x+'.nse"/>' for x in names) + '</nmaprun>')
else:
    stem = pathlib.Path(args[args.index('-oA')+1])
    marker = stem.parent / 'failed-once'
    fail = stem.name == '03_fingerprint_defaults' and not marker.exists()
    data = ''' + repr(XML) + '''
    stem.with_suffix('.xml').write_text(data.split('<runstats>')[0] if fail else data)
    stem.with_suffix('.gnmap').write_text('')
    print('synthetic stage')
    if fail:
        marker.touch()
        raise SystemExit(7)
''')
            original_run, original_popen = subprocess.run, subprocess.Popen
            def remap(command):
                return [sys.executable, str(fake)] + command[1:] if command[0] == 'fake-nmap' else command
            def run(command, *a, **kw): return original_run(remap(command), *a, **kw)
            def popen(command, *a, **kw): return original_popen(remap(command), *a, **kw)
            with patch.object(b.shutil, 'which', return_value='fake-nmap'), \
                 patch.object(subprocess, 'run', side_effect=run), \
                 patch.object(subprocess, 'Popen', side_effect=popen), contextlib.redirect_stdout(io.StringIO()):
                first = b.main(['127.0.0.1', '--nmap', 'fake-nmap', '--plain', '-o', str(root / 'out')])
                directory = next((root / 'out').iterdir())
                with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('resume DNS')):
                    second = b.main(['--resume', str(directory), '--nmap', 'fake-nmap', '--plain'])
            self.assertEqual((first, second), (1, 0))
            commands = json.loads((directory / 'commands.json').read_text())
            self.assertEqual(len(commands), 4)  # Discovery + failed fingerprint + enum + retried fingerprint.
            self.assertEqual(sum('01_tcp_discovery.log' in x['log'] for x in commands), 1)
            self.assertTrue((directory / '127.0.0.1/03_fingerprint_defaults.xml').is_file())
            self.assertTrue((directory / '127.0.0.1/03_fingerprint_defaults_attempt02.xml').is_file())
            report = json.loads((directory / 'results.json').read_text())
            self.assertEqual(report['status'], 'complete')
            self.assertEqual(len(report['hosts'][0]['scripts']), 6)

    def test_recover_complete_ports_from_truncated_xml_without_other_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scan.xml'
            path.write_text(XML.split('<runstats>')[0] + '<host><ports>')
            result = b.read_scan(path, '127.0.0.1')
        self.assertTrue(result['partial'])
        self.assertEqual([p['port'] for p in result['ports']], [22, 53])
        self.assertEqual(result['scripts'][0]['id'], 'ssh-hostkey')

    def test_grepable_fallback_keeps_uncertainty_and_filters_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scan.xml'
            path.write_text('<nmaprun><host>')
            path.with_suffix('.gnmap').write_text('Host: 127.0.0.1 ()\tPorts: 22/open/tcp//ssh///, 53/open|filtered/udp//domain///\n'
                                                   'Host: 192.0.2.1 ()\tPorts: 445/open/tcp//microsoft-ds///\n')
            result = b.read_scan(path, '127.0.0.1')
        self.assertEqual(len(result['ports']), 2)
        self.assertEqual(result['ports'][1]['state'], 'open|filtered')

    def test_import_only_never_resolves_or_runs_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'input.xml'
            path.write_text(XML)
            with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('process')), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['--import-xml', str(path), '--import-only', '-o', str(root / 'out'), '--quiet'])
            self.assertEqual(code, 0)
            report = json.loads(next(root.glob('out/*/results.json')).read_text())
            self.assertEqual(report['status'], 'imported')
            self.assertEqual(len(report['hosts']), 2)
            self.assertEqual(report['hosts'][0]['scripts'][0]['source'], 'import_01.xml')

    def test_xml_import_does_not_authorize_online_scan_targets(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(sys.stdin, 'isatty', return_value=False):
            path = Path(tmp) / 'input.xml'
            path.write_text(XML)
            with contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['--import-xml', str(path), '-o', tmp])
            self.assertEqual(code, 2)

    def test_offline_exclusions_never_resolve_hostnames(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.xml'
            path.write_text(XML)
            with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['--import-xml', str(path), '--import-only', '--exclude', 'outside.invalid', '-o', tmp])
            self.assertEqual(code, 2)

    def test_checkpoints_skip_complete_stages_and_preserve_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            h = host()
            hostdir = root / '127.0.0.1'
            hostdir.mkdir()
            args = b.parser().parse_args(['--plain'])
            runner = b.Runner(args, root, b.UI(True))
            calls = []
            def run(command, stem):
                calls.append(stem.name)
                stem.with_suffix('.xml').write_text(XML)
                return True
            with patch.object(runner, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                runner.scan(h, hostdir, '01_tcp_discovery', ['-sT'])
                b.Runner(args, root, b.UI(True)).scan(h, hostdir, '01_tcp_discovery', ['-sT'])
                self.assertEqual(calls, ['01_tcp_discovery'])
                # Different flags invalidate the completed stage.
                runner.scan(h, hostdir, '01_tcp_discovery', ['-sT', '-p', '22'])
                self.assertEqual(calls[-1], '01_tcp_discovery_attempt02')
                # Modified evidence must not be reused as a valid checkpoint.
                (hostdir / '01_tcp_discovery_attempt02.xml').write_text('<broken>')
                runner.scan(h, hostdir, '01_tcp_discovery', ['-sT', '-p', '22'])
                self.assertEqual(calls[-1], '01_tcp_discovery_attempt03')

    def test_interrupt_recovers_active_stage_before_reraising(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, h = Path(tmp), host()
            args = b.parser().parse_args(['--plain'])
            runner = b.Runner(args, root, b.UI(True))
            def interrupt(command, stem):
                stem.with_suffix('.xml').write_text(XML.split('<runstats>')[0])
                raise KeyboardInterrupt
            with patch.object(runner, 'run', side_effect=interrupt), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    runner.scan(h, root, '01_tcp_discovery', ['-sT'])
            self.assertEqual(len(h['ports']), 2)
            self.assertEqual(runner.checkpoints['127.0.0.1/01_tcp_discovery']['status'], 'partial')


class HardeningTests(unittest.TestCase):
    def test_host_mask_never_expands_scope(self):
        for value in ['10.129.1.5/24', '2001:db8::1/64']:
            with self.assertRaises(ValueError): b.normalize_target(value)

    def test_fingerprint_overrides_port_guess(self):
        port = {'port': 22, 'service': 'http', 'tunnel': '', 'fingerprint': {'method': 'probed'}}
        self.assertIn('http', b.families(port))
        self.assertNotIn('ssh', b.families(port))
        port['service'] = 'unknown'
        self.assertIn('ssh', b.families(port))

    def test_terminal_and_markdown_remote_injection(self):
        self.assertEqual(b.clean('ok\x9b\u202eevil\u2069'), 'okevil')
        value = b.md('<img src=//attacker/x>|[link](https://bad)`')
        self.assertNotIn('<img', value)
        self.assertIn('\\[link\\]', value)
        self.assertIn('\\|', value)

    def test_dns_error_names_the_target(self):
        with patch.object(socket, 'getaddrinfo', side_effect=socket.gaierror('not found')):
            with self.assertRaisesRegex(ValueError, 'missing.invalid'):
                b.resolve_targets(['missing.invalid'], 256, [])

    def test_timing_defaults_and_passthrough(self):
        args = b.parser().parse_args(['--min-rate', '1000', '--max-retries', '0', '--host-timeout', '120'])
        flags = b.tcp_flags(args, '127.0.0.1')
        self.assertIn('-T4', flags)
        self.assertIn('0', flags)
        self.assertIn('120s', flags)

    def test_codec_plain_and_quiet_modes(self):
        h = host()
        h['scripts'] = [script('ftp-anon', 'Anonymous FTP login allowed')]
        h['leads'] = rank_leads(h)
        for plain, quiet, codec in [(False, False, True), (True, False, True), (True, True, False)]:
            stream = io.StringIO()
            ui = b.UI(plain, quiet, codec)
            ui.console = None
            with contextlib.redirect_stdout(stream):
                ui.chatter('start')
                ui.leads(h)
                ui.say('FINAL', essential=True)
            output = stream.getvalue()
            self.assertEqual('Boss' in output, not plain and not quiet)
            self.assertEqual('Next move' in output, not quiet)
            self.assertIn('FINAL', output)


class ConcurrentWebTests(unittest.TestCase):
    def test_bounded_parallel_collection_caches_bodies_and_keeps_duplicate_headers(self):
        hits = []
        barrier = threading.Barrier(2)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append((self.headers['Host'], self.path))
                if self.path == '/':
                    barrier.wait(timeout=5)  # Fails if endpoints are accidentally sequential.
                self.send_response(200)
                self.send_header('Set-Cookie', 'one=1')
                self.send_header('Set-Cookie', 'two=2')
                self.end_headers()
                bodies = {'/': '<title>Test</title>', '/robots.txt': 'Disallow: /backup/',
                          '/.git/HEAD': 'ref: refs/heads/main\n',
                          '/sitemap.xml': '<urlset><url><loc>http://one.invalid/admin</loc></url></urlset>'}
                self.wfile.write(bodies.get(self.path, 'contact').encode())
            def log_message(self, *a): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                hostdir = directory / '127.0.0.1'
                hostdir.mkdir()
                h = host()
                h['inputs'] = ['one.invalid', 'two.invalid']
                port = {'port': server.server_port, 'service': 'http', 'protocol': 'tcp', 'tunnel': ''}
                args = b.parser().parse_args(['--web-workers', '2', '--web-extras'])
                report = {'hosts': [h]}
                with contextlib.redirect_stdout(io.StringIO()):
                    b.collect_web(h, [port], hostdir, args, b.UI(True), lambda: b.update_leads(directory, report, []))
                    original_hits = len(hits)
                    b.collect_web(h, [port], hostdir, args, b.UI(True), lambda: None)
                self.assertEqual(len(hits), original_hits)
                self.assertEqual(original_hits, 10)
                self.assertNotIn('body', h['http'][0]['responses'][0])
                raw = json.loads((directory / h['http'][0]['source']).read_text())
                self.assertEqual(sum(k == 'Set-Cookie' for k, v in raw[0]['headers']), 2)
                self.assertEqual(raw[2]['body'], '<urlset><url><loc>http://one.invalid/admin</loc></url></urlset>')
                self.assertIn('git-head', {lead['rule'] for lead in h['leads']})
                self.assertEqual(len(list(hostdir.glob('http_*.json'))), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
