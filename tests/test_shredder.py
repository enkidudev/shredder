import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import shredder as b

XML = '''<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="new.invalid"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/>
<script id="ssh-hostkey" output="key &amp; text"><table key="keys"><elem key="bits">256</elem></table></script></port>
<port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port>
</ports><hostscript><script id="host-test" output="host output"/></hostscript></host>
<host><address addr="192.0.2.1"/><ports><port protocol="tcp" portid="445"><state state="open"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


class ScopeTests(unittest.TestCase):
    def test_reject_options_and_urls(self):
        for value in ('--script=all', 'https://example.com', 'example.com:80', 'a b', 'a;touch-x', '../test'):
            with self.subTest(value=value), self.assertRaises(ValueError): b.normalize_target(value)

    def test_cidr_exclusions_and_budget(self):
        targets = b.resolve_targets(['192.0.2.0/30'], 4, ['192.0.2.2'])
        self.assertEqual([x['address'] for x in targets], ['192.0.2.1'])
        with self.assertRaises(ValueError): b.resolve_targets(['10.0.0.0/8'], 256, [])

    def test_domain_freezes_all_resolved_addresses(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 0))]
        with patch.object(socket, 'getaddrinfo', return_value=answers) as resolve:
            targets = b.resolve_targets(['EXAMPLE.COM', '192.0.2.10'], 2, [])
        self.assertEqual(targets, [{'address': '192.0.2.10', 'inputs': ['example.com', '192.0.2.10']}])
        resolve.assert_called_once()

    def test_ipv6(self):
        self.assertEqual(b.normalize_target('[::1]'), '::1')
        self.assertEqual(b.resolve_targets(['::1'], 1, [])[0]['address'], '::1')

    def test_invalid_ports(self):
        for value in ('0', '65536', '80,abc', '90-80', '-p-'):
            with self.assertRaises(Exception): b.ports_value(value)


class EvidenceTests(unittest.TestCase):
    def test_xml_keeps_uncertain_states_and_nested_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scan.xml'
            path.write_text(XML)
            result = b.parse_xml(path, '127.0.0.1')
        self.assertEqual(len(result['ports']), 2)
        self.assertEqual(result['ports'][1]['state'], 'open|filtered')
        self.assertEqual(result['scripts'][0]['output'], 'key & text')
        self.assertIn('<table', result['scripts'][0]['xml'])
        self.assertEqual(result['discovered_names'], ['new.invalid'])

    def test_html_escapes_remote_output(self):
        report = {'started': 'test', 'status': 'complete', 'hosts': [{'address': '127.0.0.1',
                  'inputs': ['127.0.0.1'], 'ports': [], 'http': [], 'discovered_names': [],
                  'scripts': [{'id': 'x', 'stage': 'test', 'port': 80, 'output': '<script>alert(1)</script>'}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            b.render_report(Path(tmp), report)
            page = (Path(tmp) / 'SUMMARY.html').read_text()
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)

    def test_terminal_control_sequences(self):
        self.assertEqual(b.clean('\x1b[31mred\x1b[0m\x1b]0;title\x07'), 'red')

    def test_nonstandard_port_service_routing(self):
        port = {'port': 50000, 'service': 'http', 'tunnel': ''}
        self.assertIn('http', b.families(port))
        port['service'] = 'ssh'
        self.assertIn('ssh-hostkey', b.choose_scripts([port]))


class ExecutionTests(unittest.TestCase):
    def test_timeout_kills_child_and_preserves_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = b.parser().parse_args(['--timeout', '1', '--plain'])
            runner = b.Runner(args, Path(tmp), b.UI(True))
            with contextlib.redirect_stdout(io.StringIO()):
                okay = runner.run([sys.executable, '-S', '-c', 'import time; print("started", flush=True); time.sleep(10)'], Path(tmp) / 'slow')
            self.assertFalse(okay)
            self.assertTrue(runner.partial)
            self.assertEqual(runner.commands[0]['status'], 'failed')
            self.assertIn('started', (Path(tmp) / 'slow.log').read_text())

    def test_command_arguments_are_not_shell_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = b.parser().parse_args(['--plain'])
            runner = b.Runner(args, Path(tmp), b.UI(True))
            literal = 'hello; $(echo nope) `echo nope`'
            with contextlib.redirect_stdout(io.StringIO()):
                okay = runner.run([sys.executable, '-c', 'import sys; print(sys.argv[1])', literal], Path(tmp) / 'literal')
            self.assertTrue(okay)
            self.assertEqual((Path(tmp) / 'literal.log').read_text().strip(), literal)

    def test_plan_does_not_execute_nmap(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')):
            with contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['127.0.0.1', '--plan', '--plain', '-o', tmp])
            self.assertEqual(code, 0)
            report = json.loads(next(Path(tmp).glob('*/results.json')).read_text())
            self.assertEqual(report['status'], 'planned')

    def test_workflow_with_simulated_nmap(self):
        # Real child processes and files, fake Nmap responses: no network scan.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'fake_nmap.py'
            fake.write_text('''import pathlib, sys
args = sys.argv[1:]
if '--script-help' in args:
    scripts = args[args.index('--script-help')+1].split(',')
    print('<nmaprun><nse-scripts>' + ''.join('<script filename="'+s+'.nse"/>' for s in scripts) + '</nse-scripts></nmaprun>')
else:
    stem = pathlib.Path(args[args.index('-oA')+1])
    stem.with_suffix('.xml').write_text(''' + repr(XML) + ''')
    stem.with_suffix('.nmap').write_text('simulated scan')
    stem.with_suffix('.gnmap').write_text('simulated scan')
    print('simulated Nmap stage')
''')
            original_run, original_popen = subprocess.run, subprocess.Popen
            def remap(args):
                return [sys.executable, str(fake)] + args[1:] if args[0] == 'fake-nmap' else args
            def run(args, *a, **kw): return original_run(remap(args), *a, **kw)
            def popen(args, *a, **kw): return original_popen(remap(args), *a, **kw)
            with patch.object(b.shutil, 'which', return_value='fake-nmap'), patch.object(subprocess, 'run', side_effect=run), patch.object(subprocess, 'Popen', side_effect=popen), contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['127.0.0.1', '--nmap', 'fake-nmap', '--plain', '--script', 'ssh-hostkey', '-o', str(root / 'output')])
            self.assertEqual(code, 0)
            report = json.loads(next(root.glob('output/*/results.json')).read_text())
            self.assertEqual(len(report['hosts']), 1)  # discovered name never queued
            self.assertEqual(report['hosts'][0]['discovered_names'], ['new.invalid'])
            self.assertEqual(report['status'], 'complete')
            commands = json.loads(next(root.glob('output/*/commands.json')).read_text())
            self.assertEqual(len(commands), 4)
            self.assertIn('custom_scripts', commands[-1]['log'])
            self.assertTrue(next(root.glob('output/*/SHA256.json')).is_file())

    def test_nonzero_scan_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = b.parser().parse_args(['--plain'])
            runner = b.Runner(args, Path(tmp), b.UI(True))
            with contextlib.redirect_stdout(io.StringIO()):
                okay = runner.run([sys.executable, '-c', 'raise SystemExit(7)'], Path(tmp) / 'failed')
            self.assertFalse(okay)
            self.assertEqual(runner.commands[0]['returncode'], 7)


class OutputTests(unittest.TestCase):
    def test_prompt_uses_selected_directory(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value=tmp):
            self.assertEqual(b.choose_output(None, b.UI(True)), Path(tmp))

    def test_explicit_output_skips_prompt(self):
        with patch('builtins.input', side_effect=AssertionError('unexpected prompt')):
            self.assertEqual(b.choose_output(Path('chosen'), b.UI(True)), Path('chosen'))

    def test_noninteractive_requires_output(self):
        with patch.object(sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
            b.choose_output(None, b.UI(True))

    def test_quiet_saves_raw_output_and_verbose_prints_it(self):
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                args = b.parser().parse_args(['--plain'] + (['--verbose'] if verbose else []))
                runner = b.Runner(args, Path(tmp), b.UI(True))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    runner.run([sys.executable, '-c', 'print("RAW_SCANNER_MESSAGE")'], Path(tmp) / 'scan')
                self.assertEqual('RAW_SCANNER_MESSAGE' in output.getvalue(), verbose)
                self.assertIn('RAW_SCANNER_MESSAGE', (Path(tmp) / 'scan.log').read_text())


class WebTests(unittest.TestCase):
    def test_redirect_not_followed_and_virtual_host_preserved(self):
        hits = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append((self.path, self.headers.get('Host')))
                self.send_response(302)
                self.send_header('Location', 'http://new.invalid/never-request')
                self.end_headers()
                self.wfile.write(b'<title>Test &amp; title</title>wp-content')
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            responses = b.http_probe('127.0.0.1', 'approved.invalid', {'port': server.server_port, 'tunnel': ''})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual([p for p, host in hits], ['/', '/robots.txt'])
        self.assertEqual(hits[0][1], f'approved.invalid:{server.server_port}')
        self.assertEqual(responses[0]['title'], 'Test & title')
        self.assertEqual(responses[0]['technology_clues'], ['WordPress'])
        self.assertFalse(responses[0]['redirect_followed'])


if __name__ == '__main__':
    unittest.main()
