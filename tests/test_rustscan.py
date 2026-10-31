"""Synthetic RustScan child processes: streaming, scope, handoff and recovery."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import shredder as b
from shredder_rustscan import discovery_command, parse_event
from test_v11 import host


class AdapterTests(unittest.TestCase):
    def test_live_and_summary_formats_ipv4_ipv6(self):
        for address, event in [('127.0.0.1', 'Open 127.0.0.1:22'), ('::1', 'Open [::1]:443')]:
            ports, final, empty = parse_event(event, address)
            self.assertEqual(ports, [int(event.rsplit(':', 1)[1])])
            self.assertFalse(final or empty)
            self.assertEqual(parse_event(f'{address} -> [22, 80]', address), ([22, 80], True, False))
        self.assertEqual(parse_event('127.0.0.1 -> []', '127.0.0.1'), ([], True, False))
        self.assertEqual(parse_event("[!] Looks like I didn't find any open ports for 127.0.0.1. This is usually caused by a high batch size.", '127.0.0.1'), ([], False, True))

    def test_noise_other_targets_invalid_and_unselected_ports_rejected(self):
        for line in ['Open 192.0.2.1:22', 'Closed 127.0.0.1:22', 'Open 127.0.0.1:0',
                     'Open 127.0.0.1:65536', 'Open example.com:22', 'Open 127.0.0.1:22 trailing',
                     '127.0.0.1 -> [0]', '127.0.0.1 -> [22,,80]', '192.0.2.1 -> [22]',
                     'Open 127.0.0.1:' + '9' * 5000]:
            self.assertEqual(parse_event(line, '127.0.0.1'), ([], False, False))
        self.assertEqual(parse_event('Open 127.0.0.1:80', '127.0.0.1', {22}), ([], False, False))
        self.assertEqual(parse_event('127.0.0.1 -> [22,80]', '127.0.0.1', {22}), ([], False, False))

    def test_command_pins_ip_ignores_config_and_never_invokes_scripts(self):
        args = b.parser().parse_args(['--discovery', 'rustscan'])
        cmd = discovery_command(args, '127.0.0.1')
        self.assertIn('--no-config', cmd)
        self.assertIn('--accessible', cmd)
        self.assertNotIn('--greppable', cmd)
        self.assertEqual(cmd[cmd.index('--scripts') + 1], 'none')
        self.assertEqual(cmd[cmd.index('--addresses') + 1], '127.0.0.1')
        self.assertEqual(cmd[-2:], ['--range', '1-65535'])
        with self.assertRaises(ValueError): discovery_command(args, 'example.com')

    def test_profiles_and_custom_port_translation(self):
        for options, expected in [(['--profile', 'quick'], ['--top']),
                                  (['--ports', '20-23'], ['--range', '20-23']),
                                  (['--ports', '22,80,8000-8001'], ['--ports', '22,80,8000,8001']),
                                  (['--ports', '1-65535'], ['--range', '1-65535'])]:
            cmd = discovery_command(b.parser().parse_args(options), '127.0.0.1')
            self.assertEqual(cmd[-len(expected):], expected)
        args = b.parser().parse_args(['--ports', ','.join(map(str, range(1, 65536, 2)))])
        with self.assertRaisesRegex(ValueError, 'too long'): discovery_command(args, '127.0.0.1')

    def test_nmap_remains_default_and_plan_never_runs_rustscan(self):
        self.assertEqual(b.parser().parse_args([]).discovery, 'nmap')
        with tempfile.TemporaryDirectory() as tmp, patch.object(subprocess, 'Popen', side_effect=AssertionError('scan')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.main(['127.0.0.1', '--discovery', 'rustscan', '--plan', '-o', tmp]), 0)


class StreamingTests(unittest.TestCase):
    def test_ports_are_displayed_and_journaled_before_process_can_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fake = directory / 'fake.py'
            ack = directory / 'ack'
            fake.write_text('''import pathlib, sys, time
print('Open 127.0.0.1:22', flush=True)
deadline = time.monotonic() + 5
while not pathlib.Path(sys.argv[1]).exists():
    if time.monotonic() > deadline: raise SystemExit(8)
    time.sleep(0.01)
print('Open 127.0.0.1:22', flush=True)
print('Open 192.0.2.1:445', flush=True)
print('Open 127.0.0.1:80', flush=True)
print('127.0.0.1 -> [22,80]', flush=True)
''')
            args = b.parser().parse_args(['--discovery', 'rustscan', '--plain'])
            h, output = host(), io.StringIO()
            ui = b.UI(True)
            original_say = ui.say
            checked = []
            def say(value, *a, **kw):
                if 'Discovered 22/tcp' in value:
                    journal = directory / '01_tcp_discovery.ports.jsonl'
                    self.assertEqual(json.loads(journal.read_text().splitlines()[0])['port'], 22)
                    self.assertFalse(ack.exists())
                    ack.touch()  # Child cannot finish until evidence and live output have arrived.
                    checked.append(True)
                original_say(value, *a, **kw)
            runner = b.Runner(args, directory, ui)
            with patch.object(b, 'discovery_command', return_value=[sys.executable, str(fake), str(ack)]), \
                 patch.object(ui, 'say', side_effect=say), contextlib.redirect_stdout(output):
                result = runner.discover_rustscan(h, directory)
            self.assertEqual(checked, [True])
            self.assertFalse(result['partial'])
            self.assertEqual([p['port'] for p in result['ports']], [22, 80])
            self.assertEqual(output.getvalue().count('Discovered 22/tcp'), 1)
            self.assertEqual(len((directory / '01_tcp_discovery.ports.jsonl').read_text().splitlines()), 2)
            self.assertEqual(json.loads((directory / 'commands.json').read_text())[0]['status'], 'complete')

    def test_timeout_retains_ports_and_partial_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, h = Path(tmp), host()
            args = b.parser().parse_args(['--discovery', 'rustscan', '--plain', '--timeout', '1'])
            command = [sys.executable, '-S', '-c', 'import time; print("Open 127.0.0.1:22", flush=True); time.sleep(10)']
            runner = b.Runner(args, directory, b.UI(True))
            with patch.object(b, 'discovery_command', return_value=command), contextlib.redirect_stdout(io.StringIO()):
                result = runner.discover_rustscan(h, directory)
            self.assertTrue(result['partial'])
            self.assertEqual([p['port'] for p in h['ports']], [22])
            self.assertEqual(h['discovery']['status'], 'partial')
            self.assertTrue(runner.partial)

    def test_interrupt_preserves_journal_summary_and_reraises(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, h = Path(tmp), host()
            runner = b.Runner(b.parser().parse_args(['--plain']), directory, b.UI(True))
            def run(command, stem, on_line):
                stem.with_suffix('.log').write_text('Open 127.0.0.1:22\n')
                on_line('Open 127.0.0.1:22')
                raise KeyboardInterrupt
            with patch.object(runner, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt): runner.discover_rustscan(h, directory)
            self.assertEqual(h['ports'][0]['port'], 22)
            self.assertTrue(json.loads((directory / '01_tcp_discovery.ports.json').read_text())['partial'])

    def test_unknown_zero_exit_is_not_complete_but_explicit_empty_result_is(self):
        for message, partial in [('unrecognized output', True), ('127.0.0.1 -> []', False)]:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                runner = b.Runner(b.parser().parse_args(['--plain']), directory, b.UI(True))
                def run(command, stem, on_line):
                    stem.with_suffix('.log').write_text(message)
                    on_line(message)
                    return True
                with patch.object(runner, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                    result = runner.discover_rustscan(host(), directory)
                self.assertEqual(result['partial'], partial)

    def test_checkpoint_reuse_and_tamper_invalidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            args = b.parser().parse_args(['--plain'])
            runner, calls = b.Runner(args, directory, b.UI(True)), []
            def run(command, stem, on_line):
                calls.append(stem.name)
                stem.with_suffix('.log').write_text('Open 127.0.0.1:22\n127.0.0.1 -> [22]\n')
                on_line('Open 127.0.0.1:22')
                on_line('127.0.0.1 -> [22]')
                return True
            with patch.object(b.Runner, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                runner.discover_rustscan(host(), directory)
                resumed = b.Runner(args, directory, b.UI(True))
                fresh = host()
                resumed.discover_rustscan(fresh, directory)
                self.assertEqual(calls, ['01_tcp_discovery'])
                self.assertEqual(fresh['ports'][0]['port'], 22)
                (directory / '01_tcp_discovery.ports.jsonl').write_text('changed')
                resumed.discover_rustscan(fresh, directory)
                self.assertEqual(calls[-1], '01_tcp_discovery_attempt02')


class PipelineTests(unittest.TestCase):
    def test_udp_discovery_still_uses_nmap(self):
        labels = []
        def discover(runner, h, directory):
            b.merge_results(h, {'ports': [b.port_record(22, 'synthetic')], 'scripts': [], 'discovered_names': []}, 'tcp_discovery')
        def scan(runner, h, directory, label, flags):
            labels.append((label, flags))
        with tempfile.TemporaryDirectory() as tmp, patch.object(b.shutil, 'which', side_effect=lambda x: x), \
             patch.object(b, 'elevated', return_value=True), patch.object(b, 'supported_scripts', return_value=([], [])), \
             patch.object(b.Runner, 'discover_rustscan', new=discover), patch.object(b.Runner, 'scan', new=scan), \
             contextlib.redirect_stdout(io.StringIO()):
            code = b.main(['127.0.0.1', '--discovery', 'rustscan', '--profile', 'full-udp', '-o', tmp, '--plain'])
        self.assertEqual(code, 0)
        self.assertEqual(labels[0][0], '02_udp_discovery')
        self.assertIn('-sU', labels[0][1])
        self.assertNotIn('-sT', labels[0][1])
        self.assertEqual(labels[1][0], '03_fingerprint_defaults')

    def test_legacy_v110_state_gets_new_option_defaults_without_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.main(['127.0.0.1', '--plan', '-o', tmp, '--plain']), 0)
            directory = next(Path(tmp).iterdir())
            plan = json.loads((directory / 'plan.json').read_text())
            plan['options']['plan'] = False
            for key in ('discovery', 'rustscan', 'rustscan_batch', 'rustscan_timeout', 'rustscan_tries'):
                plan['options'].pop(key)
            (directory / 'plan.json').write_text(json.dumps(plan))
            report = json.loads((directory / 'results.json').read_text())
            report.update(version='1.1.0', status='partial')
            (directory / 'results.json').write_text(json.dumps(report))
            with patch.object(b.shutil, 'which', side_effect=lambda x: x), \
                 patch.object(b, 'supported_scripts', return_value=([], [])), \
                 patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
                 patch.object(b.Runner, 'scan'), contextlib.redirect_stdout(io.StringIO()):
                code = b.main(['--resume', str(directory), '--plain'])
            self.assertEqual(code, 0)

    def test_missing_rustscan_gives_dependency_error_without_nmap_fallback(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(b.shutil, 'which', side_effect=lambda x: None if x == 'rustscan' else x), \
             patch.object(b.Runner, 'scan', side_effect=AssertionError('fallback')), \
             contextlib.redirect_stdout(io.StringIO()):
            code = b.main(['127.0.0.1', '--discovery', 'rustscan', '-o', tmp, '--plain'])
            self.assertEqual(code, 2)

    def test_rustscan_handoff_nse_partial_retry_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'scanner.py'
            fake.write_text('''import pathlib, sys
kind, args = sys.argv[1], sys.argv[2:]
if kind == 'rustscan':
    marker = pathlib.Path(__file__).with_suffix('.first')
    print('Open 127.0.0.1:22', flush=True)
    if not marker.exists():
        marker.touch()
        raise SystemExit(7)
    print('127.0.0.1 -> [22]', flush=True)
elif '--script-help' in args:
    names = args[args.index('--script-help')+1].split(',')
    print('<nmaprun>' + ''.join('<script filename="'+s+'.nse"/>' for s in names) + '</nmaprun>')
else:
    assert '-sV' in args, 'Nmap must never rediscover all TCP ports in RustScan mode'
    assert args[args.index('-p')+1] == 'T:22'
    stem = pathlib.Path(args[args.index('-oA')+1])
    stem.with_suffix('.xml').write_text('<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port portid="22" protocol="tcp"><state state="open"/><service name="ssh" method="probed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
''')
            real_run, real_popen = subprocess.run, subprocess.Popen
            def remap(command):
                if command[0] in {'fake-nmap', 'fake-rustscan'}:
                    kind = 'nmap' if command[0] == 'fake-nmap' else 'rustscan'
                    return [sys.executable, str(fake), kind] + command[1:]
                return command
            def run(command, *a, **kw): return real_run(remap(command), *a, **kw)
            def popen(command, *a, **kw): return real_popen(remap(command), *a, **kw)
            with patch.object(b.shutil, 'which', side_effect=lambda x: x), \
                 patch.object(subprocess, 'run', side_effect=run), patch.object(subprocess, 'Popen', side_effect=popen), \
                 contextlib.redirect_stdout(io.StringIO()):
                first = b.main(['127.0.0.1', '--discovery', 'rustscan', '--nmap', 'fake-nmap',
                                '--rustscan', 'fake-rustscan', '--plain', '-o', str(root / 'out')])
                directory = next((root / 'out').iterdir())
                with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('resume DNS')):
                    second = b.main(['--resume', str(directory), '--plain'])
                    third = b.main(['--resume', str(directory), '--plain'])
            self.assertEqual((first, second, third), (1, 0, 0))
            commands = json.loads((directory / 'commands.json').read_text())
            self.assertEqual(len(commands), 4)  # Partial RustScan, two Nmap stages, retried RustScan.
            self.assertEqual(sum(x['argv'][0] == 'fake-rustscan' for x in commands), 2)
            self.assertEqual(sum(x['argv'][0] == 'fake-nmap' for x in commands), 2)
            report = json.loads((directory / 'results.json').read_text())
            self.assertEqual(report['status'], 'complete')
            self.assertEqual(report['hosts'][0]['discovery']['status'], 'complete')
            self.assertTrue((directory / '127.0.0.1/01_tcp_discovery.ports.jsonl').exists())
            self.assertTrue((directory / '127.0.0.1/01_tcp_discovery_attempt02.ports.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
