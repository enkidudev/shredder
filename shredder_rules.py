"""Offline, evidence-led triage. Rules suggest checks; they never execute them."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

REVIEWED = '2026-10-31'
NSE = 'https://nmap.org/nsedoc/scripts/'
REFERENCES = {
    'ftp-anon': [NSE + 'ftp-anon.html'],
    'nfs-exports': [NSE + 'nfs-showmount.html'],
    'smb-signing': [NSE + 'smb2-security-mode.html'],
    'ldap-context': [NSE + 'ldap-rootdse.html'],
    'robots-paths': ['https://www.rfc-editor.org/rfc/rfc9309.html'],
    'redirect': ['https://www.rfc-editor.org/rfc/rfc9110.html#name-location'],
    'directory-index': ['https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html'],
    'git-head': ['https://git-scm.com/docs/gitrepository-layout'],
    'sitemap': ['https://www.sitemaps.org/protocol.html'],
    'matching-pages': ['https://httpd.apache.org/docs/2.4/vhosts/name-based.html'],
}


def load_rules(paths=()):
    """Custom rules are bounded, literal NSE-output matches, not Python/regex."""
    result, ids = [], set(REFERENCES)
    required = {'id', 'script_id', 'contains', 'title', 'priority', 'why', 'next_check', 'references'}
    for path in paths:
        path = Path(path)
        if path.stat().st_size > 1024 * 1024:
            raise ValueError(f'Rule file exceeds 1 MiB: {path}')
        rules = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(rules, list) or len(rules) > 100:
            raise ValueError(f'Expected a JSON list of at most 100 rules: {path}')
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != required:
                raise ValueError(f'Rule fields must be exactly: {", ".join(sorted(required))}')
            if any(not isinstance(rule[k], str) or not rule[k].strip() or len(rule[k]) > 2000
                   for k in required - {'references'}):
                raise ValueError('Rule text fields must be nonempty strings of at most 2000 characters.')
            if not re.fullmatch(r'[a-z0-9-]{1,64}', rule['id']) or rule['id'] in ids:
                raise ValueError(f'Invalid or duplicate rule ID: {rule["id"]}')
            if rule['priority'] not in {'check-first', 'interesting', 'follow-up'}:
                raise ValueError('Rule priority must be check-first, interesting, or follow-up.')
            refs = rule['references']
            if (not isinstance(refs, list) or not 1 <= len(refs) <= 10
                    or any(not isinstance(x, str) or len(x) > 2000 or urlsplit(x).scheme != 'https'
                           or not urlsplit(x).hostname for x in refs)):
                raise ValueError('Rule references must be a nonempty list of HTTPS URLs.')
            ids.add(rule['id'])
            result.append(rule)
            if len(result) > 100:
                raise ValueError('At most 100 custom rules may be loaded per run.')
    return result


def rank_leads(host, custom_rules=()):
    """Deterministic priorities, scoped deduplication, no version-to-CVE guesses."""
    leads = {}

    def add(rule, endpoint, title, priority, observation, why, next_check, source, refs=None):
        key = f'{rule}:{endpoint}'
        evidence = {'source': source, 'observation': observation[:1000]}
        if key in leads:
            if evidence not in leads[key]['evidence']:
                leads[key]['evidence'].append(evidence)
            return
        leads[key] = {
            'id': key, 'rule': rule, 'endpoint': endpoint, 'title': title,
            'priority': priority, 'observation_status': 'observed',
            'follow_up_status': 'unverified', 'observation': observation[:1000],
            'why_priority': why, 'next_check': next_check, 'evidence': [evidence],
            'references': refs or REFERENCES[rule], 'reviewed': REVIEWED if refs is None else None,
            'origin': 'builtin' if refs is None else 'custom',
        }

    for script in host.get('scripts', []):
        sid, output = script.get('id'), script.get('output', '')
        endpoint = f"{script.get('port') or 'host'}/{script.get('protocol') or 'host'}"
        source = script.get('source', script.get('stage', 'imported XML')) + f' -> {sid}'
        if sid == 'ftp-anon' and re.search(r'(?im)^\s*Anonymous FTP login allowed\b', output):
            add('ftp-anon', endpoint, 'Anonymous FTP login accepted', 'check-first',
                'ftp-anon reports anonymous login accepted.',
                'Authentication succeeded without supplied credentials; checking file access is a direct next step.',
                'List accessible files and inspect readable configurations/backups. Login alone does not prove file readability.', source)
        if sid == 'nfs-showmount':
            exports = re.findall(r'(?m)^\s*(/\S*)[^\r\n]*', output)
            if exports:
                add('nfs-exports', endpoint, 'NFS export paths disclosed', 'interesting',
                    'Listed exports: ' + ', '.join(exports[:8]),
                    'Concrete filesystem paths were returned; client eligibility and read access remain untested.',
                    'Check export client restrictions, then test permitted read access and inspect relevant files.', source)
        if sid == 'smb2-security-mode' and re.search(r'(?im)^\s*Message signing (?:enabled but not required|disabled)\s*$', output):
            add('smb-signing', endpoint, 'SMB signing not required for a reported dialect', 'interesting',
                'smb2-security-mode reports a dialect without mandatory signing.',
                'Negotiated configuration merits investigation; authentication and relay prerequisites are not established.',
                'Verify the relevant dialect and authentication policy. Assess relay prerequisites separately; no relay is proven.', source)
        if sid == 'ldap-rootdse':
            match = re.search(r'(?im)^\s*defaultNamingContext:\s*(DC=[^\r\n]+)', output)
            if match:
                add('ldap-context', endpoint, 'LDAP naming context discovered', 'interesting',
                    match.group(0).strip(),
                    'An explicit directory base enables focused LDAP enumeration; it does not imply privileged access.',
                    'Use the returned base DN to enumerate permitted directory data and validate domain names.', source)
        for rule in custom_rules:
            if sid == rule['script_id'] and rule['contains'].casefold() in output.casefold():
                add(rule['id'], endpoint, rule['title'], rule['priority'],
                    f'{sid} output contains the configured literal: {rule["contains"]}',
                    rule['why'], rule['next_check'], source, rule['references'])

    matching = {}
    for web in host.get('http', []):
        endpoint = f"{web['hostname']}:{web['port']}"
        for response in web['responses']:
            if response.get('error'):
                continue
            path, status = response.get('path'), response.get('status', 0)
            source = web.get('source', f'http_{web["port"]}.json') + f' -> {path}'
            body = response.get('body', '')
            if path == '/robots.txt' and status == 200:
                paths = sorted({m.group(1).split('#', 1)[0].strip() for m in
                                re.finditer(r'(?im)^\s*(?:disallow|allow):\s*(/[^\r\n]*)', body)})
                paths = [x for x in paths if x not in {'/', '/*', ''}]
                if paths:
                    add('robots-paths', endpoint, 'Paths disclosed in robots.txt', 'interesting',
                        'Declared paths: ' + ', '.join(paths[:8]),
                        'Explicit path clues are available, but robots directives do not establish access or sensitive content.',
                        'Request relevant in-scope paths and compare with a nonexistent-path response before deeper enumeration.', source)
            if 300 <= status < 400 and response.get('location'):
                location = response['location']
                try:
                    destination = urlsplit(location)
                    new_host = destination.hostname
                except ValueError:
                    new_host = None
                if new_host and new_host.casefold() != web['hostname'].casefold():
                    add('redirect', endpoint, 'Redirect names another host', 'interesting',
                        f'HTTP {status} Location: {location}',
                        'The application named another host; its purpose and relationship to this IP remain unverified.',
                        'Review scope. If appropriate, test the Host/SNI against this same scoped IP; do not assume the destination IP is in scope.', source)
            if path == '/' and status == 200:
                if re.search(r'<title[^>]*>\s*Index of\s', body, re.I) and re.search(r'<a\b', body, re.I):
                    add('directory-index', endpoint, 'Page resembles a directory index', 'interesting',
                        'Successful response contains an Index of title and links.',
                        'A recognizable page pattern gives a concrete lead; the listing and file access need verification.',
                        'Inspect links and verify listing behavior before testing relevant readable files.', source)
                digest = response.get('body_sha256') or hashlib.sha256(body.encode()).hexdigest()
                if body or response.get('body_bytes', 0):
                    matching.setdefault(digest, []).append((endpoint, source))
            if path == '/.git/HEAD' and status == 200 and re.fullmatch(r'ref: refs/[^\s]+\s*|[0-9a-fA-F]{40,64}\s*', body):
                add('git-head', endpoint, 'Git HEAD-shaped content returned', 'check-first',
                    'HTTP 200 with a Git HEAD-shaped body at /.git/HEAD.',
                    'A specific repository metadata pattern was retrieved; repository completeness and secrets are unverified.',
                    'Verify additional Git metadata and whether repository contents are accessible before claiming source disclosure.', source)
            if path == '/sitemap.xml' and status == 200:
                # Literal locations are leads only; never request them automatically.
                locs = re.findall(r'<(?:\w+:)?loc\b[^>]*>([^<]+)</(?:\w+:)?loc>', body, re.I)
                if locs:
                    add('sitemap', endpoint, 'Sitemap declares application locations', 'follow-up',
                        'Declared locations: ' + ', '.join(locs[:5]),
                        'The sitemap provides navigation leads; entries may be stale or outside scope.',
                        'Review declared locations and inspect interesting paths only after scope validation.', source)
    for digest, entries in matching.items():
        endpoints = sorted({x[0] for x in entries})
        if len(endpoints) > 1:
            add('matching-pages', digest[:16], 'Multiple web endpoints returned matching captured bodies', 'follow-up',
                ', '.join(endpoints),
                'Matching captured bodies suggest duplicate responses; a default vhost or wildcard remains a hypothesis.',
                'Compare status, headers, body truncation, and a controlled Host baseline before vhost fuzzing.', entries[0][1])
    order = {'check-first': 0, 'interesting': 1, 'follow-up': 2}
    return sorted(leads.values(), key=lambda x: (order[x['priority']], x['rule'], x['endpoint']))
