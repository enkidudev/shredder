# Offline investigation rulebook

The rule engine interprets saved observations. It does not contact reference sites at scan time, fetch newly suggested paths, execute commands, or ask an online model for guesses.

Each lead includes `observation_status: observed` and `follow_up_status: unverified`. These describe different things: source evidence exists, but suggested follow-up actions and their possible impact have not been demonstrated. Priorities are curated investigation order, not measured confidence or vulnerability severity. No percentages are invented.

## Built-in rules

| Rule | Required evidence | Priority | Deliberate limit |
|---|---|---|---|
| Anonymous FTP | ftp-anon explicitly reports login allowed | Check first | Does not establish readable files or writable directories |
| Git HEAD | HTTP 200 and Git HEAD-shaped body at /.git/HEAD (extras enabled) | Check first | Does not establish complete source disclosure or credentials |
| NFS exports | nfs-showmount output includes export paths | Interesting | Does not establish mount/read access |
| SMB signing | smb2-security-mode explicitly reports signing optional or disabled | Interesting | Does not establish authentication availability or relay success |
| LDAP context | ldap-rootdse explicitly returns defaultNamingContext | Interesting | Does not establish authenticated/privileged LDAP access |
| Robots paths | HTTP 200 robots.txt with non-root Allow/Disallow paths | Interesting | Does not establish path availability or sensitive content |
| Redirect host | HTTP 3xx Location names a different host | Interesting | Does not establish ownership, scope or virtual-host mapping |
| Directory index | HTTP 200 root page has Index of title and links | Interesting | Pattern-based lead, not verified directory/file access |
| Sitemap | HTTP 200 sitemap contains loc elements (extras enabled) | Follow-up | Does not establish entry freshness or scope |
| Matching bodies | At least two root HTTP 200 endpoints share a captured body hash | Follow-up | Does not prove default/wildcard vhost; captures may be truncated |

Deterministic sorting uses priority, rule ID and endpoint. Repeated matches from different NSE stages are grouped by rule/endpoint, retaining source evidence. Only five leads per host are displayed by default; reports always retain all leads. Negative output, empty output, a port number or an old-looking banner does not trigger these findings.

## Sources and maintenance

The initial built-ins were reviewed on 2026-10-31 against primary references. Implementation contains links and original concise interpretations, not copied articles:

- [Nmap ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html)
- [Nmap smb2-security-mode](https://nmap.org/nsedoc/scripts/smb2-security-mode.html)
- [Nmap nfs-showmount](https://nmap.org/nsedoc/scripts/nfs-showmount.html)
- [Nmap ldap-rootdse](https://nmap.org/nsedoc/scripts/ldap-rootdse.html)
- [RFC 9309, robots exclusion](https://www.rfc-editor.org/rfc/rfc9309.html)
- [RFC 9110, HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-location)
- [Apache directory indexes](https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html)
- [Git repository layout](https://git-scm.com/docs/gitrepository-layout)
- [Sitemap protocol](https://www.sitemaps.org/protocol.html)
- [Apache name-based virtual hosts](https://httpd.apache.org/docs/2.4/vhosts/name-based.html)
- [Nmap output and native resume](https://nmap.org/book/man-output.html)

Future ideas can come from vendor documentation, blogs, research, community references or source code. Verify prerequisites, add positive and negative regression cases, record a source and review date, then include the rule. A broad source pool does not mean automatically trusting or scraping arbitrary internet text.

## Add local rules

```bash
shredder TARGET --rules ./examples/rules.json -o ./evidence
```

The JSON file is a list of up to 100 objects; a run accepts at most 100 custom rules in total. Required fields are `id`, `script_id`, `contains`, `title`, `priority`, `why`, `next_check`, and `references`. All text fields are nonempty strings, at most 2000 characters. IDs are unique lowercase letters/digits/hyphens and cannot override built-ins. Priority is `check-first`, `interesting`, or `follow-up`. References are a nonempty list of HTTPS URLs. Files are limited to 1 MiB.

Matching requires an exact script ID and case-insensitive literal substring in that script's output. No regex, Python evaluation or command execution occurs. Custom rules are marked `origin: custom` and have no claimed review date. The run saves a rule snapshot for resume. Treat custom rules as locally authored interpretations; a literal match is not an independently validated conclusion.

For compound conditions, protocol-aware parsing or new HTTP rules, edit `shredder_rules.py` and add meaningful positive/negative tests. There is no need for a plugin framework in this release.
