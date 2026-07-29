# Network Intrusion Detection System — Suricata NIDS Lab

Deployment and testing of **Suricata IDS** against a **Metasploitable 2** target, including custom detection rule authoring and live traffic validation.

## Objective

Set up a network-based Intrusion Detection System (IDS) using Suricata, write custom detection rules, generate representative traffic against a vulnerable target, and confirm that Suricata correctly logged and alerted on each activity type.

Process areas covered:
- Installing and configuring Suricata as a network-based IDS
- Defining the protected network (`HOME_NET`) and writing custom detection rules
- Loading a custom rule file into Suricata's YAML configuration
- Generating test traffic (ICMP, HTTP, SSH, Telnet, FTP) against a target host
- Monitoring Suricata's `fast.log` output to verify alerts for each activity

## Lab Environment

| Component | Details |
|---|---|
| IDS sensor / attacker workstation | Ubuntu Linux running Suricata |
| Target host | Metasploitable 2 (intentionally vulnerable Linux VM) |
| Protected network | `192.168.154.0/24` (defined as `HOME_NET`) |
| Services exercised | ICMP echo, HTTP (80), SSH (22), Telnet (23), FTP (21) |
| Test web application | Altoro Mutual demo banking site (`testfire.net`) for HTTP GET traffic |

## Configuring Suricata

### HOME_NET

In the `vars: address-groups` section of `suricata.yaml`, `HOME_NET` was set to `192.168.154.0/24`, with `EXTERNAL_NET` left as the default `!$HOME_NET`, so alerts correctly distinguish protected-network traffic from external traffic.

### Rule paths and files

`default-rule-path` was set to `/var/lib/suricata/rules`, and both `suricata.rules` and `custom.rules` were listed under `rule-files` so Suricata parses the custom rules on startup.

### Custom detection rules (`custom.rules`)

| SID | Rule | Match |
|---:|---|---|
| 1000001 | ICMP Echo Request Attempt Detected | `icmp any any -> $HOME_NET any` |
| 1000002 | HTTP GET Request Attempt Detected | `http $HOME_NET any -> $EXTERNAL_NET 80` |
| 1000003 | Potential SSH Bruteforce Attack | `tcp any any -> $HOME_NET 22` (matches SSH banner / brute-force patterns) |
| 1000004 | SSH Connection Attempt Detected | `tcp any any -> $HOME_NET 22` |
| 1000005 | TELNET Connection Attempt Detected | `tcp any any -> $HOME_NET 23` |
| 1000006 | FTP Login Attempt | `ftp any any -> $HOME_NET 21` |
| — | Possible Port Scan | TCP SYN-flag flood threshold (10 within a configured window) |

Each rule carries a unique `sid` so alerts in the log can be traced back to the exact rule that fired.

## Generating and Detecting Test Traffic

All traffic was generated from the attacker workstation against the Metasploitable 2 target (`192.168.154.138`), with Suricata logs monitored in real time:

```bash
tail -f /var/log/suricata/fast.log
```

### 1. ICMP Echo Request (Ping Sweep)
- Traffic: `ping -c 4 192.168.154.138` — all four echo requests received replies.
- Detection: matching "ICMP Echo Request Attempt Detected" alerts (`sid:1000001`) in `fast.log`.

### 2. HTTP GET Request
- Traffic: browsing to the Altoro Mutual demo banking app at `http://testfire.net`.
- Detection: each page request produced a corresponding "HTTP GET Request Attempt Detected" alert (`sid:1000002`), logging source workstation IP and destination IP:port 80.

### 3. SSH Connection Attempt
- Traffic: `ssh -oHostKeyAlgorithms=+ssh-rsa msfadmin@192.168.154.138`, authenticated with default Metasploitable credentials (`msfadmin`/`msfadmin`), confirmed shell access via `ls -la`.
- Detection: "SSH Connection Attempt Detected" alert (`sid:1000004`) on TCP port 22.

### 4. Telnet Connection Attempt
- Traffic: `telnet 192.168.154.138 23`, logged in with `msfadmin`/`msfadmin`, reaching an interactive shell.
- Detection: repeated "TELNET Connection Attempt Detected" alerts (`sid:1000005`) on TCP port 23, reflecting the multiple packets exchanged during the session.

### 5. FTP Login Attempt
- Traffic: `ftp 192.168.154.138`, logged in with `msfadmin` credentials against the target's vsFTPd 2.3.4 service, listed remote directory contents.
- Detection: "FTP Login Attempt" alerts (`sid:1000006`) on TCP port 21, with repeated timestamps reflecting the control-channel handshake and login negotiation.

## Continuous Monitoring

Suricata was run with `tail -f /var/log/suricata/fast.log` kept open throughout testing, confirming the IDS was actively monitoring the interface in real time rather than performing a one-time scan — satisfying the requirement for continuous traffic monitoring.

## Conclusion

Suricata was successfully deployed as a network-based IDS protecting the `192.168.154.0/24` lab network. Custom rules were written and loaded to detect ICMP, HTTP, SSH, Telnet, and FTP activity, and each rule was validated by generating live traffic against a Metasploitable 2 target and confirming matching alerts in `/var/log/suricata/fast.log`. The exercise demonstrates the full workflow required for an operational NIDS: configuration, custom rule authoring, continuous traffic monitoring, and alert identification for each class of detected activity.

## Repository Contents

Suggested structure — adjust to match what you actually include in the repo:

```
.
├── README.md
├── config/
│   └── custom.rules        # Custom Suricata detection rules
├── docs/
│   └── NIDS_Suricata_Report.docx   # Full lab report with screenshots
└── screenshots/             # Figures referenced in the report (optional)
```

## Tools & Technologies

- **Suricata** — open-source network IDS/IPS engine
- **Metasploitable 2** — intentionally vulnerable Linux VM (test target)
- **Altoro Mutual (testfire.net)** — demo web app for HTTP traffic generation
- Standard Linux networking tools: `ping`, `ssh`, `telnet`, `ftp`

---

*This README is derived from a lab report documenting a hands-on Suricata NIDS deployment and detection exercise.*
