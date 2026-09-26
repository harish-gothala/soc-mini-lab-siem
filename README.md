# PROJECT 1 — SOC Mini Lab with SIEM Correlation
### Detection Logic, Alert Tuning & MITRE ATT&CK Mapping

**Author:** Luffy007
**Environment:** VMware Workstation (3 VMs — isolated NAT network, `192.168.49.0/24`)
**Date:** September 2026

---

## 1. Goal

Build a mini Security Operations Center (SOC) that ingests logs from multiple endpoints, deploys network intrusion detection, generates real attack traffic, correlates that traffic into actionable alerts, and documents the detection logic — including tuning out false positives and mapping detections to the MITRE ATT&CK framework.

---

## 2. Lab Architecture

```
                     ┌─────────────────────────┐
                     │   SOC-SIEM-Server        │
                     │   Ubuntu 26.04 LTS        │
                     │   IP: 192.168.49.129      │
                     │                           │
                     │  ┌─────────────────────┐  │
                     │  │ Elasticsearch 9.5.2  │  │  (Docker container: es-local-dev)
                     │  └─────────────────────┘  │
                     │  ┌─────────────────────┐  │
                     │  │ Kibana 9.5.2         │  │  (Docker container: kibana-local-dev)
                     │  └─────────────────────┘  │
                     │  Also used as "attacker"  │
                     │  host: nmap, Hydra        │
                     └───────────┬───────────────┘
                                 │
                 192.168.49.0/24 (VMware NAT network)
                                 │
        ┌────────────────────────┴────────────────────────┐
        │                                                  │
┌───────▼─────────────┐                        ┌───────────▼────────────┐
│ SOC-Windows-Endpoint │                        │ SOC-Linux-Endpoint      │
│ Windows 11 Enterprise│                        │ Ubuntu 26.04 LTS        │
│ IP: 192.168.49.131   │                        │ IP: 192.168.49.133      │
│                      │                        │                         │
│ Sysmon (telemetry)   │                        │ Suricata 8.0.3 (IDS)    │
│ Winlogbeat 9.5.2     │                        │ Filebeat 9.5.3          │
│ → ships Sysmon/       │                        │ → ships auth.log/syslog│
│   Security/System     │                        │   to Elasticsearch      │
│   event logs           │                        │                         │
└──────────────────────┘                        └─────────────────────────┘
```

**Note on substitution:** The original plan specified **Snort**. Snort was not available in the Ubuntu repository for this release ("resolute"). **Suricata 8.0.3** was substituted — it is the modern, actively-maintained successor to Snort, uses largely compatible rule syntax (Emerging Threats Open ruleset, ~60,000+ rules), and is what most current-generation SOC deployments use in practice. This substitution is noted throughout as "IDS (Suricata, Snort-compatible)".

---

## 3. Tools Used

| Tool | Version | Purpose |
|---|---|---|
| Elasticsearch | 9.5.2 | Log storage & search (SIEM backend) |
| Kibana | 9.5.2 | Visualization, Discover, Alerting rules |
| Sysmon | (SwiftOnSecurity config) | Windows endpoint telemetry (process creation, network, file events) |
| Winlogbeat | 9.5.2 | Ships Windows Event Logs → Elasticsearch |
| Filebeat | 9.5.3 | Ships Linux auth.log/syslog → Elasticsearch |
| Suricata | 8.0.3 | Network IDS (substituted for Snort) |
| nmap | 7.98 | Attack simulation — port scanning |
| Hydra | 9.6 | Attack simulation — SSH brute force |
| Docker | — | Hosts Elasticsearch & Kibana containers |
| VMware Workstation | 25H2 | Virtualization platform for all 3 lab VMs |

---

## 4. Steps Completed

1. ✅ **Deploy Elastic Stack** — Elasticsearch + Kibana 9.5.2 via Docker on SOC-SIEM-Server
2. ✅ **Forward logs from Linux + Windows** — Winlogbeat (Windows/Sysmon) and Filebeat (Linux auth.log/syslog), both confirmed live in Kibana Discover
3. ✅ **Deploy IDS on gateway** — Suricata 8.0.3 (Snort substitute) on SOC-Linux-Endpoint, monitoring interface `ens33`, loaded with the Emerging Threats Open ruleset (~60,618 rules)
4. ✅ **Generate attacks** — SYN port scan (nmap) and SSH brute-force (Hydra), both run from SOC-SIEM-Server against SOC-Linux-Endpoint
5. ✅ **Write correlation rules** — Kibana Elasticsearch Query rule (`SSH Brute Force Detection`), verified firing live against real Hydra traffic
6. ✅ **Create alert thresholds** — threshold built into the correlation rule (see §5)
7. ✅ **Tune false positives** — Suricata suppress rule added for internal SIEM traffic noise (see §6)
8. ✅ **Map alerts to MITRE ATT&CK** — see §7
9. ✅ **Build dashboards** — see §9
10. ✅ **Document detection logic** *(this document)*

---

## 5. Detection Rules

### 5.1 SIEM Correlation Rule — SSH Brute Force Detection

| Field | Value |
|---|---|
| Rule name | `SSH Brute Force Detection` |
| Rule type | Elasticsearch query |
| Data view | `filebeat-*` |
| Query (KQL) | `message: "authenticating user"` |
| Condition | `count() OVER all documents IS ABOVE 5` |
| Time window | `1 minute` |
| Schedule | Runs every 1 minute |

**Rationale:** OpenSSH logs a `Connection closed by authenticating user <user> <ip> port <port> [preauth]` line for every failed pre-authentication attempt. A legitimate user might fail a password once or twice; more than 5 failures from the same source within 60 seconds is a strong brute-force signal. This threshold was chosen based on observing Hydra's default behavior (5 parallel attempts against a small password list landing in the same second).

**Verification:** Rule fired successfully against live Hydra traffic (confirmed via Kibana Alerts page — "Notify when alerts generated: a few seconds ago" after a fresh attack run). 22 executions logged in 24 hours, 0 errors, status "Succeeded".

### 5.2 Suricata IDS Rules

Suricata was loaded with the **Emerging Threats Open** ruleset:
- 60,618 total rules loaded
- 15 rules disabled (protocol modules not in use: pgsql, modbus, dnp3, enip)
- 136 rules enabled for flowbit dependencies

No custom Suricata signatures were written; detection relies on the community ruleset plus the tuning described below.

---

## 6. Alert Tuning Notes

### 6.1 False Positive: Internal SIEM Traffic Flagged as "Credential Leak"

**Observed behavior:** Suricata repeatedly fired the following alert roughly every 5 minutes:

```
[**] [1:2006380:18] ET INFO Outgoing Basic Auth Base64 HTTP Password detected
     unencrypted [**] [Classification: Potential Corporate Privacy Violation]
     [Priority: 1] {TCP} 192.168.49.133:xxxxx -> 192.168.49.129:9200
```

and a related rule:

```
[**] [1:2012888:4] ET INFO Http Client Body contains pwd= in cleartext [**]
     [Classification: Potential Corporate Privacy Violation] [Priority: 1]
     {TCP} 192.168.49.133:xxxxx -> 192.168.49.129:9200
```

**Root cause analysis:** This traffic is Filebeat, running on SOC-Linux-Endpoint (`192.168.49.133`), authenticating to Elasticsearch (`192.168.49.129:9200`) using HTTP Basic Auth. Because the Elastic Stack in this lab is configured with `output.elasticsearch` pointing at plain `http://` (not `https://`), the `elastic` user's password is transmitted in cleartext (base64-encoded, not encrypted) on every log-shipping cycle. Suricata correctly identified this as unencrypted credential transmission — **the detection itself was accurate**, but it is expected, self-generated lab traffic, not an external threat.

**Decision:** Suppress this specific signature for this specific internal source IP, rather than disabling the rule entirely — preserving the rule's ability to catch the *same* behavior from any other (potentially malicious) source.

**Fix applied** (`/etc/suricata/threshold.config`):
```
suppress gen_id 1, sig_id 2006380, track by_src, ip 192.168.49.133
```

**Verification:** After restarting Suricata, the log was monitored for 16+ minutes with zero recurrence of the suppressed alert, while the Suricata service remained healthy and actively processing traffic.

**Production recommendation (noted, not implemented in this lab):** The correct long-term fix is not suppression but enabling TLS on the Elasticsearch output (`https://` + `ssl.verification_mode`), which would eliminate the cleartext credential exposure at its source rather than muting the alert about it. This was intentionally left as plain HTTP in this lab for setup simplicity and is documented here as a known limitation.

### 6.2 Non-Finding: Port Scan Did Not Trigger a Signature Alert

**Observed behavior:** An `nmap -sS -p 1-1000` and a full `nmap -sT -p- -T4` scan were run against SOC-Linux-Endpoint. Both completed successfully (confirming port 22/ssh open) but **produced no corresponding Suricata alert**, despite 563 scan-related signatures being present in the loaded ruleset.

**Analysis:** The Emerging Threats Open ruleset's scan-detection rules are largely *content/signature-based* (matching known scanner banners, tool fingerprints, specific packet payloads) rather than *behavioral/statistical* (e.g., "N connection attempts to N distinct ports within N seconds from one source"). A fast, low-noise SYN scan against a single mostly-closed port range does not generate the kind of distinctive payload these signature rules look for.

**Conclusion for documentation:** This is a genuine detection gap in the out-of-the-box configuration, not a tool failure. A production deployment would need either:
- Suricata's stream/anomaly-based detection tuned specifically for scan behavior, or
- A dedicated statistical threshold rule (e.g., via `detection-filter` or a SIEM-side correlation rule counting distinct destination ports per source IP per minute — the same technique used for the brute-force rule in §5.1, adapted for port-scan detection)

This gap and its explanation are themselves a valid SOC analyst deliverable — knowing *why* something wasn't detected is as important as detecting things that were.

---

## 7. MITRE ATT&CK Mapping

| Detection / Observation | MITRE ATT&CK Technique | Tactic | Evidence Source |
|---|---|---|---|
| SSH brute-force attempt (Hydra, 5 failed logins in <1s from `192.168.49.129`) | **T1110.001** – Brute Force: Password Guessing | Credential Access | `/var/log/auth.log` → Filebeat → Kibana correlation rule alert |
| Port scan (`nmap -sS` / `-sT -p-`) against SSH service | **T1046** – Network Service Discovery | Discovery | nmap output on SOC-SIEM-Server (not independently alerted by Suricata — see §6.2) |
| Cleartext credential transmission (Filebeat → Elasticsearch over HTTP) | **T1552.001** – Unsecured Credentials: Credentials In Files *(closest match; more precisely, plaintext-equivalent transmission of credentials)* | Credential Access | Suricata `fast.log`, SID 2006380 / 2012888 (tuned, see §6.1) |
| OpenSSH automatic rate-limiting on repeated auth failures (`srclimit_penalise: activating ipv4 penalty of 19 seconds`) | *Defensive control, not an attack technique* — comparable to **M1036** (Account Use Policies) / rate-limiting mitigation | Mitigation | `/var/log/auth.log` |

**Notes:**
- Only techniques with real, generated evidence in this lab are included above — no theoretical/unobserved techniques are mapped, to keep this section honest and defensible.
- The brute-force detection (T1110.001) is the strongest, fully end-to-end verified finding in this lab: attack → log → shipping → indexing → correlation rule → live alert, all independently confirmed at each stage.

---

## 9. Dashboards

A single Kibana dashboard was built consolidating the lab's key telemetry into three panels, giving an at-a-glance view of both attack activity and general endpoint health.

### 9.1 Failed SSH Login Attempts Over Time

- **Data view:** `filebeat-*`
- **Query:** `message: "authenticating user"`
- **Chart type:** Bar (vertical), date histogram on `@timestamp`, count of records on Y-axis

**What it shows:** A clean, isolated spike of ~17 failed login attempts on the day the Hydra brute-force tests were run, with flat/zero activity on every other day. At a glance, an analyst can immediately identify the anomalous burst without needing to query logs manually — this panel is the visual counterpart to the correlation rule in §5.1.

### 9.2 Log Volume by Endpoint

- **Data view:** combined data view `all-beats-*` (index pattern `filebeat-*,winlogbeat-*`), since Kibana Lens visualizations can only reference one data view at a time and the two log sources live in separate indices
- **Chart type:** Pie, broken down by `agent.hostname`

**What it shows:** A split of ~62% Windows endpoint (`DESKTOP-8IB3B8N`) vs ~38% Linux endpoint (`soc-linux-endpoint`) log volume. Useful as a sanity check that both pipelines are actively shipping data, and as a baseline — a sudden shift in this ratio (e.g., one endpoint's share dropping to near-zero) would be a fast way to notice a broken or stopped Beats agent.

### 9.3 Top Windows Event Types

- **Data view:** `winlogbeat-*`
- **Chart type:** Bar (horizontal), top 9 values of `event.code`

**What it shows:** A breakdown of the most frequent Sysmon/Windows Event Log codes. Notable finding: **Event 4907 (Auditing Settings on Object changed)** accounted for roughly 11,000 of the observed events — an order of magnitude more than any other event type (Event 11/FileCreate and Event 13/RegistryEvent each sat around 2,000; security-relevant events like 4624/Successful Logon, 4672/Special Privileges Assigned, and 5379/Credential Manager Read were present but comparatively low-volume).

**Analysis:** This volume is disproportionate to what's actually useful for detection — 4907 events are triggered by routine object-permission auditing (a default/verbose local audit policy setting), not attacker activity, in this lab. This is the same category of finding as the Suricata false positive in §6.1: a real, accurately-logged event that nonetheless drowns out higher-value security events in raw volume. **Recommended follow-up (not yet implemented):** either narrow the Windows audit policy to stop generating 4907 at this rate, or exclude `event.code: 4907` from the default Winlogbeat shipping configuration and rely on a targeted collection method if that specific auditing signal is ever needed.

---

## 10. Known Limitations & Future Work

- **TLS not enabled** between Filebeat/Winlogbeat and Elasticsearch (plain HTTP) — acceptable for an isolated lab network, not acceptable for production. See §6.1.
- **Port-scan detection gap** — signature-based IDS rules did not catch a low-and-slow SYN scan; a statistical/threshold-based detection would close this gap (see §6.2).
- **Snort → Suricata substitution** — functionally equivalent for this project's purposes, but should be explicitly noted in any deliverable referencing the original "Project 2" brief.
- **Windows audit-log noise** — Event 4907 dominates Windows log volume at roughly 5x the next-highest event type; not yet filtered or tuned out (see §9.3).
- **Dashboard panels saved "by value"** rather than from a shared visualization library, so they aren't independently reusable across other dashboards without being rebuilt or explicitly saved to the library.

---

## 11. Deliverables Checklist

- [x] SOC architecture diagram (§2)
- [x] Detection rules (§5)
- [x] MITRE mapping (§7)
- [x] Alert tuning notes (§6)
- [x] Kibana dashboards (§9)
