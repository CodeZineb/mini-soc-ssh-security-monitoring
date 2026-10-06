# Synthetic SOC Datasets

> **DISCLAIMER:** All datasets in this directory are 100% synthetic and generated exclusively for educational, demonstration, and portfolio purposes.
> - **Zero Live Connections:** No real network connections or offensive tools were used.
> - **RFC 5737 Compliance:** All public IP addresses strictly fall within the IETF reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`).
> - **Zero Real Credentials:** No production credentials, password hashes, or sensitive identifiers are present.

---

## 1. Dataset Summary

| File | Scenario Type | Primary Focus | Expected SOC Alert State |
| :--- | :--- | :--- | :--- |
| `synthetic_auth.log` | Baseline Benign Activity | Routine operations, user typos, cron tasks | Minimal / Baseline (No high alerts) |
| `brute_force_scenario.log` | Multi-Stage Security Incident | T1110.001 Brute Force, T1110.003 Spray, Compromise | High & Critical Security Alerts |

---

## 2. Dataset Detailed Breakdown

### A. `synthetic_auth.log` (Benign Baseline)
* **Description:** Represents typical authentication telemetry on a Linux server (`soc-node-01`) over an approximate 4-hour monitoring window.
* **Included Behaviors:**
  * Legitimate SSH key-based logins (`sysadmin`, `deploy`, `backup_svc`).
  * Normal password logins (`john`, `sarah`, `alex`).
  * Occasional human typo (single failed login immediately followed by successful login).
  * Automated system background tasks (periodic root cron jobs opening and closing PAM sessions).
  * Sporadic, isolated internet scanning noise (single invalid user attempts from separate IPs).
* **Detection Engine Role:** Validates that the detection threshold avoids false positives on healthy, standard operational noise.

### B. `brute_force_scenario.log` (Multi-Stage Incident)
* **Description:** Simulates an evolving cyber attack against `soc-node-01` across four sequential stages:

#### Stage A — Normal Baseline (09:00 - 09:30)
* Establishes the legitimate operational baseline with authorized administrator logins and standard cron executions.
* **Purpose:** Proves the system's ability to maintain low false positive rates prior to an incident.

#### Stage B — High-Frequency SSH Brute Force (09:40 - 09:44)
* **Attacker IP:** `203.0.113.88`
* **Target Users:** `root`, `admin`, `administrator`
* **Behavior:** 16 rapid failed password attempts in under 4 minutes.
* **MITRE ATT&CK:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
* **Detection Engine Role:** Triggers **High Severity Alert** (threshold: $\ge 10$ failures in 5 minutes).

#### Stage C — Low-and-Slow Password Spraying (10:00 - 10:25)
* **Attacker IP:** `198.51.100.45`
* **Target Users:** `service_acc`, `deploy`, `postgres`, `backup`, `jenkins`, `devops`, `oracle`, `git`
* **Behavior:** Single authentication attempts per username throttled across 25 minutes.
* **MITRE ATT&CK:** [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
* **Detection Engine Role:** Demonstrates correlation across distinct usernames originating from the same source IP over an expanded window.

#### Stage D — Targeted Account Cracking & Potential Compromise (10:45 - 10:52)
* **Attacker IP:** `198.51.100.190`
* **Target User:** `devops`
* **Behavior:** 6 consecutive failed password attempts followed immediately by a successful `Accepted password` and subsequent interactive shell privilege escalation (`sudo /bin/bash`).
* **Detection Engine Role:** Triggers **Critical Severity Alert** (Indicator of Compromise: multi-failure sequence followed by successful authenticated session from external source).

---

## 3. How the Detection Engine Evaluates These Datasets

1. **Regex Extraction:** The parser extracts `timestamp`, `hostname`, `service`, `event_type` (`FAILED`, `ACCEPTED`, `INVALID_USER`), `username`, and `source_ip`.
2. **Time-Window Correlation:** Groups failed authentication events by `source_ip` over configurable rolling windows (e.g., 5-minute sliding windows).
3. **Multi-Threshold Scoring:**
   * **Low:** 1–4 failures (logged for triage / baseline).
   * **Medium:** 5–9 failures in 5m (suspicious reconnaissance).
   * **High:** $\ge 10$ failures in 5m (active brute-force attack).
   * **Critical:** Repeated failures followed by an `ACCEPTED` status from the same IP within 10 minutes (potential compromised credential).
