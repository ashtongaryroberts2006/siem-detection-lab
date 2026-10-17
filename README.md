# SIEM-Based Detection & Incident Response Lab

## Overview
A Splunk SIEM lab built from scratch across isolated VirtualBox VMs, ingesting Windows Event Logs and Sysmon telemetry, with six detections mapped to MITRE ATT&CK and each one validated against a real simulated attack.

Author: Ashton Roberts
Built: 29/07/2026 - 17/10/2026

## Contents

- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Skills Demonstrated](#skills-demonstrated)
- [Architecture](#architecture)
- [Build Log](#build-log)
- [Detections](#detections)
- [Incident Reports](#incident-reports)
- [Screenshots](#screenshots)
- [What I'd Add With More Time](#what-id-add-with-more-time)
- [Tools Used](#tools-used)
- [Resources Used](#resources-used)

## What This Project Demonstrates

This covers the full detection engineering cycle: standing up a log pipeline from Windows endpoints into Splunk, writing detections and mapping them to MITRE ATT&CK, validating each one against a simulated attack, and reasoning about false positives and how an attacker might evade each control. The build log is the honest version — forwarder permissions, event-channel ACLs, audit policy, alert logic, even a licence expiring halfway through — rather than just the finished result with the mess cleaned off.

## Skills Demonstrated

**SIEM & detection:** Splunk, SPL (search, `stats`, `where`), scheduled alerts with cron scheduling and throttling, detection tuning and false-positive reasoning
**Frameworks:** MITRE ATT&CK technique mapping across the attack lifecycle
**Telemetry:** Windows Security Event Logs, Sysmon (SwiftOnSecurity config), Windows audit policy (`auditpol`), Splunk Universal Forwarder
**Attack simulation:** netexec (SMB), PowerShell, scheduled tasks, process-lineage abuse
**Systems & infrastructure:** VirtualBox lab networking, Ubuntu Server, Linux service/permission troubleshooting, isolated network design, LVM disk management, Splunk licensing

## Architecture

Three VMs on a single isolated VirtualBox host-only network (`192.168.116.0/24`, `VirtualBox Host-Only Ethernet Adapter #2`). No internet access — deliberately air-gapped so simulated attack traffic stays contained. Logs flow one direction: Windows-Target ships Security and Sysmon events to the Splunk indexer over TCP 9997; Kali generates attack traffic against Windows-Target over SMB (445) and other protocols.

![SIEM lab network architecture](screenshots/architecture-diagram.png)

| VM | Role | Address |
|----|------|---------|
| Splunk-Server | SIEM / indexer | 192.168.116.3 |
| Windows-Target | Monitored endpoint (Sysmon + Universal Forwarder) | 192.168.116.5 |
| Kali-Attacker | Attack simulation | 192.168.116.6 |

## Build Log

### 29/07/2026 - Splunk Server Networking

- Created the Ubuntu Server VM (came up as 26.04 LTS), host-only network for isolation.
- **Issue:** Network adapter wasn't enabled in VM settings, so no IP was assigned.
  **Fix:** Ticked "Enable Network Adapter" in VirtualBox Settings > Network.
- **Issue:** Still no IP after enabling the adapter. `networkctl status` showed the interface stuck in "degraded (configuring)" — asking for an address and never getting one back.
  **Fix:** VirtualBox's host-only network had gotten into a broken state (DHCP ticked as enabled but not actually responding). Deleted it via File > Host Network Manager, created a fresh one (came up as `VirtualBox Host-Only Ethernet Adapter #2` on `192.168.116.x`), reattached the VM to it, rebooted — fixed.
- Confirmed working IP via `ip a`: `192.168.116.3`.
- Switched from the VirtualBox console window to SSH (`ssh analyst@192.168.116.3`) since the console doesn't support clipboard paste.

### 29/07/2026 - Splunk Installation

- Downloaded the Splunk Enterprise `.deb`, installed with `sudo dpkg -i splunk*.deb`. Admin account (`analyst`) created during first-run.
- **Issue:** `sudo /opt/splunk/bin/splunk start` returned to the prompt almost instantly, no real startup messages, and `splunk status` kept reporting `splunkd is not running`.
- **Investigation:** Ruled out disk space (`df -h` showed 7.8G free). Running `splunkd` directly surfaced a missing shared library (`libmongoc-1.0.so.0`), but `find` confirmed the file actually existed — a red herring from bypassing Splunk's normal startup wrapper, not the real issue. No stale PID file either.
- Tried `chown -R splunk:splunk /opt/splunk` on a hunch — still failed.
- **Further investigation:** `/opt/splunk/bin/splunk version` ran fine and confirmed the binaries were intact, but surfaced permission warnings on `/opt/splunk/var/log/splunk` and siblings.
- **Root cause:** The install is owned by the `splunk` user, but I was starting it as `analyst` via plain `sudo`, which doesn't properly assume `splunk`'s permissions for creating directories.
- **Fix:** Reapplied ownership recursively (`chown -R splunk:splunk`, `chmod -R u+rwX`), then started Splunk explicitly as the `splunk` user: `sudo -u splunk /opt/splunk/bin/splunk start --accept-license`.
- **Status:** Resolved. Dashboard loaded at `192.168.116.3:8000`.

### 05/08/2026 - Splunk Recurring Permissions Issue

- **Issue:** After some time away, the web UI stopped loading and `splunkd` wasn't running at all.
- **Investigation:** Restarting triggered Splunk's migration routine again, which failed with a permission error on `eventtypes.conf`.
- **Root cause:** An accidental `dpkg -i` reinstall earlier had reset ownership on parts of `/opt/splunk` back to `root`, same issue as before.
- **Fix:** Same as last time — reapply `chown -R splunk:splunk`, restart as the `splunk` user.
- **Status:** Resolved. Noted this will keep happening after any future reinstall — the ownership fix needs reapplying every time.

### 05/08/2026 - Windows-Target VM and Log Ingestion

- Built Windows-Target (Windows 10, same host-only network). Recreated it once after a `<ProductKey>` error caused by VirtualBox's "Unattended Installation" — fixed by ticking "Skip Unattended Installation" on the rebuild.
- Installed Sysmon with the SwiftOnSecurity config. The VM froze briefly mid-install — recovered with Machine > Reset, and confirmed via `sc query sysmon64` and Event Viewer that the install had actually finished despite the freeze.
- Installed the Universal Forwarder, pointed at `192.168.116.3:9997`. Set `inputs.conf` to forward Security, System, and Sysmon Operational logs — created it with `notepad inputs.conf` from Command Prompt to dodge a hidden `.txt` extension.
- Opened the receiving port on Splunk (Settings > Forwarding and receiving > 9997).
- **Checkpoint passed:** `index=main` showed 942 events live from Windows-Target — pipeline confirmed end to end.
- **Issue:** Windows-Target's adapter turned out to be on NAT, not Host-only (`ipconfig` showed `10.0.2.15`).
  **Fix:** Switched to Host-only. First attempt picked the wrong network (`vboxnet0`, a leftover unrelated network giving `192.168.56.x`). Corrected to `VirtualBox Host-Only Ethernet Adapter #2` — confirmed `192.168.116.5`.

### 10/08/2026 - Kali-Attacker VM Build

- Downloaded the Kali VirtualBox image, extracted the `.7z` with 7-Zip.
- **Issue:** Expected a single `.ova`, got a `.vbox` + `.vdi` pair instead — a VirtualBox machine folder, not an OVA appliance.
  **Fix:** Used Machine > Add to register the `.vbox` directly rather than File > Import Appliance.
- Set Adapter 1 to Host-only on the same network as the other two VMs.
- **Checkpoint passed:** `ip a` confirmed `192.168.116.6`. Pinged Splunk-Server successfully; Windows-Target didn't respond (expected — Windows Firewall blocks ICMP by default, doesn't affect log forwarding over 9997).

### 10/08/2026 - Sysmon Logs Not Reaching Splunk (Access Denied)

- **Issue:** Sysmon-based detections showed nothing in Splunk despite Security logs flowing fine. `index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` returned 0 events even over 24 hours.
- **Investigation:** Confirmed `inputs.conf`, Sysmon service, and the Forwarder service were all correctly set up. The Forwarder's own log showed repeated `errorCode=5` (Access Denied) trying to subscribe to the Sysmon channel.
- **Root cause:** The Forwarder runs as a virtual service account (`NT SERVICE\SplunkForwarder`), and its SID wasn't in the Sysmon channel's access control list — by default that channel only trusts SYSTEM, Administrators, Backup/Server Operators, and Event Log Readers.
- **Fix:** Pulled the exact SID with `sc showsid SplunkForwarder`, then rebuilt the channel's ACL with `wevtutil sl` to include it, keeping every existing entry. Restarting the Forwarder alone didn't clear the error — had to fully reboot Windows-Target, since Windows caches the channel's security state.
- **Status:** Resolved. Post-reboot, Sysmon events started flowing (1,735 events); the encoded-PowerShell detection returned 3 matching events.

### 13/08/2026 - VM Clock Drift Breaking Detection Testing

- **Issue:** The scheduled-task detection showed nothing despite the trigger running fine.
- **Investigation:** Both VMs had drifted well off real-world time — no internet access on the isolated network, so no NTP sync.
- **Root cause:** Events were timestamped correctly relative to the drifted clock, but fell outside the default search windows (`Last 24 hours`, `-10m`), even though the pipeline itself was healthy.
- **Fix:** Manually set the clock on both VMs (Windows via Settings; Ubuntu via `sudo timedatectl set-ntp false` + `sudo date -s "..."`).
- **Status:** Resolved. Flagged as a standing limitation of the air-gapped network — clocks need resyncing by hand, especially after a pause/resume.

### 13/08/2026 - Enabling Object Access Auditing for Share Detection

- **Issue:** The lateral movement detection needs Security Event ID 5140 (network share accessed), which Windows 10 doesn't log by default — the "Object Access > File Share" audit subcategory is off out of the box.
- **Fix:** Enabled it from an admin Command Prompt:
  - `auditpol /set /subcategory:"File Share" /success:enable /failure:enable`
  - `auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable`
  - `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable` (needed for EventCode 4698, scheduled task creation)
- Verified with `auditpol /get /category:"Object Access"`. No reboot needed.
- **Status:** Resolved. SMB share access from Kali now generates 5140, task creation now generates 4698 — genuine detection rather than inference from command-line strings.

### 20/08/2026 - Failed-Logon Alert Not Firing (trigger logic and action)

- **Issue:** The Repeated Failed Logons alert never showed up in Triggered Alerts, even though the search itself was correctly catching the offending account.
- **Investigation:** `index=_internal sourcetype=scheduler savedsearch_name="Repeated Failed Logons"` showed `result_count` populated but `alert_actions=""` — the search was matching but nothing was set up to fire.
- **Root causes, found in sequence:**
  1. The search ends in `stats count by Account_Name | where count > 5`, which returns one summary row per account — but the trigger was set to "Number of Results greater than 5," which a single row can never satisfy. Fixed to "greater than 0," since `where count > 5` already does the real filtering.
  2. The "Add to Triggered Alerts" action had silently dropped off the saved object after a few edits, and re-adding it through Edit wouldn't stick. Fixed by deleting and recreating the alert cleanly with the action attached at creation.
- **Also noticed:** repeated failed-logon tests kept tripping the account lockout policy — had to keep the attack loop just over the alert threshold to avoid re-locking the account between runs.
- **Status:** Resolved. Noted that `stats`-based alerts need a "greater than 0" trigger, not a raw count.

### 22/08/2026 - Forwarding Lag After VM Resume

- **Issue:** After resuming the VMs, some detections briefly returned nothing even though the pipeline was fine — e.g. a fresh scheduled task showed up in Event Viewer but not yet in Splunk.
- **Investigation:** Confirmed the event existed locally and that the Security channel was otherwise flowing — just lag on the newest events, not a broken channel.
- **Fix:** Re-ran the search after a short wait / widened the time range. Restarting the Forwarder flushed the queue where the lag persisted.
- **Status:** Expected behaviour after pause/resume — give it a minute or two before assuming a detection has failed.

### 17/10/2026 - Splunk Enterprise Trial Expired

- **Issue:** Every search and the whole dashboard started failing with "Could not create search" / licence violation errors.
- **Investigation:** Splunk's 60-day Enterprise Trial (auto-applied at install, ~29/07) had expired. Switching the license group to Free didn't restore normal use — Free has no scheduled alerting at all, and the deactivated owner on the expired trial had orphaned every saved search (found under Orphaned Scheduled Searches, Reports, and Alerts). Confirmed the underlying data and `savedsearches.conf` files were still intact on disk — nothing was actually lost, just inaccessible.
- **Fix:** Reinstalled Splunk Enterprise clean (`sudo rm -rf /opt/splunk`, reinstalled the `.deb`), which issues a fresh 60-day trial. Rebuilt all six alerts and the SOC Detection Overview dashboard from the queries already documented in this README, then retriggered each attack to regenerate validation data.
- **Status:** Resolved. All six detections retested and confirmed firing on the new instance.

### 17/10/2026 - Splunk-Server Disk Space Exhaustion

- **Issue:** Dashboard panels failed with "Could not create search" even on the original instance, before the license issue above.
- **Investigation:** `df -h` showed the root filesystem at 74% used, 4.7GB free — under Splunk's built-in 5GB minimum for running searches.
- **Root cause:** `lsblk` showed the virtual disk was genuinely 40GB and the partition 38GB, but the LVM logical volume actually mounted at `/` was only 19GB — half the partition's space had never been extended into the filesystem.
- **Fix:** `sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv`, then `sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv`.
- **Status:** Resolved. `/` now shows 38GB total, 23GB free. No data loss, no VM shutdown or VirtualBox-level resize needed — the space already existed, it just hadn't been claimed.

## Detections

Chosen to span different stages of the attack lifecycle rather than clustering on one tactic, so an intrusion is caught at more than one point — evading one control still leaves an attacker visible at another stage. Mirrors how a real SOC layers detection across the kill chain.

| Tactic | MITRE Technique | Detection | Data Source | Splunk Query |
|--------|-----------------|-----------|-------------|--------------|
| Credential Access | T1110 | Repeated failed logons | Security (4625) | `index=main EventCode=4625 Account_Name=* \| stats count by Account_Name \| where count > 5` |
| Execution | T1059.001 | Encoded-command PowerShell | Sysmon (EID 1) | `index=main CommandLine="*EncodedCommand*"` |
| Persistence | T1053.005 | Scheduled task creation | Security (4698) | `index=main EventCode=4698` |
| Execution / Defense Evasion | T1059 | cmd → PowerShell process lineage | Sysmon (EID 1) | `index=main EventCode=1 ParentImage="*cmd.exe*" Image="*powershell.exe*"` |
| Lateral Movement | T1021.002 | Admin-share access over SMB | Security (5140) | `index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")` |
| Defense Evasion | T1070.001 | Windows Security log cleared | Security (1102) | `index=main EventCode=1102` |

Each detection runs as a scheduled alert on a 5-minute cron (`*/5 * * * *`) against a `-5m@m` to `@m` window, with a 60-minute throttle so the same events don't re-alert on every run. Each alert's Description field carries its MITRE ATT&CK ID, so the alert is self-documenting inside Splunk.

## Incident Reports

### Incident 1: Repeated Failed Logons
- **Date/time detected:** 20/08/2026 20:40
- **MITRE ATT&CK technique:** T1110 - Brute Force
- **What triggered the alert:** Seven failed network logon attempts (EventCode=4625, Logon Type 3) against the local `Ashton` account within a short window, exceeding the threshold of five. Generated by repeated SMB authentication attempts from Kali-Attacker (`192.168.116.6`) using an incorrect password.
- **Splunk query used:** `index=main EventCode=4625 Account_Name=* | stats count by Account_Name | where count > 5`
- **Investigation steps taken:** Confirmed the target account, source host, and timing of each attempt. All came from the same source in a tight window — consistent with automated guessing, not a mistyped password. No successful logon (4624) followed.
- **Verdict:** True positive (simulated). Live next steps: confirm lockout, investigate/block the source host, check for a later successful logon on the same account.

### Incident 2: Suspicious PowerShell - Encoded Command
- **Date/time detected:** 10/08/2026 19:12:50.427
- **MITRE ATT&CK technique:** T1059.001 - PowerShell
- **What triggered the alert:** `powershell.exe` launched with `-EncodedCommand`, a technique used to obscure the actual command from casual inspection.
- **Splunk query used:** `index=main CommandLine="*EncodedCommand*"`
- **Investigation steps taken:** Located the Sysmon event, manually decoded the base64 payload to confirm it was the test command, checked ParentImage to confirm it came from an interactive session rather than something suspicious.
- **Verdict:** True positive (simulated). Any encoded command from an unexpected parent process would warrant immediate decoding.

### Incident 3: Persistence via Scheduled Task
- **Date/time detected:** 17/08/2026 22:06:55.749
- **MITRE ATT&CK technique:** T1053.005 - Scheduled Task
- **What triggered the alert:** A new scheduled task (`\EvilPersistence`) set to run `calc.exe` on logon, recorded as EventCode=4698.
- **Splunk query used:** `index=main EventCode=4698`
- **Investigation steps taken:** Confirmed the task name, the account that created it, and the target action. Used the Security-log creation event rather than a command-line match, so the detection fires regardless of how the task was created — `schtasks.exe`, PowerShell, the GUI, or WMI.
- **Verdict:** True positive (simulated). Unexpected task creation pointing to unusual binaries warrants immediate review.

### Incident 4: Suspicious Process Spawn (cmd → PowerShell)
- **Date/time detected:** 20/08/2026 20:49:09.311
- **MITRE ATT&CK technique:** T1059 - Command and Scripting Interpreter
- **What triggered the alert:** `cmd.exe` spawning `powershell.exe` — a living-off-the-land pattern where a trusted interpreter launches PowerShell for follow-on activity.
- **Splunk query used:** `index=main EventCode=1 ParentImage="*cmd.exe*" Image="*powershell.exe*"`
- **Investigation steps taken:** Confirmed ParentImage/Image matched the test, and that the CommandLine was benign with no obfuscation.
- **Verdict:** True positive (simulated). Complements Incident 2 — rather than looking at command contents, this flags the process lineage, catching suspicious chaining regardless of obfuscation.

### Incident 5: Lateral Movement - SMB Admin Share Access
- **Date/time detected:** 20/08/2026 20:44:37.303
- **MITRE ATT&CK technique:** T1021.002 - SMB/Windows Admin Shares
- **What triggered the alert:** Access to `C$` and `ADMIN$` over SMB (EventCode=5140), following share enumeration from Kali via `netexec` using valid credentials — the same mechanism PsExec-style tools use for remote execution.
- **Splunk query used:** `index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")`
- **Investigation steps taken:** Confirmed the shares accessed, the account, and that source and destination hosts genuinely differed (Kali → Windows-Target), ruling out local loopback.
- **Verdict:** True positive (simulated). Live priorities: is the source host expected to be administering the target, is the same source touching admin shares across multiple hosts, is share access followed by service creation (7045) indicating PsExec-style execution.

### Incident 6: Defence Evasion - Windows Security Log Cleared
- **Date/time detected:** 15/09/2026 14:30:43.270
- **MITRE ATT&CK technique:** T1070.001 - Clear Windows Event Logs
- **What triggered the alert:** The Security log was cleared (EventCode 1102) — a common anti-forensics move to destroy evidence after gaining access.
- **Splunk query used:** `index=main EventCode=1102`
- **Investigation steps taken:** Confirmed the host and account responsible. Noted that clearing the log itself generates the 1102 event, so the act of destroying local evidence still produces a durable, forwarded record — exactly why centralised forwarding defeats this technique.
- **Verdict:** True positive (simulated). High priority live — an attacker clearing logs implies admin access already gained. Response: preserve the SIEM's forwarded copy, isolate the host, reconstruct activity from the centrally-stored events.

## Screenshots

### 1. Working network configuration
`ip a` output showing the interface with a valid IP address assigned.
![Working ip a output](screenshots/01-ip-config.png)

### 2. VirtualBox Host-Only Network settings
Both the Adapter tab and DHCP Server tab.
![VirtualBox Adapter settings](screenshots/02a-vbox-adapter.png)
![VirtualBox DHCP Server settings](screenshots/02b-vbox-dhcp.png)

### 3. SSH connection into the VM
![SSH login to Splunk server](screenshots/03-ssh-login.png)

### 4. Splunk package installation confirmed
`dpkg -l | grep splunk` confirming the package is installed.
![Splunk install complete](screenshots/04-splunk-install.png)

### 5. Splunk service running
`ps aux | grep splunkd` confirming splunkd is running.
![Splunk status running](screenshots/05-splunk-status.png)

### 6. Splunk web home page
![Splunk web home page](screenshots/06-splunk-web-home.png)

### 7. Splunk receiving port configured
Port 9997 added under Forwarding and receiving.
![Splunk receiving port configured](screenshots/07-splunk-port-configured.png)

### 8. Windows-Target network configuration
![Windows-Target network configuration](screenshots/08-windows-network-configuration.png)

### 9. Windows-Target desktop confirmed
![Windows-Target desktop confirmed](screenshots/09-windows-desktop-confirmed.png)

### 10. Windows-Target IP address
![Windows-Target IP address](screenshots/10-windows-IP-address.png)

### 11. Sysmon installation confirmed
![Sysmon installation confirmed](screenshots/11-Sysmon-installation-confirmed.png)

### 12. Sysmon logging confirmed
![Sysmon events in Event Viewer](screenshots/12-sysmon-events.png)

### 13. First successful log ingestion
`index=main` search showing live data flowing in from the Windows target — the key "it's actually working" screenshot.
![Splunk index search showing ingested logs](screenshots/13-log-ingestion.png)

### 14. Kali-Attacker VM confirmed
![Kali-Attacker VM Confirmed](screenshots/14-kali-confirmed.png)

### 15. Full lab connectivity confirmed
![Full lab connectivity confirmed](screenshots/15-connectivity-confirmed.png)

### 16. Saved detection alerts (configuration)
One screenshot per detection, in edit view, so the full configuration is visible — search logic, alert type, cron schedule, time range, trigger condition, throttle, and trigger action. Each alert's Description carries its MITRE ATT&CK ID.

**16a. Repeated Failed Logons - T1110**
![Detection alert - failed logons](screenshots/16a-alert-failed-logons.png)

**16b. Suspicious PowerShell (Encoded Command) - T1059.001**
![Detection alert - encoded PowerShell](screenshots/16b-alert-powershell.png)

**16c. Persistence via Scheduled Task - T1053.005**
![Detection alert - scheduled task persistence](screenshots/16c-alert-persistence.png)

**16d. Suspicious Process Spawn (cmd to PowerShell) - T1059**
![Detection alert - suspicious process spawn](screenshots/16d-alert-process-spawn.png)

**16e. Lateral Movement (SMB Admin Share Access) - T1021.002**
![Detection alert - lateral movement](screenshots/16e-alert-lateral-movement.png)

**16f. Windows Security Log Cleared - T1070.001**
![Detection alert - Security log cleared](screenshots/16f-alert-logcleared.png)

**16g. Fired-event history**
Activity > Triggered Alerts — evidence the alerts have actually fired on live events, not just that they exist.
![Triggered alerts history](screenshots/16g-triggered-alerts.png)

### 17. Detection validation (attack → detection)
Each detection validated end to end: attacker action, then the matching event in Splunk. Attack traffic came from Kali (`192.168.116.6`) for network-based techniques and locally on Windows-Target (`192.168.116.5`) for host-based ones. `netexec` (`nxc`) handles SMB attacks, having replaced the now-deprecated `crackmapexec` in current Kali.

**17a. Repeated Failed Logons** — T1110
Seven failed SMB authentications against the `Ashton` account, generating EventCode 4625.
![Attack - failed logons](screenshots/17a-attack-failed-logons.png)
![Detection - failed logons](screenshots/17a-detection-failed-logons.png)

**17b. Suspicious PowerShell** — T1059.001
Base64 `-EncodedCommand` execution.
![Attack - encoded PowerShell](screenshots/17b-attack-powershell.png)
![Detection - encoded PowerShell](screenshots/17b-detection-powershell.png)

**17c. Persistence via Scheduled Task** — T1053.005
`schtasks /create`.
![Attack - persistence](screenshots/17c-attack-persistence.png)
![Detection - persistence](screenshots/17c-detection-persistence.png)

**17d. Suspicious Process Spawn** — T1059
`cmd.exe → powershell.exe`, captured via Sysmon Event ID 1.
![Attack - process spawn](screenshots/17d-attack-process-spawn.png)
![Detection - process spawn](screenshots/17d-detection-process-spawn.png)

**17e. Lateral Movement** — T1021.002
Admin share access (`C$`, `ADMIN$`) from Kali, generating EventCode 5140.
![Attack - lateral movement](screenshots/17e-attack-lateral-movement.png)
![Detection - lateral movement](screenshots/17e-detection-lateral-movement.png)

**17f. Security Log Cleared** — T1070.001
`wevtutil cl Security`, generating EventCode 1102.
![Attack - log cleared](screenshots/17f-attack-logcleared.png)
![Detection - log cleared](screenshots/17f-detection-logcleared.png)

### 18. SOC detection overview dashboard
Three-panel Splunk dashboard summarising activity across the detections.

![Dashboard - alert firing counts by detection](screenshots/18a-dashboard-alert-counts.png)
![Dashboard - recent triggered alerts table](screenshots/18b-dashboard-triggered-table.png)
![Dashboard - failed logons by logon type](screenshots/18c-dashboard-logon-types.png)

Firing counts come from `index=_internal sourcetype=scheduler`, filtered to the six detections and to runs that actually returned results (`result_count>0`), so counts reflect genuine firings rather than every scheduled run.

## What I'd Add With More Time

- **Second Windows target machine** — the lateral movement detection is currently validated by admin-share access from Kali to a single Windows host. A second domain-joined target would let me show the full chain: remote service creation (EventCode 7045) followed by PsExec-style remote execution.
- **NTP server for the lab network** — the isolated network has no internet access, so clocks drift and can't self-correct. Hit this directly when a detection appeared to fail purely because the VMs had drifted apart. Worth scripting a manual sync on startup.
- **Honeypot integration** — feeding a Cowrie or T-Pot honeypot into the same Splunk instance would bring in genuine unsolicited attack traffic instead of only self-triggered tests.
- **Automate the recurring permissions fix** — the `chown -R splunk:splunk` fix came up repeatedly after reinstalls. A small post-install script would remove it as a recurring manual step.
- **Broaden detection coverage** — add credential dumping (T1003), defense evasion (T1562), and exfiltration techniques, ideally mapped against a wider MITRE ATT&CK Navigator-style coverage view.
- **SOAR-style automation** — right now every alert just lands in Triggered Alerts for manual review. A lightweight automated response (host isolation, or a follow-up enrichment search) would push this from pure detection into basic IR automation.

## Tools Used
- VirtualBox (host-only networking for lab isolation)
- Ubuntu Server 26.04 LTS (Splunk host OS)
- Splunk Enterprise 10.4.1 — SIEM
- Splunk Universal Forwarder — log shipping from Windows-Target to Splunk
- Sysmon (Microsoft Sysinternals), SwiftOnSecurity config
- SSH — remote administration of the Splunk-Server VM
- Windows 10 (Windows-Target VM)
- Kali Linux (attacker VM)
- netexec (`nxc`) — SMB attack simulation from Kali
- Manual attack simulation on Windows-Target (PowerShell `-EncodedCommand`, `schtasks /create`, cmd → PowerShell process chain, `wevtutil cl Security`)

## Resources Used
- MITRE ATT&CK Framework — https://attack.mitre.org
- Sysmon configuration: SwiftOnSecurity — https://github.com/SwiftOnSecurity/sysmon-config
- netexec (successor to CrackMapExec) — https://github.com/Pennyw0rth/NetExec
- Splunk Enterprise / Universal Forwarder official documentation — https://docs.splunk.com
