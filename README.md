# SIEM-Based Detection & Incident Response Lab

## Overview
A Splunk SIEM lab built from scratch across isolated VirtualBox VMs, ingesting Windows Event Logs and Sysmon telemetry, with six detections mapped to MITRE ATT&CK and each one validated against a real simulated attack.

Author: Ashton Roberts
Built: 29/07/2026 - 17/10/2026

## Contents
- What This Project Demonstrates
- Skills Demonstrated
- Architecture
- Build Log
- Detections
- Incident Reports
- Screenshots
- What I'd Add With More Time
- Tools Used
- Resources Used

## What This Project Demonstrates
This project covers the full detection engineering cycle: setting up a log pipeline from Windows endpoints into Splunk, writing detections and mapping them to MITRE ATT&CK, validating each one against a simulated attack, and reasoning about false positives and how an attacker might evade each control. The build log below covers the challenges faced completing this project, including forwarder permissions, event-channel ACLs, audit policy, alert logic, and a Splunk licence expiring halfway through, not just a clean version.

## Skills Demonstrated
- SIEM and detection: Splunk, SPL (search, stats, where), scheduled alerts with cron scheduling and throttling, detection tuning and false-positive reasoning
- Frameworks: MITRE ATT&CK technique mapping across the attack lifecycle
- Telemetry: Windows Security Event Logs, Sysmon (SwiftOnSecurity config), Windows audit policy (auditpol), Splunk Universal Forwarder
- Attack simulation: netexec (SMB), PowerShell, scheduled tasks, process-lineage abuse
- Systems and infrastructure: VirtualBox lab networking, Ubuntu Server, Linux service and permission troubleshooting, isolated network design, LVM disk management, Splunk licensing

## Architecture
Three VMs on a single isolated VirtualBox host-only network (192.168.116.0/24, "VirtualBox Host-Only Ethernet Adapter #2"). There is no internet access, so simulated attack traffic stays contained. Logs flow in one direction: Windows-Target ships Security and Sysmon events to the Splunk indexer over TCP 9997; Kali generates attack traffic against Windows-Target over SMB (445) and other protocols.

![SIEM lab network architecture](screenshots/architecture-diagram.png)

| VM | Role | Address |
|----|------|---------|
| Splunk-Server | SIEM / indexer | 192.168.116.3 |
| Windows-Target | Monitored endpoint (Sysmon + Universal Forwarder) | 192.168.116.5 |
| Kali-Attacker | Attack simulation | 192.168.116.6 |

## Build Log

### 29/07/2026 - Splunk Server Networking
- Created the Ubuntu Server VM (came up as 26.04 LTS) with host-only network for isolation
- Problem: the network adapter was not enabled, so no IP was assigned
- Solution: ticked "Enable Network Adapter" in VirtualBox Network settings
- Problem: there was still no IP after that. networkctl status showed the interface stuck, asking for an address and never getting one back
- Cause: VirtualBox's host-only network had broken, so DHCP was ticked as enabled but was not actually responding
- Solution: deleted it via File > Host Network Manager, created a new one ("VirtualBox Host-Only Ethernet Adapter #2" on 192.168.116.x), then reattached the VM and rebooted
- Confirmed working IP: 192.168.116.3
- Switched from the VirtualBox console window to SSH, since the console doesn't support clipboard paste

### 29/07/2026 - Splunk Installation
- Downloaded the Splunk Enterprise .deb, installed it, and created the admin account (analyst) during first run
- Problem: Splunk start returned to the prompt instantly with no real startup messages, and status kept saying splunkd is not running
- Ruled out disk space first (7.8G free). Running splunkd directly surfaced a missing shared library, but the file actually existed, so this was a red herring from bypassing the normal startup wrapper
- There was no stale PID file either, and chown did not fix it by itself
- Running splunk version directly confirmed the binaries were fine but surfaced permission warnings on the log directory
- Cause: the install was owned by the splunk user, but it was being started as analyst via plain sudo, which doesn't assume splunk's permissions for creating directories
- Solution: reapplied ownership recursively, then started Splunk explicitly as the splunk user
- Resolved, and the dashboard loaded fine

### 05/08/2026 - Splunk Recurring Permissions Issue
- After time away, the web UI stopped loading and splunkd wasn't running at all
- Restarting triggered the migration routine again, and it failed with a permission error
- Cause: an earlier accidental reinstall had reset ownership back to root
- Solution: same as before, reapply ownership, restart as splunk user
- Noted that this will recur after any future reinstall

### 05/08/2026 - Windows-Target VM and Log Ingestion
- Built Windows-Target, and recreated it once after a ProductKey error caused by VirtualBox's "Unattended Installation", fixed by ticking "Skip Unattended Installation"
- Installed Sysmon with the SwiftOnSecurity config, and confirmed the install had actually completed
- Installed the Universal Forwarder, pointed at 192.168.116.3:9997, then set up inputs.conf for Security, System and Sysmon logs
- Opened the receiving port on Splunk
- 942 events showed up live from Windows-Target, so the pipeline was confirmed end to end
- Problem: Windows-Target's adapter was on NAT, not Host-only (ipconfig showed 10.0.2.15)
- Solution: switched to Host-only, corrected a wrong network pick along the way, and confirmed 192.168.116.5

### 10/08/2026 - Kali-Attacker VM Build
- Downloaded the Kali image and extracted the archive
- Problem: expected a single .ova, but got a .vbox and .vdi pair instead (a VirtualBox machine folder, not an OVA)
- Solution: used Machine > Add to register the .vbox directly
- Set Adapter 1 to Host-only on the same network as the other two VMs
- Checkpoint passed: confirmed 192.168.116.6, pinged Splunk-Server successfully, and Windows-Target didn't respond (expected, since Windows Firewall blocks ICMP by default)

### 10/08/2026 - Sysmon Logs Not Reaching Splunk (Access Denied)
- Problem: Sysmon-based detections showed nothing despite Security logs flowing fine
- Confirmed inputs.conf, the Sysmon service and the Forwarder service were all correctly set up
- The Forwarder's own log showed repeated Access Denied errors trying to subscribe to the Sysmon channel
- Cause: the Forwarder runs as a virtual service account, and its SID wasn't in the Sysmon channel's access control list
- Solution: pulled the exact SID, rebuilt the channel's ACL to include it, and kept every existing entry
- Restarting the Forwarder alone didn't clear it, so it needed a full reboot since Windows caches the channel's security state
- Resolved, and Sysmon events started flowing, confirming the PowerShell detection worked end to end

### 13/08/2026 - VM Clock Drift Breaking Detection Testing
- Problem: the scheduled-task detection showed nothing despite the trigger running fine
- Both VMs had drifted off real-world time, since there's no internet access on the isolated network so no NTP sync
- Cause: events were timestamped correctly relative to the drifted clock, but fell outside the default search windows
- Solution: manually corrected the clock on both VMs
- Noted as a standing limitation of the air-gapped network, since it needs resyncing by hand, especially after a pause and resume

### 13/08/2026 - Enabling Object Access Auditing for Share Detection
- Problem: the lateral movement detection needs Security Event ID 5140, which Windows 10 doesn't log by default
- Solution: enabled the relevant auditpol subcategories (File Share, Detailed File Share, Other Object Access Events, the last one needed for the scheduled task event too)
- Verified with auditpol, and no reboot was needed
- Resolved, so SMB share access and task creation now generate genuine audit events

### 20/08/2026 - Failed-Logon Alert Not Firing
- Problem: the Repeated Failed Logons alert never showed up in Triggered Alerts even though the search was correctly matching
- Checked the scheduler log, which showed result count was populated but no action was attached
- Cause one: the search returns one summary row per account, but the trigger was set to "greater than 5", and a single row can never satisfy that. Fixed to "greater than 0", since the real threshold is already enforced inside the search
- Cause two: the "Add to Triggered Alerts" action had silently dropped off the saved alert, and re-adding it through Edit wouldn't stick. Fixed by deleting and recreating the alert cleanly
- Also noticed repeated test runs kept tripping account lockout, so trimmed the attack loop to avoid locking myself out between tests
- Noted that stats-based alerts need a "greater than 0" trigger, not a raw count

### 22/08/2026 - Forwarding Lag After VM Resume
- Problem: after resuming the VMs, some detections briefly returned nothing even though the pipeline was healthy
- Confirmed the event existed locally, so it was just lag on the newest events, not a broken channel
- Solution: re-ran the search after a short wait, and restarted the Forwarder where the lag persisted
- Noted as expected behaviour after a pause and resume

### 17/10/2026 - Splunk Enterprise Trial Expired
- Problem: every search and the whole dashboard started failing with licence violation errors
- The 60-day Enterprise Trial had expired. Switching to the Free license group didn't help, since Free has no scheduled alerting at all, and the deactivated owner on the expired trial had orphaned every saved search
- Confirmed the underlying data and config files were still intact on disk, so nothing was actually lost, just inaccessible
- Solution: reinstalled Splunk Enterprise clean, which issued a fresh 60-day trial. Rebuilt all six alerts and the dashboard from the queries already documented here, then retriggered each attack to regenerate validation data
- Resolved, and all six detections retested and fired

### 17/10/2026 - Splunk-Server Disk Space Exhaustion
- Problem: dashboard panels failed with "could not create search" on the original instance, before the license issue above
- Disk was at 74 percent used, with only 4.7GB free, under Splunk's 5GB minimum for running searches
- Cause: the virtual disk and partition were genuinely large enough (40GB, 38GB), but the LVM logical volume mounted at root was only 19GB, so half the partition's space had never been extended into the filesystem
- Solution: extended the logical volume, then resized the filesystem
- Resolved, and root now shows 38GB total, 23GB free, with no data loss and no VM shutdown needed

## Detections
Chosen to span different stages of the attack lifecycle rather than clustering on one tactic, so an intrusion is caught at more than one point. They also mix detection styles on purpose: some look at what a command says, some look at what spawned what, and one looks at whether the evidence itself was tampered with.

| Tactic | MITRE Technique | Detection | Data Source |
|--------|-----------------|-----------|-------------|
| Credential Access | T1110 | Repeated failed logons | Security (4625) |
| Execution | T1059.001 | Encoded-command PowerShell | Sysmon (EID 1) |
| Persistence | T1053.005 | Scheduled task creation | Security (4698) |
| Execution / Defense Evasion | T1059 | cmd to PowerShell process lineage | Sysmon (EID 1) |
| Lateral Movement | T1021.002 | Admin-share access over SMB | Security (5140) |
| Defense Evasion | T1070.001 | Windows Security log cleared | Security (1102) |

Each detection runs as a scheduled alert on a 5-minute cron against a 5-minute window, with a 60-minute throttle so the same events don't re-alert every run. Each alert's description carries its MITRE ATT&CK ID.

![MITRE ATT&CK Navigator coverage](screenshots/attack-navigator.png)

The interactive layer file is at screenshots/attack-navigator-layer.json, and it's importable directly into ATT&CK Navigator (mitre-attack.github.io/attack-navigator) via Open Existing Layer, Upload from local.

## Incident Reports

Each incident below follows the same pattern. Confirm the raw event in Splunk, check it against what legitimate activity would look like, decide true or false positive, then think through what a real analyst would do next.

### Incident 1: Repeated Failed Logons (T1110, Brute Force)
- Why this attack: credential brute-forcing is one of the most common initial-access patterns, and it's detectable with nothing more than default Security logging, so it was a realistic first thing for any SOC to alert on
- Detected: 20/08/2026 20:40. Seven failed network logon attempts (EventCode 4625, Logon Type 3) against the local account within a short window, past the threshold of five, from repeated SMB authentication attempts off Kali using a wrong password
- Query: index=main EventCode=4625 Account_Name=* | stats count by Account_Name | where count > 5
- Investigation: confirmed the account, source host and timing, all from the same source in a tight window, with no successful logon following
- Outcome: true positive (simulated). Live next steps: confirm lockout, investigate or block the source host, and check for a later successful logon

### Incident 2: Suspicious PowerShell, Encoded Command (T1059.001)
- Why this attack: encoded commands are a genuinely common obfuscation technique in real intrusions, used specifically to defeat keyword-matching detections. Building it forced me to detect the technique itself (the flag) rather than the content
- Detected: 10/08/2026 19:12:50. powershell.exe launched with the encoded command flag on Windows-Target
- Query: index=main CommandLine="*EncodedCommand*"
- Investigation: located the Sysmon event, manually decoded the payload to confirm it was the test command, and checked ParentImage to confirm an interactive session
- Outcome: true positive (simulated). An encoded command from an unexpected parent process would warrant immediate decoding

### Incident 3: Persistence via Scheduled Task (T1053.005)
- Why this attack: persistence turns a one-off compromise into a standing foothold. Built off the Security log task-creation event rather than a command-line match, so it fires regardless of how the task was created (schtasks, PowerShell, the GUI, or WMI)
- Detected: 17/08/2026 22:06:55. A new scheduled task set to run calc.exe on logon
- Query: index=main EventCode=4698
- Investigation: confirmed the task name, the account that created it, and the target action
- Outcome: true positive (simulated). Unexpected task creation pointing to unusual binaries would warrant immediate review

### Incident 4: Suspicious Process Spawn, cmd to PowerShell (T1059)
- Why this attack: added alongside the encoded-command detection on purpose, to cover the same general area (scripting abuse) from a different angle, process lineage rather than command content. A single detection rarely catches a whole technique family
- Detected: 20/08/2026 20:49:09. cmd.exe spawning powershell.exe, a living-off-the-land pattern
- Query: index=main EventCode=1 ParentImage="*cmd.exe*" Image="*powershell.exe*"
- Investigation: confirmed the fields matched the test, and that CommandLine was benign with no obfuscation
- Outcome: true positive (simulated), and it complements Incident 2, since it flags who spawned it rather than what it says

### Incident 5: Lateral Movement, SMB Admin Share Access (T1021.002)
- Why this attack: lateral movement turns a single compromised host into a wider breach, and admin-share access is the mechanism tools like PsExec rely on. This was also the one detection validated with genuine cross-host attacker tooling rather than a local test
- Detected: 20/08/2026 20:44:37. Access to C$ and ADMIN$ over SMB, following share enumeration from Kali via netexec using valid credentials
- Query: index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")
- Investigation: confirmed the shares accessed, the account used, and that source and destination hosts genuinely differed
- Outcome: true positive (simulated). Live priorities: is the source host expected to administer the target, is it touching shares across multiple hosts, and does share access get followed by service creation

### Incident 6: Defence Evasion, Windows Security Log Cleared (T1070.001)
- Why this attack: destroying evidence locally still generates a durable, centrally-forwarded record, which is the core argument for centralised logging. It also has a near-zero false-positive rate, so it's a small but high-value signal
- Detected: 15/09/2026 14:30:43. The Security log was cleared
- Query: index=main EventCode=1102
- Investigation: confirmed the host and account responsible, and noted that clearing the log is itself what generates the event
- Outcome: true positive (simulated), and high priority live, since it implies admin access already gained. Response: preserve the SIEM's forwarded copy, isolate the host, and reconstruct activity from the centrally-stored events

## Screenshots
Save screenshots into a screenshots folder, filenames below.

### 1. Working network configuration
ip a output.
![Working ip a output](screenshots/01-ip-config.png)

### 2. VirtualBox Host-Only Network settings
Adapter and DHCP tabs.
![VirtualBox Adapter settings](screenshots/02a-vbox-adapter.png)
![VirtualBox DHCP Server settings](screenshots/02b-vbox-dhcp.png)

### 3. SSH connection into the VM
![SSH login to Splunk server](screenshots/03-ssh-login.png)

### 4. Splunk package installation confirmed
![Splunk install complete](screenshots/04-splunk-install.png)

### 5. Splunk service running
![Splunk status running](screenshots/05-splunk-status.png)

### 6. Splunk web home page
![Splunk web home page](screenshots/06-splunk-web-home.png)

### 7. Splunk receiving port configured
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
![Splunk index search showing ingested logs](screenshots/13-log-ingestion.png)

### 14. Kali-Attacker VM confirmed
![Kali-Attacker VM Confirmed](screenshots/14-kali-confirmed.png)

### 15. Full lab connectivity confirmed
![Full lab connectivity confirmed](screenshots/15-connectivity-confirmed.png)

### 16. Saved detection alerts (configuration)
One screenshot per detection, full edit view.

16a. Repeated Failed Logons, T1110
![Detection alert, failed logons](screenshots/16a-alert-failed-logons.png)

16b. Suspicious PowerShell, T1059.001
![Detection alert, encoded PowerShell](screenshots/16b-alert-powershell.png)

16c. Persistence via Scheduled Task, T1053.005
![Detection alert, scheduled task persistence](screenshots/16c-alert-persistence.png)

16d. Suspicious Process Spawn, T1059
![Detection alert, suspicious process spawn](screenshots/16d-alert-process-spawn.png)

16e. Lateral Movement, T1021.002
![Detection alert, lateral movement](screenshots/16e-alert-lateral-movement.png)

16f. Windows Security Log Cleared, T1070.001
![Detection alert, Security log cleared](screenshots/16f-alert-logcleared.png)

16g. Fired-event history
![Triggered alerts history](screenshots/16g-triggered-alerts.png)

### 17. Detection validation (attack then detection)
One pair per technique.

17a. Repeated Failed Logons, T1110
![Attack, failed logons](screenshots/17a-attack-failed-logons.png)
![Detection, failed logons](screenshots/17a-detection-failed-logons.png)

17b. Suspicious PowerShell, T1059.001
![Attack, encoded PowerShell](screenshots/17b-attack-powershell.png)
![Detection, encoded PowerShell](screenshots/17b-detection-powershell.png)

17c. Persistence via Scheduled Task, T1053.005
![Attack, persistence](screenshots/17c-attack-persistence.png)
![Detection, persistence](screenshots/17c-detection-persistence.png)

17d. Suspicious Process Spawn, T1059
![Attack, process spawn](screenshots/17d-attack-process-spawn.png)
![Detection, process spawn](screenshots/17d-detection-process-spawn.png)

17e. Lateral Movement, T1021.002
![Attack, lateral movement](screenshots/17e-attack-lateral-movement.png)
![Detection, lateral movement](screenshots/17e-detection-lateral-movement.png)

17f. Security Log Cleared, T1070.001
![Attack, log cleared](screenshots/17f-attack-logcleared.png)
![Detection, log cleared](screenshots/17f-detection-logcleared.png)

### 18. SOC detection overview dashboard
Three panels.
![Dashboard, alert firing counts by detection](screenshots/18a-dashboard-alert-counts.png)
![Dashboard, recent triggered alerts table](screenshots/18b-dashboard-triggered-table.png)
![Dashboard, failed logons by logon type](screenshots/18c-dashboard-logon-types.png)

## What I'd Add With More Time
All six incidents here are confirmed true positives, since they were deliberately triggered test attacks. A real next step would be tuning each detection against genuine background activity on the box, to see what a false positive actually looks like for it and adjust the thresholds accordingly.
- A second Windows target, to show the full lateral movement chain (remote service creation followed by PsExec-style execution) instead of just share access
- An NTP setup for the lab network, to stop the clock drift that caused confusing false negatives
- A honeypot feeding into the same Splunk instance, for genuine unsolicited attack traffic instead of only self-triggered tests
- A post-install script to reapply the recurring ownership fix automatically
- Broader detection coverage: credential dumping (T1003), defense evasion (T1562), exfiltration, mapped against a wider Navigator layer
- Some SOAR-style automation, so alerts trigger a response rather than only landing in a list for manual review

## Tools Used
- VirtualBox, host-only networking
- Ubuntu Server 26.04 LTS, Splunk host
- Splunk Enterprise 10.4.1
- Splunk Universal Forwarder
- Sysmon (SwiftOnSecurity config)
- SSH
- Windows 10 (Windows-Target VM)
- Kali Linux (attacker VM)
- netexec, SMB attack simulation
- Manual attack simulation on Windows-Target
- MITRE ATT&CK Navigator

## Resources Used
- MITRE ATT&CK Framework, attack.mitre.org
- Sysmon configuration, SwiftOnSecurity, github.com/SwiftOnSecurity/sysmon-config
- netexec, github.com/Pennyw0rth/NetExec
- Splunk Enterprise and Universal Forwarder documentation, docs.splunk.com
- MITRE ATT&CK Navigator, mitre-attack.github.io/attack-navigator
