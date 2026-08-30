#### \# SIEM-Based Detection \& Incident Response Lab



##### \## Overview

A Splunk SIEM lab built from scratch on isolated VirtualBox virtual machines, ingesting Windows Event Logs and Sysmon telemetry, with detection rules mapped to MITRE ATT\&CK and validated against simulated attacks.

Author: Ashton Roberts

Built: 29/07/2026 – 22/08/2026



##### \## Architecture



Three virtual machines on a single isolated VirtualBox host-only network

(`192.168.116.0/24`, `VirtualBox Host-Only Ethernet Adapter #2`). No internet

access — the network is deliberately air-gapped so simulated attack traffic

stays contained. Logs flow one direction: Windows-Target ships Security and

Sysmon events to the Splunk indexer over TCP 9997; Kali generates attack

traffic against Windows-Target over SMB (445) and other protocols.



![SIEM lab network architecture](screenshots/architecture-diagram.png)





| VM | Role | Address |
|----|------|------------|
| Splunk-Server | SIEM / indexer | 192.168.116.3 |
| Windows-Target | Monitored endpoint (Sysmon + Universal Forwarder) | 192.168.116.5 |
| Kali-Attacker | Attack simulation | 192.168.116.6 |



##### \## Build Log



###### \### 29/07/2026 — Splunk Server Networking



\- Created Ubuntu Server VM (came up as 26.04 LTS), host-only network for isolation.

\- \*\*Issue:\*\* Network adapter wasn't enabled in VM settings, so no IP address was assigned.

&#x20; \*\*Fix:\*\* Ticked "Enable Network Adapter" in VirtualBox Settings > Network.

\- \*\*Issue:\*\* After enabling the adapter, still no IP address appeared via `ip a`. Diagnosed using `networkctl status`, which showed the interface stuck in "degraded (configuring)" — actively requesting an address but never receiving one back.

&#x20; \*\*Fix:\*\* VirtualBox's host-only network had gotten into a broken state (DHCP server enabled but not actually responding). Removed the broken network via File > Host Network Manager, created a fresh one (came up as `VirtualBox Host-Only Ethernet Adapter #2` on the `192.168.116.x` range), reattached the VM's network adapter setting to the new network, then rebooted — resolved the issue.

\- Confirmed working IP via `ip a`: `192.168.116.3`.

\- Switched from working directly in the VirtualBox console window to connecting via SSH (`ssh analyst@192.168.116.3`) from the host machine, since the console window doesn't support clipboard paste — makes copying commands/links across far more reliable.



###### \### 29/07/2026 — Splunk Installation



\- Downloaded Splunk Enterprise `.deb` package via `wget`, installed with `sudo dpkg -i splunk\*.deb`. Install completed, admin account (`analyst`) created during first-run prompts.

\- \*\*Issue:\*\* `sudo /opt/splunk/bin/splunk start` returned to the prompt almost instantly with only a root-deprecation warning shown — no actual startup messages, and `splunk status` continued to report `splunkd is not running`.

\- \*\*Investigation:\*\* Ruled out disk space (`df -h` showed 7.8G free). Ran `splunkd` directly to try to surface a clearer error, which showed a missing shared library (`libmongoc-1.0.so.0`) — but confirmed via `find` that the file did actually exist, so this was a red herring caused by bypassing Splunk's normal startup wrapper, not the real fault.

\- Checked for a stale PID file that might be blocking startup — none found.

\- Fixed file ownership with `sudo chown -R splunk:splunk /opt/splunk` in case running install steps via `sudo` had left ownership inconsistent — start command still failed the same way afterward.

\- \*\*Further investigation:\*\* Ran `/opt/splunk/bin/splunk version` directly to isolate the problem — this succeeded and confirmed the binaries and shared libraries were intact, ruling out a broken install. However, it surfaced permission warnings: `cannot create "/opt/splunk/var/log/splunk"` (and several sibling log directories), pointing to a permissions/ownership issue rather than a missing-file issue.

\- \*\*Root cause:\*\* The Splunk installation is owned by the `splunk` user/group (created automatically by the installer), but startup was being attempted as the `analyst` user via plain `sudo`, which doesn't correctly assume the `splunk` user's file permissions for directory creation.

\- \*\*Fix:\*\*

&#x20; 1. Confirmed ownership with `ls -ld /opt/splunk/var/log/splunk` and related directories.

&#x20; 2. Reapplied correct ownership recursively: `sudo chown -R splunk:splunk /opt/splunk` and `sudo chmod -R u+rwX /opt/splunk`.

&#x20; 3. Started Splunk explicitly as the `splunk` user rather than root: `sudo -u splunk /opt/splunk/bin/splunk start --accept-license`.

\- \*\*Status:\*\* Resolved. `splunk status` confirmed `splunkd is running`, and the Splunk web dashboard loaded successfully at `192.168.116.3:8000`, logged in with the `analyst` admin account created earlier.



###### \### 05/08/2026 — Splunk Recurring Permissions Issue



\- \*\*Issue:\*\* After a period of inactivity, the Splunk web interface stopped loading. The Splunk-Server VM itself was confirmed running, but `ps aux | grep splunkd` showed no Splunk process at all — the service had stopped.

\- \*\*Investigation:\*\* Attempted to restart with `sudo -u splunk /opt/splunk/bin/splunk start --accept-license`. This triggered Splunk's upgrade/migration routine again, which failed partway through with `PermissionError: \[Errno 13] Permission denied: '/opt/splunk/etc/system/local/eventtypes.conf'`.

\- \*\*Root cause:\*\* Same underlying issue as the original permissions fix — an intervening `sudo dpkg -i` reinstall (run accidentally earlier in the project) had reset file ownership on parts of `/opt/splunk` back to `root`, breaking the `splunk` user's ability to write to its own config files during startup migration.

\- \*\*Fix:\*\* Reapplied `sudo chown -R splunk:splunk /opt/splunk`, then reran `sudo -u splunk /opt/splunk/bin/splunk start --accept-license`. Migration completed successfully this time, confirmed running via `ps aux | grep splunkd`.

\- \*\*Status:\*\* Resolved. Noted as a recurring pattern — any future `dpkg -i` reinstall of the Splunk package will require reapplying the `chown` fix afterward before Splunk will start cleanly.



###### \### 05/08/2026 — Windows-Target VM and Log Ingestion



\- Built Windows-Target VM (Windows 10, host-only network matching the Splunk server). Recreated the VM once after hitting a `<ProductKey>` error caused by VirtualBox's automated "Unattended Installation" feature — resolved by ticking "Skip Unattended Installation" during VM creation.

\- Installed Sysmon using the SwiftOnSecurity recommended config. VM froze briefly during the install command — resolved with Machine > Reset; confirmed afterward via `sc query sysmon64` and Event Viewer (Applications and Services Logs > Microsoft > Windows > Sysmon > Operational) that the install had actually completed successfully despite the freeze.

\- Installed the Splunk Universal Forwarder, pointed at the Splunk-Server's receiving indexer (`192.168.116.3:9997`). Configured `inputs.conf` under `SplunkUniversalForwarder\\etc\\system\\local` to forward Security, System, and Sysmon Operational logs — created via `notepad inputs.conf` from Command Prompt to avoid a hidden `.txt` extension being appended.

\- Opened the receiving port on the Splunk server (Settings > Forwarding and receiving > Configure receiving > New Receiving Port > 9997).

\- \*\*Checkpoint passed:\*\* Ran `index=main` in Splunk Search — confirmed 942 events ingested live from the Windows-Target machine (Security and Sysmon events, `ComputerName=DESKTOP-0DO6S21`), proving the full pipeline (Windows → Sysmon → Forwarder → Splunk) is working end to end.

\- \*\*Issue:\*\* Windows-Target's network adapter was found set to NAT rather than Host-only, shown by `ipconfig` returning `10.0.2.15` (VirtualBox's default NAT range) instead of an address on the lab network.

&#x20; \*\*Fix:\*\* Switched Adapter 1 to Host-only in VM Settings > Network. Initial attempt selected the wrong host-only network (`vboxnet0`, giving a `192.168.56.x` address — a separate, unrelated network from the Splunk server). Corrected to the actual network in use (`VirtualBox Host-Only Ethernet Adapter #2`), confirmed via `ipconfig`: `192.168.116.5` — correctly on the same network as the Splunk server (`192.168.116.3`).



###### \### 10/08/2026 — Kali-Attacker VM Build



\- Downloaded Kali Linux VirtualBox image; extracted from `.7z` using 7-Zip.

\- \*\*Issue:\*\* Expected a single `.ova` appliance file per the build guide, but the extracted archive instead contained `.vbox` and `.vdi` files — a VirtualBox machine folder format rather than an OVA appliance.

&#x20; \*\*Fix:\*\* Used \*\*Machine > Add\*\* in VirtualBox to register the existing `.vbox` file directly, rather than \*\*File > Import Appliance\*\* (which expects an `.ova`/`.ovf`).

\- Set Adapter 1 to Host-only, matching the same network as the other two VMs (`VirtualBox Host-Only Ethernet Adapter #2`).

\- Started the VM, logged in with default Kali credentials.

\- \*\*Checkpoint passed:\*\* Confirmed IP via `ip a`: `192.168.116.6`, correctly on the same lab network as Splunk-Server and Windows-Target.

\- Confirmed connectivity from Kali: successful `ping` to Splunk-Server (`192.168.116.3`) with clean round-trip times. Windows-Target (`192.168.116.5`) did not respond to ping — expected behaviour, since Windows Firewall blocks ICMP by default; does not affect Splunk log forwarding (which uses TCP port 9997, unrelated to ICMP).



###### \### 10/08/2026 — Sysmon Logs Not Reaching Splunk (Access Denied)



\- \*\*Issue:\*\* Sysmon-based detections (starting with T1059.001, encoded PowerShell) showed no results in Splunk, despite Windows Security logs continuing to flow normally. `index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` returned 0 events even over a full 24-hour range.

\- \*\*Investigation:\*\*

&#x20; 1. Confirmed `inputs.conf` on the Forwarder correctly included the Sysmon stanza (`\[WinEventLog://Microsoft-Windows-Sysmon/Operational]`, `disabled = false`).

&#x20; 2. Confirmed Sysmon service itself was running (`sc query sysmon64` → `RUNNING`).

&#x20; 3. Confirmed the Forwarder service was running (`sc query SplunkForwarder` → `RUNNING`) and correctly configured (`outputs.conf` pointing at `192.168.116.3:9997`).

&#x20; 4. Checked the Forwarder's own log (`splunkd.log`) and found repeated errors: `WinEventLogChannel::init: Init failed, unable to subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5` — Access Denied.

\- \*\*Root cause:\*\* The Forwarder service runs under a dedicated virtual service account (`NT SERVICE\\SplunkForwarder`), not LocalSystem or a standard admin account. This account's SID was not present in the Sysmon channel's access control list, which by default only trusts SYSTEM, Administrators, Backup/Server Operators, and Event Log Readers — none of which cover a virtual service account.

\- \*\*Fix:\*\*

&#x20; 1. Retrieved the exact service SID: `sc showsid SplunkForwarder`.

&#x20; 2. Retrieved the channel's existing ACL: `wevtutil gl Microsoft-Windows-Sysmon/Operational`.

&#x20; 3. Reapplied the ACL with the Forwarder's SID appended, preserving all existing entries: `wevtutil sl Microsoft-Windows-Sysmon/Operational /ca:...`.

&#x20; 4. Restarted the Forwarder service — errors persisted initially.

&#x20; 5. Fully rebooted the Windows-Target VM, since Windows caches Event Log channel security state and doesn't always apply ACL changes to a live session.

\- \*\*Status:\*\* Resolved. Post-reboot, `index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` returned 1,735 events. Confirmed the specific PowerShell detection query (`index=main CommandLine="\*EncodedCommand\*"`) returned 3 matching events, validating the second detection end to end.



###### \### 13/08/2026 — VM Clock Drift Breaking Detection Testing



\- \*\*Issue:\*\* Scheduled task persistence detection (T1053.005) showed no results in Splunk despite the trigger command running successfully and confirming log ingestion was healthy generally.

\- \*\*Investigation:\*\* Checked current time on both VMs against real-world time — both Windows-Target and Splunk-Server had drifted significantly from the actual current date/time. Since neither VM has internet access on the isolated lab network, neither could sync via NTP.

\- \*\*Root cause:\*\* Events were being logged with incorrect (drifted) timestamps, placing them outside the default search time ranges being used (`Last 24 hours`, `earliest=-10m`), even though the events themselves existed and the pipeline was functioning correctly.

\- \*\*Fix:\*\* Manually corrected the clock on both VMs:

&#x20; - Windows-Target: Settings > Time \& Language > Date \& time, set manually.

&#x20; - Splunk-Server: `sudo timedatectl set-ntp false` followed by `sudo date -s "<correct date/time>"`.

\- \*\*Status:\*\* Resolved. Noted as a known limitation of the isolated lab network (no NTP access) — clocks will need manual resyncing periodically, particularly after VMs are paused/resumed across sessions.



###### \### 13/08/2026 — Enabling Object Access Auditing for Share Detection



\- \*\*Issue:\*\* The lateral movement detection (T1021.002) relies on Security Event ID 5140 (network share accessed), but this event is not logged by default on Windows 10 — the "Object Access > File Share" audit subcategory is disabled out of the box.

\- \*\*Fix:\*\* Enabled the relevant subcategories on Windows-Target from an admin Command Prompt:

&#x20; - `auditpol /set /subcategory:"File Share" /success:enable /failure:enable`

&#x20; - `auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable`

&#x20; - `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable` (required for EventCode 4698, scheduled task creation, used by the persistence detection)

\- Verified with `auditpol /get /category:"Object Access"`. No reboot required.

\- \*\*Status:\*\* Resolved. Subsequent SMB share access from Kali generated EventCode 5140, and scheduled task creation generated EventCode 4698, enabling genuine detection of admin-share access and task persistence rather than only inferring them from process command lines or failed authentication.



###### \### 20/08/2026 — Failed-Logon Alert Not Firing (trigger logic and action)



\- \*\*Issue:\*\* The Repeated Failed Logons alert never appeared in Triggered Alerts even though its underlying search returned the offending account correctly.

\- \*\*Investigation:\*\* Checked the alert's own execution history via `index=\_internal sourcetype=scheduler savedsearch\_name="Repeated Failed Logons"`. The scheduler log showed `result\_count` populated but `alert\_actions=""` — the alert was running and matching, but had no action attached to fire.

\- \*\*Root causes (two, found in sequence):\*\*

&#x20; 1. \*\*Trigger threshold mismatch.\*\* The search ends in `| stats count by Account\_Name | where count > 5`, so it returns a single summary row per offending account. The alert's trigger was set to "Number of Results is greater than 5", which a single-row result can never satisfy. Corrected to "greater than 0" — the `where count > 5` clause already enforces the real threshold inside the search.

&#x20; 2. \*\*Lost trigger action.\*\* After repeated edits the "Add to Triggered Alerts" action had silently dropped from the saved object (`alert\_actions=""`), and re-adding it via Edit would not persist. Resolved by deleting and recreating the alert cleanly in one pass, with the action attached at creation.

\- \*\*Also observed:\*\* repeated failed-logon simulations tripped the Windows account lockout policy (`STATUS\_ACCOUNT\_LOCKED\_OUT`), which itself is a legitimate secondary detection signal. Reduced the attack loop to just over the alert threshold to avoid re-locking the account between tests.

\- \*\*Status:\*\* Resolved. Rebuilt alert fires reliably; noted that `stats`-based alerts need a "greater than 0" trigger, not a raw-event-count threshold.



###### \### 22/08/2026 — Forwarding Lag After VM Resume



\- \*\*Issue:\*\* After resuming the VMs, some detection searches briefly returned no results even though the pipeline was healthy — e.g. a freshly created scheduled task showed EventCode 4698 in Windows Event Viewer but not yet in Splunk.

\- \*\*Investigation:\*\* Confirmed the event existed on the Windows side (Event Viewer > Security > filter 4698) and that the Security channel was otherwise flowing (`index=main source="WinEventLog:Security"` returned recent events). This isolated the gap to normal forwarding/indexing lag on the most recent events rather than a broken channel.

\- \*\*Fix:\*\* Re-ran the detection search after a short delay / widened the time range; the event appeared once forwarded. Where lag persisted, restarting the Universal Forwarder flushed the queue.

\- \*\*Status:\*\* Resolved. Noted as expected behaviour after pause/resume — allow a minute or two for the newest events to forward before assuming a detection has failed.





##### \## Detections Built



| Detection | MITRE ATT&CK ID | Data Source | Splunk Query |
|-----------|-----------------|-------------|--------------|
| Repeated failed logons | T1110 | Security (4625) | `index=main EventCode=4625 Account_Name=* \| stats count by Account_Name \| where count > 5` |
| Suspicious PowerShell (encoded command) | T1059.001 | Sysmon (EID 1) | `index=main CommandLine="*EncodedCommand*"` |
| Persistence via scheduled task | T1053.005 | Security (4698) | `index=main EventCode=4698` |
| Suspicious process spawn (cmd → PowerShell) | T1059 | Sysmon (EID 1) | `index=main EventCode=1 ParentImage="*cmd.exe*" Image="*powershell.exe*"` |
| Lateral movement (SMB admin share access) | T1021.002 | Security (5140) | `index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")` |



Each detection is saved as a scheduled alert running on a 5-minute cron (`\*/5 \* \* \* \*`) against a `-5m@m` to `@m` window, with a 60-minute throttle to prevent the same events re-alerting on every run. Each alert's Description field carries its MITRE ATT\&CK ID and a one-line purpose so the alert is self-documenting in the Splunk UI.



##### \## Incident Reports



###### \### Incident 1: Repeated Failed Logons

\- \*\*Date/time detected:\*\* 20/08/2026 20:40

\- \*\*MITRE ATT\&CK technique:\*\* T1110 - Brute Force

\- \*\*What triggered the alert:\*\* Six failed network logon attempts (EventCode=4625, Logon Type 3) recorded against the local `Ashton` account on Windows-Target within a short window, exceeding the configured threshold of five. The failures were generated by repeated SMB authentication attempts from the Kali-Attacker host (`192.168.116.6`) using an incorrect password (`STATUS\_LOGON\_FAILURE`).

\- \*\*Splunk query used:\*\* `index=main EventCode=4625 Account\_Name=\* | stats count by Account\_Name | where count > 5`

\- \*\*Investigation steps taken:\*\* Reviewed the raw EventCode=4625 events in Splunk to confirm the target account, source host, and timing of each failed attempt. All attempts originated from the same source within a short clustered window, consistent with an automated password-guessing attempt rather than a user mistyping. No evidence of a successful logon (EventCode=4624) following the failed attempts.

\- \*\*Verdict:\*\* True positive (simulated). Behaviour matches the expected signature of a brute-force/password-guessing attempt. In a live environment, next steps would include confirming whether the account was locked out per policy, blocking or investigating the source host, and correlating with any subsequent successful logon on the same account that could indicate the brute force eventually succeeded.



###### \### Incident 2: Suspicious PowerShell - Encoded Command



\- \*\*Date/time detected:\*\* 10/08/2026 19:12:50.427

\- \*\*MITRE ATT\&CK technique:\*\* T1059.001 - Command and Scripting Interpreter: PowerShell

\- \*\*What triggered the alert:\*\* A `powershell.exe` process was launched on Windows-Target using the `-EncodedCommand` flag, a technique commonly used to obscure the true content of a PowerShell command from casual inspection or basic string-based detection.

\- \*\*Splunk query used:\*\* `index=main CommandLine="\*EncodedCommand\*"`

\- \*\*Investigation steps taken:\*\* Located the Sysmon EventCode=1 (process creation) event showing `powershell.exe` invoked with the `-EncodedCommand` argument. Decoded the base64 payload manually to confirm its actual content (`Write-Host (true)`), verifying it was the deliberate test command rather than genuine malicious activity. Checked ParentImage to confirm the process was launched directly from an interactive PowerShell session rather than a suspicious parent process (e.g. an Office application or script host).

\- \*\*Verdict:\*\* True positive (simulated). The alert correctly identified the use of an encoding technique associated with obfuscated/malicious PowerShell usage. In a live environment, any encoded command from an unexpected parent process or unusual user context would warrant immediate decoding and investigation of the payload before determining intent.



###### \### Incident 3: Persistence via Scheduled Task



\- \*\*Date/time detected:\*\* 17/08/2026 22:06:55.749

\- \*\*MITRE ATT\&CK technique:\*\* T1053.005 - Scheduled Task/Job: Scheduled Task

\- \*\*What triggered the alert:\*\* A new scheduled task (`\\EvilPersistence`) was created on Windows-Target, recorded as Security EventCode=4698 ("a scheduled task was created"). The task was set to run `calc.exe` on user logon — a common technique used by attackers to establish persistence by ensuring a payload re-executes automatically at a defined time or trigger.

\- \*\*Splunk query used:\*\* `index=main EventCode=4698`

\- \*\*Investigation steps taken:\*\* Reviewed the EventCode=4698 event, confirming the task name (`\\EvilPersistence`), the account that created it (`Ashton`), and the target action from the task definition. Detection uses the Security-log task-creation event rather than a Sysmon command-line string match, so it fires on task creation regardless of the method used (`schtasks.exe`, PowerShell `Register-ScheduledTask`, the Task Scheduler GUI, or WMI) — a more robust signature that an attacker cannot evade simply by avoiding `schtasks.exe`.

\- \*\*Verdict:\*\* True positive (simulated). Scheduled task creation is a well-documented persistence technique; in a live environment, any unexpected or unauthorised task creation — particularly ones pointing to unusual binaries, script interpreters, or living-off-the-land tools — would warrant immediate review of the task's target and the account that created it.



###### \### Incident 4: Suspicious Process Spawn (cmd → PowerShell)



\- \*\*Date/time detected:\*\* 20/08/2026 20:49:09.311

\- \*\*MITRE ATT\&CK technique:\*\* T1059 - Command and Scripting Interpreter

\- \*\*What triggered the alert:\*\* `cmd.exe` spawned `powershell.exe` as a child process on Windows-Target, producing a parent-child process relationship associated with living-off-the-land execution, where an attacker uses a trusted command interpreter to launch PowerShell for follow-on activity.

\- \*\*Splunk query used:\*\* `index=main EventCode=1 ParentImage="\*cmd.exe\*" Image="\*powershell.exe\*"`

\- \*\*Investigation steps taken:\*\* Reviewed the Sysmon process creation event, confirming the ParentImage (`cmd.exe`) and Image (`powershell.exe`) fields matched the simulated test exactly. Verified the CommandLine field showed a benign, directly-typed invocation (`Write-Host test`) with no obfuscation, script wrapping, or unusual working directory — consistent with a deliberate, low-risk test rather than genuine malicious chaining.

\- \*\*Verdict:\*\* True positive (simulated). This detection complements the encoded-command detection (Incident 2): rather than looking at the \*contents\* of a PowerShell command, it flags the \*lineage\* — PowerShell being spawned by `cmd.exe` — which catches suspicious chaining regardless of whether the command itself is obfuscated. In a live environment this pairing is a genuine early indicator; the same logic extends to higher-risk children such as `rundll32.exe` or a script host launched from an unexpected parent like a document viewer or browser.



###### \### Incident 5: Lateral Movement - SMB Admin Share Access



\- \*\*Date/time detected:\*\* 20/08/2026 20:44:37.303

\- \*\*MITRE ATT\&CK technique:\*\* T1021.002 - Remote Services: SMB/Windows Admin Shares

\- \*\*What triggered the alert:\*\* Access to the hidden administrative shares (`C$` and `ADMIN$`) over SMB was recorded on Windows-Target (EventCode=5140, network share accessed), following SMB share enumeration launched from the Kali-Attacker host (`192.168.116.6`) using valid credentials via `netexec`. Access to these hidden admin shares is the same underlying mechanism tools like PsExec use to enable remote execution over SMB, making it a strong indicator of lateral movement.

\- \*\*Splunk query used:\*\* `index=main EventCode=5140 (Share\_Name="\*ADMIN$\*" OR Share\_Name="\*C$\*")`

\- \*\*Investigation steps taken:\*\* Reviewed the EventCode=5140 events to confirm the share names accessed (`\\\\\*\\C$`, `\\\\\*\\ADMIN$`), the account used, and the source and destination hosts. The source and destination hosts differed (Kali → Windows-Target), confirming this was genuine cross-host access over the lab network rather than local loopback activity.

\- \*\*Verdict:\*\* True positive (simulated). The detection correctly identified access to administrative shares — a pattern of genuine interest to a SOC analyst, since access to `C$`/`ADMIN$` from an unexpected host is a common indicator of lateral movement or remote-execution staging. In a live multi-host environment, priority indicators to correlate would be: whether the source host is expected to be administering the target at all, whether the same source is touching admin shares across multiple hosts (suggesting spread), and whether share access is immediately followed by service creation (EventCode 7045) or remote process execution — which together would indicate a PsExec-style remote execution rather than reconnaissance alone.



\---

##### \## Screenshots



###### \### 1. Working network configuration

`ip a` output showing the interface with a valid IP address assigned.

![Working ip a output](screenshots/01-ip-config.png)



###### \### 2. VirtualBox Host-Only Network settings

Both the Adapter tab and DHCP Server tab, showing the working configuration.

![VirtualBox Adapter settings](screenshots/02a-vbox-adapter.png)

![VirtualBox DHCP Server settings](screenshots/02b-vbox-dhcp.png)



###### \### 3. SSH connection into the VM

Successful SSH login from the Windows host terminal.

![SSH login to Splunk server](screenshots/03-ssh-login.png)



###### \### 4. Splunk package installation complete 

`dpkg -l | grep splunk` output showing the install finishing successfully.

![Splunk install complete](screenshots/04-splunk-install.png)



###### \### 5. Splunk service running 

`ps aux | grep splunkd` confirming the splunkd process is running.

![Splunk status running](screenshots/05-splunk-status.png)



###### \### 6. Splunk web home page

Browser showing the Splunk home screen at `192.168.116.3:8000`.

![Splunk web home page](screenshots/06-splunk-web-home.png)



###### \### 7. Splunk receiving port configured

Settings > Forwarding and receiving > Configure receiving, showing port 9997 added.

![Splunk receiving port configured](screenshots/07-splunk-port-configured.png)



###### \### 8. Windows-Target network configuration

VM Settings > Network tab showing Host-only Adapter attached to the same network as the Splunk server.

![Windows-Target network configuration](screenshots/08-windows-network-configuration.png)



###### \### 9. Windows-Target desktop confirmed

Working Windows 10 desktop inside the VM after install completes.

![Windows-Target desktop confirmed](screenshots/09-windows-desktop-confirmed.png)



###### \### 10. Windows-Target IP address

`ipconfig` output in Command Prompt showing the assigned IP address.

![Windows-Target IP address](screenshots/10-windows-IP-address.png)



###### \### 11. Sysmon installation confirmed

Command Prompt output showing "Sysmon installed" and "Sysmon started" after running the install command.

![Sysmon installation confirmed](screenshots/11-Sysmon-installation-confirmed.png)



###### \### 12. Sysmon logging confirmed

Windows Event Viewer showing Sysmon Operational log with events present.

![Sysmon events in Event Viewer](screenshots/12-sysmon-events.png)



###### \### 13. First successful log ingestion

`index=main` search in Splunk showing live data flowing in from the Windows target. This is the key "it's working end-to-end" screenshot.

![Splunk index search showing ingested logs](screenshots/13-log-ingestion.png)



###### \### 14. Kali-Attacker VM confirmed

Kali desktop loaded with `ip a` output showing it's on the same lab network.

![Kali-Attacker VM Confirmed](screenshots/14-kali-confirmed.png)



###### \### 15. Full lab connectivity confirmed

Ping results from Kali to both the Splunk server and Windows-Target, confirming all three VMs can reach each other.

![Full lab connectivity confirmed](screenshots/15-connectivity-confirmed.png)



###### \### 16. Saved detection alerts (configuration)

One screenshot per detection (5 total) showing the saved alert in Splunk in edit view, so the full configuration is visible — search logic (SPL), alert type, cron schedule, time range, trigger condition, throttle, and trigger action. Each alert's Description field carries its MITRE ATT\&CK ID.



![Detection alert - failed logons](screenshots/16a-alert-failed-logons.png)

![Detection alert - encoded PowerShell](screenshots/16b-alert-powershell.png)

![Detection alert - scheduled task persistence](screenshots/16c-alert-persistence.png)

![Detection alert - suspicious process spawn](screenshots/16d-alert-process-spawn.png)

![Detection alert - lateral movement](screenshots/16e-alert-lateral-movement.png)



Each detection runs on a 5-minute cron (`\*/5 \* \* \* \*`) against a `-5m@m` to `@m` window, with a 60-minute throttle (suppression) to prevent the same events re-alerting on every run.



\*\*16f. Fired-event history\*\*

Activity > Triggered Alerts, showing recorded firings across the five detections — evidence that the alerts have actually triggered on live events, not just that they exist.

![Triggered alerts history](screenshots/16f-triggered-alerts.png)



###### \### 17. Detection validation (attack → detection) 

Each detection is validated end-to-end: an attacker action is executed, then the matching events are shown in Splunk. This demonstrates the full chain — attacker behaviour, raw telemetry, detection firing — rather than alert configuration alone.



Attack traffic was generated from the Kali host (`192.168.116.6`) for network-based techniques and locally on the Windows target (`192.168.116.5`) for host-based techniques. `netexec` (`nxc`) is used for SMB attacks, having replaced the now-deprecated `crackmapexec` in current Kali releases. Ordering matches Section 16 (a–e).



\*\*17a. Repeated Failed Logons\*\* — `T1110` Brute Force

Seven failed SMB authentications against the `Ashton` account (`STATUS\_LOGON\_FAILURE`), generating EventCode 4625.

![Attack - failed logons](screenshots/17a-attack-failed-logons.png)

![Detection - failed logons](screenshots/17a-detection-failed-logons.png)



\*\*17b. Suspicious PowerShell - Encoded Command\*\* — `T1059.001` PowerShell

Execution of a base64 `-EncodedCommand`, the pattern flagged regardless of payload.

![Attack - encoded PowerShell](screenshots/17b-attack-powershell.png)

![Detection - encoded PowerShell](screenshots/17b-detection-powershell.png)



\*\*17c. Persistence via Scheduled Task\*\* — `T1053.005` Scheduled Task

Creation of a scheduled task (`schtasks /create`).

![Attack - persistence](screenshots/17c-attack-persistence.png)

![Detection - persistence](screenshots/17c-detection-persistence.png)



\*\*17d. Suspicious Process Spawn\*\* — `T1059` Command and Scripting Interpreter

A `cmd.exe → powershell.exe` parent-child process chain captured via Sysmon Event ID 1.

![Attack - process spawn](screenshots/17d-attack-process-spawn.png)

![Detection - process spawn](screenshots/17d-detection-process-spawn.png)



\*\*17e. Lateral Movement - SMB Admin Share Access\*\* — `T1021.002` SMB/Windows Admin Shares

Access to administrative shares (`C$`, `ADMIN$`) over SMB from Kali, generating EventCode 5140.

![Attack - lateral movement](screenshots/17e-attack-lateral-movement.png)

![Detection - lateral movement](screenshots/17e-detection-lateral-movement.png)



###### \### 18. SOC detection overview dashboard

Splunk "SOC Detection Overview" dashboard summarising activity across all five detections.



![Dashboard - alert firing counts by detection](screenshots/18a-dashboard-alert-counts.png)

![Dashboard - recent triggered alerts table](screenshots/18b-dashboard-triggered-table.png)

![Dashboard - failed logons by logon type](screenshots/18c-dashboard-logon-types.png)



Firing counts are drawn from `index=\_internal sourcetype=scheduler`, filtered to the five detections and to runs returning results (`result\_count>0`), so counts reflect genuine detection firings rather than every scheduled run.



\---

##### \## What I'd Add With More Time



\- \*\*Second Windows target machine\*\* — my lateral movement detection (T1021.002) is currently validated by admin-share access from Kali to a single Windows host. With a second Windows target, I could demonstrate the full lateral-movement chain between two domain-joined endpoints — remote service creation (EventCode 7045) and PsExec-style remote execution following the share access — which is what this technique looks like end to end in a real environment.



\- \*\*NTP server for the lab network\*\* — since the lab network is fully isolated with no internet access, VM clocks drift over time and can't sync automatically. I hit this directly when a detection appeared to fail simply because Windows-Target and Splunk-Server had drifted out of sync. A small local NTP server (or scripted manual sync on VM startup) would remove this as a recurring source of confusing false negatives.



\- \*\*Honeypot integration\*\* — feeding a Cowrie or T-Pot honeypot into the same Splunk instance would generate genuine unsolicited attack traffic, rather than only simulated/self-triggered detections, giving a much richer and more realistic dataset to build detections against.



\- \*\*Automate the recurring permissions fix\*\* — the Splunk ownership issue (`chown -R splunk:splunk /opt/splunk`) recurred every time the package was reinstalled. A small startup/post-install script to reapply this automatically would remove a known, repeatable point of failure.



\- \*\*Broaden detection coverage\*\* — the five detections map to five separate MITRE ATT\&CK techniques, but a real SOC environment would also want coverage of credential dumping (T1003), defense evasion (T1562), and exfiltration techniques — worth expanding the ruleset with a wider MITRE ATT\&CK Navigator-style coverage map.



\- \*\*SOAR-style automation\*\* — currently every alert lands in Splunk's Triggered Alerts list for manual review. Adding a lightweight automated response (e.g. auto-isolating a host, or triggering a follow-up enrichment search) would move the project from pure detection into basic incident response automation.



\---

##### \## Tools Used

\- VirtualBox (host-only networking for lab isolation)

\- Ubuntu Server 26.04 LTS (Splunk host OS)

\- Splunk Enterprise 10.4.1 (free tier) — SIEM

\- Splunk Universal Forwarder — log shipping from Windows-Target to Splunk

\- Sysmon (Microsoft Sysinternals), configured with the SwiftOnSecurity ruleset

\- SSH — remote administration of the Splunk-Server VM

\- Windows 10 (Windows-Target VM)

\- Kali Linux (attacker VM)

\- netexec (`nxc`) — SMB attack simulation from Kali

\- Manual attack simulation on Windows-Target (PowerShell `-EncodedCommand`, `schtasks /create`, cmd → PowerShell process chain)



##### \## Resources Used



\- MITRE ATT\&CK Framework — https://attack.mitre.org

\- Sysmon configuration: SwiftOnSecurity — https://github.com/SwiftOnSecurity/sysmon-config

\- netexec (successor to CrackMapExec) — https://github.com/Pennyw0rth/NetExec

\- Splunk Enterprise / Universal Forwarder official documentation — https://docs.splunk.com



