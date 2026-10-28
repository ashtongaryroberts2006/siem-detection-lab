# Detection Testing

Testing each of the six v1 detections against legitimate activity (false positives) and working out how an attacker could slip past them (evasion). In v1 every alert was a confirmed true positive because I triggered them on purpose. This is the step that checks whether they're actually any good.

**Test environment:** Windows-Target VM, Kali-Attacker powered off, normal admin activity only
**Before each session:** resync the clock on Windows-Target and Splunk-Server (no NTP on the isolated network, see build log)
**Dates tested:** YYYY-MM-DD

## Summary

| # | Detection | MITRE | False positives found? | Tuned? | Main evasion |
|---|---|---|---|---|---|
| 1 | Repeated failed logons | T1110 | | | Password spraying, slow brute force |
| 2 | Encoded-command PowerShell | T1059.001 | | | Abbreviated `-enc` / `-e` flag |
| 3 | Scheduled task creation | T1053.005 | | | Modifying an existing task |
| 4 | cmd to PowerShell lineage | T1059 | | | Renamed powershell.exe, different parent |
| 5 | Admin-share access over SMB | T1021.002 | | | WMI / WinRM instead of SMB shares |
| 6 | Security log cleared | T1070.001 | | | Clearing other logs, disabling auditing |

---

## 1. Repeated Failed Logons (T1110)

**Original SPL**
```spl
index=main EventCode=4625 Account_Name=* | stats count by Account_Name | where count > 5
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| Mistype password 3 times at the login screen, then log in | | Should not fire (under threshold) |
| Mistype password 6+ times at the login screen | | Logon Type 2 (interactive), a genuine user, not an attack |
| Map a network drive with the wrong password, let it retry | | Stale saved credentials are a classic real-world false positive |

### Things to check
- Look at the raw 4625 event. It has two "Account Name" fields (the subject and the account that failed). Check whether Splunk is extracting `Account_Name` as a multi-value field, because `stats count by Account_Name` would then count the subject value (often `-`) as well
- The query doesn't group by source, so it can't tell one attacker from several

### Tuning (starting point, test before using)
```spl
index=main EventCode=4625 Logon_Type=3
| stats count dc(Account_Name) as accounts_tried values(Account_Name) as accounts by Source_Network_Address
| where count > 5
```
- **What changed and why:** grouping by source IP shows who is attacking. Filtering to network logons (Type 3) stops a user fumbling their password at the keyboard from alerting. `accounts_tried` also makes password spraying visible (one source, many accounts)

### Limitations / evasion
- **Password spraying:** one or two attempts per account across many accounts never reaches 5 per account, so the original query misses it completely
- **Slow brute force:** fewer than 6 attempts per 5-minute window stays under the threshold forever
- **No success check:** it doesn't show whether the attacker eventually got in (this is what the new correlated detection will fix)

---

## 2. Suspicious PowerShell, Encoded Command (T1059.001)

**Original SPL**
```spl
index=main CommandLine="*EncodedCommand*"
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| `powershell -EncodedCommand` with a harmless encoded `Get-Date` | | Will fire. The point is: could you tell this apart from malicious use? |
| Run normal PowerShell admin commands (`Get-Process`, `Get-Service`) | | Should not fire |
| `powershell -ExecutionPolicy Bypass -File test.ps1` | | Should not fire on the original, check the tuned version doesn't either |

### Evasion test (run this one, it's a good finding)
PowerShell accepts any shortened version of a parameter name. All of these work the same as `-EncodedCommand`:
```powershell
powershell -enc ZwBlAHQALQBkAGEAdABlAA==
powershell -e ZwBlAHQALQBkAGEAdABlAA==
powershell -ec ZwBlAHQALQBkAGEAdABlAA==
```
| Variant | Fired? |
|---|---|
| `-enc` | |
| `-e` | |
| `-ec` | |

### Tuning (starting point, test before using)
```spl
index=main EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe")
| regex CommandLine="(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}"
| table _time host User ParentImage CommandLine
```
- **What changed and why:** matches any flag starting with `-e` (or `/e`) followed by a long base64 string, so it catches every abbreviation. The base64 length check stops `-ExecutionPolicy Bypass` from matching. Restricting to Sysmon EID 1 and PowerShell images cuts noise. Adding `ParentImage` to the output gives the analyst context straight away

### Limitations / evasion
- Abbreviated flags bypass the original query entirely
- Doesn't cover PowerShell 7 (`pwsh.exe`) in the original
- Attacker can avoid encoding altogether and use other obfuscation (string concatenation, `Invoke-Expression`), which needs PowerShell Script Block Logging (EID 4104) to see

---

## 3. Persistence via Scheduled Task (T1053.005)

**Original SPL**
```spl
index=main EventCode=4698
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| Create a harmless task in Task Scheduler GUI (e.g. runs notepad weekly) | | Will fire. Legitimate admin task |
| Leave the VM running for a day and check for Windows-created tasks | | Windows, Defender and Office create and update tasks on their own |
| Run `schtasks /query` (just listing tasks) | | Should not fire |

### Tuning (starting point, test before using)
```spl
index=main EventCode=4698
| search NOT Task_Name="\\Microsoft\\*"
| rex field=Task_Content "<Command>(?<task_command>[^<]+)</Command>"
| table _time host Account_Name Task_Name task_command
```
- **What changed and why:** excludes Windows' own tasks under `\Microsoft\` and pulls out the actual command the task runs, so the analyst can see straight away if it points somewhere suspicious (e.g. `AppData`, `Temp`, `Public`)
- Check the field names in your own 4698 events first. `Task_Content` may be named differently depending on how the event is extracted

### Limitations / evasion
- **Trade-off:** excluding `\Microsoft\` cuts noise, but an attacker can name their task `\Microsoft\Windows\Something` to hide in that exclusion. Document this either way
- Modifying an existing task fires EID 4702, not 4698, so it isn't covered
- Doesn't rate how suspicious the task's command is, so every creation looks equally important

---

## 4. Suspicious Process Spawn, cmd to PowerShell (T1059)

**Original SPL**
```spl
index=main EventCode=1 ParentImage="*cmd.exe*" Image="*powershell.exe*"
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| Open cmd, type `powershell`, run `Get-Date` | | Will fire. Admins do this constantly |
| Run a `.bat` file that calls `powershell -Command Get-Date` | | Will fire. Very common in real admin scripts and installers |
| Open PowerShell directly from the Start menu | | Should not fire (parent is explorer.exe) |

### Evasion test
```cmd
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Users\Public\notepad2.exe
cmd /c C:\Users\Public\notepad2.exe -Command Get-Date
```
| Variant | Fired? |
|---|---|
| Renamed powershell.exe | |

### Tuning (starting point, test before using)
```spl
index=main EventCode=1 ParentImage="*cmd.exe" (OriginalFileName="PowerShell.EXE" OR Image="*powershell.exe" OR Image="*pwsh.exe")
| table _time host User ParentCommandLine CommandLine Image
```
- **What changed and why:** `OriginalFileName` comes from the file's internal metadata, so it still says PowerShell even if the file is renamed. Showing `ParentCommandLine` lets the analyst see which batch file or command launched it
- If a known admin script keeps firing, add an allowlist line, e.g. `| search NOT ParentCommandLine="*C:\\AdminScripts\\*"`

### Limitations / evasion
- Very noisy on its own in a real environment. Best used as supporting evidence alongside other alerts, not as a standalone high-severity alert
- Doesn't look at what launched cmd.exe (e.g. Word or a browser launching cmd is far more suspicious than explorer)
- PowerShell launched by something other than cmd (wscript, mshta, rundll32) isn't covered

---

## 5. Lateral Movement, SMB Admin Share Access (T1021.002)

**Original SPL**
```spl
index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| On Windows-Target, open `\\127.0.0.1\C$` in File Explorer | | Local admin access to its own share |
| From your host PC, open `\\192.168.116.5\C$` with admin credentials | | Mimics an IT admin managing a machine remotely |
| Browse a normal (non-admin) share, if one exists | | Should not fire |

### Tuning (starting point, test before using)
```spl
index=main EventCode=5140 (Share_Name="*ADMIN$*" OR Share_Name="*C$*")
| search NOT Source_Address IN ("127.0.0.1", "::1")
| search NOT Account_Name="*$"
| stats count values(Share_Name) as shares by Source_Address Account_Name host
```
- **What changed and why:** drops loopback access (the machine accessing itself) and computer accounts (names ending in `$`), which are normal background noise. Grouping by source shows one row per source/account instead of one per event
- In a real network you'd also add an allowlist of known admin workstation IPs

### Limitations / evasion
- Lateral movement over WMI, WinRM or RDP doesn't touch admin shares, so it's invisible here
- `IPC$` access isn't covered
- 5140 is logged once per session, not per file, so it doesn't show what was copied or run. That would need EID 5145 or service creation (EID 7045)

---

## 6. Windows Security Log Cleared (T1070.001)

**Original SPL**
```spl
index=main EventCode=1102
```

### Legitimate activity tested
| Activity | Fired? | Notes |
|---|---|---|
| Clear the Security log through Event Viewer as admin | | Will fire. Some admins do this during troubleshooting |
| Clear the **System** log instead | | Original won't fire (different event ID) |
| Clear the **Sysmon** log | | Original won't fire |

### Tuning (starting point, test before using)
```spl
index=main (EventCode=1102 OR (EventCode=104 source="WinEventLog:System") OR EventCode=1100 OR EventCode=4719)
| table _time host EventCode Account_Name source
```
- **What changed and why:** widens it to cover all log tampering, not just the Security log:
  - `1102`: Security log cleared
  - `104`: any other log cleared (System, Sysmon, etc.)
  - `1100`: event logging service shut down
  - `4719`: audit policy changed (e.g. attacker turning auditing off)

### Limitations / evasion
- Very low false-positive rate. Even legitimate clearing is worth asking about, so no tuning down needed
- An attacker who stops the Universal Forwarder first stops anything reaching Splunk. Worth a future detection for the forwarder going silent (no events from a host for X minutes)
- Disabling Sysmon or changing its config isn't covered

---

## Overall findings

(Write this last.) What did testing show overall? Which detections were reliable, which were noisy, and which had the biggest blind spots?

-
-
-
