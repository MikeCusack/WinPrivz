# WinPrivz
## PowerShell-based Windows Privilege Escalation Script (used with SysInternal's AccessChk)

```

 █████   ███   █████  ███             ███████████             ███                        
░░███   ░███  ░░███  ░░░             ░░███░░░░░███           ░░░                         
 ░███   ░███   ░███  ████  ████████   ░███    ░███ ████████  ████  █████ █████  █████████
 ░███   ░███   ░███ ░░███ ░░███░░███  ░██████████ ░░███░░███░░███ ░░███ ░░███  ░█░░░░███ 
 ░░███  █████  ███   ░███  ░███ ░███  ░███░░░░░░   ░███ ░░░  ░███  ░███  ░███  ░   ███░  
  ░░░█████░█████░    ░███  ░███ ░███  ░███         ░███      ░███  ░░███ ███     ███░   █
    ░░███ ░░███      █████ ████ █████ █████        █████     █████  ░░█████     █████████
     ░░░   ░░░      ░░░░░ ░░░░ ░░░░░ ░░░░░        ░░░░░     ░░░░░    ░░░░░     ░░░░░░░░░ 
     

By: Mike Cusack (@m1xus)

```

WinPrivz is a PowerShell script to assist Penetration Testers in identifying some common Windows Privilege Escalation avenues including:
- Insecure Service Permissions (Service Config Modification)
- Unquoted Service Paths
- Weak Service Registry Hive Permissions
- Insecure Service Binary Permissions
- PATH DLL Hijacking Possibilities
- AutoRuns
- AlwaysInstallElevated Checks
- Saved Domain Credentials (runas /savecred)
- Stored SSH PuTTY Sessions/Credentials

[ ! ] Coming Soon:
- Startup Application Abuse
- Kernel Exploits



To use:
1. A copy of SysInternal's AccessChk.exe is required. Download Here: https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
2. Ensure the PowerShell script is executed from the same directory as accesschk.exe!
