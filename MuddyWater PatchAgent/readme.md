# PatchAgent Detection Pack / Retrohunt Rules

# Detection Pack / Retrohunt Rules

This page is a working space for the full detection pack accompanying the PatchAgent / MuddyWater PTCH loader report.

## Overview

Use this page to maintain the complete rule bodies that are intentionally kept out of the main narrative report for readability.

Rule categories:

- KQL hunting queries
- YARA rules
- Snort / Suricata signatures
- Retrohunt queries
- IOC-based enrichment pivots

---

## KQL Hunting Queries

### Regsvr32 DLL execution

```
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has "/s"
| where ProcessCommandLine has_any (".dll", "cloud.dll")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### PatchAgent-style loader execution

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("wuaupdt.exe", "svc_upd.exe", "PatchAgent")
| where ProcessCommandLine has "-p" and ProcessCommandLine has "-k"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

### 64-character key argument

```
DeviceProcessEvents
| where ProcessCommandLine matches regex @"(?i)\s-k\s+[a-f0-9]{64}"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Suspicious Run key persistence

```
DeviceRegistryEvents
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName in~ ("PatchAgent", "SvcUpd")
   or RegistryValueData has_any ("PatchAgent", "wuaupdt", "svc_upd.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### PatchAgent file creation

```
DeviceFileEvents
| where FolderPath has_any (
    @"\AppData\Roaming\Microsoft\PatchAgent\",
    @"\Temp\wuaupdt.exe",
    @"\Temp\wuaupdt.dat",
    @"\Temp\svcmon.log",
    @"\Temp\svcmon.ini"
)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName
```

### HTTP C2 endpoint pattern

```
DeviceNetworkEvents
| where RemoteUrl has_any ("/api/checkin", "/api/cmd/", "/api/result/")
   or RemoteIP == "46.30.188.99"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, Protocol
```

### Suspicious notepad process hollowing chain

```
DeviceProcessEvents
| where FileName =~ "notepad.exe"
| where InitiatingProcessFileName !in~ ("explorer.exe", "notepad.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## YARA Rules

### PatchAgent Stage 1 — cloud.dll dropper

```
rule MAL_PatchAgent_Stage1_CloudDLL_Dropper
{
    meta:
        description = "Detects PatchAgent Stage 1 cloud.dll COM dropper"
        author = "Ransom-ISAC"
        family = "PatchAgent"
        actor = "MuddyWater"
        stage = "Stage 1"
        date = "2026-03-26"

    strings:
        $export1 = "DllRegisterServer" ascii
        $export2 = "DllGetClassObject" ascii
        $fake_company = "SIFE SOFTWARE LLC" wide ascii
        $fake_product = "SIFE SOFTWARE ODBC Tools" wide ascii
        $fake_original = "dbconfig.dll" wide ascii
        $mz = { 4D 5A }

    condition:
        uint16(0) == 0x5A4D and
        2 of ($export*) and
        2 of ($fake_*)
}
```

### PatchAgent Stage 2 — wuaupdt.exe loader

```
rule MAL_PatchAgent_Stage2_Wuaupdt_Loader
{
    meta:
        description = "Detects PatchAgent Stage 2 loader with PTCH, BCrypt AES, and HMAC workflow"
        author = "Ransom-ISAC"
        family = "PatchAgent"
        actor = "MuddyWater"
        stage = "Stage 2"
        date = "2026-03-26"

    strings:
        $s1 = "svcmon v2.1.4" ascii wide
        $s2 = "Patch Agent" ascii wide
        $s3 = "Patch Agent Service" ascii wide
        $ptch = "PTCH" ascii
        $aes = "AES" wide
        $cbc = "ChainingModeCBC" wide
        $sha256 = "SHA256" wide
        $arg_p = "-p" ascii wide
        $arg_k = "-k" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($s*) and
        $ptch and
        $aes and $cbc and $sha256 and
        all of ($arg_*)
}
```

### PatchAgent Stage 3 — shellcode C2 strings

```
rule MAL_PatchAgent_Stage3_Shellcode_C2
{
    meta:
        description = "Detects decrypted PatchAgent Stage 3 shellcode based on C2 and capability strings"
        author = "Ransom-ISAC"
        family = "PatchAgent"
        actor = "MuddyWater"
        stage = "Stage 3"
        date = "2026-03-26"

    strings:
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        $ip = "46.30.188.99" ascii
        $checkin = "/api/checkin" ascii
        $cmd = "/api/cmd/%s" ascii
        $result = "/api/result/%s" ascii
        $ps = "powershell.exe -NoP -NonI -W Hidden -EncodedCommand" ascii
        $remove = "xxxxxremove" ascii
        $notepad = "C:\\Windows\\System32\\notepad.exe" ascii wide
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

    condition:
        6 of them
}
```

---

## Snort / Suricata Signatures

### Initial check-in

```
alert http any any -> any any (msg:"MALWARE PatchAgent Stage3 HTTP checkin"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/api/checkin"; http.user_agent; content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; classtype:trojan-activity; sid:9000010; rev:1;)
```

### Task retrieval

```
alert http any any -> any any (msg:"MALWARE PatchAgent Stage3 task retrieval"; flow:to_server,established; http.method; content:"GET"; http.uri; content:"/api/cmd/"; http.user_agent; content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; classtype:trojan-activity; sid:9000011; rev:1;)
```

### Result submission

```
alert http any any -> any any (msg:"MALWARE PatchAgent Stage3 result submission"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/api/result/"; http.user_agent; content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; classtype:trojan-activity; sid:9000012; rev:1;)
```

---

## Retrohunt Anchors

### Static anchors

```
DllRegisterServer
DllGetClassObject
SIFE SOFTWARE LLC
SIFE SOFTWARE ODBC Tools
dbconfig.dll
wuaupdt.exe
wuaupdt.dat
svcmon v2.1.4
Patch Agent Service
PTCH
ChainingModeCBC
/api/checkin
/api/cmd/
/api/result/
xxxxxremove
```

### Hash pivots

```
27a5d818f690b4c0b1679381ee48ffafb8d3b4ad6247797c32698bd6992a224f
28e55dc62f9a9c9938c3b48b2d17a33d6fa96e74c1e9d31f5c685fef8c39b217
8d217ad2ff7ed9e162cbd20bd207562f7e4f50d3e4d1f36ab01d653380176d16
118e43ccf635e395e029496f55174ee5772c4ceb0319dc33a46fae7001d69aed
```

### Network pivots

```
46.30.188.99
185.228.83.217
41.216.188.46
31.57.219.68
/api/checkin
/api/cmd/<id>
/api/result/<id>
```

---

## Notes

These rules should be validated and tuned before production deployment. Use the main report for context, evidence, and analyst narrative; use this page as the operational detection-pack staging area before publishing to the Ransom-ISAC GitHub repository.
