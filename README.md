# Threat Hunt Report: Devices Accidentally Exposed to the Internet

## Platforms and Languages Leveraged
- Windows Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

During routine maintenance, the security team was tasked with investigating VMs in the shared services cluster (DNS, Domain Services, DHCP, etc.) that may have been mistakenly exposed to the public internet. Because some older devices in the environment do not have account lockout configured for excessive failed login attempts, there was concern that exposed devices could have been targeted — or successfully compromised — by brute-force login attempts from external sources during the exposure window.

### High-Level IoC Discovery Plan

- **Check `DeviceInfo`** to confirm which devices were internet-facing, and for how long.
- **Check `DeviceLogonEvents`** for excessive failed login attempts from external IP addresses, and for any of those same IPs achieving a successful logon.

---

## Steps Taken

### 1. Searched the `DeviceInfo` Table for Internet Exposure

Confirmed that the target device, **ty-win-vm**, had been internet-facing since **June 9, 2026 at 4:00 AM**, with a last internet-facing timestamp of `2026-06-09T16:57:57.6033991Z`.

**Query used to locate events:**

```kql
DeviceInfo
| where DeviceName == "ty-win-vm"
| where IsInternetFacing == true
| order by Timestamp desc
```

---

### 2. Searched the `DeviceLogonEvents` Table for Failed Logon Attempts

Searched for failed network/interactive logon attempts against the device while it was exposed. Multiple external IP addresses were observed attempting — and failing — to log in repeatedly, consistent with brute-force activity.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "ty-win-vm"
| where LogonType has_any ("network", "Interactive", "remoteinteractive", "unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize attempts = count() by ActionType, RemoteIP, DeviceName
| order by attempts
```

---

### 3. Checked the Top Offending IPs for Any Logon Success

Took the top offending remote IP addresses from the failed-logon results and checked whether any of them ever achieved a successful logon against the device.

**Query used to locate events:**

```kql
let RemoteIPsInQuestion = dynamic(["80.66.83.80","141.98.83.66","45.238.132.70","45.142.193.166","203.57.6.123"]);
DeviceLogonEvents
| where LogonType has_any ("network", "Interactive", "remoteinteractive", "unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any (RemoteIPsInQuestion)
```

**Result:** None of the top offending IPs achieved a successful logon.

---

### 4. Verified the Legitimate Account Was Not Compromised

Checked whether the legitimate account (`Ty`) had any successful or failed network logons during the exposure window, to rule out compromise of the real user account.

**Queries used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "ty-win-vm"
| where LogonType == "network"
| where ActionType == "Logonsuccess"
| where AccountName == "Ty"
| summarize count()
```

```kql
DeviceLogonEvents
| where DeviceName == "ty-win-vm"
| where LogonType == "network"
| where ActionType == "Logonfailed"
| where AccountName == "Ty"
| summarize count()
```

**Result:** Zero successful and zero failed network logons for account `Ty` — the legitimate account was never targeted or compromised.

---

## Timeline Summary and Findings

The device `ty-win-vm` was exposed to the public internet from approximately 4:00 AM on June 9, 2026, until `2026-06-09T16:57:57Z`. During this window, several external IP addresses made repeated failed logon attempts consistent with brute-force password guessing. None of these attempts resulted in a successful logon, and the legitimate account on the device showed no logon activity — successful or failed — over the same period, confirming the account was not targeted or compromised.

---

## MITRE ATT&CK TTP Alignment

**Tactics:**
- **TA0001** — Initial Access
- **TA0006** — Credential Access

**Techniques:**
- **T1133** — External Remote Services
- **T1110** — Brute Force
- **T1110.001** — Password Guessing *(most likely)*
- **T1110.003** — Password Spraying *(possible, unconfirmed)*

---

## Summary

The device was confirmed to have been unintentionally exposed to the public internet for approximately 13 hours. During that time, multiple external IPs attempted brute-force login attacks against the device, but none succeeded. The legitimate user account showed no logon activity of any kind during the exposure window, confirming the account was not accessed or compromised.

---

## Response Taken

The Network Security Group (NSG) for `ty-win-vm` was hardened to only allow inbound RDP access from specific, approved endpoints, removing public internet exposure entirely.
