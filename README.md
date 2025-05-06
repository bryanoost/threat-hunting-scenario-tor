<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/bryanoost/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched `DeviceFileEvents` table for any word that contained the string “tor”. Discovered     
probable download of TOR installer by employee account named “behelit”. Observed many TOR-related files copied to desktop and the subsequent creation of file named `tor-shopping-list.txt` at `2025-05-02T19:07:29.038172Z`. 

These events began at: `2025-05-02T18:42:12.7399542Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName startswith "behelit-threat"
| where InitiatingProcessAccountName == "behelit"
| where Timestamp >= datetime(2025-05-02T18:42:12.7399542Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1318" alt="image" src="https://github.com/user-attachments/assets/e320fd45-3539-469a-81db-e9de4ac03db1">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched `DeviceProcessEvents` table for any `ProcessCommandLine` events that contained the string “tor-browser-windows”. Based on logs returned, at `2025-05-02T18:48:35.0226137Z`, the employee on the device “behelit-threat-” ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, FolderPath, SHA256
| where DeviceName == "behelit-threat-"
```
<img width="1322" alt="image" src="https://github.com/user-attachments/assets/35962481-e150-44d8-8bc2-a13df4c7ee6f">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched `DeviceProcessEvents` for any indication that user “behelit" did indeed open the TOR browser. Logs indicate that at `2025-05-02T18:49:08.1620705Z` the TOR browser was opened. Several other instances of `firefox.exe` (TOR) and `tor.exe` were spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1334" alt="image" src="https://github.com/user-attachments/assets/7bb7732f-89de-4de3-9275-a25c351670ae">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
 
Searched `DeviceNetworkEvents` for any indication that the TOR browser was used to establish a connection using known TOR port numbers.

Logs show the user on the device “behelit-threat-” establishing a connection to the remote IP address `89.58.34.53` on port `9001`. The connection was initiated by the `tor.exe` process, located in folder `c:\users\behelit\desktop\tor browser\browser\torbrowser\tor\tor.exe`. Additional connections to sites were made over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "behelit-threat-"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1313" alt="image" src="https://github.com/user-attachments/assets/91c60e80-b7e9-4a84-a45a-bb3d1acc61a2"/>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-02T18:42:12.7399542Z`
- **Event:** The user "behelit" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\behelit\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `​​2025-05-02T18:48:35.0226137Z`
- **Event:** The user "behelit" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\behelit\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-02T18:49:08.1620705Z`
- **Event:** User "behelit" opened the TOR browser. Subsequent processes `firefox.exe` and `tor.exe`, associated with the TOR browser were also created. This indicates the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\behelit\Desktop\TorBrowser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-02T18:56:55.8247553Z`
- **Event:** A network connection to IP `89.58.34.53` on port `9001` by user “behelit” was established using `tor.exe`, confirming TOR browser network connectivity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\users\behelit\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-02T18:56:59.065537Z` - Connected to `2.59.254.198` on port `443`.
  - `2025-05-02T18:57:08.9130947Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "behelit" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `	2025-05-02T19:07:29.038172Z`
- **Event:** The user “behelit” created a file named `tor-shopping-list.txt` on the desktop, indicating potential notes or a list related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\behelit\Desktop\tor-shopping-list.txt`

---

## Summary

The user "behelit" on the "behelit-threat-” device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `behelit-threat-` by the user `behelit`. The device was isolated, and the user's direct manager was notified.

---
