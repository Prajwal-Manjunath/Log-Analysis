# Log Analysis with Splunk

---

## 📌 Project Objective

The goal of this project was to learn **log analysis** using **Splunk** by analysing **Windows Security Event Logs**.

Rather than starting with predefined alerts, this project focuses on:

- Understanding log sources  
- Learning how SOC analysts explore unknown datasets  
- Building detection logic step by step  
- Debugging incorrect assumptions  
- Adapting investigation strategy based on available data  

---

## Background: Why Windows Security Logs?

Windows Security logs are one of the most critical data sources in a Security Operations Centre (SOC) because they record:

- Authentication attempts (successful and failed)  
- Process creation and termination  
- Privileged activity  
- Account and policy changes  

Understanding these logs is essential for detecting:

- Brute-force attacks  
- Credential abuse  
- Privilege escalation  
- Lateral movement  
---

## 🔹 Step 1: Log Inventory – Understanding the Dataset

### Initial Question

**“What types of logs do I even have?”**

### Query Used

```spl
index=botsv3 | stats count by sourcetype
```
### Query Explanation

Basically, this query looks at **all logs in the `botsv3` index**, groups them by **log type (`sourcetype`)**, and counts how many events exist for each type.  
This helped me quickly understand what kinds of logs were available and which ones generated the most data.

![Log Inventory by Sourcetype](https://github.com/Prajwal-Manjunath/Log-Analysis/blob/main/splunk_sourcetype.png)

### Why This Was Done

### Outcome

By running this query and reviewing the results, I learned what each log category in the dataset represented.  

| Sourcetype                                            | What it represents                            |
| ----------------------------------------------------- | --------------------------------------------- |
| `WinEventLog:Security`                                | Windows login, logoff, authentication events  |
| `WinHostMon`                                          | Endpoint monitoring activity                  |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon (process, network, file activity)      |
| `access_combined`                                     | Web server (Apache/Nginx) access logs         |
| `Unix:UserAccounts`                                   | Linux user account information                |
| `Unix:ListeningPorts`                                 | Open ports on Linux systems                   |
| `PerfmonMk:Process`                                   | Windows process performance data              |

This step helped me understand the scope of available telemetry and what type of activity each log source was capable of showing.

From this, **Windows Security logs** were chosen as the first focus due to their relevance to authentication and endpoint activity.

---

## 🔹 Step 2: Scoping to Windows Security Logs

### Question

**“What does raw Windows Security log data look like?”**

### Query Used

```spl
index=botsv3 sourcetype=WinEventLog:Security
```
### Query Explanation
From the BOTS v3 dataset, show me only Windows Security Event Logs. Here i saw eventcode field types and learn about different event code and its significance.
![WindowsEventLog](https://github.com/Prajwal-Manjunath/Log-Analysis/blob/main/security_logs_splunk.png)
### Common Windows Security EventCodes Observed

| EventCode | What it represents                                   |
|---------:|--------------------------------------------------------|
| 4624     | Successful logon                                      |
| 4625     | Failed logon                                          |
| 4634     | Logoff                                                |
| 4648     | Logon attempt using explicit credentials              |
| 4672     | Special privileges assigned to new logon              |
| 4688     | New process created                                   |

This step helped me understand what kinds of security actions are recorded by Windows and how they are represented in logs.

---

## 🔹 Step 3: Establishing Baseline Behaviour Using EventCodes

### Question

**“What types of security actions occur most frequently?”**

### Query Used

```spl
index=botsv3 sourcetype=WinEventLog:Security
| stats count by EventCode
| sort -count
```
### Query Explanation

This query searches the BOTS v3 dataset and restricts the results to **Windows Security logs only**.  
It then:

- Groups events by Windows **EventCode**  
- Counts how many times each EventCode appears  
- Sorts the results in descending order to show the most frequent events first  

### What I Learned

By running this query, I gained an overview of **what normally happens on the system**.  
Specifically, it helped me understand:

- Which security actions occur most often  
- Which EventCodes are common and represent normal activity  
- How frequently different types of security-related actions are recorded  
