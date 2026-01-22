# Log Analysis with Splunk using BOTS v3 Dataset

---

## Project Objective

The goal of this project was to learn **log analysis** using **Splunk** by analysing **Windows Security Event Logs**.

Rather than starting with predefined alerts, this project focuses on:

- Understanding log sources  
- Learning how SOC analysts explore unknown datasets  
- Building detection logic step by step  
- Debugging incorrect assumptions  
- Adapting investigation strategy based on available data  

---

## Log Inventory – Understanding the Dataset

### Initial I wanted to understand

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

## Scoping to Windows Security Logs

### Next i wanted to know 

**“How does raw Windows Security log data look like?”**

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

### Next i wanted to know

**“What types of security actions occur most frequently?”**

### Query Used

```spl
index=botsv3 sourcetype=WinEventLog:Security
| stats count by EventCode
| sort -count
```
![EventCodeWinSecLogs](https://github.com/Prajwal-Manjunath/Log-Analysis/blob/main/event_code_splunk.png)

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

  ---

##  Analysing Failed Logon Attempts (EventCode 4625)

I wanted to analyse **failed login attempts** to check for potential **brute-force or credential abuse activity** by grouping failed logons by account and source IP.
---

### Initial Query Used

```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, src_ip
| sort -count
```
### Mistake Identified

This query did not return the expected results because I assumed field names without verifying them first.  
The fields `Account_Name` and `src_ip` do not exist for failed logon events in this dataset.

This highlighted an important lesson:  
**Field names should never be assumed and they must be confirmed by inspecting the raw event data.**

---

### Investigating the Raw Event

To understand what fields were actually available, I inspected a single failed logon event using:

```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4625
| head 1
```
![RawEventFields](https://github.com/Prajwal-Manjunath/Log-Analysis/blob/main/fields_eventcode.png)

### Fields Identified from the Event

By reviewing the available fields, I learned the following:

| Field Name        | Meaning                                   |
|------------------|-------------------------------------------|
| `Account_Name`   | The account involved in the login attempt |
| `Account_Domain` | Domain the account belongs to             |
| `Security_ID`    | SID of the account                        |


### Corrected Query

After identifying the correct field names, I updated my query to:
```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Source_Network_Address, Failure_Reason, Security_ID
| sort -count
```
![4625_attempts](https://github.com/Prajwal-Manjunath/Log-Analysis/blob/main/failed_logon.png)
### Outcome

The dataset contained only 3 failed logon events (EventCode 4625).
Based on this result, there was no evidence of brute-force activity in the dataset.

