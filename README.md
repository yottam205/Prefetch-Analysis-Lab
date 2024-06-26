# Prefetch Analysis Lab - Practical Exercis

### Eric Capuano – Prefetch Analysis Lab

Eric’s explanation of Prefetch is important if you want to understand the purpose and use of this lab. Prefetch files are a feature of Windows that helps speed up the boot process and application launches. It is worth noting that Eric wrote a whole scenario in which we are operating. Make sure you read the blog post first:
[Blog Post Here](https://blog.ecapuano.com/p/prefetch-analysis-lab)

### Setup
The first step will be setting up Windows 11 on VMware Workstation. Since I’ve already done that for Eric’s blog post series ‘So You Want to Be a SOC Analyst,’ I won’t be demonstrating the installation of the VM. Once the VM is running, we’ll need to set up the lab environment. We’ll do that by running a script that will automatically install DotNet 6, Eric Zimmerman’s tools, and download the forensic evidence we need for the lab.

**Eric Zimmerman’s tools** are a suite of command-line utilities designed for digital forensics and incident response (DFIR). These tools can help analyze various artifacts from a Windows system.

**Key Tools we’ll use:**
- **PECmd.exe** – Parses Prefetch files to extract execution information.
- **JLECmd.exe** – Analyzes Jumplist files.
- **MFTECmd.exe** – Parses the Master File Table (MFT) from the NTFS file system.

These key tools will help create timelines and understand user activity.

**DotNet 6 (.NET 6)**:
Software development framework created by Microsoft. It allows developers to build applications that can run on various OS. It is a necessary tool for running Eric Zimmerman’s tools.

We will run the following command in the Administrative PowerShell to set up the lab environment:
```
IEX (New-Object Net.Webclient).downloadstring("https://ec-blog.s3.us-east-1.amazonaws.com/DFIR-Lab/PF_Lab/prep_lab.ps1")
```
After installing, we’ll make sure that the evidence we need is located in the right place ‘c:\Cases\Prefetch’.

![Screenshot (57)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/2efeaa30-ea8d-4a6f-b76e-ed1fb0990745)
![Screenshot (58)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/8cbbbc8a-ef6d-41cf-a963-e9096bc4b7c0)

### Begin Analysis
Before we begin the analysis, it is important to note that generally, we can look at the filesystem timestamps of .pf (Prefetch files) to learn two key data points:
- **Creation time (B)**: Generally, the first time the program was executed.
- **Modified time (M)**: Generally, the last time the program was executed.

It is important to note that the Prefetch files we are analyzing in this lab don’t have original filesystem timestamps. For this specific lab, it is not critical because we are still able to carve up to 8 of the most recent execution times from within the Prefetch file itself.

### Create a Prefetch Timeline
The first tool from Eric Zimmerman’s suite we’ll use is PECmd.exe. This tool analyzes individual or entire collections of Prefetch files in a very quick and thorough way.

1. From the Administrative PowerShell, we’ll run the following command. This command aims PECmd at the entire directory of Prefetch files acquired from the victim’s system. It specifies the output directory of `c:\Cases\Analysis\` and a CSV filename of `prefetch.csv`. By using this command we’ll get two output files:
   - a. `prefetch.csv`: Contains a verbose dump of all the data extracted from each .pf file.
   - b. `prefetch_Timeline.csv`: Contains a slimmed-down timeline of execution derived from all timestamps obtained from within each .pf file.
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -q -d C:\Cases\Prefetch\ --csv "C:\Cases\Analysis\" --csvf prefetch.csv
   ```
![Screenshot (59)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/24201a1c-f568-4549-acfd-da337733141b)
![Screenshot (60)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/b974b009-970e-4624-854e-3d3bd69c0dc1)


2. After launching Timeline Explorer from the desktop, we’ll open the two files created after executing the last command:
   - a. `C:\Cases\Analysis\prefetch.csv`
   - b. `C:\Cases\Analysis\prefetch_Timeline.csv`

3. The first file we’ll start with is prefetch_Timeline.csv. In this file, we are able to see a chronologically ordered list of program executions on the system based on the parsed timestamps found within the Prefetch files. We will begin by searching for the data points we have so far from the scenario. By searching `burp` in the global search bar, Timeline Explorer reveals a single execution for a program executed at `2024-03-12 18:36:11` and located at:
   `\Users\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.EXE`
We then **tag** this file, as it is a relevant and interesting one. We will also select the whole row. These two methods are important so we can return to it easily.

4. At this point, we can see all the nearby executions, so we’ll begin by looking at what happened just before the `burpsuite-pro-cracked.exe` file was executed. It seems like the execution just prior to our potential malware was a program called `7ZG.EXE`. We will tag this file as well and get back to it later.
5. Now, we’ll examine all the executions that occurred up to one hour AFTER our file `burpsuite-pro-cracked.exe` was executed. The files I found to be interesting to examine are:
   - **SC.EXE**: Creates persistence mechanisms with services.
   - **SCHTASKS.EXE**: Creates persistence mechanisms with scheduled tasks.
   - **B.EXE**, **C.EXE**, and **P.EXE**: Ran numerous times from Windows\Temp with strange names.
   - **WHOAMI.EXE**: A command for learning what privileges a process is running with.
   - **POWERSHELL.EXE**: A popular command-line interpreter.
   - **TASKLIST.EXE**: Shows all of the different local computer processes currently running.
   - **NETSTAT.EXE**: Displays the contents of various network-related data structures for active connections.
   - **RCLONE.EXE**: Often associated with exfiltration.
   - **CMD.EXE**: A popular command-line interpreter.
   - **SD.EXE**: With a strange name.

I then tagged the files because we will have to further examine if they are tied to our current threat actor or not.

![Screenshot (61)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/c99d947c-126e-400c-a556-677ca2f4de6a)
![Screenshot (62)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/a18150f6-1dae-4a0e-86ed-1552889e9b92)
![Screenshot (63)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/ad206389-85c6-4448-a37d-a0b4635db419)
![Screenshot (64)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/7f77bd5a-ff91-4771-8d27-f5ee64eaacf3)
![Screenshot (66)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/7f2b14c8-fb56-4bd3-a576-3360d0302fd6)
![Screenshot (67)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/fdc09822-d593-4cda-9c8b-d0d50e85d075)

### Deep-Diving into Interesting Prefetch Files
Using Timeline Explorer, we are able to learn which executables are worth further analysis. We’ll conduct this further analysis using PECmd, which will analyze each file individually so we can dive deeper into the information a Prefetch file about a program’s behavior within ~10 seconds of execution contains.

We’ll use this CLI syntax for using PECmd.exe:
```
PECmd.exe -k <keywords> -f c:\path\to\prefetch\file.pf
```
The -k parameter is optional since PECmd already looks for 'tmp', 'temp' by default, but it is recommended to use it so we can specify our analysis further.

1. Starting with the 7ZG.EXE execution we saw just prior to burpsuite, we’ll also provide the keyword ‘burpsuite’ since we suspect they are related. The PowerShell command is as follows:
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k burpsuite -f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf
   ```
   After running the command, we are able to see all directories and files accessed by this program within ~10 seconds of execution. Many files are DLLs and data files, which are not relevant, but we can also see that there’s a hit with the keyword `burpsuite` that reveals the relationship between `7ZG.EXE` and an archive named `BURPSUITE-PRO-CRACKED.7Z` which is in the Downloads folder. Most likely, the `burpsuite-pro-cracked.exe` was originally packed inside that `BURSUITE-PRO-CRACKED.7Z` file.

![Screenshot (69)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/80ece88c-dc0a-4367-ab07-8af29c6d1e02)
![Screenshot (70)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/dfa483bd-d59a-4c79-8ca4-caaf7f887ee2)

2. We’ll now repeat the same technique for each of our additional suspicious executables, going in the order that they were executed and answering the questions asked in the blog.
   a. **BURPSUITE-PRO-CRACKED.EXE-EF7051A8.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\BURPSUITE-PRO-CRACKED.EXE-EF7051A8.pf
   ```
   - Run time: 1. Last run: `2024-03-12 18:36:11`.
   - The full path to the program executable was:
   `\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.EXE`
   - There are no hits for other keywords.
   - As we can’t see anything interesting or noteworthy in the files or directories referenced, Eric notes that there is a Windows DLL called `WININET.DLL`. It’s noteworthy because the file provides a high-level interface for accessing internet resources via HTTP, HTTPS, and FTP protocols. In the context of malware, when a program imports such a file, it could potentially be involved in malicious activities like communicating with command and control servers, downloading additional payloads, or exfiltrating data.

![Screenshot (71)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/f77e74bd-dc23-444d-8b1f-cce22bb2aaa7)
![Screenshot (72)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/b6ceefc4-741d-4814-a543-13b2dfd5d691)

   b. **B.EXE-B3490BF0.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\B.EXE-B3590BF0.pf
   ```
   - Run time: 1. Last run: `2024-03-12 18:55:13`.
   - The full path to the program executable:
     `\WINDOWS\TEMP\B.EXE`
   - There are 6 other keyword hits for `tmp`, `temp`:
   ```
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP (Keyword True)
   \WINDOWS\TEMP (Keyword True)
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\BHV2ED.TMP (Keyword: True)
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\CHI3E8.TMP (Keyword: True)
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\CHI408.TMP (Keyword: True)
   \WINDOWS\TEMP\1.TXT (Keyword: True)
   ```
   - The following locations may suggest that this tool is accessing browser history data:
   ```
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\WINDOWS\WEBCACHE\WEBCACHEV01.DAT
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\GOOGLE\CHROME\USER DATA\DEFAULT\HISTORY
   \USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\HISTORY
   \USERS\BILL.LUMBERGH\APPDATA\ROAMING\MOZILLA\FIREFOX\PROFILES.INI
   ```
   - The fact that there is a TXT file in the same location that B.EXE ran from suggests a possible output file.
   `\WINDOWS\TEMP\1.TXT`
   
![Screenshot (73)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/974e0020-b61c-4856-a53e-a5bd37c06cc0)
![Screenshot (74)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/d9c6a300-1727-4583-b260-3403dadcc5f5)
![Screenshot (75)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/427fe59e-0a65-4568-82df-d1c9f72b17d5)


   c. **C.EXE-C6AEC675.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\C.EXE-C6AEC675.pf
   ```
   - Run count: 9. Last run: `2024-03-12 19:02:37`. Other run times: `2024-03-12 19:02:37`, `2024-03-12 19:02:01`, `2024-03-12 19:02:04`, `2024-03-12 19:00:49`, `2024-03-12 19:00:51`, `2024-03-12 18:57:58`, `2024-03-12 18:57:58`.
   - The full path to the program executable:
   `\WINDOWS\TEMP\C.EXE`
   - There are 3 other keyword hits for `tmp`, `temp`:
   ```
   \WINDOWS\TEMP (Keyword True)
   \WINDOWS\TEMP\2.TXT (Keyword: True)
   \WINDOWS\TEMP\WCEAUX.DLL (Keyword: True)
   ```
   - A quick search on Google for the file `WCEAUX.DLL` finds that it belongs to a credential access tool called Windows Credential Editor.
   - The possible output file may as well be at the same place as the C.EXE file since there is a TXT file:
   `\WINDOWS\TEMP\2.TXT`

![Screenshot (76)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/78762166-e099-465f-bfef-93381cd43e46)
![Screenshot (77)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/bf8c8a95-a594-49a4-b30b-e32680f540d3)

   d. **P.EXE-C2093F36.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\P.EXE-C2093F36.pf
   ```
   - Run time: 2. Last run: `2024-03-12 19:03:55`. Other run times: `2024-03-12 19:03:27`.
   - The full path to the program executable:
   `\WINDOWS\TEMP\P.EXE`
   - There are no other keyword hits except for the directory where the EXE itself is located.

![Screenshot (78)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/e702cc9a-780f-4f2a-aba9-fea68b8fc802)

   e. **POWERSHELL.EXE-022A1004.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\POWERSHELL.EXE-022A1004.pf
   ```
   - Run count: 23. Last run: `2024-04-13 21:31:28`. Other run times: `2024-04-13 21:21:23`, `2024-04-13 21:21:22`, `2024-04-13 20:50:40`, `2024-04-13 20:50:40`, `2024-03-12 19:26:55`, `2024-03-12 19:16:52`, `2024-03-12 19:14:15`.
   - No, we can’t see all the 23 times the program ran because Prefetch files only hold up to 8 of the most recent execution times.
   - The full path to the program executable:
   `\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`
   - At the end of the analysis report, we can see some directories and files that have been entered. This can possibly tell us that some potential business documents have been accessed by PowerShell. We can also think that PowerShell was used to copy several business documents:
   ```
   \USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\ACCOUNTS-EXPORT-2023-07-24.XLS
   \WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS
   \USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\CYBER-INSURANCE-POLICY-2023.PDF
   \WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF
   \USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\DC-BACKUPS.ZIP
   \WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP
   \USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\IT-SYSTEMS-DIAGRAM.PDF
   \WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF
   \USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\OFFSITE BACKUP ARCHITECTURE.PDF
   \WINDOWS\BACKUP\LOGS\OFFSITE BACKUP ARCHITECTURE.PDF
   ```
![Screenshot (79)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/fbc06ecb-3770-46d3-a63d-cd1c6f46dc6e)
![Screenshot (80)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/3f78b12d-134d-4149-b7e3-1f8cc640d875)
![Screenshot (81)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/70635e75-f2e5-4d34-9143-69c0eab0fcb0)
![Screenshot (83)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/25685bb1-9f19-4975-bb2a-dcbb6e049078)

   f. **RCLONE.EXE-56772E5D.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup,xls,pdf,zip -f C:\Cases\Prefetch\RCLONE.EXE-56772E5D.pf
   ```
   Note that this one we are running with the added keywords `backup`, `xls`, `pdf`, `zip`, since Rclone is a CLI program to manage files on the cloud.
   - Run count: 1. Last run: `2024-03-12 19:19:48`.
   - The full path to the program executable:
   `\WINDOWS\BACKUP\RCLONE.EXE`
   - There are 11 more keyword hits thanks to the added keywords:
   ```
   \WINDOWS\BACKUP (Keyword True)
   \WINDOWS\BACKUP\LOGS (Keyword True)
   \WINDOWS\BACKUP\RCLONE.CONF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\1.TXT (Keyword: True)
   \WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\2.TXT (Keyword: True)
   \WINDOWS\BACKUP\LOGS\OFFSITE BACKUP ARCHITECTURE.PDF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS (Keyword: True)
   \WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP (Keyword: True)
   \WINDOWS\BACKUP\LOGS\LSASS.DMP (Keyword: True)
   ```
   - `\WINDOWS\BACKUP\RCLONE.CONF` might be a configuration file.
   - We can guess that the use of the LSASS file is used for a credential dump. The file’s path is: `\WINDOWS\BACKUP\LOGS\LSASS.DMP`.
   - If we head back to Timeline Explorer and search the prefetch.csv file for `lsass.dmp`, then sort them by last run, we find that `RUNDLL32.EXE` was the first to reference it.
     
![Screenshot (84)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/0c4edf1d-df1d-44c5-9b64-a22b1da7c6fd)
![Screenshot (85)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/16264e32-6f77-48ea-84fc-61adf4cd71ce)
![Screenshot (86)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/d5e4de0d-44e6-4401-882e-226b87b71d10)

   g. **SD.EXE-A541D1D9.pf**
   ```
   C:\DFIR_Tools\ZimmermanTools\net6\PE

Cmd.exe -k backup -f C:\Cases\Prefetch\SD.EXE-A541D1D9.pf
   ```
   Here we’ll add the keyword `backup`, since this program is usually used to wipe or delete data.
   - Run time: 1. Last run: `2023-03-12 19:26:11`.
   - The full path to the program executable:
   `\WINDOWS\BACKUP\SD.EXE`
   - There are 9 more keyword hits. It is worth noting that they are very similar to the keyword hits for `RCLONE.EXE`:
   ```
   \WINDOWS\BACKUP (Keyword True)
   \WINDOWS\BACKUP\LOGS (Keyword True)
   \WINDOWS\BACKUP\LOGS\1.TXT (Keyword: True)
   \WINDOWS\BACKUP\LOGS\2.TXT (Keyword: True)
   \WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS (Keyword: True)
   \WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP (Keyword: True)
   \WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF (Keyword: True)
   \WINDOWS\BACKUP\LOGS\LSASS.DMP (Keyword: True)
   ```
   - By its location and keywords found, we can learn that this file might have been used as a wiper or secure delete utility meant to clean up the staging location post-exfil.
   - `RCLONE.CONF` that is referenced by `RCLONE.EXE` is not referenced by `SD.EXE’ located in `\WINDOWS\BACKUP\`. We can learn that `SD.EXE` deleted files in `WINDOWS\BACKUP\LOGS\`.

![Screenshot (87)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/a32aec77-adae-493f-862b-c31bb00665c9)
![Screenshot (89)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/33a5774b-93d5-4e5b-a3e2-f20b6e8ffdc9)

### Finalizing Our Scope
We will now head back to Timeline Explorer to further investigate the suspicious files we found and looked for, and to dive into the `prefetch.csv` file.
1. We will start by searching for each of the following keywords and tagging each row that matches:
   `burpsuite`, `\b.exe`, `\c.exe`, `\p.exe`, `rclone`, `\sd.exe`, `lsass.dmp`, `IT Docs`, `Windows\backup`.
2. **SYSTEMINFO.EXE** appeared when we searched the keyword `Windows\Backup` and seems like the file accessed `\WINDOWS\BACKUP\INFO.TXT\`. It is interesting since that location is a known attacker working location.

![Screenshot (90)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/56c12c00-e57f-4b2d-a7fa-68759b90127e)
![Screenshot (91)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/f3ca20a3-2317-46f2-800b-a68a74960fe3)
![Screenshot (92)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/23948bf0-5ce5-4b9d-867e-f281942a6ce7)


### Finalizing Our Timeline
Now we can see the complete list of relevant executables on our `prefetch_timeline.csv` file. We’ll have to search for and tag each execution of the executables from the previous step:
`7ZG.EXE`, `BURPSUITE-PRO-CRACKED.EXE`, `\b.exe`, `\C.EXE`, `\P.EXE`, `RUNDLL32.EXE`, `SD.EXE`, `SYSTEMINFO.EXE`, `POWERSHELL.EXE`.
We’ll focus only on the executions that occurred after 2024-03-12 18:36, which is after the initial access malware was executed.

![Screenshot (93)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/586137d5-1601-4d96-ac84-599e5826235a)
![Screenshot (94)](https://github.com/yottam205/Prefetch-Analysis-Lab/assets/117525375/56a8ef60-2f06-4b67-84f5-3bbaa6b3ecc9)


### Conclusion
This lab was just the tip of the iceberg in forensics. I learned a lot and enjoyed it. The analysis with Timeline Explorer is very specific and takes time to learn and experience. It is important to note that when investigating any event, the use of Timeline Explorer is valuable, but it is not the only tool one needs to use. There are more forensic tools to use for having a better understanding of all the activities that happened. That being said, this lab shows in a great way how with only Prefetch files, we were able to determine key activities that occurred in the event.

