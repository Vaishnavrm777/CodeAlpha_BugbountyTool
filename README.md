# CodeAlpha_BugbountyTool
It is aligned with how entry-level to junior bug bounty researchers and SOC analysts work during code review.

## 📝 Designed to detect 

| No. | Category                         | Severity | Type                      |
| --: | -------------------------------- | -------- | ------------------------- |
|   1 | Code Injection (`eval`, `exec`)  | HIGH     | Injection                 |
|   2 | Command Injection (`shell=True`) | HIGH     | Injection                 |
|   3 | Hardcoded Secrets                | MEDIUM   | Sensitive Data Exposure   |
|   4 | Debug Mode Enabled               | HIGH     | Security Misconfiguration |
|   5 | Weak Cryptography (MD5 / SHA1)   | MEDIUM   | Cryptographic Failure     |
|   6 | Logic Flaw (`== None`)           | LOW      | Logic Error               |

---
## ⚙️ Set up the tool in VS Code ##
### Step 1: Create a Project Folder ###

Example: Bugbounty/

### Step 2: Create the Analyzer File ###

Example: bugbounty_analyzer.py

### Step 3: Create a Test Target File ###

Example: target.py

---
## 🏃‍♂️‍➡️ Run the tool ##
Ensure you are in the folder as created above.

Next input the below python command in the terminal.
```bash
python bugbounty_analyzer.py target.py
```

---
## 📊 Expected output ##

Security Findings:
--------------------------------------------------
[HIGH] Security Misconfiguration (line 1): Debug mode enabled in production code

[MEDIUM] Hardcoded Secret (line 3): Possible hardcoded secret assigned to 'password'

[HIGH] Code Injection (line 6): Use of dangerous function 'eval'
