# CodeAlpha_BugbountyTool
It is aligned with how entry-level to junior bug bounty researchers and SOC analysts work during code review.

## Designed to detect 
**1️Security vulnerabilities**
-

| No. | Category                         | Severity | Type                      |
| --: | -------------------------------- | -------- | ------------------------- |
|   1 | Code Injection (`eval`, `exec`)  | HIGH     | Injection                 |
|   2 | Command Injection (`shell=True`) | HIGH     | Injection                 |
|   3 | Hardcoded Secrets                | MEDIUM   | Sensitive Data Exposure   |
|   4 | Debug Mode Enabled               | HIGH     | Security Misconfiguration |
|   5 | Weak Cryptography (MD5 / SHA1)   | MEDIUM   | Cryptographic Failure     |
|   6 | Logic Flaw (`== None`)           | LOW      | Logic Error               |
