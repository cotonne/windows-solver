# Windows CTF helper

Help solving CTF machines

## What does it do?

 - [ ] Scan port
 - [x] Run SMB shares scan on port 445
 - [x] Search for credentials in file
 - [x] Search for credentials in Groups.xml
 - [x] Search for Service Principal Names in LDAP / Kerberoasting
 - [x] Retry all actions for every new creds
 - [x] Pass "-nopass" when password is empty
 - [ ] Try to connect to WinRM
 - [ ] Try to connect to SMBEXEC
 - [ ] Try to connect to MSSQL if available
 - [ ] Perform Pass The Hash
 - [ ] Search for users and save them into users.txt
 - [ ] Search for passwords and save them into passwords.txt
 - [ ] Search for pre-auth users / AS-REP roasting
 - [ ] Try to crack hashes
 - [ ] Trusted delegation
 - Extract passwords from files
   * [x] pdf
   * [x] Policy Groups
