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
