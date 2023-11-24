#HTB-Codify

This machine can be viewed at: https://app.hackthebox.com/machines/Codify

##Phase 1: External enumeration

We begin the machine by executing the following nmap scans

```markdown
sudo nmap -sS -p- -Pn -n --min-rate 5000 $IP
[sudo] password for rat: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-24 22:38 UTC
Nmap scan report for 10.10.11.239
Host is up (0.070s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 13.86 seconds
```

We notice SSH, an HTTP server on port 80 and a service which I don't know on port 3000. We proceed with the service enumeration scan:

```markdown
sudo nmap -sCV -p 22,80,3000 $IP
[sudo] password for rat: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-24 22:44 UTC
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.070s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Codify
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.68 seconds
```

We learn that the unknown service is a Node.js frame. We enter the web server to begin enumeration.
