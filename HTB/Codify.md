#HTB-Codify

This machine can be viewed at: https://app.hackthebox.com/machines/Codify

##Phase 1: Initial Foothold

We begin the machine by enumerating the ports and services open using the following nmap scans

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

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/7f790118-aed2-4c60-bf03-ded91655ff39)

We begin some GoBuster scans in the background in case there are some hidden web directories, however, we can find three pages from the get go: /index, /about and /editor. We are mainly interested in /about and /editor.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/90a4e893-1fe7-4fa8-a8d5-9793c9d0578e)

- **/editor**: A simple page that allows the users compile and execute Node.js code on the web.

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/fb5f7ad8-74d0-4b4b-8db8-0efb0879fb40)

- **/about**: A simple about page, where we learn the page uses vm2 and is linked to the release version (3.9.16).

After we research about this vm2 version, we learn that there is an arbitrary code execution vulnerability
