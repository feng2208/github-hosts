@ECHO off

PowerShell ^
    cd ~/; ^
	certutil.exe -addstore root .mitmproxy/mitmproxy-ca-cert.cer
	
echo(
echo(
pause
