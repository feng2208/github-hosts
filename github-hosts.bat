@ECHO off

start "github-hosts" ./bin/mitmdump.exe -s ./src/github-hosts.py --set flow_detail=0 -p 8180
