@ECHO off

start "github-hosts" ./bin/mitmdump.exe -s ./src/github-hosts.py -p 8180
