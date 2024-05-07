@ECHO off

start "spotify auth" mitmdump.exe -s github-hosts.py -p 8180 --set spotify_auth
