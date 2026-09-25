@echo off
target\debug\deps\zcode_switch_lib-af41daae847d88ef.exe --list > test-out.txt 2> test-err.txt
echo RC=%ERRORLEVEL%
