@echo off
setlocal
if not defined VSINSTALLDIR (
    echo This script must run from a Visual Studio Developer Command Prompt.
    exit /b 1
)
set SRC=main.cpp
set OUT=whoexec.exe
cl /nologo /std:c++17 /W4 /EHsc /DUNICODE /D_UNICODE %SRC% ^
    advapi32.lib crypt32.lib psapi.lib userenv.lib wintrust.lib wtsapi32.lib user32.lib ^
    /Fe:%OUT%
