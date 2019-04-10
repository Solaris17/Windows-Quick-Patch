@Echo off
SETLOCAL EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & Echo on & for %%b in (1) do     rem"') do (
  set "DEL=%%a"
)
title Windows Quick Patch V .9
cls

:checkPrivileges 
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto prechk) else ( goto getPrivileges ) 

:getPrivileges 
if '%1'=='ELEV' (shift & goto prechk)                               
for /f "delims=: tokens=*" %%A in ('findstr /b ::- "%~f0"') do @Echo(%%A
setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
Echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs" 
Echo UAC.ShellExecute "!batchPath!", "ELEV", "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs" 
"%temp%\OEgetPrivileges.vbs" 
exit /B

:prechk
set /p var=<C:\Step.txt
call :%var% 2> NUL

:Start
cls
Echo.
Echo This script is brought to you by Solaris17 of TPU
Echo.
Echo Details about what this does and updates can be found here http://couchit.net/windows-and-long-updates/
Echo.
Echo This script is for Windows Vista, 7 and 8. I didn't put alot of failsafe time into it.
Echo.
Echo This script should automatically run after rebooting.
Echo.
Echo This script will modify UAC settings to prevent script stalling.
Echo.
Echo This script connects ot the internet, some patches are quite large^^!
Echo.
Echo PLEASE DO NOT MANUALLY CHANGE SETTINGS OR INTERVENE^^!
Echo.
pause
copy %0 "%USERPROFILE%\Start Menu\Programs\Startup"
mkdir C:\WinqUD
set /p var=<C:\Step.txt
call :%var% 2> NUL

:UACREM
@echo off
cls
:: Dump the current settings
reg.exe export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "C:\WinqUD\backup.reg"
:: Disable UAC
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /d "0" /t REG_DWORD /F
:: Disable auto updates but not WU service or else WU gets excited when it can find patches and stalls the script.
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "0" /F
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /V "NoAutoUpdate" /T "REG_DWORD" /D "1" /F

:detect
@Echo off
cls
ver | findstr /i "5\.1\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
ver | findstr /i "5\.2\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
ver | findstr /i "6\.0\." > nul
IF %ERRORLEVEL% EQU 0 goto vista
ver | findstr /i "6\.1\." > nul
IF %ERRORLEVEL% EQU 0 goto win7
ver | findstr /i "6\.2\." > nul
IF %ERRORLEVEL% EQU 0 goto win8
ver | findstr /i "6\.3\." > nul
IF %ERRORLEVEL% EQU 0 goto win8
ver | findstr /i "10\.0\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
goto warn

:warn
Echo.
Echo This is not Windows Vista, 7, or 8. This won't work for you.
Echo.
pause
goto exit

:vista
:: Get OS Architecture
Echo.
wmic os get osarchitecture | findstr /i "64-bit" > nul
IF %ERRORLEVEL% EQU 0 goto vista64BIT
wmic os get osarchitecture | findstr /i "32-bit" > nul
IF %ERRORLEVEL% EQU 0 goto vista32BIT

:vista64BIT
:: Get 64bit patches
@Echo vista64BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3078601 (Update 1 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2015/08/windows6.0-kb3078601-x64_ef7d88846dbf568b534901f434c99274d7ef580f.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3109094 (Update 2 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2015/11/windows6.0-kb3109094-x64_7c7fb9690a32483e79d600b6886e5bfc4d3fe71c.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3185911 (Update 3 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2016/08/windows6.0-kb3185911-x64_b3edd2f8de09e7451767ee73658ec54b394228c3.msu C:\WinqUD\3rd.msu
bitsadmin.exe /transfer "Downloading KB3191203 (Update 4 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/09/windows6.0-kb3191203-x64_05e165673951228ca651faa659dd24341efda6f4.msu C:\WinqUD\4th.msu
bitsadmin.exe /transfer "Downloading KB3198234 (Update 5 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2016/10/windows6.0-kb3198234-x64_d35cbdb3fee35903e7ea4901a38f18f9376cd94f.msu C:\WinqUD\5th.msu
bitsadmin.exe /transfer "Downloading KB3203859 (Update 6 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/11/windows6.0-kb3203859-x64_a5276a41e72f8888572d5459c6a757fe28844706.msu C:\WinqUD\6th.msu
bitsadmin.exe /transfer "Downloading KB3205638 (Update 7 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/11/windows6.0-kb3205638-x64_a52aaa009ee56ca941e21a6009c00bc4c88cbb7c.msu C:\WinqUD\7th.msu
bitsadmin.exe /transfer "Downloading KB4012583 (Update 8 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows6.0-kb4012583-x64_f63c9a85aa877d86c886e432560fdcfad53b752d.msu C:\WinqUD\8th.msu
bitsadmin.exe /transfer "Downloading KB4015195 (Update 9 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/03/windows6.0-kb4015195-x64_2e310724d86b6a43c5ae8ec659685dd6cfb28ba4.msu C:\WinqUD\9th.msu
bitsadmin.exe /transfer "Downloading KB4015380 (Update 10 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/03/windows6.0-kb4015380-x64_959aedbe0403d160be89f4dac057e2a0cd0c6d40.msu C:\WinqUD\10th.msu
bitsadmin.exe /transfer "Downloading KB4018466 (Sec Update 1 of 4)" http://download.windowsupdate.com/c/csa/csa/secu/2017/04/windows6.0-kb4018466-x64-custom_f745d7719f346e656afb0cb2fae119d303a689a0.msu C:\WinqUD\Sec1st.msu
bitsadmin.exe /transfer "Downloading KB4021903 (Sec Update 2 of 4)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows6.0-kb4021903-x64_d945e443391871f55a9d01d3fdd4c6c48370ecec.msu C:\WinqUD\Sec2nd.msu
bitsadmin.exe /transfer "Downloading KB4024402 (Sec Update 3 of 4)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/06/windows6.0-kb4024402-x64-custom_a53e6cda8028f207a3664e12ee23e401914e55a9.msu C:\WinqUD\Sec3rd.msu
bitsadmin.exe /transfer "Downloading KB4019204 (Sec Update 4 of 4)" http://download.windowsupdate.com/c/csa/csa/secu/2017/05/windows6.0-kb4019204-x64-custom_d9d9d6baa3ea706ff7148ca2c0a06f861c1d77c4.msu C:\WinqUD\Sec4th.msu
goto step2

:vista32BIT
:: Get 32bit patches
@Echo vista32BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3078601 (Update 1 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2015/08/windows6.0-kb3078601-x86_f1cb8512dbc3b00959237a0cfc831e2779ebc6ed.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3109094 (Update 2 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2015/11/windows6.0-kb3109094-x86_4db5c730ad9adb0d12ddd522a5173dc4bb3cbd00.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3185911 (Update 3 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2016/08/windows6.0-kb3185911-x86_2e8f1048893ba89b73be7bb0a3ee664fdfee6a14.msu C:\WinqUD\3rd.msu
bitsadmin.exe /transfer "Downloading KB3191203 (Update 4 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/09/windows6.0-kb3191203-x86_0a0aa9355bf35baac6a07d4f41ee06918e5c067b.msu C:\WinqUD\4th.msu
bitsadmin.exe /transfer "Downloading KB3198234 (Update 5 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2016/10/windows6.0-kb3198234-x86_965d8e33da8e948e45e47ecb56837ce2028a8bcb.msu C:\WinqUD\5th.msu
bitsadmin.exe /transfer "Downloading KB3203859 (Update 6 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/11/windows6.0-kb3203859-x86_722738430267470c95ed36e962e799af92695b0e.msu C:\WinqUD\6th.msu
bitsadmin.exe /transfer "Downloading KB3205638 (Update 7 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/11/windows6.0-kb3205638-x86_e2211e9a6523061972decd158980301fc4c32a47.msu C:\WinqUD\7th.msu
bitsadmin.exe /transfer "Downloading KB4012583 (Update 8 of 10)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows6.0-kb4012583-x86_1887cb5393b62cbd2dbb6a6ff6b136e809a2fbd0.msu C:\WinqUD\8th.msu
bitsadmin.exe /transfer "Downloading KB4015195 (Update 9 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/03/windows6.0-kb4015195-x86_eb045e0144266b20b615f29fa581c4001ebb7852.msu C:\WinqUD\9th.msu
bitsadmin.exe /transfer "Downloading KB4015380 (Update 10 of 10)" http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/03/windows6.0-kb4015380-x86_3f3548db24cf61d6f47d2365c298d739e6cb069a.msu C:\WinqUD\10th.msu
bitsadmin.exe /transfer "Downloading KB4018466 (Sec Update 1 of 4)" http://download.windowsupdate.com/c/csa/csa/secu/2017/04/windows6.0-kb4018466-x86-custom_ff895d127be20344a0905d8f5bac2712b15d5c42.msu C:\WinqUD\Sec1st.msu
bitsadmin.exe /transfer "Downloading KB4021903 (Sec Update 2 of 4)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows6.0-kb4021903-x86_e242c183d5161a316b402855f03c57150ef59cf4.msu C:\WinqUD\Sec2nd.msu
bitsadmin.exe /transfer "Downloading KB4024402 (Sec Update 3 of 4)" http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/06/windows6.0-kb4024402-x86-custom_fd416b75f530305df455c1ea9098eccd48acb103.msu C:\WinqUD\Sec3rd.msu
bitsadmin.exe /transfer "Downloading KB4019204 (Sec Update 4 of 4)" http://download.windowsupdate.com/c/csa/csa/secu/2017/05/windows6.0-kb4019204-x86-custom_cc1a90841c15759e36c5095580dfb0b32b34eb8a.msu C:\WinqUD\Sec4th.msu
goto step2

:win7
:: Get OS Architecture
Echo.
wmic os get osarchitecture | findstr /i "64-bit" > nul
IF %ERRORLEVEL% EQU 0 goto 764BIT
wmic os get osarchitecture | findstr /i "32-bit" > nul
IF %ERRORLEVEL% EQU 0 goto 732BIT

:764BIT
:: Get 64bit patches
@Echo 764BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3020369 (Update 1 of 3)" https://download.microsoft.com/download/5/D/0/5D0821EB-A92D-4CA2-9020-EC41D56B074F/Windows6.1-KB3020369-x64.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3172605 (Update 2 of 3)" https://download.microsoft.com/download/5/6/0/560504D4-F91A-4DEB-867F-C713F7821374/Windows6.1-KB3172605-x64.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3125574 (Update 3 of 3)" http://download.windowsupdate.com/d/msdownload/update/software/updt/2016/05/windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu C:\WinqUD\3rd.msu
goto step2

:732BIT
:: Get 32bit patches
@Echo 732BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3020369 (Update 1 of 3)" https://download.microsoft.com/download/C/0/8/C0823F43-BFE9-4147-9B0A-35769CBBE6B0/Windows6.1-KB3020369-x86.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3172605 (Update 2 of 3)" https://download.microsoft.com/download/C/D/5/CD5DE7B2-E857-4BD4-AA9C-6B30C3E1735A/Windows6.1-KB3172605-x86.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3125574 (Update 3 of 3)" http://download.windowsupdate.com/d/msdownload/update/software/updt/2016/05/windows6.1-kb3125574-v4-x86_ba1ff5537312561795cc04db0b02fbb0a74b2cbd.msu C:\WinqUD\3rd.msu
goto step2

:win8
:: Get OS Architecture
Echo.
wmic os get osarchitecture | findstr /i "64-bit" > nul
IF %ERRORLEVEL% EQU 0 goto 864BIT
wmic os get osarchitecture | findstr /i "32-bit" > nul
IF %ERRORLEVEL% EQU 0 goto 832BIT

:864BIT
:: Get 64bit patches
@Echo 864BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3021910 (Update 1 of 5)" https://download.microsoft.com/download/6/1/5/615B8D87-A02C-485E-B9B5-D6F4AEB52D78/Windows8.1-KB3021910-x64.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3173424 (Update 2 of 5)" https://download.microsoft.com/download/D/B/4/DB4B93B5-5E6B-4FC4-85A9-0C0FC82DF07F/Windows8.1-KB3173424-x64.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3172614 (Update 3 of 5)" https://download.microsoft.com/download/3/0/D/30DB904F-EA28-4CE9-A4C8-1BD660D43607/Windows8.1-KB3172614-x64.msu C:\WinqUD\3rd.msu
bitsadmin.exe /transfer "Downloading KB2919355 (Update 4 of 5)" https://download.microsoft.com/download/D/B/1/DB1F29FC-316D-481E-B435-1654BA185DCF/Windows8.1-KB2919355-x64.msu C:\WinqUD\4th.msu
bitsadmin.exe /transfer "Downloading KB3138615 (Update 5 of 5)" https://download.microsoft.com/download/8/8/A/88AFE5D4-0021-4384-9D64-5411257CCC5B/Windows8.1-KB3138615-x64.msu C:\WinqUD\5th.msu
goto step2

:832BIT
:: Get 32bit patches
@Echo 832BIT > C:\Step.txt
cls
Echo.
Echo Step 1 of 6
Echo.
Echo Downloading KB updates.
Echo.
bitsadmin.exe /transfer "Downloading KB3021910 (Update 1 of 5)" https://download.microsoft.com/download/2/B/8/2B832205-A313-45A4-9356-DF5E47B70663/Windows8.1-KB3021910-x86.msu C:\WinqUD\1st.msu
bitsadmin.exe /transfer "Downloading KB3173424 (Update 2 of 5)" https://download.microsoft.com/download/4/5/F/45F8AA2A-1C72-460A-B9E9-83D3966DDA46/Windows8.1-KB3173424-x86.msu C:\WinqUD\2nd.msu
bitsadmin.exe /transfer "Downloading KB3172614 (Update 3 of 5)" https://download.microsoft.com/download/E/5/8/E5864645-6391-4D75-BB2C-7D7F05EF7D13/Windows8.1-KB3172614-x86.msu C:\WinqUD\3rd.msu
bitsadmin.exe /transfer "Downloading KB2919355 (Update 4 of 5)" https://download.microsoft.com/download/4/E/C/4EC66C83-1E15-43FD-B591-63FB7A1A5C04/Windows8.1-KB2919355-x86.msu C:\WinqUD\4th.msu
bitsadmin.exe /transfer "Downloading KB3138615 (Update 5 of 5)" https://download.microsoft.com/download/9/6/4/964EE585-03DC-441A-AA99-6A39BA731869/Windows8.1-KB3138615-x86.msu C:\WinqUD\5th.msu
goto step2

:step2
:: Kill windows update Services
@Echo step2 > C:\Step.txt
cls
Echo.
Echo Step 2 of 6
Echo.
Echo Killing Services etc
SC stop wuauserv
rmdir c:\windows\softwaredistribution\WuRedir /s /q
shutdown /r /t 60 /c "Stage Complete: Process will continue after restart."
@Echo step3 > C:\Step.txt
exit


:step3
@Echo step3 > C:\Step.txt
:: Installing first MSU
SC stop wuauserv
cls
Echo.
Echo Step 3 of 6
Echo.
time /t
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 15min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\1st.msu /quiet /norestart
shutdown /r /t 60 /c "Stage Complete: Process will continue after restart."
@Echo step4 > C:\Step.txt
exit

:step4
@Echo step4 > C:\Step.txt
:: Installing second MSU
SC stop wuauserv
cls
Echo.
Echo Step 4 of 6
Echo.
time /t
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 15min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\2nd.msu /quiet /norestart
shutdown /r /t 60 /c "Stage Complete: Process will continue after restart."
@Echo step5 > C:\Step.txt
exit

:step5
@Echo step5 > C:\Step.txt
:: Installing third MSU
SC stop wuauserv
cls
Echo.
Echo Step 5 of 6
Echo.
time /t
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 35min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\3rd.msu /quiet /norestart
shutdown /r /t 60 /c "Stage Complete: Process will continue after restart."
@Echo chk2 > C:\Step.txt
exit

:chk2
@Echo off
cls
ver | findstr /i "5\.1\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
ver | findstr /i "5\.2\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
ver | findstr /i "6\.0\." > nul
IF %ERRORLEVEL% EQU 0 goto vista4
ver | findstr /i "6\.1\." > nul
IF %ERRORLEVEL% EQU 0 goto step6
ver | findstr /i "6\.2\." > nul
IF %ERRORLEVEL% EQU 0 goto win8
ver | findstr /i "6\.3\." > nul
IF %ERRORLEVEL% EQU 0 goto win8
ver | findstr /i "10\.0\." > nul
IF %ERRORLEVEL% EQU 0 goto warn
goto step6

:win8
@Echo win8 > C:\Step.txt
:: Installing Extra MSUs
SC stop wuauserv
cls
Echo.
Echo Step 5 1/2 of 6
Echo.
time /t
Echo.
Echo Extra patche(s) in progress, these are added as they become relevant.
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 35min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\4th.msu /quiet /norestart
Start /wait C:\WinqUD\5th.msu /quiet /norestart
shutdown /r /t 60 /c "Security Patches Complete: Process will continue after restart."
@Echo step6 > C:\Step.txt
exit

:vista4
@Echo vista4 > C:\Step.txt
:: Installing extra MSUs
SC stop wuauserv
cls
Echo.
Echo Step 5 1/2 of 6
Echo.
time /t
Echo.
Echo Extra patche(s) in progress, these are added as they become relevant.
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 35min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\4th.msu /quiet /norestart
Start /wait C:\WinqUD\5th.msu /quiet /norestart
Start /wait C:\WinqUD\6th.msu /quiet /norestart
Start /wait C:\WinqUD\7th.msu /quiet /norestart
Start /wait C:\WinqUD\8th.msu /quiet /norestart
Start /wait C:\WinqUD\9th.msu /quiet /norestart
Start /wait C:\WinqUD\10th.msu /quiet /norestart
shutdown /r /t 60 /c "Extra Complete: Process will continue after restart."
@Echo secinstall > C:\Step.txt
exit

:secinstall
@Echo secinstall > C:\Step.txt
:: Installing Security MSUs
SC stop wuauserv
cls
Echo.
Echo Step 5 3/4 of 6
Echo.
time /t
Echo.
Echo Security patche(s) in progress, these are added as they become relevant.
Echo.
Echo Starting Install...
Echo.
Echo This can take a long time; Average is 35min, reboot if machine hangs.
Echo.
Echo Do NOT attempt to run Windows Update during patching^^!
Echo.
Echo To check to see if it's working "TrustedInstaller/SVCHOST" should be going nuts.
Echo.
Start /wait C:\WinqUD\Sec1st.msu /quiet /norestart
Start /wait C:\WinqUD\Sec2nd.msu /quiet /norestart
Start /wait C:\WinqUD\Sec3rd.msu /quiet /norestart
Start /wait C:\WinqUD\Sec4th.msu /quiet /norestart
shutdown /r /t 60 /c "Security Patches Complete: Process will continue after restart."
@Echo step6 > C:\Step.txt
exit


:step6
Echo.
:: Cleaning up files etc
SC stop wuauserv
cls
reg.exe import "C:\WinqUD\backup.reg"
rmdir C:\WinqUD /s /q
del C:\Step.txt
Echo.
Echo Step 6 of 6
Echo.
Echo Complete^^!
Echo.
Echo You should now be able to continue Windows Updates as normal.
Echo.
Echo You can delete this script after it closes if you wish.
Echo.
Echo This script will now delete itself from startup.
Echo.
Echo This script will now attempt to restore UAC settings.
Echo.
pause
goto exit

:exit
cls
:: For Vista re-enable open file security warning & auto-updates.
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "1" /F
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /V "NoAutoUpdate" /T "REG_DWORD" /D "0" /F
:: For everyone else load dumped reg settings for UAC
reg.exe import "C:\WinqUD\backup.reg"
shutdown /r /t 60 /c "Restoring UAC: Rebooting Machine."
rmdir C:\WinqUD /s /q
del C:\Step.txt
del "%USERPROFILE%\Start Menu\Programs\Startup\*.bat"
exit

::v9 Added Extra patches to bring Vista into 2017. Melvis forced me to do this on my brutally slow I5. Improved Windows 8 Patches.
::v8 Added UAC disable feature for even mroe touchless approach. Fixed some typos. Clarified instructions.
::v7 Changed batch layout to a more universal install process and rebuilt the downloads section for easier modification. Added /norestart flag.
::v6 Added Vista Support.
::v5 Added Windows 8 Support.
::v4 Fixed bug with other windows versions leaving script in startup. | Clarified actions needed by user | Improved Architecture check | Improved chance script won't hang via WU
::v3 Added /quiet | Fixed bug with other windows versions leaving script in startup. | Put check for previous run at head to skip start text.