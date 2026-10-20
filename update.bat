@echo off
setlocal
rem Update PuTTY MCP: pull the latest code and reinstall it.
rem Double-click this file, or run "update.bat" from this folder.

cd /d "%~dp0"
echo.
echo === PuTTY MCP update ===
echo.

rem 1. Claude must be closed: a running server locks its files, and pip
rem    then leaves a broken "~utty-mcp" install behind.
:check_claude
tasklist /FI "IMAGENAME eq Claude.exe" 2>nul | find /I "Claude.exe" >nul
if %errorlevel%==0 (
    echo Claude is still running. Close Claude completely ^(also the icon next to the clock^),
    echo then press a key to continue. Press Ctrl+C to cancel.
    pause >nul
    goto check_claude
)

rem 2. Stop leftover server processes
tasklist /FI "IMAGENAME eq putty-mcp.exe" 2>nul | find /I "putty-mcp.exe" >nul
if %errorlevel%==0 (
    echo Stopping leftover putty-mcp processes...
    taskkill /F /IM putty-mcp.exe >nul 2>&1
)

rem 3. Remove leftovers of an interrupted earlier update (~utty-mcp)
for /f "delims=" %%P in ('python -c "import site; print(site.getsitepackages()[-1])"') do set "SITE=%%P"
if defined SITE (
    for /d %%D in ("%SITE%\~utty*") do (
        echo Removing broken leftover: %%D
        rmdir /s /q "%%D"
    )
)

rem 4. Get the latest code
echo Pulling the latest version...
git pull
if errorlevel 1 (
    echo.
    echo git pull failed. If you changed files in this folder yourself, commit or undo
    echo those changes first ^(git status shows them^), then run this script again.
    pause
    exit /b 1
)

rem 5. Reinstall
echo.
echo Installing...
python -m pip install --upgrade .
if errorlevel 1 (
    echo.
    echo Installation failed; see the messages above.
    pause
    exit /b 1
)

echo.
rem Run from another folder so the installed package is checked, not this source folder
pushd "%TEMP%"
for /f "delims=" %%V in ('python -c "import putty_lib; print(putty_lib.__version__)"') do echo Installed PuTTY MCP %%V
popd
echo You can start Claude again.
echo.
pause
