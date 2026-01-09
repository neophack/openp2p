@echo off
set "PATH=C:\Program Files\JetBrains\CLion 2025.2.3\bin\mingw\bin;%PATH%"
set CGO_ENABLED=1
set CC=gcc
set CXX=g++

echo Running OpenP2P CGO Compatibility Tests...
go test -v ./core -run TestCGOCompatibility
if %ERRORLEVEL% NEQ 0 (
    echo Tests failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ==========================================
echo All compatibility tests passed successfully!
echo ==========================================
pause
