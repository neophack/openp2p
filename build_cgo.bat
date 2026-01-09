@echo off
set "PATH=C:\Program Files\JetBrains\CLion 2025.2.3\bin\mingw\bin;%PATH%"
set CGO_ENABLED=1
set CC=gcc
set CXX=g++

echo Building OpenP2P with CGO...
go build -o openp2p.exe ./cmd/openp2p.go
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b %ERRORLEVEL%
)
echo Build success: openp2p.exe
pause
