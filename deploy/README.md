# YARA Scanner Deployment Scripts

This directory contains scripts for deploying the YARA Scanner agent on Windows endpoints.

## Scripts

### install.ps1

Install the YARA Scanner as a Windows service:

```powershell
.\install.ps1
```

This will:
- Copy binaries to `C:\Program Files\YARA Scanner`
- Create a Windows service
- Start the service

### uninstall.ps1

Remove the YARA Scanner service:

```powershell
.\uninstall.ps1
```

### configure-gpo.md

See the separate document for Group Policy deployment instructions.

## Deployment Methods

### Method 1: Manual Deployment

1. Copy all files from the release to a network share
2. On each endpoint, run:
   ```powershell
   .\install.ps1
   ```

### Method 2: Intune/SCCM

Package the files and deploy via Intune or SCCM.

### Method 3: PowerShell Remoting

```powershell
$computers = Get-Content "computers.txt"
Invoke-Command -ComputerName $computers -ScriptBlock {
    $uri = "https://github.com/dominikszabo/yara-scanner/releases/latest/download/yara-scanner.zip"
    Invoke-WebRequest -Uri $uri -OutFile "C:\temp\yara-scanner.zip"
    Expand-Archive -Path "C:\temp\yara-scanner.zip" -DestinationPath "C:\Program Files\YARA Scanner"
    & "C:\Program Files\YARA Scanner\install.ps1"
}
```

## Post-Deployment Verification

Run the following on each endpoint to verify:

```powershell
# Check service status
Get-Service "YARA Scanner"

# Run a test scan
& "C:\Program Files\YARA Scanner\yara-scanner-agent.exe" scan "C:\Windows\Temp"
```
