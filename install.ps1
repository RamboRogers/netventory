# PowerShell script to install NetVentory
$ErrorActionPreference = "Stop"

Write-Host "Installing NetVentory..." -ForegroundColor Blue

# Create temp directory
$tempDir = Join-Path $env:TEMP "netventory_install"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

# Download URL
$downloadUrl = "https://raw.githubusercontent.com/RamboRogers/netventory/master/bins/netventory.zip"
$zipPath = Join-Path $tempDir "netventory.zip"

try {
    # Download the zip file
    Write-Host "Downloading NetVentory..." -ForegroundColor Blue
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

    # Extract the zip
    Write-Host "Extracting files..." -ForegroundColor Blue
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

    # Find the exe
    $exePath = Get-ChildItem -Path $tempDir -Filter "netventory-windows-amd64.exe" -Recurse | Select-Object -First 1

    # Create destination directory in user's profile
    $installDir = "$env:USERPROFILE\.netventory"
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    # Copy the exe
    Write-Host "Installing NetVentory to $installDir..." -ForegroundColor Blue
    Copy-Item -Path $exePath.FullName -Destination "$installDir\netventory.exe" -Force

    # Add to PATH if not already there
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$installDir*") {
        Write-Host "Adding NetVentory to PATH..." -ForegroundColor Blue
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$userPath;$installDir",
            "User"
        )
    }

    Write-Host "NetVentory installed successfully!" -ForegroundColor Green
    Write-Host "Please restart your terminal, then run 'netventory -h' to see available options." -ForegroundColor Blue
}
catch {
    Write-Host "Error installing NetVentory: $_" -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}