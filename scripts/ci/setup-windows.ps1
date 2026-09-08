# PowerShell script for setting up Rust and NASM on Windows in CircleCI

$ErrorActionPreference = "Stop"

# 1. Install NASM via Chocolatey if not present
if (!(Get-Command nasm -ErrorAction SilentlyContinue) -and !(Test-Path "C:\Program Files\NASM\nasm.exe")) {
    Write-Host "Installing NASM via Chocolatey..."
    choco install -y nasm
}
$nasmDir = "C:\Program Files\NASM"

# 2. Check / Install Rust via rustup
$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (!(Get-Command rustup -ErrorAction SilentlyContinue) -and !(Test-Path "$cargoBin\rustup.exe")) {
    Write-Host "Downloading rustup-init.exe..."
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"
    Write-Host "Running rustup-init..."
    .\rustup-init.exe -y --default-toolchain stable
    Remove-Item -Force rustup-init.exe
}

# 3. Add to Environment Path permanently for subsequent sessions
$combinedNewPaths = "$cargoBin;$nasmDir"
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$cargoBin*") {
    [Environment]::SetEnvironmentVariable("Path", "$combinedNewPaths;$machinePath", "Machine")
}
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$cargoBin*") {
    [Environment]::SetEnvironmentVariable("Path", "$combinedNewPaths;$userPath", "User")
}

# 4. Set PATH for current process & verify
$env:Path = "$combinedNewPaths;$env:Path"
rustup default stable
rustup component add clippy
rustc --version
cargo --version
