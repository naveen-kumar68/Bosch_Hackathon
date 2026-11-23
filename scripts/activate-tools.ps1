# Dot-source from PowerShell: . .\scripts\activate-tools.ps1
$guardianRoot = Split-Path -Parent $PSScriptRoot
$guardianPaths = @(
    (Join-Path $guardianRoot '.venv\Scripts'),
    (Join-Path $guardianRoot '.tools\syft'),
    (Join-Path $guardianRoot '.tools\cargo-cyclonedx'),
    (Join-Path $env:USERPROFILE '.cargo\bin'),
    (Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin'),
    (Join-Path $env:USERPROFILE 'anaconda3\Scripts')
)
$env:PATH = ($guardianPaths -join [IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $env:PATH
$env:PYTHONUTF8 = '1'
