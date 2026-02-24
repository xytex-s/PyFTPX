param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [int]$Port = 40404,
    [string]$SampleFile = "sample.txt",
    [string]$OutDir = "recv",
    [string]$Payload = "PyFTPX smoke test payload",
    [int]$ReceiverTimeoutSec = 30,
    [int]$SenderTimeoutSec = 10
)

$ErrorActionPreference = "Stop"
$receiverJob = $null

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot

try {
    if (-not (Test-Path $PythonExe)) {
        throw "Python executable not found at '$PythonExe'."
    }

    $pythonPath = (Resolve-Path $PythonExe).Path
    $env:PYTHONPATH = "src"

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    Set-Content -Path $SampleFile -Value $Payload -NoNewline

    $receiverJob = Start-Job -ScriptBlock {
        param($root, $python, $port, $outDir, $receiverTimeoutSec)
        Set-Location $root
        $env:PYTHONPATH = "src"
        & $python -m pyftpx.cli receive --bind 127.0.0.1 --port $port --out $outDir --timeout $receiverTimeoutSec
    } -ArgumentList $repoRoot.Path, $pythonPath, $Port, $OutDir, $ReceiverTimeoutSec

    Start-Sleep -Milliseconds 500

    & $pythonPath -m pyftpx.cli send $SampleFile --host 127.0.0.1 --port $Port --timeout $SenderTimeoutSec

    $completed = Wait-Job -Job $receiverJob -Timeout ($ReceiverTimeoutSec + 5)
    if (-not $completed) {
        Stop-Job -Job $receiverJob -Force | Out-Null
        throw "Receiver did not complete within timeout."
    }

    $receiverOutput = Receive-Job -Job $receiverJob
    if ($receiverOutput) {
        Write-Host $receiverOutput
    }

    $sourceHash = (Get-FileHash $SampleFile -Algorithm SHA256).Hash
    $receivedFile = Join-Path $OutDir (Split-Path $SampleFile -Leaf)

    if (-not (Test-Path $receivedFile)) {
        throw "Expected received file '$receivedFile' was not created."
    }

    $receivedHash = (Get-FileHash $receivedFile -Algorithm SHA256).Hash

    if ($sourceHash -ne $receivedHash) {
        throw "Hash mismatch. source=$sourceHash received=$receivedHash"
    }

    Write-Host "Smoke test passed."
    Write-Host "Source hash  : $sourceHash"
    Write-Host "Received hash: $receivedHash"
}
finally {
    if ($receiverJob) {
        Remove-Job -Job $receiverJob -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}
