# Windows/PowerShell version of fetch_sources.sh.
# Clones the public datasets the benchmark is built from (nothing is redistributed in this repo).
# Usage (from the repo root):  powershell -ExecutionPolicy Bypass -File bench\fetch_sources.ps1
param([string]$Dest = "bench\sources")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Push-Location $Dest
try {
    $repos = @(
        "microsoft/BIPIA",                    # MIT  - indirect injection benchmark (attacks + email/table contexts)
        "uiuc-kang-lab/InjecAgent",           # MIT  - tool-output injection cases
        "ethz-spylab/agentdojo",              # MIT  - agent injection goals + attack templates (large, ~560 MB)
        "HumanCompatibleAI/tensor-trust-data",# BSD-2 - human-written hijacking/extraction attacks (~260 MB)
        "mozilla/readability"                 # Apache-2.0 - 130 real-world web pages (benign HTML)
    )
    foreach ($r in $repos) {
        $name = $r.Split("/")[1]
        if (Test-Path $name) { Write-Host "$name already present, skipping"; continue }
        Write-Host "Cloning $r ..."
        git clone --depth 1 "https://github.com/$r.git"
        if ($LASTEXITCODE -ne 0) { throw "git clone failed for $r" }
    }
    Write-Host "Sources ready in $Dest"
}
finally { Pop-Location }