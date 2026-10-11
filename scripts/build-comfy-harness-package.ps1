param(
  [string]$Version = "0.1.0",
  [ValidateSet("amd64", "arm64")]
  [string]$Architecture = "amd64",
  [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"
$repository = Split-Path -Parent $PSScriptRoot
$go = Join-Path $repository ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe"
if (-not (Test-Path -LiteralPath $go)) {
  $go = (Get-Command go -ErrorAction Stop).Source
}
$packageName = "vram-governor-comfy-harness-$Version-linux-$Architecture"
$outputRoot = Join-Path $repository $OutputDirectory
$stage = Join-Path $outputRoot $packageName
$archive = Join-Path $outputRoot "$packageName.zip"

New-Item -ItemType Directory -Force -Path $stage | Out-Null
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$previousGOTOOLCHAIN = $env:GOTOOLCHAIN
$previousGOPROXY = $env:GOPROXY
$previousGOCACHE = $env:GOCACHE
$previousGOMODCACHE = $env:GOMODCACHE
try {
  $env:GOOS = "linux"
  $env:GOARCH = $Architecture
  $env:CGO_ENABLED = "0"
  $env:GOTOOLCHAIN = "local"
  $env:GOPROXY = "off"
  $env:GOCACHE = Join-Path $repository ".cache\go-build-harness-linux-$Architecture"
  $env:GOMODCACHE = Join-Path $repository ".cache\gopath\pkg\mod"
  New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null
  & $go build -buildvcs=false -trimpath -ldflags "-s -w" -o (Join-Path $stage "vram-governor-comfy-harness") ./cmd/comfy-harness
  if ($LASTEXITCODE -ne 0) { throw "comfy harness build failed" }
} finally {
  $env:GOOS = $previousGOOS
  $env:GOARCH = $previousGOARCH
  $env:CGO_ENABLED = $previousCGO
  $env:GOTOOLCHAIN = $previousGOTOOLCHAIN
  $env:GOPROXY = $previousGOPROXY
  $env:GOCACHE = $previousGOCACHE
  $env:GOMODCACHE = $previousGOMODCACHE
}
Copy-Item (Join-Path $repository "deploy/comfy-harness.service") $stage
Copy-Item (Join-Path $repository "configs/fleet/comfy-harness.env.example") $stage
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $archive
Write-Output "comfy harness package built: $archive"
