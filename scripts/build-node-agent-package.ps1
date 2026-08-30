param(
  [ValidateSet('amd64','arm64')]
  [string]$Architecture = 'amd64',
  [string]$Version = '1.1.0',
  [string]$OutputDirectory = '.cache/releases'
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repository $OutputDirectory))
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vram-governor-package-' + [guid]::NewGuid().ToString('N'))
$packageName = "vram-governor-node-agent-$Version-linux-$Architecture"
$stage = Join-Path $stageRoot $packageName
$archive = Join-Path $outputRoot ($packageName + '.tar.gz')
$previousEnvironment = @{
  GOOS = $env:GOOS
  GOARCH = $env:GOARCH
  CGO_ENABLED = $env:CGO_ENABLED
  GOTOOLCHAIN = $env:GOTOOLCHAIN
  GOPROXY = $env:GOPROXY
  GOSUMDB = $env:GOSUMDB
  GOPATH = $env:GOPATH
  GOCACHE = $env:GOCACHE
}

try {
  New-Item -ItemType Directory -Path $stage -Force | Out-Null
  New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

  $bundled = Join-Path $repository '.cache/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin/go.exe'
  if (Test-Path $bundled) {
    $goPath = (Resolve-Path $bundled).Path
  } else {
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) { throw 'Go 1.23.4 or newer is required' }
    $goPath = $go.Source
  }

  $env:GOOS = 'linux'
  $env:GOARCH = $Architecture
  $env:CGO_ENABLED = '0'
  $env:GOTOOLCHAIN = 'local'
  $env:GOPROXY = 'off'
  $env:GOSUMDB = 'off'
  $env:GOPATH = (Join-Path $repository '.cache/gopath')
  $env:GOCACHE = (Join-Path $repository '.cache/gocache')
  & $goPath build -buildvcs=false -trimpath -ldflags '-s -w' -o (Join-Path $stage 'vram-governor-node-agent') ./cmd/node-agent
  if ($LASTEXITCODE -ne 0) { throw 'node-agent build failed' }

  Copy-Item (Join-Path $repository 'packaging/node-agent/install.sh') $stage
  Copy-Item (Join-Path $repository 'packaging/node-agent/uninstall.sh') $stage
  Copy-Item (Join-Path $repository 'packaging/node-agent/README.txt') $stage
  Copy-Item (Join-Path $repository 'deploy/vram-governor-node-agent.service') $stage

  tar.exe -czf $archive -C $stageRoot $packageName
  if ($LASTEXITCODE -ne 0) { throw 'tar archive creation failed' }
  $checksum = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
  Set-Content -Path ($archive + '.sha256') -Value "$checksum  $($packageName).tar.gz" -Encoding ascii
  [pscustomobject]@{ Archive = $archive; SHA256 = $checksum; Architecture = $Architecture; Version = $Version }
}
finally {
  foreach ($entry in $previousEnvironment.GetEnumerator()) {
    Set-Item -Path ("Env:" + $entry.Key) -Value $entry.Value
  }
  if (Test-Path $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
}
