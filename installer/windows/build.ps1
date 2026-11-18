# Stage everything the installer ships: the official Node build (hash-checked against nodejs.org's
# SHASUMS256.txt) and StarClaw installed from its npm tarball with production dependencies only.
#   pwsh installer/windows/build.ps1 -Tarball starclaw-2.0.0-alpha.8.tgz -Out installer/windows/staging
param(
  [Parameter(Mandatory)] [string] $Tarball,
  [Parameter(Mandatory)] [string] $Out,
  [string] $NodeVersion = '25.9.0'
)
$ErrorActionPreference = 'Stop'
if (Test-Path $Out) { throw "$Out already exists; remove it first" }
# Native dependencies (better-sqlite3 via @mnemopay/sdk) are fetched prebuilt for the Node that runs npm,
# so that Node must be exactly the one we bundle, or the installed app fails to load them.
$running = (& node --version).Trim()
if ($running -ne "v$NodeVersion") { throw "npm runs on Node $running but the installer bundles v$NodeVersion; use the same version" }
$Tarball = (Resolve-Path $Tarball).Path
New-Item -ItemType Directory -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$dl = Join-Path $Out '_download'
New-Item -ItemType Directory -Path $dl | Out-Null

$name = "node-v$NodeVersion-win-x64"
$base = "https://nodejs.org/dist/v$NodeVersion"
Invoke-WebRequest "$base/$name.zip" -OutFile "$dl\$name.zip"
Invoke-WebRequest "$base/SHASUMS256.txt" -OutFile "$dl\SHASUMS256.txt"
$expected = (Select-String -Path "$dl\SHASUMS256.txt" -Pattern "^([0-9a-f]{64})\s+$([regex]::Escape("$name.zip"))$").Matches.Groups[1].Value
if (-not $expected) { throw "$name.zip is not listed in SHASUMS256.txt" }
$actual = (Get-FileHash "$dl\$name.zip" -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Node download hash mismatch: got $actual, nodejs.org lists $expected" }
Write-Host "node $NodeVersion zip sha256 $actual matches SHASUMS256.txt"
Expand-Archive "$dl\$name.zip" -DestinationPath $dl
Move-Item "$dl\$name" (Join-Path $Out 'node')

$app = Join-Path $Out 'app'
New-Item -ItemType Directory -Path $app | Out-Null
'{ "private": true }' | Out-File (Join-Path $app 'package.json') -Encoding ascii
# --omit=optional drops @mnemopay/sdk's local-embedding stack (@huggingface/transformers + onnxruntime,
# ~470 MB) from SDK 1.17.0 on; StarClaw never loads it.
& npm install --prefix $app --omit=dev --omit=optional --no-audit --no-fund $Tarball
if ($LASTEXITCODE -ne 0) { throw 'npm install of the StarClaw tarball failed' }
if (-not (Test-Path (Join-Path $app 'node_modules\starclaw\dist\cli.js'))) { throw 'starclaw/dist/cli.js missing after install' }

Copy-Item (Join-Path $PSScriptRoot 'StarClaw.cmd') $Out
Remove-Item -Recurse -Force $dl
$v = & (Join-Path $Out 'node\node.exe') (Join-Path $app 'node_modules\starclaw\dist\cli.js') --version
Write-Host "staged StarClaw $v with Node $NodeVersion in $Out"
