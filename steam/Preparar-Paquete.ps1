param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+$')]
    [string]$AppId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+$')]
    [string]$DepotId
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$content = Join-Path $PSScriptRoot "content"
$output = Join-Path $PSScriptRoot "output"
$icons = Join-Path $content "icons"

New-Item -ItemType Directory -Force -Path $content, $output, $icons | Out-Null

$packageFiles = @(
    "index.html",
    "servidor.py",
    "iniciar_juego.py",
    "Iniciar Orbita.bat",
    "Iniciar Orbita.vbs"
)

foreach ($file in $packageFiles) {
    Copy-Item -Force (Join-Path $root $file) (Join-Path $content $file)
}

Copy-Item -Force (Join-Path $root "icons\orbita.ico") (Join-Path $icons "orbita.ico")
Copy-Item -Force (Join-Path $root "icons\orbita.svg") (Join-Path $icons "orbita.svg")
Copy-Item -Force (Join-Path $PSScriptRoot "Iniciar Orbita en Steam.bat") `
    (Join-Path $content "Iniciar Orbita en Steam.bat")

$contentPath = $content.Replace("\", "/")
$outputPath = $output.Replace("\", "/")
$depotConfig = @"
"DepotBuildConfig"
{
    "DepotID" "$DepotId"
    "ContentRoot" "$contentPath"
    "FileMapping"
    {
        "LocalPath" "*"
        "DepotPath" "."
        "recursive" "1"
    }
    "FileExclusion" "*.db"
    "FileExclusion" "*.db-*"
    "FileExclusion" "*.pyc"
    "FileExclusion" "__pycache__/*"
    "FileExclusion" "tools/*"
    "FileExclusion" "tests/*"
}
"@
$appConfig = @"
"AppBuild"
{
    "AppID" "$AppId"
    "Desc" "Orbita Windows build"
    "BuildOutput" "$outputPath"
    "ContentRoot" "$contentPath"
    "SetLive" ""
    "Depots"
    {
        "$DepotId" "depot_build.vdf"
    }
}
"@

Set-Content -Encoding ascii (Join-Path $PSScriptRoot "depot_build.vdf") $depotConfig
Set-Content -Encoding ascii (Join-Path $PSScriptRoot "app_build.vdf") $appConfig

Write-Host "Paquete preparado en: $content"
Write-Host "Configuracion SteamPipe: $(Join-Path $PSScriptRoot 'app_build.vdf')"
Write-Host "No se copiaron la base de datos ni las herramientas privadas."
Write-Host "Este paquete requiere Python 3 y Edge o Chrome; aun no es autonomo."
