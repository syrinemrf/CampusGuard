[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$reportDirectory = Join-Path $repositoryRoot "reports"
$timestamp = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")
$reportPath = Join-Path $reportDirectory "feasibility-$timestamp.txt"
$reportLines = [System.Collections.Generic.List[string]]::new()
$hadError = $false

New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null

function Add-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $script:reportLines.Add("")
    $script:reportLines.Add("=== $Title ===")
    $script:reportLines.Add($Content)
}

$reportLines.Add("CampusGuard CORE - rapport de faisabilite")
$reportLines.Add("Date UTC: $timestamp")
$reportLines.Add("Depot: $repositoryRoot")

Push-Location $repositoryRoot
try {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $dockerCommand) {
        $hadError = $true
        Add-Section "docker compose ps --all" "Non execute: commande docker introuvable."
        Add-Section "docker stats" "Non execute: commande docker introuvable."
    }
    else {
        $composeOutput = & docker compose ps --all 2>&1
        $composeExitCode = $LASTEXITCODE
        $composeText = ($composeOutput | Out-String).TrimEnd()
        if ([string]::IsNullOrWhiteSpace($composeText)) {
            $composeText = "(aucune sortie)"
        }
        Add-Section "docker compose ps --all (exit $composeExitCode)" $composeText
        if ($composeExitCode -ne 0) {
            $hadError = $true
        }

        # Keep stderr out of the ID array: Compose warnings must never become
        # arguments to docker stats. The full diagnostics are captured above.
        $idOutput = & docker compose ps --quiet --status running 2>$null
        $idExitCode = $LASTEXITCODE
        if ($idExitCode -ne 0) {
            $hadError = $true
            Add-Section "docker stats" "Non execute: impossible d'obtenir les IDs du projet (exit $idExitCode); voir la sortie Compose ci-dessus."
        }
        else {
            $containerIds = @(
                $idOutput |
                    ForEach-Object { $_.ToString().Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )

            if ($containerIds.Count -eq 0) {
                $hadError = $true
                Add-Section "docker stats" "Non execute: aucun conteneur du projet n'est en cours d'execution."
            }
            else {
                # Supplying the Compose-owned IDs is essential: docker stats with
                # no IDs would measure every running container on the host.
                $statsArguments = @(
                    "stats",
                    "--no-stream",
                    "--format",
                    "table {{.Name}}`t{{.MemUsage}}`t{{.CPUPerc}}"
                ) + $containerIds
                $statsOutput = & docker @statsArguments 2>&1
                $statsExitCode = $LASTEXITCODE
                $statsText = ($statsOutput | Out-String).TrimEnd()
                if ([string]::IsNullOrWhiteSpace($statsText)) {
                    $statsText = "(aucune donnee)"
                }
                Add-Section "docker stats - conteneurs du projet uniquement (exit $statsExitCode)" $statsText
                if ($statsExitCode -ne 0) {
                    $hadError = $true
                }
            }
        }
    }

    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalGiB = [double]$operatingSystem.TotalVisibleMemorySize / 1MB
        $freeGiB = [double]$operatingSystem.FreePhysicalMemory / 1MB
        $usedGiB = $totalGiB - $freeGiB
        $usagePercent = if ($totalGiB -gt 0) { 100.0 * $usedGiB / $totalGiB } else { 0.0 }
        $memoryText = @(
            "Memoire totale : {0:N2} GiB" -f $totalGiB
            "Memoire utilisee : {0:N2} GiB" -f $usedGiB
            "Memoire disponible : {0:N2} GiB" -f $freeGiB
            "Utilisation : {0:N1} %" -f $usagePercent
        ) -join [Environment]::NewLine
        Add-Section "Memoire physique de l'hote Windows" $memoryText
    }
    catch {
        $hadError = $true
        Add-Section "Memoire physique de l'hote Windows" "Mesure impossible: $($_.Exception.Message)"
    }
}
finally {
    Pop-Location
    $reportLines.Add("")
    $reportLines.Add("Fin de mesure UTC: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))")
    $reportLines | Set-Content -LiteralPath $reportPath -Encoding UTF8
}

Write-Host "Rapport ecrit dans $reportPath"
if ($hadError) {
    exit 1
}
exit 0
