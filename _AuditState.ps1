# =============================================================================
# Sentinel Lookout - shared checkpoint / resume / parallel-worker helpers.
#
# Dot-source from Audit-*.ps1 scripts:
#     . "$PSScriptRoot/_AuditState.ps1"
#
# Provides:
#   Initialize-AuditState        - create or reattach to a state directory
#   Test-SubscriptionDone        - is this sub's .done marker present?
#   Set-SubscriptionDone         - atomically write .done marker
#   Write-AuditError             - append a non-fatal error to errors.jsonl
#   Add-CsvRow                   - per-row append to a per-worker partial CSV
#   Merge-PartialCsvs            - merge & sort partials into final output
#   Invoke-ArmRequest            - Invoke-AzRestMethod with bounded retry
#   Get-WorkerFunctionDefinitions - bundle helpers for ForEach-Object -Parallel
# =============================================================================

function Initialize-AuditState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $Kind,
        [switch] $Force
    )

    foreach ($sub in @('', 'subscriptions', 'partials', 'errors')) {
        $p = if ($sub) { Join-Path $StatePath $sub } else { $StatePath }
        if (-not (Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
        }
    }

    $manifestPath = Join-Path $StatePath 'manifest.json'
    if (Test-Path $manifestPath) {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.tenantId -ne $TenantId -and -not $Force) {
            throw "State directory '$StatePath' was created for tenant $($manifest.tenantId); current context is $TenantId. Pass -Force to override."
        }
        if ($manifest.kind -ne $Kind) {
            throw "State directory '$StatePath' was created by '$($manifest.kind)'; cannot resume with '$Kind'. Use a different -StatePath."
        }
        $doneCount = (Get-ChildItem -Path (Join-Path $StatePath 'subscriptions') -Filter '*.done' -ErrorAction SilentlyContinue).Count
        Write-Host "Resuming run $($manifest.runId) (started $($manifest.started); $doneCount sub(s) already complete)" -ForegroundColor Green
        return $manifest
    }

    $manifest = [ordered]@{
        runId         = [guid]::NewGuid().ToString()
        kind          = $Kind
        tenantId      = $TenantId
        outputPath    = $OutputPath
        started       = (Get-Date).ToString('o')
        schemaVersion = 1
    }
    $manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Encoding UTF8
    Write-Host "Created new run $($manifest.runId)" -ForegroundColor Cyan
    return [pscustomobject]$manifest
}

function Test-SubscriptionDone {
    param(
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $SubscriptionId
    )
    Test-Path (Join-Path $StatePath "subscriptions/$SubscriptionId.done")
}

function Set-SubscriptionDone {
    param(
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [hashtable] $Stats = @{}
    )
    $marker = Join-Path $StatePath "subscriptions/$SubscriptionId.done"
    $tmp    = "$marker.tmp"
    $payload = @{ subId = $SubscriptionId; completedAt = (Get-Date).ToString('o') } + $Stats
    ($payload | ConvertTo-Json -Compress) | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $marker -Force
}

function Write-AuditError {
    param(
        [Parameter(Mandatory)] [string] $StatePath,
        [string] $SubscriptionId = '',
        [string] $Phase          = '',
        [string] $Target         = '',
        [Parameter(Mandatory)] [string] $Message
    )
    $line = [pscustomobject]@{
        ts      = (Get-Date).ToString('o')
        sub     = $SubscriptionId
        phase   = $Phase
        target  = $Target
        message = $Message
    } | ConvertTo-Json -Compress
    Add-Content -Path (Join-Path $StatePath 'errors/errors.jsonl') -Value $line -Encoding UTF8
}

# Append a single row to a per-worker CSV. No cross-runspace locking is needed
# because each worker has its own file (e.g. partials/dcrs.<subId>.csv).
function Add-CsvRow {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [pscustomobject] $Row
    )
    if (-not (Test-Path $Path)) {
        $Row | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    } else {
        $line = $Row | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
        Add-Content -Path $Path -Value $line -Encoding UTF8
    }
}

function Merge-PartialCsvs {
    param(
        [Parameter(Mandatory)] [string]   $PartialsDir,
        [Parameter(Mandatory)] [string]   $Filter,
        [Parameter(Mandatory)] [string]   $OutputPath,
        [string[]] $SortBy = @(),
        [switch]   $Descending
    )
    $files = Get-ChildItem -Path $PartialsDir -Filter $Filter -ErrorAction SilentlyContinue
    if (-not $files -or $files.Count -eq 0) {
        Write-Warning "No partial CSV files matched '$Filter' under '$PartialsDir'. Output not written."
        return @()
    }
    $all = foreach ($f in $files) { Import-Csv -Path $f.FullName }
    if ($SortBy.Count -gt 0) {
        if ($Descending) {
            $all = $all | Sort-Object -Property $SortBy -Descending
        } else {
            $all = $all | Sort-Object -Property $SortBy
        }
    }
    $all | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    return $all
}

# Bounded-retry wrapper around Invoke-AzRestMethod. Treats 429 / 5xx as transient.
function Invoke-ArmRequest {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [string] $Method     = 'GET',
        [int]    $MaxAttempts = 4
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $r = Invoke-AzRestMethod -Method $Method -Uri $Uri -ErrorAction Stop
        } catch {
            if ($attempt -ge $MaxAttempts) { throw }
            Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempt)))
            continue
        }
        if (($r.StatusCode -eq 429 -or $r.StatusCode -ge 500) -and $attempt -lt $MaxAttempts) {
            Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempt)))
            continue
        }
        return $r
    }
}

# Bundle the helper functions above (plus any extras the caller provides) into
# a hashtable suitable for $using: import inside ForEach-Object -Parallel:
#
#   $fnDefs = Get-WorkerFunctionDefinitions -Extra @('My-Helper')
#   $items | ForEach-Object -Parallel {
#       $defs = $using:fnDefs
#       foreach ($n in $defs.Keys) { Set-Item -Path "function:$n" -Value $defs[$n] }
#       ...
#   }
function Get-WorkerFunctionDefinitions {
    param([string[]] $Extra = @())
    $base = @(
        'Test-SubscriptionDone'
        'Set-SubscriptionDone'
        'Write-AuditError'
        'Add-CsvRow'
        'Invoke-ArmRequest'
    )
    $names = @($base) + @($Extra)
    $defs = @{}
    foreach ($n in $names) {
        $cmd = Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue
        if (-not $cmd) { throw "Function '$n' not found; cannot bundle for parallel workers." }
        $defs[$n] = $cmd.Definition
    }
    return $defs
}
