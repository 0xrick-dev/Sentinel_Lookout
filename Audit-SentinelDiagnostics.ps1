<#
.SYNOPSIS
    Audits diagnostic settings across all subscriptions in a tenant and identifies
    which resources are sending logs to a Microsoft Sentinel-enabled Log Analytics Workspace.
    Supports parallel workers and resume-on-rerun for large tenants.

.DESCRIPTION
    - Discovers all Log Analytics Workspaces with Sentinel (SecurityInsights) enabled.
    - Iterates over every subscription / resource the signed-in identity can read.
    - Retrieves diagnostic settings for each resource and notes the destination workspace
      and which log categories / metrics are enabled.
    - Adds Entra ID (Azure AD) diagnostic settings separately, since Entra is tenant-scoped
      and not returned by Get-AzResource.
    - Exports a CSV with: ResourceName, ResourceType, LogAnalyticsWorkspace, DiagnosticData,
      SentinelEnabled, SubscriptionName, ResourceGroup.

    Tracking & resume:
        Per-subscription progress is written to a sidecar state directory next to
        -OutputPath (default '<OutputPath>.state'). Each diagnostic-setting row is
        appended to a per-subscription partial CSV immediately, so an interrupted
        run loses at most the in-flight subscription. On rerun the script
        reattaches and skips subscriptions whose .done marker is present.

    Parallelism:
        On PowerShell 7+ subscriptions are processed concurrently with
        ForEach-Object -Parallel (default 4 workers, configurable via
        -ThrottleLimit). The constant ARM traffic also helps prevent Azure
        Cloud Shell's 20-minute idle timeout from killing the session.

.PARAMETER OutputPath
    Final CSV path.

.PARAMETER ThrottleLimit
    Maximum number of subscriptions to process in parallel. Default 4.

.PARAMETER StatePath
    Override the state directory location. Default: '<OutputPath>.state'.

.PARAMETER Force
    Allow resuming a state directory whose recorded tenantId differs from the
    current Az context. Use with care.

.PARAMETER CleanState
    Delete the state directory after a successful run. Errors.jsonl is preserved
    as '<OutputPath>.errors.jsonl' if any non-fatal errors were recorded.

.EXAMPLE
    ./Audit-SentinelDiagnostics.ps1
        Run with defaults; resumes automatically if the state directory exists.

.EXAMPLE
    ./Audit-SentinelDiagnostics.ps1 -ThrottleLimit 8

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout

    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell)
    and Microsoft.Graph.Identity.DirectoryManagement for Entra ID diagnostic settings.
    PowerShell 7+ is required for parallel execution; PS5.1 is not supported.

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.
#>

[CmdletBinding()]
param(
    [string] $OutputPath    = "$HOME/SentinelDiagnosticsAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]    $ThrottleLimit = 4,
    [string] $StatePath,
    [switch] $Force,
    [switch] $CleanState
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "PowerShell 7+ is required (parallel workers use ForEach-Object -Parallel). Detected: $($PSVersionTable.PSVersion). Run inside Cloud Shell PowerShell or install pwsh."
    return
}

if (-not $StatePath) { $StatePath = $OutputPath + '.state' }

. "$PSScriptRoot/_AuditState.ps1"

# ---------------------------------------------------------------------------
# 0. Sanity check
# ---------------------------------------------------------------------------
$ctx = Get-AzContext
if (-not $ctx) {
    Write-Host "Not signed in. Run Connect-AzAccount first." -ForegroundColor Red
    return
}
Write-Host "Signed in as : $($ctx.Account.Id)" -ForegroundColor Cyan
Write-Host "Tenant       : $($ctx.Tenant.Id)" -ForegroundColor Cyan
Write-Host "State dir    : $StatePath"        -ForegroundColor Cyan
Write-Host "Output CSV   : $OutputPath"       -ForegroundColor Cyan
Write-Host "Throttle     : $ThrottleLimit"    -ForegroundColor Cyan

$null = Initialize-AuditState -StatePath $StatePath -TenantId $ctx.Tenant.Id `
                              -OutputPath $OutputPath -Kind 'DIAG' -Force:$Force

$subscriptions = Get-AzSubscription -TenantId $ctx.Tenant.Id |
                 Where-Object { $_.State -eq 'Enabled' }
$tenantId   = $ctx.Tenant.Id
$totalSubs  = $subscriptions.Count
$partialsDir = Join-Path $StatePath 'partials'

# ---------------------------------------------------------------------------
# 1. Discover Sentinel-enabled Log Analytics Workspaces (refreshed every run)
# ---------------------------------------------------------------------------
Write-Host "`n[1/4] Locating Sentinel-enabled Log Analytics Workspaces..." -ForegroundColor Yellow

$sentinelWorkspaces = @{}
$wsHits = $subscriptions | ForEach-Object -Parallel {
    $sub = $_
    $tid = $using:tenantId
    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $tid -ErrorAction Stop | Out-Null }
    catch { return }

    $solutions = Get-AzResource -ResourceType 'Microsoft.OperationsManagement/solutions' `
                                -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'SecurityInsights*' }

    foreach ($sol in $solutions) {
        $full = Get-AzResource -ResourceId $sol.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        $wsId = $full.Properties.workspaceResourceId
        if ($wsId) { [pscustomobject]@{ id = $wsId; name = ($wsId -split '/')[-1] } }
    }
} -ThrottleLimit $ThrottleLimit

foreach ($w in $wsHits) {
    $sentinelWorkspaces[$w.id.ToLower()] = $w.name
    Write-Host "  Sentinel workspace: $($w.id)" -ForegroundColor Green
}

if ($sentinelWorkspaces.Count -eq 0) {
    Write-Warning "No Sentinel-enabled workspaces found. SentinelEnabled will be False for all rows."
} else {
    Write-Host "  Total Sentinel-enabled workspaces discovered: $($sentinelWorkspaces.Count)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Walk every resource in every subscription, pull diagnostic settings (parallel)
# ---------------------------------------------------------------------------
Write-Host "`n[2/4] Enumerating resources and diagnostic settings..." -ForegroundColor Yellow

$fnDefs  = Get-WorkerFunctionDefinitions
$counter = [hashtable]::Synchronized(@{ done = 0 })

$subscriptions | ForEach-Object -Parallel {
    $sub      = $_
    $sp       = $using:StatePath
    $partials = $using:partialsDir
    $tid      = $using:tenantId
    $wsMap    = $using:sentinelWorkspaces
    $defs     = $using:fnDefs
    $ctr      = $using:counter
    $totSubs  = $using:totalSubs

    foreach ($n in $defs.Keys) { Set-Item -Path "function:$n" -Value $defs[$n] }

    $diagCsv    = Join-Path $partials "diag.$($sub.Id).csv"
    $doneMarker = "diag-$($sub.Id)"

    if (Test-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker) {
        $ctr.done++
        Write-Host ("  [{0,3}/{1}] {2,-40} (cached)" -f $ctr.done, $totSubs, $sub.Name) -ForegroundColor DarkGray
        return
    }
    if (Test-Path $diagCsv) { Remove-Item -Force $diagCsv }

    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $tid -ErrorAction Stop | Out-Null }
    catch {
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'set-context' -Message $_.Exception.Message
        $ctr.done++
        return
    }

    $resources = Get-AzResource -ErrorAction SilentlyContinue
    $rowCount  = 0

    foreach ($res in $resources) {
        $settings = $null
        try {
            $settings = Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop
        } catch {
            # Most ARM 404s land here (resource type doesn't support diagnostic settings).
            continue
        }
        if (-not $settings) { continue }

        foreach ($s in $settings) {
            $logCats = @()
            if ($s.Log) {
                $logCats = $s.Log | Where-Object { $_.Enabled } | ForEach-Object { $_.Category }
            }
            $metricCats = @()
            if ($s.Metric) {
                $metricCats = $s.Metric | Where-Object { $_.Enabled } | ForEach-Object { "metric:$($_.Category)" }
            }
            $diagData = (@($logCats) + @($metricCats)) -join '; '
            if ([string]::IsNullOrWhiteSpace($diagData)) { $diagData = '(none enabled)' }

            $wsId           = $s.WorkspaceId
            $wsName         = if ($wsId) { ($wsId -split '/')[-1] } else { '' }
            $isSentinel     = $false
            $sentinelWsName = ''
            if ($wsId -and $wsMap.ContainsKey($wsId.ToLower())) {
                $isSentinel     = $true
                $sentinelWsName = $wsMap[$wsId.ToLower()]
            }

            $row = [pscustomobject]@{
                ResourceName          = $res.Name
                ResourceType          = $res.ResourceType
                LogAnalyticsWorkspace = $wsName
                DiagnosticData        = $diagData
                SentinelEnabled       = $isSentinel
                SentinelWorkspaceName = $sentinelWsName
                DiagnosticSettingName = $s.Name
                SubscriptionName      = $sub.Name
                ResourceGroup         = $res.ResourceGroupName
                WorkspaceResourceId   = $wsId
            }
            Add-CsvRow -Path $diagCsv -Row $row
            $rowCount++
        }
    }

    Set-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker `
                         -Stats @{ resources = $resources.Count; rows = $rowCount }
    $ctr.done++
    Write-Host ("  [{0,3}/{1}] {2,-40} resources={3,-5} rows={4}" -f $ctr.done, $totSubs, $sub.Name, $resources.Count, $rowCount) -ForegroundColor Cyan
} -ThrottleLimit $ThrottleLimit

# ---------------------------------------------------------------------------
# 3. Entra ID (Azure AD) diagnostic settings - tenant-scoped, run once
# ---------------------------------------------------------------------------
Write-Host "`n[3/4] Checking Entra ID diagnostic settings..." -ForegroundColor Yellow

$entraDoneMarker = 'entra-tenant'
$entraCsv        = Join-Path $partialsDir 'diag.entra.csv'

if (Test-SubscriptionDone -StatePath $StatePath -SubscriptionId $entraDoneMarker) {
    Write-Host "  Entra ID block already complete (cached)." -ForegroundColor DarkGray
} else {
    if (Test-Path $entraCsv) { Remove-Item -Force $entraCsv }
    try {
        $aadUri  = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
        $aadResp = Invoke-ArmRequest -Uri $aadUri
        if ($aadResp.StatusCode -eq 200) {
            $aadJson = $aadResp.Content | ConvertFrom-Json
            if ($aadJson.value -and $aadJson.value.Count -gt 0) {
                foreach ($ds in $aadJson.value) {
                    $props = $ds.properties

                    $logCats = @()
                    if ($props.logs) {
                        $logCats = $props.logs | Where-Object { $_.enabled } | ForEach-Object { $_.category }
                    }
                    $diagData = $logCats -join '; '
                    if ([string]::IsNullOrWhiteSpace($diagData)) { $diagData = '(none enabled)' }

                    $wsId           = $props.workspaceId
                    $wsName         = if ($wsId) { ($wsId -split '/')[-1] } else { '' }
                    $isSentinel     = $false
                    $sentinelWsName = ''
                    if ($wsId -and $sentinelWorkspaces.ContainsKey($wsId.ToLower())) {
                        $isSentinel     = $true
                        $sentinelWsName = $sentinelWorkspaces[$wsId.ToLower()]
                    }

                    $row = [pscustomobject]@{
                        ResourceName          = 'Entra ID (Azure AD)'
                        ResourceType          = 'microsoft.aadiam/diagnosticSettings'
                        LogAnalyticsWorkspace = $wsName
                        DiagnosticData        = $diagData
                        SentinelEnabled       = $isSentinel
                        SentinelWorkspaceName = $sentinelWsName
                        DiagnosticSettingName = $ds.name
                        SubscriptionName      = '(tenant scope)'
                        ResourceGroup         = '(tenant scope)'
                        WorkspaceResourceId   = $wsId
                    }
                    Add-CsvRow -Path $entraCsv -Row $row
                    Write-Host "  Found Entra setting '$($ds.name)' -> $wsName  Sentinel=$isSentinel" -ForegroundColor Green
                }

                # Inform on missing Entra log categories.
                $catUri  = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettingsCategories?api-version=2017-04-01-preview"
                $catResp = Invoke-ArmRequest -Uri $catUri
                if ($catResp.StatusCode -eq 200) {
                    $allCats = ($catResp.Content | ConvertFrom-Json).value.name
                    $enabledCats = $aadJson.value | ForEach-Object {
                        $_.properties.logs | Where-Object { $_.enabled } | ForEach-Object { $_.category }
                    } | Select-Object -Unique
                    $missing = $allCats | Where-Object { $_ -notin $enabledCats }
                    if ($missing) {
                        Write-Host "  Entra log categories NOT enabled anywhere: $($missing -join ', ')" -ForegroundColor Yellow
                    } else {
                        Write-Host "  All Entra log categories are enabled in at least one diagnostic setting." -ForegroundColor Green
                    }
                }
            } else {
                Write-Warning "  No Entra ID diagnostic settings configured."
                $row = [pscustomobject]@{
                    ResourceName          = 'Entra ID (Azure AD)'
                    ResourceType          = 'microsoft.aadiam/diagnosticSettings'
                    LogAnalyticsWorkspace = ''
                    DiagnosticData        = '(no diagnostic setting configured)'
                    SentinelEnabled       = $false
                    SentinelWorkspaceName = ''
                    DiagnosticSettingName = ''
                    SubscriptionName      = '(tenant scope)'
                    ResourceGroup         = '(tenant scope)'
                    WorkspaceResourceId   = ''
                }
                Add-CsvRow -Path $entraCsv -Row $row
            }
            Set-SubscriptionDone -StatePath $StatePath -SubscriptionId $entraDoneMarker -Stats @{ entra = 'ok' }
        } else {
            Write-Warning "  Entra diagnostic settings query returned HTTP $($aadResp.StatusCode). You likely need Global Administrator or Security Administrator rights."
            Write-AuditError -StatePath $StatePath -SubscriptionId '(tenant)' -Phase 'entra' `
                             -Message "HTTP $($aadResp.StatusCode)"
        }
    } catch {
        Write-Warning "  Failed to query Entra ID diagnostic settings: $_"
        Write-AuditError -StatePath $StatePath -SubscriptionId '(tenant)' -Phase 'entra' -Message $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# 4. Merge partials into final CSV
# ---------------------------------------------------------------------------
Write-Host "`n[4/4] Merging partial CSVs..." -ForegroundColor Yellow
Write-Host "  Output  : $OutputPath"

$results = Merge-PartialCsvs -PartialsDir $partialsDir -Filter 'diag.*.csv' `
                             -OutputPath $OutputPath `
                             -SortBy @('SentinelEnabled','SubscriptionName','ResourceName') -Descending

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
$total            = $results.Count
$toSentinel       = ($results | Where-Object { $_.SentinelEnabled -eq 'True' }).Count
$uniqueResources  = ($results | Select-Object ResourceName -Unique).Count

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Diagnostic-setting rows recorded : $total"
Write-Host "  Unique resources                 : $uniqueResources"
Write-Host "  Rows targeting a Sentinel WS     : $toSentinel"
Write-Host "  CSV saved to                     : $OutputPath"

if ($sentinelWorkspaces.Count -gt 1) {
    Write-Host "`n  Breakdown by Sentinel workspace:" -ForegroundColor Cyan
    $results | Where-Object { $_.SentinelEnabled -eq 'True' } |
               Group-Object SentinelWorkspaceName |
               Sort-Object Count -Descending |
               ForEach-Object {
                   Write-Host ("    {0,-40} {1,5} rows" -f $_.Name, $_.Count)
               }
}

# ---------------------------------------------------------------------------
# Optional state cleanup
# ---------------------------------------------------------------------------
$errorsFile = Join-Path $StatePath 'errors/errors.jsonl'
if (Test-Path $errorsFile) {
    $errCount = (Get-Content $errorsFile | Measure-Object -Line).Lines
    if ($errCount -gt 0) {
        Write-Warning "  $errCount non-fatal error(s) recorded in $errorsFile"
    }
}

if ($CleanState) {
    if (Test-Path $errorsFile) {
        Copy-Item -Path $errorsFile -Destination ($OutputPath + '.errors.jsonl') -Force
    }
    Remove-Item -Path $StatePath -Recurse -Force
    Write-Host "  State directory removed (-CleanState)." -ForegroundColor DarkGray
}
