<#
.SYNOPSIS
    Audits Microsoft Defender for Cloud plan coverage across every subscription
    in the tenant. Produces a CSV with one row per (subscription x plan) so you
    can quickly see which workloads are covered (Standard / paid) and which are
    not (Free / deprecated). Supports parallel workers and resume-on-rerun.

.DESCRIPTION
    - Iterates every enabled subscription the signed-in identity can read.
    - Calls Microsoft.Security/pricings (api-version 2024-01-01) per subscription
      and records every plan returned, including:
        * PricingTier (Free / Standard)         <- THE coverage signal
        * SubPlan (P1 / P2 / PerNode / etc.)
        * Deprecated + ReplacedBy
        * Free-trial remaining time
        * Enforcement / inheritance hints
        * Defender extensions per plan (name + isEnabled), e.g. AgentlessVmScanning,
          ContainerRegistriesVulnerabilityAssessments, AgentlessDiscoveryForKubernetes
    - Adds a Covered boolean (PricingTier eq 'Standard' and not deprecated) so
      the gap report can filter on it directly.

    Tracking & resume:
        Per-subscription progress is written to a sidecar state directory next
        to -OutputPath (default '<OutputPath>.state'). Each plan row is
        appended to a per-subscription partial CSV immediately, so an
        interrupted run loses at most the in-flight subscription. On rerun the
        script reattaches and skips subscriptions whose .done marker is present.

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
    ./Audit-DefenderForCloud.ps1
        Run with defaults; resumes automatically if the state directory exists.

.EXAMPLE
    ./Audit-DefenderForCloud.ps1 -ThrottleLimit 8 -OutputPath ./mdc.csv

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout

    Run from Azure Cloud Shell (PowerShell) or local pwsh 7+. Requires Az modules.
    Reader on each subscription is sufficient to *list* pricings; Security Reader
    on each subscription gives the most reliable read on extension state.

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.
#>

[CmdletBinding()]
param(
    [string] $OutputPath    = "$HOME/DefenderForCloudAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
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

$PricingApiVersion = '2024-01-01'

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
                              -OutputPath $OutputPath -Kind 'MDC' -Force:$Force

$subscriptions = Get-AzSubscription -TenantId $ctx.Tenant.Id |
                 Where-Object { $_.State -eq 'Enabled' }
$tenantId    = $ctx.Tenant.Id
$totalSubs   = $subscriptions.Count
$partialsDir = Join-Path $StatePath 'partials'

# ---------------------------------------------------------------------------
# 1. Enumerate Defender for Cloud plans per subscription (parallel, resumable)
# ---------------------------------------------------------------------------
Write-Host "`n[1/2] Enumerating Defender for Cloud plans..." -ForegroundColor Yellow

$fnDefs  = Get-WorkerFunctionDefinitions
$counter = [hashtable]::Synchronized(@{ done = 0 })

$subscriptions | ForEach-Object -Parallel {
    $sub      = $_
    $sp       = $using:StatePath
    $partials = $using:partialsDir
    $tid      = $using:tenantId
    $apiVer   = $using:PricingApiVersion
    $defs     = $using:fnDefs
    $ctr      = $using:counter
    $totSubs  = $using:totalSubs

    foreach ($n in $defs.Keys) { Set-Item -Path "function:$n" -Value $defs[$n] }

    $mdcCsv     = Join-Path $partials "mdc.$($sub.Id).csv"
    $doneMarker = "mdc-$($sub.Id)"

    if (Test-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker) {
        $ctr.done++
        Write-Host ("  [{0,3}/{1}] {2,-40} (cached)" -f $ctr.done, $totSubs, $sub.Name) -ForegroundColor DarkGray
        return
    }
    if (Test-Path $mdcCsv) { Remove-Item -Force $mdcCsv }

    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $tid -ErrorAction Stop | Out-Null }
    catch {
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'set-context' -Message $_.Exception.Message
        $ctr.done++
        return
    }

    $uri  = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Security/pricings?api-version=$apiVer"
    try { $resp = Invoke-ArmRequest -Uri $uri }
    catch {
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'pricings-list' -Message $_.Exception.Message
        $ctr.done++
        return
    }
    if (-not $resp -or $resp.StatusCode -ne 200) {
        $msg = if ($resp) { "HTTP $($resp.StatusCode): $($resp.Content)" } else { 'no response' }
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'pricings-list' -Message $msg
        # Still mark .done so we don't loop on a perma-403; user can grep errors.jsonl.
        Set-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker -Stats @{ plans = 0; error = $true }
        $ctr.done++
        return
    }

    $plans      = ($resp.Content | ConvertFrom-Json).value
    $covCount   = 0
    $uncovCount = 0

    foreach ($p in $plans) {
        $props = $p.properties
        $tier  = $props.pricingTier
        $sub2  = $props.subPlan
        $depr  = [bool]$props.deprecated
        $repl  = ''
        if ($props.replacedBy) {
            $repl = (@($props.replacedBy)) -join '; '
        }
        $covered = ($tier -eq 'Standard' -and -not $depr)
        $freeRem = ''
        if ($props.freeTrialRemainingTime) { $freeRem = $props.freeTrialRemainingTime }
        $enforce = ''
        if ($props.enforce) { $enforce = $props.enforce }
        $inherit = ''
        if ($props.inherited) { $inherit = $props.inherited }
        $resCount = ''
        if ($null -ne $props.resourcesCoverageStatus) { $resCount = $props.resourcesCoverageStatus }

        # Extensions: list of { name, isEnabled, additionalExtensionProperties, operationStatus }
        $exts        = @()
        $extsEnabled = @()
        if ($props.extensions) {
            foreach ($e in $props.extensions) {
                $on = if ($e.isEnabled -eq 'True' -or $e.isEnabled -eq $true) { 'on' } else { 'off' }
                $exts += "$($e.name)=$on"
                if ($on -eq 'on') { $extsEnabled += $e.name }
            }
        }

        if ($covered) { $covCount++ } else { $uncovCount++ }

        $row = [pscustomobject]@{
            SubscriptionName       = $sub.Name
            SubscriptionId         = $sub.Id
            PlanName               = $p.name
            PricingTier            = $tier
            SubPlan                = $sub2
            Covered                = $covered
            Deprecated             = $depr
            ReplacedBy             = $repl
            FreeTrialRemainingTime = $freeRem
            Enforce                = $enforce
            Inherited              = $inherit
            ExtensionsEnabled      = ($extsEnabled -join '; ')
            Extensions             = ($exts        -join '; ')
            ResourcesCoverageStatus= $resCount
            PlanResourceId         = $p.id
        }
        Add-CsvRow -Path $mdcCsv -Row $row
    }

    # Synthesize a single placeholder row for subscriptions where no plans are
    # returned (rare; can happen for blocked / deleted-but-not-removed subs) so
    # the report still surfaces them.
    if (-not $plans -or $plans.Count -eq 0) {
        $row = [pscustomobject]@{
            SubscriptionName       = $sub.Name
            SubscriptionId         = $sub.Id
            PlanName               = '(no plans returned)'
            PricingTier            = 'Free'
            SubPlan                = ''
            Covered                = $false
            Deprecated             = $false
            ReplacedBy             = ''
            FreeTrialRemainingTime = ''
            Enforce                = ''
            Inherited              = ''
            ExtensionsEnabled      = ''
            Extensions             = ''
            ResourcesCoverageStatus= ''
            PlanResourceId         = ''
        }
        Add-CsvRow -Path $mdcCsv -Row $row
        $uncovCount++
    }

    Set-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker `
                         -Stats @{ plans = $plans.Count; covered = $covCount; uncovered = $uncovCount }
    $ctr.done++
    Write-Host ("  [{0,3}/{1}] {2,-40} plans={3,-3} covered={4,-3} not={5}" -f $ctr.done, $totSubs, $sub.Name, $plans.Count, $covCount, $uncovCount) -ForegroundColor Cyan
} -ThrottleLimit $ThrottleLimit

# ---------------------------------------------------------------------------
# 2. Merge partials into final CSV
# ---------------------------------------------------------------------------
Write-Host "`n[2/2] Merging partial CSVs..." -ForegroundColor Yellow
Write-Host "  Output  : $OutputPath"

$results = Merge-PartialCsvs -PartialsDir $partialsDir -Filter 'mdc.*.csv' `
                             -OutputPath $OutputPath `
                             -SortBy @('Covered','SubscriptionName','PlanName') -Descending

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
$total          = $results.Count
$covered        = ($results | Where-Object { $_.Covered -eq 'True' }).Count
$uncovered      = ($results | Where-Object { $_.Covered -ne 'True' }).Count
$uniqSubs       = ($results | Select-Object -ExpandProperty SubscriptionName -Unique).Count

# Subs that have at least one Standard plan vs subs that are 100% Free.
$bySub          = $results | Group-Object SubscriptionId
$subsAnyStd     = ($bySub | Where-Object { $_.Group | Where-Object { $_.Covered -eq 'True' } }).Count
$subsAllFree    = $uniqSubs - $subsAnyStd

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Plan rows recorded             : $total"
Write-Host "  Subscriptions audited          : $uniqSubs"
Write-Host "  Subs with >=1 Standard plan    : $subsAnyStd"
Write-Host "  Subs entirely on Free plans    : $subsAllFree"
Write-Host "  Plan rows COVERED  (Standard)  : $covered"
Write-Host "  Plan rows NOT covered (Free/dep): $uncovered"
Write-Host "  CSV saved to                   : $OutputPath"

# Per-plan breakdown (which workloads are best/worst covered tenant-wide)
Write-Host "`n  Coverage by plan (Standard / Total subs):" -ForegroundColor Cyan
$results | Group-Object PlanName | Sort-Object Name | ForEach-Object {
    $std = ($_.Group | Where-Object { $_.Covered -eq 'True' }).Count
    $tot = $_.Count
    Write-Host ("    {0,-40} {1,4}/{2,-4}" -f $_.Name, $std, $tot)
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
