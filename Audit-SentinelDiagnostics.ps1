<#
.SYNOPSIS
    Audits diagnostic settings across all subscriptions in a tenant and identifies
    which resources are sending logs to a Microsoft Sentinel-enabled Log Analytics Workspace.

.DESCRIPTION
    - Discovers all Log Analytics Workspaces with Sentinel (SecurityInsights) enabled.
    - Iterates over every subscription / resource the signed-in identity can read.
    - Retrieves diagnostic settings for each resource and notes the destination workspace
      and which log categories / metrics are enabled.
    - Adds Entra ID (Azure AD) diagnostic settings separately, since Entra is tenant-scoped
      and not returned by Get-AzResource.
    - Exports a CSV with: ResourceName, ResourceType, LogAnalyticsWorkspace, DiagnosticData,
      SentinelEnabled, SubscriptionName, ResourceGroup.

.NOTES

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout
 
    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell)
    and Microsoft.Graph.Identity.DirectoryManagement for Entra ID diagnostic settings.
 
    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$HOME/SentinelDiagnosticsAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# Suppress Az upcoming-breaking-change warnings (e.g. Get-AzDiagnosticSetting Log/Metric
# becoming List<>) so they don't drown out script output. The cmdlet behaviour is
# unchanged for our use case – we only read .Enabled and .Category which work in both shapes.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

# ---------------------------------------------------------------------------
# 0. Sanity check – make sure we are signed in
# ---------------------------------------------------------------------------
$ctx = Get-AzContext
if (-not $ctx) {
    Write-Host "Not signed in. Run Connect-AzAccount first." -ForegroundColor Red
    return
}
Write-Host "Signed in as: $($ctx.Account.Id)" -ForegroundColor Cyan
Write-Host "Tenant      : $($ctx.Tenant.Id)" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# 1. Discover all Sentinel-enabled Log Analytics Workspaces in the tenant
# ---------------------------------------------------------------------------
Write-Host "`n[1/3] Locating Sentinel-enabled Log Analytics Workspaces..." -ForegroundColor Yellow

$sentinelWorkspaces = @{}   # key = workspace ResourceId (lowercase), value = workspace name
$subscriptions      = Get-AzSubscription -TenantId $ctx.Tenant.Id |
                      Where-Object { $_.State -eq 'Enabled' }

foreach ($sub in $subscriptions) {
    try {
        Set-AzContext -SubscriptionId $sub.Id -Tenant $ctx.Tenant.Id -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Cannot switch to subscription $($sub.Name): $_"
        continue
    }

    # SecurityInsights solutions = Sentinel
    $solutions = Get-AzResource -ResourceType 'Microsoft.OperationsManagement/solutions' `
                                -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'SecurityInsights*' }

    foreach ($sol in $solutions) {
        # The workspace ResourceId is on the solution properties.workspaceResourceId
        $full = Get-AzResource -ResourceId $sol.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        $wsId = $full.Properties.workspaceResourceId
        if ($wsId) {
            $sentinelWorkspaces[$wsId.ToLower()] = ($wsId -split '/')[-1]
            Write-Host "  Sentinel workspace: $wsId" -ForegroundColor Green
        }
    }
}

if ($sentinelWorkspaces.Count -eq 0) {
    Write-Warning "No Sentinel-enabled workspaces found. The script will still record all diagnostic settings, but SentinelEnabled will be False for all rows."
} else {
    Write-Host "  Total Sentinel-enabled workspaces discovered: $($sentinelWorkspaces.Count)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Walk every resource in every subscription, pull diagnostic settings
# ---------------------------------------------------------------------------
Write-Host "`n[2/3] Enumerating resources and diagnostic settings..." -ForegroundColor Yellow

foreach ($sub in $subscriptions) {
    try {
        Set-AzContext -SubscriptionId $sub.Id -Tenant $ctx.Tenant.Id -ErrorAction Stop | Out-Null
    } catch { continue }

    Write-Host "`n  Subscription: $($sub.Name)" -ForegroundColor Cyan

    $resources = Get-AzResource -ErrorAction SilentlyContinue
    Write-Host "    $($resources.Count) resources to inspect..."

    foreach ($res in $resources) {
        # Get-AzDiagnosticSetting requires -ResourceId; suppress noise for resources
        # that simply don't support diagnostic settings (most ARM 404s land here).
        $settings = $null
        try {
            $settings = Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop
        } catch {
            # Silently skip – resource type doesn't support diagnostic settings
            continue
        }

        if (-not $settings) { continue }

        foreach ($s in $settings) {
            # Enabled log categories
            $logCats = @()
            if ($s.Log) {
                $logCats = $s.Log | Where-Object { $_.Enabled } |
                           ForEach-Object { $_.Category }
            }
            # Enabled metric categories
            $metricCats = @()
            if ($s.Metric) {
                $metricCats = $s.Metric | Where-Object { $_.Enabled } |
                              ForEach-Object { "metric:$($_.Category)" }
            }
            $diagData = (@($logCats) + @($metricCats)) -join '; '
            if ([string]::IsNullOrWhiteSpace($diagData)) { $diagData = '(none enabled)' }

            $wsId       = $s.WorkspaceId
            $wsName     = if ($wsId) { ($wsId -split '/')[-1] } else { '' }
            $isSentinel = $false
            $sentinelWsName = ''
            if ($wsId -and $sentinelWorkspaces.ContainsKey($wsId.ToLower())) {
                $isSentinel     = $true
                $sentinelWsName = $sentinelWorkspaces[$wsId.ToLower()]
            }

            $results.Add([pscustomobject]@{
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
            }) | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Entra ID (Azure AD) diagnostic settings – tenant-scoped, separate API
# ---------------------------------------------------------------------------
Write-Host "`n[3/3] Checking Entra ID diagnostic settings..." -ForegroundColor Yellow

# The Entra ID diagnostic settings live at /providers/microsoft.aadiam/diagnosticSettings.
# Easiest universal way from Cloud Shell is the ARM REST call via Invoke-AzRestMethod.
try {
    $aadUri  = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
    $aadResp = Invoke-AzRestMethod -Method GET -Uri $aadUri -ErrorAction Stop
    if ($aadResp.StatusCode -eq 200) {
        $aadJson = $aadResp.Content | ConvertFrom-Json
        if ($aadJson.value -and $aadJson.value.Count -gt 0) {
            foreach ($ds in $aadJson.value) {
                $props = $ds.properties

                $logCats = @()
                if ($props.logs) {
                    $logCats = $props.logs | Where-Object { $_.enabled } |
                               ForEach-Object { $_.category }
                }
                $diagData = $logCats -join '; '
                if ([string]::IsNullOrWhiteSpace($diagData)) { $diagData = '(none enabled)' }

                $wsId       = $props.workspaceId
                $wsName     = if ($wsId) { ($wsId -split '/')[-1] } else { '' }
                $isSentinel = $false
                $sentinelWsName = ''
                if ($wsId -and $sentinelWorkspaces.ContainsKey($wsId.ToLower())) {
                    $isSentinel     = $true
                    $sentinelWsName = $sentinelWorkspaces[$wsId.ToLower()]
                }

                $results.Add([pscustomobject]@{
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
                }) | Out-Null

                Write-Host "  Found Entra setting '$($ds.name)' -> $wsName  Sentinel=$isSentinel" -ForegroundColor Green
            }

            # Compare to the full set of available Entra log categories so the user
            # can see what is NOT being collected.
            $catUri  = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettingsCategories?api-version=2017-04-01-preview"
            $catResp = Invoke-AzRestMethod -Method GET -Uri $catUri -ErrorAction SilentlyContinue
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
            $results.Add([pscustomobject]@{
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
            }) | Out-Null
        }
    } else {
        Write-Warning "  Entra diagnostic settings query returned HTTP $($aadResp.StatusCode). You likely need Global Administrator or Security Administrator rights."
    }
} catch {
    Write-Warning "  Failed to query Entra ID diagnostic settings: $_"
}

# ---------------------------------------------------------------------------
# 4. Export CSV
# ---------------------------------------------------------------------------
Write-Host "`nWriting CSV: $OutputPath" -ForegroundColor Yellow
$results | Sort-Object SentinelEnabled, SubscriptionName, ResourceName -Descending |
           Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Quick on-screen summary
$total            = $results.Count
$toSentinel       = ($results | Where-Object SentinelEnabled).Count
$uniqueResources  = ($results | Select-Object ResourceName -Unique).Count
Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Diagnostic-setting rows recorded : $total"
Write-Host "  Unique resources                 : $uniqueResources"
Write-Host "  Rows targeting a Sentinel WS     : $toSentinel"
Write-Host "  CSV saved to                     : $OutputPath"

# Per-Sentinel-workspace breakdown so multi-Sentinel tenants see the split
if ($sentinelWorkspaces.Count -gt 1) {
    Write-Host "`n  Breakdown by Sentinel workspace:" -ForegroundColor Cyan
    $results | Where-Object SentinelEnabled |
               Group-Object SentinelWorkspaceName |
               Sort-Object Count -Descending |
               ForEach-Object {
                   Write-Host ("    {0,-40} {1,5} rows" -f $_.Name, $_.Count)
               }
}
