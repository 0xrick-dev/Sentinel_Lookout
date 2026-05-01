<#
.SYNOPSIS
    Audits every Data Collection Rule (DCR) in the tenant, the resources associated
    with each rule, and whether the destination Log Analytics Workspace is Sentinel-enabled.

.DESCRIPTION
    - Discovers all Log Analytics Workspaces with Sentinel (SecurityInsights) enabled.
    - Iterates over every enabled subscription the signed-in identity can read.
    - Lists every Microsoft.Insights/dataCollectionRules resource and pulls full properties.
    - For each DCR records:
        * Destination workspace(s) and whether any of them is a Sentinel workspace.
        * Data sources actually being collected (Windows Event Logs incl. Security log,
          Syslog, performance counters, custom log file paths, IIS logs, extensions
          such as the ASC/Defender data source, Prometheus, Windows Firewall, etc.).
        * Streams declared in dataFlows (Microsoft-SecurityEvent, Custom-*, etc.).
        * Every resource currently associated with the rule (VMs, VMSS, Arc machines)
          via the data collection rule associations API.
    - Exports a CSV with one row per DCR.

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/sentinel-lookout

    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell).
    Reader on each subscription is sufficient. No Microsoft Graph calls are made.

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$HOME/SentinelDCRAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

# DCR + DCRA stable GA API version.
$DcrApiVersion  = '2022-06-01'
$DcraApiVersion = '2022-06-01'

# ---------------------------------------------------------------------------
# 0. Sanity check
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
# 1. Discover Sentinel-enabled Log Analytics Workspaces
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

    $solutions = Get-AzResource -ResourceType 'Microsoft.OperationsManagement/solutions' `
                                -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'SecurityInsights*' }

    foreach ($sol in $solutions) {
        $full = Get-AzResource -ResourceId $sol.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        $wsId = $full.Properties.workspaceResourceId
        if ($wsId) {
            $sentinelWorkspaces[$wsId.ToLower()] = ($wsId -split '/')[-1]
            Write-Host "  Sentinel workspace: $wsId" -ForegroundColor Green
        }
    }
}

if ($sentinelWorkspaces.Count -eq 0) {
    Write-Warning "No Sentinel-enabled workspaces found. SentinelEnabled will be False for all rows."
} else {
    Write-Host "  Total Sentinel-enabled workspaces discovered: $($sentinelWorkspaces.Count)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-DcrDataCollectionSummary {
    param($Properties)

    $summary = New-Object System.Collections.Generic.List[string]
    $ds      = $Properties.dataSources
    if (-not $ds) {
        $summary.Add('(no data sources)')
        return ,$summary
    }

    # Windows Event Logs (xPathQueries reveal whether Security log is collected)
    if ($ds.windowsEventLogs) {
        foreach ($w in $ds.windowsEventLogs) {
            $xpaths = @($w.xPathQueries) -join ', '
            $hasSecurity = $false
            foreach ($q in @($w.xPathQueries)) {
                if ($q -match '^\s*Security\b' -or $q -match '!Security!') { $hasSecurity = $true }
            }
            $tag = if ($hasSecurity) { 'WindowsEventLogs(SECURITY)' } else { 'WindowsEventLogs' }
            $summary.Add("$tag [$xpaths]")
        }
    }

    # Syslog
    if ($ds.syslog) {
        foreach ($s in $ds.syslog) {
            $facs = @($s.facilityNames) -join ','
            $lvls = @($s.logLevels)     -join ','
            $summary.Add("Syslog facilities=[$facs] levels=[$lvls]")
        }
    }

    # Performance counters
    if ($ds.performanceCounters) {
        foreach ($p in $ds.performanceCounters) {
            $cnt  = (@($p.counterSpecifiers)).Count
            $freq = $p.samplingFrequencyInSeconds
            $summary.Add("PerfCounters x$cnt @${freq}s")
        }
    }

    # Custom log files
    if ($ds.logFiles) {
        foreach ($l in $ds.logFiles) {
            $patterns = @($l.filePatterns) -join ', '
            $fmt      = $l.format
            $summary.Add("LogFiles($fmt) [$patterns]")
        }
    }

    # IIS logs
    if ($ds.iisLogs) {
        foreach ($i in $ds.iisLogs) {
            $dirs = @($i.logDirectories) -join ', '
            $summary.Add("IISLogs [$dirs]")
        }
    }

    # Extensions (e.g. AzureSecurityWindowsAgent / Defender for Servers, DependencyAgent...)
    if ($ds.extensions) {
        foreach ($e in $ds.extensions) {
            $summary.Add("Extension:$($e.extensionName)")
        }
    }

    # Prometheus forwarder (AKS)
    if ($ds.prometheusForwarder) {
        $summary.Add("PrometheusForwarder x$((@($ds.prometheusForwarder)).Count)")
    }

    # Windows Firewall logs
    if ($ds.windowsFirewallLogs) {
        $summary.Add("WindowsFirewallLogs")
    }

    # Platform telemetry
    if ($ds.platformTelemetry) {
        $summary.Add("PlatformTelemetry")
    }

    # Data Imports (e.g. Event Hub stream ingest)
    if ($Properties.dataSources.dataImports) {
        $summary.Add("DataImports")
    }

    if ($summary.Count -eq 0) { $summary.Add('(no data sources)') }
    return ,$summary
}

function Get-DcrCollectionFlags {
    param($Properties)

    $flags = [ordered]@{
        WindowsEventLogs        = $false
        WindowsSecurityLog      = $false
        Syslog                  = $false
        PerformanceCounters     = $false
        CustomLogFiles          = $false
        IISLogs                 = $false
        Extensions              = $false
        Prometheus              = $false
        WindowsFirewallLogs     = $false
    }
    $ds = $Properties.dataSources
    if (-not $ds) { return $flags }

    if ($ds.windowsEventLogs) {
        $flags.WindowsEventLogs = $true
        foreach ($w in $ds.windowsEventLogs) {
            foreach ($q in @($w.xPathQueries)) {
                if ($q -match '^\s*Security\b' -or $q -match '!Security!') { $flags.WindowsSecurityLog = $true }
            }
        }
    }
    if ($ds.syslog)              { $flags.Syslog              = $true }
    if ($ds.performanceCounters) { $flags.PerformanceCounters = $true }
    if ($ds.logFiles)            { $flags.CustomLogFiles      = $true }
    if ($ds.iisLogs)             { $flags.IISLogs             = $true }
    if ($ds.extensions)          { $flags.Extensions          = $true }
    if ($ds.prometheusForwarder) { $flags.Prometheus          = $true }
    if ($ds.windowsFirewallLogs) { $flags.WindowsFirewallLogs = $true }
    return $flags
}

# ---------------------------------------------------------------------------
# 2. Enumerate every DCR per subscription, plus its associations
# ---------------------------------------------------------------------------
Write-Host "`n[2/3] Enumerating Data Collection Rules and associations..." -ForegroundColor Yellow

foreach ($sub in $subscriptions) {
    try {
        Set-AzContext -SubscriptionId $sub.Id -Tenant $ctx.Tenant.Id -ErrorAction Stop | Out-Null
    } catch { continue }

    Write-Host "`n  Subscription: $($sub.Name)" -ForegroundColor Cyan

    # List DCRs in the subscription via REST (one shot, paginated).
    $dcrs    = New-Object System.Collections.Generic.List[object]
    $nextUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Insights/dataCollectionRules?api-version=$DcrApiVersion"
    while ($nextUri) {
        try {
            $resp = Invoke-AzRestMethod -Method GET -Uri $nextUri -ErrorAction Stop
        } catch {
            Write-Warning "    DCR list call failed: $_"
            break
        }
        if ($resp.StatusCode -ne 200) {
            Write-Warning "    DCR list HTTP $($resp.StatusCode): $($resp.Content)"
            break
        }
        $page = $resp.Content | ConvertFrom-Json
        if ($page.value) { $page.value | ForEach-Object { $dcrs.Add($_) | Out-Null } }
        $nextUri = $page.nextLink
    }

    Write-Host "    $($dcrs.Count) DCR(s) to inspect..."

    foreach ($dcr in $dcrs) {
        $props = $dcr.properties

        # --- Destinations / workspaces ---
        $laDestinations = @()
        if ($props.destinations -and $props.destinations.logAnalytics) {
            $laDestinations = @($props.destinations.logAnalytics)
        }

        $wsNames        = @()
        $wsResourceIds  = @()
        $sentinelHits   = @()
        $hasNonSentinel = $false

        foreach ($d in $laDestinations) {
            $wsId = $d.workspaceResourceId
            if (-not $wsId) { continue }
            $wsResourceIds += $wsId
            $wsName = ($wsId -split '/')[-1]
            $wsNames += $wsName
            if ($sentinelWorkspaces.ContainsKey($wsId.ToLower())) {
                $sentinelHits += $sentinelWorkspaces[$wsId.ToLower()]
            } else {
                $hasNonSentinel = $true
            }
        }

        $sentinelEnabled = ($sentinelHits.Count -gt 0)

        # Other destinations (less common but possible)
        $otherDestinations = @()
        if ($props.destinations.azureMonitorMetrics) { $otherDestinations += 'AzureMonitorMetrics' }
        if ($props.destinations.eventHubs)           { $otherDestinations += 'EventHubs'           }
        if ($props.destinations.eventHubsDirect)     { $otherDestinations += 'EventHubsDirect'     }
        if ($props.destinations.storageAccounts)     { $otherDestinations += 'StorageAccounts'     }
        if ($props.destinations.storageBlobsDirect)  { $otherDestinations += 'StorageBlobsDirect'  }
        if ($props.destinations.storageTablesDirect) { $otherDestinations += 'StorageTablesDirect' }
        if ($props.destinations.monitoringAccounts)  { $otherDestinations += 'MonitoringAccounts'  }

        # --- Data sources / streams ---
        $dataSummary = Get-DcrDataCollectionSummary -Properties $props
        $dataFlowStreams = @()
        if ($props.dataFlows) {
            foreach ($df in $props.dataFlows) {
                $dataFlowStreams += @($df.streams)
            }
        }
        $dataFlowStreams = $dataFlowStreams | Select-Object -Unique
        $flags = Get-DcrCollectionFlags -Properties $props

        # --- Associations (which VMs / Arc / VMSS reference this rule) ---
        $assocResourceIds   = @()
        $assocResourceTypes = @()
        $assocCount         = 0
        try {
            $assocUri  = "https://management.azure.com$($dcr.id)/associations?api-version=$DcraApiVersion"
            $assocResp = Invoke-AzRestMethod -Method GET -Uri $assocUri -ErrorAction Stop
            if ($assocResp.StatusCode -eq 200) {
                $assocPayload = $assocResp.Content | ConvertFrom-Json
                foreach ($a in @($assocPayload.value)) {
                    # Association id form:
                    #   {targetResourceId}/providers/Microsoft.Insights/dataCollectionRuleAssociations/{name}
                    $idx = $a.id.ToLower().IndexOf('/providers/microsoft.insights/datacollectionruleassociations/')
                    if ($idx -gt 0) {
                        $targetId = $a.id.Substring(0, $idx)
                        $assocResourceIds   += $targetId
                        # Resource type = segments [-2..-1] above the resource name
                        $segs = $targetId -split '/'
                        if ($segs.Length -ge 8) {
                            # /subscriptions/<id>/resourceGroups/<rg>/providers/<ns>/<type>[/<sub>/<subType>]/<name>
                            $providerNs = $segs[6]
                            $typeChain  = ($segs[7..($segs.Length - 2)] | Where-Object { $_ }) -join '/'
                            $assocResourceTypes += "$providerNs/$typeChain"
                        }
                    }
                    $assocCount++
                }
            } elseif ($assocResp.StatusCode -ne 404) {
                Write-Warning "    Associations HTTP $($assocResp.StatusCode) for $($dcr.name)"
            }
        } catch {
            Write-Warning "    Failed to enumerate associations for $($dcr.name): $_"
        }
        $assocResourceTypes = $assocResourceTypes | Select-Object -Unique

        # --- Resource group from id ---
        $rg = ''
        $m  = [regex]::Match($dcr.id, '/resourceGroups/([^/]+)/', 'IgnoreCase')
        if ($m.Success) { $rg = $m.Groups[1].Value }

        $row = [pscustomobject]@{
            DcrName                          = $dcr.name
            DcrResourceId                    = $dcr.id
            Location                         = $dcr.location
            Kind                             = $dcr.kind
            ResourceGroup                    = $rg
            SubscriptionName                 = $sub.Name
            SubscriptionId                   = $sub.Id
            DestinationWorkspaces            = ($wsNames        | Select-Object -Unique) -join '; '
            DestinationWorkspaceResourceIds  = ($wsResourceIds  | Select-Object -Unique) -join '; '
            SentinelEnabled                  = $sentinelEnabled
            SentinelWorkspaces               = ($sentinelHits   | Select-Object -Unique) -join '; '
            HasNonSentinelDestination        = $hasNonSentinel
            OtherDestinations                = ($otherDestinations | Select-Object -Unique) -join '; '
            DataCollectionSummary            = ($dataSummary)   -join '; '
            Streams                          = ($dataFlowStreams) -join '; '
            CollectsWindowsEventLogs         = $flags.WindowsEventLogs
            CollectsWindowsSecurityLog       = $flags.WindowsSecurityLog
            CollectsSyslog                   = $flags.Syslog
            CollectsPerformanceCounters      = $flags.PerformanceCounters
            CollectsCustomLogFiles           = $flags.CustomLogFiles
            CollectsIISLogs                  = $flags.IISLogs
            CollectsExtensions               = $flags.Extensions
            CollectsPrometheus               = $flags.Prometheus
            CollectsWindowsFirewallLogs      = $flags.WindowsFirewallLogs
            AssociationCount                 = $assocCount
            AssociatedResourceTypes          = ($assocResourceTypes) -join '; '
            AssociatedResourceIds            = ($assocResourceIds   | Select-Object -Unique) -join '; '
        }
        $results.Add($row) | Out-Null

        $sentinelMark  = if ($sentinelEnabled) { '→ Sentinel' } else { 'NOT Sentinel' }
        $sentinelColor = if ($sentinelEnabled) { 'Green' }      else { 'DarkYellow' }
        Write-Host ("    {0,-50} assoc={1,-3} {2}" -f $dcr.name, $assocCount, $sentinelMark) `
                   -ForegroundColor $sentinelColor
    }
}

# ---------------------------------------------------------------------------
# 3. Export
# ---------------------------------------------------------------------------
Write-Host "`n[3/3] Writing CSV: $OutputPath" -ForegroundColor Yellow
$results | Sort-Object SentinelEnabled, SubscriptionName, DcrName -Descending |
           Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
$total           = $results.Count
$toSentinel      = ($results | Where-Object SentinelEnabled).Count
$nonSentinel     = ($results | Where-Object { -not $_.SentinelEnabled }).Count
$totalAssocs     = ($results | Measure-Object -Property AssociationCount -Sum).Sum
$collectingSec   = ($results | Where-Object CollectsWindowsSecurityLog).Count

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  DCRs inventoried                     : $total"
Write-Host "  DCRs targeting a Sentinel workspace  : $toSentinel"
Write-Host "  DCRs NOT targeting Sentinel          : $nonSentinel"
Write-Host "  DCRs collecting Windows Security log : $collectingSec"
Write-Host "  Total resource associations          : $totalAssocs"
Write-Host "  CSV saved to                         : $OutputPath"

if ($sentinelWorkspaces.Count -gt 1) {
    Write-Host "`n  Breakdown by Sentinel workspace:" -ForegroundColor Cyan
    $results | Where-Object SentinelEnabled |
               ForEach-Object { ($_.SentinelWorkspaces -split '; ') } |
               Where-Object { $_ } |
               Group-Object |
               Sort-Object Count -Descending |
               ForEach-Object {
                   Write-Host ("    {0,-40} {1,5} DCRs" -f $_.Name, $_.Count)
               }
}
