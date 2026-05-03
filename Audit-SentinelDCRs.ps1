<#
.SYNOPSIS
    Audits every Data Collection Rule (DCR) in the tenant, the resources associated
    with each rule, and whether the destination Log Analytics Workspace is Sentinel-enabled.
    Supports parallel workers and resume-on-rerun for large tenants.

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

    Tracking & resume:
        Per-subscription progress is written to a sidecar state directory next to
        -OutputPath (default '<OutputPath>.state'). Each DCR row is appended to
        a per-subscription partial CSV immediately after it is fetched, so an
        interrupted run loses at most the in-flight subscription. On rerun the
        script reattaches to the existing state directory and skips subscriptions
        whose .done marker is present.

    Parallelism:
        On PowerShell 7+ subscriptions are processed concurrently with
        ForEach-Object -Parallel (default 4 workers, configurable via
        -ThrottleLimit). The constant ARM traffic also helps prevent Azure
        Cloud Shell's 20-minute idle timeout from killing the session.

.PARAMETER OutputPath
    Final CSV path. A companion CSV with VM-association data is written next to it.

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
    ./Audit-SentinelDCRs.ps1
        Run with defaults; resumes automatically if the state directory exists.

.EXAMPLE
    ./Audit-SentinelDCRs.ps1 -ThrottleLimit 8 -OutputPath ./dcr.csv
        Use 8 parallel workers and a custom output path.

.EXAMPLE
    ./Audit-SentinelDCRs.ps1 -OutputPath ./dcr.csv -CleanState
        Delete the state directory on successful completion.

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout

    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell).
    Reader on each subscription is sufficient. No Microsoft Graph calls are made.
    PowerShell 7+ is required for parallel execution; PS5.1 is not supported.

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.
#>

[CmdletBinding()]
param(
    [string] $OutputPath    = "$HOME/SentinelDCRAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
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

# DCR + DCRA stable GA API version.
$DcrApiVersion  = '2022-06-01'
$DcraApiVersion = '2022-06-01'

# Companion CSV listing every VM-like resource and whether it is associated with any DCR.
$VmOutputPath = [System.IO.Path]::Combine(
    [System.IO.Path]::GetDirectoryName($OutputPath),
    [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_VMs.csv'
)

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
Write-Host "VM CSV       : $VmOutputPath"     -ForegroundColor Cyan
Write-Host "Throttle     : $ThrottleLimit"    -ForegroundColor Cyan

$null = Initialize-AuditState -StatePath $StatePath -TenantId $ctx.Tenant.Id `
                              -OutputPath $OutputPath -Kind 'DCR' -Force:$Force

$subscriptions = Get-AzSubscription -TenantId $ctx.Tenant.Id |
                 Where-Object { $_.State -eq 'Enabled' }

# ---------------------------------------------------------------------------
# Helpers (per-DCR data shaping). Re-imported into each parallel runspace.
# ---------------------------------------------------------------------------
function Get-DcrDataCollectionSummary {
    param($Properties)

    $summary = New-Object System.Collections.Generic.List[string]
    $ds      = $Properties.dataSources
    if (-not $ds) {
        $summary.Add('(no data sources)')
        return ,$summary
    }

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
    if ($ds.syslog) {
        foreach ($s in $ds.syslog) {
            $facs = @($s.facilityNames) -join ','
            $lvls = @($s.logLevels)     -join ','
            $summary.Add("Syslog facilities=[$facs] levels=[$lvls]")
        }
    }
    if ($ds.performanceCounters) {
        foreach ($p in $ds.performanceCounters) {
            $cnt  = (@($p.counterSpecifiers)).Count
            $freq = $p.samplingFrequencyInSeconds
            $summary.Add("PerfCounters x$cnt @${freq}s")
        }
    }
    if ($ds.logFiles) {
        foreach ($l in $ds.logFiles) {
            $patterns = @($l.filePatterns) -join ', '
            $fmt      = $l.format
            $summary.Add("LogFiles($fmt) [$patterns]")
        }
    }
    if ($ds.iisLogs) {
        foreach ($i in $ds.iisLogs) {
            $dirs = @($i.logDirectories) -join ', '
            $summary.Add("IISLogs [$dirs]")
        }
    }
    if ($ds.extensions) {
        foreach ($e in $ds.extensions) { $summary.Add("Extension:$($e.extensionName)") }
    }
    if ($ds.prometheusForwarder) { $summary.Add("PrometheusForwarder x$((@($ds.prometheusForwarder)).Count)") }
    if ($ds.windowsFirewallLogs) { $summary.Add("WindowsFirewallLogs") }
    if ($ds.platformTelemetry)   { $summary.Add("PlatformTelemetry") }
    if ($Properties.dataSources.dataImports) { $summary.Add("DataImports") }

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
# 1. Discover Sentinel-enabled Log Analytics Workspaces (refreshed every run)
# ---------------------------------------------------------------------------
Write-Host "`n[1/4] Locating Sentinel-enabled Log Analytics Workspaces..." -ForegroundColor Yellow

$workspacesCachePath = Join-Path $StatePath 'workspaces.json'
$sentinelWorkspaces  = @{}

# Always refresh: workspaces are cheap to list and stale data leads to wrong SentinelEnabled.
$tenantId = $ctx.Tenant.Id
$wsHits   = $subscriptions | ForEach-Object -Parallel {
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
        if ($wsId) {
            [pscustomobject]@{ id = $wsId; name = ($wsId -split '/')[-1] }
        }
    }
} -ThrottleLimit $ThrottleLimit

foreach ($w in $wsHits) {
    $sentinelWorkspaces[$w.id.ToLower()] = $w.name
    Write-Host "  Sentinel workspace: $($w.id)" -ForegroundColor Green
}
$sentinelWorkspaces | ConvertTo-Json | Set-Content -Path $workspacesCachePath -Encoding UTF8

if ($sentinelWorkspaces.Count -eq 0) {
    Write-Warning "No Sentinel-enabled workspaces found. SentinelEnabled will be False for all rows."
} else {
    Write-Host "  Total Sentinel-enabled workspaces discovered: $($sentinelWorkspaces.Count)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Enumerate every DCR per subscription (parallel, resumable)
# ---------------------------------------------------------------------------
Write-Host "`n[2/4] Enumerating Data Collection Rules and associations..." -ForegroundColor Yellow

$fnDefs = Get-WorkerFunctionDefinitions -Extra @('Get-DcrDataCollectionSummary', 'Get-DcrCollectionFlags')
$partialsDir = Join-Path $StatePath 'partials'

$totalSubs = $subscriptions.Count
$counter   = [hashtable]::Synchronized(@{ done = 0 })

$subscriptions | ForEach-Object -Parallel {
    $sub        = $_
    $sp         = $using:StatePath
    $partials   = $using:partialsDir
    $tid        = $using:tenantId
    $apiVer     = $using:DcrApiVersion
    $apiVerA    = $using:DcraApiVersion
    $wsMap      = $using:sentinelWorkspaces
    $defs       = $using:fnDefs
    $ctr        = $using:counter
    $totSubs    = $using:totalSubs

    # Reconstitute helper functions in this runspace.
    foreach ($n in $defs.Keys) { Set-Item -Path "function:$n" -Value $defs[$n] }

    $dcrCsv     = Join-Path $partials "dcrs.$($sub.Id).csv"
    $assocFile  = Join-Path $partials "assoc.$($sub.Id).jsonl"
    $doneMarker = "dcr-$($sub.Id)"

    if (Test-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker) {
        $ctr.done++
        Write-Host ("  [{0,3}/{1}] {2,-40} (cached)" -f $ctr.done, $totSubs, $sub.Name) -ForegroundColor DarkGray
        return
    }

    # Fresh attempt: clear any partial leftovers from a previous interrupted run.
    if (Test-Path $dcrCsv)    { Remove-Item -Force $dcrCsv }
    if (Test-Path $assocFile) { Remove-Item -Force $assocFile }

    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $tid -ErrorAction Stop | Out-Null }
    catch {
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'set-context' -Message $_.Exception.Message
        $ctr.done++
        return
    }

    # List DCRs (paginated REST call) with retry.
    $dcrs    = New-Object System.Collections.Generic.List[object]
    $nextUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Insights/dataCollectionRules?api-version=$apiVer"
    while ($nextUri) {
        try { $resp = Invoke-ArmRequest -Uri $nextUri }
        catch {
            Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'dcr-list' -Message $_.Exception.Message
            $resp = $null
            break
        }
        if (-not $resp -or $resp.StatusCode -ne 200) {
            if ($resp) {
                Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'dcr-list' `
                                 -Message "HTTP $($resp.StatusCode): $($resp.Content)"
            }
            break
        }
        $page = $resp.Content | ConvertFrom-Json
        if ($page.value) { $page.value | ForEach-Object { $dcrs.Add($_) | Out-Null } }
        $nextUri = $page.nextLink
    }

    $totalAssocs = 0
    foreach ($dcr in $dcrs) {
        $props = $dcr.properties

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
            $wsNames       += ($wsId -split '/')[-1]
            if ($wsMap.ContainsKey($wsId.ToLower())) {
                $sentinelHits += $wsMap[$wsId.ToLower()]
            } else {
                $hasNonSentinel = $true
            }
        }
        $sentinelEnabled = ($sentinelHits.Count -gt 0)

        $otherDestinations = @()
        if ($props.destinations.azureMonitorMetrics) { $otherDestinations += 'AzureMonitorMetrics' }
        if ($props.destinations.eventHubs)           { $otherDestinations += 'EventHubs'           }
        if ($props.destinations.eventHubsDirect)     { $otherDestinations += 'EventHubsDirect'     }
        if ($props.destinations.storageAccounts)     { $otherDestinations += 'StorageAccounts'     }
        if ($props.destinations.storageBlobsDirect)  { $otherDestinations += 'StorageBlobsDirect'  }
        if ($props.destinations.storageTablesDirect) { $otherDestinations += 'StorageTablesDirect' }
        if ($props.destinations.monitoringAccounts)  { $otherDestinations += 'MonitoringAccounts'  }

        $dataSummary     = Get-DcrDataCollectionSummary -Properties $props
        $dataFlowStreams = @()
        if ($props.dataFlows) {
            foreach ($df in $props.dataFlows) { $dataFlowStreams += @($df.streams) }
        }
        $dataFlowStreams = $dataFlowStreams | Select-Object -Unique
        $flags = Get-DcrCollectionFlags -Properties $props

        # Associations
        $assocResourceIds   = @()
        $assocResourceTypes = @()
        $assocCount         = 0
        try {
            $assocUri  = "https://management.azure.com$($dcr.id)/associations?api-version=$apiVerA"
            $assocResp = Invoke-ArmRequest -Uri $assocUri
            if ($assocResp.StatusCode -eq 200) {
                $assocPayload = $assocResp.Content | ConvertFrom-Json
                foreach ($a in @($assocPayload.value)) {
                    $idx = $a.id.ToLower().IndexOf('/providers/microsoft.insights/datacollectionruleassociations/')
                    if ($idx -gt 0) {
                        $targetId = $a.id.Substring(0, $idx)
                        $assocResourceIds += $targetId

                        # Persist association so the VM-cross-reference phase can rebuild
                        # the index without re-fetching DCRs.
                        $assocLine = [pscustomobject]@{
                            target          = $targetId
                            dcrName         = $dcr.name
                            dcrId           = $dcr.id
                            sentinelEnabled = $sentinelEnabled
                        } | ConvertTo-Json -Compress
                        Add-Content -Path $assocFile -Value $assocLine -Encoding UTF8

                        $segs = $targetId -split '/'
                        if ($segs.Length -ge 8) {
                            $providerNs = $segs[6]
                            $typeChain  = ($segs[7..($segs.Length - 2)] | Where-Object { $_ }) -join '/'
                            $assocResourceTypes += "$providerNs/$typeChain"
                        }
                    }
                    $assocCount++
                }
            } elseif ($assocResp.StatusCode -ne 404) {
                Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'dcr-assoc' `
                                 -Target $dcr.name -Message "HTTP $($assocResp.StatusCode)"
            }
        } catch {
            Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'dcr-assoc' `
                             -Target $dcr.name -Message $_.Exception.Message
        }
        $totalAssocs += $assocCount
        $assocResourceTypes = $assocResourceTypes | Select-Object -Unique

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

        # Per-DCR durable append.
        Add-CsvRow -Path $dcrCsv -Row $row
    }

    Set-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker `
                         -Stats @{ dcrs = $dcrs.Count; assocs = $totalAssocs }

    $ctr.done++
    Write-Host ("  [{0,3}/{1}] {2,-40} dcrs={3,-4} assocs={4}" -f $ctr.done, $totSubs, $sub.Name, $dcrs.Count, $totalAssocs) -ForegroundColor Cyan
} -ThrottleLimit $ThrottleLimit

# ---------------------------------------------------------------------------
# 3. Rebuild assocIndex from disk and enumerate VMs (parallel, resumable)
# ---------------------------------------------------------------------------
Write-Host "`n[3/4] Enumerating VMs / VMSS / Arc machines and checking DCR coverage..." -ForegroundColor Yellow

# Build with List[object] for fast appends, then FREEZE to plain object[] arrays.
# This is critical: PS7 ForEach-Object -Parallel passes $using: variables through
# a serialization boundary, and hashtables whose values are List[object] become
# unindexable inside the runspace ($idx[$key] throws "Argument types do not
# match"). Plain arrays survive the boundary correctly.
$assocBuild = @{}
Get-ChildItem -Path $partialsDir -Filter 'assoc.*.jsonl' -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($line in (Get-Content -Path $_.FullName)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $entry = $line | ConvertFrom-Json
        $key = $entry.target.ToLower()
        if (-not $assocBuild.ContainsKey($key)) {
            $assocBuild[$key] = New-Object System.Collections.Generic.List[object]
        }
        $assocBuild[$key].Add([pscustomobject]@{
            DcrName         = $entry.dcrName
            DcrId           = $entry.dcrId
            SentinelEnabled = $entry.sentinelEnabled
        }) | Out-Null
    }
}
$assocIndex = @{}
foreach ($k in $assocBuild.Keys) {
    $assocIndex[$k] = $assocBuild[$k].ToArray()
}
$assocBuild = $null
Write-Host "  Loaded $($assocIndex.Count) associated resource id(s) from partial state."

$vmTypes = @(
    'Microsoft.Compute/virtualMachines',
    'Microsoft.Compute/virtualMachineScaleSets',
    'Microsoft.HybridCompute/machines'
)

# Drop any stale vm-* .done markers from runs that pre-date the assoc-index fix,
# so users don't have to manually nuke their state directory after upgrading.
$staleMarkers = Get-ChildItem -Path (Join-Path $StatePath 'subscriptions') -Filter 'vm-*.done' -ErrorAction SilentlyContinue
if ($staleMarkers) {
    Write-Host "  Resetting $($staleMarkers.Count) VM .done marker(s) to recompute associations..." -ForegroundColor DarkYellow
    $staleMarkers | Remove-Item -Force
}

$vmCounter = [hashtable]::Synchronized(@{ done = 0 })

$subscriptions | ForEach-Object -Parallel {
    $sub      = $_
    $sp       = $using:StatePath
    $partials = $using:partialsDir
    $tid      = $using:tenantId
    $defs     = $using:fnDefs
    $idx      = $using:assocIndex
    $vmTypes2 = $using:vmTypes
    $ctr      = $using:vmCounter
    $totSubs  = $using:totalSubs

    foreach ($n in $defs.Keys) { Set-Item -Path "function:$n" -Value $defs[$n] }

    $vmCsv      = Join-Path $partials "vms.$($sub.Id).csv"
    $doneMarker = "vm-$($sub.Id)"

    if (Test-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker) {
        $ctr.done++
        Write-Host ("  [{0,3}/{1}] {2,-40} (cached)" -f $ctr.done, $totSubs, $sub.Name) -ForegroundColor DarkGray
        return
    }
    if (Test-Path $vmCsv) { Remove-Item -Force $vmCsv }

    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $tid -ErrorAction Stop | Out-Null }
    catch {
        Write-AuditError -StatePath $sp -SubscriptionId $sub.Id -Phase 'set-context-vm' -Message $_.Exception.Message
        $ctr.done++
        return
    }

    $vms = @()
    foreach ($t in $vmTypes2) {
        $vms += Get-AzResource -ResourceType $t -ErrorAction SilentlyContinue
    }

    foreach ($vm in $vms) {
        $key     = $vm.ResourceId.ToLower()
        $entries = @()
        if ($idx.ContainsKey($key)) {
            # Wrap in @() to coerce single-element values into an array; the
            # value is already a plain object[] (see assoc-index freeze in main
            # thread above) so the indexer is safe across the parallel boundary.
            $entries = @($idx[$key])
        }

        $dcrCount = $entries.Count
        $hasDcr   = $dcrCount -gt 0
        $hasSent  = $false
        $dcrNames = ''
        if ($dcrCount -gt 0) {
            $hasSent  = (@($entries | Where-Object { $_.SentinelEnabled })).Count -gt 0
            $dcrNames = (@($entries | Select-Object -ExpandProperty DcrName -Unique)) -join '; '
        }

        $osType = ''
        if ($vm.Kind)                                      { $osType = $vm.Kind }
        elseif ($vm.Properties -and $vm.Properties.osType) { $osType = $vm.Properties.osType }

        $row = [pscustomobject]@{
            VmName               = $vm.Name
            VmType               = $vm.ResourceType
            ResourceId           = $vm.ResourceId
            Location             = $vm.Location
            ResourceGroup        = $vm.ResourceGroupName
            SubscriptionName     = $sub.Name
            SubscriptionId       = $sub.Id
            OsHint               = $osType
            HasDcrAssociation    = $hasDcr
            AssociatedDcrCount   = $dcrCount
            SendingToSentinel    = $hasSent
            AssociatedDcrNames   = $dcrNames
        }
        Add-CsvRow -Path $vmCsv -Row $row
    }

    Set-SubscriptionDone -StatePath $sp -SubscriptionId $doneMarker -Stats @{ vms = $vms.Count }
    $ctr.done++
    Write-Host ("  [{0,3}/{1}] {2,-40} vms={3}" -f $ctr.done, $totSubs, $sub.Name, $vms.Count) -ForegroundColor Cyan
} -ThrottleLimit $ThrottleLimit

# ---------------------------------------------------------------------------
# 4. Merge partials into final CSVs
# ---------------------------------------------------------------------------
Write-Host "`n[4/4] Merging partial CSVs..." -ForegroundColor Yellow
Write-Host "  DCR CSV : $OutputPath"
$results = Merge-PartialCsvs -PartialsDir $partialsDir -Filter 'dcrs.*.csv' `
                             -OutputPath $OutputPath `
                             -SortBy @('SentinelEnabled','SubscriptionName','DcrName') -Descending

Write-Host "  VM CSV  : $VmOutputPath"
$vmResults = Merge-PartialCsvs -PartialsDir $partialsDir -Filter 'vms.*.csv' `
                               -OutputPath $VmOutputPath `
                               -SortBy @('HasDcrAssociation','SubscriptionName','VmName')

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
$total           = $results.Count
$toSentinel      = ($results | Where-Object { $_.SentinelEnabled -eq 'True' }).Count
$nonSentinel     = ($results | Where-Object { $_.SentinelEnabled -ne 'True' }).Count
$totalAssocs     = ($results | Measure-Object -Property AssociationCount -Sum).Sum
$collectingSec   = ($results | Where-Object { $_.CollectsWindowsSecurityLog -eq 'True' }).Count

$totalVms        = $vmResults.Count
$vmsNoDcr        = ($vmResults | Where-Object { $_.HasDcrAssociation -ne 'True' }).Count
$vmsNoSentinel   = ($vmResults | Where-Object { $_.SendingToSentinel -ne 'True' }).Count

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  DCRs inventoried                     : $total"
Write-Host "  DCRs targeting a Sentinel workspace  : $toSentinel"
Write-Host "  DCRs NOT targeting Sentinel          : $nonSentinel"
Write-Host "  DCRs collecting Windows Security log : $collectingSec"
Write-Host "  Total resource associations          : $totalAssocs"
Write-Host "  VM-like resources discovered         : $totalVms"
Write-Host "  VMs with NO DCR association          : $vmsNoDcr"
Write-Host "  VMs not sending to any Sentinel WS   : $vmsNoSentinel"
Write-Host "  DCR CSV                              : $OutputPath"
Write-Host "  VM  CSV                              : $VmOutputPath"

if ($sentinelWorkspaces.Count -gt 1) {
    Write-Host "`n  Breakdown by Sentinel workspace:" -ForegroundColor Cyan
    $results | Where-Object { $_.SentinelEnabled -eq 'True' } |
               ForEach-Object { ($_.SentinelWorkspaces -split '; ') } |
               Where-Object { $_ } |
               Group-Object |
               Sort-Object Count -Descending |
               ForEach-Object {
                   Write-Host ("    {0,-40} {1,5} DCRs" -f $_.Name, $_.Count)
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
