# Sentinel Lookout

> A PowerShell toolkit for Azure Cloud Shell that maps every diagnostic setting **and every Data Collection Rule** in your tenant against your Microsoft Sentinel-enabled Log Analytics workspaces, then turns the result into interactive HTML reports.

**Author:** Predrag (Peter) Petrovic <ppetrovic@microsoft.com>

---

> [!IMPORTANT]
> **This is an open-source community project.** It is **not** an official Microsoft product, is **not** supported by Microsoft, and has no affiliation with or endorsement from Microsoft Corporation. *Microsoft Sentinel*, *Azure*, and *Entra ID* are trademarks of Microsoft Corporation, used here solely to describe the services this tool inspects. Use at your own risk; review the code before running it in production.

---

## What it does

Sentinel Lookout answers the questions every SOC eventually asks:

- Which Log Analytics workspaces have Sentinel attached?
- Which resources in the tenant are sending logs there?
- Which resources have diagnostic settings configured but pointing somewhere else (or nowhere)?
- What kind of telemetry is each resource emitting — and to which Sentinel instance?
- Is Entra ID forwarding all of its log categories?
- **Which Data Collection Rules exist, what are they collecting (Security log, Syslog, custom paths, perf, IIS, extensions…), and where is the data going?**
- **Which VMs / VMSS / Arc machines are not associated with any DCR at all** — and therefore not sending data anywhere?

## Contents

The toolkit ships **two independent audit pipelines** that share the same Sentinel-workspace discovery and the same dark-themed report design.

| File | Purpose |
|---|---|
| `Audit-SentinelDiagnostics.ps1` | Discovers Sentinel workspaces, walks every subscription, exports a CSV of all **diagnostic settings**. |
| `Build-SentinelReport.ps1` | Renders the diagnostic-settings CSV as a self-contained `.html` dashboard. |
| `Audit-SentinelDCRs.ps1` | Inventories every **Data Collection Rule**, what it collects, where it sends data, and which VMs are associated. Also emits a companion VM-coverage CSV. |
| `Build-DCRReport.ps1` | Renders the DCR audit CSVs as a self-contained `.html` dashboard with an **Unassociated VMs** view. |
| `sample-report.html` | Example output rendered against fictional data, for previewing the design. |

## Requirements

- **Azure Cloud Shell (PowerShell)** — works out of the box. The Az modules are preinstalled.
- **Permissions on the tenant:**
  - **Reader** on every subscription you want covered. The cleanest setup is to grant the auditing identity Reader at the **tenant root management group** with inheritance, so no subscription is invisible.
  - **Security Reader** or **Global Reader** at the tenant root for the Entra ID diagnostic settings query. Without it that section returns 403 and is skipped (the rest still runs).

## Quick start

### Diagnostic settings audit

```powershell
# 1. Inventory every diagnostic setting in the tenant
./Audit-SentinelDiagnostics.ps1

# 2. Turn the CSV into an interactive HTML report
./Build-SentinelReport.ps1 -InputCsv ~/SentinelDiagnosticsAudit_20260427_104500.csv

# 3. Pull the HTML out of Cloud Shell to view locally
download ~/SentinelDiagnosticsAudit_20260427_104500.html
```

### Data Collection Rule audit

```powershell
# 1. Inventory every DCR + every VM-like resource in the tenant.
#    Produces two CSVs side by side:
#      ~/SentinelDCRAudit_<ts>.csv      (one row per DCR)
#      ~/SentinelDCRAudit_<ts>_VMs.csv  (one row per VM/VMSS/Arc machine)
./Audit-SentinelDCRs.ps1

# 2. Render the report. Pass only the DCR CSV — the VM CSV is auto-discovered
#    next to it (same base name + _VMs suffix).
./Build-DCRReport.ps1 -InputCsv ~/SentinelDCRAudit_20260501_104500.csv

# 3. Download to view locally
download ~/SentinelDCRAudit_20260501_104500.html
```

## Step 1 — `Audit-SentinelDiagnostics.ps1`

### What it does

1. **Finds Sentinel workspaces.** Sentinel surfaces in ARM as a `Microsoft.OperationsManagement/solutions` resource named `SecurityInsights(<workspace>)`. The script walks every enabled subscription, collects the `workspaceResourceId` from each such solution, and treats that set as "the Sentinel workspaces" — so multi-Sentinel tenants are handled natively.
2. **Enumerates every resource** in every subscription via `Get-AzResource` and runs `Get-AzDiagnosticSetting` on each. Resources that don't support diagnostic settings throw a 404 and are silently skipped.
3. **Queries Entra ID separately.** Entra is tenant-scoped at `/providers/microsoft.aadiam/diagnosticSettings`, which `Get-AzResource` does not return. The script fetches it via `Invoke-AzRestMethod` (API `2017-04-01-preview`), then also pulls the full category list and prints which Entra log categories (e.g. `AuditLogs`, `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ProvisioningLogs`, `RiskyUsers`, `UserRiskEvents` …) are *not* enabled anywhere — useful for finding gaps in identity telemetry.

### Output

A CSV named `SentinelDiagnosticsAudit_<timestamp>.csv` (default location `$HOME`) with one row per diagnostic setting:

| Column | Description |
|---|---|
| `ResourceName` | The resource name, or `Entra ID (Azure AD)` for the tenant-scoped row. |
| `ResourceType` | ARM resource type, e.g. `Microsoft.KeyVault/vaults`. |
| `LogAnalyticsWorkspace` | Workspace name the diagnostic setting points at. |
| `DiagnosticData` | Semicolon-separated list of enabled log categories. Metric categories are prefixed `metric:` so they're easy to tell apart. |
| `SentinelEnabled` | `True` if the destination workspace has Sentinel attached. |
| `SentinelWorkspaceName` | Which Sentinel instance — populated only when `SentinelEnabled = True`. Critical in multi-Sentinel tenants. |
| `DiagnosticSettingName` | Name of the diagnostic setting itself (a single resource can have several). |
| `SubscriptionName`, `ResourceGroup` | Where the resource lives. |
| `WorkspaceResourceId` | Full ARM ID of the destination workspace, for disambiguation. |

### Console summary

The script prints a multi-Sentinel breakdown at the end when more than one Sentinel workspace exists, e.g.:

```
Breakdown by Sentinel workspace:
  sentinel-prod-eu                          142 rows
  sentinel-prod-us                           87 rows
  sentinel-dev                               12 rows
```

### Coverage notes

- **All enabled subscriptions are walked.** Disabled subscriptions are skipped — drop the `State -eq 'Enabled'` filter if you want them included.
- **Management groups are not iterated**, and intentionally so — resources live under subscriptions, not management groups, so a subscription walk covers 100% of resources.
- **Subscription-level and management-group-level diagnostic settings** (Activity Log forwarding) are *not* covered by the current script. They live at separate ARM endpoints and aren't returned by `Get-AzResource`. If you want those, that's a feature to add.

### Az breaking-change warnings

The script sets `$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'` to silence the noisy warnings about `Get-AzDiagnosticSetting` `Log`/`Metric` becoming `List<>` in Az.Monitor 7.0.0+. The cmdlet behaviour we rely on (`.Enabled` and `.Category`) works on both shapes, so the script is forward-compatible.

## Step 2 — `Build-SentinelReport.ps1`

### What it does

Reads the CSV from step 1 and writes a single self-contained `.html` file (no servers, no external JS — just one optional Google Fonts fetch for typography). The page contains:

- **A KPI strip** — rows sending to Sentinel (cyan), rows not sending (red), total diagnostic-setting rows, and Sentinel workspace count.
- **Workspace distribution** — how many rows each Sentinel instance is receiving. In multi-Sentinel tenants this shows the split immediately.
- **Largest gaps** — top 10 resource types whose diagnostics aren't reaching Sentinel, sorted by row count. Use this to prioritise remediation.
- **Two browsable tables:**
  - **Sending to Sentinel** — diagnostic categories rendered as cyan chips. Metric categories appear in a lighter blue so logs and metrics are visually distinct. Status column shows `→ SENTINEL`.
  - **Not sending to Sentinel** — same layout, but every diagnostic chip is **rendered in amber** to highlight that the telemetry is configured but not flowing into your SOC. Empty diagnostic settings render as a red `(none enabled)` chip. Column header carries a `⚠ not flowing to Sentinel` warning.
- **Live filter box** — type any string (resource, type, workspace, subscription, RG, log category) and both tabs filter in real time, with row-count badges updating.
- **Export filtered CSV** — downloads whatever is currently visible in the active tab as a CSV, so you can hand a focused remediation list to an owner without re-running anything.

### Usage

```powershell
# Default: writes alongside the CSV, same filename with .html
./Build-SentinelReport.ps1 -InputCsv ~/SentinelDiagnosticsAudit_20260427_104500.csv

# Custom output path
./Build-SentinelReport.ps1 -InputCsv ~/audit.csv -OutputHtml ~/report.html
```

### Distribution

The report is a single file with all data embedded as JSON. You can email it, drop it in SharePoint, or check it into a repo. Recipients open it offline. If your environment blocks Google Fonts the page falls back to system serif/mono and still renders correctly.

## Step 3 — `Audit-SentinelDCRs.ps1`

### What it does

1. **Discovers Sentinel workspaces** the same way the diagnostics audit does (via `Microsoft.OperationsManagement/solutions` named `SecurityInsights*`), so multi-Sentinel tenants are handled natively.
2. **Lists every Data Collection Rule** in every enabled subscription via the ARM REST API (`Microsoft.Insights/dataCollectionRules`, api-version `2022-06-01`) — including DCRs created by AMA, Defender for Servers, AKS / Container Insights, custom-table rules, and Event Hub stream rules.
3. **For each DCR records:**
   - Destination workspace(s) and a `SentinelEnabled` flag (plus `HasNonSentinelDestination` to flag mixed routing where one DCR sends to both Sentinel and somewhere else).
   - Other destinations (Azure Monitor Metrics, Event Hubs, Storage, Monitoring Accounts).
   - What is actually being collected — both a human-readable summary and per-source booleans:
     - `CollectsWindowsEventLogs` / `CollectsWindowsSecurityLog` (detected from the xPath queries — the Security log is called out specifically because it's the SOC-critical one)
     - `CollectsSyslog`, `CollectsPerformanceCounters`
     - `CollectsCustomLogFiles` (with the configured file patterns preserved)
     - `CollectsIISLogs`, `CollectsExtensions`, `CollectsPrometheus`, `CollectsWindowsFirewallLogs`
   - `Streams` declared in `dataFlows` (e.g. `Microsoft-SecurityEvent`, `Microsoft-Syslog`, `Custom-MyApp_CL`, …).
   - **Every VM / VMSS / Arc machine associated with the rule** via the data-collection-rule-associations API (`{dcrId}/associations?api-version=2022-06-01`). Output captures both a deduped resource-type summary and the full list of associated resource IDs.
4. **Cross-references all VM-like resources** (`Microsoft.Compute/virtualMachines`, `Microsoft.Compute/virtualMachineScaleSets`, `Microsoft.HybridCompute/machines`) against the DCR association index, so you can answer **"which machines have no DCR at all?"** in one pass.

### Output

Two CSVs written side-by-side in `$HOME` (default):

**`SentinelDCRAudit_<timestamp>.csv`** — one row per DCR:

| Column | Description |
|---|---|
| `DcrName`, `DcrResourceId`, `Kind`, `Location` | Identity of the rule. |
| `ResourceGroup`, `SubscriptionName`, `SubscriptionId` | Where it lives. |
| `DestinationWorkspaces` / `DestinationWorkspaceResourceIds` | LA workspaces the DCR sends to (semicolon-joined when multiple). |
| `SentinelEnabled` | `True` if **any** destination workspace has Sentinel attached. |
| `SentinelWorkspaces` | Names of the Sentinel-enabled destinations (multi-Sentinel safe). |
| `HasNonSentinelDestination` | `True` if at least one destination is **not** a Sentinel workspace — flags split routing. |
| `OtherDestinations` | Non-LA destinations: `AzureMonitorMetrics`, `EventHubs`, `StorageAccounts`, `MonitoringAccounts`, etc. |
| `DataCollectionSummary` | Human-readable list of what is being collected, e.g. `WindowsEventLogs(SECURITY) [Security!*[…]]; PerfCounters x12 @60s; LogFiles(json) [/var/log/myapp/*.json]`. |
| `Streams` | Stream names from `dataFlows` (e.g. `Microsoft-SecurityEvent;Microsoft-Perf`). |
| `CollectsWindowsSecurityLog`, `CollectsSyslog`, `CollectsCustomLogFiles`, … | Per-source booleans for fast filtering. |
| `AssociationCount` | How many VMs / VMSS / Arc machines reference this rule. |
| `AssociatedResourceTypes` | Deduped list of associated resource types. |
| `AssociatedResourceIds` | Full list of associated resource IDs (semicolon-joined). |

**`SentinelDCRAudit_<timestamp>_VMs.csv`** — one row per VM-like resource:

| Column | Description |
|---|---|
| `VmName`, `VmType`, `ResourceId`, `Location` | Identity of the machine. |
| `OsHint` | Best-effort OS / kind hint (filled when easily available). |
| `ResourceGroup`, `SubscriptionName`, `SubscriptionId` | Where it lives. |
| `HasDcrAssociation` | `False` for machines with **zero** DCR associations — these are the ones not collecting anything via AMA. |
| `AssociatedDcrCount` | How many DCRs target this machine. |
| `SendingToSentinel` | `True` if at least one of the associated DCRs writes to a Sentinel workspace. |
| `AssociatedDcrNames` | Names of the DCRs associated to this machine. |

### Console summary

At the end of the run the script prints:

```
DCRs inventoried                     : 47
DCRs targeting a Sentinel workspace  : 31
DCRs NOT targeting Sentinel          : 16
DCRs collecting Windows Security log : 22
Total resource associations          : 412
VM-like resources discovered         : 318
VMs with NO DCR association          :  74
VMs not sending to any Sentinel WS   : 102
```

Multi-Sentinel tenants additionally get a per-workspace breakdown of how many DCRs feed each Sentinel.

### Permissions

**Reader** on each subscription is sufficient. No Microsoft Graph calls are made — the DCR audit is purely ARM. Granting Reader at the **tenant root management group** with inheritance gives complete coverage.

## Step 4 — `Build-DCRReport.ps1`

### What it does

Reads the DCR CSV (and auto-discovers the `_VMs.csv` companion next to it) and writes a single self-contained `.html` dashboard with:

- **KPI strip** — DCRs sending to Sentinel, DCRs **not** sending to Sentinel (with their respective association counts), total DCRs, Sentinel workspace count, and **VMs without any DCR**.
- **Workspace distribution** — which Sentinel instance each DCR is feeding (handles multi-Sentinel tenants).
- **Collection-coverage matrix** — how many DCRs collect each kind of data (Windows Security log, Windows Event Logs, Syslog, performance counters, custom log files, IIS, extensions, Prometheus, Windows firewall).
- **Three browsable tables:**
  - **Sending to Sentinel** — destinations rendered with a `ⓢ` marker for Sentinel workspaces; data sources rendered as colored chips, with the Windows Security log chip highlighted in red so it pops; per-DCR expandable list of the actual VMs / VMSS / Arc machines associated.
  - **Not sending to Sentinel** — same layout, all chips amber to flag that the data is being collected but not flowing into your SOC. Status badge distinguishes `Sentinel + other` (split routing) from `no Sentinel`.
  - **Unassociated VMs** — every VM / VMSS / Arc machine in the tenant with zero DCR associations. This is the gap list — machines whose AMA isn't pulling anything because no rule targets them.
- **Live filter** — type any substring (DCR name, workspace, subscription, RG, stream, data source, associated VM ID) and all three tabs filter in real time.
- **Export filtered CSV** — exports whatever is visible in the active tab; the Unassociated VMs tab exports the VM column set, the DCR tabs export the DCR column set.

### Usage

```powershell
# Default: writes alongside the CSV, same filename with .html
./Build-DCRReport.ps1 -InputCsv ~/SentinelDCRAudit_20260501_104500.csv

# Custom output path
./Build-DCRReport.ps1 -InputCsv ~/dcrs.csv -OutputHtml ~/dcr-report.html
```

The companion VM CSV is found automatically by stripping the `.csv` extension and appending `_VMs.csv`. If the file isn't found alongside the DCR CSV the script logs a warning and the **Unassociated VMs** tab simply renders empty — the rest of the report still works.

## Typical workflow

### Diagnostic-settings gap hunt

1. Run `Audit-SentinelDiagnostics.ps1` from Cloud Shell.
2. Run `Build-SentinelReport.ps1` against the CSV.
3. `download` the HTML, open it locally.
4. Click the **Not sending to Sentinel** tab.
5. Sort or filter by `Subscription`, `ResourceType`, or a specific log category.
6. Use **Export filtered CSV** to send a targeted list to whoever owns those resources.
7. Re-run after remediation to confirm the gap closed.

### DCR / VM coverage gap hunt

1. Run `Audit-SentinelDCRs.ps1` from Cloud Shell. Two CSVs are produced.
2. Run `Build-DCRReport.ps1 -InputCsv <DCR csv>`. The VM CSV is picked up automatically.
3. `download` the HTML, open it locally.
4. Open the **Unassociated VMs** tab — every machine here is silent: no DCR, no AMA pipeline, no data.
5. Open the **Not sending to Sentinel** tab — every DCR here is collecting data but routing it somewhere other than your SOC. Filter for `Microsoft-SecurityEvent` to find Security-event collection that is bypassing Sentinel.
6. On the **Sending to Sentinel** tab, filter the collection-coverage matrix or the chips to confirm critical sources (Windows Security log, Syslog auth facilities, custom application paths) are actually reaching Sentinel.
7. Use **Export filtered CSV** for any of the three tabs to hand off remediation lists.

## Caveats

- **Performance.** One ARM call per resource means large tenants (10k+ resources) take time. If you need it faster, the same data can be pulled in bulk via Azure Resource Graph (`resources | join (...) on ...`) — that's a bigger rewrite.
- **Multiple diagnostic settings per resource** are common (a Key Vault might send audit events to Sentinel and metrics to a separate workspace). Each becomes its own row, which is what you want for an audit but means the row count exceeds the unique resource count.
- **`SentinelEnabled = True` means "the destination workspace has the SecurityInsights solution attached."** It does not validate that Sentinel data connectors for that resource type are *enabled* in the Sentinel workspace, or that ingestion is actually succeeding — only that the diagnostic setting points at a Sentinel-equipped workspace. Connector and ingestion checks are a separate problem.
- **Identity scope matters.** `Get-AzSubscription` only returns subscriptions the running identity can see. To guarantee tenant-wide visibility, elevate to the tenant root group ("Access management for Azure resources" in the Entra portal) before running, or assign Reader at the root MG to the auditing identity.

## License

Released under the **MIT License**. See `LICENSE` for the full text.

Copyright © 2026 Predrag (Peter) Petrovic.

## Disclaimer

Sentinel Lookout is an independent open-source project. It is not produced, endorsed, sponsored, or supported by Microsoft Corporation. References to *Microsoft Sentinel*, *Azure*, *Entra ID*, *Log Analytics*, and related product names are made solely to describe the Microsoft services this tool inspects, and all such trademarks remain the property of their respective owners.

The software is provided "as is", without warranty of any kind. The author accepts no liability for any consequences of running it against your tenant. Always review code before granting it tenant-wide read permissions.

## Contributing

Issues, feature requests, and pull requests are welcome. Useful directions for contribution include:

- Subscription-level and management-group-level Activity Log diagnostic settings.
- Azure Resource Graph backend for large tenants (10k+ resources).
- Validation that Sentinel data connectors for inspected resource types are actually enabled.
- DCR ingestion-health check (correlate DCR associations with actual heartbeat data in the workspace).
- Detection of orphaned DCRs (rules with zero associations) and orphaned DCEs (Data Collection Endpoints unreferenced by any DCR).
- Additional output formats (JSON, Markdown table, Azure Workbook export).
