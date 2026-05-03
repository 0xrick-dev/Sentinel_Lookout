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

The toolkit ships **three independent audit pipelines** that share the same checkpoint/resume engine and the same dark-themed report design.

| File | Purpose |
|---|---|
| `Audit-SentinelDiagnostics.ps1` | Discovers Sentinel workspaces, walks every subscription, exports a CSV of all **diagnostic settings**. Parallel + resumable. |
| `Build-SentinelReport.ps1` | Renders the diagnostic-settings CSV as a self-contained `.html` dashboard. |
| `Audit-SentinelDCRs.ps1` | Inventories every **Data Collection Rule**, what it collects, where it sends data, and which VMs are associated. Also emits a companion VM-coverage CSV. Parallel + resumable. |
| `Build-DCRReport.ps1` | Renders the DCR audit CSVs as a self-contained `.html` dashboard with an **Unassociated VMs** view. |
| `Audit-DefenderForCloud.ps1` | Inventories every **Defender for Cloud plan** in every subscription — PricingTier, sub-plan, deprecated flag, and per-plan extensions — so you can see exactly what is and isn't covered. Parallel + resumable. |
| `Build-DefenderReport.ps1` | Renders the Defender plan CSV as a self-contained `.html` dashboard with **Covered (Standard)** vs **Not covered** views. |
| `_AuditState.ps1` | Shared helpers used by all audit scripts: checkpoint state, per-subscription `.done` markers, partial-CSV append, ARM retry. Dot-sourced; not run directly. |
| `sample-report.html` | Example output rendered against fictional data, for previewing the design. |

## Requirements

- **Azure Cloud Shell (PowerShell)** — works out of the box. The Az modules are preinstalled. **PowerShell 7+** is required (Cloud Shell PowerShell is 7.x by default); the audit scripts use `ForEach-Object -Parallel` and will exit on PS 5.1.
- **Permissions on the tenant:**
  - **Reader** on every subscription you want covered. The cleanest setup is to grant the auditing identity Reader at the **tenant root management group** with inheritance, so no subscription is invisible.
  - **Security Reader** or **Global Reader** at the tenant root for the Entra ID diagnostic settings query. Without it that section returns 403 and is skipped (the rest still runs).

### Running locally (outside Cloud Shell)

The toolkit was designed for Cloud Shell but runs identically on a local workstation. You just need to install what Cloud Shell provides for free.

#### Required

1. **PowerShell 7.2+.** `ForEach-Object -Parallel` and the parallel/resume code path require it; PS 5.1 is not supported.
   - macOS: `brew install --cask powershell` then run `pwsh`
   - Windows: install PowerShell 7 from the Microsoft Store or [github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell)
   - Linux: distro package or the same GitHub release
2. **Az PowerShell modules.** Install once:
   ```powershell
   Install-Module Az -Scope CurrentUser -Repository PSGallery
   # Minimum subset if you don't want all of Az:
   #   Az.Accounts, Az.Resources, Az.Monitor, Az.OperationalInsights
   ```
3. **Sign in to Azure** before running the scripts:
   ```powershell
   Connect-AzAccount -TenantId <your-tenant-id>
   # Optional: pin a default subscription (the scripts switch contexts internally anyway)
   Set-AzContext -SubscriptionId <sub-id>
   ```
4. **Azure permissions** — same as Cloud Shell: **Reader** on every subscription (cleanest at the tenant root MG with inheritance, after elevating via *Entra portal → Properties → Access management for Azure resources*) plus **Security Reader** / **Global Reader** for the Entra ID diagnostic-settings block.
5. **Execution policy (Windows only).** If `./Audit-SentinelDCRs.ps1` is blocked:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   # or unblock just the script files in this repo:
   Get-ChildItem *.ps1 | Unblock-File
   ```

#### Recommended

- **Internet egress** to `*.management.azure.com` and `login.microsoftonline.com`. If you're behind a corporate proxy:
  ```powershell
  $env:HTTPS_PROXY = 'http://proxy.corp:8080'
  ```
- **Disk space** next to your `-OutputPath` for the `<OutputPath>.state` sidecar. For a 100-subscription tenant, expect a few hundred MB of partial CSVs during the run; they're merged into the final CSV at the end and can be removed with `-CleanState`.

#### Optional — unattended / service-principal runs

```powershell
$sp = Get-Credential   # appId as username, client secret as password
Connect-AzAccount -ServicePrincipal -TenantId <tid> -Credential $sp
```

The SP needs the same Reader / Security Reader assignments described above.

#### Quick local smoke test

```powershell
pwsh
Connect-AzAccount -TenantId <tid>
cd /path/to/Sentinel_Lookout
./Audit-SentinelDCRs.ps1 -ThrottleLimit 4 -OutputPath ./dcr.csv
./Build-DCRReport.ps1   -InputCsv ./dcr.csv
# Open ./dcr.html in any browser
```

If the run is interrupted, just re-run the same `Audit-*` command — it reattaches to `./dcr.csv.state` and skips the subscriptions already marked done.

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

### Defender for Cloud coverage audit

```powershell
# 1. Inventory every Defender for Cloud plan in every subscription.
#    One row per (subscription × plan): VirtualMachines, Containers, StorageAccounts,
#    SqlServers, KeyVaults, Arm, Api, CloudPosture, etc.
./Audit-DefenderForCloud.ps1

# 2. Render the report. Two browsable tabs: Covered (Standard) vs Not covered.
./Build-DefenderReport.ps1 -InputCsv ~/DefenderForCloudAudit_20260503_104500.csv

# 3. Download to view locally
download ~/DefenderForCloudAudit_20260503_104500.html
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

### Tracking, resume, and parallel workers

Large tenants used to get cut off mid-run by Azure Cloud Shell's 20-minute idle timeout. Both audit scripts now checkpoint per subscription and run subscriptions in parallel:

- **Per-subscription `.done` markers** are written to a sidecar state directory next to `-OutputPath` (default `<OutputPath>.state`). Re-running the script reattaches to the existing state directory, prints `Resuming run <id> (...; N sub(s) already complete)`, and **skips subscriptions that already finished** — printing `(cached)` next to their names.
- **Per-DCR / per-resource durability.** Each row is appended to a per-subscription partial CSV (`partials/diag.<subId>.csv`, `partials/dcrs.<subId>.csv`, `partials/vms.<subId>.csv`) immediately after it is fetched. An interruption mid-subscription costs at most that one in-flight subscription, which is automatically refetched from scratch on rerun.
- **Parallel workers.** Subscriptions are processed concurrently with `ForEach-Object -Parallel`. Default 4 workers, configurable via `-ThrottleLimit`. Constant ARM traffic also keeps the Cloud Shell session active so the 20-minute idle timer does not fire.
- **ARM retry.** All ARM REST calls are wrapped with bounded exponential retry on HTTP 429 / 5xx so a transient throttle does not fail a whole subscription.
- **Final merge.** When all subscriptions are complete, partial CSVs are merged, sorted, and written to `-OutputPath` — exactly the same schema as before, so the report scripts (`Build-SentinelReport.ps1`, `Build-DCRReport.ps1`) need no changes.
- **Non-fatal errors** (one resource that times out, an Entra 403, etc.) are appended to `<state>/errors/errors.jsonl` and do not stop the run. After completion the script reports the count and points at the file.

#### New parameters (both audit scripts)

| Parameter | Default | Purpose |
|---|---|---|
| `-ThrottleLimit <int>` | `4` | Max subscriptions processed concurrently. Increase for large tenants; back off if you see 429s. |
| `-StatePath <path>` | `<OutputPath>.state` | Override location of the checkpoint state directory. |
| `-Force` | off | Allow resuming a state directory whose recorded `tenantId` differs from the current Az context. |
| `-CleanState` | off | Delete the state directory after a successful run. `errors.jsonl` is preserved as `<OutputPath>.errors.jsonl` if any non-fatal errors were recorded. |

#### Examples

```powershell
# Default run; resumes automatically if a prior run was interrupted.
./Audit-SentinelDCRs.ps1

# 8 parallel workers and a custom output path.
./Audit-SentinelDCRs.ps1 -ThrottleLimit 8 -OutputPath ./dcr.csv

# Force resume against a different tenant context (rare).
./Audit-SentinelDiagnostics.ps1 -StatePath ./diag.state -Force

# Clean up state on a successful run, keep any error log.
./Audit-SentinelDiagnostics.ps1 -OutputPath ./diag.csv -CleanState
```

#### Recovering from a Cloud Shell timeout

1. Reconnect to Cloud Shell, re-run `Connect-AzAccount` if needed.
2. Re-run the same audit command with the same `-OutputPath`. The script reattaches to `<OutputPath>.state`, prints how many subscriptions are already done, and processes only the remaining ones.
3. When the final merge completes, the `-OutputPath` CSV contains the full result — same schema, same downstream report flow.

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

## Step 5 — `Audit-DefenderForCloud.ps1`

### What it does

1. **Iterates every enabled subscription** the signed-in identity can see and calls the `Microsoft.Security/pricings` ARM endpoint (api-version `2024-01-01`) once per subscription. This single call returns every Defender plan that exists for that subscription — covered or not.
2. **For each plan records:**
   - `PricingTier` — `Standard` (paid, protections active) or `Free` (no protections). **This is the coverage signal.**
   - `SubPlan` — e.g. `P1` / `P2` for Defender for Servers, `PerNode` / `PerApi` for others.
   - `Covered` — derived boolean: `True` only when `PricingTier = Standard` **and** the plan is not deprecated. Use this column to filter the gap report.
   - `Deprecated` + `ReplacedBy` — surfaces plans Microsoft has retired (e.g. legacy `KubernetesService` replaced by `Containers`) so you can clean them up.
   - `FreeTrialRemainingTime` — still ticking? You're not actually paying yet.
   - `Extensions` — Defender extensions per plan as `name=on/off` pairs (e.g. `AgentlessVmScanning=on; MdeDesignatedSubscription=on; FileIntegrityMonitoring=off`). Surfaces feature gaps even on Standard tier.
   - `Enforce`, `Inherited` — hints when a plan is being inherited from a management-group policy.
3. **Synthesises a placeholder row** for any subscription that returns no plans (rare; usually 403 or a deleted-but-not-removed sub) so the report still flags it instead of silently dropping it.

No Microsoft Graph calls are made. No subscription-level scanners are invoked — this is a pure plan-inventory pass.

### Output

A CSV named `DefenderForCloudAudit_<timestamp>.csv` (default location `$HOME`) with one row per (subscription × plan):

| Column | Description |
|---|---|
| `SubscriptionName`, `SubscriptionId` | Where the plan lives. |
| `PlanName` | Plan identifier returned by ARM, e.g. `VirtualMachines`, `Containers`, `StorageAccounts`, `SqlServers`, `KeyVaults`, `Arm`, `Api`, `CloudPosture`. |
| `PricingTier` | `Standard` (covered) or `Free` (not covered). |
| `SubPlan` | Tier sub-plan when applicable (e.g. `P2`). |
| `Covered` | `True` when `PricingTier = Standard` and not deprecated. The single column to filter on for gap reports. |
| `Deprecated`, `ReplacedBy` | Surfaces retired plans and their replacements. |
| `FreeTrialRemainingTime` | Empty when no trial; otherwise the remaining duration. |
| `Enforce`, `Inherited` | MG-policy enforcement / inheritance hints. |
| `ExtensionsEnabled` | Semicolon-joined list of extensions in `on` state. |
| `Extensions` | Full list as `name=on/off` pairs — useful to spot Standard plans where critical features (e.g. `AgentlessVmScanning`) are off. |
| `PlanResourceId` | Full ARM ID of the pricing resource for traceability. |

### Console summary

At the end of the run the script prints a per-plan rollup, e.g.:

```
Plan rows recorded             : 84
Subscriptions audited          : 12
Subs with >=1 Standard plan    :  9
Subs entirely on Free plans    :  3
Plan rows COVERED  (Standard)  : 51
Plan rows NOT covered (Free/dep): 33

Coverage by plan (Standard / Total subs):
  Api                                       2/12
  Arm                                      10/12
  CloudPosture                             12/12
  Containers                                7/12
  KeyVaults                                 5/12
  SqlServers                                8/12
  StorageAccounts                           4/12
  VirtualMachines                          11/12
```

### Permissions

**Reader** on each subscription is enough to *list* pricings. **Security Reader** at the same scope is recommended for the most reliable read on extension state. Granting either at the **tenant root management group** with inheritance gives complete coverage in one assignment.

## Step 6 — `Build-DefenderReport.ps1`

### What it does

Reads the Defender CSV and writes a single self-contained `.html` file (same dark theme, same interactivity model as the Sentinel and DCR reports) with:

- **KPI strip** — covered (Standard) plan rows, not-covered (Free / deprecated) plan rows, total subscriptions audited, and a dedicated **All-Free subs** counter.
- **Subscriptions panel** — every subscription with its `Standard / Total` plan ratio and a status flag: `all standard` (green), `mixed` (amber), or `all free` (red). Scrollable.
- **Plan coverage matrix** — every plan name with the number of subscriptions on Standard tier and a coloured percentage column (green ≥80%, amber ≥40%, red below). Lets you spot tenant-wide blind spots in seconds.
- **Two browsable tables:**
  - **Covered (Standard)** — Defender extensions rendered as cyan chips, with `· off` chips for any extensions disabled on a paid plan (a common partial-coverage anti-pattern).
  - **Not covered** — same layout, all chips amber, status badge distinguishes `free / off` from `deprecated`. This is the upgrade list.
- **Live filter box** — type any substring (subscription name, plan, sub-plan, extension name) and both tabs filter in real time, with row-count badges updating.
- **Export filtered CSV** — downloads whatever is visible in the active tab.

### Usage

```powershell
# Default: writes alongside the CSV, same filename with .html
./Build-DefenderReport.ps1 -InputCsv ~/DefenderForCloudAudit_20260503_104500.csv

# Custom output path
./Build-DefenderReport.ps1 -InputCsv ~/mdc.csv -OutputHtml ~/defender-report.html
```

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

### Defender for Cloud coverage gap hunt

1. Run `Audit-DefenderForCloud.ps1` from Cloud Shell (or local pwsh).
2. Run `Build-DefenderReport.ps1 -InputCsv <CSV>`.
3. `download` the HTML, open it locally.
4. Open the **Not covered** tab — every row is a workload type with no Defender protection. Sort by `Subscription` to see whose subs are bare, or filter by plan name (e.g. `VirtualMachines`) to find tenant-wide gaps for a specific Defender plan.
5. Use the **Plan coverage matrix** to spot plans where most of the tenant is on Free tier — those are the highest-impact upgrades.
6. On the **Covered** tab, scan extension chips for `· off` markers — they reveal Standard plans where individual capabilities (e.g. `AgentlessVmScanning`, `FileIntegrityMonitoring`) are disabled and the protection is therefore partial.
7. **Export filtered CSV** to hand off subscription-by-subscription upgrade lists to whoever owns the billing for those subs.

## Caveats

- **Performance.** One ARM call per resource means large tenants (10k+ resources) take time. The parallel-worker mode (`-ThrottleLimit`) and per-subscription resume help, but the same data can be pulled in bulk via Azure Resource Graph (`resources | join (...) on ...`) for a much bigger speed-up — that's a bigger rewrite.
- **Multiple diagnostic settings per resource** are common (a Key Vault might send audit events to Sentinel and metrics to a separate workspace). Each becomes its own row, which is what you want for an audit but means the row count exceeds the unique resource count.
- **`SentinelEnabled = True` means "the destination workspace has the SecurityInsights solution attached."** It does not validate that Sentinel data connectors for that resource type are *enabled* in the Sentinel workspace, or that ingestion is actually succeeding — only that the diagnostic setting points at a Sentinel-equipped workspace. Connector and ingestion checks are a separate problem.
- **Identity scope matters.** `Get-AzSubscription` only returns subscriptions the running identity can see. To guarantee tenant-wide visibility, elevate to the tenant root group ("Access management for Azure resources" in the Entra portal) before running, or assign Reader at the root MG to the auditing identity.
- **`Covered = True` only validates billing tier.** It means the plan is on `Standard` and not deprecated. It does **not** validate that Defender agents are deployed, that auto-provisioning is on, or that the subscription has any *resources of that type* to protect. A `Covered = True` row for `Containers` on a subscription with no AKS clusters is paid-for but inert. Use the `Extensions` column and the per-plan resource inventory (e.g. the DCR/VM audit, Resource Graph) to validate actual deployment.

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
