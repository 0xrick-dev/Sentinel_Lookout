# Sentinel Lookout

> A two-step PowerShell toolkit for Azure Cloud Shell that maps every diagnostic setting in your tenant against your Microsoft Sentinel-enabled Log Analytics workspaces, then turns the result into an interactive HTML report.

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

## Contents

| File | Purpose |
|---|---|
| `Audit-SentinelDiagnostics.ps1` | Discovers Sentinel workspaces, walks every subscription, exports a CSV of all diagnostic settings. |
| `Build-SentinelReport.ps1` | Reads the CSV and produces a single self-contained `.html` dashboard. |
| `sample-report.html` | Example output rendered against fictional data, for previewing the design. |

## Requirements

- **Azure Cloud Shell (PowerShell)** — works out of the box. The Az modules are preinstalled.
- **Permissions on the tenant:**
  - **Reader** on every subscription you want covered. The cleanest setup is to grant the auditing identity Reader at the **tenant root management group** with inheritance, so no subscription is invisible.
  - **Security Reader** or **Global Reader** at the tenant root for the Entra ID diagnostic settings query. Without it that section returns 403 and is skipped (the rest still runs).

## Quick start

```powershell
# 1. Inventory every diagnostic setting in the tenant
./Audit-SentinelDiagnostics.ps1

# 2. Turn the CSV into an interactive HTML report
./Build-SentinelReport.ps1 -InputCsv ~/SentinelDiagnosticsAudit_20260427_104500.csv

# 3. Pull the HTML out of Cloud Shell to view locally
download ~/SentinelDiagnosticsAudit_20260427_104500.html
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

## Typical workflow

1. Run `Audit-SentinelDiagnostics.ps1` from Cloud Shell.
2. Run `Build-SentinelReport.ps1` against the CSV.
3. `download` the HTML, open it locally.
4. Click the **Not sending to Sentinel** tab.
5. Sort or filter by `Subscription`, `ResourceType`, or a specific log category.
6. Use **Export filtered CSV** to send a targeted list to whoever owns those resources.
7. Re-run after remediation to confirm the gap closed.

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
- Additional output formats (JSON, Markdown table, Azure Workbook export).
