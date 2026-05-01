<#
.SYNOPSIS
    Builds a self-contained HTML report from the CSV produced by Audit-SentinelDiagnostics.ps1.

.DESCRIPTION
    Produces a single .html file (no external assets) showing:
      - Top-line counts: resources sending vs. not sending to Sentinel
      - Per-Sentinel-workspace breakdown (handles multi-Sentinel tenants)
      - Two browsable tables: "Sending to Sentinel" and "Not sending to Sentinel"
      - Diagnostic data column rendered as colored chips so log categories pop
      - Live filter box and CSV export of any filtered view

.PARAMETER InputCsv
    Path to the CSV from Audit-SentinelDiagnostics.ps1.

.PARAMETER OutputHtml
    Where to write the HTML report. Defaults to the same folder as the CSV.

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout
 
    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell)
    and Microsoft.Graph.Identity.DirectoryManagement for Entra ID diagnostic settings.
 
    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.

.EXAMPLE
    ./Build-SentinelReport.ps1 -InputCsv ~/SentinelDiagnosticsAudit_20260427_104500.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsv,

    [string]$OutputHtml
)

if (-not (Test-Path $InputCsv)) {
    Write-Error "CSV not found: $InputCsv"
    return
}

if (-not $OutputHtml) {
    $OutputHtml = [System.IO.Path]::ChangeExtension($InputCsv, '.html')
}

$rows = Import-Csv -Path $InputCsv
if (-not $rows) {
    Write-Error "CSV is empty: $InputCsv"
    return
}

# Normalise the SentinelEnabled column (CSV stores booleans as strings)
foreach ($r in $rows) {
    $r.SentinelEnabled = ($r.SentinelEnabled -eq 'True')
}

# ---- Summary stats --------------------------------------------------------
$totalRows         = $rows.Count
$sendingRows       = @($rows | Where-Object { $_.SentinelEnabled })
$notSendingRows    = @($rows | Where-Object { -not $_.SentinelEnabled })

$uniqueResSending     = ($sendingRows    | Select-Object ResourceName,ResourceGroup,SubscriptionName -Unique).Count
$uniqueResNotSending  = ($notSendingRows | Select-Object ResourceName,ResourceGroup,SubscriptionName -Unique).Count

# Per-Sentinel-workspace breakdown
$workspaceBreakdown = $sendingRows |
    Group-Object SentinelWorkspaceName |
    Sort-Object Count -Descending |
    ForEach-Object {
        [pscustomobject]@{ Workspace = $_.Name; Rows = $_.Count }
    }

# Resource-type breakdown (top 10) for the "not sending" cohort - handy gap view
$gapByType = $notSendingRows |
    Group-Object ResourceType |
    Sort-Object Count -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        [pscustomobject]@{ Type = $_.Name; Rows = $_.Count }
    }

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

# ---- Build JSON payloads for embedded JS ----------------------------------
$sendingJson    = $sendingRows    | ConvertTo-Json -Depth 4 -Compress
$notSendingJson = $notSendingRows | ConvertTo-Json -Depth 4 -Compress

# Single-row arrays come back as objects, not arrays. Force array shape.
if ($sendingRows.Count    -eq 1) { $sendingJson    = "[$sendingJson]" }
if ($notSendingRows.Count -eq 1) { $notSendingJson = "[$notSendingJson]" }
if ($sendingRows.Count    -eq 0) { $sendingJson    = '[]' }
if ($notSendingRows.Count -eq 0) { $notSendingJson = '[]' }

$workspaceRowsHtml = if ($workspaceBreakdown) {
    ($workspaceBreakdown | ForEach-Object {
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Workspace))</td><td class=`"num`">$($_.Rows)</td></tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="2" class="muted">No Sentinel workspaces receiving data.</td></tr>'
}

$gapRowsHtml = if ($gapByType) {
    ($gapByType | ForEach-Object {
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Type))</td><td class=`"num`">$($_.Rows)</td></tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="2" class="muted">Nothing missing — every diagnostic setting points at Sentinel.</td></tr>'
}

# Need System.Web for HtmlEncode in Cloud Shell pwsh
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$tenantHint = if ($rows | Where-Object SubscriptionName) {
    ($rows | Select-Object -ExpandProperty SubscriptionName -Unique) -join ', '
} else { '' }
if ($tenantHint.Length -gt 120) { $tenantHint = $tenantHint.Substring(0,117) + '...' }

# ---- HTML -----------------------------------------------------------------
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Diagnostics Audit — $generated</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Fraunces:opsz,wght@9..144,400;9..144,600;9..144,800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e14;
    --bg-2:#10151d;
    --panel:#141a23;
    --panel-2:#1a212c;
    --border:#222b38;
    --border-2:#2c3848;
    --ink:#e6edf3;
    --ink-dim:#9aa6b2;
    --ink-muted:#5d6877;
    --accent:#5ee0c1;       /* signal: healthy / sending */
    --accent-2:#7dd3fc;
    --warn:#f5c451;         /* signal: partial / attention */
    --danger:#ff6b6b;       /* signal: missing */
    --grid: rgba(255,255,255,0.025);
    --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
    --display:'Fraunces',Georgia,serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13.5px;line-height:1.55}
  body{
    background-image:
      radial-gradient(circle at 12% 8%, rgba(94,224,193,0.06), transparent 40%),
      radial-gradient(circle at 88% 4%, rgba(125,211,252,0.05), transparent 38%),
      linear-gradient(var(--grid) 1px, transparent 1px),
      linear-gradient(90deg, var(--grid) 1px, transparent 1px);
    background-size: auto, auto, 32px 32px, 32px 32px;
    min-height:100vh;
  }
  a{color:var(--accent-2);text-decoration:none}
  a:hover{text-decoration:underline}

  header.top{
    padding:34px 40px 22px;
    border-bottom:1px solid var(--border);
    display:flex;align-items:flex-end;justify-content:space-between;gap:32px;
    flex-wrap:wrap;
  }
  .brand{display:flex;flex-direction:column;gap:6px}
  .brand .eyebrow{
    font-size:11px;letter-spacing:0.32em;text-transform:uppercase;color:var(--ink-muted);
  }
  .brand h1{
    margin:0;font-family:var(--display);font-weight:800;
    font-size:46px;letter-spacing:-0.02em;line-height:1;
    background:linear-gradient(180deg,var(--ink) 0%,#a9b6c4 100%);
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  .brand .sub{font-size:12.5px;color:var(--ink-dim);margin-top:8px;max-width:62ch}
  .meta{
    text-align:right;font-size:11.5px;color:var(--ink-muted);
    display:flex;flex-direction:column;gap:4px;
  }
  .meta .ts{color:var(--ink-dim)}
  .meta .pulse{
    display:inline-flex;align-items:center;gap:8px;
    color:var(--accent);font-weight:500;
  }
  .pulse::before{
    content:'';width:7px;height:7px;border-radius:50%;background:var(--accent);
    box-shadow:0 0 0 0 var(--accent);
    animation:pulse 2.4s cubic-bezier(.4,0,.6,1) infinite;
  }
  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(94,224,193,0.6)}
    70%{box-shadow:0 0 0 10px rgba(94,224,193,0)}
    100%{box-shadow:0 0 0 0 rgba(94,224,193,0)}
  }

  main{padding:28px 40px 80px;max-width:1600px;margin:0 auto}

  /* KPI strip */
  .kpis{
    display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
    gap:1px;background:var(--border);border:1px solid var(--border);
    margin-bottom:32px;
  }
  .kpi{background:var(--panel);padding:22px 24px;position:relative;overflow:hidden}
  .kpi .label{
    font-size:10.5px;letter-spacing:0.24em;text-transform:uppercase;color:var(--ink-muted);
    margin-bottom:14px;
  }
  .kpi .value{
    font-family:var(--display);font-weight:800;font-size:54px;line-height:1;
    letter-spacing:-0.03em;color:var(--ink);
  }
  .kpi .delta{
    margin-top:10px;font-size:11.5px;color:var(--ink-dim);
  }
  .kpi.good .value{color:var(--accent)}
  .kpi.bad  .value{color:var(--danger)}
  .kpi.warn .value{color:var(--warn)}
  .kpi::after{
    content:'';position:absolute;left:0;right:0;bottom:0;height:2px;
    background:linear-gradient(90deg,transparent,var(--border-2),transparent);
  }
  .kpi.good::after{background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0.7}
  .kpi.bad::after {background:linear-gradient(90deg,transparent,var(--danger),transparent);opacity:0.7}

  /* Two-column inline tables (workspace + gaps) */
  .splits{
    display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:36px;
  }
  @media (max-width: 980px){ .splits{grid-template-columns:1fr} }
  .panel{
    background:var(--panel);border:1px solid var(--border);
    padding:20px 22px;
  }
  .panel h2{
    margin:0 0 16px 0;font-family:var(--display);font-weight:600;font-size:20px;
    letter-spacing:-0.01em;color:var(--ink);
    display:flex;align-items:baseline;gap:10px;
  }
  .panel h2 small{
    font-family:var(--mono);font-size:10.5px;letter-spacing:0.2em;text-transform:uppercase;
    color:var(--ink-muted);font-weight:400;
  }
  table.mini{width:100%;border-collapse:collapse;font-size:12.5px}
  table.mini td{padding:7px 8px;border-bottom:1px dashed var(--border);}
  table.mini tr:last-child td{border-bottom:none}
  table.mini td.num{text-align:right;color:var(--accent);font-weight:500;width:80px}
  .muted{color:var(--ink-muted);font-style:italic}

  /* Section nav */
  .tabs{
    display:flex;gap:0;margin-bottom:0;border-bottom:1px solid var(--border);
  }
  .tab{
    background:transparent;border:none;color:var(--ink-dim);
    font-family:var(--mono);font-size:12px;letter-spacing:0.18em;text-transform:uppercase;
    padding:14px 22px;cursor:pointer;border-bottom:2px solid transparent;
    transition:all 0.15s ease;
  }
  .tab:hover{color:var(--ink)}
  .tab.active{color:var(--ink);border-bottom-color:var(--accent)}
  .tab .count{
    display:inline-block;margin-left:8px;font-size:10.5px;
    color:var(--ink-muted);background:var(--bg-2);
    padding:2px 7px;border-radius:10px;letter-spacing:0;
  }
  .tab.active .count{color:var(--ink);background:var(--panel-2)}

  /* Toolbar */
  .toolbar{
    display:flex;align-items:center;justify-content:space-between;gap:16px;
    padding:16px 0 18px;flex-wrap:wrap;
  }
  .search{
    flex:1;min-width:240px;position:relative;
  }
  .search input{
    width:100%;background:var(--panel);border:1px solid var(--border);
    color:var(--ink);font-family:var(--mono);font-size:13px;
    padding:11px 14px 11px 38px;outline:none;
    transition:border-color 0.15s ease;
  }
  .search input:focus{border-color:var(--accent)}
  .search::before{
    content:'⌕';position:absolute;left:14px;top:50%;transform:translateY(-50%);
    color:var(--ink-muted);font-size:14px;
  }
  .toolbar .actions{display:flex;gap:10px}
  .btn{
    background:transparent;border:1px solid var(--border-2);color:var(--ink-dim);
    font-family:var(--mono);font-size:11.5px;letter-spacing:0.14em;text-transform:uppercase;
    padding:10px 16px;cursor:pointer;transition:all 0.15s ease;
  }
  .btn:hover{color:var(--ink);border-color:var(--accent)}

  /* Main table */
  .table-wrap{
    border:1px solid var(--border);background:var(--panel);
    overflow-x:auto;
  }
  table.data{
    width:100%;border-collapse:collapse;font-size:12.5px;
  }
  table.data thead th{
    text-align:left;padding:13px 14px;
    font-size:10.5px;letter-spacing:0.18em;text-transform:uppercase;
    color:var(--ink-muted);font-weight:500;
    background:var(--bg-2);border-bottom:1px solid var(--border);
    position:sticky;top:0;z-index:1;
    white-space:nowrap;
  }
  table.data tbody td{
    padding:12px 14px;border-bottom:1px solid var(--border);
    vertical-align:top;
  }
  table.data tbody tr:hover{background:var(--panel-2)}
  table.data tbody tr:last-child td{border-bottom:none}

  .resname{color:var(--ink);font-weight:500}
  .restype{color:var(--ink-muted);font-size:11.5px}
  .ws{color:var(--accent-2)}
  .ws.sentinel{color:var(--accent);font-weight:500}
  .sub{color:var(--ink-dim);font-size:11.5px}

  /* Diagnostic chips */
  .chips{display:flex;flex-wrap:wrap;gap:4px}
  .chip{
    display:inline-block;padding:3px 8px;border-radius:2px;
    font-size:10.5px;letter-spacing:0.04em;
    background:rgba(94,224,193,0.08);color:var(--accent);
    border:1px solid rgba(94,224,193,0.25);
  }
  .chip.metric{
    background:rgba(125,211,252,0.06);color:var(--accent-2);
    border-color:rgba(125,211,252,0.22);
  }
  .chip.empty{
    background:rgba(255,107,107,0.07);color:var(--danger);
    border-color:rgba(255,107,107,0.25);font-style:italic;
  }
  /* In the "not sending" table, all chips render in amber to highlight
     that these categories are configured but not flowing to Sentinel. */
  tr.not-sending .chip{
    background:rgba(245,196,81,0.07);color:var(--warn);
    border-color:rgba(245,196,81,0.28);
  }
  tr.not-sending .chip.empty{
    background:rgba(255,107,107,0.07);color:var(--danger);
    border-color:rgba(255,107,107,0.25);
  }

  .badge{
    display:inline-block;font-size:10px;letter-spacing:0.18em;text-transform:uppercase;
    padding:2px 7px;border:1px solid currentColor;
  }
  .badge.ok{color:var(--accent)}
  .badge.no{color:var(--danger)}

  .empty-state{
    padding:60px 20px;text-align:center;color:var(--ink-muted);font-style:italic;
  }

  /* Hide non-active section */
  section.view{display:none}
  section.view.active{display:block}

  /* Footer */
  footer{
    margin-top:48px;padding-top:18px;border-top:1px solid var(--border);
    color:var(--ink-muted);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;
    display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;
  }
</style>
</head>
<body>

<header class="top">
  <div class="brand">
    <div class="eyebrow">Microsoft Sentinel · Diagnostic Coverage Audit</div>
    <h1>Telemetry Posture</h1>
    <div class="sub">Inventory of every diagnostic setting in the tenant, mapped against Sentinel-enabled Log Analytics workspaces. Use this view to find resources whose logs are configured but not flowing to your SOC.</div>
  </div>
  <div class="meta">
    <span class="pulse">live snapshot</span>
    <span class="ts">generated $generated</span>
    <span class="ts">$totalRows diagnostic rows · $($workspaceBreakdown.Count) Sentinel workspace(s)</span>
  </div>
</header>

<main>

  <!-- KPI strip -->
  <div class="kpis">
    <div class="kpi good">
      <div class="label">→ Sentinel</div>
      <div class="value">$($sendingRows.Count)</div>
      <div class="delta">$uniqueResSending unique resources delivering telemetry</div>
    </div>
    <div class="kpi bad">
      <div class="label">Not → Sentinel</div>
      <div class="value">$($notSendingRows.Count)</div>
      <div class="delta">$uniqueResNotSending unique resources with diagnostics elsewhere or unrouted</div>
    </div>
    <div class="kpi">
      <div class="label">Total rows</div>
      <div class="value">$totalRows</div>
      <div class="delta">one row per resource × diagnostic setting</div>
    </div>
    <div class="kpi warn">
      <div class="label">Sentinel WS</div>
      <div class="value">$($workspaceBreakdown.Count)</div>
      <div class="delta">workspaces with SecurityInsights solution attached</div>
    </div>
  </div>

  <!-- Splits -->
  <div class="splits">
    <div class="panel">
      <h2>Workspace distribution <small>where the data lands</small></h2>
      <table class="mini">
        <tbody>
$workspaceRowsHtml
        </tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Largest gaps <small>resource types not reaching Sentinel</small></h2>
      <table class="mini">
        <tbody>
$gapRowsHtml
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" data-view="sending">
      Sending to Sentinel <span class="count" id="cnt-sending">$($sendingRows.Count)</span>
    </button>
    <button class="tab" data-view="notsending">
      Not sending to Sentinel <span class="count" id="cnt-notsending">$($notSendingRows.Count)</span>
    </button>
  </div>

  <div class="toolbar">
    <div class="search">
      <input id="filter" type="text" placeholder="filter by resource, type, workspace, subscription, log category..." autocomplete="off">
    </div>
    <div class="actions">
      <button class="btn" id="btn-export">Export filtered CSV</button>
    </div>
  </div>

  <section class="view active" id="view-sending">
    <div class="table-wrap">
      <table class="data" id="tbl-sending">
        <thead>
          <tr>
            <th>Resource</th>
            <th>Type</th>
            <th>Sentinel Workspace</th>
            <th>Diagnostic Data</th>
            <th>Subscription / RG</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <section class="view" id="view-notsending">
    <div class="table-wrap">
      <table class="data" id="tbl-notsending">
        <thead>
          <tr>
            <th>Resource</th>
            <th>Type</th>
            <th>Destination Workspace</th>
            <th>Diagnostic Data <span style="color:var(--warn);text-transform:none;letter-spacing:0;font-weight:400">⚠ not flowing to Sentinel</span></th>
            <th>Subscription / RG</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <footer>
    <span>Audit · $generated</span>
    <span>Source CSV · $([System.IO.Path]::GetFileName($InputCsv))</span>
  </footer>
</main>

<script>
  const SENDING     = $sendingJson;
  const NOT_SENDING = $notSendingJson;

  function escapeHtml(s){
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function renderChips(diagData){
    if (!diagData || diagData === '(none enabled)' || diagData === '(no diagnostic setting configured)') {
      return '<span class="chip empty">' + escapeHtml(diagData || '(none)') + '</span>';
    }
    const parts = String(diagData).split(';').map(s => s.trim()).filter(Boolean);
    return '<div class="chips">' + parts.map(p => {
      const isMetric = p.toLowerCase().startsWith('metric:');
      const label = isMetric ? p.substring(7) : p;
      return '<span class="chip' + (isMetric ? ' metric' : '') + '">' + escapeHtml(label) + '</span>';
    }).join('') + '</div>';
  }

  function renderRow(r, sending){
    const wsClass = sending ? 'ws sentinel' : 'ws';
    const wsName  = sending
      ? (r.SentinelWorkspaceName || r.LogAnalyticsWorkspace || '—')
      : (r.LogAnalyticsWorkspace || '—');
    const badge = sending
      ? '<span class="badge ok">→ Sentinel</span>'
      : '<span class="badge no">no Sentinel</span>';
    const cls = sending ? '' : ' class="not-sending"';
    return '<tr' + cls + '>'
      + '<td><div class="resname">' + escapeHtml(r.ResourceName) + '</div>'
      +   '<div class="sub">' + escapeHtml(r.DiagnosticSettingName || '') + '</div></td>'
      + '<td><span class="restype">' + escapeHtml(r.ResourceType) + '</span></td>'
      + '<td><span class="' + wsClass + '">' + escapeHtml(wsName) + '</span></td>'
      + '<td>' + renderChips(r.DiagnosticData) + '</td>'
      + '<td><div>' + escapeHtml(r.SubscriptionName) + '</div>'
      +   '<div class="sub">' + escapeHtml(r.ResourceGroup) + '</div></td>'
      + '<td>' + badge + '</td>'
      + '</tr>';
  }

  function rowMatches(r, q){
    if (!q) return true;
    const hay = [
      r.ResourceName, r.ResourceType, r.LogAnalyticsWorkspace, r.SentinelWorkspaceName,
      r.DiagnosticData, r.DiagnosticSettingName, r.SubscriptionName, r.ResourceGroup
    ].map(v => (v||'').toString().toLowerCase()).join(' | ');
    return hay.indexOf(q) !== -1;
  }

  function paint(){
    const q = document.getElementById('filter').value.trim().toLowerCase();
    const sBody = document.querySelector('#tbl-sending tbody');
    const nBody = document.querySelector('#tbl-notsending tbody');

    const sFilt = SENDING.filter(r => rowMatches(r, q));
    const nFilt = NOT_SENDING.filter(r => rowMatches(r, q));

    sBody.innerHTML = sFilt.length
      ? sFilt.map(r => renderRow(r, true)).join('')
      : '<tr><td colspan="6" class="empty-state">No matching resources are sending to Sentinel.</td></tr>';
    nBody.innerHTML = nFilt.length
      ? nFilt.map(r => renderRow(r, false)).join('')
      : '<tr><td colspan="6" class="empty-state">Nothing matches — every resource in this filter is reaching Sentinel.</td></tr>';

    document.getElementById('cnt-sending').textContent    = sFilt.length;
    document.getElementById('cnt-notsending').textContent = nFilt.length;
  }

  // Tabs
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('view-' + btn.dataset.view).classList.add('active');
    });
  });

  // Filter
  document.getElementById('filter').addEventListener('input', paint);

  // Export filtered
  document.getElementById('btn-export').addEventListener('click', () => {
    const q = document.getElementById('filter').value.trim().toLowerCase();
    const activeView = document.querySelector('.tab.active').dataset.view;
    const data = (activeView === 'sending' ? SENDING : NOT_SENDING).filter(r => rowMatches(r, q));
    if (!data.length){ alert('Nothing to export.'); return; }
    const cols = ['ResourceName','ResourceType','LogAnalyticsWorkspace','SentinelWorkspaceName',
                  'DiagnosticData','SentinelEnabled','DiagnosticSettingName','SubscriptionName',
                  'ResourceGroup','WorkspaceResourceId'];
    const esc = v => {
      if (v === null || v === undefined) return '';
      const s = String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
    };
    const csv = [cols.join(',')].concat(data.map(r => cols.map(c => esc(r[c])).join(','))).join('\r\n');
    const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = activeView + '_filtered.csv';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  paint();
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputHtml -Encoding utf8

Write-Host "`nReport written: $OutputHtml" -ForegroundColor Green
Write-Host "  Sending to Sentinel    : $($sendingRows.Count) rows ($uniqueResSending unique resources)"
Write-Host "  Not sending to Sentinel: $($notSendingRows.Count) rows ($uniqueResNotSending unique resources)"
Write-Host "  Sentinel workspaces    : $($workspaceBreakdown.Count)"
Write-Host "`nIn Cloud Shell, download with: download $OutputHtml" -ForegroundColor Cyan
