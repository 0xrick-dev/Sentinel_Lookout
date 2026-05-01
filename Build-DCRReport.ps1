<#
.SYNOPSIS
    Builds a self-contained HTML report from the CSV produced by Audit-SentinelDCRs.ps1.

.DESCRIPTION
    Produces a single .html file (no external assets) showing:
      - Top-line counts: DCRs sending to Sentinel vs. not
      - Per-Sentinel-workspace breakdown
      - Data-collection coverage (Security log, Syslog, custom paths, perf, IIS, extensions...)
      - Two browsable tables: "Sending to Sentinel" and "Not sending to Sentinel"
      - Each row exposes destination workspaces, what is being collected, and the
        VMs / Arc machines / VMSS instances associated with the rule
      - Live filter and CSV export of the filtered view

.PARAMETER InputCsv
    Path to the CSV from Audit-SentinelDCRs.ps1.

.PARAMETER OutputHtml
    Where to write the HTML. Defaults to alongside the CSV.

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/sentinel-lookout

    Run from Azure Cloud Shell (PowerShell). Requires Az modules (preinstalled in Cloud Shell).

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.

.EXAMPLE
    ./Build-DCRReport.ps1 -InputCsv ~/SentinelDCRAudit_20260501_104500.csv
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

# Normalise booleans from CSV strings.
$boolCols = @(
    'SentinelEnabled','HasNonSentinelDestination',
    'CollectsWindowsEventLogs','CollectsWindowsSecurityLog','CollectsSyslog',
    'CollectsPerformanceCounters','CollectsCustomLogFiles','CollectsIISLogs',
    'CollectsExtensions','CollectsPrometheus','CollectsWindowsFirewallLogs'
)
foreach ($r in $rows) {
    foreach ($c in $boolCols) {
        if ($r.PSObject.Properties[$c]) {
            $r.$c = ($r.$c -eq 'True')
        }
    }
    if ($r.PSObject.Properties['AssociationCount']) {
        $n = 0; [int]::TryParse([string]$r.AssociationCount, [ref]$n) | Out-Null
        $r.AssociationCount = $n
    }
}

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ---- Summary ---------------------------------------------------------------
$totalRows         = $rows.Count
$sendingRows       = @($rows | Where-Object { $_.SentinelEnabled })
$notSendingRows    = @($rows | Where-Object { -not $_.SentinelEnabled })

$totalAssocs        = ($rows | Measure-Object -Property AssociationCount -Sum).Sum
$assocsToSentinel   = ($sendingRows    | Measure-Object -Property AssociationCount -Sum).Sum
$assocsNotSentinel  = ($notSendingRows | Measure-Object -Property AssociationCount -Sum).Sum

# Per-Sentinel-workspace breakdown (workspaces are semicolon-joined inside the column)
$wsBreakdown = $sendingRows |
    ForEach-Object { ($_.SentinelWorkspaces -split '; ') } |
    Where-Object { $_ } |
    Group-Object |
    Sort-Object Count -Descending |
    ForEach-Object { [pscustomobject]@{ Workspace = $_.Name; Rules = $_.Count } }

# Coverage matrix
$coverage = [ordered]@{
    'Windows Security log' = ($rows | Where-Object CollectsWindowsSecurityLog).Count
    'Windows Event Logs'   = ($rows | Where-Object CollectsWindowsEventLogs).Count
    'Syslog'               = ($rows | Where-Object CollectsSyslog).Count
    'Performance counters' = ($rows | Where-Object CollectsPerformanceCounters).Count
    'Custom log files'     = ($rows | Where-Object CollectsCustomLogFiles).Count
    'IIS logs'             = ($rows | Where-Object CollectsIISLogs).Count
    'Extensions'           = ($rows | Where-Object CollectsExtensions).Count
    'Prometheus'           = ($rows | Where-Object CollectsPrometheus).Count
    'Windows firewall'     = ($rows | Where-Object CollectsWindowsFirewallLogs).Count
}

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

# ---- JSON for embedded JS --------------------------------------------------
$sendingJson    = $sendingRows    | ConvertTo-Json -Depth 4 -Compress
$notSendingJson = $notSendingRows | ConvertTo-Json -Depth 4 -Compress
if ($sendingRows.Count    -eq 1) { $sendingJson    = "[$sendingJson]" }
if ($notSendingRows.Count -eq 1) { $notSendingJson = "[$notSendingJson]" }
if ($sendingRows.Count    -eq 0) { $sendingJson    = '[]' }
if ($notSendingRows.Count -eq 0) { $notSendingJson = '[]' }

$workspaceRowsHtml = if ($wsBreakdown) {
    ($wsBreakdown | ForEach-Object {
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Workspace))</td><td class=`"num`">$($_.Rules)</td></tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="2" class="muted">No DCRs are sending data to a Sentinel workspace.</td></tr>'
}

$coverageRowsHtml = ($coverage.GetEnumerator() | ForEach-Object {
    "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Key))</td><td class=`"num`">$($_.Value)</td></tr>"
}) -join "`n"

# ---- HTML ------------------------------------------------------------------
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel DCR Audit — $generated</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Fraunces:opsz,wght@9..144,400;9..144,600;9..144,800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e14; --bg-2:#10151d; --panel:#141a23; --panel-2:#1a212c;
    --border:#222b38; --border-2:#2c3848;
    --ink:#e6edf3; --ink-dim:#9aa6b2; --ink-muted:#5d6877;
    --accent:#5ee0c1; --accent-2:#7dd3fc; --warn:#f5c451; --danger:#ff6b6b;
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
    background-size: auto, auto, 32px 32px, 32px 32px; min-height:100vh;
  }
  a{color:var(--accent-2);text-decoration:none}
  a:hover{text-decoration:underline}

  header.top{padding:34px 40px 22px;border-bottom:1px solid var(--border);display:flex;align-items:flex-end;justify-content:space-between;gap:32px;flex-wrap:wrap}
  .brand{display:flex;flex-direction:column;gap:6px}
  .brand .eyebrow{font-size:11px;letter-spacing:0.32em;text-transform:uppercase;color:var(--ink-muted)}
  .brand h1{margin:0;font-family:var(--display);font-weight:800;font-size:46px;letter-spacing:-0.02em;line-height:1;background:linear-gradient(180deg,var(--ink) 0%,#a9b6c4 100%);-webkit-background-clip:text;background-clip:text;color:transparent}
  .brand .sub{font-size:12.5px;color:var(--ink-dim);margin-top:8px;max-width:62ch}
  .meta{text-align:right;font-size:11.5px;color:var(--ink-muted);display:flex;flex-direction:column;gap:4px}
  .meta .ts{color:var(--ink-dim)}
  .meta .pulse{display:inline-flex;align-items:center;gap:8px;color:var(--accent);font-weight:500}
  .pulse::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 0 var(--accent);animation:pulse 2.4s cubic-bezier(.4,0,.6,1) infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(94,224,193,0.6)}70%{box-shadow:0 0 0 10px rgba(94,224,193,0)}100%{box-shadow:0 0 0 0 rgba(94,224,193,0)}}

  main{padding:28px 40px 80px;max-width:1700px;margin:0 auto}

  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:32px}
  .kpi{background:var(--panel);padding:22px 24px;position:relative;overflow:hidden}
  .kpi .label{font-size:10.5px;letter-spacing:0.24em;text-transform:uppercase;color:var(--ink-muted);margin-bottom:14px}
  .kpi .value{font-family:var(--display);font-weight:800;font-size:54px;line-height:1;letter-spacing:-0.03em;color:var(--ink)}
  .kpi .delta{margin-top:10px;font-size:11.5px;color:var(--ink-dim)}
  .kpi.good .value{color:var(--accent)}
  .kpi.bad  .value{color:var(--danger)}
  .kpi.warn .value{color:var(--warn)}
  .kpi::after{content:'';position:absolute;left:0;right:0;bottom:0;height:2px;background:linear-gradient(90deg,transparent,var(--border-2),transparent)}
  .kpi.good::after{background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0.7}
  .kpi.bad::after {background:linear-gradient(90deg,transparent,var(--danger),transparent);opacity:0.7}

  .splits{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:36px}
  @media (max-width: 980px){ .splits{grid-template-columns:1fr} }
  .panel{background:var(--panel);border:1px solid var(--border);padding:20px 22px}
  .panel h2{margin:0 0 16px 0;font-family:var(--display);font-weight:600;font-size:20px;letter-spacing:-0.01em;color:var(--ink);display:flex;align-items:baseline;gap:10px}
  .panel h2 small{font-family:var(--mono);font-size:10.5px;letter-spacing:0.2em;text-transform:uppercase;color:var(--ink-muted);font-weight:400}
  table.mini{width:100%;border-collapse:collapse;font-size:12.5px}
  table.mini td{padding:7px 8px;border-bottom:1px dashed var(--border)}
  table.mini tr:last-child td{border-bottom:none}
  table.mini td.num{text-align:right;color:var(--accent);font-weight:500;width:80px}
  .muted{color:var(--ink-muted);font-style:italic}

  .tabs{display:flex;gap:0;margin-bottom:0;border-bottom:1px solid var(--border)}
  .tab{background:transparent;border:none;color:var(--ink-dim);font-family:var(--mono);font-size:12px;letter-spacing:0.18em;text-transform:uppercase;padding:14px 22px;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s ease}
  .tab:hover{color:var(--ink)}
  .tab.active{color:var(--ink);border-bottom-color:var(--accent)}
  .tab .count{display:inline-block;margin-left:8px;font-size:10.5px;color:var(--ink-muted);background:var(--bg-2);padding:2px 7px;border-radius:10px;letter-spacing:0}
  .tab.active .count{color:var(--ink);background:var(--panel-2)}

  .toolbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 0 18px;flex-wrap:wrap}
  .search{flex:1;min-width:240px;position:relative}
  .search input{width:100%;background:var(--panel);border:1px solid var(--border);color:var(--ink);font-family:var(--mono);font-size:13px;padding:11px 14px 11px 38px;outline:none;transition:border-color 0.15s ease}
  .search input:focus{border-color:var(--accent)}
  .search::before{content:'⌕';position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--ink-muted);font-size:14px}
  .toolbar .actions{display:flex;gap:10px}
  .btn{background:transparent;border:1px solid var(--border-2);color:var(--ink-dim);font-family:var(--mono);font-size:11.5px;letter-spacing:0.14em;text-transform:uppercase;padding:10px 16px;cursor:pointer;transition:all 0.15s ease}
  .btn:hover{color:var(--ink);border-color:var(--accent)}

  .table-wrap{border:1px solid var(--border);background:var(--panel);overflow-x:auto}
  table.data{width:100%;border-collapse:collapse;font-size:12.5px}
  table.data thead th{text-align:left;padding:13px 14px;font-size:10.5px;letter-spacing:0.18em;text-transform:uppercase;color:var(--ink-muted);font-weight:500;background:var(--bg-2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1;white-space:nowrap}
  table.data tbody td{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:top}
  table.data tbody tr:hover{background:var(--panel-2)}
  table.data tbody tr:last-child td{border-bottom:none}

  .resname{color:var(--ink);font-weight:500}
  .restype{color:var(--ink-muted);font-size:11.5px}
  .ws{color:var(--accent-2)}
  .ws.sentinel{color:var(--accent);font-weight:500}
  .ws.empty{color:var(--danger);font-style:italic}
  .sub{color:var(--ink-dim);font-size:11.5px}

  .chips{display:flex;flex-wrap:wrap;gap:4px}
  .chip{display:inline-block;padding:3px 8px;border-radius:2px;font-size:10.5px;letter-spacing:0.04em;background:rgba(94,224,193,0.08);color:var(--accent);border:1px solid rgba(94,224,193,0.25)}
  .chip.stream{background:rgba(125,211,252,0.06);color:var(--accent-2);border-color:rgba(125,211,252,0.22)}
  .chip.sec{background:rgba(255,107,107,0.10);color:var(--danger);border-color:rgba(255,107,107,0.32);font-weight:500}
  .chip.path{background:rgba(245,196,81,0.08);color:var(--warn);border-color:rgba(245,196,81,0.28)}
  .chip.empty{background:rgba(255,107,107,0.07);color:var(--danger);border-color:rgba(255,107,107,0.25);font-style:italic}
  tr.not-sending .chip{background:rgba(245,196,81,0.07);color:var(--warn);border-color:rgba(245,196,81,0.28)}
  tr.not-sending .chip.empty{background:rgba(255,107,107,0.07);color:var(--danger);border-color:rgba(255,107,107,0.25)}

  .badge{display:inline-block;font-size:10px;letter-spacing:0.18em;text-transform:uppercase;padding:2px 7px;border:1px solid currentColor}
  .badge.ok{color:var(--accent)}
  .badge.no{color:var(--danger)}
  .badge.warn{color:var(--warn)}

  details.assoc{margin-top:6px}
  details.assoc summary{cursor:pointer;color:var(--ink-dim);font-size:11.5px;list-style:none}
  details.assoc summary::-webkit-details-marker{display:none}
  details.assoc summary::before{content:'▸ ';color:var(--ink-muted)}
  details.assoc[open] summary::before{content:'▾ '}
  details.assoc ul{margin:6px 0 0 0;padding-left:14px;color:var(--ink-dim);font-size:11.5px;max-height:160px;overflow-y:auto;border-left:1px dashed var(--border-2)}
  details.assoc li{padding:2px 0;list-style:none;font-family:var(--mono);word-break:break-all}

  .empty-state{padding:60px 20px;text-align:center;color:var(--ink-muted);font-style:italic}
  section.view{display:none}
  section.view.active{display:block}

  footer{margin-top:48px;padding-top:18px;border-top:1px solid var(--border);color:var(--ink-muted);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}
</style>
</head>
<body>

<header class="top">
  <div class="brand">
    <div class="eyebrow">Microsoft Sentinel · Data Collection Rule Audit</div>
    <h1>DCR Coverage</h1>
    <div class="sub">Inventory of every Data Collection Rule in the tenant: where it sends data, what it collects, and which machines it is associated with. Use this view to find DCRs that are bypassing Sentinel or missing critical telemetry like the Windows Security log.</div>
  </div>
  <div class="meta">
    <span class="pulse">live snapshot</span>
    <span class="ts">generated $generated</span>
    <span class="ts">$totalRows DCRs · $totalAssocs associations · $($wsBreakdown.Count) Sentinel workspace(s)</span>
  </div>
</header>

<main>

  <div class="kpis">
    <div class="kpi good">
      <div class="label">DCRs → Sentinel</div>
      <div class="value">$($sendingRows.Count)</div>
      <div class="delta">$assocsToSentinel resource associations feeding Sentinel</div>
    </div>
    <div class="kpi bad">
      <div class="label">DCRs ⇏ Sentinel</div>
      <div class="value">$($notSendingRows.Count)</div>
      <div class="delta">$assocsNotSentinel associations whose data never reaches Sentinel</div>
    </div>
    <div class="kpi">
      <div class="label">Total DCRs</div>
      <div class="value">$totalRows</div>
      <div class="delta">across the entire tenant</div>
    </div>
    <div class="kpi warn">
      <div class="label">Sentinel WS</div>
      <div class="value">$($wsBreakdown.Count)</div>
      <div class="delta">workspaces with SecurityInsights solution attached</div>
    </div>
  </div>

  <div class="splits">
    <div class="panel">
      <h2>Workspace distribution <small>where DCR data lands</small></h2>
      <table class="mini">
        <tbody>
$workspaceRowsHtml
        </tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Collection coverage <small>DCRs collecting each data source</small></h2>
      <table class="mini">
        <tbody>
$coverageRowsHtml
        </tbody>
      </table>
    </div>
  </div>

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
      <input id="filter" type="text" placeholder="filter by DCR, workspace, subscription, stream, data source, associated VM..." autocomplete="off">
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
            <th>DCR</th>
            <th>Destination Workspace(s)</th>
            <th>Data Collected</th>
            <th>Streams</th>
            <th>Associated Resources</th>
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
            <th>DCR</th>
            <th>Destination Workspace(s) <span style="color:var(--warn);text-transform:none;letter-spacing:0;font-weight:400">⚠ not Sentinel</span></th>
            <th>Data Collected</th>
            <th>Streams</th>
            <th>Associated Resources</th>
            <th>Subscription / RG</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <footer>
    <span>DCR audit · $generated</span>
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

  function splitList(s){
    return String(s||'').split(';').map(x => x.trim()).filter(Boolean);
  }

  function dataChips(r){
    const items = splitList(r.DataCollectionSummary);
    if (!items.length || (items.length===1 && items[0]==='(no data sources)')) {
      return '<span class="chip empty">(no data sources)</span>';
    }
    return '<div class="chips">' + items.map(p => {
      const lower = p.toLowerCase();
      let cls = 'chip';
      if (p.indexOf('SECURITY') !== -1) cls += ' sec';
      else if (lower.startsWith('logfiles') || lower.startsWith('iislogs')) cls += ' path';
      return '<span class="' + cls + '">' + escapeHtml(p) + '</span>';
    }).join('') + '</div>';
  }

  function streamChips(r){
    const items = splitList(r.Streams);
    if (!items.length) return '<span class="chip empty">(no streams)</span>';
    return '<div class="chips">' + items.map(p =>
      '<span class="chip stream">' + escapeHtml(p) + '</span>').join('') + '</div>';
  }

  function shortResource(rid){
    // /subscriptions/<id>/resourceGroups/<rg>/providers/<ns>/<type>/<name>[/...]
    const segs = rid.split('/').filter(Boolean);
    const i = segs.findIndex(x => x.toLowerCase()==='resourcegroups');
    const rg = (i>=0 && segs[i+1]) ? segs[i+1] : '';
    const name = segs[segs.length-1];
    return rg ? (name + '  (' + rg + ')') : name;
  }

  function assocBlock(r){
    const ids = splitList(r.AssociatedResourceIds);
    const types = splitList(r.AssociatedResourceTypes);
    const count = parseInt(r.AssociationCount,10) || ids.length;
    if (!count) return '<span class="muted">no associations</span>';
    const typeChips = types.length
      ? '<div class="chips" style="margin-bottom:6px">' +
        types.map(t => '<span class="chip stream">' + escapeHtml(t) + '</span>').join('') +
        '</div>'
      : '';
    const list = ids.slice(0,500).map(rid =>
      '<li title="' + escapeHtml(rid) + '">' + escapeHtml(shortResource(rid)) + '</li>'
    ).join('');
    return typeChips +
      '<details class="assoc"><summary>' + count + ' associated resource' +
      (count===1?'':'s') + '</summary><ul>' + list + '</ul></details>';
  }

  function destChips(r, sending){
    const wsList = splitList(r.DestinationWorkspaces);
    const sentinelList = splitList(r.SentinelWorkspaces);
    const others = splitList(r.OtherDestinations);
    const isSentinel = name => sentinelList.indexOf(name) !== -1;

    const parts = [];
    if (!wsList.length) {
      parts.push('<span class="ws empty">(no workspace destination)</span>');
    } else {
      wsList.forEach(w => {
        parts.push('<span class="ws ' + (isSentinel(w) ? 'sentinel' : '') + '">' +
          escapeHtml(w) + (isSentinel(w) ? '  ⓢ' : '') + '</span>');
      });
    }
    if (others.length) {
      parts.push('<div class="chips" style="margin-top:6px">' +
        others.map(o => '<span class="chip stream">' + escapeHtml(o) + '</span>').join('') +
        '</div>');
    }
    return parts.join('<br>');
  }

  function statusBadge(r){
    if (r.SentinelEnabled === true || r.SentinelEnabled === 'True') {
      if (r.HasNonSentinelDestination === true || r.HasNonSentinelDestination === 'True') {
        return '<span class="badge warn">→ Sentinel + other</span>';
      }
      return '<span class="badge ok">→ Sentinel</span>';
    }
    return '<span class="badge no">no Sentinel</span>';
  }

  function renderRow(r, sending){
    const cls = sending ? '' : ' class="not-sending"';
    return '<tr' + cls + '>'
      + '<td><div class="resname">' + escapeHtml(r.DcrName) + '</div>'
      +   '<div class="sub">' + escapeHtml(r.Kind || '') + (r.Location?(' · ' + escapeHtml(r.Location)):'') + '</div></td>'
      + '<td>' + destChips(r, sending) + '</td>'
      + '<td>' + dataChips(r) + '</td>'
      + '<td>' + streamChips(r) + '</td>'
      + '<td>' + assocBlock(r) + '</td>'
      + '<td><div>' + escapeHtml(r.SubscriptionName) + '</div>'
      +   '<div class="sub">' + escapeHtml(r.ResourceGroup) + '</div></td>'
      + '<td>' + statusBadge(r) + '</td>'
      + '</tr>';
  }

  function rowMatches(r, q){
    if (!q) return true;
    const hay = [
      r.DcrName, r.DcrResourceId, r.Kind, r.Location,
      r.DestinationWorkspaces, r.SentinelWorkspaces, r.OtherDestinations,
      r.DataCollectionSummary, r.Streams,
      r.AssociatedResourceIds, r.AssociatedResourceTypes,
      r.SubscriptionName, r.ResourceGroup
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
      : '<tr><td colspan="7" class="empty-state">No DCRs match the current filter.</td></tr>';
    nBody.innerHTML = nFilt.length
      ? nFilt.map(r => renderRow(r, false)).join('')
      : '<tr><td colspan="7" class="empty-state">Nothing matches — every DCR in this filter is feeding Sentinel.</td></tr>';

    document.getElementById('cnt-sending').textContent    = sFilt.length;
    document.getElementById('cnt-notsending').textContent = nFilt.length;
  }

  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('view-' + btn.dataset.view).classList.add('active');
    });
  });

  document.getElementById('filter').addEventListener('input', paint);

  document.getElementById('btn-export').addEventListener('click', () => {
    const q = document.getElementById('filter').value.trim().toLowerCase();
    const activeView = document.querySelector('.tab.active').dataset.view;
    const data = (activeView === 'sending' ? SENDING : NOT_SENDING).filter(r => rowMatches(r, q));
    if (!data.length){ alert('Nothing to export.'); return; }
    const cols = ['DcrName','DcrResourceId','Kind','Location','ResourceGroup','SubscriptionName',
                  'DestinationWorkspaces','DestinationWorkspaceResourceIds','SentinelEnabled',
                  'SentinelWorkspaces','HasNonSentinelDestination','OtherDestinations',
                  'DataCollectionSummary','Streams',
                  'CollectsWindowsEventLogs','CollectsWindowsSecurityLog','CollectsSyslog',
                  'CollectsPerformanceCounters','CollectsCustomLogFiles','CollectsIISLogs',
                  'CollectsExtensions','CollectsPrometheus','CollectsWindowsFirewallLogs',
                  'AssociationCount','AssociatedResourceTypes','AssociatedResourceIds'];
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
    a.download = 'dcr_' + activeView + '_filtered.csv';
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
Write-Host "  DCRs sending to Sentinel    : $($sendingRows.Count) ($assocsToSentinel associations)"
Write-Host "  DCRs NOT sending to Sentinel: $($notSendingRows.Count) ($assocsNotSentinel associations)"
Write-Host "  Sentinel workspaces         : $($wsBreakdown.Count)"
Write-Host "`nIn Cloud Shell, download with: download $OutputHtml" -ForegroundColor Cyan
