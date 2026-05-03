<#
.SYNOPSIS
    Builds a self-contained HTML report from the CSV produced by Audit-DefenderForCloud.ps1.

.DESCRIPTION
    Produces a single .html file (no external assets) showing:
      - Top-line counts: covered (Standard) vs not-covered (Free/deprecated) plan rows
      - Per-subscription coverage breakdown (which subs are entirely Free vs mixed vs all Standard)
      - Plan-coverage matrix (e.g. how many subs have Defender for Servers vs Containers vs Storage)
      - Two browsable tables: "Covered" and "Not covered"
      - Defender extensions rendered as colored chips so enablement state pops
      - Live filter box and CSV export of any filtered view

.PARAMETER InputCsv
    Path to the CSV from Audit-DefenderForCloud.ps1.

.PARAMETER OutputHtml
    Where to write the HTML report. Defaults to the same folder as the CSV.

.NOTES
    Project : Sentinel Lookout
    Author  : Predrag (Peter) Petrovic <ppetrovic@microsoft.com>
    License : MIT
    Repo    : https://github.com/0xrick-dev/Sentinel_Lookout

    DISCLAIMER: This is an open-source project. It is not produced, endorsed, or
    supported by Microsoft Corporation. Use at your own risk.

.EXAMPLE
    ./Build-DefenderReport.ps1 -InputCsv ~/DefenderForCloudAudit_20260503_104500.csv
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

# Normalise booleans (CSV stores them as strings)
foreach ($r in $rows) {
    $r.Covered    = ($r.Covered    -eq 'True')
    $r.Deprecated = ($r.Deprecated -eq 'True')
}

# ---- Summary stats --------------------------------------------------------
$totalRows      = $rows.Count
$coveredRows    = @($rows | Where-Object { $_.Covered })
$uncoveredRows  = @($rows | Where-Object { -not $_.Covered })

$uniqSubs       = ($rows | Select-Object -ExpandProperty SubscriptionId -Unique).Count
$bySub          = $rows | Group-Object SubscriptionId
$subsAllStd     = 0
$subsMixed      = 0
$subsAllFree    = 0
foreach ($g in $bySub) {
    $cov = (@($g.Group | Where-Object { $_.Covered })).Count
    $tot = $g.Group.Count
    if     ($cov -eq 0)    { $subsAllFree++ }
    elseif ($cov -eq $tot) { $subsAllStd++  }
    else                   { $subsMixed++   }
}

# Per-subscription roll-up: rows / standard / free
$subBreakdown = $bySub |
    ForEach-Object {
        $cov = (@($_.Group | Where-Object { $_.Covered })).Count
        $tot = $_.Group.Count
        $name = $_.Group[0].SubscriptionName
        [pscustomobject]@{
            Subscription = $name
            Standard     = $cov
            Total        = $tot
            Status       = if ($cov -eq 0) { 'all-free' }
                           elseif ($cov -eq $tot) { 'all-standard' }
                           else { 'mixed' }
        }
    } | Sort-Object @{Expression='Standard';Descending=$false}, Subscription

# Per-plan coverage matrix (how many subs have plan X on Standard)
$planMatrix = $rows |
    Group-Object PlanName |
    ForEach-Object {
        $std  = (@($_.Group | Where-Object { $_.Covered })).Count
        $totS = ($_.Group | Select-Object -ExpandProperty SubscriptionId -Unique).Count
        [pscustomobject]@{
            Plan     = $_.Name
            Standard = $std
            Subs     = $totS
            Pct      = if ($totS -gt 0) { [math]::Round(100 * $std / $totS, 0) } else { 0 }
        }
    } | Sort-Object @{Expression='Standard';Descending=$true}, Plan

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

# ---- Build JSON payloads --------------------------------------------------
$coveredJson   = $coveredRows   | ConvertTo-Json -Depth 4 -Compress
$uncoveredJson = $uncoveredRows | ConvertTo-Json -Depth 4 -Compress

if ($coveredRows.Count   -eq 1) { $coveredJson   = "[$coveredJson]" }
if ($uncoveredRows.Count -eq 1) { $uncoveredJson = "[$uncoveredJson]" }
if ($coveredRows.Count   -eq 0) { $coveredJson   = '[]' }
if ($uncoveredRows.Count -eq 0) { $uncoveredJson = '[]' }

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$subRowsHtml = if ($subBreakdown) {
    ($subBreakdown | ForEach-Object {
        $statusLabel = switch ($_.Status) {
            'all-standard' { '<span style="color:var(--accent)">all standard</span>' }
            'all-free'     { '<span style="color:var(--danger)">all free</span>'     }
            default        { '<span style="color:var(--warn)">mixed</span>'          }
        }
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Subscription))</td><td class=`"num`">$($_.Standard)/$($_.Total)</td><td class=`"num`" style=`"width:120px`">$statusLabel</td></tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="3" class="muted">No subscriptions audited.</td></tr>'
}

$planRowsHtml = if ($planMatrix) {
    ($planMatrix | ForEach-Object {
        $color = if    ($_.Pct -ge 80) { 'var(--accent)' }
                 elseif ($_.Pct -ge 40) { 'var(--warn)'   }
                 else                   { 'var(--danger)' }
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Plan))</td><td class=`"num`">$($_.Standard)/$($_.Subs)</td><td class=`"num`" style=`"color:$color;width:60px`">$($_.Pct)%</td></tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="3" class="muted">No plans recorded.</td></tr>'
}

# ---- HTML -----------------------------------------------------------------
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Defender for Cloud Coverage Audit — $generated</title>
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
    --accent:#5ee0c1;
    --accent-2:#7dd3fc;
    --warn:#f5c451;
    --danger:#ff6b6b;
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
  .kpi .delta{margin-top:10px;font-size:11.5px;color:var(--ink-dim)}
  .kpi.good .value{color:var(--accent)}
  .kpi.bad  .value{color:var(--danger)}
  .kpi.warn .value{color:var(--warn)}
  .kpi::after{
    content:'';position:absolute;left:0;right:0;bottom:0;height:2px;
    background:linear-gradient(90deg,transparent,var(--border-2),transparent);
  }
  .kpi.good::after{background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0.7}
  .kpi.bad::after {background:linear-gradient(90deg,transparent,var(--danger),transparent);opacity:0.7}

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
  .panel.scroll{max-height:340px;overflow-y:auto}
  table.mini{width:100%;border-collapse:collapse;font-size:12.5px}
  table.mini td{padding:7px 8px;border-bottom:1px dashed var(--border);}
  table.mini tr:last-child td{border-bottom:none}
  table.mini td.num{text-align:right;color:var(--accent);font-weight:500;width:80px}
  .muted{color:var(--ink-muted);font-style:italic}

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

  .toolbar{
    display:flex;align-items:center;justify-content:space-between;gap:16px;
    padding:16px 0 18px;flex-wrap:wrap;
  }
  .search{flex:1;min-width:240px;position:relative}
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

  .table-wrap{
    border:1px solid var(--border);background:var(--panel);
    overflow-x:auto;
  }
  table.data{width:100%;border-collapse:collapse;font-size:12.5px}
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

  .planname{color:var(--ink);font-weight:500}
  .subname{color:var(--ink);font-weight:500}
  .subid{color:var(--ink-muted);font-size:11px;font-family:var(--mono)}
  .tier-std{color:var(--accent);font-weight:600;letter-spacing:0.08em}
  .tier-free{color:var(--danger);font-weight:600;letter-spacing:0.08em}
  .subplan{color:var(--accent-2);font-size:11.5px}
  .deprecated{
    display:inline-block;margin-left:6px;font-size:9.5px;letter-spacing:0.18em;
    text-transform:uppercase;color:var(--danger);border:1px solid currentColor;padding:1px 5px;
  }

  .chips{display:flex;flex-wrap:wrap;gap:4px}
  .chip{
    display:inline-block;padding:3px 8px;border-radius:2px;
    font-size:10.5px;letter-spacing:0.04em;
    background:rgba(94,224,193,0.08);color:var(--accent);
    border:1px solid rgba(94,224,193,0.25);
  }
  .chip.off{
    background:rgba(255,107,107,0.06);color:var(--danger);
    border-color:rgba(255,107,107,0.22);
  }
  .chip.empty{
    background:rgba(93,104,119,0.06);color:var(--ink-muted);
    border-color:rgba(93,104,119,0.25);font-style:italic;
  }
  /* In the "not covered" tab, all on-chips render amber to underline that the
     plan they belong to is not actually paid-for. */
  tr.not-covered .chip{
    background:rgba(245,196,81,0.07);color:var(--warn);
    border-color:rgba(245,196,81,0.28);
  }
  tr.not-covered .chip.off{
    background:rgba(255,107,107,0.07);color:var(--danger);
    border-color:rgba(255,107,107,0.25);
  }

  .badge{
    display:inline-block;font-size:10px;letter-spacing:0.18em;text-transform:uppercase;
    padding:2px 7px;border:1px solid currentColor;
  }
  .badge.ok{color:var(--accent)}
  .badge.no{color:var(--danger)}
  .badge.warn{color:var(--warn)}

  .empty-state{padding:60px 20px;text-align:center;color:var(--ink-muted);font-style:italic}

  section.view{display:none}
  section.view.active{display:block}

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
    <div class="eyebrow">Microsoft Defender for Cloud · Plan Coverage Audit</div>
    <h1>Coverage Posture</h1>
    <div class="sub">Inventory of every Defender for Cloud plan in every subscription. Use this view to find subscriptions and workload types running on Free tier — i.e. with no Defender protections — so you can prioritise upgrades.</div>
  </div>
  <div class="meta">
    <span class="pulse">live snapshot</span>
    <span class="ts">generated $generated</span>
    <span class="ts">$totalRows plan rows · $uniqSubs subscription(s)</span>
  </div>
</header>

<main>

  <!-- KPI strip -->
  <div class="kpis">
    <div class="kpi good">
      <div class="label">Covered (Standard)</div>
      <div class="value">$($coveredRows.Count)</div>
      <div class="delta">plan rows on a paid Defender tier</div>
    </div>
    <div class="kpi bad">
      <div class="label">Not covered</div>
      <div class="value">$($uncoveredRows.Count)</div>
      <div class="delta">plan rows on Free tier or deprecated</div>
    </div>
    <div class="kpi">
      <div class="label">Subscriptions</div>
      <div class="value">$uniqSubs</div>
      <div class="delta">$subsAllStd all-Standard · $subsMixed mixed · $subsAllFree all-Free</div>
    </div>
    <div class="kpi warn">
      <div class="label">All-Free subs</div>
      <div class="value">$subsAllFree</div>
      <div class="delta">subscriptions with zero paid Defender plans</div>
    </div>
  </div>

  <!-- Splits -->
  <div class="splits">
    <div class="panel scroll">
      <h2>Subscriptions <small>standard / total plans</small></h2>
      <table class="mini">
        <tbody>
$subRowsHtml
        </tbody>
      </table>
    </div>
    <div class="panel scroll">
      <h2>Plan coverage matrix <small>subs on Standard / total subs</small></h2>
      <table class="mini">
        <tbody>
$planRowsHtml
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" data-view="covered">
      Covered (Standard) <span class="count" id="cnt-covered">$($coveredRows.Count)</span>
    </button>
    <button class="tab" data-view="uncovered">
      Not covered <span class="count" id="cnt-uncovered">$($uncoveredRows.Count)</span>
    </button>
  </div>

  <div class="toolbar">
    <div class="search">
      <input id="filter" type="text" placeholder="filter by subscription, plan, sub-plan, extension..." autocomplete="off">
    </div>
    <div class="actions">
      <button class="btn" id="btn-export">Export filtered CSV</button>
    </div>
  </div>

  <section class="view active" id="view-covered">
    <div class="table-wrap">
      <table class="data" id="tbl-covered">
        <thead>
          <tr>
            <th>Subscription</th>
            <th>Plan</th>
            <th>Tier / Sub-plan</th>
            <th>Extensions</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <section class="view" id="view-uncovered">
    <div class="table-wrap">
      <table class="data" id="tbl-uncovered">
        <thead>
          <tr>
            <th>Subscription</th>
            <th>Plan</th>
            <th>Tier / Sub-plan <span style="color:var(--warn);text-transform:none;letter-spacing:0;font-weight:400">⚠ no Defender protections</span></th>
            <th>Extensions</th>
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
  const COVERED   = $coveredJson;
  const UNCOVERED = $uncoveredJson;

  function escapeHtml(s){
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function renderExtensions(extStr){
    if (!extStr) return '<span class="chip empty">(no extensions)</span>';
    const parts = String(extStr).split(';').map(s => s.trim()).filter(Boolean);
    if (!parts.length) return '<span class="chip empty">(no extensions)</span>';
    return '<div class="chips">' + parts.map(p => {
      const m = p.match(/^(.*?)=(\w+)`$/);
      const name = m ? m[1] : p;
      const on   = m ? (m[2] === 'on') : true;
      return '<span class="chip' + (on ? '' : ' off') + '">'
           + escapeHtml(name) + (on ? '' : ' · off') + '</span>';
    }).join('') + '</div>';
  }

  function renderRow(r, covered){
    const cls = covered ? '' : ' class="not-covered"';
    const tierClass = covered ? 'tier-std' : 'tier-free';
    const tier = '<span class="' + tierClass + '">' + escapeHtml(r.PricingTier || 'Free') + '</span>';
    const sub  = r.SubPlan ? ' · <span class="subplan">' + escapeHtml(r.SubPlan) + '</span>' : '';
    const depr = (r.Deprecated === true || r.Deprecated === 'True')
                  ? '<span class="deprecated">deprecated</span>' : '';
    let badge;
    if (covered) {
      badge = '<span class="badge ok">covered</span>';
    } else if (r.Deprecated === true || r.Deprecated === 'True') {
      badge = '<span class="badge warn">deprecated</span>';
    } else {
      badge = '<span class="badge no">free / off</span>';
    }
    return '<tr' + cls + '>'
      + '<td><div class="subname">' + escapeHtml(r.SubscriptionName) + '</div>'
      +   '<div class="subid">' + escapeHtml(r.SubscriptionId) + '</div></td>'
      + '<td><span class="planname">' + escapeHtml(r.PlanName) + '</span>' + depr + '</td>'
      + '<td>' + tier + sub + '</td>'
      + '<td>' + renderExtensions(r.Extensions) + '</td>'
      + '<td>' + badge + '</td>'
      + '</tr>';
  }

  function rowMatches(r, q){
    if (!q) return true;
    const hay = [
      r.SubscriptionName, r.SubscriptionId, r.PlanName, r.PricingTier, r.SubPlan,
      r.Extensions, r.ExtensionsEnabled, r.ReplacedBy
    ].map(v => (v||'').toString().toLowerCase()).join(' | ');
    return hay.indexOf(q) !== -1;
  }

  function paint(){
    const q = document.getElementById('filter').value.trim().toLowerCase();
    const cBody = document.querySelector('#tbl-covered tbody');
    const uBody = document.querySelector('#tbl-uncovered tbody');

    const cFilt = COVERED.filter(r => rowMatches(r, q));
    const uFilt = UNCOVERED.filter(r => rowMatches(r, q));

    cBody.innerHTML = cFilt.length
      ? cFilt.map(r => renderRow(r, true)).join('')
      : '<tr><td colspan="5" class="empty-state">No matching plan rows are on Standard tier.</td></tr>';
    uBody.innerHTML = uFilt.length
      ? uFilt.map(r => renderRow(r, false)).join('')
      : '<tr><td colspan="5" class="empty-state">Nothing matches — every plan in this filter is on Standard tier.</td></tr>';

    document.getElementById('cnt-covered').textContent   = cFilt.length;
    document.getElementById('cnt-uncovered').textContent = uFilt.length;
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
    const data = (activeView === 'covered' ? COVERED : UNCOVERED).filter(r => rowMatches(r, q));
    if (!data.length){ alert('Nothing to export.'); return; }
    const cols = ['SubscriptionName','SubscriptionId','PlanName','PricingTier','SubPlan','Covered',
                  'Deprecated','ReplacedBy','FreeTrialRemainingTime','Enforce','Inherited',
                  'ExtensionsEnabled','Extensions','PlanResourceId'];
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
Write-Host "  Covered (Standard)        : $($coveredRows.Count) rows"
Write-Host "  Not covered (Free / depr) : $($uncoveredRows.Count) rows"
Write-Host "  Subscriptions             : $uniqSubs ($subsAllStd all-standard · $subsMixed mixed · $subsAllFree all-free)"
Write-Host "`nIn Cloud Shell, download with: download $OutputHtml" -ForegroundColor Cyan
