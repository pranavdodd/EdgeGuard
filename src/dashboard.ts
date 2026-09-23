export const dashboardResponse = (): Response =>
  new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EdgeGuard Control Room</title>
  <style>
    :root { color-scheme: dark; --ink:#edf4f1; --muted:#8fa6a1; --line:#263c3a; --panel:#102321; --bg:#081514; --lime:#b7f36b; --coral:#ff876f; --cyan:#71d7d1; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:320px; background:radial-gradient(circle at 80% 0%, #173b35 0, transparent 36%), var(--bg); color:var(--ink); font:15px/1.5 ui-sans-serif, system-ui, sans-serif; }
    main { max-width:1180px; margin:0 auto; padding:36px 22px 64px; }
    header { display:flex; justify-content:space-between; gap:20px; align-items:end; border-bottom:1px solid var(--line); padding-bottom:26px; }
    h1 { margin:0; font:700 clamp(30px,5vw,58px)/.95 Georgia, serif; letter-spacing:-1px; }
    .eyebrow { color:var(--lime); font-size:12px; font-weight:800; letter-spacing:2px; text-transform:uppercase; margin:0 0 12px; }
    .status { color:var(--muted); text-align:right; } .status b { color:var(--lime); }
    .auth { display:flex; gap:10px; margin:25px 0; max-width:600px; }
    input, button { border:1px solid var(--line); border-radius:6px; padding:12px 14px; font:inherit; }
    input { background:#0b1c1a; color:var(--ink); flex:1; min-width:0; } button { background:var(--lime); color:#102018; cursor:pointer; font-weight:800; } button:hover { filter:brightness(1.08); }
    .error { color:var(--coral); min-height:24px; } .hidden { display:none; }
    .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:22px 0; }
    .card, section { background:color-mix(in srgb, var(--panel) 92%, transparent); border:1px solid var(--line); border-radius:8px; }
    .card { padding:18px; min-height:112px; } .card span { color:var(--muted); display:block; font-size:12px; text-transform:uppercase; letter-spacing:1px; } .card strong { display:block; font-size:34px; margin-top:14px; }
    .content { display:grid; grid-template-columns:1.1fr .9fr; gap:14px; } section { padding:20px; min-width:0; } h2 { font-size:16px; margin:0 0 18px; } table { width:100%; border-collapse:collapse; } th,td { border-bottom:1px solid var(--line); padding:10px 6px; text-align:left; font-size:13px; } th { color:var(--muted); font-weight:500; } td:last-child, th:last-child { text-align:right; } .bar { background:#1e3b35; height:7px; border-radius:8px; overflow:hidden; margin-top:7px; } .bar i { background:var(--cyan); display:block; height:100%; }
    .empty { color:var(--muted); padding:18px 0; } .ai { border-left:3px solid var(--lime); padding-left:14px; } .ai small { color:var(--lime); font-weight:800; letter-spacing:1px; text-transform:uppercase; } .ai p { margin:8px 0 0; }
    @media (max-width:760px) { header { display:block; } .status { text-align:left; margin-top:16px; } .grid,.content { grid-template-columns:1fr 1fr; } .content { display:block; } section + section { margin-top:14px; } }
    @media (max-width:480px) { .grid { grid-template-columns:1fr; } .auth { display:block; } .auth button { margin-top:8px; width:100%; } }
  </style>
</head>
<body>
  <main>
    <header><div><p class="eyebrow">EdgeGuard / operations</p><h1>Control room</h1></div><div class="status" id="status">Waiting for access</div></header>
    <form class="auth" id="auth"><input id="key" type="password" autocomplete="off" placeholder="Analytics API key" aria-label="Analytics API key"><button>Open dashboard</button></form>
    <div class="error" id="error" role="alert"></div>
    <div id="app" class="hidden">
      <div class="grid"><div class="card"><span>Events / 24h</span><strong id="total">0</strong></div><div class="card"><span>Average risk</span><strong id="risk">0</strong></div><div class="card"><span>Blocked</span><strong id="blocked">0</strong></div><div class="card"><span>Rate limited</span><strong id="limited">0</strong></div></div>
      <div class="content"><section><h2>Recent security events</h2><div id="events" class="empty">No events recorded.</div></section><section><h2>Top paths</h2><div id="paths" class="empty">No paths recorded.</div><div id="analysis" class="hidden ai"><small>AI-generated analysis</small><p id="analysisText"></p></div></section></div>
    </div>
  </main>
  <script>
    const auth = document.querySelector('#auth'), key = document.querySelector('#key'), error = document.querySelector('#error'), app = document.querySelector('#app'), status = document.querySelector('#status');
    const get = (path, token) => fetch(path, { headers: { 'x-api-key': token } }).then(async response => { const body = await response.json(); if (!response.ok) throw new Error(body.error?.code || 'Request failed'); return body; });
    const esc = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    auth.addEventListener('submit', async event => { event.preventDefault(); const token = key.value.trim(); if (!token) return; error.textContent = ''; status.textContent = 'Loading…'; try { const [summary, events] = await Promise.all([get('/api/analytics/summary', token), get('/api/analytics/events?limit=20', token)]); const data = summary.summary; document.querySelector('#total').textContent = data.totalEvents; document.querySelector('#risk').textContent = Number(data.averageRiskScore).toFixed(1); document.querySelector('#blocked').textContent = data.actionCounts.block; document.querySelector('#limited').textContent = data.actionCounts.rate_limited; document.querySelector('#events').innerHTML = events.events.length ? '<table><thead><tr><th>Time</th><th>Path</th><th>Action</th><th>Risk</th></tr></thead><tbody>' + events.events.map(item => '<tr><td>' + esc(new Date(item.createdAt).toLocaleTimeString()) + '</td><td>' + esc(item.path) + '</td><td>' + esc(item.action) + '</td><td>' + esc(item.riskScore) + '</td></tr>').join('') + '</tbody></table>' : '<div class="empty">No events recorded.</div>'; const max = Math.max(1, ...data.topPaths.map(item => item.count)); document.querySelector('#paths').innerHTML = data.topPaths.length ? data.topPaths.map(item => '<div><b>' + esc(item.path) + '</b><span style="float:right">' + item.count + '</span><div class="bar"><i style="width:' + (item.count / max * 100) + '%"></i></div></div>').join('') : '<div class="empty">No paths recorded.</div>'; app.classList.remove('hidden'); auth.classList.add('hidden'); status.innerHTML = '<b>Connected</b> · 24 hour window'; } catch (reason) { status.textContent = 'Access denied'; error.textContent = reason.message === 'EDGEGUARD_ANALYTICS_UNAUTHORIZED' ? 'The API key was not accepted.' : 'Dashboard data is unavailable.'; } });
  </script>
</body>
</html>`,
    {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store",
      },
    },
  );
